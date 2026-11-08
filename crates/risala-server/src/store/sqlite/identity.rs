//! [`IdentityStore`] on SQLite, and the identity area's tables (4.6-4.9,
//! 10.5).

use rusqlite::{OptionalExtension as _, Transaction, params};

use risala_proto::auth::{PUBLIC_KEY_LEN, PublicKey};
use risala_proto::chain::Pin;
use risala_proto::names::{BlobRef, Identity, Name, Uid};
use risala_proto::time::Timestamp;

use super::{SqliteStore, from_sql_u64, sql_u64};
use crate::store::identity::{HostedName, PairPut, StoredRecord};
use crate::store::{IdentityStore, Result, StoreError, fixed, millis, parsed, timestamp};

/// The identity area's tables.
pub(super) const SCHEMA: &str = "
-- Identities that have signed in here and not unregistered since (4.6,
-- 4.9).
CREATE TABLE accounts (
    uid TEXT PRIMARY KEY,           -- the identity, in lower case
    first_seen INTEGER NOT NULL,    -- ms
    last_seen INTEGER NOT NULL      -- ms
) STRICT;

-- The names hosted under the identity domain (4.7). An unregistered name
-- keeps its row, so that it is never registered again and its key file
-- answers 410 (4.9, 10.5).
CREATE TABLE hosted (
    name TEXT PRIMARY KEY,          -- <name> of <name>@<identity domain>
    uid TEXT NOT NULL UNIQUE,       -- the whole identity
    registered INTEGER NOT NULL,    -- ms
    unregistered INTEGER            -- ms, or NULL while hosted
) STRICT;

-- The chains of records the server keeps (4.4): those of the identities
-- it hosts, and of those whose chains name its log (4.7). They mirror the
-- log, so nothing deletes them.
CREATE TABLE records (
    uid TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0), -- 0 for the first record
    record BLOB NOT NULL,           -- the encoded Record
    hash BLOB NOT NULL UNIQUE CHECK (length(hash) = 48), -- its SHA-384 hash
    log_index INTEGER UNIQUE,       -- its index in log_entries, once logged
    PRIMARY KEY (uid, position)
) STRICT;

-- The server's pins on identities it does not host (4.6): the master key
-- of the first chain it accepted, and the newest record it holds.
CREATE TABLE pins (
    uid TEXT PRIMARY KEY,
    master_key BLOB NOT NULL CHECK (length(master_key) = 1312),
    head BLOB NOT NULL CHECK (length(head) = 48),
    updated INTEGER NOT NULL        -- ms
) STRICT;

-- Pairing messages (4.8), for 10 minutes. The id is a bearer secret, so
-- only its hash is kept (Section 14).
CREATE TABLE pairing (
    id_hash BLOB PRIMARY KEY CHECK (length(id_hash) = 48), -- SHA-384 of the id
    data BLOB NOT NULL,             -- the encrypted message, as received
    expires INTEGER NOT NULL        -- ms
) STRICT;
CREATE INDEX pairing_expires ON pairing (expires);
";

fn insert_records(
    tx: &Transaction<'_>,
    identity: &Identity,
    from: usize,
    records: &[StoredRecord],
) -> Result<()> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO records (uid, position, record, hash, log_index) VALUES (?, ?, ?, ?, ?)",
    )?;
    for (position, r) in (from..).zip(records) {
        insert.execute(params![
            identity.as_str(),
            i64::try_from(position).unwrap_or(i64::MAX),
            r.record,
            &r.hash.hash()[..],
            r.log_index.map(sql_u64),
        ])?;
    }
    Ok(())
}

fn record_count(tx: &Transaction<'_>, identity: &Identity) -> Result<usize> {
    let n: i64 = tx.query_row(
        "SELECT count(*) FROM records WHERE uid = ?",
        [identity.as_str()],
        |r| r.get(0),
    )?;
    usize::try_from(n).map_err(|_| StoreError::Corrupt(format!("record count {n}")))
}

impl IdentityStore for SqliteStore {
    fn note_sign_in(&self, uid: &Uid, now: Timestamp) -> Result<bool> {
        self.write(|tx| {
            let t = millis(now);
            let added = tx.execute(
                "INSERT INTO accounts (uid, first_seen, last_seen) VALUES (?1, ?2, ?2)
                 ON CONFLICT (uid) DO NOTHING",
                params![uid.as_str(), t],
            )?;
            if added == 0 {
                tx.execute(
                    "UPDATE accounts SET last_seen = max(last_seen, ?2) WHERE uid = ?1",
                    params![uid.as_str(), t],
                )?;
            }
            Ok(added == 1)
        })
    }

    fn knows(&self, uid: &Uid) -> Result<bool> {
        self.read(|tx| {
            Ok(tx
                .query_row(
                    "SELECT 1 FROM accounts WHERE uid = ?",
                    [uid.as_str()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
    }

    fn forget(&self, uid: &Uid) -> Result<bool> {
        self.write(|tx| Ok(tx.execute("DELETE FROM accounts WHERE uid = ?", [uid.as_str()])? == 1))
    }

    fn hosted(&self, name: &Name) -> Result<Option<HostedName>> {
        self.read(|tx| {
            let row = tx
                .query_row(
                    "SELECT uid, registered, unregistered FROM hosted WHERE name = ?",
                    [name.as_str()],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, Option<i64>>(2)?,
                        ))
                    },
                )
                .optional()?;
            row.map(|(uid, registered, unregistered)| {
                Ok(HostedName {
                    identity: parsed("hosted identity", &uid)?,
                    registered: timestamp(registered)?,
                    unregistered: unregistered.map(timestamp).transpose()?,
                })
            })
            .transpose()
        })
    }

    fn hosted_names(&self) -> Result<Vec<Name>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached("SELECT name FROM hosted ORDER BY name")?;
            let names = select.query_map([], |r| r.get::<_, String>(0))?;
            names.map(|name| parsed("hosted name", &name?)).collect()
        })
    }

    fn register(
        &self,
        name: &Name,
        identity: &Identity,
        records: &[StoredRecord],
        now: Timestamp,
    ) -> Result<bool> {
        self.write(|tx| {
            let taken = tx
                .query_row(
                    "SELECT 1 FROM hosted WHERE name = ?1 OR uid = ?2",
                    params![name.as_str(), identity.as_str()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if taken || record_count(tx, identity)? > 0 {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO hosted (name, uid, registered) VALUES (?, ?, ?)",
                params![name.as_str(), identity.as_str(), millis(now)],
            )?;
            insert_records(tx, identity, 0, records)?;
            Ok(true)
        })
    }

    fn chain_records(&self, identity: &Identity) -> Result<Vec<StoredRecord>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(
                "SELECT record, hash, log_index FROM records WHERE uid = ? ORDER BY position",
            )?;
            let rows = select.query_map([identity.as_str()], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                ))
            })?;
            rows.map(|row| {
                let (record, hash, log_index) = row?;
                Ok(StoredRecord {
                    record,
                    hash: BlobRef::from_hash(fixed("record hash", &hash)?),
                    log_index: log_index
                        .map(|i| from_sql_u64("log index", i))
                        .transpose()?,
                })
            })
            .collect()
        })
    }

    fn add_records(
        &self,
        identity: &Identity,
        from: usize,
        records: &[StoredRecord],
    ) -> Result<()> {
        self.write(|tx| {
            let held = record_count(tx, identity)?;
            if held != from {
                return Err(StoreError::Corrupt(format!(
                    "adding records at {from} to a chain of {held}"
                )));
            }
            insert_records(tx, identity, from, records)
        })
    }

    fn pin(&self, identity: &Identity) -> Result<Option<Pin>> {
        self.read(|tx| {
            let row = tx
                .query_row(
                    "SELECT master_key, head FROM pins WHERE uid = ?",
                    [identity.as_str()],
                    |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?;
            row.map(|(key, head)| {
                Ok(Pin {
                    master_key: PublicKey::from_bytes(&fixed::<PUBLIC_KEY_LEN>(
                        "pinned master key",
                        &key,
                    )?),
                    head: BlobRef::from_hash(fixed("pinned head", &head)?),
                })
            })
            .transpose()
        })
    }

    fn set_pin(&self, identity: &Identity, pin: &Pin, now: Timestamp) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO pins (uid, master_key, head, updated) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (uid) DO UPDATE SET
                    master_key = ?2, head = ?3, updated = ?4",
                params![
                    identity.as_str(),
                    &pin.master_key.as_bytes()[..],
                    &pin.head.hash()[..],
                    millis(now)
                ],
            )?;
            Ok(())
        })
    }

    fn unregister(&self, uid: &Uid, now: Timestamp) -> Result<bool> {
        self.write(|tx| {
            let u = uid.as_str();
            let mut known = 0;
            known += tx.execute("DELETE FROM accounts WHERE uid = ?", [u])?;
            known += tx.execute("DELETE FROM pins WHERE uid = ?", [u])?;
            known += tx.execute(
                "UPDATE hosted SET unregistered = ?2 WHERE uid = ?1 AND unregistered IS NULL",
                params![u, millis(now)],
            )?;
            // The other areas' rows of the identity (4.9). Welcomes waiting
            // for its devices go with what they were handed out for.
            known += tx.execute("DELETE FROM key_packages WHERE uid = ?", [u])?;
            known += tx.execute("DELETE FROM handed_out WHERE uid = ?", [u])?;
            known += tx.execute("DELETE FROM push_subscriptions WHERE uid = ?", [u])?;
            known += tx.execute("DELETE FROM backups WHERE uid = ?", [u])?;
            known += tx.execute("DELETE FROM presence WHERE uid = ?", [u])?;
            Ok(known > 0)
        })
    }

    fn pair_put(
        &self,
        id_hash: &[u8; 48],
        data: &[u8],
        expires: Timestamp,
        now: Timestamp,
    ) -> Result<PairPut> {
        self.write(|tx| {
            let held = tx
                .query_row(
                    "SELECT data FROM pairing WHERE id_hash = ? AND expires > ?",
                    params![&id_hash[..], millis(now)],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            match held {
                Some(held) if held == data => Ok(PairPut::Same),
                Some(_) => Ok(PairPut::Taken),
                None => {
                    tx.execute(
                        "INSERT INTO pairing (id_hash, data, expires) VALUES (?1, ?2, ?3)
                         ON CONFLICT (id_hash) DO UPDATE SET data = ?2, expires = ?3",
                        params![&id_hash[..], data, millis(expires)],
                    )?;
                    Ok(PairPut::Stored)
                }
            }
        })
    }

    fn pair_get(&self, id_hash: &[u8; 48], now: Timestamp) -> Result<Option<Vec<u8>>> {
        self.read(|tx| {
            Ok(tx
                .query_row(
                    "SELECT data FROM pairing WHERE id_hash = ? AND expires > ?",
                    params![&id_hash[..], millis(now)],
                    |r| r.get(0),
                )
                .optional()?)
        })
    }

    fn expire_pairing(&self, now: Timestamp) -> Result<usize> {
        self.write(|tx| Ok(tx.execute("DELETE FROM pairing WHERE expires <= ?", [millis(now)])?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn record(n: u8, log_index: Option<u64>) -> StoredRecord {
        StoredRecord {
            record: vec![n; 10],
            hash: BlobRef::of(&[n]),
            log_index,
        }
    }

    #[test]
    fn accounts() {
        let store = SqliteStore::open_in_memory().unwrap();
        let alice: Uid = "alice@example.org".parse().unwrap();
        let t = t("2026-11-09T00:00:00.000Z");
        assert!(!store.knows(&alice).unwrap());
        assert!(store.note_sign_in(&alice, t).unwrap());
        assert!(!store.note_sign_in(&alice, t).unwrap());
        assert!(store.knows(&alice).unwrap());
        assert!(store.forget(&alice).unwrap());
        assert!(!store.forget(&alice).unwrap());
        assert!(!store.knows(&alice).unwrap());
        // After UNREGISTER, signing in again is new (4.9).
        assert!(store.note_sign_in(&alice, t).unwrap());
    }

    /// A name is registered once, ever (4.7, 4.9).
    #[test]
    fn hosted_names_and_chains() {
        let store = SqliteStore::open_in_memory().unwrap();
        let now = t("2026-11-09T00:00:00.000Z");
        let alice: Name = "alice".parse().unwrap();
        let id: Identity = "alice@example.org".parse().unwrap();
        assert_eq!(store.hosted(&alice).unwrap(), None);
        let first = [record(1, Some(0)), record(2, Some(1))];
        assert!(store.register(&alice, &id, &first, now).unwrap());
        assert!(!store.register(&alice, &id, &first, now).unwrap());
        assert_eq!(store.chain_records(&id).unwrap(), first);
        assert_eq!(store.hosted_names().unwrap(), std::slice::from_ref(&alice));
        assert_eq!(
            store.hosted(&alice).unwrap(),
            Some(HostedName {
                identity: id.clone(),
                registered: now,
                unregistered: None
            })
        );

        // Records go on at the end, and only there.
        let more = [record(3, None), record(4, Some(2))];
        assert!(store.add_records(&id, 1, &more).is_err());
        store.add_records(&id, 2, &more).unwrap();
        assert_eq!(store.chain_records(&id).unwrap().len(), 4);
        // The same record twice is refused.
        assert!(store.add_records(&id, 4, &[record(1, None)]).is_err());

        let later = now.checked_add(Duration::from_secs(60)).unwrap();
        assert!(store.unregister(&id.to_uid(), later).unwrap());
        assert_eq!(
            store.hosted(&alice).unwrap().unwrap().unregistered,
            Some(later)
        );
        assert_eq!(store.hosted_names().unwrap(), std::slice::from_ref(&alice));
        // The records stay, and the name stays taken.
        assert_eq!(store.chain_records(&id).unwrap().len(), 4);
        assert!(!store.register(&alice, &id, &first, later).unwrap());
        // An identity whose records the server holds cannot be registered
        // under another name either.
        let bob: Name = "bob".parse().unwrap();
        assert!(!store.register(&bob, &id, &first, later).unwrap());
    }

    #[test]
    fn pins() {
        let store = SqliteStore::open_in_memory().unwrap();
        let now = t("2026-11-09T00:00:00.000Z");
        let id: Identity = "bob@example.net".parse().unwrap();
        assert_eq!(store.pin(&id).unwrap(), None);
        let pin = Pin {
            master_key: PublicKey::from_bytes(&[3; PUBLIC_KEY_LEN]),
            head: BlobRef::of(b"head"),
        };
        store.set_pin(&id, &pin, now).unwrap();
        assert_eq!(store.pin(&id).unwrap(), Some(pin.clone()));
        let moved = Pin {
            head: BlobRef::of(b"newer"),
            ..pin
        };
        store.set_pin(&id, &moved, now).unwrap();
        assert_eq!(store.pin(&id).unwrap(), Some(moved));
        // UNREGISTER and ADMIN UNREGISTER clear it (4.9, 10.5).
        assert!(store.unregister(&id.to_uid(), now).unwrap());
        assert_eq!(store.pin(&id).unwrap(), None);
        assert!(!store.unregister(&id.to_uid(), now).unwrap());
    }

    /// UNREGISTER deletes what the other areas keep about the identity
    /// too (4.9).
    #[test]
    fn unregister_deletes_the_other_areas_rows() {
        let store = SqliteStore::open_in_memory().unwrap();
        let now = t("2026-11-09T00:00:00.000Z");
        let alice: Uid = "alice@example.org".parse().unwrap();
        {
            let conn = store.raw();
            conn.execute("INSERT INTO presence (uid) VALUES (?)", [alice.as_str()])
                .unwrap();
            conn.execute(
                "INSERT INTO backups (uid, generation, hash, key, stored)
                 VALUES (?, 0, zeroblob(48), zeroblob(61), 0)",
                [alice.as_str()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO key_packages (uid, device, ref, key_package, not_after)
                 VALUES (?, zeroblob(48), zeroblob(48), x'00', 0)",
                [alice.as_str()],
            )
            .unwrap();
        }
        assert!(store.unregister(&alice, now).unwrap());
        let conn = store.raw();
        for table in ["presence", "backups", "key_packages"] {
            let n: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0, "{table}");
        }
    }

    /// Pairing data lives for its time, and an id holds one message (4.8).
    #[test]
    fn pairing() {
        let store = SqliteStore::open_in_memory().unwrap();
        let now = t("2026-11-09T00:00:00.000Z");
        let expires = now.checked_add(Duration::from_secs(600)).unwrap();
        let id = [9u8; 48];
        assert_eq!(store.pair_get(&id, now).unwrap(), None);
        assert_eq!(
            store.pair_put(&id, b"one", expires, now).unwrap(),
            PairPut::Stored
        );
        assert_eq!(
            store.pair_put(&id, b"one", expires, now).unwrap(),
            PairPut::Same
        );
        assert_eq!(
            store.pair_put(&id, b"two", expires, now).unwrap(),
            PairPut::Taken
        );
        assert_eq!(store.pair_get(&id, now).unwrap(), Some(b"one".to_vec()));
        // Once expired it is gone, even before it is deleted.
        assert_eq!(store.pair_get(&id, expires).unwrap(), None);
        assert_eq!(
            store
                .pair_put(
                    &id,
                    b"two",
                    expires.checked_add(Duration::from_secs(600)).unwrap(),
                    expires
                )
                .unwrap(),
            PairPut::Stored
        );
        assert_eq!(store.expire_pairing(expires).unwrap(), 0);
        assert_eq!(
            store
                .expire_pairing(expires.checked_add(Duration::from_secs(600)).unwrap())
                .unwrap(),
            1
        );
    }
}
