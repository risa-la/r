//! [`IdentityStore`] on SQLite, and the identity area's tables (4.6-4.9,
//! 10.5).

use rusqlite::{OptionalExtension as _, params};

use risala_proto::names::Uid;
use risala_proto::time::Timestamp;

use super::SqliteStore;
use crate::store::{IdentityStore, Result, millis};

/// The identity area's tables.
pub(super) const SCHEMA: &str = "
-- Identities that have signed in here and not unregistered since (4.6,
-- 4.9).
CREATE TABLE accounts (
    uid TEXT PRIMARY KEY,           -- the identity, in lower case
    first_seen INTEGER NOT NULL,    -- ms
    last_seen INTEGER NOT NULL      -- ms
) STRICT;

-- The names hosted under the identity domain (4.7). A retired name keeps
-- its row, so that it is never registered again and its key file answers
-- 410 (4.9, 10.5).
CREATE TABLE hosted (
    name TEXT PRIMARY KEY,          -- <name> of <name>@<identity domain>
    uid TEXT NOT NULL UNIQUE,       -- the whole identity
    registered INTEGER NOT NULL,    -- ms
    retired INTEGER                 -- ms, or NULL while hosted
) STRICT;

-- The chains of records the server keeps (4.4): those of the identities
-- it hosts, and of those whose key files name its log (4.7).
CREATE TABLE records (
    uid TEXT NOT NULL,
    position INTEGER NOT NULL,      -- 0 for the chain's first record
    record BLOB NOT NULL,           -- the encoded Record
    hash BLOB NOT NULL UNIQUE,      -- its SHA-384 hash, as in RECORD (4.7)
    log_index INTEGER UNIQUE,       -- its index in log_entries, once logged
    PRIMARY KEY (uid, position)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts() {
        let store = SqliteStore::open_in_memory().unwrap();
        let alice: Uid = "alice@example.org".parse().unwrap();
        let t: Timestamp = "2026-11-09T00:00:00.000Z".parse().unwrap();
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
}
