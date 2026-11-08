//! [`E2eeStore`] on SQLite.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use risala_proto::auth::PublicKey;
use risala_proto::mls::{BackupBlob, KeyPackage, RatchetTree, Welcome};
use risala_proto::names::{Conv, Id, Seq, Uid};
use risala_proto::time::Timestamp;

use super::{SqliteStore, corrupt, ms, parse, seq, sql_seq};
use crate::store::{
    BackupAdded, BackupPage, ConvKey, E2eeStore, KeyPackageAdded, KeyPackageCount, NewKeyPackage,
    PendingWelcome, Result, StoreError, random_id,
};

/// An epoch as SQLite stores it. Epochs from commands are at most 2^63-1
/// (12.10), so this fails only for one that is not.
fn sql_epoch(epoch: u64) -> Result<i64> {
    i64::try_from(epoch).map_err(|_| corrupt("epoch", epoch))
}

/// Deletes the Welcome and tree of each commit that no device has pending
/// any more (12.7).
/// Stores a commit's Welcome as pending for each of `devices`, in `tx`
/// (see [`E2eeStore::add_welcomes`]).
pub(super) fn add_welcomes_in(
    tx: &Transaction<'_>,
    conv: ConvKey,
    seq: Seq,
    welcome: &Welcome,
    tree: &RatchetTree,
    devices: &[(Uid, PublicKey)],
) -> Result<Vec<Id>> {
    if devices.is_empty() {
        return Ok(Vec::new());
    }
    tx.execute(
        "INSERT INTO welcome_commits (conv, seq, welcome, tree) VALUES (?, ?, ?, ?)",
        params![conv.0, sql_seq(seq), welcome.as_str(), tree.as_str()],
    )?;
    let n = tx.last_insert_rowid();
    let mut ids = Vec::with_capacity(devices.len());
    for (uid, key) in devices {
        let device = key.to_string();
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM pending_welcomes \
                 WHERE uid = ? AND device_key = ? AND commit_n = ?",
                params![uid.as_str(), device, n],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            ids.push(parse("Welcome id", &id)?);
            continue;
        }
        // Ids are random: one that is taken, however unlikely, is made
        // again.
        let id = loop {
            let id = random_id()?;
            let added = tx.execute(
                "INSERT OR IGNORE INTO pending_welcomes (id, commit_n, uid, device_key) \
                 VALUES (?, ?, ?, ?)",
                params![id.as_str(), n, uid.as_str(), device],
            )?;
            if added > 0 {
                break id;
            }
        };
        ids.push(id);
    }
    Ok(ids)
}

pub(super) fn prune_welcome_commits(tx: &Transaction<'_>) -> Result<()> {
    tx.execute(
        "DELETE FROM welcome_commits WHERE NOT EXISTS \
         (SELECT 1 FROM pending_welcomes p WHERE p.commit_n = welcome_commits.n)",
        [],
    )?;
    Ok(())
}

fn key_list(conn: &Connection, sql: &str, args: impl rusqlite::Params) -> Result<Vec<PublicKey>> {
    conn.prepare_cached(sql)?
        .query_map(args, |row| row.get::<_, String>(0))?
        .map(|key| parse("device key", &key?))
        .collect()
}

impl E2eeStore for SqliteStore {
    fn add_key_package(
        &self,
        uid: &Uid,
        key: &PublicKey,
        kp: &NewKeyPackage,
        max: usize,
        now: Timestamp,
    ) -> Result<KeyPackageAdded> {
        let device = key.to_string();
        self.write(|tx| {
            tx.execute(
                "DELETE FROM key_packages WHERE uid = ? AND device_key = ? AND not_after <= ?",
                params![uid.as_str(), device, ms(now)],
            )?;
            let known: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM key_packages \
                 WHERE uid = ? AND device_key = ? AND kp_ref = ?)",
                params![uid.as_str(), device, kp.kp_ref],
                |row| row.get(0),
            )?;
            if known {
                return Ok(KeyPackageAdded::Already);
            }
            if kp.last_resort {
                tx.execute(
                    "DELETE FROM key_packages \
                     WHERE uid = ? AND device_key = ? AND last_resort = 1",
                    params![uid.as_str(), device],
                )?;
            } else {
                let count: i64 = tx.query_row(
                    "SELECT count(*) FROM key_packages \
                     WHERE uid = ? AND device_key = ? AND last_resort = 0",
                    params![uid.as_str(), device],
                    |row| row.get(0),
                )?;
                if count as u64 >= max as u64 {
                    return Ok(KeyPackageAdded::Full);
                }
            }
            tx.execute(
                "INSERT INTO key_packages \
                 (uid, device_key, kp_ref, key_package, last_resort, not_after, added) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    uid.as_str(),
                    device,
                    kp.kp_ref,
                    kp.key_package.as_str(),
                    kp.last_resort,
                    ms(kp.not_after),
                    ms(now)
                ],
            )?;
            Ok(KeyPackageAdded::Added)
        })
    }

    fn key_package_count(
        &self,
        uid: &Uid,
        key: &PublicKey,
        now: Timestamp,
    ) -> Result<KeyPackageCount> {
        let (ordinary, last_resort): (i64, i64) = self.conn().query_row(
            "SELECT count(*) FILTER (WHERE last_resort = 0), \
                    count(*) FILTER (WHERE last_resort = 1) \
             FROM key_packages WHERE uid = ? AND device_key = ? AND not_after > ?",
            params![uid.as_str(), key.to_string(), ms(now)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(KeyPackageCount {
            ordinary: ordinary as u64,
            last_resort: last_resort > 0,
        })
    }

    fn key_package_devices(&self, uid: &Uid, now: Timestamp) -> Result<Vec<PublicKey>> {
        key_list(
            &self.conn(),
            "SELECT DISTINCT device_key FROM key_packages \
             WHERE uid = ? AND not_after > ? ORDER BY device_key",
            params![uid.as_str(), ms(now)],
        )
    }

    fn take_key_packages(
        &self,
        uid: &Uid,
        except: Option<&PublicKey>,
        listed: &[PublicKey],
        now: Timestamp,
    ) -> Result<Vec<(PublicKey, KeyPackage)>> {
        let except = except.map(PublicKey::to_string);
        let listed: Vec<String> = listed.iter().map(PublicKey::to_string).collect();
        self.write(|tx| {
            let devices: Vec<String> = tx
                .prepare_cached(
                    "SELECT DISTINCT device_key FROM key_packages \
                     WHERE uid = ? AND not_after > ? ORDER BY device_key",
                )?
                .query_map(params![uid.as_str(), ms(now)], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let mut taken = Vec::new();
            for device in devices {
                if except.as_ref() == Some(&device) || !listed.contains(&device) {
                    continue;
                }
                // The oldest ordinary one, else the last-resort one, which
                // sorts after every ordinary one.
                let found: Option<(i64, bool, String)> = tx
                    .query_row(
                        "SELECT n, last_resort, key_package FROM key_packages \
                         WHERE uid = ? AND device_key = ? AND not_after > ? \
                         ORDER BY last_resort, n LIMIT 1",
                        params![uid.as_str(), device, ms(now)],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                let Some((n, last_resort, key_package)) = found else {
                    continue;
                };
                if !last_resort {
                    tx.execute("DELETE FROM key_packages WHERE n = ?", [n])?;
                }
                taken.push((
                    parse("device key", &device)?,
                    parse("KeyPackage", &key_package)?,
                ));
            }
            Ok(taken)
        })
    }

    fn prune_key_packages(&self, now: Timestamp) -> Result<u64> {
        self.write(|tx| {
            let n = tx.execute("DELETE FROM key_packages WHERE not_after <= ?", [ms(now)])?;
            Ok(n as u64)
        })
    }

    fn add_welcomes(
        &self,
        conv: ConvKey,
        seq: Seq,
        welcome: &Welcome,
        tree: &RatchetTree,
        devices: &[(Uid, PublicKey)],
    ) -> Result<Vec<Id>> {
        if devices.is_empty() {
            return Ok(Vec::new());
        }
        self.write(|tx| add_welcomes_in(tx, conv, seq, welcome, tree, devices))
    }

    fn pending_welcomes(&self, uid: &Uid, key: &PublicKey) -> Result<Vec<Id>> {
        self.conn()
            .prepare_cached(
                "SELECT p.id FROM pending_welcomes p \
                 JOIN welcome_commits w ON w.n = p.commit_n \
                 JOIN conversations c ON c.conv = w.conv \
                 WHERE p.uid = ? AND p.device_key = ? AND c.dropping = 0 \
                 ORDER BY p.commit_n",
            )?
            .query_map(params![uid.as_str(), key.to_string()], |row| {
                row.get::<_, String>(0)
            })?
            .map(|id| parse("Welcome id", &id?))
            .collect()
    }

    fn pending_welcome(
        &self,
        uid: &Uid,
        key: &PublicKey,
        id: &Id,
    ) -> Result<Option<PendingWelcome>> {
        type Row = (
            i64,
            Option<String>,
            Option<String>,
            Option<String>,
            i64,
            String,
            String,
        );
        let row: Option<Row> = self
            .conn()
            .query_row(
                "SELECT c.conv, c.room, c.uid_a, c.uid_b, w.seq, w.welcome, w.tree \
                 FROM pending_welcomes p \
                 JOIN welcome_commits w ON w.n = p.commit_n \
                 JOIN conversations c ON c.conv = w.conv \
                 WHERE p.id = ? AND p.uid = ? AND p.device_key = ? AND c.dropping = 0",
                params![id.as_str(), uid.as_str(), key.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((conv_key, room, uid_a, uid_b, s, welcome, tree)) = row else {
            return Ok(None);
        };
        // A direct conversation is named by the other participant, or by
        // the identity itself in a conversation with itself (5.2).
        let conv = match (room, uid_a, uid_b) {
            (Some(room), _, _) => Conv::Room(parse("room", &room)?),
            (None, Some(a), Some(b)) => {
                let other = if a == uid.as_str() { b } else { a };
                Conv::Uid(parse("uid", &other)?)
            }
            _ => {
                return Err(StoreError::Corrupt(format!(
                    "conversation {conv_key} has no name"
                )));
            }
        };
        Ok(Some(PendingWelcome {
            id: id.clone(),
            conv,
            conv_key: ConvKey(conv_key),
            seq: seq(s)?,
            welcome: parse("Welcome", &welcome)?,
            tree: parse("ratchet tree", &tree)?,
        }))
    }

    fn delete_welcome(&self, uid: &Uid, key: &PublicKey, id: &Id) -> Result<bool> {
        self.write(|tx| {
            let deleted = tx.execute(
                "DELETE FROM pending_welcomes WHERE id = ? AND uid = ? AND device_key = ?",
                params![id.as_str(), uid.as_str(), key.to_string()],
            )?;
            prune_welcome_commits(tx)?;
            Ok(deleted > 0)
        })
    }

    fn stored_devices(&self, uid: &Uid) -> Result<Vec<PublicKey>> {
        key_list(
            &self.conn(),
            "SELECT device_key FROM key_packages WHERE uid = ?1 \
             UNION SELECT device_key FROM pending_welcomes WHERE uid = ?1 \
             UNION SELECT device_key FROM group_leaves l WHERE uid = ?1 AND NOT EXISTS \
                 (SELECT 1 FROM removed_keys r WHERE r.uid = l.uid \
                  AND r.device_key = l.device_key) \
             ORDER BY 1",
            [uid.as_str()],
        )
    }

    fn forget_device(&self, uid: &Uid, key: &PublicKey) -> Result<()> {
        let device = key.to_string();
        self.write(|tx| {
            for sql in [
                "DELETE FROM key_packages WHERE uid = ? AND device_key = ?",
                "DELETE FROM pending_welcomes WHERE uid = ? AND device_key = ?",
                // Its leaves must go before anyone sends again (12.6).
                "INSERT OR IGNORE INTO removed_keys (uid, device_key) VALUES (?, ?)",
            ] {
                tx.execute(sql, params![uid.as_str(), device])?;
            }
            prune_welcome_commits(tx)
        })
    }

    fn relist_keys(&self, uid: &Uid, keys: &[PublicKey]) -> Result<()> {
        self.write(|tx| {
            let mut delete =
                tx.prepare_cached("DELETE FROM removed_keys WHERE uid = ? AND device_key = ?")?;
            for key in keys {
                delete.execute(params![uid.as_str(), key.to_string()])?;
            }
            Ok(())
        })
    }

    fn add_backup(
        &self,
        uid: &Uid,
        conv_id: &Id,
        epoch: u64,
        blob: &BackupBlob,
        max_per_epoch: usize,
    ) -> Result<BackupAdded> {
        let epoch = sql_epoch(epoch)?;
        self.write(|tx| {
            let (count, same): (i64, bool) = tx.query_row(
                "SELECT count(*), coalesce(max(key_id = ?4), 0) FROM backups \
                 WHERE uid = ?1 AND conv_id = ?2 AND epoch = ?3",
                params![uid.as_str(), conv_id.as_str(), epoch, &blob.key_id()[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if same {
                return Ok(BackupAdded::Kept);
            }
            if count as u64 >= max_per_epoch as u64 {
                return Ok(BackupAdded::Full);
            }
            tx.execute(
                "INSERT INTO backups (uid, conv_id, epoch, key_id, blob) VALUES (?, ?, ?, ?, ?)",
                params![
                    uid.as_str(),
                    conv_id.as_str(),
                    epoch,
                    &blob.key_id()[..],
                    &blob.as_bytes()[..]
                ],
            )?;
            Ok(BackupAdded::Added)
        })
    }

    fn backups(
        &self,
        uid: &Uid,
        conv_id: &Id,
        after: Option<u64>,
        max_epochs: u64,
        max_blobs: usize,
    ) -> Result<BackupPage> {
        let from = match after {
            None => 0,
            Some(after) => match i64::try_from(after) {
                // No epoch is later than 2^63-1.
                Ok(i64::MAX) | Err(_) => {
                    return Ok(BackupPage {
                        blobs: Vec::new(),
                        more: false,
                    });
                }
                Ok(after) => after + 1,
            },
        };
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT epoch, blob FROM backups WHERE uid = ? AND conv_id = ? AND epoch >= ? \
             ORDER BY epoch, key_id",
        )?;
        let mut rows = stmt.query(params![uid.as_str(), conv_id.as_str(), from])?;
        let mut blobs: Vec<(u64, BackupBlob)> = Vec::new();
        // Where the epoch being read starts in `blobs`, and how many epochs
        // came before it.
        let (mut start, mut epochs) = (0, 0u64);
        let mut more = false;
        while let Some(row) = rows.next()? {
            let epoch: i64 = row.get(0)?;
            let bytes: Vec<u8> = row.get(1)?;
            let epoch = u64::try_from(epoch).map_err(|_| corrupt("epoch", epoch))?;
            let blob: [u8; risala_proto::mls::BACKUP_BLOB_LEN] = bytes
                .try_into()
                .map_err(|b: Vec<u8>| corrupt("backup blob length", b.len()))?;
            let new_epoch = blobs.last().is_none_or(|(last, _)| *last != epoch);
            if new_epoch {
                if epochs == max_epochs {
                    more = true;
                    break;
                }
                start = blobs.len();
                epochs += 1;
            }
            if blobs.len() >= max_blobs && start > 0 {
                // This epoch does not fit whole: the page ends before it.
                blobs.truncate(start);
                more = true;
                break;
            }
            blobs.push((epoch, BackupBlob::from_bytes(blob)));
        }
        Ok(BackupPage { blobs, more })
    }

    fn delete_backups(&self, uid: &Uid, conv_id: Option<&Id>) -> Result<u64> {
        self.write(|tx| {
            let n = match conv_id {
                Some(id) => tx.execute(
                    "DELETE FROM backups WHERE uid = ? AND conv_id = ?",
                    params![uid.as_str(), id.as_str()],
                )?,
                None => tx.execute("DELETE FROM backups WHERE uid = ?", [uid.as_str()])?,
            };
            Ok(n as u64)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use risala_proto::auth::SecretKey;

    use super::*;
    use crate::store::{ReportStore, Store};

    fn t() -> Timestamp {
        "2026-11-06T15:40:58.120Z".parse().unwrap()
    }

    fn later(secs: u64) -> Timestamp {
        t().checked_add(Duration::from_secs(secs)).unwrap()
    }

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    fn key(n: u8) -> PublicKey {
        SecretKey::from_seed([n; 32]).public_key()
    }

    /// An ordinary KeyPackage whose lifetime ends an hour from `t()`. Its
    /// bytes are `n` repeated, and so is its ref.
    fn kp(n: u8) -> NewKeyPackage {
        NewKeyPackage {
            key_package: KeyPackage::from_bytes(&[n; 6]).unwrap(),
            kp_ref: vec![n; 4],
            not_after: later(3600),
            last_resort: false,
        }
    }

    fn last_resort(n: u8) -> NewKeyPackage {
        NewKeyPackage {
            last_resort: true,
            ..kp(n)
        }
    }

    fn count(s: &SqliteStore, who: &Uid, k: &PublicKey, now: Timestamp) -> (u64, bool) {
        let c = s.key_package_count(who, k, now).unwrap();
        (c.ordinary, c.last_resort)
    }

    /// The bytes of each KeyPackage taken, by device key number.
    fn take(
        s: &SqliteStore,
        who: &Uid,
        except: Option<u8>,
        listed: &[u8],
        now: Timestamp,
    ) -> Vec<(PublicKey, u8)> {
        let listed: Vec<PublicKey> = listed.iter().map(|n| key(*n)).collect();
        s.take_key_packages(who, except.map(key).as_ref(), &listed, now)
            .unwrap()
            .into_iter()
            .map(|(k, kp)| (k, kp.decode()[0]))
            .collect()
    }

    #[test]
    fn key_packages_are_handed_out_once_then_the_last_resort_one() {
        let s = SqliteStore::open_in_memory().unwrap();
        let alice = uid("alice@example.org");
        let (k1, k2) = (key(1), key(2));
        for n in [10, 11] {
            assert_eq!(
                s.add_key_package(&alice, &k1, &kp(n), 100, t()).unwrap(),
                KeyPackageAdded::Added
            );
        }
        // The same ref again stores nothing.
        assert_eq!(
            s.add_key_package(&alice, &k1, &kp(10), 100, t()).unwrap(),
            KeyPackageAdded::Already
        );
        s.add_key_package(&alice, &k1, &last_resort(19), 100, t())
            .unwrap();
        // A new last-resort one replaces the old.
        s.add_key_package(&alice, &k1, &last_resort(18), 100, t())
            .unwrap();
        s.add_key_package(&alice, &k2, &kp(20), 100, t()).unwrap();
        assert_eq!(count(&s, &alice, &k1, t()), (2, true));
        assert_eq!(count(&s, &alice, &k2, t()), (1, false));
        assert_eq!(s.key_package_devices(&alice, t()).unwrap().len(), 2);

        // Oldest first, deleted once handed out.
        let mut got = take(&s, &alice, None, &[1, 2], t());
        got.sort_by_key(|(_, n)| *n);
        assert_eq!(got, [(k1.clone(), 10), (k2.clone(), 20)]);
        assert_eq!(take(&s, &alice, None, &[1, 2], t()), [(k1.clone(), 11)]);
        // Then the last-resort one, which stays.
        for _ in 0..2 {
            assert_eq!(take(&s, &alice, None, &[1, 2], t()), [(k1.clone(), 18)]);
        }
        assert_eq!(count(&s, &alice, &k1, t()), (0, true));
        assert!(take(&s, &uid("bob@example.org"), None, &[1, 2], t()).is_empty());
    }

    #[test]
    fn taking_leaves_out_the_asker_and_unlisted_devices() {
        let s = SqliteStore::open_in_memory().unwrap();
        let alice = uid("alice@example.org");
        for n in 1..=3 {
            s.add_key_package(&alice, &key(n), &kp(n), 100, t())
                .unwrap();
        }
        // Device 1 asks; device 3's key is not in the key file.
        assert_eq!(
            take(&s, &alice, Some(1), &[1, 2], t()),
            [(key(2), 2)],
            "only device 2"
        );
        assert_eq!(count(&s, &alice, &key(1), t()), (1, false));
        assert_eq!(count(&s, &alice, &key(3), t()), (1, false));
    }

    #[test]
    fn key_packages_expire_and_are_limited_per_device() {
        let s = SqliteStore::open_in_memory().unwrap();
        let alice = uid("alice@example.org");
        let k = key(1);
        for n in 1..=3 {
            s.add_key_package(&alice, &k, &kp(n), 3, t()).unwrap();
        }
        assert_eq!(
            s.add_key_package(&alice, &k, &kp(4), 3, t()).unwrap(),
            KeyPackageAdded::Full
        );
        // The last-resort one does not count.
        assert_eq!(
            s.add_key_package(&alice, &k, &last_resort(5), 3, t())
                .unwrap(),
            KeyPackageAdded::Added
        );
        // One that ends later than the others.
        let long = NewKeyPackage {
            not_after: later(7200),
            ..kp(6)
        };
        // An hour on, the first three and the last-resort one have ended:
        // they are not counted or handed out, and adding deletes them.
        let hour = later(3600);
        assert_eq!(count(&s, &alice, &k, hour), (0, false));
        assert!(take(&s, &alice, None, &[1], hour).is_empty());
        assert_eq!(
            s.add_key_package(&alice, &k, &long, 3, hour).unwrap(),
            KeyPackageAdded::Added
        );
        assert_eq!(count(&s, &alice, &k, t()), (1, false));
        // Pruning deletes the ended ones of every device.
        s.add_key_package(&alice, &key(2), &kp(7), 3, t()).unwrap();
        assert_eq!(s.prune_key_packages(hour).unwrap(), 1);
        assert_eq!(s.key_package_devices(&alice, t()).unwrap(), [k]);
    }

    fn welcome(n: u8) -> Welcome {
        Welcome::from_bytes(&[n; 3]).unwrap()
    }

    fn tree(n: u8) -> RatchetTree {
        RatchetTree::from_bytes(&[n; 3]).unwrap()
    }

    /// Rows in `welcome_commits`.
    fn commits(s: &SqliteStore) -> i64 {
        s.conn()
            .query_row("SELECT count(*) FROM welcome_commits", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn welcomes_are_pending_per_device_until_deleted() {
        let s = SqliteStore::open_in_memory().unwrap();
        let room = s.ensure_room(&"#e2ee".parse().unwrap(), t()).unwrap();
        let (alice, bob) = (uid("alice@example.org"), uid("bob@example.net"));
        let seq1 = Seq::new(5).unwrap();
        let ids = s
            .add_welcomes(
                room.key,
                seq1,
                &welcome(1),
                &tree(1),
                &[
                    (alice.clone(), key(1)),
                    (bob.clone(), key(2)),
                    (alice.clone(), key(1)),
                ],
            )
            .unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0], ids[2], "one Welcome per device");
        assert_ne!(ids[0], ids[1]);
        let ids2 = s
            .add_welcomes(
                room.key,
                Seq::new(9).unwrap(),
                &welcome(2),
                &tree(2),
                &[(alice.clone(), key(1))],
            )
            .unwrap();
        assert!(
            s.add_welcomes(room.key, seq1, &welcome(3), &tree(3), &[])
                .unwrap()
                .is_empty()
        );
        assert_eq!(commits(&s), 2);

        assert_eq!(
            s.pending_welcomes(&alice, &key(1)).unwrap(),
            [ids[0].clone(), ids2[0].clone()]
        );
        assert!(s.pending_welcomes(&alice, &key(2)).unwrap().is_empty());
        let w = s.pending_welcome(&bob, &key(2), &ids[1]).unwrap().unwrap();
        assert_eq!(w.conv, Conv::Room("#e2ee".parse().unwrap()));
        assert_eq!((w.seq, w.welcome, w.tree), (seq1, welcome(1), tree(1)));
        // Not another device's.
        assert!(s.pending_welcome(&bob, &key(1), &ids[1]).unwrap().is_none());
        assert!(!s.delete_welcome(&bob, &key(1), &ids[1]).unwrap());

        // The commit's Welcome and tree stay while any device has it.
        assert!(s.delete_welcome(&alice, &key(1), &ids[0]).unwrap());
        assert!(!s.delete_welcome(&alice, &key(1), &ids[0]).unwrap());
        assert_eq!(commits(&s), 2);
        assert!(s.delete_welcome(&bob, &key(2), &ids[1]).unwrap());
        assert_eq!(commits(&s), 1);

        // A device that goes takes its Welcomes and KeyPackages with it.
        s.add_key_package(&alice, &key(1), &kp(1), 100, t())
            .unwrap();
        s.add_key_package(&alice, &key(3), &kp(3), 100, t())
            .unwrap();
        assert_eq!(s.stored_devices(&alice).unwrap().len(), 2);
        s.forget_device(&alice, &key(1)).unwrap();
        assert_eq!(s.stored_devices(&alice).unwrap(), [key(3)]);
        assert!(s.pending_welcomes(&alice, &key(1)).unwrap().is_empty());
        assert_eq!(commits(&s), 0);
    }

    #[test]
    fn welcomes_of_a_dropped_room_go_with_it() {
        let s = SqliteStore::open_in_memory().unwrap();
        let room = s.ensure_room(&"#e2ee".parse().unwrap(), t()).unwrap();
        let alice = uid("alice@example.org");
        let ids = s
            .add_welcomes(
                room.key,
                Seq::new(1).unwrap(),
                &welcome(1),
                &tree(1),
                &[(alice.clone(), key(1))],
            )
            .unwrap();
        s.drop_room(room.key, false, t()).unwrap();
        assert!(s.pending_welcomes(&alice, &key(1)).unwrap().is_empty());
        assert!(
            s.pending_welcome(&alice, &key(1), &ids[0])
                .unwrap()
                .is_none()
        );
        assert_eq!(commits(&s), 0);
    }

    #[test]
    fn welcomes_name_a_direct_conversation_by_the_other_participant() {
        let s = SqliteStore::open_in_memory().unwrap();
        let (alice, bob) = (uid("alice@example.org"), uid("bob@example.net"));
        // Made by hand, without groups.
        let conn = s.conn();
        let make = |id: &str, a: &Uid, b: &Uid| {
            conn.execute(
                "INSERT INTO used_ids (id, kind, created) VALUES (?, 'conversation', 0)",
                [id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO conversations (id, kind, uid_a, uid_b, created) \
                 VALUES (?, 'direct', ?, ?, 0)",
                params![id, a.as_str(), b.as_str()],
            )
            .unwrap();
            ConvKey(conn.last_insert_rowid())
        };
        let pair = make("d1", &alice, &bob);
        let own = make("d2", &alice, &alice);
        drop(conn);
        let seq = Seq::new(1).unwrap();
        let both = [(alice.clone(), key(1)), (bob.clone(), key(2))];
        let ids = s
            .add_welcomes(pair, seq, &welcome(1), &tree(1), &both)
            .unwrap();
        let conv =
            |who: &Uid, k: u8, id: &Id| s.pending_welcome(who, &key(k), id).unwrap().unwrap().conv;
        assert_eq!(conv(&alice, 1, &ids[0]), Conv::Uid(bob.clone()));
        assert_eq!(conv(&bob, 2, &ids[1]), Conv::Uid(alice.clone()));
        let ids = s
            .add_welcomes(own, seq, &welcome(1), &tree(1), &both[..1])
            .unwrap();
        assert_eq!(conv(&alice, 1, &ids[0]), Conv::Uid(alice.clone()));
    }

    fn blob(key_id: u8, n: u8) -> BackupBlob {
        let mut b = [n; 84];
        b[..8].copy_from_slice(&[key_id; 8]);
        BackupBlob::from_bytes(b)
    }

    /// Each blob of a page as (epoch, key id, filler).
    fn page(p: &BackupPage) -> Vec<(u64, u8, u8)> {
        p.blobs
            .iter()
            .map(|(e, b)| (*e, b.as_bytes()[0], b.as_bytes()[8]))
            .collect()
    }

    #[test]
    fn backups_keep_the_first_blob_of_a_key_id() {
        let s = SqliteStore::open_in_memory().unwrap();
        let alice = uid("alice@example.org");
        let conv: Id = "k3f9q2".parse().unwrap();
        let add = |epoch, b: &BackupBlob| s.add_backup(&alice, &conv, epoch, b, 2).unwrap();
        assert_eq!(add(0, &blob(1, 1)), BackupAdded::Added);
        assert_eq!(add(0, &blob(1, 2)), BackupAdded::Kept);
        assert_eq!(add(0, &blob(2, 3)), BackupAdded::Added);
        assert_eq!(add(0, &blob(3, 4)), BackupAdded::Full);
        // At most 2^63-1.
        assert!(
            s.add_backup(&alice, &conv, u64::MAX, &blob(1, 1), 2)
                .is_err()
        );
        let p = s.backups(&alice, &conv, None, 500, 1000).unwrap();
        assert_eq!(page(&p), [(0, 1, 1), (0, 2, 3)]);
        assert!(!p.more);
        // Only the identity's own, of that conversation.
        let other: Id = "other".parse().unwrap();
        assert!(
            s.backups(&alice, &other, None, 500, 1000)
                .unwrap()
                .blobs
                .is_empty()
        );
        let bob = uid("bob@example.org");
        assert!(
            s.backups(&bob, &conv, None, 500, 1000)
                .unwrap()
                .blobs
                .is_empty()
        );
    }

    #[test]
    fn backup_pages_hold_whole_epochs() {
        let s = SqliteStore::open_in_memory().unwrap();
        let alice = uid("alice@example.org");
        let conv: Id = "k3f9q2".parse().unwrap();
        // Epochs 0, 1 and 2 have one blob; 3 has three; 7 has one.
        for (epoch, key_id) in [(0, 1), (1, 1), (2, 1), (3, 1), (3, 2), (3, 3), (7, 1)] {
            s.add_backup(&alice, &conv, epoch, &blob(key_id, epoch as u8), 8)
                .unwrap();
        }
        let get = |after, epochs, blobs| s.backups(&alice, &conv, after, epochs, blobs).unwrap();
        let p = get(None, 2, 100);
        assert_eq!(page(&p), [(0, 1, 0), (1, 1, 1)]);
        assert!(p.more);
        let p = get(Some(1), 2, 100);
        assert_eq!(page(&p), [(2, 1, 2), (3, 1, 3), (3, 2, 3), (3, 3, 3)]);
        assert!(p.more);
        let p = get(Some(3), 2, 100);
        assert_eq!(page(&p), [(7, 1, 7)]);
        assert!(!p.more);
        assert!(get(Some(7), 2, 100).blobs.is_empty());
        assert!(get(Some(u64::MAX), 2, 100).blobs.is_empty());
        // Epoch 3 does not fit in four blobs after epoch 2: the page ends
        // before it.
        let p = get(Some(1), 100, 3);
        assert_eq!(page(&p), [(2, 1, 2)]);
        assert!(p.more);
        // But a first epoch is always whole.
        let p = get(Some(2), 100, 2);
        assert_eq!(page(&p), [(3, 1, 3), (3, 2, 3), (3, 3, 3)]);
        assert!(p.more);

        let other: Id = "other".parse().unwrap();
        s.add_backup(&alice, &other, 0, &blob(1, 0), 8).unwrap();
        assert_eq!(s.delete_backups(&alice, Some(&conv)).unwrap(), 7);
        assert_eq!(s.delete_backups(&alice, None).unwrap(), 1);
    }

    #[test]
    fn forgetting_an_identity_deletes_its_e2ee_data() {
        let s = SqliteStore::open_in_memory().unwrap();
        let room = s.ensure_room(&"#e2ee".parse().unwrap(), t()).unwrap();
        let (alice, bob) = (uid("alice@example.org"), uid("bob@example.org"));
        let conv: Id = "k3f9q2".parse().unwrap();
        for who in [&alice, &bob] {
            s.add_key_package(who, &key(1), &kp(1), 100, t()).unwrap();
            s.add_backup(who, &conv, 0, &blob(1, 1), 8).unwrap();
        }
        let both = [(alice.clone(), key(1)), (bob.clone(), key(1))];
        s.add_welcomes(room.key, Seq::new(1).unwrap(), &welcome(1), &tree(1), &both)
            .unwrap();
        let only_alice = [(alice.clone(), key(1))];
        s.add_welcomes(
            room.key,
            Seq::new(2).unwrap(),
            &welcome(2),
            &tree(2),
            &only_alice,
        )
        .unwrap();
        s.forget_identity(&alice, false, t()).unwrap();
        assert!(s.stored_devices(&alice).unwrap().is_empty());
        assert!(
            s.backups(&alice, &conv, None, 500, 100)
                .unwrap()
                .blobs
                .is_empty()
        );
        // Bob's stay, with the Welcome he still has pending.
        assert_eq!(s.stored_devices(&bob).unwrap(), [key(1)]);
        assert_eq!(
            s.backups(&bob, &conv, None, 500, 100).unwrap().blobs.len(),
            1
        );
        assert_eq!(commits(&s), 1);
    }
}
