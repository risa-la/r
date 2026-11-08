//! [`KeysStore`] on SQLite, and the tables of KeyPackages, Welcomes,
//! blobs, uploads and backups (5.6, 12.5, 12.8, 12.12, 12.13).

use rusqlite::{OptionalExtension as _, Transaction, params};

use risala_proto::binary::WrappedKey;
use risala_proto::names::{BlobRef, Uid};
use risala_proto::time::Timestamp;

use super::SqliteStore;
use crate::store::{BackupRecord, KeysStore, Result, StoreError, fixed, millis};

/// The keys area's tables.
pub(super) const SCHEMA: &str = "
-- KeyPackages (12.5), until handed out or their lifetime ends. A device
-- has at most one last-resort KeyPackage, which stays when handed out.
CREATE TABLE key_packages (
    id INTEGER PRIMARY KEY,
    uid TEXT NOT NULL,              -- the device's identity
    device BLOB NOT NULL CHECK (length(device) = 48), -- its device id (4.4)
    ref BLOB NOT NULL UNIQUE CHECK (length(ref) = 48), -- its KeyPackageRef (12.8)
    key_package BLOB NOT NULL,      -- the MLSMessage
    last_resort INTEGER NOT NULL DEFAULT 0 CHECK (last_resort IN (0, 1)),
    not_after INTEGER NOT NULL      -- ms, when its lifetime ends
) STRICT;
CREATE INDEX key_packages_device ON key_packages (uid, device, last_resort);
CREATE UNIQUE INDEX key_packages_last_resort ON key_packages (device) WHERE last_resort = 1;
CREATE INDEX key_packages_not_after ON key_packages (not_after);

-- The KeyPackageRefs a Welcome may be put for (12.8): those KEYPKG GET
-- handed out, for a device, and those of external Add proposals in public
-- rooms, for WELCOME GET.
CREATE TABLE handed_out (
    ref BLOB PRIMARY KEY CHECK (length(ref) = 48),
    uid TEXT,                       -- the device's identity...
    device BLOB CHECK (length(device) = 48), -- ...and device id, from KEYPKG GET
    box BLOB CHECK (length(box) = 16), -- or the public room of an external proposal
    handed INTEGER NOT NULL,        -- ms; forgotten after retention (7.5)
    CHECK ((device IS NULL) != (box IS NULL))
) STRICT;
CREATE INDEX handed_out_device ON handed_out (device);

-- Welcomes waiting for their device, or for WELCOME GET (12.8).
CREATE TABLE welcomes (
    id TEXT PRIMARY KEY,            -- the id the server gave it (3.5)
    ref BLOB NOT NULL REFERENCES handed_out (ref) ON DELETE CASCADE,
    welcome BLOB NOT NULL,          -- the Welcome, or its blob's hash
    is_blob INTEGER NOT NULL DEFAULT 0,
    received INTEGER NOT NULL       -- ms; deleted after retention (7.5)
) STRICT;
CREATE INDEX welcomes_ref ON welcomes (ref);

-- Blobs (12.12). Their bytes are in files named by their hash.
CREATE TABLE blobs (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 48),
    size INTEGER NOT NULL CHECK (size >= 0),
    stored INTEGER NOT NULL,        -- ms, from which retention counts (7.5)
    kept INTEGER NOT NULL DEFAULT 0 -- kept whatever the retention: a current
                                    -- backup or public room tree (12.12, 12.13)
) STRICT;

-- The put URLs BLOB handed out (12.12), for 10 minutes. A URL is looked up
-- by its public part; its secret part is a bearer secret, kept as a hash
-- (Section 14).
CREATE TABLE blob_puts (
    id TEXT PRIMARY KEY,            -- the URL's public part
    secret_hash BLOB NOT NULL CHECK (length(secret_hash) = 48),
    hash BLOB NOT NULL CHECK (length(hash) = 48), -- the blob it is for
    size INTEGER NOT NULL,
    expires INTEGER NOT NULL        -- ms
) STRICT;

-- Uploaded files (5.6): their put, get and del URLs share a public part,
-- and each has a secret part kept as a hash (Section 14).
CREATE TABLE uploads (
    id TEXT PRIMARY KEY,            -- the URLs' public part
    box BLOB NOT NULL CHECK (length(box) = 16), -- the mailbox it was for
    put_hash BLOB NOT NULL CHECK (length(put_hash) = 48),
    get_hash BLOB NOT NULL CHECK (length(get_hash) = 48),
    del_hash BLOB NOT NULL CHECK (length(del_hash) = 48),
    size INTEGER NOT NULL CHECK (size >= 0),
    created INTEGER NOT NULL,       -- ms; put works for 10 minutes from here
    stored INTEGER                  -- ms when the PUT finished, from which
                                    -- retention counts; NULL until then
) STRICT;

-- Each identity's backup (12.13).
CREATE TABLE backups (
    uid TEXT PRIMARY KEY,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    hash BLOB NOT NULL CHECK (length(hash) = 48), -- the archive's blob
    key BLOB NOT NULL CHECK (length(key) = 60), -- the wrapped key
    stored INTEGER NOT NULL         -- ms
) STRICT;
";

/// The backup of `uid`, in a transaction.
fn backup_in(tx: &Transaction<'_>, uid: &Uid) -> Result<Option<BackupRecord>> {
    let row = tx
        .query_row(
            "SELECT generation, hash, key FROM backups WHERE uid = ?",
            [uid.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((generation, hash, key)) = row else {
        return Ok(None);
    };
    Ok(Some(BackupRecord {
        generation: u32::try_from(generation)
            .map_err(|_| StoreError::Corrupt(format!("backup generation {generation}")))?,
        hash: BlobRef::from_hash(fixed("backup hash", &hash)?),
        key: WrappedKey::from_bytes(fixed("wrapped key", &key)?),
    }))
}

impl KeysStore for SqliteStore {
    fn backup(&self, uid: &Uid) -> Result<Option<BackupRecord>> {
        self.read(|tx| backup_in(tx, uid))
    }

    fn put_backup(
        &self,
        uid: &Uid,
        backup: &BackupRecord,
        now: Timestamp,
    ) -> Result<Option<BlobRef>> {
        self.write(|tx| {
            let old = backup_in(tx, uid)?;
            tx.execute(
                "INSERT OR REPLACE INTO backups (uid, generation, hash, key, stored)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    uid.as_str(),
                    backup.generation,
                    &backup.hash.hash()[..],
                    &backup.key.as_bytes()[..],
                    millis(now)
                ],
            )?;
            Ok(old.map(|old| old.hash).filter(|hash| *hash != backup.hash))
        })
    }

    fn delete_backup(&self, uid: &Uid) -> Result<Option<BlobRef>> {
        self.write(|tx| {
            let old = backup_in(tx, uid)?;
            tx.execute("DELETE FROM backups WHERE uid = ?", [uid.as_str()])?;
            Ok(old.map(|old| old.hash))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backup(n: u8) -> BackupRecord {
        BackupRecord {
            generation: u32::from(n),
            hash: BlobRef::of(&[n]),
            key: WrappedKey::from_bytes([n; 60]),
        }
    }

    #[test]
    fn one_backup_per_identity() {
        let store = SqliteStore::open_in_memory().unwrap();
        let alice: Uid = "alice@example.org".parse().unwrap();
        let t = "2026-11-09T00:00:00.000Z".parse().unwrap();
        assert_eq!(store.backup(&alice).unwrap(), None);
        assert_eq!(store.put_backup(&alice, &backup(1), t).unwrap(), None);
        assert_eq!(store.backup(&alice).unwrap(), Some(backup(1)));
        // A new backup replaces the old, whose blob goes (12.13).
        let old = store.put_backup(&alice, &backup(2), t).unwrap();
        assert_eq!(old, Some(backup(1).hash));
        assert_eq!(store.backup(&alice).unwrap(), Some(backup(2)));
        // The same blob again is not deleted.
        assert_eq!(store.put_backup(&alice, &backup(2), t).unwrap(), None);
        assert_eq!(store.delete_backup(&alice).unwrap(), Some(backup(2).hash));
        assert_eq!(store.delete_backup(&alice).unwrap(), None);
        assert_eq!(store.backup(&alice).unwrap(), None);
    }
}
