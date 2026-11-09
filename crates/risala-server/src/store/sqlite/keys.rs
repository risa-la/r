//! [`KeysStore`] on SQLite, and the tables of KeyPackages, Welcomes,
//! blobs, uploads and backups (5.6, 12.5, 12.8, 12.12, 12.13).

use rusqlite::{OptionalExtension as _, Row, Transaction, params};

use risala_proto::binary::{WRAPPED_KEY_LEN, WrappedKey};
use risala_proto::mls::OrBlob;
use risala_proto::names::{BlobRef, BoxName, Uid};
use risala_proto::time::Timestamp;

use super::{SqliteStore, from_sql_u64, sql_u64};
use crate::secret::SecretHash;
use crate::store::keys::{
    AddedKeyPackage, BlobPut, BlobRecord, DeviceBytes, Expired, ExpiryTimes, HandedKeyPackage,
    Handout, HandoutRow, KeyPackageCount, NewKeyPackage, PutWelcome, RefBytes, RoomJoins,
    RoomWelcome, StoredBytes, StoredWelcome, UploadRecord,
};
use crate::store::{
    BackupRecord, KeysStore, Result, StoreError, coarse, fixed, millis, parsed, timestamp,
};

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
CREATE UNIQUE INDEX key_packages_last_resort ON key_packages (uid, device) WHERE last_resort = 1;
CREATE INDEX key_packages_not_after ON key_packages (not_after);

-- The identities that have uploaded KeyPackages (12.5), so that KEYPKG
-- GET can tell a uid it does not know. Forgotten after retention.
CREATE TABLE key_package_uids (
    uid TEXT PRIMARY KEY,
    added INTEGER NOT NULL          -- ms of the last KEYPKG ADD
) STRICT;

-- The ratchet tree of each public-room epoch that a commit applying
-- external Add proposals started (12.6, 12.8), for WELCOME GET's tree.
-- Deleted 24 hours after the commit, with the Welcomes that need it. A
-- tree too large for a line is a blob, kept by 'tree ' and this id.
CREATE TABLE room_trees (
    id INTEGER PRIMARY KEY,
    box BLOB NOT NULL CHECK (length(box) = 16), -- the room's mailbox
    epoch INTEGER NOT NULL CHECK (epoch >= 0), -- the epoch the commit started
    tree BLOB NOT NULL,             -- the tree, or its blob's hash
    is_blob INTEGER NOT NULL DEFAULT 0 CHECK (is_blob IN (0, 1)),
    committed INTEGER NOT NULL,     -- ms, when the server took the commit
    UNIQUE (box, epoch)
) STRICT;
CREATE INDEX room_trees_committed ON room_trees (committed);

-- What a Welcome may be put for (12.8), once each: every time KEYPKG GET
-- handed out a KeyPackage of a device (a last-resort one may be handed
-- out many times), with the hash of the put secret only the fetcher
-- knows (12.5); and every KeyPackage of an external Add proposal that a
-- public room's commit applied, with the device that made the commit,
-- for WELCOME GET.
CREATE TABLE handed_out (
    id INTEGER PRIMARY KEY,
    ref BLOB NOT NULL CHECK (length(ref) = 48), -- the KeyPackageRef
    uid TEXT,                       -- from KEYPKG GET: the device's identity,
    device BLOB CHECK (length(device) = 48), -- its device id,
    secret_hash BLOB CHECK (length(secret_hash) = 48), -- and the put secret's hash
    tree INTEGER REFERENCES room_trees (id) ON DELETE CASCADE, -- or the epoch
                                    -- of an external proposal's commit,
    committer_uid TEXT,             -- and the identity and device id of the
    committer BLOB CHECK (length(committer) = 48), -- device that made it
    handed INTEGER NOT NULL,        -- ms, to the hour (4.2); forgotten after retention (7.5)
    welcomed BLOB CHECK (length(welcomed) = 48), -- the hash of the Welcome put for it
    CHECK ((device IS NULL) != (tree IS NULL)),
    CHECK ((device IS NULL) = (uid IS NULL) AND (device IS NULL) = (secret_hash IS NULL)),
    CHECK ((tree IS NULL) = (committer IS NULL) AND (tree IS NULL) = (committer_uid IS NULL))
) STRICT;
CREATE INDEX handed_out_ref ON handed_out (ref);
CREATE INDEX handed_out_device ON handed_out (uid, device);
CREATE INDEX handed_out_tree ON handed_out (tree) WHERE tree IS NOT NULL;
CREATE INDEX handed_out_handed ON handed_out (handed);

-- Welcomes waiting for their device, or for WELCOME GET (12.8): a
-- SealedWelcome for a device, the MLSMessage for an external proposal.
CREATE TABLE welcomes (
    id TEXT PRIMARY KEY,            -- the id the server gave it (3.5)
    handed INTEGER NOT NULL UNIQUE REFERENCES handed_out (id) ON DELETE CASCADE,
    welcome BLOB NOT NULL,          -- the Welcome, or its blob's hash
    is_blob INTEGER NOT NULL DEFAULT 0 CHECK (is_blob IN (0, 1)),
    received INTEGER NOT NULL,      -- ms, to the hour (4.2); deleted after retention (7.5)
    fetched INTEGER NOT NULL DEFAULT 0 CHECK (fetched IN (0, 1)) -- unused: WELCOME GET does not
                                    -- freeze a Welcome, since anyone may send it
) STRICT;
CREATE INDEX welcomes_received ON welcomes (received);

-- Blobs (12.12). Their bytes are in files named by their hash.
CREATE TABLE blobs (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 48),
    size INTEGER NOT NULL CHECK (size >= 0),
    stored INTEGER NOT NULL,        -- ms of the last BLOB that named it (7.5)
    box BLOB CHECK (length(box) = 16), -- the mailbox whose quota it counts against
    uid TEXT                        -- or the identity that stored it
) STRICT;
CREATE INDEX blobs_stored ON blobs (stored);
CREATE INDEX blobs_box ON blobs (box) WHERE box IS NOT NULL;

-- What keeps each blob whatever the retention (12.6, 12.12, 12.13):
-- 'backup ' and a uid for its current backup, 'room ' and a box in hex
-- for a public room's current tree, 'tree ' and a room_trees id for the
-- tree of an epoch with Welcomes.
CREATE TABLE blob_keeps (
    owner TEXT NOT NULL,
    hash BLOB NOT NULL CHECK (length(hash) = 48),
    PRIMARY KEY (owner, hash)
) STRICT, WITHOUT ROWID;
CREATE INDEX blob_keeps_hash ON blob_keeps (hash);

-- The put URLs BLOB handed out (12.12), for 10 minutes. A URL is looked up
-- by its public part; its secret part is a bearer secret, kept as a hash
-- (Section 14). Deleted once used.
CREATE TABLE blob_puts (
    id TEXT PRIMARY KEY,            -- the URL's public part
    secret_hash BLOB NOT NULL CHECK (length(secret_hash) = 48),
    hash BLOB NOT NULL CHECK (length(hash) = 48), -- the blob it is for
    size INTEGER NOT NULL CHECK (size >= 0),
    box BLOB CHECK (length(box) = 16),
    uid TEXT,
    expires INTEGER NOT NULL        -- ms
) STRICT;
CREATE INDEX blob_puts_box ON blob_puts (box) WHERE box IS NOT NULL;

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
    claimed INTEGER NOT NULL DEFAULT 0 CHECK (claimed IN (0, 1)), -- an upload started
    stored INTEGER,                 -- ms when the PUT finished, from which
                                    -- retention counts; NULL until then
    held INTEGER NOT NULL DEFAULT 0 CHECK (held >= 0), -- open reports that keep it (5.8)
    deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)) -- deleted while held
) STRICT;
CREATE INDEX uploads_box ON uploads (box);

-- The uploads each open report keeps (5.8), counted in uploads.held.
CREATE TABLE report_holds (
    report TEXT NOT NULL,           -- the report's id
    upload TEXT NOT NULL REFERENCES uploads (id) ON DELETE CASCADE,
    PRIMARY KEY (report, upload)
) STRICT, WITHOUT ROWID;
CREATE INDEX report_holds_upload ON report_holds (upload);

-- Each identity's backup (12.13). Its blobs, the first archive's and
-- those in its list, are kept while it is current (blob_keeps).
CREATE TABLE backups (
    uid TEXT PRIMARY KEY,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    hash BLOB NOT NULL CHECK (length(hash) = 48), -- the first archive's blob
    key BLOB NOT NULL CHECK (length(key) = 61), -- the WrappedKey
    files BLOB CHECK (length(files) = 48), -- the list's blob, if any
    stored INTEGER NOT NULL         -- ms
) STRICT;
";

/// The bytes of the blobs and uploaded files that open reports keep
/// (5.8): blobs kept by a `report ` owner in `blob_keeps`, and uploads
/// with `held` above 0.
pub(super) fn reported_bytes(tx: &Transaction<'_>) -> Result<u64> {
    let total: i64 = tx.query_row(
        "SELECT (SELECT coalesce(sum(size), 0) FROM blobs WHERE hash IN
                    (SELECT hash FROM blob_keeps WHERE owner LIKE 'report %'))
              + (SELECT coalesce(sum(size), 0) FROM uploads WHERE held > 0)",
        [],
        |row| row.get(0),
    )?;
    from_sql_u64("bytes", total)
}

/// A blob hash, read back.
fn blob_ref(what: &str, bytes: &[u8]) -> Result<BlobRef> {
    Ok(BlobRef::from_hash(fixed(what, bytes)?))
}

/// A secret hash, read back.
fn secret(what: &str, bytes: &[u8]) -> Result<SecretHash> {
    Ok(SecretHash::from_bytes(fixed(what, bytes)?))
}

/// A box, read back.
fn mailbox(bytes: Option<Vec<u8>>) -> Result<Option<BoxName>> {
    bytes
        .map(|b| fixed("box", &b).map(BoxName::from_bytes))
        .transpose()
}

/// A uid, read back.
fn uid(text: Option<String>) -> Result<Option<Uid>> {
    text.map(|t| parsed("uid", &t)).transpose()
}

/// The backup of `uid`, in a transaction.
fn backup_in(tx: &Transaction<'_>, uid: &Uid) -> Result<Option<BackupRecord>> {
    let row = tx
        .query_row(
            "SELECT generation, hash, key, files FROM backups WHERE uid = ?",
            [uid.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((generation, hash, key, files)) = row else {
        return Ok(None);
    };
    let key: [u8; WRAPPED_KEY_LEN] = fixed("wrapped key", &key)?;
    Ok(Some(BackupRecord {
        generation: u32::try_from(generation)
            .map_err(|_| StoreError::Corrupt(format!("backup generation {generation}")))?,
        hash: blob_ref("backup hash", &hash)?,
        key: WrappedKey::from_array(&key),
        files: files.map(|f| blob_ref("backup list", &f)).transpose()?,
    }))
}

/// The raw columns of a Welcome: id, bytes, whether they are a blob's hash.
type WelcomeRow = (String, Vec<u8>, i64);

fn welcome_row(row: &Row<'_>) -> rusqlite::Result<WelcomeRow> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
}

/// Bytes stored inline, or a blob's hash.
fn or_blob(what: &str, bytes: Vec<u8>, is_blob: i64) -> Result<OrBlob<Vec<u8>>> {
    Ok(if is_blob != 0 {
        OrBlob::Blob(blob_ref(what, &bytes)?)
    } else {
        OrBlob::Inline(bytes)
    })
}

/// Bytes to store, and whether they are a blob's hash.
fn or_blob_column(value: &OrBlob<Vec<u8>>) -> (&[u8], bool) {
    match value {
        OrBlob::Inline(bytes) => (bytes.as_slice(), false),
        OrBlob::Blob(blob) => (&blob.hash()[..], true),
    }
}

fn stored_welcome((id, bytes, is_blob): WelcomeRow) -> Result<StoredWelcome> {
    Ok(StoredWelcome {
        id,
        welcome: or_blob("welcome blob", bytes, is_blob)?,
    })
}

/// What keeps the blob of the tree `room_trees.id`.
fn tree_owner(id: i64) -> String {
    format!("tree {id}")
}

/// The raw columns of an upload, in the order of [`UPLOAD_COLUMNS`].
type UploadRow = (
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Option<i64>,
    i64,
    i64,
);

const UPLOAD_COLUMNS: &str =
    "id, box, put_hash, get_hash, del_hash, size, created, claimed, stored, held, deleted";

fn upload_row(row: &Row<'_>) -> rusqlite::Result<UploadRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn upload_record(r: UploadRow) -> Result<UploadRecord> {
    let (id, mailbox, put, get, del, size, created, claimed, stored, held, deleted) = r;
    Ok(UploadRecord {
        id,
        mailbox: BoxName::from_bytes(fixed("box", &mailbox)?),
        put: secret("put hash", &put)?,
        get: secret("get hash", &get)?,
        del: secret("del hash", &del)?,
        size: from_sql_u64("size", size)?,
        created: timestamp(created)?,
        claimed: claimed != 0,
        stored: stored.map(timestamp).transpose()?,
        held: u32::try_from(held).map_err(|_| StoreError::Corrupt(format!("held {held}")))?,
        deleted: deleted != 0,
    })
}

/// Deletes the blobs in `hashes` that nothing keeps, and returns them.
fn delete_unkept(tx: &Transaction<'_>, hashes: &[BlobRef]) -> Result<Vec<BlobRef>> {
    let mut gone = Vec::new();
    for hash in hashes {
        let n = tx.execute(
            "DELETE FROM blobs WHERE hash = ?1
             AND NOT EXISTS (SELECT 1 FROM blob_keeps WHERE hash = ?1)",
            [&hash.hash()[..]],
        )?;
        if n > 0 {
            gone.push(*hash);
        }
    }
    Ok(gone)
}

impl KeysStore for SqliteStore {
    fn add_key_package(
        &self,
        kp: &NewKeyPackage,
        max_ordinary: u64,
        now: Timestamp,
    ) -> Result<AddedKeyPackage> {
        self.write(|tx| {
            let known = tx
                .query_row(
                    "SELECT 1 FROM key_packages WHERE ref = ?",
                    [&kp.key_package_ref[..]],
                    |_| Ok(()),
                )
                .optional()?;
            if known.is_some() {
                return Ok(AddedKeyPackage::Again);
            }
            tx.execute(
                "DELETE FROM key_packages WHERE uid = ? AND device = ? AND not_after < ?",
                params![kp.uid.as_str(), &kp.device[..], millis(now)],
            )?;
            if kp.last_resort {
                tx.execute(
                    "DELETE FROM key_packages WHERE uid = ? AND device = ? AND last_resort = 1",
                    params![kp.uid.as_str(), &kp.device[..]],
                )?;
            } else {
                let held: i64 = tx.query_row(
                    "SELECT count(*) FROM key_packages
                     WHERE uid = ? AND device = ? AND last_resort = 0",
                    params![kp.uid.as_str(), &kp.device[..]],
                    |row| row.get(0),
                )?;
                if from_sql_u64("count", held)? >= max_ordinary {
                    return Ok(AddedKeyPackage::Full);
                }
            }
            tx.execute(
                "INSERT INTO key_packages (uid, device, ref, key_package, last_resort, not_after)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    kp.uid.as_str(),
                    &kp.device[..],
                    &kp.key_package_ref[..],
                    &kp.key_package,
                    kp.last_resort,
                    millis(kp.not_after)
                ],
            )?;
            tx.execute(
                "INSERT INTO key_package_uids (uid, added) VALUES (?1, ?2)
                 ON CONFLICT (uid) DO UPDATE SET added = ?2",
                params![kp.uid.as_str(), millis(now)],
            )?;
            Ok(AddedKeyPackage::Added)
        })
    }

    fn count_key_packages(
        &self,
        uid: &Uid,
        device: &DeviceBytes,
        now: Timestamp,
    ) -> Result<KeyPackageCount> {
        self.read(|tx| {
            let (ordinary, last_resort): (i64, i64) = tx.query_row(
                "SELECT count(*) FILTER (WHERE last_resort = 0),
                        count(*) FILTER (WHERE last_resort = 1)
                 FROM key_packages WHERE uid = ? AND device = ? AND not_after >= ?",
                params![uid.as_str(), &device[..], millis(now)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            Ok(KeyPackageCount {
                ordinary: from_sql_u64("count", ordinary)?,
                last_resort: last_resort > 0,
            })
        })
    }

    fn knows_key_package_uid(&self, uid: &Uid, since: Timestamp) -> Result<bool> {
        self.read(|tx| {
            Ok(tx
                .query_row(
                    "SELECT 1 FROM key_package_uids WHERE uid = ? AND added >= ?",
                    params![uid.as_str(), millis(since)],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
    }

    fn take_key_packages(
        &self,
        uid: &Uid,
        devices: &[(DeviceBytes, SecretHash)],
        now: Timestamp,
    ) -> Result<Vec<HandedKeyPackage>> {
        self.write(|tx| {
            let mut out = Vec::new();
            for (device, secret) in devices {
                // Ordinary ones first, oldest first; the last-resort one
                // only when none is left (12.5).
                let found = tx
                    .query_row(
                        "SELECT id, ref, key_package, last_resort FROM key_packages
                         WHERE uid = ? AND device = ? AND not_after >= ?
                         ORDER BY last_resort, id LIMIT 1",
                        params![uid.as_str(), &device[..], millis(now)],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, Vec<u8>>(1)?,
                                row.get::<_, Vec<u8>>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        },
                    )
                    .optional()?;
                let Some((id, kp_ref, key_package, last_resort)) = found else {
                    continue;
                };
                if last_resort == 0 {
                    tx.execute("DELETE FROM key_packages WHERE id = ?", [id])?;
                }
                tx.execute(
                    "INSERT INTO handed_out (ref, uid, device, secret_hash, handed)
                     VALUES (?, ?, ?, ?, ?)",
                    params![
                        &kp_ref,
                        uid.as_str(),
                        &device[..],
                        &secret.as_bytes()[..],
                        coarse(now)
                    ],
                )?;
                out.push(HandedKeyPackage {
                    device: *device,
                    key_package,
                });
            }
            Ok(out)
        })
    }

    fn forget_device(&self, uid: &Uid, device: &DeviceBytes) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "DELETE FROM key_packages WHERE uid = ? AND device = ?",
                params![uid.as_str(), &device[..]],
            )?;
            // Their Welcomes go with them.
            tx.execute(
                "DELETE FROM handed_out WHERE uid = ? AND device = ?",
                params![uid.as_str(), &device[..]],
            )?;
            Ok(())
        })
    }

    fn add_room_joins(&self, joins: &RoomJoins, now: Timestamp) -> Result<()> {
        self.write(|tx| {
            let mailbox = &joins.mailbox.as_bytes()[..];
            let epoch = i64::try_from(joins.epoch)
                .map_err(|_| StoreError::Corrupt(format!("epoch {}", joins.epoch)))?;
            let (tree, is_blob) = or_blob_column(&joins.tree);
            tx.execute(
                "INSERT INTO room_trees (box, epoch, tree, is_blob, committed)
                 VALUES (?, ?, ?, ?, ?) ON CONFLICT (box, epoch) DO NOTHING",
                params![mailbox, epoch, tree, is_blob, millis(now)],
            )?;
            let id: i64 = tx.query_row(
                "SELECT id FROM room_trees WHERE box = ? AND epoch = ?",
                params![mailbox, epoch],
                |row| row.get(0),
            )?;
            if let OrBlob::Blob(hash) = &joins.tree {
                tx.execute(
                    "INSERT INTO blobs (hash, size, stored) VALUES (?, ?, ?)
                     ON CONFLICT (hash) DO NOTHING",
                    params![&hash.hash()[..], sql_u64(joins.tree_size), millis(now)],
                )?;
                tx.execute(
                    "INSERT INTO blob_keeps (owner, hash) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    params![tree_owner(id), &hash.hash()[..]],
                )?;
            }
            for kp_ref in &joins.refs {
                tx.execute(
                    "INSERT INTO handed_out (ref, tree, committer_uid, committer, handed)
                     VALUES (?, ?, ?, ?, ?)",
                    params![
                        &kp_ref[..],
                        id,
                        joins.committer_uid.as_str(),
                        &joins.committer[..],
                        coarse(now)
                    ],
                )?;
            }
            Ok(())
        })
    }

    fn handouts(&self, key_package_ref: &RefBytes) -> Result<Vec<HandoutRow>> {
        self.read(|tx| {
            let mut stmt = tx.prepare(
                "SELECT h.id, h.uid, h.device, h.secret_hash, t.box, t.epoch,
                        h.committer_uid, h.committer
                 FROM handed_out h LEFT JOIN room_trees t ON h.tree = t.id
                 WHERE h.ref = ? ORDER BY h.id DESC",
            )?;
            let rows = stmt.query_map([&key_package_ref[..]], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (id, who, device, secret_hash, room, epoch, committer_uid, committer) = row?;
                let handout = match (who, device, secret_hash) {
                    (Some(who), Some(device), Some(hash)) => Handout::Device {
                        uid: parsed("uid", &who)?,
                        device: fixed("device", &device)?,
                        secret: secret("put secret hash", &hash)?,
                    },
                    _ => match (mailbox(room)?, epoch, uid(committer_uid)?, committer) {
                        (Some(mailbox), Some(epoch), Some(committer_uid), Some(committer)) => {
                            Handout::Room {
                                mailbox,
                                epoch: from_sql_u64("epoch", epoch)?,
                                committer_uid,
                                committer: fixed("committer", &committer)?,
                            }
                        }
                        _ => return Err(StoreError::Corrupt("handed_out row".into())),
                    },
                };
                out.push(HandoutRow { id, handout });
            }
            Ok(out)
        })
    }

    fn put_welcome(
        &self,
        handout: i64,
        id: &str,
        welcome: &OrBlob<Vec<u8>>,
        digest: &[u8; 48],
        max_pending: u64,
        now: Timestamp,
    ) -> Result<PutWelcome> {
        self.write(|tx| {
            let found = tx
                .query_row(
                    "SELECT uid, device, welcomed FROM handed_out WHERE id = ?",
                    [handout],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<Vec<u8>>>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                        ))
                    },
                )
                .optional()?;
            let Some((who, device, welcomed)) = found else {
                return Ok(PutWelcome::NotFound);
            };
            // The same Welcome again, as from a committer whose OK was lost
            // (12.8), whether or not it has been fetched.
            if welcomed.as_deref() == Some(&digest[..]) {
                return Ok(PutWelcome::Same);
            }
            let existing = tx
                .query_row(
                    "SELECT id, fetched FROM welcomes WHERE handed = ?",
                    [handout],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?;
            let (bytes, is_blob) = or_blob_column(welcome);
            let result = match existing {
                Some((_, fetched)) if fetched != 0 => return Ok(PutWelcome::Taken),
                Some((existing, _)) => {
                    tx.execute(
                        "UPDATE welcomes SET welcome = ?, is_blob = ?, received = ? WHERE id = ?",
                        params![bytes, is_blob, coarse(now), existing],
                    )?;
                    PutWelcome::Replaced(existing)
                }
                // Deleted by its device, or expired.
                None if welcomed.is_some() => return Ok(PutWelcome::Taken),
                None => {
                    if let (Some(who), Some(device)) = (who, device) {
                        let pending: i64 = tx.query_row(
                            "SELECT count(*) FROM welcomes w JOIN handed_out h ON w.handed = h.id
                             WHERE h.uid = ? AND h.device = ?",
                            params![who, device],
                            |row| row.get(0),
                        )?;
                        if from_sql_u64("count", pending)? >= max_pending {
                            return Ok(PutWelcome::TooMany);
                        }
                    }
                    tx.execute(
                        "INSERT INTO welcomes (id, handed, welcome, is_blob, received)
                         VALUES (?, ?, ?, ?, ?)",
                        params![id, handout, bytes, is_blob, coarse(now)],
                    )?;
                    PutWelcome::Stored(id.to_owned())
                }
            };
            tx.execute(
                "UPDATE handed_out SET welcomed = ? WHERE id = ?",
                params![&digest[..], handout],
            )?;
            Ok(result)
        })
    }

    fn device_welcomes(&self, uid: &Uid, device: &DeviceBytes) -> Result<Vec<StoredWelcome>> {
        self.read(|tx| {
            let mut stmt = tx.prepare(
                "SELECT w.id, w.welcome, w.is_blob FROM welcomes w
                 JOIN handed_out h ON w.handed = h.id
                 WHERE h.uid = ? AND h.device = ? ORDER BY w.received, w.rowid",
            )?;
            let rows = stmt.query_map(params![uid.as_str(), &device[..]], welcome_row)?;
            rows.map(|row| stored_welcome(row?)).collect()
        })
    }

    fn delete_welcome(&self, uid: &Uid, device: &DeviceBytes, id: &str) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "DELETE FROM welcomes WHERE id = ? AND handed IN
                 (SELECT id FROM handed_out WHERE uid = ? AND device = ?)",
                params![id, uid.as_str(), &device[..]],
            )?;
            Ok(())
        })
    }

    fn room_welcome(&self, key_package_ref: &RefBytes) -> Result<Option<RoomWelcome>> {
        self.read(|tx| {
            let row = tx
                .query_row(
                    "SELECT w.id, w.welcome, w.is_blob, t.tree, t.is_blob FROM welcomes w
                     JOIN handed_out h ON w.handed = h.id
                     JOIN room_trees t ON h.tree = t.id
                     WHERE h.ref = ? ORDER BY h.id DESC LIMIT 1",
                    [&key_package_ref[..]],
                    |row| {
                        Ok((
                            welcome_row(row)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .optional()?;
            let Some((welcome, tree, is_blob)) = row else {
                return Ok(None);
            };
            // Not marked fetched: a KeyPackageRef of an external proposal
            // is public, so anyone may GET it, and that must not stop the
            // committer replacing its Welcome (12.8).
            Ok(Some(RoomWelcome {
                welcome: stored_welcome(welcome)?,
                tree: or_blob("tree blob", tree, is_blob)?,
            }))
        })
    }

    fn blob(&self, hash: &BlobRef) -> Result<Option<BlobRecord>> {
        self.read(|tx| {
            let row = tx
                .query_row(
                    "SELECT size, stored, box, uid,
                            EXISTS (SELECT 1 FROM blob_keeps k WHERE k.hash = blobs.hash)
                     FROM blobs WHERE hash = ?",
                    [&hash.hash()[..]],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .optional()?;
            let Some((size, stored, room, owner, kept)) = row else {
                return Ok(None);
            };
            Ok(Some(BlobRecord {
                hash: *hash,
                size: from_sql_u64("size", size)?,
                stored: timestamp(stored)?,
                kept: kept != 0,
                mailbox: mailbox(room)?,
                uid: uid(owner)?,
            }))
        })
    }

    fn touch_blob(&self, hash: &BlobRef, now: Timestamp) -> Result<bool> {
        self.write(|tx| {
            let n = tx.execute(
                "UPDATE blobs SET stored = max(stored, ?) WHERE hash = ?",
                params![millis(now), &hash.hash()[..]],
            )?;
            Ok(n > 0)
        })
    }

    fn add_blob_put(&self, put: &BlobPut) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO blob_puts (id, secret_hash, hash, size, box, uid, expires)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    put.id,
                    &put.secret.as_bytes()[..],
                    &put.hash.hash()[..],
                    sql_u64(put.size),
                    put.mailbox.as_ref().map(|m| m.as_bytes().to_vec()),
                    put.uid.as_ref().map(Uid::as_str),
                    millis(put.expires)
                ],
            )?;
            Ok(())
        })
    }

    fn blob_put(&self, id: &str) -> Result<Option<BlobPut>> {
        self.read(|tx| {
            let row = tx
                .query_row(
                    "SELECT secret_hash, hash, size, box, uid, expires FROM blob_puts WHERE id = ?",
                    [id],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Option<Vec<u8>>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    },
                )
                .optional()?;
            let Some((secret_hash, hash, size, room, owner, expires)) = row else {
                return Ok(None);
            };
            Ok(Some(BlobPut {
                id: id.to_owned(),
                secret: secret("put hash", &secret_hash)?,
                hash: blob_ref("blob hash", &hash)?,
                size: from_sql_u64("size", size)?,
                mailbox: mailbox(room)?,
                uid: uid(owner)?,
                expires: timestamp(expires)?,
            }))
        })
    }

    fn claim_blob_put(&self, id: &str) -> Result<bool> {
        self.write(|tx| Ok(tx.execute("DELETE FROM blob_puts WHERE id = ?", [id])? > 0))
    }

    fn blob_stored(&self, put: &BlobPut, now: Timestamp) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO blobs (hash, size, stored, box, uid) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (hash) DO UPDATE SET stored = max(stored, ?3)",
                params![
                    &put.hash.hash()[..],
                    sql_u64(put.size),
                    millis(now),
                    put.mailbox.as_ref().map(|m| m.as_bytes().to_vec()),
                    put.uid.as_ref().map(Uid::as_str)
                ],
            )?;
            Ok(())
        })
    }

    fn mailbox_file_bytes(&self, mailbox: &BoxName) -> Result<u64> {
        self.read(|tx| {
            let b = &mailbox.as_bytes()[..];
            let total: i64 = tx.query_row(
                "SELECT (SELECT coalesce(sum(size), 0) FROM blobs WHERE box = ?1)
                      + (SELECT coalesce(sum(size), 0) FROM blob_puts WHERE box = ?1)
                      + (SELECT coalesce(sum(size), 0) FROM uploads WHERE box = ?1)",
                [b],
                |row| row.get(0),
            )?;
            from_sql_u64("bytes", total)
        })
    }

    fn stored_total(&self) -> Result<StoredBytes> {
        self.read(|tx| {
            let reported = reported_bytes(tx)?;
            let total: i64 = tx.query_row(
                "SELECT (SELECT coalesce(sum(size), 0) FROM blobs)
                      + (SELECT coalesce(sum(size), 0) FROM blob_puts)
                      + (SELECT coalesce(sum(size), 0) FROM uploads)
                      + (SELECT coalesce(sum(bytes), 0) FROM mailboxes)",
                [],
                |row| row.get(0),
            )?;
            Ok(StoredBytes {
                stored: from_sql_u64("bytes", total)?.saturating_sub(reported),
                reported,
            })
        })
    }

    fn set_blob_keeps(&self, owner: &str, hashes: &[BlobRef]) -> Result<Vec<BlobRef>> {
        self.write(|tx| {
            let before: Vec<BlobRef> = {
                let mut stmt = tx.prepare("SELECT hash FROM blob_keeps WHERE owner = ?")?;
                let rows = stmt.query_map([owner], |row| row.get::<_, Vec<u8>>(0))?;
                rows.map(|row| blob_ref("kept hash", &row?))
                    .collect::<Result<_>>()?
            };
            tx.execute("DELETE FROM blob_keeps WHERE owner = ?", [owner])?;
            for hash in hashes {
                tx.execute(
                    "INSERT INTO blob_keeps (owner, hash) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    params![owner, &hash.hash()[..]],
                )?;
            }
            let mut freed = Vec::new();
            for hash in before {
                let kept = tx
                    .query_row(
                        "SELECT 1 FROM blob_keeps WHERE hash = ?",
                        [&hash.hash()[..]],
                        |_| Ok(()),
                    )
                    .optional()?;
                if kept.is_none() {
                    freed.push(hash);
                }
            }
            Ok(freed)
        })
    }

    fn keep_own_blob(
        &self,
        owner: &str,
        hash: &BlobRef,
        size: u64,
        now: Timestamp,
    ) -> Result<Vec<BlobRef>> {
        // Its stored time only moves forward, so that it does not expire
        // before `owner` keeps it.
        self.write(|tx| {
            tx.execute(
                "INSERT INTO blobs (hash, size, stored) VALUES (?, ?, ?)
                 ON CONFLICT (hash) DO UPDATE SET stored = max(stored, excluded.stored)",
                params![&hash.hash()[..], sql_u64(size), millis(now)],
            )?;
            Ok(())
        })?;
        self.set_blob_keeps(owner, std::slice::from_ref(hash))
    }

    fn delete_blob(&self, hash: &BlobRef) -> Result<bool> {
        self.write(|tx| Ok(!delete_unkept(tx, std::slice::from_ref(hash))?.is_empty()))
    }

    fn add_upload(&self, u: &UploadRecord) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO uploads (id, box, put_hash, get_hash, del_hash, size, created,
                                      claimed, stored, held, deleted)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    u.id,
                    &u.mailbox.as_bytes()[..],
                    &u.put.as_bytes()[..],
                    &u.get.as_bytes()[..],
                    &u.del.as_bytes()[..],
                    sql_u64(u.size),
                    millis(u.created),
                    u.claimed,
                    u.stored.map(millis),
                    u.held,
                    u.deleted
                ],
            )?;
            Ok(())
        })
    }

    fn upload(&self, id: &str) -> Result<Option<UploadRecord>> {
        self.read(|tx| {
            tx.query_row(
                &format!("SELECT {UPLOAD_COLUMNS} FROM uploads WHERE id = ?"),
                [id],
                upload_row,
            )
            .optional()?
            .map(upload_record)
            .transpose()
        })
    }

    fn claim_upload(&self, id: &str) -> Result<bool> {
        self.write(|tx| {
            Ok(tx.execute(
                "UPDATE uploads SET claimed = 1 WHERE id = ? AND claimed = 0",
                [id],
            )? > 0)
        })
    }

    fn upload_stored(&self, id: &str, now: Timestamp) -> Result<bool> {
        self.write(|tx| {
            Ok(tx.execute(
                "UPDATE uploads SET stored = ? WHERE id = ? AND stored IS NULL AND deleted = 0",
                params![millis(now), id],
            )? > 0)
        })
    }

    fn delete_upload(&self, id: &str) -> Result<bool> {
        self.write(|tx| {
            let n = tx.execute("DELETE FROM uploads WHERE id = ? AND held = 0", [id])?;
            if n > 0 {
                return Ok(true);
            }
            tx.execute("UPDATE uploads SET deleted = 1 WHERE id = ?", [id])?;
            Ok(false)
        })
    }

    fn hold_upload(&self, report: &str, id: &str, max_reported: u64) -> Result<bool> {
        self.write(|tx| {
            let held: Option<(i64, i64)> = tx
                .query_row("SELECT size, held FROM uploads WHERE id = ?", [id], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()?;
            let Some((size, held)) = held else {
                return Ok(false);
            };
            // A file another report keeps already counts (5.8).
            if held == 0
                && max_reported > 0
                && reported_bytes(tx)?.saturating_add(from_sql_u64("size", size)?) > max_reported
            {
                return Ok(false);
            }
            let n = tx.execute(
                "INSERT INTO report_holds (report, upload) VALUES (?, ?) ON CONFLICT DO NOTHING",
                params![report, id],
            )?;
            if n > 0 {
                tx.execute("UPDATE uploads SET held = held + 1 WHERE id = ?", [id])?;
            }
            Ok(true)
        })
    }

    fn release_uploads(&self, report: &str, retention: Timestamp) -> Result<Vec<String>> {
        self.write(|tx| {
            let held: Vec<String> = {
                let mut stmt =
                    tx.prepare("DELETE FROM report_holds WHERE report = ? RETURNING upload")?;
                let rows = stmt.query_map([report], |row| row.get(0))?;
                rows.collect::<rusqlite::Result<_>>()?
            };
            let mut gone = Vec::new();
            for id in held {
                tx.execute(
                    "UPDATE uploads SET held = held - 1 WHERE id = ? AND held > 0",
                    [&id],
                )?;
                let n = tx.execute(
                    "DELETE FROM uploads WHERE id = ? AND held = 0
                     AND (deleted = 1 OR (stored IS NOT NULL AND stored < ?))",
                    params![&id, millis(retention)],
                )?;
                if n > 0 {
                    gone.push(id);
                }
            }
            Ok(gone)
        })
    }

    fn backup(&self, uid: &Uid) -> Result<Option<BackupRecord>> {
        self.read(|tx| backup_in(tx, uid))
    }

    fn put_backup(
        &self,
        uid: &Uid,
        backup: &BackupRecord,
        now: Timestamp,
    ) -> Result<Option<BackupRecord>> {
        self.write(|tx| {
            let old = backup_in(tx, uid)?;
            tx.execute(
                "INSERT OR REPLACE INTO backups (uid, generation, hash, key, files, stored)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    uid.as_str(),
                    backup.generation,
                    &backup.hash.hash()[..],
                    &backup.key.as_bytes()[..],
                    backup.files.as_ref().map(|files| &files.hash()[..]),
                    millis(now)
                ],
            )?;
            Ok(old)
        })
    }

    fn delete_backup(&self, uid: &Uid) -> Result<Option<BackupRecord>> {
        self.write(|tx| {
            let old = backup_in(tx, uid)?;
            tx.execute("DELETE FROM backups WHERE uid = ?", [uid.as_str()])?;
            Ok(old)
        })
    }

    fn expire_keys(&self, t: &ExpiryTimes) -> Result<Expired> {
        self.write(|tx| {
            let now = millis(t.now);
            let retention = millis(t.retention);
            tx.execute("DELETE FROM key_packages WHERE not_after < ?", [now])?;
            tx.execute("DELETE FROM key_package_uids WHERE added < ?", [retention])?;
            tx.execute("DELETE FROM welcomes WHERE received < ?", [retention])?;
            // A record of handing out stays while its Welcome is pending,
            // and otherwise for retention, so that no second Welcome is
            // taken for it.
            tx.execute(
                "DELETE FROM handed_out WHERE handed < ?
                 AND NOT EXISTS (SELECT 1 FROM welcomes WHERE handed = handed_out.id)",
                [retention],
            )?;
            tx.execute("DELETE FROM blob_puts WHERE expires < ?", [now])?;
            let mut blobs = Vec::new();
            // Public rooms' trees past their 24 hours, with the Welcomes
            // that need them (12.6). A blob the server made of a tree goes
            // now, unless something else keeps it, or someone named it or
            // stored it since.
            let trees: Vec<(i64, Vec<u8>, i64, i64)> = {
                let mut stmt = tx.prepare(
                    "DELETE FROM room_trees WHERE committed < ?
                     RETURNING id, tree, is_blob, committed",
                )?;
                let rows = stmt.query_map([millis(t.room_trees)], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?;
                rows.collect::<rusqlite::Result<_>>()?
            };
            for (id, tree, is_blob, committed) in trees {
                if is_blob == 0 {
                    continue;
                }
                tx.execute("DELETE FROM blob_keeps WHERE owner = ?", [tree_owner(id)])?;
                let n = tx.execute(
                    "DELETE FROM blobs WHERE hash = ?1 AND box IS NULL AND uid IS NULL
                     AND stored <= ?2
                     AND NOT EXISTS (SELECT 1 FROM blob_keeps WHERE hash = ?1)",
                    params![&tree, committed],
                )?;
                if n > 0 {
                    blobs.push(blob_ref("tree blob", &tree)?);
                }
            }
            {
                let mut stmt = tx.prepare(
                    "DELETE FROM blobs WHERE stored < ?
                     AND NOT EXISTS (SELECT 1 FROM blob_keeps k WHERE k.hash = blobs.hash)
                     RETURNING hash",
                )?;
                let rows = stmt.query_map([retention], |row| row.get::<_, Vec<u8>>(0))?;
                for row in rows {
                    blobs.push(blob_ref("blob hash", &row?)?);
                }
            }
            let mut uploads = Vec::new();
            {
                let mut stmt = tx.prepare(
                    "DELETE FROM uploads WHERE held = 0 AND (
                         deleted = 1
                      OR (stored IS NOT NULL AND stored < ?1)
                      OR (stored IS NULL AND claimed = 0 AND created < ?2)
                      OR (stored IS NULL AND created < ?3))
                     RETURNING id",
                )?;
                let rows = stmt.query_map(
                    params![retention, millis(t.unclaimed), millis(t.unfinished)],
                    |row| row.get::<_, String>(0),
                )?;
                for row in rows {
                    uploads.push(row?);
                }
            }
            Ok(Expired { blobs, uploads })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    const T0: &str = "2026-11-09T00:00:00.000Z";

    fn later(secs: u64) -> Timestamp {
        t(T0).checked_add(Duration::from_secs(secs)).unwrap()
    }

    fn backup(n: u8) -> BackupRecord {
        let mut key = [n; WRAPPED_KEY_LEN];
        key[0] = 1;
        BackupRecord {
            generation: u32::from(n),
            hash: BlobRef::of(&[n]),
            key: WrappedKey::from_array(&key),
            files: n.is_multiple_of(2).then(|| BlobRef::of(&[n, n])),
        }
    }

    fn alice() -> Uid {
        "alice@example.org".parse().unwrap()
    }

    fn kp(n: u8, last_resort: bool) -> NewKeyPackage {
        NewKeyPackage {
            uid: alice(),
            device: [1; 48],
            key_package_ref: [n; 48],
            key_package: vec![n; 10],
            last_resort,
            not_after: later(3600),
        }
    }

    #[test]
    fn one_backup_per_identity() {
        let store = SqliteStore::open_in_memory().unwrap();
        let alice = alice();
        let t = t(T0);
        assert_eq!(store.backup(&alice).unwrap(), None);
        assert_eq!(store.put_backup(&alice, &backup(1), t).unwrap(), None);
        assert_eq!(store.backup(&alice).unwrap(), Some(backup(1)));
        // A new backup replaces the old, which is returned so that its
        // blobs can go (12.13).
        let old = store.put_backup(&alice, &backup(2), t).unwrap();
        assert_eq!(old, Some(backup(1)));
        assert_eq!(store.backup(&alice).unwrap(), Some(backup(2)));
        assert_eq!(store.delete_backup(&alice).unwrap(), Some(backup(2)));
        assert_eq!(store.delete_backup(&alice).unwrap(), None);
        assert_eq!(store.backup(&alice).unwrap(), None);
    }

    #[test]
    fn key_packages_are_handed_out_once_but_the_last_resort_stays() {
        let store = SqliteStore::open_in_memory().unwrap();
        let now = t(T0);
        let dev = [1; 48];
        assert_eq!(
            store.add_key_package(&kp(1, false), 2, now).unwrap(),
            AddedKeyPackage::Added
        );
        assert_eq!(
            store.add_key_package(&kp(1, false), 2, now).unwrap(),
            AddedKeyPackage::Again
        );
        assert_eq!(
            store.add_key_package(&kp(2, false), 2, now).unwrap(),
            AddedKeyPackage::Added
        );
        assert_eq!(
            store.add_key_package(&kp(3, false), 2, now).unwrap(),
            AddedKeyPackage::Full
        );
        store.add_key_package(&kp(4, true), 2, now).unwrap();
        // A new last-resort one replaces the old.
        store.add_key_package(&kp(5, true), 2, now).unwrap();
        assert_eq!(
            store.count_key_packages(&alice(), &dev, now).unwrap(),
            KeyPackageCount {
                ordinary: 2,
                last_resort: true
            }
        );
        let secret = SecretHash::of(b"put");
        let take = |n| {
            store
                .take_key_packages(&alice(), &[(dev, secret), ([9; 48], secret)], now)
                .unwrap()
                .into_iter()
                .map(|h| h.key_package[0])
                .take(n)
                .collect::<Vec<_>>()
        };
        assert_eq!(take(5), [1]);
        assert_eq!(take(5), [2]);
        assert_eq!(take(5), [5]);
        assert_eq!(take(5), [5]);
        // Each handing out is recorded, with its put secret, for one
        // Welcome each.
        let handouts = store.handouts(&[5; 48]).unwrap();
        assert_eq!(handouts.len(), 2);
        assert!(handouts[0].id > handouts[1].id);
        assert_eq!(
            handouts[0].handout,
            Handout::Device {
                uid: alice(),
                device: dev,
                secret
            }
        );
        assert_eq!(store.handouts(&[1; 48]).unwrap().len(), 1);
        assert!(store.handouts(&[3; 48]).unwrap().is_empty());
        let w = OrBlob::Inline(vec![1]);
        for (n, h) in handouts.iter().enumerate() {
            let id = format!("w{n}");
            assert_eq!(
                store.put_welcome(h.id, &id, &w, &[1; 48], 10, now).unwrap(),
                PutWelcome::Stored(id)
            );
        }
        assert_eq!(
            store.put_welcome(9999, "c", &w, &[1; 48], 10, now).unwrap(),
            PutWelcome::NotFound
        );
        // Lifetimes end.
        assert_eq!(
            store
                .count_key_packages(&alice(), &dev, later(7200))
                .unwrap(),
            KeyPackageCount::default()
        );
        assert!(
            store
                .take_key_packages(&alice(), &[(dev, secret)], later(7200))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn welcomes_are_limited_per_device_and_deleted_by_their_device() {
        let store = SqliteStore::open_in_memory().unwrap();
        let now = t(T0);
        let dev = [1; 48];
        for n in 1..=3 {
            store.add_key_package(&kp(n, false), 10, now).unwrap();
        }
        let secret = [(dev, SecretHash::of(b"put"))];
        store.take_key_packages(&alice(), &secret, now).unwrap();
        store.take_key_packages(&alice(), &secret, now).unwrap();
        let handout = |r: u8| store.handouts(&[r; 48]).unwrap()[0].id;
        let w = OrBlob::Blob(BlobRef::of(b"x"));
        let other = OrBlob::Inline(vec![7]);
        assert_eq!(
            store
                .put_welcome(handout(1), "a", &w, &[1; 48], 1, now)
                .unwrap(),
            PutWelcome::Stored("a".into())
        );
        assert_eq!(
            store
                .put_welcome(handout(2), "b", &w, &[1; 48], 1, now)
                .unwrap(),
            PutWelcome::TooMany
        );
        // The same Welcome again changes nothing; another replaces it, and
        // keeps its id, while it is pending (12.8).
        assert_eq!(
            store
                .put_welcome(handout(1), "c", &w, &[1; 48], 1, now)
                .unwrap(),
            PutWelcome::Same
        );
        assert_eq!(
            store
                .put_welcome(handout(1), "c", &other, &[2; 48], 1, now)
                .unwrap(),
            PutWelcome::Replaced("a".into())
        );
        assert_eq!(
            store
                .put_welcome(handout(1), "c", &w, &[1; 48], 1, now)
                .unwrap(),
            PutWelcome::Replaced("a".into())
        );
        let pending = store.device_welcomes(&alice(), &dev).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].welcome, w);
        // Another device cannot delete it.
        store.delete_welcome(&alice(), &[2; 48], "a").unwrap();
        assert_eq!(store.device_welcomes(&alice(), &dev).unwrap().len(), 1);
        store.delete_welcome(&alice(), &dev, "a").unwrap();
        assert!(store.device_welcomes(&alice(), &dev).unwrap().is_empty());
        // Once deleted, only the same Welcome is taken, and changes
        // nothing.
        assert_eq!(
            store
                .put_welcome(handout(1), "c", &w, &[1; 48], 1, now)
                .unwrap(),
            PutWelcome::Same
        );
        assert_eq!(
            store
                .put_welcome(handout(1), "c", &other, &[2; 48], 1, now)
                .unwrap(),
            PutWelcome::Taken
        );
        assert!(store.device_welcomes(&alice(), &dev).unwrap().is_empty());
        // Removing the device removes its pending Welcomes.
        assert_eq!(
            store
                .put_welcome(handout(2), "b", &w, &[1; 48], 1, now)
                .unwrap(),
            PutWelcome::Stored("b".into())
        );
        store.forget_device(&alice(), &dev).unwrap();
        assert!(store.device_welcomes(&alice(), &dev).unwrap().is_empty());
        assert_eq!(
            store.count_key_packages(&alice(), &dev, now).unwrap(),
            KeyPackageCount::default()
        );
    }

    fn times(now: Timestamp, retention: Timestamp, room_trees: Timestamp) -> ExpiryTimes {
        ExpiryTimes {
            now,
            retention,
            room_trees,
            unclaimed: now,
            unfinished: now,
        }
    }

    #[test]
    fn room_joins_keep_their_tree_for_welcome_get() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mailbox = BoxName::from_bytes([3; 16]);
        let tree = BlobRef::of(b"tree");
        let joins = |epoch, refs: Vec<RefBytes>, tree| RoomJoins {
            mailbox,
            epoch,
            committer_uid: alice(),
            committer: [1; 48],
            refs,
            tree,
            tree_size: 4,
        };
        store
            .add_room_joins(&joins(4, vec![[7; 48], [8; 48]], OrBlob::Blob(tree)), t(T0))
            .unwrap();
        store
            .add_room_joins(
                &joins(5, vec![[9; 48]], OrBlob::Inline(vec![1, 2])),
                later(60),
            )
            .unwrap();
        // The server made the tree's blob, which counts against nobody and
        // is kept.
        let blob = store.blob(&tree).unwrap().unwrap();
        assert!(blob.kept && blob.mailbox.is_none() && blob.uid.is_none());
        let handouts = store.handouts(&[7; 48]).unwrap();
        assert_eq!(
            handouts[0].handout,
            Handout::Room {
                mailbox,
                epoch: 4,
                committer_uid: alice(),
                committer: [1; 48]
            }
        );
        assert_eq!(store.room_welcome(&[7; 48]).unwrap(), None);
        let w = OrBlob::Inline(vec![5]);
        for r in [7, 9] {
            let h = store.handouts(&[r; 48]).unwrap()[0].id;
            let id = format!("w{r}");
            assert_eq!(
                store.put_welcome(h, &id, &w, &[5; 48], 0, t(T0)).unwrap(),
                PutWelcome::Stored(id)
            );
        }
        let got = store.room_welcome(&[7; 48]).unwrap().unwrap();
        assert_eq!(got.welcome.id, "w7");
        assert_eq!(got.tree, OrBlob::Blob(tree));
        assert_eq!(
            store.room_welcome(&[9; 48]).unwrap().unwrap().tree,
            OrBlob::Inline(vec![1, 2])
        );
        // WELCOME GET does not freeze it: the committer may still replace
        // it, since anyone may send WELCOME GET (12.8).
        let h = handouts[0].id;
        assert!(matches!(
            store
                .put_welcome(h, "x", &OrBlob::Inline(vec![6]), &[6; 48], 0, t(T0))
                .unwrap(),
            PutWelcome::Replaced(_)
        ));
        // 24 hours after its commit, a tree goes with its Welcomes, and the
        // blob the server made of it with them.
        let expired = store
            .expire_keys(&times(later(30), t(T0), later(30)))
            .unwrap();
        assert_eq!(expired.blobs, vec![tree]);
        assert!(store.blob(&tree).unwrap().is_none());
        assert!(store.handouts(&[7; 48]).unwrap().is_empty());
        assert_eq!(store.room_welcome(&[7; 48]).unwrap(), None);
        assert!(store.room_welcome(&[9; 48]).unwrap().is_some());
        // A tree blob that someone named with BLOB since stays for
        // retention.
        let other = BlobRef::of(b"other tree");
        store
            .add_room_joins(&joins(6, vec![[10; 48]], OrBlob::Blob(other)), later(100))
            .unwrap();
        assert!(store.touch_blob(&other, later(200)).unwrap());
        let expired = store
            .expire_keys(&times(later(300), t(T0), later(300)))
            .unwrap();
        assert!(expired.blobs.is_empty());
        let blob = store.blob(&other).unwrap().unwrap();
        assert!(!blob.kept);
    }

    #[test]
    fn blobs_expire_unless_kept() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mailbox = BoxName::from_bytes([3; 16]);
        let put = |n: u8| BlobPut {
            id: format!("p{n}"),
            secret: SecretHash::of(&[n]),
            hash: BlobRef::of(&[n]),
            size: 100,
            mailbox: Some(mailbox),
            uid: None,
            expires: later(600),
        };
        store.add_blob_put(&put(1)).unwrap();
        assert_eq!(store.mailbox_file_bytes(&mailbox).unwrap(), 100);
        assert_eq!(store.blob_put("p1").unwrap(), Some(put(1)));
        assert!(store.claim_blob_put("p1").unwrap());
        assert!(!store.claim_blob_put("p1").unwrap());
        store.blob_stored(&put(1), t(T0)).unwrap();
        store.blob_stored(&put(2), t(T0)).unwrap();
        assert_eq!(store.mailbox_file_bytes(&mailbox).unwrap(), 200);
        assert!(
            store
                .set_blob_keeps("backup a", &[BlobRef::of(&[1])])
                .unwrap()
                .is_empty()
        );
        assert!(store.blob(&BlobRef::of(&[1])).unwrap().unwrap().kept);
        // Retention counts from the last BLOB that named it.
        assert!(store.touch_blob(&BlobRef::of(&[2]), later(50)).unwrap());
        let times = |retention| ExpiryTimes {
            now: later(100),
            retention: later(retention),
            room_trees: later(0),
            unclaimed: later(0),
            unfinished: later(0),
        };
        assert_eq!(store.expire_keys(&times(10)).unwrap(), Expired::default());
        assert_eq!(
            store.expire_keys(&times(60)).unwrap().blobs,
            [BlobRef::of(&[2])]
        );
        assert!(store.blob(&BlobRef::of(&[1])).unwrap().is_some());
        // Once nothing keeps it, it goes too.
        assert_eq!(
            store.set_blob_keeps("backup a", &[]).unwrap(),
            [BlobRef::of(&[1])]
        );
        assert!(store.delete_blob(&BlobRef::of(&[1])).unwrap());
        assert!(!store.touch_blob(&BlobRef::of(&[1]), later(60)).unwrap());
    }

    #[test]
    fn uploads_expire_from_their_upload_and_reports_keep_them() {
        let store = SqliteStore::open_in_memory().unwrap();
        let upload = |id: &str| UploadRecord {
            id: id.into(),
            mailbox: BoxName::from_bytes([3; 16]),
            put: SecretHash::of(b"p"),
            get: SecretHash::of(b"g"),
            del: SecretHash::of(b"d"),
            size: 10,
            created: t(T0),
            claimed: false,
            stored: None,
            held: 0,
            deleted: false,
        };
        for id in ["a", "b", "c"] {
            store.add_upload(&upload(id)).unwrap();
        }
        assert!(store.claim_upload("a").unwrap());
        assert!(!store.claim_upload("a").unwrap());
        assert!(store.upload_stored("a", later(5)).unwrap());
        assert!(store.claim_upload("b").unwrap());
        assert!(store.hold_upload("r1", "a", 0).unwrap());
        assert!(store.hold_upload("r1", "a", 0).unwrap());
        assert!(store.hold_upload("r2", "a", 0).unwrap());
        assert!(!store.hold_upload("r2", "none", 0).unwrap());
        assert_eq!(store.upload("a").unwrap().unwrap().held, 2);
        // What reports keep has its own bound: a file no report keeps yet
        // that does not fit is not kept; one another report keeps is.
        assert_eq!(store.stored_total().unwrap().reported, 10);
        assert!(!store.hold_upload("r3", "c", 15).unwrap());
        assert!(store.hold_upload("r3", "a", 15).unwrap());
        assert!(store.hold_upload("r3", "c", 20).unwrap());
        assert!(store.release_uploads("r3", later(0)).unwrap().is_empty());
        assert_eq!(store.upload("a").unwrap().unwrap().held, 2);
        // Held: the uploader's DELETE waits for the report.
        assert!(!store.delete_upload("a").unwrap());
        assert!(store.upload("a").unwrap().unwrap().deleted);
        let expired = store
            .expire_keys(&ExpiryTimes {
                now: later(700),
                retention: later(100),
                room_trees: later(0),
                unclaimed: later(1),
                unfinished: later(0),
            })
            .unwrap();
        // c never started; b started and may still finish.
        assert_eq!(expired.uploads, ["c"]);
        // Kept until every report that keeps it is resolved.
        assert!(store.release_uploads("r1", later(0)).unwrap().is_empty());
        assert!(store.upload("a").unwrap().is_some());
        assert!(store.release_uploads("r1", later(0)).unwrap().is_empty());
        assert_eq!(store.release_uploads("r2", later(0)).unwrap(), ["a"]);
        assert_eq!(store.upload("a").unwrap(), None);
        assert!(store.delete_upload("b").unwrap());
    }
}
