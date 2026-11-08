//! Files, blobs, history transfers, backups and reports (5.6, 5.8,
//! 12.11-12.13).
//!
//! Owned by task C4.
//!
//! - **`files`**: the files this device shared (with the `del` URL that
//!   deletes them, 5.6) and the ones it fetched or may fetch from a blob
//!   that a transfer or backup listed (12.13). A file's key and hash stay
//!   in the message's content, where the TEXT line has them.
//! - **`file_blobs`**: the blob copies of files this device made for
//!   transfers and backups, reused for the same file (12.13).
//! - **`message_meta`**: what a stored message's RisalaMessage held that the
//!   messages table does not (its counter, `previous` and the sender's
//!   device), and where it came from besides the server: copied by another
//!   device, or restored from a backup (12.13).
//! - **`wants`** and **`want_requests`**: the ranges this device asked for
//!   with WANT and has not filled, and the WANTs of other devices still to
//!   answer (12.13).
//! - **`transfers`** and **`transfer_pending`**: TRANSFER lines and the
//!   pairing transfer to fetch and apply, and archived conversations of a
//!   pairing transfer waiting for this device to join their groups.
//! - **`backups`**: the last backup this device made or restored, per
//!   identity.
//! - **`reports`**: REPORT lines received as a room's owner or moderator
//!   (5.8).
//! - **`server_files`**: what INFO says about uploads and blobs (8.5).

use rusqlite::{OptionalExtension as _, Row, params};

use super::conversations::ConversationId;
use super::{AccountId, Change, Store, StoreError, Tx};

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- Files shared in conversations (5.6, 12.11), by the message that shares
-- them. hash is file-hash. del_url is set for a file this device uploaded
-- (5.6). path is the decrypted copy, once fetched. blob_hash and blob_key
-- are the blob a transfer or backup listed for this message's file
-- (12.13), fetched instead of url, and only for this message.
CREATE TABLE files (
    conv       INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    message_id BLOB NOT NULL,
    hash       BLOB NOT NULL,
    url        TEXT NOT NULL,
    del_url    TEXT,
    size       INTEGER,
    media_type TEXT,
    path       TEXT,
    blob_hash  BLOB,
    blob_key   BLOB,
    state      TEXT NOT NULL CHECK (state IN ('shared', 'fetched', 'failed', 'deleted')),
    created    INTEGER NOT NULL,
    PRIMARY KEY (conv, message_id)
) WITHOUT ROWID;

-- Files this device encrypted again as blobs for transfers and backups
-- (12.13), by file-hash, so that later backups reuse the blob and key.
CREATE TABLE file_blobs (
    account   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    file_hash BLOB NOT NULL,
    blob_hash BLOB NOT NULL,
    key       BLOB NOT NULL,
    PRIMARY KEY (account, file_hash)
) WITHOUT ROWID;

-- What a message's RisalaMessage held besides its content (12.9): the
-- counter, previous, and the sender's device id, for transfers (12.13).
-- origin is where the message came from: 'server', 'copied' from another
-- device of the identity (by device id and label), or 'restored' from a
-- backup made at made. vouched is the verified flag of the device that
-- archived it: its word, never shown as this device's own check.
CREATE TABLE message_meta (
    conv         INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    message_id   BLOB NOT NULL,
    counter      INTEGER NOT NULL,
    previous     BLOB,
    device_id    BLOB,
    origin       TEXT NOT NULL DEFAULT 'server'
                 CHECK (origin IN ('server', 'copied', 'restored')),
    from_device  BLOB,
    from_label   TEXT,
    made         INTEGER,
    vouched      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conv, message_id)
) WITHOUT ROWID;

-- Ranges of a mailbox this device asked its identity's other devices for
-- with WANT, and has not filled (12.13). before is NULL for '-'.
CREATE TABLE wants (
    account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    mailbox TEXT NOT NULL,
    after   INTEGER NOT NULL,
    before  INTEGER,
    asked   INTEGER NOT NULL,
    PRIMARY KEY (account, mailbox, after)
) WITHOUT ROWID;

-- WANTs from the identity's other devices, to answer with TRANSFER.
CREATE TABLE want_requests (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    account  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    mailbox  TEXT NOT NULL,
    after    INTEGER NOT NULL,
    before   INTEGER,
    received INTEGER NOT NULL,
    UNIQUE (account, mailbox, after, before)
);

-- History transfers to fetch and apply (12.13): from a TRANSFER line, or
-- the IdentityBundle's at pairing, or a backup restored after recovery
-- (kind 'backup', made when it was made). ref is the encoded TransferRef. state:
-- 'pending' to fetch, 'waiting' (a pairing transfer whose conversations
-- wait in transfer_pending for this device to join them), 'done',
-- 'failed'. missing is how many archives could not be fetched or opened,
-- ignored how many conversations were out of seq order: the user is told.
CREATE TABLE transfers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account     INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('pairing', 'want', 'backup')),
    ref         BLOB NOT NULL,
    from_device BLOB,
    from_label  TEXT,
    state       TEXT NOT NULL CHECK (state IN ('pending', 'waiting', 'done', 'failed')),
    attempts    INTEGER NOT NULL DEFAULT 0,
    not_before  INTEGER,
    missing     INTEGER NOT NULL DEFAULT 0,
    ignored     INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    made        INTEGER,
    created     INTEGER NOT NULL
);

-- The conversations of a pairing transfer that this device is not in yet
-- (12.13, 4.8): each as an encoded HistoryArchive holding that
-- conversation and the transfer's files, applied once the device joins.
CREATE TABLE transfer_pending (
    transfer INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    group_id BLOB NOT NULL,
    archive  BLOB NOT NULL,
    PRIMARY KEY (transfer, group_id)
) WITHOUT ROWID;

-- The last backup this device made or restored, per identity (12.13).
-- blobs is every blob it names, as 48-byte hashes one after another.
CREATE TABLE backups (
    uid        TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    blob_hash  BLOB NOT NULL,
    made       INTEGER NOT NULL,
    restored   INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

-- Reports received as a room's owner or moderator (5.8): from REPORT
-- lines in a direct conversation (conv) with the reporter. room is the
-- room's conversation on this device, if it has one. context holds the
-- context's message ids, 16 bytes each.
CREATE TABLE reports (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    account  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    conv     INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    reporter TEXT NOT NULL,
    room     INTEGER REFERENCES conversations(id) ON DELETE SET NULL,
    mailbox  TEXT NOT NULL,
    target   BLOB NOT NULL,
    context  BLOB NOT NULL,
    reason   TEXT NOT NULL,
    received INTEGER NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0
);

-- What INFO says about files and blobs, per server (8.5): the largest
-- upload (NULL for upload=no), the origins of get URLs, comma-separated,
-- and the blobs URL prefix.
CREATE TABLE server_files (
    server  TEXT PRIMARY KEY,
    upload  INTEGER,
    files   TEXT NOT NULL,
    blobs   TEXT,
    fetched INTEGER NOT NULL
) WITHOUT ROWID;
";

/// A change to files, transfers, backups or reports.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransferChange {
    /// A file's state changed: the message that shares it.
    File(ConversationId, [u8; 16]),
    /// A transfer or a WANT changed.
    Transfers,
    /// A backup was made or restored.
    Backups,
    /// A report arrived or was resolved.
    Reports,
}

fn change(c: TransferChange) -> Change {
    Change::Transfer(c)
}

/// A file row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    /// The conversation.
    pub conv: ConversationId,
    /// The message that shares it.
    pub message_id: [u8; 16],
    /// Its `file-hash`.
    pub hash: [u8; 48],
    /// Its `get` URL.
    pub url: String,
    /// Its `del` URL, if this device uploaded it.
    pub del_url: Option<String>,
    /// Its size before encryption, as shown before the download.
    pub size: Option<u64>,
    /// Its media type, as the message gives it.
    pub media_type: Option<String>,
    /// The decrypted copy on this device.
    pub path: Option<String>,
    /// The blob a transfer or backup listed for it, and its key (12.13).
    pub blob: Option<([u8; 48], [u8; 32])>,
    /// `shared`, `fetched`, `failed` or `deleted`.
    pub state: String,
}

const FILE_COLUMNS: &str =
    "conv, message_id, hash, url, del_url, size, media_type, path, blob_hash, blob_key, state";

fn fixed<const N: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, "length".into())
    })
}

fn file_row(row: &Row<'_>) -> rusqlite::Result<FileRow> {
    let blob_hash: Option<Vec<u8>> = row.get(8)?;
    let blob_key: Option<Vec<u8>> = row.get(9)?;
    let blob = match (blob_hash, blob_key) {
        (Some(h), Some(k)) => Some((fixed(h)?, fixed(k)?)),
        _ => None,
    };
    Ok(FileRow {
        conv: ConversationId(row.get(0)?),
        message_id: fixed(row.get(1)?)?,
        hash: fixed(row.get(2)?)?,
        url: row.get(3)?,
        del_url: row.get(4)?,
        size: row.get::<_, Option<i64>>(5)?.map(|s| s as u64),
        media_type: row.get(6)?,
        path: row.get(7)?,
        blob,
        state: row.get(10)?,
    })
}

/// Where a stored message came from (12.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// From the server, as posted.
    Server,
    /// Copied from another device of the identity, in a transfer: its
    /// device id and label.
    Copied {
        /// The device that sent the transfer.
        device: Option<[u8; 48]>,
        /// Its label, as this device knew it.
        label: Option<String>,
    },
    /// Restored from a backup made at `made` (ms).
    Restored {
        /// When the backup was made.
        made: u64,
    },
}

/// What [`Tx::message_meta`] keeps of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMeta {
    /// The RisalaMessage's counter.
    pub counter: u64,
    /// Its `previous`.
    pub previous: Option<[u8; 16]>,
    /// The sender's device id, `None` for a guest.
    pub device_id: Option<[u8; 48]>,
    /// Where it came from.
    pub origin: Origin,
    /// For a copied or restored message, whether the archiving device had
    /// confirmed the sender's leaf (12.13): its word, not this device's.
    pub vouched: bool,
}

fn meta_row(row: &Row<'_>) -> rusqlite::Result<MessageMeta> {
    let origin: String = row.get(3)?;
    let previous: Option<Vec<u8>> = row.get(1)?;
    let device: Option<Vec<u8>> = row.get(2)?;
    let from: Option<Vec<u8>> = row.get(4)?;
    Ok(MessageMeta {
        counter: row.get::<_, i64>(0)? as u64,
        previous: previous.map(fixed).transpose()?,
        device_id: device.map(fixed).transpose()?,
        origin: match origin.as_str() {
            "copied" => Origin::Copied {
                device: from.map(fixed).transpose()?,
                label: row.get(5)?,
            },
            "restored" => Origin::Restored {
                made: row.get::<_, Option<i64>>(6)?.unwrap_or(0) as u64,
            },
            _ => Origin::Server,
        },
        vouched: row.get(7)?,
    })
}

/// A range asked for with WANT (12.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WantRange {
    /// After this seq.
    pub after: u64,
    /// Before this seq; `None` for `-`.
    pub before: Option<u64>,
}

impl WantRange {
    /// Whether `seq` lies in the range.
    pub fn holds(&self, seq: u64) -> bool {
        seq > self.after && self.before.is_none_or(|b| seq < b)
    }
}

/// A WANT of another device, to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WantRequest {
    /// Its row.
    pub id: i64,
    /// The mailbox.
    pub mailbox: String,
    /// The range.
    pub range: WantRange,
}

/// The kind of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    /// The IdentityBundle's, at pairing (4.8).
    Pairing,
    /// A TRANSFER line's, for a WANT.
    Want,
    /// A backup restored after recovery (12.13): its conversations wait
    /// for the device to join them, as at pairing.
    Backup,
}

impl TransferKind {
    fn as_str(self) -> &'static str {
        match self {
            TransferKind::Pairing => "pairing",
            TransferKind::Want => "want",
            TransferKind::Backup => "backup",
        }
    }
}

/// A transfer row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRow {
    /// Its id.
    pub id: i64,
    /// The account.
    pub account: AccountId,
    /// Its kind.
    pub kind: TransferKind,
    /// The encoded TransferRef.
    pub reference: Vec<u8>,
    /// The device that sent it.
    pub from_device: Option<[u8; 48]>,
    /// That device's label.
    pub from_label: Option<String>,
    /// `pending`, `waiting`, `done` or `failed`.
    pub state: String,
    /// Fetch attempts so far.
    pub attempts: u32,
    /// Archives that could not be fetched or opened.
    pub missing: u32,
    /// Conversations out of seq order.
    pub ignored: u32,
    /// Why it failed.
    pub error: Option<String>,
    /// When a backup was made.
    pub made: Option<u64>,
    /// When it arrived.
    pub created: u64,
}

const TRANSFER_COLUMNS: &str = "id, account, kind, ref, from_device, from_label, state, attempts, \
     missing, ignored, error, made, created";

fn transfer_row(row: &Row<'_>) -> rusqlite::Result<TransferRow> {
    let kind: String = row.get(2)?;
    let from: Option<Vec<u8>> = row.get(4)?;
    Ok(TransferRow {
        id: row.get(0)?,
        account: AccountId(row.get(1)?),
        kind: match kind.as_str() {
            "pairing" => TransferKind::Pairing,
            "backup" => TransferKind::Backup,
            _ => TransferKind::Want,
        },
        reference: row.get(3)?,
        from_device: from.map(fixed).transpose()?,
        from_label: row.get(5)?,
        state: row.get(6)?,
        attempts: row.get(7)?,
        missing: row.get(8)?,
        ignored: row.get(9)?,
        error: row.get(10)?,
        made: row.get::<_, Option<i64>>(11)?.map(|m| m as u64),
        created: row.get::<_, i64>(12)? as u64,
    })
}

/// The last backup this device made or restored for an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRow {
    /// The identity.
    pub uid: String,
    /// Its generation.
    pub generation: u32,
    /// The first archive's blob.
    pub blob_hash: [u8; 48],
    /// When it was made.
    pub made: u64,
    /// Whether this device restored it rather than made it.
    pub restored: bool,
}

/// A report received as a room's owner or moderator (5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRow {
    /// Its id.
    pub id: i64,
    /// The account.
    pub account: AccountId,
    /// The direct conversation it came in.
    pub conv: ConversationId,
    /// Who reported, as their leaf shows.
    pub reporter: String,
    /// The room, on this device.
    pub room: Option<ConversationId>,
    /// The room's mailbox.
    pub mailbox: String,
    /// The reported message.
    pub target: [u8; 16],
    /// The context's messages, oldest first.
    pub context: Vec<[u8; 16]>,
    /// The reason, escaped.
    pub reason: String,
    /// When it arrived.
    pub received: u64,
    /// Whether the moderator dealt with it.
    pub resolved: bool,
}

fn report_row(row: &Row<'_>) -> rusqlite::Result<ReportRow> {
    let context: Vec<u8> = row.get(7)?;
    Ok(ReportRow {
        id: row.get(0)?,
        account: AccountId(row.get(1)?),
        conv: ConversationId(row.get(2)?),
        reporter: row.get(3)?,
        room: row.get::<_, Option<i64>>(4)?.map(ConversationId),
        mailbox: row.get(5)?,
        target: fixed(row.get(6)?)?,
        context: context
            .chunks_exact(16)
            .map(|c| c.try_into().expect("16 bytes"))
            .collect(),
        reason: row.get(8)?,
        received: row.get::<_, i64>(9)? as u64,
        resolved: row.get(10)?,
    })
}

/// What INFO says about a server's files and blobs (8.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFiles {
    /// The largest upload, or `None` for `upload=no`.
    pub upload: Option<u64>,
    /// The origins of the server's `get` URLs (`https://host[:port]`).
    pub files: Vec<String>,
    /// The blobs URL prefix.
    pub blobs: Option<String>,
    /// When INFO was sent.
    pub fetched: u64,
}

impl Tx<'_> {
    // ---- files

    /// Notes a file this device shared, with its `del` URL (5.6).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_shared_file(
        &mut self,
        conv: ConversationId,
        message_id: &[u8; 16],
        hash: &[u8; 48],
        url: &str,
        del_url: Option<&str>,
        size: u64,
        media_type: Option<&str>,
        now: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO files (conv, message_id, hash, url, del_url, size, media_type, state, created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'shared', ?8)
             ON CONFLICT DO UPDATE SET del_url = excluded.del_url",
            params![
                conv.0,
                &message_id[..],
                &hash[..],
                url,
                del_url,
                size as i64,
                media_type,
                now as i64
            ],
        )?;
        self.changed(change(TransferChange::File(conv, *message_id)));
        Ok(())
    }

    /// Notes the blob a transfer or backup listed for a message's file
    /// (12.13): fetched instead of the `file` URL, for this message only.
    pub(crate) fn set_file_blob(
        &mut self,
        conv: ConversationId,
        message_id: &[u8; 16],
        hash: &[u8; 48],
        url: &str,
        blob: &[u8; 48],
        key: &[u8; 32],
        now: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO files (conv, message_id, hash, url, blob_hash, blob_key, state, created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'shared', ?7)
             ON CONFLICT DO UPDATE SET blob_hash = excluded.blob_hash, blob_key = excluded.blob_key",
            params![
                conv.0,
                &message_id[..],
                &hash[..],
                url,
                &blob[..],
                &key[..],
                now as i64
            ],
        )?;
        Ok(())
    }

    /// Notes where a file's decrypted copy is, or that fetching it failed.
    pub(crate) fn set_file_fetched(
        &mut self,
        conv: ConversationId,
        message_id: &[u8; 16],
        hash: &[u8; 48],
        url: &str,
        path: Option<&str>,
        now: u64,
    ) -> Result<(), StoreError> {
        let state = if path.is_some() { "fetched" } else { "failed" };
        self.conn().execute(
            "INSERT INTO files (conv, message_id, hash, url, path, state, created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT DO UPDATE SET path = excluded.path, state = excluded.state",
            params![
                conv.0,
                &message_id[..],
                &hash[..],
                url,
                path,
                state,
                now as i64
            ],
        )?;
        self.changed(change(TransferChange::File(conv, *message_id)));
        Ok(())
    }

    /// Marks a file deleted on the server (5.6).
    pub(crate) fn set_file_deleted(
        &mut self,
        conv: ConversationId,
        message_id: &[u8; 16],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE files SET state = 'deleted', del_url = NULL WHERE conv = ?1 AND message_id = ?2",
            params![conv.0, &message_id[..]],
        )?;
        self.changed(change(TransferChange::File(conv, *message_id)));
        Ok(())
    }

    /// The file a message shares, if the cache has a row for it.
    pub(crate) fn file(
        &self,
        conv: ConversationId,
        message_id: &[u8; 16],
    ) -> Result<Option<FileRow>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT {FILE_COLUMNS} FROM files WHERE conv = ?1 AND message_id = ?2"),
                params![conv.0, &message_id[..]],
                file_row,
            )
            .optional()?)
    }

    /// The blob copy of a file for transfers and backups, if this device
    /// made one (12.13).
    pub(crate) fn file_blob(
        &self,
        account: AccountId,
        file_hash: &[u8; 48],
    ) -> Result<Option<([u8; 48], [u8; 32])>, StoreError> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn()
            .query_row(
                "SELECT blob_hash, key FROM file_blobs WHERE account = ?1 AND file_hash = ?2",
                params![account.0, &file_hash[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row
            .map(|(h, k)| Ok::<_, rusqlite::Error>((fixed(h)?, fixed(k)?)))
            .transpose()?)
    }

    /// Keeps the blob copy of a file (12.13).
    pub(crate) fn add_file_blob(
        &mut self,
        account: AccountId,
        file_hash: &[u8; 48],
        blob: &[u8; 48],
        key: &[u8; 32],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO file_blobs (account, file_hash, blob_hash, key) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT DO UPDATE SET blob_hash = excluded.blob_hash, key = excluded.key",
            params![account.0, &file_hash[..], &blob[..], &key[..]],
        )?;
        Ok(())
    }

    // ---- message meta

    /// Keeps what a message's RisalaMessage held besides its content.
    pub(crate) fn set_message_meta(
        &mut self,
        conv: ConversationId,
        message_id: &[u8; 16],
        meta: &MessageMeta,
    ) -> Result<(), StoreError> {
        let (origin, from, label, made) = match &meta.origin {
            Origin::Server => ("server", None, None, None),
            Origin::Copied { device, label } => {
                ("copied", device.map(|d| d.to_vec()), label.clone(), None)
            }
            Origin::Restored { made } => ("restored", None, None, Some(*made as i64)),
        };
        self.conn().execute(
            "INSERT INTO message_meta
                 (conv, message_id, counter, previous, device_id, origin, from_device, from_label,
                  made, vouched)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT DO NOTHING",
            params![
                conv.0,
                &message_id[..],
                meta.counter as i64,
                meta.previous.as_ref().map(|p| &p[..]),
                meta.device_id.as_ref().map(|d| &d[..]),
                origin,
                from,
                label,
                made,
                meta.vouched
            ],
        )?;
        Ok(())
    }

    /// What the cache keeps of a message's RisalaMessage.
    pub(crate) fn message_meta(
        &self,
        conv: ConversationId,
        message_id: &[u8; 16],
    ) -> Result<Option<MessageMeta>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT counter, previous, device_id, origin, from_device, from_label, made, vouched
                 FROM message_meta WHERE conv = ?1 AND message_id = ?2",
                params![conv.0, &message_id[..]],
                meta_row,
            )
            .optional()?)
    }

    /// Whether the group has seen a message id: stored, or seen as a line
    /// that is not shown (12.9, 12.13).
    pub(crate) fn message_seen(
        &self,
        conv: ConversationId,
        message_id: &[u8; 16],
    ) -> Result<bool, StoreError> {
        let n: i64 = self.conn().query_row(
            "SELECT (SELECT count(*) FROM messages WHERE conv = ?1 AND message_id = ?2)
                  + (SELECT count(*) FROM seen WHERE conv = ?1 AND message_id = ?2)",
            params![conv.0, &message_id[..]],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    // ---- wants

    /// Notes a range asked for with WANT. Returns false if the same range
    /// was already asked.
    pub(crate) fn add_want(
        &mut self,
        account: AccountId,
        mailbox: &str,
        range: WantRange,
        now: u64,
    ) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "INSERT INTO wants (account, mailbox, after, before, asked) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT DO NOTHING",
            params![
                account.0,
                mailbox,
                range.after as i64,
                range.before.map(|b| b as i64),
                now as i64
            ],
        )?;
        if n > 0 {
            self.changed(change(TransferChange::Transfers));
        }
        Ok(n > 0)
    }

    /// The ranges of `mailbox` asked for and not filled.
    pub(crate) fn wants(
        &self,
        account: AccountId,
        mailbox: &str,
    ) -> Result<Vec<WantRange>, StoreError> {
        let mut stmt = self.conn().prepare_cached(
            "SELECT after, before FROM wants WHERE account = ?1 AND mailbox = ?2",
        )?;
        let rows = stmt.query_map(params![account.0, mailbox], |r| {
            Ok(WantRange {
                after: r.get::<_, i64>(0)? as u64,
                before: r.get::<_, Option<i64>>(1)?.map(|b| b as u64),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every range asked for and not filled, by mailbox.
    pub(crate) fn all_wants(
        &self,
        account: AccountId,
    ) -> Result<Vec<(String, WantRange, u64)>, StoreError> {
        let mut stmt = self
            .conn()
            .prepare_cached("SELECT mailbox, after, before, asked FROM wants WHERE account = ?1")?;
        let rows = stmt.query_map(params![account.0], |r| {
            Ok((
                r.get::<_, String>(0)?,
                WantRange {
                    after: r.get::<_, i64>(1)? as u64,
                    before: r.get::<_, Option<i64>>(2)?.map(|b| b as u64),
                },
                r.get::<_, i64>(3)? as u64,
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Marks a range filled.
    pub(crate) fn remove_want(
        &mut self,
        account: AccountId,
        mailbox: &str,
        after: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM wants WHERE account = ?1 AND mailbox = ?2 AND after = ?3",
            params![account.0, mailbox, after as i64],
        )?;
        self.changed(change(TransferChange::Transfers));
        Ok(())
    }

    /// Keeps another device's WANT, to answer.
    pub(crate) fn add_want_request(
        &mut self,
        account: AccountId,
        mailbox: &str,
        range: WantRange,
        now: u64,
    ) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "INSERT INTO want_requests (account, mailbox, after, before, received)
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING",
            params![
                account.0,
                mailbox,
                range.after as i64,
                range.before.map(|b| b as i64),
                now as i64
            ],
        )?;
        if n > 0 {
            self.changed(change(TransferChange::Transfers));
        }
        Ok(())
    }

    /// The WANTs of other devices to answer.
    pub(crate) fn want_requests(&self, account: AccountId) -> Result<Vec<WantRequest>, StoreError> {
        let mut stmt = self.conn().prepare_cached(
            "SELECT id, mailbox, after, before FROM want_requests WHERE account = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![account.0], |r| {
            Ok(WantRequest {
                id: r.get(0)?,
                mailbox: r.get(1)?,
                range: WantRange {
                    after: r.get::<_, i64>(2)? as u64,
                    before: r.get::<_, Option<i64>>(3)?.map(|b| b as u64),
                },
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Drops an answered WANT.
    pub(crate) fn remove_want_request(&mut self, id: i64) -> Result<(), StoreError> {
        self.conn()
            .execute("DELETE FROM want_requests WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ---- transfers

    /// Keeps a transfer to fetch. Returns its id, or `None` if the same
    /// TransferRef is already kept.
    pub(crate) fn add_transfer(
        &mut self,
        account: AccountId,
        kind: TransferKind,
        reference: &[u8],
        from_device: Option<&[u8; 48]>,
        from_label: Option<&str>,
        now: u64,
    ) -> Result<Option<i64>, StoreError> {
        let exists: i64 = self.conn().query_row(
            "SELECT count(*) FROM transfers WHERE account = ?1 AND ref = ?2",
            params![account.0, reference],
            |r| r.get(0),
        )?;
        if exists > 0 {
            return Ok(None);
        }
        self.conn().execute(
            "INSERT INTO transfers (account, kind, ref, from_device, from_label, state, created)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
            params![
                account.0,
                kind.as_str(),
                reference,
                from_device.map(|d| &d[..]),
                from_label,
                now as i64
            ],
        )?;
        self.changed(change(TransferChange::Transfers));
        Ok(Some(self.conn().last_insert_rowid()))
    }

    /// The transfers due to fetch now.
    pub(crate) fn due_transfers(
        &self,
        account: AccountId,
        now: u64,
    ) -> Result<Vec<TransferRow>, StoreError> {
        let mut stmt = self.conn().prepare_cached(&format!(
            "SELECT {TRANSFER_COLUMNS} FROM transfers
             WHERE account = ?1 AND state = 'pending' AND (not_before IS NULL OR not_before <= ?2)
             ORDER BY id"
        ))?;
        let rows = stmt.query_map(params![account.0, now as i64], transfer_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// A transfer.
    pub(crate) fn transfer(&self, id: i64) -> Result<Option<TransferRow>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT {TRANSFER_COLUMNS} FROM transfers WHERE id = ?1"),
                params![id],
                transfer_row,
            )
            .optional()?)
    }

    /// Sets a transfer's state, with what to tell the user.
    pub(crate) fn set_transfer_state(
        &mut self,
        id: i64,
        state: &str,
        missing: usize,
        ignored: usize,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE transfers SET state = ?2, missing = ?3, ignored = ?4, error = ?5 WHERE id = ?1",
            params![id, state, missing as i64, ignored as i64, error],
        )?;
        self.changed(change(TransferChange::Transfers));
        Ok(())
    }

    /// Notes when a restored backup was made.
    pub(crate) fn set_transfer_made(&mut self, id: i64, made: u64) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE transfers SET made = ?2 WHERE id = ?1",
            params![id, made as i64],
        )?;
        Ok(())
    }

    /// Puts a transfer off after a failed fetch.
    pub(crate) fn retry_transfer(&mut self, id: i64, not_before: u64) -> Result<u32, StoreError> {
        self.conn().execute(
            "UPDATE transfers SET attempts = attempts + 1, not_before = ?2 WHERE id = ?1",
            params![id, not_before as i64],
        )?;
        Ok(self.conn().query_row(
            "SELECT attempts FROM transfers WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?)
    }

    /// Keeps a conversation of a pairing transfer until this device joins
    /// its group.
    pub(crate) fn add_transfer_pending(
        &mut self,
        transfer: i64,
        group_id: &[u8],
        archive: &[u8],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO transfer_pending (transfer, group_id, archive) VALUES (?1, ?2, ?3)
             ON CONFLICT DO UPDATE SET archive = excluded.archive",
            params![transfer, group_id, archive],
        )?;
        Ok(())
    }

    /// The conversations of pairing transfers still waiting: transfer,
    /// group id and encoded archive.
    pub(crate) fn transfer_pending(
        &self,
        account: AccountId,
    ) -> Result<Vec<(i64, Vec<u8>, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn().prepare_cached(
            "SELECT p.transfer, p.group_id, p.archive FROM transfer_pending p
             JOIN transfers t ON t.id = p.transfer WHERE t.account = ?1",
        )?;
        let rows = stmt.query_map(params![account.0], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Drops a waiting conversation of a pairing transfer; the transfer is
    /// done once none is left.
    pub(crate) fn remove_transfer_pending(
        &mut self,
        transfer: i64,
        group_id: &[u8],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM transfer_pending WHERE transfer = ?1 AND group_id = ?2",
            params![transfer, group_id],
        )?;
        self.conn().execute(
            "UPDATE transfers SET state = 'done' WHERE id = ?1 AND state = 'waiting'
             AND NOT EXISTS (SELECT 1 FROM transfer_pending WHERE transfer = ?1)",
            params![transfer],
        )?;
        self.changed(change(TransferChange::Transfers));
        Ok(())
    }

    /// Drops the waiting conversations of pairing transfers older than
    /// `before`: the device was never added to them.
    pub(crate) fn expire_transfer_pending(
        &mut self,
        account: AccountId,
        before: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM transfer_pending WHERE transfer IN
                 (SELECT id FROM transfers WHERE account = ?1 AND created < ?2)",
            params![account.0, before as i64],
        )?;
        self.conn().execute(
            "UPDATE transfers SET state = 'done' WHERE account = ?1 AND state = 'waiting'
             AND created < ?2",
            params![account.0, before as i64],
        )?;
        Ok(())
    }

    // ---- backups

    /// Keeps the backup this device made or restored.
    pub(crate) fn set_backup(&mut self, row: &BackupRow) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO backups (uid, generation, blob_hash, made, restored)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT DO UPDATE SET generation = excluded.generation,
                 blob_hash = excluded.blob_hash, made = excluded.made, restored = excluded.restored",
            params![
                row.uid,
                row.generation,
                &row.blob_hash[..],
                row.made as i64,
                row.restored
            ],
        )?;
        self.changed(change(TransferChange::Backups));
        Ok(())
    }

    /// Forgets the identity's backup.
    pub(crate) fn remove_backup(&mut self, uid: &str) -> Result<(), StoreError> {
        self.conn()
            .execute("DELETE FROM backups WHERE uid = ?1", params![uid])?;
        self.changed(change(TransferChange::Backups));
        Ok(())
    }

    // ---- reports

    /// Keeps a report received as a room's owner or moderator.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_report(
        &mut self,
        account: AccountId,
        conv: ConversationId,
        reporter: &str,
        room: Option<ConversationId>,
        mailbox: &str,
        target: &[u8; 16],
        context: &[[u8; 16]],
        reason: &str,
        now: u64,
    ) -> Result<i64, StoreError> {
        let context: Vec<u8> = context.iter().flatten().copied().collect();
        self.conn().execute(
            "INSERT INTO reports
                 (account, conv, reporter, room, mailbox, target, context, reason, received)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                account.0,
                conv.0,
                reporter,
                room.map(|r| r.0),
                mailbox,
                &target[..],
                context,
                reason,
                now as i64
            ],
        )?;
        self.changed(change(TransferChange::Reports));
        Ok(self.conn().last_insert_rowid())
    }

    /// Marks a report dealt with.
    pub(crate) fn resolve_report(&mut self, id: i64) -> Result<(), StoreError> {
        self.conn()
            .execute("UPDATE reports SET resolved = 1 WHERE id = ?1", params![id])?;
        self.changed(change(TransferChange::Reports));
        Ok(())
    }

    // ---- server files

    /// Keeps what INFO says about a server's files and blobs.
    pub(crate) fn set_server_files(
        &mut self,
        server: &str,
        info: &ServerFiles,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO server_files (server, upload, files, blobs, fetched)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT DO UPDATE SET upload = excluded.upload, files = excluded.files,
                 blobs = excluded.blobs, fetched = excluded.fetched",
            params![
                server,
                info.upload.map(|u| u as i64),
                info.files.join(","),
                info.blobs,
                info.fetched as i64
            ],
        )?;
        Ok(())
    }
}

impl Store {
    /// The file a message shares, if the cache has a row for it.
    pub fn file_row(
        &self,
        conv: ConversationId,
        message_id: &[u8; 16],
    ) -> Result<Option<FileRow>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row(
                    &format!(
                        "SELECT {FILE_COLUMNS} FROM files WHERE conv = ?1 AND message_id = ?2"
                    ),
                    params![conv.0, &message_id[..]],
                    file_row,
                )
                .optional()?)
        })
    }

    /// Files this device shared whose message is now deleted, and which
    /// it has not deleted on the server yet (5.6).
    pub fn files_to_delete(&self, account: AccountId) -> Result<Vec<FileRow>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {} FROM files f
                 JOIN messages m ON m.conv = f.conv AND m.message_id = f.message_id
                 JOIN conversations c ON c.id = f.conv
                 WHERE c.account = ?1 AND f.del_url IS NOT NULL AND m.deleted = 1",
                FILE_COLUMNS
                    .split(", ")
                    .map(|c| format!("f.{c}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))?;
            let rows = stmt.query_map(params![account.0], file_row)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Where a stored message came from (12.13).
    pub fn message_origin(
        &self,
        conv: ConversationId,
        message_id: &[u8; 16],
    ) -> Result<Origin, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT counter, previous, device_id, origin, from_device, from_label, made, vouched
                     FROM message_meta WHERE conv = ?1 AND message_id = ?2",
                    params![conv.0, &message_id[..]],
                    meta_row,
                )
                .optional()?
                .map_or(Origin::Server, |m| m.origin))
        })
    }

    /// The account's transfers, newest first.
    pub fn transfer_rows(&self, account: AccountId) -> Result<Vec<TransferRow>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {TRANSFER_COLUMNS} FROM transfers WHERE account = ?1 ORDER BY id DESC"
            ))?;
            let rows = stmt.query_map(params![account.0], transfer_row)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The ranges the account asked for with WANT and has not filled.
    pub fn want_rows(&self, account: AccountId) -> Result<Vec<(String, WantRange)>, StoreError> {
        self.read(|conn| {
            let mut stmt =
                conn.prepare("SELECT mailbox, after, before FROM wants WHERE account = ?1")?;
            let rows = stmt.query_map(params![account.0], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    WantRange {
                        after: r.get::<_, i64>(1)? as u64,
                        before: r.get::<_, Option<i64>>(2)?.map(|b| b as u64),
                    },
                ))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The last backup this device made or restored for `uid`.
    pub fn backup_row(&self, uid: &str) -> Result<Option<BackupRow>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT uid, generation, blob_hash, made, restored FROM backups WHERE uid = ?1",
                    params![uid],
                    |r| {
                        Ok(BackupRow {
                            uid: r.get(0)?,
                            generation: r.get(1)?,
                            blob_hash: fixed(r.get(2)?)?,
                            made: r.get::<_, i64>(3)? as u64,
                            restored: r.get(4)?,
                        })
                    },
                )
                .optional()?)
        })
    }

    /// The reports the account received as an owner or moderator, newest
    /// first.
    pub fn report_rows(&self, account: AccountId) -> Result<Vec<ReportRow>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, account, conv, reporter, room, mailbox, target, context, reason,
                        received, resolved
                 FROM reports WHERE account = ?1 ORDER BY id DESC",
            )?;
            let rows = stmt.query_map(params![account.0], report_row)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// What INFO said about a server's files and blobs, if it was asked.
    pub fn server_files(&self, server: &str) -> Result<Option<ServerFiles>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT upload, files, blobs, fetched FROM server_files WHERE server = ?1",
                    params![server],
                    |r| {
                        let files: String = r.get(1)?;
                        Ok(ServerFiles {
                            upload: r.get::<_, Option<i64>>(0)?.map(|u| u as u64),
                            files: files
                                .split(',')
                                .filter(|s| !s.is_empty())
                                .map(str::to_owned)
                                .collect(),
                            blobs: r.get(2)?,
                            fetched: r.get::<_, i64>(3)? as u64,
                        })
                    },
                )
                .optional()?)
        })
    }
}
