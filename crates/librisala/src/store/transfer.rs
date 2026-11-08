//! Files, blobs, history transfers and backups (5.6, 12.11-12.13).
//!
//! Owned by task C4. The tables are a sketch from the spec; C4 may add
//! and change columns and tables.

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- Files shared in conversations (5.6, 12.11): those sent, and those
-- received and fetched. hash is file-hash, key the file key, size the
-- size before encryption. path is the local copy in the download cache.
CREATE TABLE files (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    conv       INTEGER REFERENCES conversations(id) ON DELETE SET NULL,
    message_id BLOB,
    url        TEXT NOT NULL,
    del_url    TEXT,
    hash       BLOB NOT NULL,
    key        BLOB NOT NULL,
    media_type TEXT,
    size       INTEGER NOT NULL,
    path       TEXT,
    state      TEXT NOT NULL CHECK (state IN
               ('uploading', 'uploaded', 'downloading', 'downloaded', 'failed', 'expired')),
    created    INTEGER NOT NULL
);

-- Blobs this device stored or is fetching (12.12), by blob-ref.
CREATE TABLE blobs (
    hash    TEXT NOT NULL,
    server  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    state   TEXT NOT NULL CHECK (state IN ('uploading', 'stored', 'fetching', 'fetched', 'failed')),
    created INTEGER NOT NULL,
    PRIMARY KEY (hash, server)
) WITHOUT ROWID;

-- History transfers (12.13): sent at pairing or to catch a device up, and
-- received. blob_hash and key are the TransferRef.
CREATE TABLE transfers (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    uid       TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('sent', 'received')),
    blob_hash TEXT NOT NULL,
    key       BLOB NOT NULL,
    state     TEXT NOT NULL CHECK (state IN ('pending', 'done', 'failed')),
    created   INTEGER NOT NULL
);

-- The last backup this device made or restored, per identity (12.13).
CREATE TABLE backups (
    uid        TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    blob_hash  TEXT NOT NULL,
    made       INTEGER NOT NULL
) WITHOUT ROWID;
";

/// A change to files, transfers or backups.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransferChange {
    /// A file's state changed. Holds its row id.
    File(i64),
    /// A transfer's state changed.
    Transfers,
    /// A backup was made or restored.
    Backups,
}
