//! Key logs: witnessed checkpoints, the witness policy, cached tiles and
//! forks (4.5).
//!
//! Owned by task C1. The proofs themselves are `risala-keylog`'s; this is
//! what a device keeps between them. The tables are a sketch from the
//! spec; C1 may add and change columns and tables.

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- The key logs this device has seen (4.4, 4.5), by origin. vkey and url
-- come from the log line of a key file. checkpoint is the newest
-- witnessed checkpoint seen, as a signed note with its cosignatures, and
-- size and root its tree. watched is the index up to which the entries
-- have been read for the device's own identities (4.5, watching).
-- forked is set when two witnessed checkpoints did not agree.
CREATE TABLE logs (
    origin     TEXT PRIMARY KEY,
    vkey       TEXT NOT NULL,
    url        TEXT NOT NULL,
    checkpoint TEXT,
    size       INTEGER NOT NULL DEFAULT 0,
    root       BLOB,
    checked    INTEGER,
    watched    INTEGER NOT NULL DEFAULT 0,
    forked     INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

-- The witness policy (4.5): the witnesses this device trusts, as
-- signed-note verifier keys. builtin marks the list shipped with the
-- app. k is the setting 'keylog.witness_k'.
CREATE TABLE witnesses (
    vkey    TEXT PRIMARY KEY,
    builtin INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

-- Tiles and entry bundles fetched from logs (tlog-tiles), by path.
CREATE TABLE tiles (
    origin TEXT NOT NULL REFERENCES logs(origin) ON DELETE CASCADE,
    path   TEXT NOT NULL,
    data   BLOB NOT NULL,
    PRIMARY KEY (origin, path)
) WITHOUT ROWID;

-- Forks found (4.5), with what shows them, until the user resolves them.
-- uid is NULL for a log's fork, which marks every identity in the log.
CREATE TABLE forks (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    uid      TEXT,
    origin   TEXT,
    kind     TEXT NOT NULL CHECK (kind IN ('records', 'masters', 'checkpoints')),
    evidence BLOB NOT NULL,
    found    INTEGER NOT NULL,
    resolved INTEGER
);
";

/// A change to key logs or forks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyLogChange {
    /// A fork was found or resolved.
    Forks,
    /// The witness policy changed.
    Witnesses,
}
