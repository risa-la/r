//! Identities this device holds, and what it knows of every identity it
//! deals with: key file records, devices, pins and verification (4.3-4.9,
//! 12.14).
//!
//! Owned by task C1. The tables are a sketch from the spec; C1 may add
//! and change columns and tables (see the [store docs](super)).
//!
//! Secrets are not here: the device key, attestation key, device-signing
//! key and backup key live in the platform key store ([`crate::keys`]),
//! under `key_id`. The recovery key and master key are never kept (4.8).

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- The identities this device holds (4.3, 4.8): one row each. device_id is
-- the SHA-384 hash of this device's device key (4.4). key_id names its
-- secrets in the platform key store. backup_generation is the generation
-- of the backup key it holds (12.13).
CREATE TABLE identities (
    uid               TEXT PRIMARY KEY,
    device_id         BLOB NOT NULL,
    key_id            TEXT NOT NULL UNIQUE,
    backup_generation INTEGER NOT NULL DEFAULT 0,
    created           INTEGER NOT NULL
) WITHOUT ROWID;

-- Every key file record seen, of any identity (4.4), keyed by its SHA-384
-- hash. previous is empty in a chain's first record. log_index is the
-- index the key file gives, NULL while it is '-'. state is 'pending' until
-- the record passes the checks of 4.5, then 'accepted'. For the device's
-- own identities, announced says another device announced it with RECORD
-- (4.5); one that nobody announced is an alert.
CREATE TABLE records (
    uid       TEXT NOT NULL,
    hash      BLOB NOT NULL,
    previous  BLOB NOT NULL,
    type      TEXT NOT NULL CHECK (type IN ('master', 'signing', 'device')),
    record    BLOB NOT NULL,
    time      INTEGER NOT NULL,
    log_index INTEGER,
    state     TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'accepted')),
    announced INTEGER NOT NULL DEFAULT 0,
    seen      INTEGER NOT NULL,
    PRIMARY KEY (uid, hash)
) WITHOUT ROWID;
CREATE INDEX records_previous ON records (uid, previous);

-- Each identity's devices, from its accepted records (4.4). removed_by is
-- the signing record that removed the device, if one has.
CREATE TABLE devices (
    uid             TEXT NOT NULL,
    device_id       BLOB NOT NULL,
    device_key      BLOB NOT NULL,
    attestation_key BLOB NOT NULL,
    label           TEXT NOT NULL,
    added_by        BLOB NOT NULL,
    removed_by      BLOB,
    PRIMARY KEY (uid, device_id)
) WITHOUT ROWID;

-- What this device knows of each identity it deals with, its own
-- included. master_key and log_origin are the pins of 4.5. verified is
-- set when the user checked the safety number (12.14). new_master_key and
-- forked stop sending until the user acts (4.5, 12.14). fetched is when
-- the key file was last fetched, key_file the copy from then (4.4).
CREATE TABLE contacts (
    uid            TEXT PRIMARY KEY,
    master_key     BLOB,
    log_origin     TEXT,
    verified       INTEGER NOT NULL DEFAULT 0,
    new_master_key INTEGER NOT NULL DEFAULT 0,
    forked         INTEGER NOT NULL DEFAULT 0,
    fetched        INTEGER,
    key_file       BLOB
) WITHOUT ROWID;
";

/// A change to identities, devices or contacts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdentityChange {
    /// An identity's devices, pins or verification changed. Holds its uid.
    Contact(String),
    /// The device's own identities changed.
    Own,
}
