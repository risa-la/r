//! Identities this device holds, and what it knows of every identity it
//! deals with: key file records, devices, pins and verification (4.3-4.9,
//! 12.14).
//!
//! Owned by task C1 (see the [store docs](super)). The rules that decide
//! what goes in here are in [`crate::client::identity`]; this keeps them.
//!
//! Secrets are not here: the device key, attestation key, device-signing
//! key and backup key live in the platform key store ([`crate::keys`]),
//! under `key_id`. The recovery key and master key are never kept (4.8).
//! The only secrets here are those of a pairing in progress and the lines
//! waiting to go to the conversation with yourself, which the cache's
//! encryption protects.

use risala_proto::names::BlobRef;
use rusqlite::{Connection, OptionalExtension, params};

use super::{Change, Store, StoreError, Tx};

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- The identities this device holds (4.3, 4.8): one row each. device_id is
-- the SHA-384 hash of this device's device key (4.4). key_id names its
-- secrets in the platform key store (crate::keys::KeyNames).
-- backup_generation is the generation of the backup key it holds
-- (12.13). home is the server of the conversation with yourself (12.13).
-- told_full is set once the user was told that the chain passed 3,072
-- records (4.4).
CREATE TABLE identities (
    uid               TEXT PRIMARY KEY,
    device_id         BLOB NOT NULL,
    key_id            TEXT NOT NULL UNIQUE,
    home              TEXT NOT NULL,
    backup_generation INTEGER NOT NULL DEFAULT 0,
    created           INTEGER NOT NULL,
    told_full         INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

-- The records of each identity's chain, as far as this device holds it
-- (4.4), keyed by their SHA-384 hash, with their place in the chain.
-- log_vkey is the log the record is listed under (or,
-- for the device's own records not yet listed, the log the chain puts it
-- in); log_index is its index there, NULL until it is logged. accepted is
-- set once it passed the checks of 4.5; the accepted records are always a
-- prefix of the chain. mine marks a record this device signed, kept
-- exactly as encoded until the log holds it (4.7). witnessed is when it
-- was first seen in a witnessed checkpoint, in ms, for the 24-hour rule
-- of 4.5.
CREATE TABLE records (
    uid        TEXT NOT NULL,
    hash       BLOB NOT NULL,
    position   INTEGER NOT NULL,
    type       TEXT NOT NULL
        CHECK (type IN ('master', 'signing', 'device', 'log', 'retire')),
    record     BLOB NOT NULL,
    time       INTEGER NOT NULL,
    log_origin TEXT NOT NULL,
    log_vkey   TEXT NOT NULL,
    log_index  INTEGER,
    accepted   INTEGER NOT NULL DEFAULT 0,
    mine       INTEGER NOT NULL DEFAULT 0,
    witnessed  INTEGER,
    PRIMARY KEY (uid, hash),
    UNIQUE (uid, position)
) WITHOUT ROWID;

-- Records of the device's own identities that a device announced with
-- RECORD, or that a RECORDS answer listed (4.5). A record nobody announced
-- within 24 hours of being witnessed is an alert. alerted is set once
-- the device has alerted for it.
CREATE TABLE announced (
    uid     TEXT NOT NULL,
    hash    BLOB NOT NULL,
    alerted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (uid, hash)
) WITHOUT ROWID;

-- Each identity's devices, from its records (4.4). state is 'current'
-- once the record that added it is accepted, 'pending' before, and
-- 'removed' once an accepted record removed it. A removed device stays
-- removed, whatever a later key file says (4.4).
CREATE TABLE devices (
    uid             TEXT NOT NULL,
    device_id       BLOB NOT NULL,
    device_key      BLOB NOT NULL,
    attestation_key BLOB NOT NULL,
    label           TEXT NOT NULL,
    added           INTEGER NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('current', 'pending', 'removed')),
    PRIMARY KEY (uid, device_id)
) WITHOUT ROWID;

-- What this device knows of each identity it deals with, its own
-- included (4.4, 4.5, 12.14).
-- - master_key and log_origin are the pins of 4.5, head and head_index
--   the head (the newest accepted record, and its index in its log).
-- - pin_master and pin_origin are a pin learnt from a PIN line before the
--   device checked the identity itself (12.9): the hash of the master key
--   and the log's origin.
-- - verified is set when the user checked the safety number (12.14).
-- - new_master_key is a master key that differs from the pin, until the
--   user acknowledges it (4.5, 12.14). forked stops sending (4.5).
-- - keys is the last fetch's state (4.4): 'unknown' before any, 'keys',
--   or 'missing', with why in missing. An outage changes neither.
-- - fetched is the last fetch, refreshed the last time the identity's
--   view passed the freshness checks of 4.5 (7 days without makes it
--   stale), and next_check when it is next due (12.14), all in ms.
-- - witness_problem is set while no checkpoint of its log has k
--   cosignatures from the device's list (4.5).
-- - pending is how many records of its key file are not accepted yet.
CREATE TABLE contacts (
    uid             TEXT PRIMARY KEY,
    master_key      BLOB,
    log_origin      TEXT,
    head            BLOB,
    head_index      INTEGER,
    pin_master      BLOB,
    pin_origin      TEXT,
    verified        INTEGER NOT NULL DEFAULT 0,
    new_master_key  BLOB,
    forked          INTEGER NOT NULL DEFAULT 0,
    keys            TEXT NOT NULL DEFAULT 'unknown'
        CHECK (keys IN ('unknown', 'keys', 'missing')),
    missing         TEXT,
    fetched         INTEGER,
    refreshed       INTEGER,
    next_check      INTEGER,
    witness_problem INTEGER NOT NULL DEFAULT 0,
    pending         INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

-- Lines for the conversation with yourself (12.9) that the identity area
-- has to send: RECORD, ALERT, RECORDS, SIGNINGKEY, BACKUPKEY and PIN, in
-- order. The conversations area takes them (task C2).
CREATE TABLE self_lines (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    uid     TEXT NOT NULL,
    line    TEXT NOT NULL,
    created INTEGER NOT NULL
);

-- Pairings in progress (4.8). role 'new' is this device being paired: its
-- keys are in the key store under key_id, pairing_seed is its one-time
-- X-Wing pairing key. role 'old' is this device pairing another for uid:
-- record is the device record it made, sealed the SealedBundle it sent,
-- kept to resend the same bytes. secret is the QR code's secret,
-- new_device the encoded NewDevice.
CREATE TABLE pairings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    role         TEXT NOT NULL CHECK (role IN ('new', 'old')),
    uid          TEXT,
    host         TEXT NOT NULL,
    secret       BLOB NOT NULL,
    key_id       TEXT,
    label        TEXT,
    pairing_seed BLOB,
    new_device   BLOB NOT NULL,
    record       BLOB,
    sealed       BLOB,
    created      INTEGER NOT NULL
);
";

/// A change to identities, devices or contacts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdentityChange {
    /// An identity's devices, pins or verification changed. Holds its uid.
    Contact(String),
    /// The device's own identities changed.
    Own,
    /// Lines wait for the conversation with yourself of this identity.
    SelfLines(String),
}

/// An identity this device holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnRow {
    /// The identity.
    pub uid: String,
    /// This device's id.
    pub device_id: [u8; 48],
    /// Where its secrets are in the key store.
    pub key_id: String,
    /// The home server, of the conversation with yourself.
    pub home: String,
    /// The generation of the backup key the device holds.
    pub backup_generation: u32,
    /// When it was made or joined, in ms.
    pub created: u64,
    /// Whether the user was told that the chain is filling up.
    pub told_full: bool,
}

/// A record of an identity's chain, as kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRow {
    /// Its hash.
    pub hash: BlobRef,
    /// Its place in the chain, from 0.
    pub position: u64,
    /// The encoded Record.
    pub record: Vec<u8>,
    /// Its log's origin and verifier key; the log's URL is `https://` and
    /// its origin (4.4).
    pub log: (String, String),
    /// Its index in the log, once logged.
    pub log_index: Option<u64>,
    /// Whether it passed the checks of 4.5.
    pub accepted: bool,
    /// Whether this device signed it.
    pub mine: bool,
    /// When it was first seen witnessed, in ms.
    pub witnessed: Option<u64>,
}

/// A device's state (4.4, 4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceState {
    /// Added by an accepted record: its leaves are accepted (12.7).
    Current,
    /// Added by a record not yet accepted: nothing acts on it yet.
    Pending,
    /// Removed by an accepted record. It stays removed.
    Removed,
}

impl DeviceState {
    fn as_str(self) -> &'static str {
        match self {
            DeviceState::Current => "current",
            DeviceState::Pending => "pending",
            DeviceState::Removed => "removed",
        }
    }

    fn parse(s: &str) -> Result<DeviceState, StoreError> {
        Ok(match s {
            "current" => DeviceState::Current,
            "pending" => DeviceState::Pending,
            "removed" => DeviceState::Removed,
            _ => return Err(StoreError::Corrupt(format!("bad device state {s:?}"))),
        })
    }
}

/// A device of an identity, as kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    /// Its id.
    pub device_id: [u8; 48],
    /// Its ML-DSA-44 device key.
    pub device_key: Vec<u8>,
    /// Its X-Wing attestation key.
    pub attestation_key: Vec<u8>,
    /// Its label.
    pub label: String,
    /// The time of the record that added it, in ms.
    pub added: u64,
    /// Its state.
    pub state: DeviceState,
}

/// The state of an identity's keys after the last fetch (4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysState {
    /// Never fetched with an answer.
    Unknown,
    /// A valid key file.
    Keys,
    /// Keys missing, and why.
    Missing(String),
}

/// What the device knows of an identity, as kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRow {
    /// The identity.
    pub uid: String,
    /// The pinned master key.
    pub master_key: Option<Vec<u8>>,
    /// The pinned log's origin.
    pub log_origin: Option<String>,
    /// The head: the newest accepted record's hash.
    pub head: Option<BlobRef>,
    /// The head's index in its log.
    pub head_index: Option<u64>,
    /// A pin from a PIN line: the hash of a master key, and a log origin.
    pub pin_hint: Option<(BlobRef, String)>,
    /// Whether the user checked the safety number.
    pub verified: bool,
    /// A new master key, not yet acknowledged.
    pub new_master_key: Option<Vec<u8>>,
    /// Whether a fork stops sending.
    pub forked: bool,
    /// The last fetch's state.
    pub keys: KeysState,
    /// The last fetch, in ms.
    pub fetched: Option<u64>,
    /// The last time the view passed the freshness checks, in ms.
    pub refreshed: Option<u64>,
    /// When the next fetch is due, in ms.
    pub next_check: Option<u64>,
    /// Whether no checkpoint of its log has k cosignatures from the list.
    pub witness_problem: bool,
    /// How many records of its key file are pending.
    pub pending: u64,
}

impl ContactRow {
    /// A contact that the device knows nothing of yet.
    pub fn new(uid: &str) -> ContactRow {
        ContactRow {
            uid: uid.to_owned(),
            master_key: None,
            log_origin: None,
            head: None,
            head_index: None,
            pin_hint: None,
            verified: false,
            new_master_key: None,
            forked: false,
            keys: KeysState::Unknown,
            fetched: None,
            refreshed: None,
            next_check: None,
            witness_problem: false,
            pending: 0,
        }
    }
}

/// A pairing in progress (4.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRow {
    /// Its id.
    pub id: i64,
    /// Whether this device is the new one.
    pub new: bool,
    /// The identity, for the device pairing another.
    pub uid: Option<String>,
    /// The relay server.
    pub host: String,
    /// The pairing secret.
    pub secret: Vec<u8>,
    /// The new device's keys in the key store.
    pub key_id: Option<String>,
    /// The new device's label.
    pub label: Option<String>,
    /// The new device's pairing key seed.
    pub pairing_seed: Option<Vec<u8>>,
    /// The encoded NewDevice.
    pub new_device: Vec<u8>,
    /// The device record made for the new device.
    pub record: Option<Vec<u8>>,
    /// The SealedBundle sent.
    pub sealed: Option<Vec<u8>>,
    /// When it started, in ms.
    pub created: u64,
}

fn hash_of(bytes: Vec<u8>) -> Result<BlobRef, StoreError> {
    let hash: [u8; 48] = bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("a hash is 48 bytes".into()))?;
    Ok(BlobRef::from_hash(hash))
}

fn id_of(bytes: Vec<u8>) -> Result<[u8; 48], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("a device id is 48 bytes".into()))
}

fn opt_u64(v: Option<i64>) -> Option<u64> {
    v.map(|v| v as u64)
}

fn opt_i64(v: Option<u64>) -> Option<i64> {
    v.map(|v| v as i64)
}

const OWN_COLUMNS: &str = "uid, device_id, key_id, home, backup_generation, created, told_full";

fn own_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(OwnRow, Vec<u8>)> {
    Ok((
        OwnRow {
            uid: row.get(0)?,
            device_id: [0; 48],
            key_id: row.get(2)?,
            home: row.get(3)?,
            backup_generation: row.get(4)?,
            created: row.get::<_, i64>(5)? as u64,
            told_full: row.get(6)?,
        },
        row.get(1)?,
    ))
}

pub(crate) fn read_own(conn: &Connection, uid: &str) -> Result<Option<OwnRow>, StoreError> {
    let row = conn
        .query_row(
            &format!("SELECT {OWN_COLUMNS} FROM identities WHERE uid = ?1"),
            [uid],
            own_row,
        )
        .optional()?;
    row.map(|(mut own, id)| {
        own.device_id = id_of(id)?;
        Ok(own)
    })
    .transpose()
}

const CONTACT_COLUMNS: &str = "uid, master_key, log_origin, head, head_index, pin_master, \
    pin_origin, verified, new_master_key, forked, keys, missing, fetched, refreshed, \
    next_check, witness_problem, pending";

pub(crate) fn read_contact(conn: &Connection, uid: &str) -> Result<Option<ContactRow>, StoreError> {
    let row = conn
        .query_row(
            &format!("SELECT {CONTACT_COLUMNS} FROM contacts WHERE uid = ?1"),
            [uid],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, bool>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, bool>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    (
                        row.get::<_, Option<i64>>(12)?,
                        row.get::<_, Option<i64>>(13)?,
                        row.get::<_, Option<i64>>(14)?,
                        row.get::<_, bool>(15)?,
                        row.get::<_, i64>(16)?,
                    ),
                ))
            },
        )
        .optional()?;
    let Some((
        uid,
        master_key,
        log_origin,
        head,
        head_index,
        pin_master,
        pin_origin,
        verified,
        new_master_key,
        forked,
        keys,
        missing,
        (fetched, refreshed, next_check, witness_problem, pending),
    )) = row
    else {
        return Ok(None);
    };
    let keys = match keys.as_str() {
        "unknown" => KeysState::Unknown,
        "keys" => KeysState::Keys,
        "missing" => KeysState::Missing(missing.unwrap_or_default()),
        other => return Err(StoreError::Corrupt(format!("bad keys state {other:?}"))),
    };
    let pin_hint = match (pin_master, pin_origin) {
        (Some(m), Some(o)) => Some((hash_of(m)?, o)),
        _ => None,
    };
    Ok(Some(ContactRow {
        uid,
        master_key,
        log_origin,
        head: head.map(hash_of).transpose()?,
        head_index: opt_u64(head_index),
        pin_hint,
        verified,
        new_master_key,
        forked,
        keys,
        fetched: opt_u64(fetched),
        refreshed: opt_u64(refreshed),
        next_check: opt_u64(next_check),
        witness_problem,
        pending: pending as u64,
    }))
}

pub(crate) fn read_records(conn: &Connection, uid: &str) -> Result<Vec<RecordRow>, StoreError> {
    let mut stmt = conn.prepare_cached(
        "SELECT hash, position, record, log_origin, log_vkey, log_index, accepted,
                mine, witnessed
         FROM records WHERE uid = ?1 ORDER BY position",
    )?;
    let rows = stmt.query_map([uid], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            (row.get(3)?, row.get(4)?),
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, bool>(6)?,
            row.get::<_, bool>(7)?,
            row.get::<_, Option<i64>>(8)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (hash, position, record, log, log_index, accepted, mine, witnessed) = row?;
        out.push(RecordRow {
            hash: hash_of(hash)?,
            position: position as u64,
            record,
            log,
            log_index: opt_u64(log_index),
            accepted,
            mine,
            witnessed: opt_u64(witnessed),
        });
    }
    Ok(out)
}

pub(crate) fn read_devices(conn: &Connection, uid: &str) -> Result<Vec<DeviceRow>, StoreError> {
    let mut stmt = conn.prepare_cached(
        "SELECT device_id, device_key, attestation_key, label, added, state
         FROM devices WHERE uid = ?1 ORDER BY added, device_id",
    )?;
    let rows = stmt.query_map([uid], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, device_key, attestation_key, label, added, state) = row?;
        out.push(DeviceRow {
            device_id: id_of(id)?,
            device_key,
            attestation_key,
            label,
            added: added as u64,
            state: DeviceState::parse(&state)?,
        });
    }
    Ok(out)
}

fn pairing_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PairingRow> {
    Ok(PairingRow {
        id: row.get(0)?,
        new: row.get::<_, String>(1)? == "new",
        uid: row.get(2)?,
        host: row.get(3)?,
        secret: row.get(4)?,
        key_id: row.get(5)?,
        label: row.get(6)?,
        pairing_seed: row.get(7)?,
        new_device: row.get(8)?,
        record: row.get(9)?,
        sealed: row.get(10)?,
        created: row.get::<_, i64>(11)? as u64,
    })
}

const PAIRING_COLUMNS: &str = "id, role, uid, host, secret, key_id, label, pairing_seed, \
    new_device, record, sealed, created";

impl Tx<'_> {
    /// Adds an identity this device holds.
    pub(crate) fn add_own(&mut self, own: &OwnRow) -> Result<(), StoreError> {
        self.conn().execute(
            &format!("INSERT INTO identities ({OWN_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"),
            params![
                own.uid,
                &own.device_id[..],
                own.key_id,
                own.home,
                own.backup_generation,
                own.created as i64,
                own.told_full
            ],
        )?;
        self.changed(Change::Identity(IdentityChange::Own));
        Ok(())
    }

    /// Sets the generation of the backup key the device holds.
    pub(crate) fn set_backup_generation(
        &mut self,
        uid: &str,
        generation: u32,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE identities SET backup_generation = ?2 WHERE uid = ?1",
            params![uid, generation],
        )?;
        self.changed(Change::Identity(IdentityChange::Own));
        Ok(())
    }

    /// Notes that the user was told the chain is filling up (4.4).
    pub(crate) fn set_told_full(&mut self, uid: &str) -> Result<(), StoreError> {
        self.conn()
            .execute("UPDATE identities SET told_full = 1 WHERE uid = ?1", [uid])?;
        Ok(())
    }

    /// What the device knows of `uid`, read in this transaction.
    pub(crate) fn contact(&self, uid: &str) -> Result<Option<ContactRow>, StoreError> {
        read_contact(self.conn(), uid)
    }

    /// The records kept of `uid`, read in this transaction.
    pub(crate) fn records(&self, uid: &str) -> Result<Vec<RecordRow>, StoreError> {
        read_records(self.conn(), uid)
    }

    /// The devices kept of `uid`, read in this transaction.
    pub(crate) fn devices(&self, uid: &str) -> Result<Vec<DeviceRow>, StoreError> {
        read_devices(self.conn(), uid)
    }

    /// Writes what the device knows of an identity.
    pub(crate) fn put_contact(&mut self, c: &ContactRow) -> Result<(), StoreError> {
        let (keys, missing) = match &c.keys {
            KeysState::Unknown => ("unknown", None),
            KeysState::Keys => ("keys", None),
            KeysState::Missing(why) => ("missing", Some(why.as_str())),
        };
        let (pin_master, pin_origin) = match &c.pin_hint {
            Some((m, o)) => (Some(m.hash().to_vec()), Some(o.as_str())),
            None => (None, None),
        };
        self.conn().execute(
            &format!(
                "INSERT OR REPLACE INTO contacts ({CONTACT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                         ?16, ?17)"
            ),
            params![
                c.uid,
                c.master_key,
                c.log_origin,
                c.head.map(|h| h.hash().to_vec()),
                opt_i64(c.head_index),
                pin_master,
                pin_origin,
                c.verified,
                c.new_master_key,
                c.forked,
                keys,
                missing,
                opt_i64(c.fetched),
                opt_i64(c.refreshed),
                opt_i64(c.next_check),
                c.witness_problem,
                c.pending as i64,
            ],
        )?;
        self.changed(Change::Identity(IdentityChange::Contact(c.uid.clone())));
        Ok(())
    }

    /// Replaces the records kept of `uid` from position `from` on with
    /// `records`, which continue the chain there.
    pub(crate) fn put_records(
        &mut self,
        uid: &str,
        from: u64,
        records: &[RecordRow],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM records WHERE uid = ?1 AND position >= ?2",
            params![uid, from as i64],
        )?;
        for r in records {
            let content = risala_proto::record::Record::decode(&r.record)
                .map_err(|e| StoreError::Corrupt(format!("a record to keep: {e}")))?;
            self.conn().execute(
                "INSERT INTO records (uid, hash, position, type, record, time, log_origin,
                    log_vkey, log_index, accepted, mine, witnessed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    uid,
                    &r.hash.hash()[..],
                    r.position as i64,
                    content.record_type().as_str(),
                    r.record,
                    content.content().time as i64,
                    r.log.0,
                    r.log.1,
                    opt_i64(r.log_index),
                    r.accepted,
                    r.mine,
                    opt_i64(r.witnessed),
                ],
            )?;
        }
        self.changed(Change::Identity(IdentityChange::Contact(uid.to_owned())));
        Ok(())
    }

    /// Writes the devices of `uid`. A device kept as removed stays
    /// removed (4.4).
    pub(crate) fn put_devices(
        &mut self,
        uid: &str,
        devices: &[DeviceRow],
    ) -> Result<(), StoreError> {
        for d in devices {
            self.conn().execute(
                "INSERT INTO devices (uid, device_id, device_key, attestation_key, label, added,
                    state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (uid, device_id) DO UPDATE SET
                    label = excluded.label, added = excluded.added,
                    state = CASE WHEN devices.state = 'removed' THEN 'removed'
                                 ELSE excluded.state END",
                params![
                    uid,
                    &d.device_id[..],
                    d.device_key,
                    d.attestation_key,
                    d.label,
                    d.added as i64,
                    d.state.as_str()
                ],
            )?;
        }
        self.changed(Change::Identity(IdentityChange::Contact(uid.to_owned())));
        Ok(())
    }

    /// Deletes the devices of `uid` that are not in `keep`, except those
    /// removed by record, which stay removed (4.4).
    pub(crate) fn retain_devices(
        &mut self,
        uid: &str,
        keep: &[[u8; 48]],
    ) -> Result<(), StoreError> {
        for d in read_devices(self.conn(), uid)? {
            if d.state != DeviceState::Removed && !keep.contains(&d.device_id) {
                self.conn().execute(
                    "DELETE FROM devices WHERE uid = ?1 AND device_id = ?2",
                    params![uid, &d.device_id[..]],
                )?;
            }
        }
        Ok(())
    }

    /// Notes that a device announced the record `hash` of `uid` (4.5).
    pub(crate) fn add_announced(&mut self, uid: &str, hash: &BlobRef) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO announced (uid, hash) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![uid, &hash.hash()[..]],
        )?;
        Ok(())
    }

    /// Notes that the device alerted for the record `hash` of `uid`.
    /// Returns whether it had not already.
    pub(crate) fn set_alerted(&mut self, uid: &str, hash: &BlobRef) -> Result<bool, StoreError> {
        self.conn().execute(
            "INSERT INTO announced (uid, hash, alerted) VALUES (?1, ?2, 0)
             ON CONFLICT DO NOTHING",
            params![uid, &hash.hash()[..]],
        )?;
        let n = self.conn().execute(
            "UPDATE announced SET alerted = 1 WHERE uid = ?1 AND hash = ?2 AND alerted = 0",
            params![uid, &hash.hash()[..]],
        )?;
        Ok(n == 1)
    }

    /// Whether a device announced the record `hash` of `uid`.
    pub(crate) fn is_announced(&self, uid: &str, hash: &BlobRef) -> Result<bool, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM announced WHERE uid = ?1 AND hash = ?2 AND alerted = 0",
                params![uid, &hash.hash()[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Queues a line for the conversation with yourself of `uid` (12.9).
    pub(crate) fn push_self_line(
        &mut self,
        uid: &str,
        line: &str,
        now: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO self_lines (uid, line, created) VALUES (?1, ?2, ?3)",
            params![uid, line, now as i64],
        )?;
        self.changed(Change::Identity(IdentityChange::SelfLines(uid.to_owned())));
        Ok(())
    }

    /// Takes the lines queued for the conversation with yourself of
    /// `uid`, oldest first.
    pub(crate) fn take_self_lines(&mut self, uid: &str) -> Result<Vec<String>, StoreError> {
        let lines = {
            let mut stmt = self
                .conn()
                .prepare_cached("SELECT line FROM self_lines WHERE uid = ?1 ORDER BY id")?;
            stmt.query_map([uid], |row| row.get(0))?
                .collect::<Result<Vec<String>, _>>()?
        };
        self.conn()
            .execute("DELETE FROM self_lines WHERE uid = ?1", [uid])?;
        Ok(lines)
    }

    /// Adds a pairing in progress, and returns its id.
    pub(crate) fn add_pairing(&mut self, p: &PairingRow) -> Result<i64, StoreError> {
        self.conn().execute(
            "INSERT INTO pairings (role, uid, host, secret, key_id, label, pairing_seed,
                new_device, record, sealed, created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                if p.new { "new" } else { "old" },
                p.uid,
                p.host,
                p.secret,
                p.key_id,
                p.label,
                p.pairing_seed,
                p.new_device,
                p.record,
                p.sealed,
                p.created as i64
            ],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Keeps the device record and SealedBundle of a pairing.
    pub(crate) fn set_pairing_sent(
        &mut self,
        id: i64,
        record: &[u8],
        sealed: &[u8],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE pairings SET record = ?2, sealed = ?3 WHERE id = ?1",
            params![id, record, sealed],
        )?;
        Ok(())
    }

    /// Deletes a pairing, which wipes its secrets from the cache.
    pub(crate) fn delete_pairing(&mut self, id: i64) -> Result<(), StoreError> {
        self.conn()
            .execute("DELETE FROM pairings WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Deletes the pairings of `role` started before `before`.
    pub(crate) fn delete_old_pairings(
        &mut self,
        before: u64,
    ) -> Result<Vec<PairingRow>, StoreError> {
        let rows = {
            let mut stmt = self.conn().prepare_cached(&format!(
                "SELECT {PAIRING_COLUMNS} FROM pairings WHERE created < ?1"
            ))?;
            stmt.query_map([before as i64], pairing_row)?
                .collect::<Result<Vec<_>, _>>()?
        };
        self.conn()
            .execute("DELETE FROM pairings WHERE created < ?1", [before as i64])?;
        Ok(rows)
    }
}

impl Store {
    /// The identities this device holds, oldest first.
    pub fn own_identities(&self) -> Result<Vec<OwnRow>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {OWN_COLUMNS} FROM identities ORDER BY created, uid"
            ))?;
            let rows = stmt.query_map([], own_row)?;
            let mut out = Vec::new();
            for row in rows {
                let (mut own, id) = row?;
                own.device_id = id_of(id)?;
                out.push(own);
            }
            Ok(out)
        })
    }

    /// The identity `uid`, if this device holds it.
    pub fn own_identity(&self, uid: &str) -> Result<Option<OwnRow>, StoreError> {
        self.read(|conn| read_own(conn, uid))
    }

    /// What this device knows of `uid`.
    pub fn contact(&self, uid: &str) -> Result<Option<ContactRow>, StoreError> {
        self.read(|conn| read_contact(conn, uid))
    }

    /// Every identity this device knows of.
    pub fn contacts(&self) -> Result<Vec<ContactRow>, StoreError> {
        let uids: Vec<String> = self.read(|conn| {
            let mut stmt = conn.prepare_cached("SELECT uid FROM contacts ORDER BY uid")?;
            Ok(stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<_, _>>()?)
        })?;
        let mut out = Vec::new();
        for uid in uids {
            if let Some(c) = self.contact(&uid)? {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// The records kept of `uid`, in chain order.
    pub fn records(&self, uid: &str) -> Result<Vec<RecordRow>, StoreError> {
        self.read(|conn| read_records(conn, uid))
    }

    /// The devices kept of `uid`.
    pub fn devices(&self, uid: &str) -> Result<Vec<DeviceRow>, StoreError> {
        self.read(|conn| read_devices(conn, uid))
    }

    /// The pairing in progress with this id.
    pub fn pairing(&self, id: i64) -> Result<Option<PairingRow>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row(
                    &format!("SELECT {PAIRING_COLUMNS} FROM pairings WHERE id = ?1"),
                    [id],
                    pairing_row,
                )
                .optional()?)
        })
    }

    /// The newest pairing in progress of this role: as the new device, or
    /// as the device pairing another for `uid`.
    pub fn latest_pairing(
        &self,
        new: bool,
        uid: Option<&str>,
    ) -> Result<Option<PairingRow>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row(
                    &format!(
                        "SELECT {PAIRING_COLUMNS} FROM pairings
                         WHERE role = ?1 AND uid IS ?2 ORDER BY id DESC LIMIT 1"
                    ),
                    params![if new { "new" } else { "old" }, uid],
                    pairing_row,
                )
                .optional()?)
        })
    }

    /// The lines queued for the conversation with yourself of `uid`,
    /// without taking them.
    pub fn self_lines(&self, uid: &str) -> Result<Vec<String>, StoreError> {
        self.read(|conn| {
            let mut stmt =
                conn.prepare_cached("SELECT line FROM self_lines WHERE uid = ?1 ORDER BY id")?;
            Ok(stmt
                .query_map([uid], |row| row.get(0))?
                .collect::<Result<_, _>>()?)
        })
    }

    /// The hashes of the records of `uid` that this device knows were
    /// announced (4.5, for a RECORDS answer).
    pub fn announced(&self, uid: &str) -> Result<Vec<BlobRef>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT hash FROM announced WHERE uid = ?1 AND alerted = 0 ORDER BY hash",
            )?;
            let rows = stmt
                .query_map([uid], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().map(hash_of).collect()
        })
    }
}
