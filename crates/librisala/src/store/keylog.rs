//! Key logs: witnessed checkpoints, hand-offs, the witness policy, cached
//! tiles and forks (4.5, 4.10).
//!
//! Owned by task C1. The proofs themselves are `risala-keylog`'s; this is
//! what a device keeps between them: for each log, the newest witnessed
//! checkpoint it has seen, which every later one must be consistent with
//! (4.5, "Accepting a record", step 4), and the hand-off it accepted.

use rusqlite::{OptionalExtension, params};

use super::{Change, Store, StoreError, Tx};

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- The key logs this device has seen (4.4, 4.5), by origin; a log's URL
-- is always https:// and its origin. vkey is the log's signed-note
-- verifier key, from the log line of a key file. checkpoint is the newest witnessed checkpoint seen, as a
-- signed note with its cosignatures, and size its tree's size. checked is
-- when a fetched checkpoint of it was last fresh (4.5, Freshness), in ms.
-- handoff_index and handoff_vkey are the hand-off to the host's next log
-- that the device accepted (4.5, Hand-offs). forked is set when two
-- witnessed checkpoints of it did not agree, which marks every identity
-- whose records are in it.
CREATE TABLE logs (
    origin        TEXT PRIMARY KEY,
    vkey          TEXT NOT NULL,
    checkpoint    TEXT,
    size          INTEGER NOT NULL DEFAULT 0,
    checked       INTEGER,
    handoff_index INTEGER,
    handoff_vkey  TEXT,
    forked        INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

-- The witness policy (4.5): the witnesses this device trusts, as
-- signed-note verifier keys. builtin marks the list shipped with the
-- app. k is the setting 'keylog.witness_k'.
CREATE TABLE witnesses (
    position INTEGER PRIMARY KEY,
    vkey     TEXT NOT NULL UNIQUE,
    builtin  INTEGER NOT NULL DEFAULT 0
);

-- Full hash tiles fetched from logs (tlog-tiles), by path. A full tile
-- never changes in an honest log, and every proof computed from one is
-- checked against a witnessed checkpoint, so they are kept to save
-- fetches. Partial tiles and entry bundles are not kept.
CREATE TABLE tiles (
    origin TEXT NOT NULL REFERENCES logs(origin) ON DELETE CASCADE,
    path   TEXT NOT NULL,
    data   BLOB NOT NULL,
    PRIMARY KEY (origin, path)
) WITHOUT ROWID;

-- Forks found (4.5), with what shows them, until the user resolves them.
-- uid is NULL for a log's fork, which marks every identity in the log.
-- kind: two records with one previous ('records'), two first master
-- records ('masters'), inconsistent witnessed checkpoints ('checkpoints'),
-- or a key file that does not hold the device's head ('rollback').
-- evidence holds what shows it: the records, or the two checkpoints.
CREATE TABLE forks (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    uid      TEXT,
    origin   TEXT,
    kind     TEXT NOT NULL CHECK (kind IN ('records', 'masters', 'checkpoints', 'rollback')),
    evidence BLOB NOT NULL,
    found    INTEGER NOT NULL,
    resolved INTEGER
);
CREATE INDEX forks_uid ON forks (uid) WHERE resolved IS NULL;
";

/// The setting that holds the witness policy's k.
pub const WITNESS_K_SETTING: &str = "keylog.witness_k";

/// A change to key logs or forks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyLogChange {
    /// A fork was found or resolved.
    Forks,
    /// The witness policy changed.
    Witnesses,
    /// What the device knows of a log changed. Holds its origin.
    Log(String),
}

/// What a device keeps of one key log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRow {
    /// Its origin, `<host>/risala-log/<n>`.
    pub origin: String,
    /// Its signed-note verifier key.
    pub vkey: String,
    /// The newest witnessed checkpoint seen, as a signed note.
    pub checkpoint: Option<String>,
    /// That checkpoint's size.
    pub size: u64,
    /// When a fetched checkpoint of it was last fresh, in ms.
    pub checked: Option<u64>,
    /// The hand-off accepted: the entry's index and the next log's
    /// verifier key.
    pub handoff: Option<(u64, String)>,
    /// Whether it forked.
    pub forked: bool,
}

/// What kind of fork (4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForkKind {
    /// Two records of one uid with the same `previous` and different
    /// contents.
    Records,
    /// Two first `master` records of one uid.
    Masters,
    /// Two witnessed checkpoints of one log that are not consistent.
    Checkpoints,
    /// A valid key file that does not hold the device's head.
    Rollback,
}

impl ForkKind {
    fn as_str(self) -> &'static str {
        match self {
            ForkKind::Records => "records",
            ForkKind::Masters => "masters",
            ForkKind::Checkpoints => "checkpoints",
            ForkKind::Rollback => "rollback",
        }
    }

    fn parse(s: &str) -> Result<ForkKind, StoreError> {
        Ok(match s {
            "records" => ForkKind::Records,
            "masters" => ForkKind::Masters,
            "checkpoints" => ForkKind::Checkpoints,
            "rollback" => ForkKind::Rollback,
            _ => return Err(StoreError::Corrupt(format!("bad fork kind {s:?}"))),
        })
    }
}

/// A fork found and not yet resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkRow {
    /// Its id.
    pub id: i64,
    /// The identity, or `None` for a log's fork.
    pub uid: Option<String>,
    /// The log, for a log's fork.
    pub origin: Option<String>,
    /// What kind.
    pub kind: ForkKind,
    /// What shows it.
    pub evidence: Vec<u8>,
    /// When it was found, in ms.
    pub found: u64,
}

fn log_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LogRow> {
    let handoff = match (
        row.get::<_, Option<i64>>(5)?,
        row.get::<_, Option<String>>(6)?,
    ) {
        (Some(i), Some(v)) => Some((i as u64, v)),
        _ => None,
    };
    Ok(LogRow {
        origin: row.get(0)?,
        vkey: row.get(1)?,
        checkpoint: row.get(2)?,
        size: row.get::<_, i64>(3)? as u64,
        checked: row.get::<_, Option<i64>>(4)?.map(|t| t as u64),
        handoff,
        forked: row.get(7)?,
    })
}

const LOG_COLUMNS: &str =
    "origin, vkey, checkpoint, size, checked, handoff_index, handoff_vkey, forked";

pub(crate) fn read_log(
    conn: &rusqlite::Connection,
    origin: &str,
) -> Result<Option<LogRow>, StoreError> {
    Ok(conn
        .query_row(
            &format!("SELECT {LOG_COLUMNS} FROM logs WHERE origin = ?1"),
            [origin],
            log_row,
        )
        .optional()?)
}

impl Tx<'_> {
    /// Adds a log if it is new, by its `log` line. A log already known
    /// keeps its key: a key file that names another key for the same
    /// origin is checked against the one known by the caller.
    pub(crate) fn add_log(&mut self, origin: &str, vkey: &str) -> Result<(), StoreError> {
        let added = self.conn().execute(
            "INSERT INTO logs (origin, vkey) VALUES (?1, ?2)
             ON CONFLICT (origin) DO NOTHING",
            params![origin, vkey],
        )?;
        if added == 1 {
            self.changed(Change::KeyLog(KeyLogChange::Log(origin.to_owned())));
        }
        Ok(())
    }

    /// Keeps a log's newest witnessed checkpoint.
    pub(crate) fn set_log_checkpoint(
        &mut self,
        origin: &str,
        checkpoint: &str,
        size: u64,
        checked: Option<u64>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE logs SET checkpoint = ?2, size = ?3, checked = coalesce(?4, checked)
             WHERE origin = ?1",
            params![origin, checkpoint, size as i64, checked.map(|t| t as i64)],
        )?;
        self.changed(Change::KeyLog(KeyLogChange::Log(origin.to_owned())));
        Ok(())
    }

    /// Keeps the hand-off a device accepted from a log (4.5).
    pub(crate) fn set_log_handoff(
        &mut self,
        origin: &str,
        index: u64,
        next_vkey: &str,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE logs SET handoff_index = ?2, handoff_vkey = ?3 WHERE origin = ?1",
            params![origin, index as i64, next_vkey],
        )?;
        self.changed(Change::KeyLog(KeyLogChange::Log(origin.to_owned())));
        Ok(())
    }

    /// Marks a log as forked (4.5).
    pub(crate) fn set_log_forked(&mut self, origin: &str) -> Result<(), StoreError> {
        self.conn()
            .execute("UPDATE logs SET forked = 1 WHERE origin = ?1", [origin])?;
        self.changed(Change::KeyLog(KeyLogChange::Log(origin.to_owned())));
        Ok(())
    }

    /// Marks every identity whose records the log holds as forked (4.5).
    pub(crate) fn fork_log_contacts(&mut self, origin: &str) -> Result<(), StoreError> {
        let uids: Vec<String> = {
            let mut stmt = self
                .conn()
                .prepare_cached("SELECT DISTINCT uid FROM records WHERE log_origin = ?1")?;
            stmt.query_map([origin], |row| row.get(0))?
                .collect::<Result<_, _>>()?
        };
        for uid in uids {
            self.conn()
                .execute("UPDATE contacts SET forked = 1 WHERE uid = ?1", [&uid])?;
            self.changed(Change::Identity(super::identity::IdentityChange::Contact(
                uid,
            )));
        }
        Ok(())
    }

    /// Records a fork, unless the same one is already recorded and not
    /// resolved. Returns whether it is new.
    pub(crate) fn add_fork(
        &mut self,
        uid: Option<&str>,
        origin: Option<&str>,
        kind: ForkKind,
        evidence: &[u8],
        found: u64,
    ) -> Result<bool, StoreError> {
        let known: Option<i64> = self
            .conn()
            .query_row(
                "SELECT id FROM forks WHERE uid IS ?1 AND origin IS ?2 AND kind = ?3
                 AND evidence = ?4 AND resolved IS NULL",
                params![uid, origin, kind.as_str(), evidence],
                |row| row.get(0),
            )
            .optional()?;
        if known.is_some() {
            return Ok(false);
        }
        self.conn().execute(
            "INSERT INTO forks (uid, origin, kind, evidence, found) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![uid, origin, kind.as_str(), evidence, found as i64],
        )?;
        self.changed(Change::KeyLog(KeyLogChange::Forks));
        Ok(true)
    }

    /// Marks every unresolved fork of `uid` as resolved at `now`.
    pub(crate) fn resolve_forks(&mut self, uid: &str, now: u64) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "UPDATE forks SET resolved = ?2 WHERE uid = ?1 AND resolved IS NULL",
            params![uid, now as i64],
        )?;
        if n > 0 {
            self.changed(Change::KeyLog(KeyLogChange::Forks));
        }
        Ok(())
    }

    /// Keeps a full hash tile of a log.
    pub(crate) fn put_tile(
        &mut self,
        origin: &str,
        path: &str,
        data: &[u8],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO tiles (origin, path, data) VALUES (?1, ?2, ?3)
             ON CONFLICT (origin, path) DO NOTHING",
            params![origin, path, data],
        )?;
        Ok(())
    }

    /// Replaces the witness policy.
    pub(crate) fn set_witnesses(&mut self, vkeys: &[String], k: usize) -> Result<(), StoreError> {
        self.conn().execute("DELETE FROM witnesses", [])?;
        for vkey in vkeys {
            self.conn().execute(
                "INSERT INTO witnesses (vkey) VALUES (?1) ON CONFLICT DO NOTHING",
                [vkey],
            )?;
        }
        self.conn().execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![WITNESS_K_SETTING, k.to_string()],
        )?;
        self.changed(Change::KeyLog(KeyLogChange::Witnesses));
        Ok(())
    }

    /// Forgets the witness policy, for the apps' default (4.10).
    pub(crate) fn clear_witnesses(&mut self) -> Result<(), StoreError> {
        self.conn().execute("DELETE FROM witnesses", [])?;
        self.conn()
            .execute("DELETE FROM settings WHERE key = ?1", [WITNESS_K_SETTING])?;
        self.changed(Change::KeyLog(KeyLogChange::Witnesses));
        Ok(())
    }
}

impl Store {
    /// What the device keeps of the log with this origin.
    pub fn log(&self, origin: &str) -> Result<Option<LogRow>, StoreError> {
        self.read(|conn| read_log(conn, origin))
    }

    /// Every log the device keeps.
    pub fn logs(&self) -> Result<Vec<LogRow>, StoreError> {
        self.read(|conn| {
            let mut stmt =
                conn.prepare_cached(&format!("SELECT {LOG_COLUMNS} FROM logs ORDER BY origin"))?;
            let rows = stmt.query_map([], log_row)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The full hash tiles kept of a log, by path.
    pub fn tiles(&self, origin: &str) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached("SELECT path, data FROM tiles WHERE origin = ?1")?;
            let rows = stmt.query_map([origin], |row| Ok((row.get(0)?, row.get(1)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The witness policy: the witnesses' verifier keys, and k. `None`
    /// for k if it was never set.
    pub fn witnesses(&self) -> Result<(Vec<String>, Option<usize>), StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached("SELECT vkey FROM witnesses ORDER BY position")?;
            let vkeys = stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<String>, _>>()?;
            let k: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key = ?1",
                    [WITNESS_K_SETTING],
                    |row| row.get(0),
                )
                .optional()?;
            let k = k
                .map(|k| super::parse::<usize>(&k, "witness k"))
                .transpose()?;
            Ok((vkeys, k))
        })
    }

    /// The forks not yet resolved, of `uid` and of the logs that hold its
    /// records, or of every identity for `None`.
    pub fn forks(&self, uid: Option<&str>) -> Result<Vec<ForkRow>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT id, uid, origin, kind, evidence, found FROM forks
                 WHERE resolved IS NULL AND (?1 IS NULL OR uid = ?1
                    OR (uid IS NULL AND origin IN
                        (SELECT log_origin FROM records WHERE records.uid = ?1)))
                 ORDER BY id",
            )?;
            let rows = stmt.query_map([uid], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (id, uid, origin, kind, evidence, found) = row?;
                out.push(ForkRow {
                    id,
                    uid,
                    origin,
                    kind: ForkKind::parse(&kind)?,
                    evidence,
                    found: found as u64,
                });
            }
            Ok(out)
        })
    }
}
