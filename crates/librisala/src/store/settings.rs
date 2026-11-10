//! Servers, their trust records (2.2), accounts and device-wide settings.
//!
//! Owned by task C0. [`Store`] is the [`TrustStore`] that connections
//! use.

use risala_proto::command::GuestToken;
use risala_proto::fingerprint::Fingerprint;
use risala_proto::names::{Name, Uid};
use rusqlite::{Connection, OptionalExtension, params};

use super::{Change, Store, StoreError, Tx, parse, row_id};
use crate::addr::{PinChange, Replaced, ServerAddr, TrustRecord, TrustStore, TrustStoreError};

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- Servers by address (ServerAddr's display form). time is the newest
-- server time the device has seen there, in ms: the newest t of any post,
-- or of a PING or the OK to one (3.2, 11). It never goes back (7.6, 12.9).
CREATE TABLE servers (
    id   INTEGER PRIMARY KEY,
    addr TEXT NOT NULL UNIQUE,
    time INTEGER
);

-- How each server was verified (2.2). No row: nothing yet. 'ca' has no
-- fingerprint; 'pinned' and 'strict' (PLAN.md 58) have one.
CREATE TABLE trust (
    server      INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('ca', 'pinned', 'strict')),
    fingerprint TEXT,
    CHECK ((kind = 'ca') = (fingerprint IS NULL))
);

-- A pin that a CA-valid certificate with another key replaced (2.2), to
-- tell the user once. Deleted when the user has seen it.
CREATE TABLE pin_notices (
    server          INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    old_fingerprint TEXT NOT NULL,
    new_fingerprint TEXT NOT NULL
);

-- Accounts: an identity this device holds, on a server it uses (4.1), or a
-- guest on a server (4.2). An identity has an account on each server it
-- has conversations on (5.1). uid is the identity, or the guest uid asked
-- for (~name); guest_name and guest_token are the guest session it last
-- had (4.2), which may have a numbered name. presence is PRESENCE ON or
-- OFF (8.3), off by default.
CREATE TABLE accounts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    server      INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('identity', 'guest')),
    uid         TEXT NOT NULL,
    guest_name  TEXT,
    guest_token TEXT,
    presence    INTEGER NOT NULL DEFAULT 0,
    UNIQUE (server, uid),
    CHECK ((guest_name IS NULL) = (guest_token IS NULL)),
    CHECK (kind = 'guest' OR guest_name IS NULL)
);

-- Device-wide settings, by key. Areas name their keys after themselves,
-- such as 'keylog.witness_k'.
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
";

row_id!(
    /// An account in the cache.
    AccountId
);

/// What kind of account it is (4.1, 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountKind {
    /// An identity this device holds, with a signed-in connection and
    /// anonymous ones.
    Identity,
    /// A guest, with one guest connection.
    Guest,
}

impl AccountKind {
    fn as_str(self) -> &'static str {
        match self {
            AccountKind::Identity => "identity",
            AccountKind::Guest => "guest",
        }
    }
}

/// An account, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRow {
    /// Its id.
    pub id: AccountId,
    /// The server.
    pub server: ServerAddr,
    /// Identity or guest.
    pub kind: AccountKind,
    /// The identity, or the guest uid asked for.
    pub uid: Uid,
}

/// A change to servers, trust or accounts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SettingsChange {
    /// A server's trust record changed, or a notice came or went.
    Trust(ServerAddr),
    /// An account was added or removed.
    Accounts,
}

fn record(conn: &Connection, addr: &ServerAddr) -> Result<Option<TrustRecord>, StoreError> {
    let row: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT t.kind, t.fingerprint FROM trust t JOIN servers s ON s.id = t.server
             WHERE s.addr = ?1",
            [addr.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(match row {
        None => None,
        Some((kind, None)) if kind == "ca" => Some(TrustRecord::Ca),
        Some((kind, Some(fp))) if kind == "pinned" => {
            Some(TrustRecord::Pinned(parse(&fp, "fingerprint")?))
        }
        Some((kind, Some(fp))) if kind == "strict" => {
            Some(TrustRecord::Strict(parse(&fp, "fingerprint")?))
        }
        Some((kind, _)) => {
            return Err(StoreError::Corrupt(format!("bad trust record {kind:?}")));
        }
    })
}

impl Tx<'_> {
    /// Sets a server's trust record.
    fn set_trust(&mut self, addr: &ServerAddr, record: &TrustRecord) -> Result<(), StoreError> {
        let server = self.server_id(addr)?;
        let (kind, fp) = match record {
            TrustRecord::Ca => ("ca", None),
            TrustRecord::Pinned(fp) => ("pinned", Some(fp.to_string())),
            TrustRecord::Strict(fp) => ("strict", Some(fp.to_string())),
        };
        self.conn().execute(
            "INSERT INTO trust (server, kind, fingerprint) VALUES (?1, ?2, ?3)
             ON CONFLICT (server) DO UPDATE SET kind = excluded.kind,
                 fingerprint = excluded.fingerprint",
            params![server, kind, fp],
        )?;
        self.changed(Change::Settings(SettingsChange::Trust(addr.clone())));
        Ok(())
    }
}

impl Tx<'_> {
    /// Notes `t`, in ms, a time the server of `account` stamped on a post,
    /// a PING or the OK to one (3.2, 11). The server time the device knows
    /// is the newest it has seen, and never goes back (7.6, 12.9).
    pub(crate) fn note_server_time(
        &mut self,
        account: AccountId,
        t: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE servers SET time = max(coalesce(time, 0), ?2)
             WHERE id = (SELECT server FROM accounts WHERE id = ?1)",
            params![account.0, t as i64],
        )?;
        Ok(())
    }

    /// The newest server time the device knows for the server of
    /// `account`, in ms (7.6, 12.9), or `None` if it has seen none.
    pub(crate) fn server_time(&self, account: AccountId) -> Result<Option<u64>, StoreError> {
        server_time(self.conn(), account)
    }
}

fn server_time(conn: &Connection, account: AccountId) -> Result<Option<u64>, StoreError> {
    let t: Option<i64> = conn
        .query_row(
            "SELECT s.time FROM servers s JOIN accounts a ON a.server = s.id
             WHERE a.id = ?1",
            params![account.0],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(t.map(|t| t as u64))
}

impl From<StoreError> for TrustStoreError {
    fn from(e: StoreError) -> TrustStoreError {
        TrustStoreError(e.to_string())
    }
}

impl TrustStore for Store {
    fn get(&self, addr: &ServerAddr) -> Result<Option<TrustRecord>, TrustStoreError> {
        Ok(self.read(|conn| record(conn, addr))?)
    }

    fn replace(
        &self,
        addr: &ServerAddr,
        expected: Option<&TrustRecord>,
        new: TrustRecord,
        notice: Option<PinChange>,
    ) -> Result<Replaced, TrustStoreError> {
        // One IMMEDIATE transaction: no other writer comes between the
        // check and the write.
        let (replaced, _) = self.write(|tx| {
            let found = record(tx.conn(), addr)?;
            if found.as_ref() != expected {
                return Ok(Replaced::Found(found));
            }
            tx.set_trust(addr, &new)?;
            if let Some(notice) = notice {
                let server = tx.server_id(addr)?;
                tx.conn().execute(
                    "INSERT INTO pin_notices (server, old_fingerprint, new_fingerprint)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT (server) DO UPDATE SET
                         old_fingerprint = excluded.old_fingerprint,
                         new_fingerprint = excluded.new_fingerprint",
                    params![server, notice.old.to_string(), notice.new.to_string()],
                )?;
            }
            Ok(Replaced::Done)
        })?;
        Ok(replaced)
    }

    fn forget(&self, addr: &ServerAddr) -> Result<(), TrustStoreError> {
        self.write(|tx| {
            for table in ["trust", "pin_notices"] {
                tx.conn().execute(
                    &format!(
                        "DELETE FROM {table}
                         WHERE server = (SELECT id FROM servers WHERE addr = ?1)"
                    ),
                    [addr.to_string()],
                )?;
            }
            tx.changed(Change::Settings(SettingsChange::Trust(addr.clone())));
            Ok(())
        })?;
        Ok(())
    }

    fn notices(&self) -> Result<Vec<(ServerAddr, PinChange)>, TrustStoreError> {
        Ok(self.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT s.addr, n.old_fingerprint, n.new_fingerprint
                 FROM pin_notices n JOIN servers s ON s.id = n.server ORDER BY s.addr",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (addr, old, new) = row?;
                let old: Fingerprint = parse(&old, "fingerprint")?;
                let new: Fingerprint = parse(&new, "fingerprint")?;
                out.push((parse(&addr, "server address")?, PinChange { old, new }));
            }
            Ok(out)
        })?)
    }

    fn dismiss_notice(&self, addr: &ServerAddr) -> Result<(), TrustStoreError> {
        self.write(|tx| {
            tx.conn().execute(
                "DELETE FROM pin_notices
                 WHERE server = (SELECT id FROM servers WHERE addr = ?1)",
                [addr.to_string()],
            )?;
            tx.changed(Change::Settings(SettingsChange::Trust(addr.clone())));
            Ok(())
        })?;
        Ok(())
    }
}

impl Store {
    /// The account of `kind` for `uid` on `server`, added if it is not
    /// there. A guest's uid is the one asked for, `~<name>`.
    pub fn add_account(
        &self,
        server: &ServerAddr,
        kind: AccountKind,
        uid: &Uid,
    ) -> Result<AccountId, StoreError> {
        if uid.is_guest() != (kind == AccountKind::Guest) {
            return Err(StoreError::Corrupt(format!(
                "{uid} is not a uid for a {} account",
                kind.as_str()
            )));
        }
        let (id, _) = self.write(|tx| {
            let server = tx.server_id(server)?;
            let added = tx.conn().execute(
                "INSERT INTO accounts (server, kind, uid) VALUES (?1, ?2, ?3)
                 ON CONFLICT (server, uid) DO NOTHING",
                params![server, kind.as_str(), uid.as_str()],
            )?;
            if added == 1 {
                tx.changed(Change::Settings(SettingsChange::Accounts));
            }
            let id = tx.conn().query_row(
                "SELECT id FROM accounts WHERE server = ?1 AND uid = ?2",
                params![server, uid.as_str()],
                |row| row.get(0),
            )?;
            Ok(AccountId(id))
        })?;
        Ok(id)
    }

    /// Notes `t`, in ms, a time the server of `account` stamped on a PING
    /// or the OK to one (3.2, 11). The server time the device knows is the
    /// newest it has seen, posts' `t` included, and never goes back (7.6,
    /// 12.9).
    pub fn note_server_time(&self, account: AccountId, t: u64) -> Result<(), StoreError> {
        self.write(|tx| tx.note_server_time(account, t))?;
        Ok(())
    }

    /// The newest server time the device knows for the server of
    /// `account`, in ms (7.6, 12.9), or `None` if it has seen none.
    pub fn server_time(&self, account: AccountId) -> Result<Option<u64>, StoreError> {
        self.read(|conn| server_time(conn, account))
    }

    /// Every account, in the order they were added.
    pub fn accounts(&self) -> Result<Vec<AccountRow>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT a.id, s.addr, a.kind, a.uid FROM accounts a
                 JOIN servers s ON s.id = a.server ORDER BY a.id",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (id, addr, kind, uid) = row?;
                let kind = match kind.as_str() {
                    "identity" => AccountKind::Identity,
                    "guest" => AccountKind::Guest,
                    other => return Err(StoreError::Corrupt(format!("account kind {other:?}"))),
                };
                out.push(AccountRow {
                    id: AccountId(id),
                    server: parse(&addr, "server address")?,
                    kind,
                    uid: parse(&uid, "uid")?,
                });
            }
            Ok(out)
        })
    }

    /// Removes an account, and everything stored for it.
    pub fn remove_account(&self, account: AccountId) -> Result<(), StoreError> {
        self.write(|tx| {
            tx.conn()
                .execute("DELETE FROM accounts WHERE id = ?1", [account.0])?;
            tx.changed(Change::Settings(SettingsChange::Accounts));
            Ok(())
        })?;
        Ok(())
    }

    /// The guest session the account last had (4.2): the name it got,
    /// which may be a numbered one, and the token that resumes it. The
    /// token is a secret.
    pub fn guest_session(
        &self,
        account: AccountId,
    ) -> Result<Option<(Name, GuestToken)>, StoreError> {
        self.read(|conn| {
            let row: Option<(Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT guest_name, guest_token FROM accounts WHERE id = ?1",
                    [account.0],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                None => Err(StoreError::NotFound("account")),
                Some((Some(name), Some(token))) => Ok(Some((
                    parse(&name, "guest name")?,
                    parse(&token, "guest token")?,
                ))),
                Some(_) => Ok(None),
            }
        })
    }

    /// Records the guest session the account has, or forgets it.
    pub fn set_guest_session(
        &self,
        account: AccountId,
        session: Option<(&Name, &GuestToken)>,
    ) -> Result<(), StoreError> {
        let (name, token) = match session {
            Some((name, token)) => (Some(name.as_str().to_owned()), Some(token.to_string())),
            None => (None, None),
        };
        self.write(|tx| {
            let n = tx.conn().execute(
                "UPDATE accounts SET guest_name = ?2, guest_token = ?3
                 WHERE id = ?1 AND kind = 'guest'",
                params![account.0, name, token],
            )?;
            if n == 0 {
                return Err(StoreError::NotFound("guest account"));
            }
            Ok(())
        })?;
        Ok(())
    }

    /// A device-wide setting.
    pub fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                    r.get(0)
                })
                .optional()?)
        })
    }

    /// Sets a device-wide setting, or deletes it.
    pub fn set_setting(&self, key: &str, value: Option<&str>) -> Result<(), StoreError> {
        self.write(|tx| {
            match value {
                Some(v) => tx.conn().execute(
                    "INSERT INTO settings (key, value) VALUES (?1, ?2)
                     ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    params![key, v],
                )?,
                None => tx
                    .conn()
                    .execute("DELETE FROM settings WHERE key = ?1", [key])?,
            };
            Ok(())
        })?;
        Ok(())
    }
}
