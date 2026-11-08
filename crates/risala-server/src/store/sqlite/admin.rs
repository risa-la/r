//! [`AdminStore`] on SQLite, and the tables of settings, operators and
//! bans (Section 10).

use rusqlite::params;

use risala_proto::names::Uid;
use risala_proto::time::Timestamp;
use risala_proto::types::ServerSetting;

use super::SqliteStore;
use crate::store::{AdminStore, Result, ServerSettings, StoreError, millis, parsed};

/// The admin area's tables.
pub(super) const SCHEMA: &str = "
-- The settings of ADMIN SET (10.6), as on the wire. A setting with no row
-- has its value from the configuration.
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- Operators added with ADMIN OP (10.1). Those in the configuration are
-- not stored here.
CREATE TABLE operators (
    uid TEXT PRIMARY KEY,
    added INTEGER NOT NULL          -- ms
) STRICT;

-- Server bans (10.2): an identity, a domain (*@example.net) or an address
-- or prefix, as ADMIN BANS lists them.
CREATE TABLE server_bans (
    target TEXT PRIMARY KEY,
    reason TEXT NOT NULL DEFAULT '', -- escaped (3.4)
    added INTEGER NOT NULL          -- ms
) STRICT;
";

impl AdminStore for SqliteStore {
    fn settings(&self, defaults: &ServerSettings) -> Result<ServerSettings> {
        self.read(|tx| {
            let mut settings = defaults.clone();
            let mut select = tx.prepare_cached("SELECT key, value FROM settings ORDER BY key")?;
            let rows = select.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (key, value) = row?;
                let setting = ServerSetting::parse(&key, &value)
                    .map_err(|e| StoreError::Corrupt(format!("setting {key} {value:?}: {e}")))?;
                if !settings.apply(&setting) {
                    return Err(StoreError::Corrupt(format!("unknown setting {key}")));
                }
            }
            Ok(settings)
        })
    }

    fn save_setting(&self, setting: &ServerSetting) -> Result<bool> {
        if !setting.is_known() {
            return Ok(false);
        }
        self.write(|tx| {
            tx.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                params![setting.key(), setting.value()],
            )?;
            Ok(true)
        })
    }

    fn operators(&self) -> Result<Vec<Uid>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached("SELECT uid FROM operators ORDER BY uid")?;
            let rows = select.query_map([], |row| row.get::<_, String>(0))?;
            rows.map(|uid| parsed("operator", &uid?)).collect()
        })
    }

    fn add_operator(&self, uid: &Uid, now: Timestamp) -> Result<bool> {
        self.write(|tx| {
            Ok(tx.execute(
                "INSERT INTO operators (uid, added) VALUES (?, ?) ON CONFLICT DO NOTHING",
                params![uid.as_str(), millis(now)],
            )? == 1)
        })
    }

    fn remove_operator(&self, uid: &Uid) -> Result<bool> {
        self.write(|tx| Ok(tx.execute("DELETE FROM operators WHERE uid = ?", [uid.as_str()])? == 1))
    }
}

#[cfg(test)]
mod tests {
    use risala_proto::types::Retention;

    use super::*;

    fn defaults() -> ServerSettings {
        ServerSettings {
            anon: true,
            guests: true,
            registration: false,
            retention: Retention::new(30).unwrap(),
            welcome: "Hello".into(),
        }
    }

    #[test]
    fn settings_outlast_the_configuration() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(store.settings(&defaults()).unwrap(), defaults());
        for line in [
            "anon no",
            "guests no",
            "registration open",
            "retention 7",
            "welcome  Two spaces ",
        ] {
            assert!(
                store.save_setting(&line.parse().unwrap()).unwrap(),
                "{line}"
            );
        }
        let unknown: ServerSetting = "colour blue".parse().unwrap();
        assert!(!store.save_setting(&unknown).unwrap());
        assert_eq!(
            store.settings(&defaults()).unwrap(),
            ServerSettings {
                anon: false,
                guests: false,
                registration: true,
                retention: Retention::new(7).unwrap(),
                // The welcome text keeps its spaces (10.6).
                welcome: " Two spaces ".into(),
            }
        );
    }

    #[test]
    fn operators() {
        let store = SqliteStore::open_in_memory().unwrap();
        let t = "2026-11-09T00:00:00.000Z".parse().unwrap();
        let bob: Uid = "bob@example.org".parse().unwrap();
        let alice: Uid = "alice@example.org".parse().unwrap();
        assert!(store.operators().unwrap().is_empty());
        assert!(store.add_operator(&bob, t).unwrap());
        assert!(store.add_operator(&alice, t).unwrap());
        assert!(!store.add_operator(&bob, t).unwrap());
        assert_eq!(store.operators().unwrap(), [alice.clone(), bob.clone()]);
        assert!(store.remove_operator(&bob).unwrap());
        assert!(!store.remove_operator(&bob).unwrap());
        assert_eq!(store.operators().unwrap(), [alice]);
    }
}
