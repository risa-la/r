//! [`AdminStore`] on SQLite.

use rusqlite::params;

use risala_proto::auth::PublicKey;
use risala_proto::names::{ServerBanTarget, Uid};
use risala_proto::time::Timestamp;

use super::{SqliteStore, hosted_keys_in, is_hosted, ms, parse, time};
use crate::store::{AdminStore, KeyChange, Result, ServerBan};

impl AdminStore for SqliteStore {
    fn add_operator(&self, uid: &Uid, now: Timestamp) -> Result<bool> {
        self.write(|tx| {
            let added = tx.execute(
                "INSERT OR IGNORE INTO operators (uid, added) VALUES (?, ?)",
                params![uid.as_str(), ms(now)],
            )?;
            Ok(added > 0)
        })
    }

    fn remove_operator(&self, uid: &Uid) -> Result<bool> {
        self.write(|tx| {
            let removed = tx.execute("DELETE FROM operators WHERE uid = ?", [uid.as_str()])?;
            Ok(removed > 0)
        })
    }

    fn server_bans(&self) -> Result<Vec<ServerBan>> {
        self.conn()
            .prepare_cached("SELECT target, reason, t FROM server_bans ORDER BY target")?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .map(|r| {
                let (target, reason, t) = r?;
                Ok(ServerBan {
                    target: parse("server ban", &target)?,
                    reason,
                    t: time(t)?,
                })
            })
            .collect()
    }

    fn add_server_ban(&self, ban: &ServerBan) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "INSERT OR REPLACE INTO server_bans (target, reason, t) VALUES (?, ?, ?)",
                params![ban.target.to_string(), ban.reason, ms(ban.t)],
            )?;
            Ok(())
        })
    }

    fn remove_server_ban(&self, target: &ServerBanTarget) -> Result<bool> {
        self.write(|tx| {
            let removed = tx.execute(
                "DELETE FROM server_bans WHERE target = ?",
                [target.to_string()],
            )?;
            Ok(removed > 0)
        })
    }

    fn remove_any_hosted_key(&self, uid: &Uid, key: &PublicKey) -> Result<KeyChange> {
        self.write(|tx| {
            if !is_hosted(tx, uid)? {
                return Ok(KeyChange::NotHosted);
            }
            let removed = tx.execute(
                "DELETE FROM hosted_keys WHERE uid = ? AND key = ?",
                params![uid.as_str(), key.to_string()],
            )?;
            if removed == 0 {
                return Ok(KeyChange::NotFound);
            }
            Ok(KeyChange::Done(hosted_keys_in(tx, uid)?))
        })
    }
}

#[cfg(test)]
mod tests {
    use risala_proto::auth::SecretKey;

    use super::*;
    use crate::store::Store;

    fn t() -> Timestamp {
        "2026-11-06T15:40:58.120Z".parse().unwrap()
    }

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    #[test]
    fn operators() {
        let s = SqliteStore::open_in_memory().unwrap();
        assert!(s.add_operator(&uid("b@example.net"), t()).unwrap());
        assert!(!s.add_operator(&uid("b@example.net"), t()).unwrap());
        assert!(s.add_operator(&uid("a@example.net"), t()).unwrap());
        assert_eq!(
            s.operators().unwrap(),
            [uid("a@example.net"), uid("b@example.net")]
        );
        assert!(s.remove_operator(&uid("b@example.net")).unwrap());
        assert!(!s.remove_operator(&uid("b@example.net")).unwrap());
        assert_eq!(s.operators().unwrap(), [uid("a@example.net")]);
    }

    #[test]
    fn server_bans() {
        let s = SqliteStore::open_in_memory().unwrap();
        for (target, reason) in [
            ("spam@example.net", "first"),
            ("2001:db8::/32", ""),
            ("*@example.com", "domain"),
            ("spam@example.net", "second"),
            ("203.0.113.7", ""),
        ] {
            let ban = ServerBan {
                target: target.parse().unwrap(),
                reason: reason.into(),
                t: t(),
            };
            s.add_server_ban(&ban).unwrap();
        }
        let listed: Vec<String> = s
            .server_bans()
            .unwrap()
            .iter()
            .map(|b| format!("{} {}", b.target, b.reason))
            .collect();
        assert_eq!(
            listed,
            [
                "*@example.com domain",
                "2001:db8::/32 ",
                "203.0.113.7 ",
                "spam@example.net second"
            ]
        );
        let gone: ServerBanTarget = "2001:db8::/32".parse().unwrap();
        assert!(s.remove_server_ban(&gone).unwrap());
        assert!(!s.remove_server_ban(&gone).unwrap());
        assert_eq!(s.server_bans().unwrap().len(), 3);
    }

    #[test]
    fn the_last_hosted_key_can_go() {
        let s = SqliteStore::open_in_memory().unwrap();
        let alice = uid("alice@example.org");
        let key = |n: u8| SecretKey::from_seed([n; 32]).public_key();
        assert_eq!(
            s.remove_any_hosted_key(&alice, &key(1)).unwrap(),
            KeyChange::NotHosted
        );
        s.register(&alice, &key(1), t()).unwrap();
        assert_eq!(
            s.remove_any_hosted_key(&alice, &key(2)).unwrap(),
            KeyChange::NotFound
        );
        assert_eq!(
            s.remove_any_hosted_key(&alice, &key(1)).unwrap(),
            KeyChange::Done(Vec::new())
        );
        // Still hosted, with no keys: locked (10.5).
        assert_eq!(s.hosted_keys(&alice).unwrap(), Some(Vec::new()));
    }
}
