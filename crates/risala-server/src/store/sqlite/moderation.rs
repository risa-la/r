//! [`ModerationStore`] on SQLite.

use super::{SqliteStore, parse};
use crate::store::{ConvKey, ModerationStore, Result};
use risala_proto::names::Uid;

impl ModerationStore for SqliteStore {
    fn room_bans(&self, conv: ConvKey) -> Result<Vec<(Uid, String)>> {
        let conn = self.conn();
        conn.prepare_cached("SELECT uid, reason FROM room_bans WHERE conv = ? ORDER BY uid")?
            .query_map([conv.0], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .map(|r| {
                let (uid, reason) = r?;
                Ok((parse::<Uid>("banned uid", &uid)?, reason))
            })
            .collect()
    }

    fn set_room_ban_reason(&self, conv: ConvKey, uid: &Uid, reason: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE room_bans SET reason = ? WHERE conv = ? AND uid = ?",
            rusqlite::params![reason, conv.0, uid.as_str()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use risala_proto::names::Room;
    use risala_proto::time::Timestamp;

    use super::*;
    use crate::store::{EventKind, NewEvent, Store};

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    #[test]
    fn bans_come_with_their_reasons_and_go_with_unban() {
        let store = SqliteStore::open_in_memory().unwrap();
        let t: Timestamp = "2026-11-06T15:40:58.120Z".parse().unwrap();
        let room: Room = "#general".parse().unwrap();
        let key = store.ensure_room(&room, t).unwrap().key;
        assert_eq!(store.room_bans(key).unwrap(), vec![]);
        let append = |kind| {
            let event = NewEvent {
                t,
                from: uid("alice@example.org"),
                kind,
                cid: None,
            };
            store.append(key, &event).unwrap();
        };
        append(EventKind::Ban {
            uid: uid("mallory@example.net"),
            reason: "spam\\sagain".into(),
        });
        append(EventKind::Ban {
            uid: uid("~sam"),
            reason: String::new(),
        });
        append(EventKind::Ban {
            uid: uid("eve@example.net"),
            reason: String::new(),
        });
        append(EventKind::Unban {
            uid: uid("eve@example.net"),
        });
        assert_eq!(
            store.room_bans(key).unwrap(),
            vec![
                (uid("mallory@example.net"), "spam\\sagain".to_owned()),
                (uid("~sam"), String::new()),
            ]
        );
        // The room's record agrees.
        let record = store.room(&room).unwrap().unwrap();
        assert_eq!(record.bans, vec![uid("mallory@example.net"), uid("~sam")]);
    }
}
