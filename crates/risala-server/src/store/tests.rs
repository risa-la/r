//! Tests of the SQLite store.

use std::collections::BTreeSet;
use std::sync::Arc;

use risala_proto::names::{BlockTarget, Conv, Id, Room, Seq, Uid};
use risala_proto::time::Timestamp;
use risala_proto::types::{
    GuestAccess, Relation, Role, RoomRetention, RoomSetting, ServerRetention, ServerSetting,
};

use super::*;

fn t(ms: u64) -> Timestamp {
    Timestamp::from_unix_millis(1_800_000_000_000 + ms).unwrap()
}

fn room(s: &str) -> Room {
    s.parse().unwrap()
}

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn seq(n: u64) -> Seq {
    Seq::new(n).unwrap()
}

fn msg(from: &str, at: u64, text: &str) -> NewEvent {
    NewEvent {
        t: t(at),
        from: uid(from),
        kind: EventKind::Msg {
            relation: None,
            file: None,
            text: text.into(),
        },
        cid: None,
    }
}

fn related(from: &str, relation: Relation, text: &str) -> NewEvent {
    NewEvent {
        kind: EventKind::Msg {
            relation: Some(relation),
            file: None,
            text: text.into(),
        },
        ..msg(from, 0, "")
    }
}

fn event(from: &str, kind: EventKind) -> NewEvent {
    NewEvent {
        t: t(0),
        from: uid(from),
        kind,
        cid: None,
    }
}

fn new_seq(a: Appended) -> u64 {
    match a {
        Appended::New(s) => s.get(),
        Appended::Duplicate(s) => panic!("unexpected duplicate of {s}"),
    }
}

fn store_with_room() -> (SqliteStore, ConvKey) {
    let store = SqliteStore::open_in_memory().unwrap();
    let r = store.ensure_room(&room("#general"), t(0)).unwrap();
    (store, r.key)
}

fn seqs(page: &Page) -> Vec<u64> {
    page.events.iter().map(|e| e.seq.get()).collect()
}

#[test]
fn random_ids_have_the_right_shape() {
    let mut seen = BTreeSet::new();
    for _ in 0..1000 {
        let id = random_id().unwrap();
        assert_eq!(id.as_str().len(), ID_LEN);
        assert!(
            id.as_str()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );
        seen.insert(id);
    }
    assert_eq!(seen.len(), 1000);
}

#[test]
fn ensure_room_creates_once() {
    let store = SqliteStore::open_in_memory().unwrap();
    let a = store.ensure_room(&room("#general"), t(0)).unwrap();
    assert_eq!(a.room, room("#general"));
    assert_eq!(a.head, None);
    assert_eq!(a.settings, RoomSettings::new());
    assert!(a.members.is_empty());
    assert!(a.roles.is_empty());
    assert_eq!(a.created, t(0));
    let b = store.ensure_room(&room("#general"), t(5)).unwrap();
    assert_eq!(a, b);
    let c = store.ensure_room(&room("#other"), t(5)).unwrap();
    assert_ne!(a.id, c.id);
    assert_ne!(a.key, c.key);
    let all: Vec<_> = store.rooms().unwrap().into_iter().map(|r| r.room).collect();
    assert_eq!(all, [room("#general"), room("#other")]);
    assert_eq!(store.room(&room("#general")).unwrap(), Some(a));
    assert_eq!(store.room(&room("#nope")).unwrap(), None);
}

#[test]
fn create_room_makes_the_creator_its_owner() {
    let store = SqliteStore::open_in_memory().unwrap();
    let alice = uid("alice@example.org");
    let Created::New(r) = store.create_room(&room("#new"), &alice, t(3)).unwrap() else {
        panic!("not created");
    };
    assert_eq!(r.room, room("#new"));
    assert_eq!(r.head, Some(seq(1)));
    assert_eq!(r.settings, RoomSettings::new());
    assert_eq!(r.members, std::slice::from_ref(&alice));
    assert_eq!(r.roles, [(alice.clone(), Role::Owner)]);
    assert_eq!(r.created, t(3));
    let page = store
        .history(
            r.key,
            HistoryQuery {
                after: Some(0),
                before: None,
                limit: 10,
            },
        )
        .unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].kind, EventKind::Join);
    assert_eq!(page.events[0].from, alice);
    assert_eq!(page.events[0].t, t(3));

    // A second creation changes nothing.
    let bob = uid("bob@example.net");
    let again = store.create_room(&room("#new"), &bob, t(9)).unwrap();
    assert_eq!(again, Created::Exists(r.clone()));
    // A room from the configuration exists too.
    let general = store.ensure_room(&room("#general"), t(0)).unwrap();
    assert_eq!(
        store.create_room(&room("#general"), &bob, t(9)).unwrap(),
        Created::Exists(general)
    );
}

#[test]
fn reopening_keeps_everything() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("risala.db");
    let (id, key) = {
        let store = SqliteStore::open(&path).unwrap();
        let r = store.ensure_room(&room("#general"), t(0)).unwrap();
        store.append(r.key, &msg("~sam", 1, "hello")).unwrap();
        (r.id, r.key)
    };
    let store = SqliteStore::open(&path).unwrap();
    let r = store.room(&room("#general")).unwrap().unwrap();
    assert_eq!((r.id, r.key, r.head), (id, key, Some(seq(1))));
    let e = store.event(key, seq(1)).unwrap().unwrap();
    assert_eq!(e.from, uid("~sam"));
    assert_eq!(e.t, t(1));
    let conn = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, schema::MIGRATIONS.len() as i64);
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}

#[test]
fn commits_are_durable() {
    // In WAL mode, synchronous=NORMAL can lose the last commits after a
    // power failure, and their seqs would be used again (5.2).
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&dir.path().join("risala.db")).unwrap();
    let conn = store.conn();
    let sync: i64 = conn
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .unwrap();
    assert_eq!(sync, 2, "synchronous=FULL");
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    drop(conn);

    // Only for filling a database quickly.
    let sync = |store: &SqliteStore| -> i64 {
        store
            .conn()
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap()
    };
    store.set_durable(false).unwrap();
    assert_eq!(sync(&store), 0);
    store.set_durable(true).unwrap();
    assert_eq!(sync(&store), 2);
}

#[test]
fn a_database_without_wal_is_refused() {
    // An in-memory database cannot use WAL: its journal mode stays
    // "memory".
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let err = SqliteStore::setup(conn, true).unwrap_err();
    assert!(
        matches!(&err, StoreError::Setup(m) if m.contains("WAL")),
        "{err}"
    );
}

#[test]
fn a_newer_database_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("risala.db");
    drop(SqliteStore::open(&path).unwrap());
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", 99).unwrap();
    drop(conn);
    assert!(matches!(
        SqliteStore::open(&path),
        Err(StoreError::Corrupt(_))
    ));
}

/// A migration that rebuilds `conversations`, the parent of most tables,
/// in the usual way: a new table, the rows copied, the old one dropped and
/// the new one renamed.
const REBUILD_CONVERSATIONS: &str = r#"
CREATE TABLE conversations_new (
    conv    INTEGER PRIMARY KEY,
    id      TEXT NOT NULL UNIQUE REFERENCES used_ids (id),
    kind    TEXT NOT NULL CHECK (kind IN ('room', 'direct')),
    room    TEXT UNIQUE,
    uid_a   TEXT,
    uid_b   TEXT,
    head    INTEGER NOT NULL DEFAULT 0 CHECK (head >= 0),
    created INTEGER NOT NULL,
    note    TEXT NOT NULL DEFAULT '',
    UNIQUE (uid_a, uid_b)
);
INSERT INTO conversations_new (conv, id, kind, room, uid_a, uid_b, head, created)
    SELECT conv, id, kind, room, uid_a, uid_b, head, created FROM conversations;
DROP TABLE conversations;
ALTER TABLE conversations_new RENAME TO conversations;
"#;

fn count(store: &SqliteStore, table: &str) -> i64 {
    store
        .conn()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn foreign_keys_on(store: &SqliteStore) -> bool {
    store
        .conn()
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap()
}

#[test]
fn migrations_can_rebuild_a_parent_table() {
    let (store, key) = store_with_room();
    store
        .append(key, &event("alice@example.org", EventKind::Join))
        .unwrap();
    store
        .append(key, &msg("alice@example.org", 1, "hello"))
        .unwrap();
    let before: Vec<i64> = ["events", "event_text", "members", "room_settings"]
        .iter()
        .map(|table| count(&store, table))
        .collect();
    assert_eq!(before, [2, 1, 1, 1]);

    let mut migrations = schema::MIGRATIONS.to_vec();
    migrations.push(REBUILD_CONVERSATIONS);
    schema::migrate_with(&mut store.conn(), &migrations).unwrap();

    // The rows that refer to the rebuilt table are all still there, and
    // foreign keys are on again.
    let after: Vec<i64> = ["events", "event_text", "members", "room_settings"]
        .iter()
        .map(|table| count(&store, table))
        .collect();
    assert_eq!(after, before);
    assert!(foreign_keys_on(&store));
    let version: i64 = store
        .conn()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, migrations.len() as i64);
    assert_eq!(store.room(&room("#general")).unwrap().unwrap().key, key);
    assert_eq!(
        new_seq(store.append(key, &msg("~sam", 2, "hi")).unwrap()),
        3
    );

    // With foreign keys on, as they were before, the same rebuild deletes
    // every event.
    let (store, key) = store_with_room();
    store.append(key, &msg("~sam", 1, "hello")).unwrap();
    store.conn().execute_batch(REBUILD_CONVERSATIONS).unwrap();
    assert_eq!(count(&store, "events"), 0);
}

#[test]
fn a_migration_that_breaks_foreign_keys_is_rolled_back() {
    let (store, key) = store_with_room();
    store.append(key, &msg("~sam", 1, "hello")).unwrap();
    let mut migrations = schema::MIGRATIONS.to_vec();
    migrations.push("DELETE FROM conversations;");
    let err = schema::migrate_with(&mut store.conn(), &migrations).unwrap_err();
    assert!(
        matches!(&err, StoreError::Corrupt(m) if m.contains("foreign keys")),
        "{err}"
    );
    assert!(foreign_keys_on(&store));
    let version: i64 = store
        .conn()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, schema::MIGRATIONS.len() as i64);
    assert_eq!(count(&store, "conversations"), 1);
    assert_eq!(count(&store, "events"), 1);
}

#[test]
fn append_numbers_events_from_one() {
    let (store, key) = store_with_room();
    for n in 1..=5 {
        let a = store.append(key, &msg("~sam", n, "hi")).unwrap();
        assert_eq!(new_seq(a), n);
    }
    let r = store.room(&room("#general")).unwrap().unwrap();
    assert_eq!(r.head, Some(seq(5)));
    assert!(matches!(
        store.append(ConvKey(999), &msg("~sam", 0, "hi")),
        Err(StoreError::NoConversation)
    ));
}

#[test]
fn events_round_trip() {
    let (store, key) = store_with_room();
    let kinds = [
        EventKind::Join,
        EventKind::Msg {
            relation: None,
            file: Some(risala_proto::server::Attachment {
                url: "https://files.example.org/f/x/cat.png".parse().unwrap(),
                media_type: Some("image/png".parse().unwrap()),
                size: Some(48213),
            }),
            text: "look at this".into(),
        },
        EventKind::Msg {
            relation: Some(Relation::Reply(seq(2))),
            file: None,
            text: "nice \\n cat".into(),
        },
        EventKind::Part {
            reason: String::new(),
        },
        EventKind::Part {
            reason: "bye now".into(),
        },
        EventKind::Invite {
            uid: uid("bob@example.net"),
        },
        EventKind::Kick {
            uid: uid("bob@example.net"),
            reason: "spam".into(),
        },
        EventKind::Ban {
            uid: uid("bob@example.net"),
            reason: String::new(),
        },
        EventKind::Unban {
            uid: uid("bob@example.net"),
        },
        EventKind::Set(RoomSetting::Topic(String::new())),
        EventKind::Set(RoomSetting::Topic("General chat. Be kind.".into())),
        EventKind::Set(RoomSetting::Public(false)),
        EventKind::Set(RoomSetting::Guests(GuestAccess::Read)),
        EventKind::Set(RoomSetting::Retention(RoomRetention::Days(
            std::num::NonZeroU32::new(30).unwrap(),
        ))),
        EventKind::Role {
            uid: uid("bob@example.net"),
            role: Role::Mod,
        },
        EventKind::Delete { target: seq(3) },
    ];
    for (i, kind) in kinds.iter().enumerate() {
        let a = store
            .append(key, &event("alice@example.org", kind.clone()))
            .unwrap();
        assert_eq!(new_seq(a), i as u64 + 1);
    }
    for (i, kind) in kinds.iter().enumerate() {
        let e = store.event(key, seq(i as u64 + 1)).unwrap().unwrap();
        if i == 2 {
            // Deleted by the last event.
            assert!(e.deleted);
            assert_eq!(
                e.kind,
                EventKind::Msg {
                    relation: Some(Relation::Reply(seq(2))),
                    file: None,
                    text: String::new()
                }
            );
        } else {
            assert!(!e.deleted);
            assert_eq!(&e.kind, kind, "event {}", i + 1);
        }
        assert_eq!(e.from, uid("alice@example.org"));
    }
}

#[test]
fn deleted_events_are_placeholders() {
    let (store, key) = store_with_room();
    let r = store.room(&room("#general")).unwrap().unwrap();
    store.append(key, &msg("~sam", 0, "first")).unwrap();
    store
        .append(key, &related("~sam", Relation::Reply(seq(1)), "a reply"))
        .unwrap();
    store
        .append(key, &related("~sam", Relation::Edit(seq(1)), "first!"))
        .unwrap();
    store
        .append(key, &related("~bob", Relation::React(seq(1)), "👍"))
        .unwrap();
    store
        .append(key, &event("~sam", EventKind::Delete { target: seq(1) }))
        .unwrap();
    let page = store
        .history(
            key,
            HistoryQuery {
                after: Some(0),
                before: None,
                limit: 10,
            },
        )
        .unwrap();
    let lines: Vec<String> = page
        .events
        .iter()
        .map(|e| {
            let line = e.to_event(Conv::Room(r.room.clone()), &r.id).unwrap();
            let s = risala_proto::server::ServerMessage::new(line)
                .to_line()
                .to_string();
            // Drop the time, which is the same everywhere.
            s.replace(&format!(";t={}", t(0)), "")
        })
        .collect();
    assert_eq!(
        lines,
        [
            "@seq=1;from=~sam;deleted MSG #general",
            "@seq=2;from=~sam;reply=1 MSG #general a reply",
            "@seq=3;from=~sam;edit=1;deleted MSG #general",
            "@seq=4;from=~bob;react=1;deleted MSG #general",
            "@seq=5;from=~sam DELETE #general 1",
        ]
    );
    // The text is gone from the database, not only hidden.
    let conn = store.conn();
    let n: i64 = conn
        .query_row(
            "SELECT count(*) FROM event_text WHERE conv = ?",
            [key.0],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn room_events_in_a_direct_conversation_are_errors() {
    // Only MSG and DELETE happen in direct conversations. Anything else
    // there is bad data, and an error rather than a panic.
    let id: Id = "abcdefghijkl".parse().unwrap();
    let direct = Conv::Uid(uid("alice@example.org"));
    let stored = |kind| StoredEvent {
        seq: seq(3),
        t: t(0),
        from: uid("bob@example.org"),
        kind,
        deleted: false,
    };
    let message = stored(msg("bob@example.org", 0, "hi").kind);
    assert!(message.to_event(direct.clone(), &id).is_ok());
    assert!(
        stored(EventKind::Delete { target: seq(1) })
            .to_event(direct.clone(), &id)
            .is_ok()
    );
    for kind in [
        EventKind::Join,
        EventKind::Part {
            reason: String::new(),
        },
        EventKind::Set(RoomSetting::Public(true)),
    ] {
        let err = stored(kind).to_event(direct.clone(), &id).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
    }
}

#[test]
fn deleting_an_edit_leaves_the_original() {
    let (store, key) = store_with_room();
    store.append(key, &msg("~sam", 0, "first")).unwrap();
    store
        .append(key, &related("~sam", Relation::Edit(seq(1)), "first!"))
        .unwrap();
    store
        .append(key, &event("~sam", EventKind::Delete { target: seq(2) }))
        .unwrap();
    assert!(!store.event(key, seq(1)).unwrap().unwrap().deleted);
    assert!(store.event(key, seq(2)).unwrap().unwrap().deleted);
}

#[test]
fn identities_are_members_and_guests_are_not() {
    let (store, key) = store_with_room();
    let general = room("#general");
    for who in ["alice@example.org", "~sam", "bob@example.net"] {
        store.append(key, &event(who, EventKind::Join)).unwrap();
    }
    let r = store.room(&general).unwrap().unwrap();
    assert_eq!(
        r.members,
        [uid("alice@example.org"), uid("bob@example.net")]
    );
    store
        .append(
            key,
            &event(
                "alice@example.org",
                EventKind::Part {
                    reason: String::new(),
                },
            ),
        )
        .unwrap();
    let r = store.room(&general).unwrap().unwrap();
    assert_eq!(r.members, [uid("bob@example.net")]);
}

#[test]
fn guest_memberships_follow_joins_and_parts() {
    let (store, key) = store_with_room();
    let other = store.ensure_room(&room("#other"), t(0)).unwrap().key;
    let part = || EventKind::Part {
        reason: String::new(),
    };
    for (conv, who) in [(key, "~sam"), (key, "~ann"), (other, "~sam")] {
        store.append(conv, &event(who, EventKind::Join)).unwrap();
    }
    store
        .append(key, &event("alice@example.org", EventKind::Join))
        .unwrap();
    assert_eq!(
        store.guest_members().unwrap(),
        [(key, uid("~ann")), (key, uid("~sam")), (other, uid("~sam"))]
    );
    store.append(key, &event("~sam", part())).unwrap();
    let kick = EventKind::Kick {
        uid: uid("~sam"),
        reason: String::new(),
    };
    store
        .append(other, &event("alice@example.org", kick))
        .unwrap();
    assert_eq!(store.guest_members().unwrap(), [(key, uid("~ann"))]);
    store.append(key, &event("~ann", part())).unwrap();
    assert_eq!(store.guest_members().unwrap(), []);
}

#[test]
fn settings_roles_and_bans_follow_events() {
    let (store, key) = store_with_room();
    let general = room("#general");
    let bob = uid("bob@example.net");
    store
        .append(key, &event("bob@example.net", EventKind::Join))
        .unwrap();
    for setting in [
        RoomSetting::Topic("hello there".into()),
        RoomSetting::Public(false),
        RoomSetting::Guests(GuestAccess::None),
        RoomSetting::Retention(RoomRetention::Days(std::num::NonZeroU32::new(7).unwrap())),
    ] {
        store
            .append(key, &event("alice@example.org", EventKind::Set(setting)))
            .unwrap();
    }
    store
        .append(
            key,
            &event(
                "alice@example.org",
                EventKind::Role {
                    uid: bob.clone(),
                    role: Role::Mod,
                },
            ),
        )
        .unwrap();
    let r = store.room(&general).unwrap().unwrap();
    assert_eq!(
        r.settings,
        RoomSettings {
            topic: "hello there".into(),
            public: false,
            guests: GuestAccess::None,
            retention: RoomRetention::Days(std::num::NonZeroU32::new(7).unwrap()),
        }
    );
    assert_eq!(r.roles, [(bob.clone(), Role::Mod)]);
    assert_eq!(r.members, std::slice::from_ref(&bob));

    store
        .append(
            key,
            &event(
                "alice@example.org",
                EventKind::Ban {
                    uid: bob.clone(),
                    reason: "no".into(),
                },
            ),
        )
        .unwrap();
    let r = store.room(&general).unwrap().unwrap();
    assert!(r.roles.is_empty());
    assert!(r.members.is_empty());
    assert_eq!(r.bans, std::slice::from_ref(&bob));
    assert!(r.invites.is_empty());
    let conn = store.conn();
    let reason: String = conn
        .query_row(
            "SELECT reason FROM room_bans WHERE conv = ? AND uid = ?",
            rusqlite::params![key.0, bob.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reason, "no");
}

#[test]
fn cids_match_within_a_day_and_a_conversation() {
    let (store, key) = store_with_room();
    let other = store.ensure_room(&room("#other"), t(0)).unwrap().key;
    let with_cid = |from: &str, at: u64, cid: &str| NewEvent {
        cid: Some(cid.parse().unwrap()),
        ..msg(from, at, "hi")
    };
    let cid = "0123456789abcdef";
    assert_eq!(
        store
            .append(key, &with_cid("alice@example.org", 0, cid))
            .unwrap(),
        Appended::New(seq(1))
    );
    assert_eq!(
        store
            .append(key, &with_cid("alice@example.org", 1000, cid))
            .unwrap(),
        Appended::Duplicate(seq(1))
    );
    // Someone else's cid, another room, or another cid: new messages.
    assert_eq!(
        store
            .append(key, &with_cid("bob@example.net", 0, cid))
            .unwrap(),
        Appended::New(seq(2))
    );
    assert_eq!(
        store
            .append(other, &with_cid("alice@example.org", 0, cid))
            .unwrap(),
        Appended::New(seq(1))
    );
    assert_eq!(
        store
            .append(key, &with_cid("alice@example.org", 0, "fedcba9876543210"))
            .unwrap(),
        Appended::New(seq(3))
    );
    // Just inside, then just outside, the 24 hours.
    assert_eq!(
        store
            .append(key, &with_cid("alice@example.org", CID_WINDOW_MS, cid))
            .unwrap(),
        Appended::Duplicate(seq(1))
    );
    assert_eq!(
        store
            .append(key, &with_cid("alice@example.org", CID_WINDOW_MS + 1, cid))
            .unwrap(),
        Appended::New(seq(4))
    );
    // The new message now owns the cid.
    assert_eq!(
        store
            .append(key, &with_cid("alice@example.org", CID_WINDOW_MS + 2, cid))
            .unwrap(),
        Appended::Duplicate(seq(4))
    );
    assert_eq!(store.prune_cids(t(CID_WINDOW_MS)).unwrap(), 3);
}

#[test]
fn history_pages_at_every_edge() {
    let (store, key) = store_with_room();
    let q = |after: Option<u64>, before: Option<u64>, limit: u64| HistoryQuery {
        after,
        before: before.map(seq),
        limit,
    };
    // Empty.
    let page = store.history(key, q(Some(0), None, 5)).unwrap();
    assert_eq!((seqs(&page), page.more), (vec![], false));
    let page = store.history(key, q(None, None, 5)).unwrap();
    assert_eq!((seqs(&page), page.more), (vec![], false));

    for n in 1..=10 {
        store.append(key, &msg("~sam", n, "hi")).unwrap();
    }
    // (after, before, limit, the seqs returned, more)
    type Case = (Option<u64>, Option<u64>, u64, &'static [u64], bool);
    let cases: &[Case] = &[
        // after
        (Some(0), None, 3, &[1, 2, 3], true),
        (Some(0), None, 10, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], false),
        (Some(0), None, 11, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], false),
        (Some(7), None, 3, &[8, 9, 10], false),
        (Some(7), None, 2, &[8, 9], true),
        (Some(9), None, 5, &[10], false),
        (Some(10), None, 5, &[], false),
        (Some(500), None, 5, &[], false),
        // after and before
        (Some(2), Some(6), 10, &[3, 4, 5], false),
        (Some(2), Some(6), 3, &[3, 4, 5], false),
        (Some(2), Some(6), 2, &[3, 4], true),
        (Some(2), Some(3), 5, &[], false),
        (Some(5), Some(2), 5, &[], false),
        (Some(0), Some(1), 5, &[], false),
        // before only
        (None, None, 3, &[8, 9, 10], true),
        (None, None, 10, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], false),
        (None, None, 50, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], false),
        (None, Some(5), 2, &[3, 4], true),
        (None, Some(5), 4, &[1, 2, 3, 4], false),
        (None, Some(5), 9, &[1, 2, 3, 4], false),
        (None, Some(2), 1, &[1], false),
        (None, Some(1), 5, &[], false),
        (None, Some(11), 1, &[10], true),
        (None, Some(500), 2, &[9, 10], true),
        // limit 1
        (Some(0), None, 1, &[1], true),
        (None, None, 1, &[10], true),
    ];
    for &(after, before, limit, want, more) in cases {
        let page = store.history(key, q(after, before, limit)).unwrap();
        assert_eq!(
            (seqs(&page), page.more),
            (want.to_vec(), more),
            "after={after:?} before={before:?} limit={limit}"
        );
    }
}

#[test]
fn server_settings_start_from_the_defaults() {
    let store = SqliteStore::open_in_memory().unwrap();
    let defaults = ServerSettings {
        guests: true,
        registration: false,
        retention: ServerRetention::Forever,
        welcome: "Welcome!".into(),
    };
    assert_eq!(store.load_server_settings(&defaults).unwrap(), defaults);
    store
        .set_server_setting(&ServerSetting::Guests(false))
        .unwrap();
    store
        .set_server_setting(&ServerSetting::Welcome("Hi there".into()))
        .unwrap();
    // Stored values win over the configuration from now on.
    let got = store.load_server_settings(&defaults).unwrap();
    assert!(!got.guests);
    assert_eq!(got.welcome, "Hi there");
    assert_eq!(got.retention, ServerRetention::Forever);
}

#[test]
fn concurrent_appends_get_every_seq_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteStore::open(&dir.path().join("risala.db")).unwrap());
    let key = store.ensure_room(&room("#general"), t(0)).unwrap().key;
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let store = store.clone();
            std::thread::spawn(move || {
                (0..50)
                    .map(|_| new_seq(store.append(key, &msg("~sam", i, "hi")).unwrap()))
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut all: Vec<u64> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();
    all.sort_unstable();
    assert_eq!(all, (1..=400).collect::<Vec<_>>());
}

// ---------------------------------------------------------------------------
// Identities (4.3-4.8)

fn key(n: u8) -> risala_proto::auth::PublicKey {
    risala_proto::auth::SecretKey::from_seed([n; 32]).public_key()
}

/// Labels over 64 bytes, which KEY ADD took before draft-02 set the
/// limit, are dropped by migration 3, and any that turns up later is not
/// loaded, since it cannot be sent in a KEY line (4.4, 4.7).
#[test]
fn key_labels_over_64_bytes_are_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("risala.db");
    let alice = uid("alice@example.org");
    let long = "x".repeat(65);
    let fits = "\\s".repeat(16) + &"y".repeat(32);
    assert_eq!(fits.len(), 64);
    {
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        schema::migrate_with(&mut conn, &schema::MIGRATIONS[..2]).unwrap();
        conn.execute(
            "INSERT INTO identities (uid, hosted, first_seen, last_seen) VALUES (?, 1, 0, 0)",
            [alice.as_str()],
        )
        .unwrap();
        for (n, label) in [(1, long.as_str()), (2, fits.as_str()), (3, "phone")] {
            conn.execute(
                "INSERT INTO hosted_keys (uid, key, label, added) VALUES (?, ?, ?, ?)",
                rusqlite::params![alice.as_str(), key(n).to_string(), label, n],
            )
            .unwrap();
        }
    }
    let store = SqliteStore::open(&path).unwrap();
    let labels = |store: &SqliteStore| -> Vec<String> {
        store
            .hosted_keys(&alice)
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|k| k.label)
            .collect()
    };
    assert_eq!(labels(&store), ["", fits.as_str(), "phone"]);
    store
        .conn()
        .execute(
            "UPDATE hosted_keys SET label = ? WHERE key = ?",
            rusqlite::params![long, key(3).to_string()],
        )
        .unwrap();
    assert_eq!(labels(&store), ["", fits.as_str(), ""]);
}

#[test]
fn signing_in_makes_an_identity_known() {
    let store = SqliteStore::open_in_memory().unwrap();
    let bob = uid("bob@example.net");
    assert_eq!(store.identity(&bob).unwrap(), None);
    store.touch_identity(&bob, t(5)).unwrap();
    store.touch_identity(&bob, t(9)).unwrap();
    // A clock that went back does not move last_seen back.
    store.touch_identity(&bob, t(7)).unwrap();
    let r = store.identity(&bob).unwrap().unwrap();
    assert!(!r.hosted);
    assert_eq!((r.first_seen, r.last_seen), (t(5), t(9)));
    assert_eq!(r.display_name, "");
    // Not hosted: no keys of its own.
    assert_eq!(store.hosted_keys(&bob).unwrap(), None);
    assert_eq!(
        store.add_hosted_key(&bob, &key(1), "", 64, t(9)).unwrap(),
        KeyChange::NotHosted
    );
}

#[test]
fn registering_and_managing_keys() {
    let store = SqliteStore::open_in_memory().unwrap();
    let alice = uid("alice@example.org");
    assert_eq!(
        store.register(&alice, &key(1), t(1)).unwrap(),
        Registered::Done
    );
    assert_eq!(
        store.register(&alice, &key(2), t(2)).unwrap(),
        Registered::Taken
    );
    assert!(store.identity(&alice).unwrap().unwrap().hosted);
    let keys = |store: &SqliteStore| -> Vec<(risala_proto::auth::PublicKey, String)> {
        store
            .hosted_keys(&alice)
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|k| (k.key, k.label))
            .collect()
    };
    assert_eq!(keys(&store), [(key(1), String::new())]);

    // The last key cannot be deleted; an unknown one is not found.
    assert_eq!(
        store.delete_hosted_key(&alice, &key(1)).unwrap(),
        KeyChange::LastKey
    );
    assert_eq!(
        store.delete_hosted_key(&alice, &key(2)).unwrap(),
        KeyChange::NotFound
    );

    let KeyChange::Done(after) = store
        .add_hosted_key(&alice, &key(2), "phone", 3, t(2))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(after.len(), 2);
    // Adding a key again changes its label.
    store
        .add_hosted_key(&alice, &key(2), "new\\sphone", 3, t(3))
        .unwrap();
    store.add_hosted_key(&alice, &key(3), "", 3, t(4)).unwrap();
    assert_eq!(
        store.add_hosted_key(&alice, &key(4), "", 3, t(5)).unwrap(),
        KeyChange::TooMany
    );
    assert_eq!(
        keys(&store),
        [
            (key(1), String::new()),
            (key(2), "new\\sphone".into()),
            (key(3), String::new())
        ]
    );
    let KeyChange::Done(after) = store.delete_hosted_key(&alice, &key(1)).unwrap() else {
        panic!()
    };
    assert_eq!(after.len(), 2);
    assert_eq!(after[0].key, key(2));
    assert_eq!(
        store.hosted_identities().unwrap(),
        [(alice.clone(), store.hosted_keys(&alice).unwrap().unwrap())]
    );
}

#[test]
fn forgetting_an_identity() {
    let (store, general) = store_with_room();
    let alice = uid("alice@example.org");
    let bob = uid("bob@example.net");
    store.register(&alice, &key(1), t(0)).unwrap();
    let other = match store.create_room(&room("#alice"), &alice, t(0)).unwrap() {
        Created::New(r) => r,
        Created::Exists(_) => panic!(),
    };
    store
        .append(general, &event("alice@example.org", EventKind::Join))
        .unwrap();
    store
        .append(
            general,
            &NewEvent {
                cid: Some("0123456789abcdef".parse().unwrap()),
                ..msg("alice@example.org", 0, "hi")
            },
        )
        .unwrap();
    store
        .append(
            general,
            &event("bob@example.net", EventKind::Invite { uid: alice.clone() }),
        )
        .unwrap();
    store.set_read_marker(general, &alice, seq(2)).unwrap();
    store.set_read_marker(general, &bob, seq(2)).unwrap();
    store
        .conn()
        .execute_batch(
            "INSERT INTO blocks (uid, target, t) VALUES ('alice@example.org', 'bob@example.net', 0);
             INSERT INTO operators (uid, added) VALUES ('alice@example.org', 0);
             INSERT INTO push_registrations (device_key, url, uid, tag, added)
                 VALUES ('k', 'https://push.example/x', 'alice@example.org', 't', 0);",
        )
        .unwrap();
    assert_eq!(
        store.rooms_with_role_or_invite(&alice).unwrap(),
        [room("#alice"), room("#general")]
    );
    assert_eq!(store.operators().unwrap(), std::slice::from_ref(&alice));

    store.forget_identity(&alice, true, t(9)).unwrap();
    assert_eq!(store.identity(&alice).unwrap(), None);
    assert_eq!(store.hosted_keys(&alice).unwrap(), None);
    assert_eq!(count(&store, "hosted_keys"), 0);
    assert!(store.rooms_with_role_or_invite(&alice).unwrap().is_empty());
    assert!(store.read_markers(&alice).unwrap().is_empty());
    assert_eq!(store.read_markers(&bob).unwrap(), [(general, seq(2))]);
    for table in [
        "blocks",
        "operators",
        "push_registrations",
        "cids",
        "members",
        "invites",
        "roles",
    ] {
        assert_eq!(count(&store, table), 0, "{table}");
    }
    assert!(
        store
            .room(&room("#alice"))
            .unwrap()
            .unwrap()
            .roles
            .is_empty()
    );
    let _ = other;
    // Retired: never again (4.8, 10.5).
    assert_eq!(
        store.register(&alice, &key(2), t(10)).unwrap(),
        Registered::Retired
    );
    // Without retiring, a name may come back.
    store
        .register(&uid("carol@example.org"), &key(3), t(0))
        .unwrap();
    store
        .forget_identity(&uid("carol@example.org"), false, t(9))
        .unwrap();
    assert_eq!(
        store
            .register(&uid("carol@example.org"), &key(3), t(10))
            .unwrap(),
        Registered::Done
    );
}

#[test]
fn read_markers_only_move_forward_and_stop_at_the_head() {
    let (store, general) = store_with_room();
    let alice = uid("alice@example.org");
    let marker = |n: u64, moved: bool| Some(ReadMarker { seq: seq(n), moved });
    // No events yet: no marker.
    assert_eq!(
        store.set_read_marker(general, &alice, seq(3)).unwrap(),
        None
    );
    for n in 0..5 {
        store
            .append(general, &msg("bob@example.net", n, "x"))
            .unwrap();
    }
    assert_eq!(
        store.set_read_marker(general, &alice, seq(3)).unwrap(),
        marker(3, true)
    );
    assert_eq!(store.read_marker(general, &alice).unwrap(), Some(seq(3)));
    let bob = uid("bob@example.net");
    assert_eq!(store.read_marker(general, &bob).unwrap(), None);
    assert_eq!(
        store.set_read_marker(general, &alice, seq(3)).unwrap(),
        marker(3, false)
    );
    assert_eq!(
        store.set_read_marker(general, &alice, seq(2)).unwrap(),
        marker(3, false)
    );
    assert_eq!(
        store.set_read_marker(general, &alice, seq(99)).unwrap(),
        marker(5, true)
    );
    assert_eq!(
        store.set_read_marker(general, &alice, seq(99)).unwrap(),
        marker(5, false)
    );
    assert_eq!(store.read_markers(&alice).unwrap(), [(general, seq(5))]);
}

#[test]
fn display_names_belong_to_known_identities() {
    let store = SqliteStore::open_in_memory().unwrap();
    let (alice, bob) = (uid("alice@example.org"), uid("bob@example.net"));
    store.touch_identity(&alice, t(1)).unwrap();
    store.touch_identity(&bob, t(1)).unwrap();
    store.set_display_name(&alice, "Alice Martin").unwrap();
    // Unknown identities are left alone.
    store
        .set_display_name(&uid("carol@example.com"), "Carol")
        .unwrap();
    let all = [
        alice.clone(),
        bob.clone(),
        uid("carol@example.com"),
        uid("~sam"),
    ];
    let names = store.display_names(&all).unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[&alice], "Alice Martin");
    assert_eq!(
        store.identity(&alice).unwrap().unwrap().display_name,
        "Alice Martin"
    );
    // Empty clears it.
    store.set_display_name(&alice, "").unwrap();
    assert!(store.display_names(&all).unwrap().is_empty());
}

#[test]
fn blocks_are_kept_per_account_up_to_a_limit() {
    let store = SqliteStore::open_in_memory().unwrap();
    let (alice, bob) = (uid("alice@example.org"), uid("bob@example.net"));
    let target = |s: &str| s.parse::<BlockTarget>().unwrap();
    assert!(store.blocks(&alice).unwrap().is_empty());
    assert!(
        store
            .add_block(&alice, &target("spam@example.net"), 2, t(1))
            .unwrap()
    );
    assert!(
        store
            .add_block(&alice, &target("*@bad.example"), 2, t(1))
            .unwrap()
    );
    // A third is over the limit, but one it has already counts as done.
    assert!(
        !store
            .add_block(&alice, &target("x@example.com"), 2, t(1))
            .unwrap()
    );
    assert!(
        store
            .add_block(&alice, &target("spam@example.net"), 2, t(1))
            .unwrap()
    );
    assert_eq!(
        store.blocks(&alice).unwrap(),
        [target("*@bad.example"), target("spam@example.net")]
    );
    assert!(store.blocks(&bob).unwrap().is_empty());
    store
        .remove_block(&alice, &target("*@bad.example"))
        .unwrap();
    // Removing one it does not have changes nothing.
    store
        .remove_block(&alice, &target("*@bad.example"))
        .unwrap();
    assert_eq!(store.blocks(&alice).unwrap(), [target("spam@example.net")]);
}
