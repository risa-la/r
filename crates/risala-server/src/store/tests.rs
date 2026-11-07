//! Tests of the SQLite store.

use std::collections::BTreeSet;
use std::sync::Arc;

use risala_proto::names::{Conv, Room, Seq, Uid};
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
            let line = e.to_event(Conv::Room(r.room.clone()), &r.id);
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
