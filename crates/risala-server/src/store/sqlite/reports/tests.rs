//! Tests of [`ReportStore`] on SQLite, of migration 4, which lets
//! reports outlive their room, and of migration 7, which marks a room
//! being dropped.

use risala_proto::names::Room;
use risala_proto::types::Relation;

use super::*;
use crate::store::sqlite::SqliteStore;
use crate::store::{Appended, NewEvent, RoomSetting, Store, schema};

fn t(s: &str) -> Timestamp {
    s.parse().unwrap()
}

fn room(name: &str) -> Room {
    name.parse().unwrap()
}

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

/// A store with `#general`, in which bob said "spam" as event 1, and
/// alice replied as event 2.
fn store() -> (SqliteStore, RoomRecord) {
    let store = SqliteStore::open_in_memory().unwrap();
    let record = store
        .ensure_room(&room("#general"), t("2026-11-06T15:00:00.000Z"))
        .unwrap();
    for (from, relation, text) in [
        ("bob@example.net", None, "spam"),
        (
            "alice@example.org",
            Some(Relation::Reply(Seq::new(1).unwrap())),
            "stop",
        ),
    ] {
        let appended = store
            .append(
                record.key,
                &NewEvent {
                    t: t("2026-11-06T15:43:58.019Z"),
                    from: uid(from),
                    kind: EventKind::Msg {
                        relation,
                        file: None,
                        text: text.into(),
                    },
                    cid: None,
                },
            )
            .unwrap();
        assert!(matches!(appended, Appended::New(_)));
    }
    (store, record)
}

fn new_report(store: &SqliteStore, record: &RoomRecord, n: u64, reporter: &str) -> NewReport {
    let event = store
        .event(record.key, Seq::new(n).unwrap())
        .unwrap()
        .unwrap();
    NewReport {
        conv_id: record.id.clone(),
        room: Some(record.room.clone()),
        reporter: uid(reporter),
        reason: "spam".into(),
        t: t("2026-11-06T15:44:10.230Z"),
        event,
        franking: None,
    }
}

fn new_id(added: ReportAdded) -> Id {
    match added {
        ReportAdded::New(id) => id,
        other => panic!("not new: {other:?}"),
    }
}

#[test]
fn a_report_keeps_a_copy_and_is_found_again() {
    let (store, record) = store();
    let report = new_report(&store, &record, 2, "~sam");
    let id = new_id(store.add_report(&report).unwrap());
    assert_eq!(
        store.add_report(&report).unwrap(),
        ReportAdded::Existing(id.clone())
    );
    assert_eq!(
        store
            .report_of(&record.id, Seq::new(2).unwrap(), &uid("~sam"))
            .unwrap(),
        Some(id.clone())
    );
    assert_eq!(
        store
            .report_of(&record.id, Seq::new(1).unwrap(), &uid("~sam"))
            .unwrap(),
        None
    );
    let stored = store.report(&id).unwrap().unwrap();
    assert_eq!(stored.id, id);
    assert_eq!(stored.report, report);

    // Another reporter makes another report.
    let other = new_id(
        store
            .add_report(&new_report(&store, &record, 2, "carol@example.com"))
            .unwrap(),
    );
    assert_ne!(other, id);
    let all = store.reports(None, 0, 10).unwrap();
    assert_eq!(all.iter().map(|r| &r.id).collect::<Vec<_>>(), [&id, &other]);
    // Paging.
    let rest = store.reports(Some(&record.id), all[0].n, 10).unwrap();
    assert_eq!(rest.iter().map(|r| &r.id).collect::<Vec<_>>(), [&other]);
    assert_eq!(store.reports(None, 0, 1).unwrap().len(), 1);

    assert!(store.resolve_report(&id).unwrap());
    assert!(!store.resolve_report(&id).unwrap());
    assert_eq!(store.report(&id).unwrap(), None);
    // A report id is never used for anything else.
    let kind: String = store
        .conn()
        .query_row(
            "SELECT kind FROM used_ids WHERE id = ?",
            [id.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kind, "report");
}

#[test]
fn dropping_a_room_keeps_its_reports() {
    let (store, record) = store();
    let id = new_id(
        store
            .add_report(&new_report(&store, &record, 1, "~sam"))
            .unwrap(),
    );
    store
        .append(
            record.key,
            &NewEvent {
                t: t("2026-11-06T15:50:00.000Z"),
                from: uid("alice@example.org"),
                kind: EventKind::Set(RoomSetting::Public(false)),
                cid: None,
            },
        )
        .unwrap();

    assert_eq!(
        store
            .drop_room(record.key, false, t("2026-11-06T16:00:00.000Z"))
            .unwrap(),
        None
    );
    assert_eq!(store.room(&room("#general")).unwrap(), None);
    assert_eq!(store.clear_dropped(record.key, 100).unwrap(), 3);
    assert_eq!(store.clear_dropped(record.key, 100).unwrap(), 0);
    assert_eq!(store.event(record.key, Seq::new(1).unwrap()).unwrap(), None);
    let left = store.report(&id).unwrap().unwrap().report;
    assert_eq!(left.conv_id, record.id);
    assert_eq!(left.room, Some(room("#general")));
    assert_eq!(
        left.event.kind,
        EventKind::Msg {
            relation: None,
            file: None,
            text: "spam".into()
        }
    );
    // Dropping it again finds nothing.
    assert!(matches!(
        store.drop_room(record.key, false, t("2026-11-06T16:00:00.000Z")),
        Err(StoreError::NoConversation)
    ));
}

#[test]
fn dropping_a_configured_room_creates_it_again() {
    let (store, record) = store();
    let now = t("2026-11-06T16:00:00.000Z");
    let new = store.drop_room(record.key, true, now).unwrap().unwrap();
    assert_eq!(new.room, room("#general"));
    assert_ne!(new.id, record.id);
    assert_ne!(new.key, record.key);
    assert_eq!(new.head, None);
    assert_eq!(new.created, now);
    assert!(new.members.is_empty() && new.roles.is_empty());
    assert_eq!(store.room(&room("#general")).unwrap(), Some(new));
}

#[test]
fn a_dropped_room_is_gone_before_its_events_are() {
    use crate::store::{HistoryQuery, MessageStore, RelatedQuery};
    let (store, record) = store();
    let key = record.key;
    // Events 1 and 2, a reaction to 1, and four more.
    let mut more = vec![EventKind::Msg {
        relation: Some(Relation::React(Seq::new(1).unwrap())),
        file: None,
        text: "+1".into(),
    }];
    more.extend((0..4).map(|n| EventKind::Msg {
        relation: None,
        file: None,
        text: format!("more {n}"),
    }));
    for kind in more {
        store
            .append(
                key,
                &NewEvent {
                    t: t("2026-11-06T15:50:00.000Z"),
                    from: uid("bob@example.net"),
                    kind,
                    cid: None,
                },
            )
            .unwrap();
    }
    let seqs = |store: &SqliteStore| -> Vec<u64> {
        (1..=7)
            .filter(|&n| store.event(key, Seq::new(n).unwrap()).unwrap().is_some())
            .collect()
    };
    let gone = |r: Result<()>| matches!(r, Err(StoreError::NoConversation));
    let history = HistoryQuery {
        after: Some(0),
        before: None,
        limit: 100,
    };
    let related = RelatedQuery {
        first: Seq::new(1).unwrap(),
        last: Seq::new(7).unwrap(),
        after: 0,
        limit: 100,
    };
    let one = Seq::new(1).unwrap();
    assert_eq!(store.history(key, history).unwrap().events.len(), 7);
    assert_eq!(store.related(key, related).unwrap().events.len(), 1);
    assert_eq!(store.clear_dropped(key, 3).unwrap(), 0);
    assert_eq!(seqs(&store), [1, 2, 3, 4, 5, 6, 7]);

    assert_eq!(
        store
            .drop_room(key, false, t("2026-11-06T16:00:00.000Z"))
            .unwrap(),
        None
    );
    // Gone for everyone, though its events are still there.
    assert_eq!(seqs(&store), [1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(store.dropped_rooms().unwrap(), [key]);
    assert!(gone(store.history(key, history).map(|_| ())));
    assert!(gone(store.related(key, related).map(|_| ())));
    let join = NewEvent {
        t: t("2026-11-06T16:00:00.000Z"),
        from: uid("bob@example.net"),
        kind: EventKind::Join,
        cid: None,
    };
    assert!(gone(store.append(key, &join).map(|_| ())));
    assert!(gone(
        store
            .set_read_marker(key, &uid("bob@example.net"), one)
            .map(|_| ())
    ));
    assert!(gone(
        store
            .drop_room(key, false, t("2026-11-06T16:00:00.000Z"))
            .map(|_| ())
    ));
    assert_eq!(store.room(&room("#general")).unwrap(), None);
    assert_eq!(store.rooms().unwrap(), []);
    assert_eq!(
        store.authored_rooms(&uid("bob@example.net"), None).unwrap(),
        []
    );

    // A batch at a time, oldest first, and then the room.
    assert_eq!(store.clear_dropped(key, 0).unwrap(), 0);
    assert_eq!(store.clear_dropped(key, 3).unwrap(), 3);
    assert_eq!(seqs(&store), [4, 5, 6, 7]);
    assert!(gone(store.history(key, history).map(|_| ())));
    assert_eq!(store.clear_dropped(key, 3).unwrap(), 3);
    assert_eq!(seqs(&store), [7]);
    assert_eq!(store.dropped_rooms().unwrap(), [key]);
    assert_eq!(store.clear_dropped(key, 3).unwrap(), 1);
    assert_eq!(seqs(&store), Vec::<u64>::new());
    assert_eq!(store.dropped_rooms().unwrap(), []);
    assert!(gone(store.history(key, history).map(|_| ())));
    assert_eq!(store.clear_dropped(key, 3).unwrap(), 0);
}

/// Migration 7 keeps the conversations, and a dropped room's key is still
/// not given to the next conversation.
#[test]
fn migration_7_keeps_conversation_keys() {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    let v7 = schema::MIGRATIONS
        .iter()
        .position(|m| *m == schema::V7)
        .unwrap();
    schema::migrate_with(&mut conn, &schema::MIGRATIONS[..v7]).unwrap();
    conn.execute_batch(
        "INSERT INTO used_ids VALUES ('c1', 'conversation', 0), ('c2', 'conversation', 0);
         INSERT INTO conversations (id, kind, room, head, created)
             VALUES ('c1', 'room', '#general', 4, 0);
         INSERT INTO conversations (id, kind, room, created) VALUES ('c2', 'room', '#gone', 0);
         DELETE FROM conversations WHERE id = 'c2';",
    )
    .unwrap();
    schema::migrate_with(&mut conn, schema::MIGRATIONS).unwrap();
    let kept: (i64, String, i64, bool) = conn
        .query_row(
            "SELECT conv, room, head, dropping FROM conversations WHERE id = 'c1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(kept, (1, "#general".to_owned(), 4, false));
    conn.execute_batch(
        "INSERT INTO used_ids VALUES ('c3', 'conversation', 0);
         INSERT INTO conversations (id, kind, room, created) VALUES ('c3', 'room', '#new', 0);",
    )
    .unwrap();
    let key: i64 = conn
        .query_row("SELECT conv FROM conversations WHERE id = 'c3'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(key, 3);
}

#[test]
fn migration_4_keeps_open_reports() {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    let v4 = schema::MIGRATIONS
        .iter()
        .position(|m| *m == schema::V4)
        .unwrap();
    schema::migrate_with(&mut conn, &schema::MIGRATIONS[..v4]).unwrap();
    conn.execute_batch(
        "INSERT INTO used_ids VALUES ('c1', 'conversation', 0), ('r1', 'report', 0);
         INSERT INTO conversations (conv, id, kind, room, created)
             VALUES (7, 'c1', 'room', '#general', 0);
         INSERT INTO reports (id, conv, seq, reporter, reason, t, ev_t, ev_author,
                              ev_relation, ev_target, ev_text)
             VALUES ('r1', 7, 3, '~sam', 'spam', 20, 10, 'bob@example.net', 'reply', 1,
                     'cheap pills');",
    )
    .unwrap();
    schema::migrate_with(&mut conn, schema::MIGRATIONS).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    // The room goes; the report stays, naming it.
    conn.execute("DELETE FROM conversations WHERE conv = 7", [])
        .unwrap();
    let report = conn
        .query_row(
            &format!("SELECT {REPORT_COLUMNS} WHERE id = 'r1'"),
            [],
            report_from_row,
        )
        .unwrap()
        .finish()
        .unwrap()
        .report;
    assert_eq!(report.conv_id.as_str(), "c1");
    assert_eq!(report.room, Some(room("#general")));
    assert_eq!(report.event.seq, Seq::new(3).unwrap());
    assert_eq!(report.event.from, uid("bob@example.net"));
    assert_eq!(
        report.event.kind,
        EventKind::Msg {
            relation: Some(Relation::Reply(Seq::new(1).unwrap())),
            file: None,
            text: "cheap pills".into()
        }
    );
    assert_eq!(report.reason, "spam");

    // The dropped room's key is not given to the next conversation.
    conn.execute_batch(
        "INSERT INTO used_ids VALUES ('c2', 'conversation', 0);
         INSERT INTO conversations (id, kind, room, created) VALUES ('c2', 'room', '#new', 0);",
    )
    .unwrap();
    let key: i64 = conn
        .query_row("SELECT conv FROM conversations WHERE id = 'c2'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(key, 8);
}
