//! Tests of the cache.

use risala_proto::fingerprint::Fingerprint;
use risala_proto::names::{Conv, Id, Name, Room, Seq, Uid};
use risala_proto::server::{Event, ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::{Relation, Role, RoomSetting};

use super::*;
use crate::addr::{ServerAddr, TrustRecord, TrustStore};

fn addr() -> ServerAddr {
    "chat.example.org".parse().unwrap()
}

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn room() -> Conv {
    "#general".parse().unwrap()
}

fn id(s: &str) -> Id {
    s.parse().unwrap()
}

fn seq(n: u64) -> Seq {
    Seq::new(n).unwrap()
}

/// An event line, with `t` filled in from the seq.
fn ev(seq: u64, rest: &str) -> Event {
    let t = Timestamp::from_unix_millis(1_800_000_000_000 + seq).unwrap();
    let line = format!("@seq={seq};t={t};{rest}");
    match line.parse::<ServerMessage>().unwrap().line {
        ServerLine::Event(e) => e,
        other => panic!("{other:?}"),
    }
}

fn snapshot(line: &str) -> Event {
    match line.parse::<ServerMessage>().unwrap().line {
        ServerLine::Event(e) => e,
        other => panic!("{other:?}"),
    }
}

/// A store with alice's account and #general known by id `k1`.
fn setup() -> (Store, AccountId, ConvId) {
    let store = Store::open_in_memory().unwrap();
    let account = store.account(&addr(), &uid("alice@example.org")).unwrap();
    let (conv, _) = store
        .write(|tx| {
            let mut row = tx.conv_or_create(account, &room())?;
            tx.learn_id(&mut row, &id("k1"), Some(0))?;
            Ok(row.id)
        })
        .unwrap();
    (store, account, conv)
}

fn store_all(store: &Store, conv: ConvId, events: &[Event]) -> Vec<Change> {
    let ((), changes) = store
        .write(|tx| {
            let mut row = tx.conv(conv)?.unwrap();
            for e in events {
                tx.store_event(&row, e)?;
            }
            tx.raise_sync_point(&mut row, 0)?;
            Ok(())
        })
        .unwrap();
    changes
}

fn text(store: &Store, conv: ConvId, n: u64) -> (String, bool) {
    let item = store.message(conv, seq(n)).unwrap().unwrap();
    (item.text.unwrap(), item.deleted)
}

#[test]
fn trust_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    let store = Store::open(&path).unwrap();
    let a = addr();
    assert_eq!(TrustStore::get(&store, &a).unwrap(), None);
    store.set(&a, TrustRecord::Ca).unwrap();
    assert_eq!(TrustStore::get(&store, &a).unwrap(), Some(TrustRecord::Ca));
    let fp = Fingerprint::from_bytes([7; 32]);
    store.set(&a, TrustRecord::Pinned(fp)).unwrap();
    drop(store);

    // The record survives reopening.
    let store = Store::open(&path).unwrap();
    assert_eq!(
        TrustStore::get(&store, &a).unwrap(),
        Some(TrustRecord::Pinned(fp))
    );
    let other: ServerAddr = "chat.example.org:7000".parse().unwrap();
    assert_eq!(TrustStore::get(&store, &other).unwrap(), None);
    // 2.1: the same server written another way finds the same record.
    let shouted: ServerAddr = "Chat.Example.ORG.".parse().unwrap();
    assert_eq!(
        TrustStore::get(&store, &shouted).unwrap(),
        Some(TrustRecord::Pinned(fp))
    );
    store.forget(&a).unwrap();
    assert_eq!(TrustStore::get(&store, &a).unwrap(), None);
}

#[test]
fn reads_do_not_wait_for_writes() {
    // A write holds the write connection, for example while it waits for
    // another process's lock. Reads use their own connection, and see
    // what was committed before.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("cache.db")).unwrap();
    let account = store.account(&addr(), &uid("alice@example.org")).unwrap();
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let writer = {
        let store = store.clone();
        std::thread::spawn(move || {
            store
                .write(|tx| {
                    tx.conv_or_create(account, &room())?;
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();
        })
    };
    entered.recv().unwrap();
    let (done_tx, done) = std::sync::mpsc::channel();
    {
        let store = store.clone();
        std::thread::spawn(move || {
            done_tx.send(store.conversations(account).unwrap()).unwrap();
        });
    }
    // Generous: the read takes milliseconds, or never ends if it waits.
    let seen = done
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the read waited for the write");
    assert!(seen.is_empty(), "the write is not committed yet");
    release.send(()).unwrap();
    writer.join().unwrap();
    assert_eq!(store.conversations(account).unwrap().len(), 1);
}

#[test]
fn schema_versions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    drop(Store::open(&path).unwrap());
    let conn = rusqlite::Connection::open(&path).unwrap();
    let version: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, schema::VERSION);
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    conn.pragma_update(None, "user_version", schema::VERSION + 1)
        .unwrap();
    drop(conn);
    assert!(matches!(Store::open(&path), Err(StoreError::TooNew(_))));
}

#[test]
fn two_processes() {
    // Two connections to one file, as an app and its notification
    // extension would have.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    let a = Store::open(&path).unwrap();
    let b = Store::open(&path).unwrap();
    let account = a.account(&addr(), &uid("alice@example.org")).unwrap();
    assert_eq!(
        b.account(&addr(), &uid("alice@example.org")).unwrap(),
        account
    );
    let (conv, _) = a
        .write(|tx| {
            let mut row = tx.conv_or_create(account, &room())?;
            tx.learn_id(&mut row, &id("k1"), Some(1))?;
            Ok(row.id)
        })
        .unwrap();
    store_all(&a, conv, &[ev(1, "from=bob@example.net MSG #general hi")]);
    let seen = b.conversation(account, &room()).unwrap().unwrap();
    assert_eq!((seen.sync_point, seen.unread), (1, 1));
    assert_eq!(b.export(conv).unwrap().len(), 1);
}

#[test]
fn accounts() {
    let store = Store::open_in_memory().unwrap();
    let a = store.account(&addr(), &uid("alice@example.org")).unwrap();
    let g = store.account(&addr(), &uid("~sam")).unwrap();
    assert_ne!(a, g);
    assert_eq!(store.account_uid(g).unwrap(), uid("~sam"));
    assert_eq!(store.accounts().unwrap().len(), 2);
    store.remove_account(g).unwrap();
    assert_eq!(store.accounts().unwrap().len(), 1);
    assert!(matches!(store.account_uid(g), Err(StoreError::NotFound(_))));
}

#[test]
fn edits_and_reactions() {
    let (store, _, conv) = setup();
    let changes = store_all(
        &store,
        conv,
        &[
            ev(1, "from=bob@example.net MSG #general lunch?"),
            ev(2, "from=bob@example.net;edit=1 MSG #general lunch at 12?"),
            // Only the author may edit (5.3); the client ignores others.
            ev(3, "from=alice@example.org;edit=1 MSG #general hacked"),
            ev(4, "from=alice@example.org;react=1 MSG #general 🍕"),
            ev(5, "from=carol@example.com;react=1 MSG #general 🍕"),
            ev(6, "from=carol@example.com;react=1 MSG #general 👍"),
        ],
    );
    assert!(changes.contains(&Change::Inserted { conv, seq: seq(1) }));
    assert!(changes.contains(&Change::Updated { conv, seq: seq(1) }));
    assert!(!changes.contains(&Change::Inserted { conv, seq: seq(2) }));
    let item = store.message(conv, seq(1)).unwrap().unwrap();
    assert_eq!(item.text.as_deref(), Some("lunch at 12?"));
    assert_eq!(item.edit, Some(seq(2)));
    let reactions: Vec<_> = item
        .reactions
        .iter()
        .map(|r| (r.reaction.as_str(), r.count, r.mine))
        .collect();
    assert_eq!(reactions, [("🍕", 2, Some(seq(4))), ("👍", 1, None)]);
    // Edits and reactions are not timeline items.
    assert!(store.message(conv, seq(2)).unwrap().is_none());
    let timeline = store.timeline(conv, None, 10).unwrap();
    assert_eq!(timeline.len(), 1);

    // Deleting the edit brings back the original (5.4).
    store_all(
        &store,
        conv,
        &[ev(7, "from=bob@example.net DELETE #general 2")],
    );
    assert_eq!(text(&store, conv, 1), ("lunch?".into(), false));
    // Deleting a reaction removes it.
    store_all(
        &store,
        conv,
        &[ev(8, "from=alice@example.org DELETE #general 4")],
    );
    let item = store.message(conv, seq(1)).unwrap().unwrap();
    assert_eq!(item.reactions[0].count, 1);
    assert_eq!(item.reactions[0].mine, None);
}

#[test]
fn deleting_a_message() {
    let (store, _, conv) = setup();
    store_all(
        &store,
        conv,
        &[
            ev(
                1,
                "from=bob@example.net;file=https://f.example.org/f/abc/cat.png;file-type=image/png;file-size=10 MSG #general cat",
            ),
            ev(2, "from=bob@example.net;edit=1 MSG #general a cat"),
            ev(3, "from=carol@example.com;react=1 MSG #general 😺"),
            ev(4, "from=carol@example.com;reply=1 MSG #general nice"),
            ev(5, "from=bob@example.net DELETE #general 1"),
        ],
    );
    // The text and file are gone, and the line is the placeholder (5.4).
    assert_eq!(text(&store, conv, 1), (String::new(), true));
    let lines = store.export(conv).unwrap();
    assert_eq!(
        lines[0],
        "@seq=1;t=2027-01-15T08:00:00.001Z;from=bob@example.net;deleted MSG #general"
    );
    // Its edits and reactions go too; replies stay.
    assert!(lines[1].contains(";deleted MSG"), "{}", lines[1]);
    assert!(lines[2].contains(";deleted MSG"), "{}", lines[2]);
    assert!(
        store
            .message(conv, seq(1))
            .unwrap()
            .unwrap()
            .reactions
            .is_empty()
    );
    assert_eq!(text(&store, conv, 4), ("nice".into(), false));
    for line in &lines {
        assert!(!line.contains("cat"), "{line}");
    }
}

#[test]
fn delete_before_its_target() {
    // A DELETE can be stored before its target arrives, from an older page
    // that was read before the deletion (5.4).
    let (store, _, conv) = setup();
    store_all(
        &store,
        conv,
        &[ev(9, "from=bob@example.net DELETE #general 3")],
    );
    store_all(
        &store,
        conv,
        &[
            ev(3, "from=bob@example.net MSG #general oops"),
            ev(4, "from=bob@example.net;edit=3 MSG #general oops!"),
            ev(5, "from=carol@example.com;react=3 MSG #general 😬"),
        ],
    );
    assert_eq!(text(&store, conv, 3), (String::new(), true));
    for line in store.export(conv).unwrap().iter().take(3) {
        assert!(line.contains("deleted"), "{line}");
    }
    // A placeholder from HISTORY marks a stored message deleted.
    store_all(
        &store,
        conv,
        &[ev(6, "from=bob@example.net MSG #general fine")],
    );
    store_all(
        &store,
        conv,
        &[ev(6, "from=bob@example.net;deleted MSG #general")],
    );
    assert_eq!(text(&store, conv, 6), (String::new(), true));
}

#[test]
fn related_placeholders_remove_edits_and_reactions() {
    // 7.3: RELATED returns deleted edits and reactions as placeholders, so
    // that a client can remove ones it has stored (5.4).
    let (store, _, conv) = setup();
    store_all(
        &store,
        conv,
        &[
            ev(1, "from=bob@example.net MSG #general lunch?"),
            ev(2, "from=bob@example.net;edit=1 MSG #general lunch at 12?"),
            ev(3, "from=bob@example.net;edit=1 MSG #general lunch at 1?"),
            ev(4, "from=carol@example.com;react=1 MSG #general 🍕"),
        ],
    );
    assert_eq!(text(&store, conv, 1), ("lunch at 1?".into(), false));
    let changes = store_all(
        &store,
        conv,
        &[
            ev(3, "from=bob@example.net;edit=1;deleted MSG #general"),
            ev(4, "from=carol@example.com;react=1;deleted MSG #general"),
        ],
    );
    // The previous version is current again, and the reaction is gone.
    assert_eq!(text(&store, conv, 1), ("lunch at 12?".into(), false));
    let item = store.message(conv, seq(1)).unwrap().unwrap();
    assert_eq!(item.edit, Some(seq(2)));
    assert!(item.reactions.is_empty());
    assert!(changes.contains(&Change::Updated { conv, seq: seq(1) }));
    for line in &store.export(conv).unwrap()[2..] {
        assert!(line.contains(";deleted MSG"), "{line}");
        assert!(!line.contains("lunch") && !line.contains('🍕'), "{line}");
    }
    // A placeholder for an edit not stored yet is stored as one.
    store_all(
        &store,
        conv,
        &[ev(5, "from=bob@example.net;edit=1;deleted MSG #general")],
    );
    assert_eq!(text(&store, conv, 1), ("lunch at 12?".into(), false));
}

#[test]
fn sync_point_follows_stored_events() {
    let (store, _, conv) = setup();
    let msg = |n| ev(n, "from=bob@example.net MSG #general hi");
    store_all(&store, conv, &[msg(1), msg(3), msg(4)]);
    let sp = |s: &Store| s.conversation_by_id(conv).unwrap().unwrap().sync_point;
    assert_eq!(sp(&store), 1);
    store_all(&store, conv, &[msg(2)]);
    assert_eq!(sp(&store), 4);
    store
        .write(|tx| {
            let row = tx.conv(conv)?.unwrap();
            assert_eq!(tx.first_missing_after(conv, 0)?, 5);
            assert_eq!(tx.gap_top(&row)?, None);
            Ok(())
        })
        .unwrap();
    store_all(&store, conv, &[msg(9), msg(10)]);
    store
        .write(|tx| {
            let mut row = tx.conv(conv)?.unwrap();
            assert_eq!(tx.gap_top(&row)?, Some(9));
            // Raising it past a gap is the caller's claim; then it moves on.
            tx.raise_sync_point(&mut row, 8)?;
            assert_eq!(row.sync_point, 10);
            Ok(())
        })
        .unwrap();
}

#[test]
fn a_new_id_discards_history() {
    let (store, account, conv) = setup();
    store_all(
        &store,
        conv,
        &[ev(1, "from=bob@example.net MSG #general hi")],
    );
    let (out, _) = store
        .write(|tx| {
            tx.queue(
                account,
                &room(),
                Some(&id("k1")),
                &Draft::text("hello"),
                Timestamp::MIN,
            )?;
            tx.queue(
                account,
                &room(),
                Some(&id("k1")),
                &Draft::text("again"),
                Timestamp::MIN,
            )
        })
        .unwrap();
    store.write(|tx| tx.outbox_sent(out, seq(2))).unwrap();

    // The same id and a head at or past what is stored: nothing happens.
    let (reset, _) = store
        .write(|tx| {
            let mut row = tx.conv(conv)?.unwrap();
            tx.learn_id(&mut row, &id("k1"), Some(1))
        })
        .unwrap();
    assert!(!reset);

    // Events stored past the sync point do not count (7.1): another
    // process may have stored them after the server computed the head.
    store_all(
        &store,
        conv,
        &[ev(3, "from=bob@example.net MSG #general later")],
    );
    let (reset, _) = store
        .write(|tx| {
            let mut row = tx.conv(conv)?.unwrap();
            assert_eq!(row.sync_point, 1);
            tx.learn_id(&mut row, &id("k1"), Some(1))
        })
        .unwrap();
    assert!(!reset);
    assert_eq!(store.export(conv).unwrap().len(), 2);

    // A head below the sync point (7.1). The room is the same, so the
    // outbox entries bound to it stay.
    let (reset, changes) = store
        .write(|tx| {
            let mut row = tx.conv(conv)?.unwrap();
            tx.learn_id(&mut row, &id("k1"), Some(0))
        })
        .unwrap();
    assert!(reset);
    assert!(changes.contains(&Change::Cleared { conv }));
    assert!(store.export(conv).unwrap().is_empty());
    assert_eq!(store.outbox(account).unwrap()[0].state, OutboxState::Queued);

    // A new id (7.1 step 2) also fails what was bound to the old one.
    store_all(
        &store,
        conv,
        &[ev(1, "from=bob@example.net MSG #general hi")],
    );
    let (reset, _) = store
        .write(|tx| {
            let mut row = tx.conv(conv)?.unwrap();
            tx.queue(
                account,
                &room(),
                Some(&id("k1")),
                &Draft::text("late"),
                Timestamp::MIN,
            )?;
            tx.learn_id(&mut row, &id("k2"), Some(5))
        })
        .unwrap();
    assert!(reset);
    let summary = store.conversation_by_id(conv).unwrap().unwrap();
    assert_eq!(summary.conv_id, Some(id("k2")));
    assert_eq!((summary.sync_point, summary.head), (0, 5));
    let states: Vec<_> = store
        .outbox(account)
        .unwrap()
        .into_iter()
        .map(|i| i.state)
        .collect();
    assert_eq!(
        states,
        [
            OutboxState::Failed(FailReason::RoomChanged),
            OutboxState::Sent(seq(2)),
            OutboxState::Failed(FailReason::RoomChanged),
        ]
    );
}

#[test]
fn removing_a_room() {
    let (store, account, conv) = setup();
    store_all(
        &store,
        conv,
        &[ev(1, "from=bob@example.net MSG #general hi")],
    );
    store
        .write(|tx| {
            tx.queue(
                account,
                &room(),
                Some(&id("k1")),
                &Draft::text("x"),
                Timestamp::MIN,
            )
        })
        .unwrap();
    let (_, changes) = store
        .write(|tx| {
            let row = tx.conv(conv)?.unwrap();
            tx.remove(&row)
        })
        .unwrap();
    assert!(changes.contains(&Change::ConversationRemoved { conv, name: room() }));
    assert!(store.conversations(account).unwrap().is_empty());
    assert!(store.export(conv).unwrap().is_empty());
    assert_eq!(
        store.outbox(account).unwrap()[0].state,
        OutboxState::Failed(FailReason::Dropped)
    );
    // A new row never reuses the old id.
    let (row, _) = store
        .write(|tx| tx.conv_or_create(account, &room()))
        .unwrap();
    assert_ne!(row.id, conv);
}

#[test]
fn unread_counts_the_gap_that_is_not_stored() {
    // 7.1 step 4: only the newest page of a long gap is stored. The rest
    // counts as unread too, from the read marker or the sync point.
    let (store, _account, conv) = setup();
    let newest: Vec<Event> = (591..=600)
        .map(|n| ev(n, "from=bob@example.net MSG #general hi"))
        .collect();
    store_all(&store, conv, &newest);
    store
        .write(|tx| {
            let mut row = tx.conv(conv)?.unwrap();
            tx.note_head(&mut row, 600)
        })
        .unwrap();
    assert_eq!(store.unread(conv).unwrap(), 600);
    let read = |n: u64| {
        store
            .write(|tx| {
                let mut row = tx.conv(conv)?.unwrap();
                tx.set_read(&mut row, n)
            })
            .unwrap();
    };
    read(500);
    assert_eq!(store.unread(conv).unwrap(), 100);
    read(595);
    assert_eq!(store.unread(conv).unwrap(), 5);
    // Below the sync point, events that are not stored have expired: they
    // do not count.
    store
        .write(|tx| {
            let mut row = tx.conv(conv)?.unwrap();
            tx.raise_sync_point(&mut row, 590)
        })
        .unwrap();
    assert_eq!(
        store.conversation_by_id(conv).unwrap().unwrap().sync_point,
        600
    );
    assert_eq!(store.unread(conv).unwrap(), 5);
}

#[test]
fn unread_and_read_markers() {
    let (store, account, conv) = setup();
    store_all(
        &store,
        conv,
        &[
            ev(1, "from=bob@example.net MSG #general one"),
            ev(2, "from=alice@example.org MSG #general mine"),
            ev(3, "from=bob@example.net MSG #general two"),
            ev(4, "from=bob@example.net;edit=3 MSG #general two!"),
            ev(5, "from=bob@example.net;react=1 MSG #general 👍"),
            ev(6, "from=bob@example.net MSG #general three"),
            ev(7, "from=bob@example.net DELETE #general 6"),
        ],
    );
    assert_eq!(store.unread(conv).unwrap(), 2);
    store
        .write(|tx| {
            let mut row = tx.conv(conv)?.unwrap();
            assert!(tx.set_read(&mut row, 1)?);
            // Only forward (7.4).
            assert!(!tx.set_read(&mut row, 0)?);
            Ok(())
        })
        .unwrap();
    assert_eq!(store.unread(conv).unwrap(), 1);
    let summary = store.conversation(account, &room()).unwrap().unwrap();
    assert_eq!((summary.read, summary.newest), (1, Some(seq(7))));
}

#[test]
fn timeline_pages() {
    let (store, _, conv) = setup();
    let events: Vec<Event> = (1..=10)
        .map(|n| ev(n, &format!("from=bob@example.net MSG #general n{n}")))
        .collect();
    store_all(&store, conv, &events);
    let seqs = |items: Vec<TimelineItem>| items.iter().map(|i| i.seq.get()).collect::<Vec<_>>();
    assert_eq!(seqs(store.timeline(conv, None, 3).unwrap()), [8, 9, 10]);
    assert_eq!(
        seqs(store.timeline(conv, Some(seq(8)), 3).unwrap()),
        [5, 6, 7]
    );
    assert_eq!(seqs(store.timeline(conv, Some(seq(2)), 3).unwrap()), [1]);
}

#[test]
fn settings_and_members() {
    let (store, _, conv) = setup();
    store_all(
        &store,
        conv,
        &[
            ev(5, "from=bob@example.net;id=k1 JOIN #general"),
            ev(6, "from=bob@example.net SET #general topic new topic"),
            ev(
                7,
                "from=bob@example.net ROLE #general carol@example.com mod",
            ),
            ev(
                8,
                "from=bob@example.net KICK #general dave@example.com spam",
            ),
        ],
    );
    // An older event loaded later does not overwrite a newer value.
    store_all(
        &store,
        conv,
        &[ev(2, "from=bob@example.net SET #general topic old topic")],
    );
    // A snapshot is the state now.
    let (_, _) = store
        .write(|tx| {
            let row = tx.conv(conv)?.unwrap();
            tx.apply_snapshot(&row, &snapshot("SET #general public no"))?;
            tx.apply_snapshot(&row, &snapshot("BAN #general eve@example.com"))
        })
        .unwrap();
    let mut settings = store.room_settings(conv).unwrap();
    settings.sort_by(|a, b| a.key().cmp(b.key()));
    assert_eq!(
        settings,
        [
            RoomSetting::Public(false),
            RoomSetting::Topic("new topic".into())
        ]
    );
    let members = store.room_members(conv).unwrap();
    let find = |u: &str| members.iter().find(|m| m.uid == uid(u)).unwrap().clone();
    assert_eq!(find("bob@example.net").joined, Some(true));
    assert_eq!(find("carol@example.com").role, Some(Role::Mod));
    let dave = find("dave@example.com");
    assert_eq!((dave.joined, dave.role), (Some(false), Some(Role::Member)));
    assert!(find("eve@example.com").banned);
}

#[test]
fn outbox_entries() {
    let (store, account, _) = setup();
    let draft = Draft {
        text: "yes".into(),
        relation: Some(Relation::Reply(seq(3))),
        file: None,
    };
    let now = Timestamp::from_unix_millis(1_800_000_000_000).unwrap();
    let (a, _) = store
        .write(|tx| tx.queue(account, &room(), Some(&id("k1")), &draft, now))
        .unwrap();
    let (b, _) = store
        .write(|tx| tx.queue(account, &room(), None, &Draft::text("no"), now))
        .unwrap();
    let items = store.outbox_for(account, &room()).unwrap();
    assert_eq!(items[0].draft, draft);
    assert_eq!(items[0].state, OutboxState::Queued);
    // Fresh, long cids (7.6).
    assert_ne!(items[0].cid, items[1].cid);
    assert!(items[0].cid.as_str().len() >= 16);

    store
        .write(|tx| {
            tx.outbox_sending(a, &store.new_claim(), now)?;
            tx.outbox_bind(b, &id("k1"))?;
            tx.outbox_failed(
                b,
                FailReason::Rejected(risala_proto::error::ErrorCode::Forbidden),
            )
        })
        .unwrap();
    let a = store.outbox_item(a).unwrap().unwrap();
    assert_eq!((a.state, a.first_sent), (OutboxState::Sending, Some(now)));
    let b2 = store.outbox_item(b).unwrap().unwrap();
    assert_eq!(b2.conv_id, Some(id("k1")));
    assert_eq!(
        b2.state,
        OutboxState::Failed(FailReason::Rejected(
            risala_proto::error::ErrorCode::Forbidden
        ))
    );
    store.remove_outbox(b).unwrap();
    assert!(store.outbox_item(b).unwrap().is_none());
}

#[test]
fn rooms_to_rejoin() {
    let store = Store::open_in_memory().unwrap();
    let a = store.account(&addr(), &uid("~sam")).unwrap();
    let b = store.account(&addr(), &uid("~ann")).unwrap();
    let general: Room = "#general".parse().unwrap();
    let dev: Room = "#dev".parse().unwrap();
    assert!(store.rejoin_rooms(a).unwrap().is_empty());
    store.set_rejoin(a, &general, true).unwrap();
    store.set_rejoin(a, &dev, true).unwrap();
    store.set_rejoin(a, &dev, true).unwrap();
    store.set_rejoin(b, &dev, true).unwrap();
    assert_eq!(
        store.rejoin_rooms(a).unwrap(),
        [dev.clone(), general.clone()]
    );
    store.set_rejoin(a, &dev, false).unwrap();
    assert_eq!(store.rejoin_rooms(a).unwrap(), [general]);
    store.remove_account(a).unwrap();
    assert!(store.rejoin_rooms(a).unwrap().is_empty());
    assert_eq!(store.rejoin_rooms(b).unwrap(), [dev]);
}

#[test]
fn guest_sessions() {
    let store = Store::open_in_memory().unwrap();
    let sam = store.account(&addr(), &uid("~sam")).unwrap();
    let ann = store.account(&addr(), &uid("~ann")).unwrap();
    assert_eq!(store.guest_session(sam).unwrap(), None);
    let name: Name = "sam2".parse().unwrap();
    let token = id("q7m2x9k4b8n1v5c3z6l0w2e4r7t9y1u3");
    store.set_guest_session(sam, Some((&name, &token))).unwrap();
    assert_eq!(
        store.guest_session(sam).unwrap(),
        Some((name.clone(), token.clone()))
    );
    assert_eq!(store.guest_session(ann).unwrap(), None);
    store.set_guest_session(sam, None).unwrap();
    assert_eq!(store.guest_session(sam).unwrap(), None);
}

#[test]
fn own_events_follow_the_connection_uid() {
    // The guest account ~sam signed in as ~sam2 (4.2): what ~sam2 sent is
    // its own, and neither counts as unread nor as someone else's
    // reaction. ~sam is someone else now, since the name was taken.
    let store = Store::open_in_memory().unwrap();
    let account = store.account(&addr(), &uid("~sam")).unwrap();
    let events = [
        ev(1, "from=~bob MSG #general hi"),
        ev(2, "from=~sam2 MSG #general hello"),
        ev(3, "from=~sam MSG #general the new holder of the name"),
        ev(4, "from=~sam2;react=1 MSG #general 👍"),
    ];
    let ((conv, _), _) = store
        .write(|tx| {
            tx.signed_in_as(&uid("~sam2"));
            let mut row = tx.conv_or_create(account, &room())?;
            tx.learn_id(&mut row, &id("k1"), Some(0))?;
            for e in &events {
                tx.store_event(&row, e)?;
            }
            tx.raise_sync_point(&mut row, 0)?;
            Ok((row.id, ()))
        })
        .unwrap();
    assert_eq!(store.unread(conv).unwrap(), 2);
    let first = store.message(conv, seq(1)).unwrap().unwrap();
    assert_eq!(first.reactions.len(), 1, "{first:?}");
    assert_eq!(first.reactions[0].mine, Some(seq(4)));

    // Stored without the connection's uid, ~sam2 is someone else.
    let other = store.account(&addr(), &uid("~ann")).unwrap();
    let (conv, _) = store
        .write(|tx| {
            let mut row = tx.conv_or_create(other, &room())?;
            tx.learn_id(&mut row, &id("k1"), Some(0))?;
            Ok(row.id)
        })
        .unwrap();
    store_all(&store, conv, &events);
    assert_eq!(store.unread(conv).unwrap(), 3);
}

#[test]
fn a_version_4_cache_with_data_migrates() {
    // Versions 5 to 8 add names, blocks, the accepted key, the block
    // clock and lost UNREGISTERs. What a version 4 cache holds must come through, and work
    // with them.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for m in &schema::MIGRATIONS[..4] {
            conn.execute_batch(m).unwrap();
        }
        conn.pragma_update(None, "user_version", 4).unwrap();
        conn.execute_batch(
            "INSERT INTO servers (id, addr) VALUES (1, 'chat.example.org');
             INSERT INTO trust (server, kind) VALUES (1, 'ca');
             INSERT INTO accounts (id, server, uid) VALUES (1, 1, 'alice@example.org');
             INSERT INTO convs (id, account, name, conv_id, sync_point, head, read, joined)
                 VALUES (1, 1, '#general', 'k1', 3, 3, 1, 1);
             INSERT INTO events (conv, seq, t, author, verb, text, line) VALUES
                 (1, 1, 0, 'bob@example.net', 'MSG', 'hi',
                  '@seq=1;t=1970-01-01T00:00:00.000Z;from=bob@example.net MSG #general hi'),
                 (1, 2, 0, 'troll@example.com', 'MSG', 'boo',
                  '@seq=2;t=1970-01-01T00:00:00.000Z;from=troll@example.com MSG #general boo');
             INSERT INTO events (conv, seq, t, author, verb, rel, target, text, line) VALUES
                 (1, 3, 0, 'troll@example.com', 'MSG', 'react', 1, 'x',
                  '@seq=3;t=1970-01-01T00:00:00.000Z;from=troll@example.com;react=1 MSG #general x');
             INSERT INTO message_state (conv, seq, text) VALUES (1, 1, 'hi'), (1, 2, 'boo');
             INSERT INTO reactions (conv, target, reaction, count) VALUES (1, 1, 'x', 1);
             INSERT INTO outbox (account, conv, conv_id, cid, text, state, created, claim,
                                 claimed_at)
                 VALUES (1, '#general', 'k1', 'Abcdefghijklmnopqrstu1', 'later', 'queued', 0, NULL,
                         NULL);",
        )
        .unwrap();
    }
    let store = Store::open(&path).unwrap();
    let account = store.account(&addr(), &uid("alice@example.org")).unwrap();
    assert_eq!(account, AccountId(1));
    assert_eq!(
        TrustStore::get(&store, &addr()).unwrap(),
        Some(TrustRecord::Ca)
    );
    let summary = store.conversation(account, &room()).unwrap().unwrap();
    assert_eq!(
        (summary.sync_point, summary.read, summary.unread),
        (3, 1, 1)
    );
    assert_eq!(store.outbox(account).unwrap().len(), 1);
    // Nothing yet of what the new versions add.
    assert_eq!(
        store.user_name(account, &uid("bob@example.net")).unwrap(),
        None
    );
    assert!(store.blocks(account).unwrap().is_empty());
    assert!(!store.hides_blocked(account).unwrap());
    assert_eq!(store.blocks_clock(account).unwrap(), 0);
    assert_eq!(store.accepted_key(account).unwrap(), None);
    assert_eq!(store.unregister_lost(account).unwrap(), None);
    // And they work on the old data.
    let troll: risala_proto::names::BlockTarget = "troll@example.com".parse().unwrap();
    store
        .write(|tx| tx.change_block(account, &troll, true).map(drop))
        .unwrap();
    store.set_hide_blocked(account, true).unwrap();
    let shown: Vec<u64> = store
        .timeline(ConvId(1), None, 50)
        .unwrap()
        .iter()
        .map(|i| i.seq.get())
        .collect();
    assert_eq!(shown, [1]);
    assert!(
        store
            .message(ConvId(1), seq(1))
            .unwrap()
            .unwrap()
            .reactions
            .is_empty()
    );
    assert_eq!(store.blocks_clock(account).unwrap(), 1);
    store.set_accepted_key(account, "sha256:x").unwrap();
    assert_eq!(
        store.accepted_key(account).unwrap().as_deref(),
        Some("sha256:x")
    );
}

#[test]
fn version_2_caches_mark_own_events_by_the_account_uid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for m in &schema::MIGRATIONS[..2] {
            conn.execute_batch(m).unwrap();
        }
        conn.pragma_update(None, "user_version", 2).unwrap();
        conn.execute_batch(
            "INSERT INTO servers (id, addr) VALUES (1, 'chat.example.org');
             INSERT INTO accounts (id, server, uid) VALUES (1, 1, '~sam');
             INSERT INTO convs (id, account, name, conv_id) VALUES (1, 1, '#general', 'k1');
             INSERT INTO events (conv, seq, t, author, verb, text, line) VALUES
                 (1, 1, 0, '~bob', 'MSG', 'hi', '@seq=1;t=1970-01-01T00:00:00.000Z;from=~bob MSG #general hi'),
                 (1, 2, 0, '~sam', 'MSG', 'yo', '@seq=2;t=1970-01-01T00:00:00.000Z;from=~sam MSG #general yo');",
        )
        .unwrap();
    }
    let store = Store::open(&path).unwrap();
    assert_eq!(store.unread(ConvId(1)).unwrap(), 1);
    let account = store.account(&addr(), &uid("~sam")).unwrap();
    assert_eq!(account, AccountId(1));
    assert_eq!(store.guest_session(account).unwrap(), None);
}

#[test]
fn blocked_people_can_be_hidden_in_rooms() {
    // 5.7: hiding is the client's, so the messages stay stored.
    let (store, account, conv) = setup();
    store_all(
        &store,
        conv,
        &[
            ev(1, "from=bob@example.net MSG #general hi"),
            ev(2, "from=spam@mail.evil.example MSG #general buy"),
            ev(3, "from=troll@example.com MSG #general boo"),
            ev(4, "from=troll@example.com;react=1 MSG #general 👎"),
            ev(5, "from=alice@example.org MSG #general hello"),
            ev(6, "from=troll@example.com;id=k1 JOIN #general"),
        ],
    );
    let shown = |store: &Store| -> Vec<u64> {
        store
            .timeline(conv, None, 50)
            .unwrap()
            .iter()
            .map(|i| i.seq.get())
            .collect()
    };
    let unread = |store: &Store| store.conversation_by_id(conv).unwrap().unwrap().unread;
    assert_eq!(shown(&store), [1, 2, 3, 5, 6]);
    assert_eq!(unread(&store), 3);

    let blocks: Vec<risala_proto::names::BlockTarget> = vec![
        "*@evil.example".parse().unwrap(),
        "troll@example.com".parse().unwrap(),
    ];
    let ((), changes) = store
        .write(|tx| tx.apply_blocks(account, &blocks, 0).map(drop))
        .unwrap();
    assert_eq!(changes, [Change::Blocks { account }]);
    // Blocking alone hides nothing.
    assert_eq!(shown(&store), [1, 2, 3, 5, 6]);
    assert!(!store.hides_blocked(account).unwrap());

    let changes = store.set_hide_blocked(account, true).unwrap();
    assert_eq!(changes, [Change::Blocks { account }]);
    assert!(store.set_hide_blocked(account, true).unwrap().is_empty());
    // Their messages are hidden, a subdomain's too, and are not unread.
    // Their JOIN stays: only messages are hidden.
    assert_eq!(shown(&store), [1, 5, 6]);
    assert_eq!(store.message(conv, seq(3)).unwrap(), None);
    assert_eq!(unread(&store), 1);
    let troll = uid("troll@example.com");
    assert!(store.is_hidden(account, &room(), &troll).unwrap());
    assert!(
        !store
            .is_hidden(account, &"bob@example.net".parse().unwrap(), &troll)
            .unwrap()
    );

    // Their reactions do not count either: of the 👍 on message 1, only
    // bob's, and the troll's 👎 and 🍕 not at all.
    let counts = |store: &Store| -> Vec<(String, u64)> {
        store
            .message(conv, seq(1))
            .unwrap()
            .unwrap()
            .reactions
            .iter()
            .map(|r| (r.reaction.clone(), r.count))
            .collect()
    };
    store_all(
        &store,
        conv,
        &[
            ev(7, "from=bob@example.net;react=1 MSG #general 👍"),
            ev(8, "from=troll@example.com;react=1 MSG #general 👍"),
            ev(9, "from=troll@example.com;react=1 MSG #general 🍕"),
        ],
    );
    assert_eq!(counts(&store), [("👍".to_owned(), 1)]);
    store.set_hide_blocked(account, false).unwrap();
    assert_eq!(
        counts(&store),
        [
            ("🍕".to_owned(), 1),
            ("👍".to_owned(), 2),
            ("👎".to_owned(), 1)
        ]
    );
    store.set_hide_blocked(account, true).unwrap();

    // Unblocking shows them again.
    let ((), changes) = store
        .write(|tx| tx.change_block(account, &blocks[1], false).map(drop))
        .unwrap();
    assert_eq!(changes, [Change::Blocks { account }]);
    assert_eq!(shown(&store), [1, 3, 5, 6]);
    assert_eq!(counts(&store).len(), 3);
    store.set_hide_blocked(account, false).unwrap();
    assert_eq!(shown(&store), [1, 2, 3, 5, 6]);
    assert_eq!(store.export(conv).unwrap().len(), 9);
}

#[test]
fn display_names() {
    let (store, account, _) = setup();
    let bob = uid("bob@example.net");
    let ((), changes) = store
        .write(|tx| tx.set_user_name(account, &bob, "Bob B").map(drop))
        .unwrap();
    assert_eq!(
        changes,
        [Change::User {
            account,
            uid: bob.clone()
        }]
    );
    assert_eq!(
        store
            .user_names(account, &[bob.clone(), uid("~x")])
            .unwrap(),
        [(bob.clone(), "Bob B".to_owned())].into_iter().collect()
    );
    // Names belong to the account: another account on the server has
    // not learned them.
    let other = store.account(&addr(), &uid("~sam")).unwrap();
    assert_eq!(store.user_name(other, &bob).unwrap(), None);
    store.remove_account(account).unwrap();
    assert_eq!(store.user_name(account, &bob).unwrap(), None);
}

#[cfg(unix)]
#[test]
fn only_the_owner_can_read_a_new_cache() {
    // It holds private history and guest session tokens (4.2).
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    let store = Store::open(&path).unwrap();
    let account = store.account(&addr(), &uid("~sam")).unwrap();
    store
        .set_guest_session(account, Some((&"sam".parse().unwrap(), &id("t1"))))
        .unwrap();
    let mut files = 0;
    for name in ["cache.db", "cache.db-wal", "cache.db-shm"] {
        let Ok(meta) = std::fs::metadata(dir.path().join(name)) else {
            continue;
        };
        files += 1;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{name}");
    }
    assert_eq!(files, 3, "WAL mode keeps -wal and -shm while open");
    drop(store);
    // Opening it again works, and leaves the mode alone.
    let store = Store::open(&path).unwrap();
    assert_eq!(store.accounts().unwrap().len(), 1);
}
