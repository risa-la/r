//! Unit tests of the client layer that need no server: offline sends,
//! the timeline's diffs and input checks. The end-to-end tests are in
//! `tests/client.rs` and `tests/cuts.rs`.

use std::sync::Arc;
use std::time::Duration;

use risala_proto::names::{Conv, Seq};
use risala_proto::server::{Event, ServerLine, ServerMessage};
use risala_proto::time::Timestamp;

use super::account::Batch;
use super::*;
use crate::store::{Draft, FailReason, Store};

const SERVER: &str = "chat.example.org";

fn event(seq: u64, rest: &str) -> Event {
    let t = Timestamp::from_unix_millis(1_800_000_000_000 + seq).unwrap();
    match format!("@seq={seq};t={t};{rest}")
        .parse::<ServerMessage>()
        .unwrap()
        .line
    {
        ServerLine::Event(e) => e,
        other => panic!("{other:?}"),
    }
}

/// Stores events for `conv` as the sync engine would, and tells the
/// account's subscribers, as its task does.
fn store_events(account: &Account, conv: &str, id: &str, events: &[Event]) {
    let shared = account.shared();
    let conv: Conv = conv.parse().unwrap();
    let account_id = shared.id;
    let ((), changes) = shared
        .store
        .write(|tx| {
            let mut row = tx.conv_or_create(account_id, &conv)?;
            tx.learn_id(&mut row, &id.parse().unwrap(), None)?;
            tx.set_joined(&mut row, true)?;
            for e in events {
                tx.store_event(&row, e)?;
            }
            Ok(())
        })
        .unwrap();
    shared.publish(Batch {
        reload: false,
        changes,
        events: Vec::new(),
    });
}

fn guest() -> Account {
    let client = Client::open_in_memory(ClientOptions::default()).unwrap();
    client.add_guest(SERVER, "sam").unwrap()
}

#[tokio::test]
async fn invalid_input_is_refused() {
    let client = Client::open_in_memory(ClientOptions::default()).unwrap();
    assert!(matches!(
        client.add_guest("bad host!", "sam"),
        Err(ClientError::Invalid(_))
    ));
    assert!(matches!(
        client.add_guest(SERVER, "not a name"),
        Err(ClientError::Invalid(_))
    ));
    assert!(matches!(
        client.accept_fingerprint(SERVER, "sha256:nothex"),
        Err(ClientError::Invalid(_))
    ));
    let sam = client.add_guest(SERVER, "sam").unwrap();
    assert!(matches!(
        sam.conversation("general"),
        Err(ClientError::Invalid(_))
    ));
    assert!(matches!(
        sam.join("general").await,
        Err(ClientError::Invalid(_))
    ));
    // The same account is the same handle.
    let again = client.add_guest(SERVER, "sam").unwrap();
    assert!(Arc::ptr_eq(sam.shared(), again.shared()));
    assert_eq!(client.accounts().unwrap().len(), 1);
    assert_eq!(
        client.account(SERVER, "~sam").unwrap().unwrap().id(),
        sam.id()
    );
}

#[tokio::test]
async fn offline_sends_wait_in_the_outbox() {
    let sam = guest();
    let general = sam.conversation("#general").unwrap();
    // A room never joined has no id to bind a message to (7.6).
    assert_eq!(
        general.send("hi").await.unwrap_err(),
        ClientError::NotJoined("#general".into())
    );
    store_events(
        &sam,
        "#general",
        "k1",
        &[event(1, "from=~sam;id=k1 JOIN #general")],
    );
    let events = sam.subscribe();
    let entry = general.send("hi\nthere").await.unwrap();
    assert_eq!(entry.status, OutboxStatus::Queued);
    assert_eq!(entry.text, "hi\nthere");
    assert_eq!(entry.conversation, "#general");
    match events.next().await.unwrap() {
        AccountEvent::Outbox { entry: e } => assert_eq!(e, entry),
        other => panic!("{other:?}"),
    }
    assert_eq!(sam.outbox().unwrap(), std::slice::from_ref(&entry));
    // Blank text is refused (5.3).
    assert!(matches!(
        general.send(" \t").await,
        Err(ClientError::Invalid(_))
    ));
    // Things that need a server say so.
    assert_eq!(general.load_older().await, Err(ClientError::NotConnected));
    assert_eq!(
        sam.join("#dev").await.unwrap_err(),
        ClientError::NotConnected
    );
    assert_eq!(sam.wait_synced().await, Err(ClientError::NotConnected));
    // A guest that is offline is in no room: parting only stops the room
    // being joined again.
    let rooms = |a: &Account| a.shared().store.rejoin_rooms(a.id()).unwrap();
    sam.shared()
        .store
        .set_rejoin(sam.id(), &"#general".parse().unwrap(), true)
        .unwrap();
    sam.part("#general", "").await.unwrap();
    assert!(rooms(&sam).is_empty());
    assert!(!general.info().unwrap().unwrap().joined);
    // The read marker moves in the cache.
    general.mark_read(1).await.unwrap();
    assert_eq!(general.info().unwrap().unwrap().read, 1);
    // Removing an outbox entry.
    sam.remove_outbox(entry.id).unwrap();
    assert!(sam.outbox().unwrap().is_empty());
}

#[tokio::test]
async fn the_timeline_reports_inserts_updates_and_resets() {
    let sam = guest();
    let general = sam.conversation("#general").unwrap();
    let timeline = general.timeline(3).unwrap();
    assert!(timeline.items().is_empty());
    let next = || async {
        tokio::time::timeout(Duration::from_secs(5), timeline.next())
            .await
            .expect("diffs")
            .expect("not closed")
    };

    // The conversation appears; its messages are inserted.
    store_events(
        &sam,
        "#general",
        "k1",
        &[
            event(1, "from=~ann;id=k1 JOIN #general"),
            event(3, "from=~ann MSG #general three"),
        ],
    );
    let diffs = next().await;
    assert_eq!(diffs.len(), 2);
    assert!(matches!(&diffs[1], TimelineDiff::Insert { index: 1, item } if item.seq == 3));
    // An older one goes in its place.
    store_events(
        &sam,
        "#general",
        "k1",
        &[event(2, "from=~ann MSG #general two")],
    );
    let diffs = next().await;
    assert!(
        matches!(&diffs[..], [TimelineDiff::Insert { index: 1, item }] if item.text.as_deref() == Some("two")),
        "{diffs:?}"
    );
    // An edit and a reaction update their target, and are not items.
    store_events(
        &sam,
        "#general",
        "k1",
        &[
            event(4, "from=~ann;edit=3 MSG #general THREE"),
            event(5, "from=~sam;react=3 MSG #general 👍"),
        ],
    );
    let diffs = next().await;
    let TimelineDiff::Update { index: 2, item } = diffs.last().unwrap() else {
        panic!("{diffs:?}")
    };
    assert_eq!(item.text.as_deref(), Some("THREE"));
    assert!(item.edited);
    assert_eq!(item.reactions.len(), 1);
    assert!(item.reactions[0].mine);
    assert_eq!(timeline.items().len(), 3);
    assert_eq!(
        timeline.items(),
        general.messages(None, 10).unwrap().messages
    );

    // A new id discards the history (7.1): a reset.
    let shared = sam.shared();
    let account = shared.id;
    let ((), changes) = shared
        .store
        .write(|tx| {
            let mut row = tx
                .conv_by_name(account, &"#general".parse().unwrap())?
                .unwrap();
            tx.discard(&mut row, Some("k2".parse().unwrap()))?;
            Ok(())
        })
        .unwrap();
    shared.publish(Batch {
        reload: false,
        changes,
        events: Vec::new(),
    });
    let diffs = next().await;
    assert!(diffs.contains(&TimelineDiff::Reset { items: Vec::new() }));
    assert!(timeline.items().is_empty());
}

#[tokio::test]
async fn the_timeline_pages_back_through_the_cache() {
    let sam = guest();
    let general = sam.conversation("#general").unwrap();
    let events: Vec<Event> = (1..=10)
        .map(|n| event(n, &format!("from=~ann MSG #general m{n}")))
        .collect();
    store_events(&sam, "#general", "k1", &events);
    let timeline = general.timeline(4).unwrap();
    let seqs = |t: &Timeline| t.items().iter().map(|m| m.seq).collect::<Vec<_>>();
    assert_eq!(seqs(&timeline), [7, 8, 9, 10]);
    // An item below the window is not shown.
    assert!(!timeline.paginate_back(4).await.unwrap());
    let diffs = timeline.next().await.unwrap();
    assert_eq!(diffs.len(), 4);
    assert_eq!(seqs(&timeline), [3, 4, 5, 6, 7, 8, 9, 10]);
    // The cache runs out; offline, nothing more comes.
    assert!(timeline.paginate_back(4).await.unwrap());
    assert_eq!(seqs(&timeline), (1..=10).collect::<Vec<_>>());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_timeline_loses_nothing_when_next_is_dropped() {
    // A UI selects over the timeline and other things; a dropped next()
    // must not lose the batch it was applying. Regression: it did.
    let sam = guest();
    let general = sam.conversation("#general").unwrap();
    let timeline = general.timeline(1000).unwrap();
    let mut items = timeline.items();
    let apply = |items: &mut Vec<Message>, diffs: Vec<TimelineDiff>| {
        for diff in diffs {
            match diff {
                TimelineDiff::Insert { index, item } => items.insert(index as usize, item),
                TimelineDiff::Update { index, item } => items[index as usize] = item,
                TimelineDiff::Remove { index } => {
                    items.remove(index as usize);
                }
                TimelineDiff::Reset { items: all } => *items = all,
            }
        }
    };
    for n in 1..=300u64 {
        store_events(
            &sam,
            "#general",
            "k1",
            &[event(n, &format!("from=~ann MSG #general m{n}"))],
        );
        // Start next() and drop it at once, sometimes mid-apply. What it
        // did return counts.
        if let Ok(Some(diffs)) = tokio::time::timeout(Duration::ZERO, timeline.next()).await {
            apply(&mut items, diffs);
        }
        if n % 7 == 0 {
            tokio::task::yield_now().await;
        }
    }
    while items.len() < 300 {
        let diffs = tokio::time::timeout(Duration::from_secs(5), timeline.next())
            .await
            .expect("every change arrives")
            .unwrap();
        apply(&mut items, diffs);
    }
    assert_eq!(items, timeline.items());
    assert_eq!(items, all_messages(&general));
}

/// Every message of a conversation in the cache, page by page.
fn all_messages(conv: &Conversation) -> Vec<Message> {
    let mut out: Vec<Message> = Vec::new();
    let mut cursor = None;
    loop {
        let page = conv.messages(cursor, MAX_PAGE).unwrap();
        let mut older = page.messages;
        older.append(&mut out);
        out = older;
        match page.older {
            Some(c) => cursor = Some(c),
            None => return out,
        }
    }
}

#[tokio::test]
async fn writes_from_another_process_reach_timelines() {
    // The app and its notification extension share one cache file.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    let app = Client::open(&path, ClientOptions::default()).unwrap();
    let extension = Client::open(&path, ClientOptions::default()).unwrap();
    let sam = app.add_guest(SERVER, "sam").unwrap();
    let general = sam.conversation("#general").unwrap();
    store_events(
        &sam,
        "#general",
        "k1",
        &[event(1, "from=~sam;id=k1 JOIN #general")],
    );
    // The app's own writes do not count.
    assert!(!app.check_for_external_changes().unwrap());

    let timeline = general.timeline(50).unwrap();
    assert_eq!(timeline.items().len(), 1);
    let events = sam.subscribe();

    // The extension stores a message. The app hears nothing of it...
    let other = extension.add_guest(SERVER, "sam").unwrap();
    store_events(
        &other,
        "#general",
        "k1",
        &[event(2, "from=~bob MSG #general hi")],
    );
    assert_eq!(general.messages(None, 50).unwrap().messages.len(), 2);
    // ...until it checks.
    assert!(app.check_for_external_changes().unwrap());
    assert!(!app.check_for_external_changes().unwrap());
    assert_eq!(events.next().await, Some(AccountEvent::CacheChanged));
    match timeline.next().await.unwrap().as_slice() {
        [TimelineDiff::Reset { items }] => {
            assert_eq!(items.len(), 2);
            assert_eq!(items[1].text.as_deref(), Some("hi"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(timeline.items().len(), 2);

    // A refresh by hand does the same for one timeline.
    store_events(
        &other,
        "#general",
        "k1",
        &[event(3, "from=~bob MSG #general again")],
    );
    timeline.refresh().await.unwrap();
    match timeline.next().await.unwrap().as_slice() {
        [TimelineDiff::Reset { items }] => assert_eq!(items.len(), 3),
        other => panic!("{other:?}"),
    }
}

#[test]
fn errors_carry_kinds_to_localize() {
    use crate::conn::{CloseReason, Error};
    let e = ClientError::from_conn("x", &Error::Timeout);
    assert!(matches!(
        e,
        ClientError::Connection {
            kind: ConnectionErrorKind::Timeout,
            permanent: false,
            ..
        }
    ));
    let e = ClientError::from_conn(
        "x",
        &Error::KeyExchange(rustls::Error::General("no group".into())),
    );
    assert!(matches!(
        e,
        ClientError::Connection {
            kind: ConnectionErrorKind::KeyExchange,
            permanent: true,
            ..
        }
    ));
    let e = ClientError::from_conn("x", &Error::Closed(CloseReason::PingTimeout));
    assert!(matches!(
        e,
        ClientError::Connection {
            kind: ConnectionErrorKind::Closed,
            ..
        }
    ));
    assert_eq!(
        DisconnectKind::of(&CloseReason::Server { bye: None }),
        DisconnectKind::Server
    );

    // Outbox failures: "room changed" and "dropped" differ by kind.
    let store = Store::open_in_memory().unwrap();
    let server = parse_server(SERVER).unwrap();
    let account = store.account(&server, &"~sam".parse().unwrap()).unwrap();
    let conv: Conv = "#general".parse().unwrap();
    for (why, kind, maybe) in [
        (FailReason::RoomChanged, FailKind::RoomChanged, false),
        (FailReason::Dropped, FailKind::Dropped, false),
        (FailReason::Unconfirmed, FailKind::Unconfirmed, true),
        (
            FailReason::Rejected(risala_proto::error::ErrorCode::Forbidden),
            FailKind::Rejected,
            false,
        ),
    ] {
        let (id, _) = store
            .write(|tx| {
                let id = tx.queue(account, &conv, None, &Draft::text("hi"), Timestamp::MIN)?;
                tx.outbox_failed(id, why.clone())?;
                Ok(id)
            })
            .unwrap();
        let entry = OutboxEntry::from(store.outbox_item(id).unwrap().unwrap());
        match entry.status {
            OutboxStatus::Failed {
                kind: k,
                maybe_sent,
                ..
            } => assert_eq!((k, maybe_sent), (kind, maybe), "{why:?}"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn messages_say_whether_they_are_the_accounts_own() {
    // A guest signed in as ~sam2 (4.2): its messages are its own, and
    // ~sam's are someone else's.
    let sam = guest();
    let shared = sam.shared();
    let conv: Conv = "#general".parse().unwrap();
    let account = shared.id;
    shared
        .store
        .write(|tx| {
            tx.signed_in_as(&"~sam2".parse().unwrap());
            let mut row = tx.conv_or_create(account, &conv)?;
            tx.learn_id(&mut row, &"k1".parse().unwrap(), None)?;
            tx.store_event(&row, &event(1, "from=~sam2 MSG #general mine"))?;
            tx.store_event(&row, &event(2, "from=~sam MSG #general theirs"))
        })
        .unwrap();
    let own: Vec<(String, bool)> = sam
        .conversation("#general")
        .unwrap()
        .messages(None, 10)
        .unwrap()
        .messages
        .into_iter()
        .map(|m| (m.text.unwrap(), m.own))
        .collect();
    assert_eq!(own, [("mine".into(), true), ("theirs".into(), false)]);
}

#[test]
fn conversation_info_has_the_topic_and_settings() {
    let sam = guest();
    let shared = sam.shared();
    let conv: Conv = "#general".parse().unwrap();
    let account = shared.id;
    let snapshot = |line: &str| match line.parse::<ServerMessage>().unwrap().line {
        ServerLine::Event(e) => e,
        other => panic!("{other:?}"),
    };
    shared
        .store
        .write(|tx| {
            let mut row = tx.conv_or_create(account, &conv)?;
            tx.learn_id(&mut row, &"k1".parse().unwrap(), Some(1))?;
            tx.apply_snapshot(&row, &snapshot("SET #general topic Plans\\nfor now"))?;
            tx.apply_snapshot(&row, &snapshot("SET #general guests write"))?;
            tx.apply_snapshot(&row, &snapshot("SET #general public yes"))
        })
        .unwrap();
    let info = sam
        .conversation("#general")
        .unwrap()
        .info()
        .unwrap()
        .unwrap();
    assert_eq!(info.topic, "Plans\nfor now");
    let settings: Vec<(&str, &str)> = info
        .settings
        .iter()
        .map(|s| (s.key.as_str(), s.value.as_str()))
        .collect();
    assert_eq!(
        settings,
        [
            ("guests", "write"),
            ("public", "yes"),
            ("topic", "Plans\nfor now")
        ]
    );
}

#[tokio::test]
async fn the_timeline_shows_the_outbox_until_sent() {
    let sam = guest();
    let general = sam.conversation("#general").unwrap();
    store_events(
        &sam,
        "#general",
        "k1",
        &[event(1, "from=~sam;id=k1 JOIN #general")],
    );
    let timeline = general.timeline(50).unwrap();
    let next = || async {
        tokio::time::timeout(Duration::from_secs(5), timeline.next())
            .await
            .expect("diffs")
            .expect("not closed")
    };

    // Queued offline: a pending item after the stored ones.
    let entry = general.send("hello").await.unwrap();
    match next().await.as_slice() {
        [TimelineDiff::Insert { index: 1, item }] => {
            assert_eq!(item.seq, 0);
            assert!(item.own);
            assert_eq!(item.text.as_deref(), Some("hello"));
            assert_eq!(item.outbox.as_ref().unwrap().status, OutboxStatus::Queued);
        }
        other => panic!("{other:?}"),
    }

    // Sent: its event goes in among the stored ones, and the pending item
    // goes.
    let shared = sam.shared().clone();
    let (account, conv) = (shared.id, "#general".parse::<Conv>().unwrap());
    let ((), changes) = shared
        .store
        .write(|tx| {
            let row = tx.conv_by_name(account, &conv)?.unwrap();
            tx.store_event(&row, &event(2, "from=~sam MSG #general hello"))?;
            tx.outbox_sent(crate::store::OutboxId(entry.id), Seq::new(2).unwrap())
        })
        .unwrap();
    shared.publish(Batch {
        reload: false,
        changes,
        events: Vec::new(),
    });
    match next().await.as_slice() {
        [
            TimelineDiff::Insert { index: 1, item },
            TimelineDiff::Remove { index: 2 },
        ] => assert_eq!((item.seq, item.outbox.is_none()), (2, true)),
        other => panic!("{other:?}"),
    }

    // Failed: updated in place, until the app removes it.
    let entry = general.send("again").await.unwrap();
    assert!(matches!(
        next().await.as_slice(),
        [TimelineDiff::Insert { index: 2, .. }]
    ));
    let ((), changes) = shared
        .store
        .write(|tx| tx.outbox_failed(crate::store::OutboxId(entry.id), FailReason::Unconfirmed))
        .unwrap();
    shared.publish(Batch {
        reload: false,
        changes,
        events: Vec::new(),
    });
    match next().await.as_slice() {
        [TimelineDiff::Update { index: 2, item }] => assert!(matches!(
            item.outbox.as_ref().unwrap().status,
            OutboxStatus::Failed {
                kind: FailKind::Unconfirmed,
                ..
            }
        )),
        other => panic!("{other:?}"),
    }
    assert_eq!(timeline.items().len(), 3);
    sam.remove_outbox(entry.id).unwrap();
    assert!(matches!(
        next().await.as_slice(),
        [TimelineDiff::Remove { index: 2 }]
    ));
    assert_eq!(timeline.items().len(), 2);
}

#[test]
fn reads_come_in_bounded_pages() {
    let sam = guest();
    let events: Vec<Event> = (1..=7)
        .map(|n| event(n, &format!("from=~ann MSG #general m{n}")))
        .collect();
    store_events(&sam, "#general", "k1", &events);
    store_events(&sam, "#a", "k2", &[]);
    store_events(&sam, "#b", "k3", &[]);
    let general = sam.conversation("#general").unwrap();

    // Messages, newest page first, then older ones by cursor.
    let mut seqs = Vec::new();
    let mut cursor = None;
    loop {
        let page = general.messages(cursor, 3).unwrap();
        assert!(page.messages.len() <= 3);
        let mut these: Vec<u64> = page.messages.iter().map(|m| m.seq).collect();
        these.append(&mut seqs);
        seqs = these;
        match page.older {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seqs, [1, 2, 3, 4, 5, 6, 7]);
    // A full last page says there is nothing older.
    let page = general.messages(None, 7).unwrap();
    assert_eq!((page.messages.len(), page.older), (7, None));
    assert!(matches!(
        general.messages(Some("bad".into()), 3),
        Err(ClientError::Invalid(_))
    ));

    // Conversations, by name.
    let first = sam.conversations(None, 2).unwrap();
    let names: Vec<&str> = first
        .conversations
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(names, ["#a", "#b"]);
    let rest = sam.conversations(first.next, 2).unwrap();
    let names: Vec<&str> = rest.conversations.iter().map(|c| c.name.as_str()).collect();
    assert_eq!((names, rest.next), (vec!["#general"], None));

    // The library caps what one page may ask for.
    let many: Vec<Event> = (8..=8 + u64::from(MAX_PAGE))
        .map(|n| event(n, &format!("from=~ann MSG #general m{n}")))
        .collect();
    store_events(&sam, "#general", "k1", &many);
    let page = general.messages(None, u32::MAX).unwrap();
    assert_eq!(page.messages.len(), MAX_PAGE as usize);
    assert!(page.older.is_some());
    assert_eq!(
        general.messages(None, 0).unwrap().messages.len(),
        DEFAULT_PAGE as usize
    );
}
