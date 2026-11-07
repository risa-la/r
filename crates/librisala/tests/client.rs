//! The client against a real server (`risala_server::testing`): signing
//! in as a guest, joining, sending and receiving, trust on first use,
//! reconnects, and reading offline.

mod common;

use std::time::Duration;

use common::*;
use librisala::client::{
    AccountEvent, Client, ClientError, ConnectionState, EventKind, Notice, OutboxStatus,
    TimelineDiff,
};
use risala_server::testing::{Proxy, TestServer};

/// Waits until the account's conversation has `text` from someone else.
async fn wait_for_text(conv: &librisala::client::Conversation, text: &str) {
    within(&format!("waiting for {text:?}"), async {
        loop {
            let found = conv
                .messages(None, 200)
                .unwrap()
                .iter()
                .any(|m| m.text.as_deref() == Some(text));
            if found {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn trust_on_first_use() {
    let server = TestServer::start().await;
    let client = Client::open_in_memory(options(50)).unwrap();
    let addr = addr_of(server.addr());
    let fp = server.fingerprint().to_string();

    // First use: the fingerprint comes with the error (2.2).
    let err = client.probe(&addr).await.unwrap_err();
    match &err {
        ClientError::UnknownCertificate { fingerprint, .. } => assert_eq!(*fingerprint, fp),
        other => panic!("{other:?}"),
    }
    assert!(err.is_trust());
    let sam = client.add_guest(&addr, "sam").unwrap();
    assert_eq!(sam.connect().await.unwrap_err(), err);
    assert!(matches!(sam.state(), ConnectionState::Failed { .. }));

    client.accept_fingerprint(&addr, &fp).unwrap();
    let hello = client.probe(&addr).await.unwrap();
    assert_eq!(hello.fingerprint, fp);
    assert_eq!(hello.host, "localhost");
    assert_eq!(sam.connect().await.unwrap(), "~sam");
    sam.disconnect().await;
    assert_eq!(sam.state(), ConnectionState::Offline);

    // A different pin is refused until the user forgets the record.
    client.forget_trust(&addr).unwrap();
    let other = "sha256:".to_owned() + &"0".repeat(64);
    client.accept_fingerprint(&addr, &other).unwrap();
    assert!(client.accept_fingerprint(&addr, &fp).is_err());
    match sam.connect().await.unwrap_err() {
        ClientError::CertificateMismatch {
            recorded,
            presented,
            ..
        } => {
            assert_eq!(recorded, other);
            assert_eq!(presented, fp);
        }
        other => panic!("{other:?}"),
    }
    server.stop().await;
}

#[tokio::test]
async fn guest_joins_sends_and_receives() {
    let server = TestServer::builder().room("#general").start().await;
    let (client, addr) = trusting_client(&server, server.addr(), 50);
    let mut ann = guest_in(&server, "ann", "#general").await;
    post(&mut ann, "#general", "before sam came").await;

    let sam = client.add_guest(&addr, "sam").unwrap();
    assert_eq!(sam.uid(), "~sam");
    assert!(sam.is_guest());
    within("connect", sam.connect()).await.unwrap();
    let rooms = sam.list_rooms(None, None).await.unwrap();
    assert_eq!(rooms.rooms.len(), 1);
    assert_eq!(rooms.rooms[0].room, "#general");
    assert!(!rooms.more);

    let general = sam.conversation("#general").unwrap();
    let timeline = general.timeline(20).unwrap();
    assert!(timeline.items().is_empty());
    within("join", sam.join("#general")).await.unwrap();
    within("sync", sam.wait_synced()).await.unwrap();
    let info = general.info().unwrap().unwrap();
    assert!(info.joined && info.caught_up, "{info:?}");
    assert_eq!(info.sync_point, info.head);

    // History arrived: ann's JOIN, her message, sam's JOIN.
    let texts: Vec<_> = general
        .messages(None, 50)
        .unwrap()
        .into_iter()
        .map(|m| (m.from, m.kind, m.text))
        .collect();
    assert_eq!(
        texts,
        [
            ("~ann".into(), EventKind::Join, None),
            (
                "~ann".into(),
                EventKind::Message,
                Some("before sam came".into())
            ),
            ("~sam".into(), EventKind::Join, None),
        ]
    );

    // Receiving.
    post(&mut ann, "#general", "hi sam; welcome").await;
    wait_for_text(&general, "hi sam; welcome").await;

    // Sending, with text that needs escaping (3.4).
    let entry = general.send("hello ann\nsecond line").await.unwrap();
    let entry = within("sent", sam.wait_outbox(entry.id)).await.unwrap();
    let OutboxStatus::Sent { seq } = entry.status else {
        panic!("{entry:?}")
    };
    loop {
        let line = ann.expect_line().await.unwrap();
        if line.contains("from=~sam") && line.contains(" MSG ") {
            assert!(line.starts_with(&format!("@seq={seq};")), "{line}");
            assert!(
                line.ends_with("MSG #general hello ann\\nsecond line"),
                "{line}"
            );
            break;
        }
    }
    let mine = general.messages(None, 50).unwrap().pop().unwrap();
    assert_eq!(mine.seq, seq);
    assert_eq!(mine.text.as_deref(), Some("hello ann\nsecond line"));

    // The timeline saw all of it, in order. The message may show as
    // pending in the outbox first.
    let mut items = timeline.items();
    while items.len() < 5 || items.iter().any(|m| m.outbox.is_some()) {
        let diffs = within("timeline", timeline.next()).await.unwrap();
        for diff in diffs {
            match diff {
                TimelineDiff::Insert { index, item } => items.insert(index as usize, item),
                TimelineDiff::Update { index, item } => items[index as usize] = item,
                TimelineDiff::Remove { index } => {
                    items.remove(index as usize);
                }
                TimelineDiff::Reset { items: all } => items = all,
            }
        }
    }
    assert_eq!(items, general.messages(None, 50).unwrap());
    assert_eq!(items, timeline.items());

    // Parting keeps the history.
    sam.part("#general", "bye").await.unwrap();
    within("sync", sam.wait_synced()).await.unwrap();
    let info = general.info().unwrap().unwrap();
    assert!(!info.joined);
    assert_eq!(general.messages(None, 50).unwrap().len(), 6);
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn reads_work_offline_after_the_server_stops() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    let server = TestServer::builder().room("#general").start().await;
    let mut ann = guest_in(&server, "ann", "#general").await;
    for i in 0..12 {
        post(&mut ann, "#general", &format!("m{i}")).await;
    }
    {
        let client = Client::open(&path, options(5)).unwrap();
        let addr = addr_of(server.addr());
        client
            .accept_fingerprint(&addr, &server.fingerprint().to_string())
            .unwrap();
        let sam = client.add_guest(&addr, "sam").unwrap();
        sam.connect().await.unwrap();
        sam.join("#general").await.unwrap();
        within("sync", sam.wait_synced()).await.unwrap();
        // A message written while offline waits in the outbox.
        server.stop().await;
        within("offline", async {
            while sam.state().is_online() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let general = sam.conversation("#general").unwrap();
        let queued = general.send("written offline").await.unwrap();
        assert_eq!(queued.status, OutboxStatus::Queued);
        sam.disconnect().await;
    }

    // Another process opens the same cache with no server at all.
    let client = Client::open(&path, options(5)).unwrap();
    let accounts = client.accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    let sam = &accounts[0];
    assert_eq!(sam.state(), ConnectionState::Offline);
    let convs = sam.conversations().unwrap();
    assert_eq!(convs.len(), 1);
    assert_eq!(convs[0].name, "#general");
    assert!(convs[0].caught_up);
    let general = sam.conversation("#general").unwrap();
    let texts: Vec<String> = general
        .messages(None, 100)
        .unwrap()
        .into_iter()
        .filter(|m| m.kind == EventKind::Message)
        .filter_map(|m| m.text)
        .collect();
    let expected: Vec<String> = (0..12).map(|i| format!("m{i}")).collect();
    assert_eq!(texts, expected);
    // Paging back through the cache.
    let newest = general.messages(None, 4).unwrap();
    let older = general.messages(Some(newest[0].seq), 4).unwrap();
    assert_eq!(older.last().unwrap().seq + 1, newest[0].seq);
    assert_eq!(general.export().unwrap().len(), 14);
    let outbox = general.outbox().unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].text, "written offline");
    assert_eq!(outbox[0].status, OutboxStatus::Queued);
    // Commands that need a server say so.
    assert_eq!(
        sam.join("#general").await.unwrap_err(),
        ClientError::NotConnected
    );
    assert!(sam.list_rooms(None, None).await.is_err());
}

/// The events by `uid` in `room` on the server, as verbs.
async fn verbs_of(server: &TestServer, room: &str, uid: &str) -> Vec<String> {
    server_history(server, room)
        .await
        .iter()
        .filter(|l| l.contains(&format!(";from={uid};")) || l.contains(&format!(";from={uid} ")))
        .map(|l| l.split(' ').nth(1).unwrap().to_owned())
        .collect()
}

/// Waits until the account has gone offline and come back.
async fn reconnected(events: &librisala::client::AccountEvents) {
    within("reconnect", async {
        let mut down = false;
        loop {
            match events.next().await.unwrap() {
                AccountEvent::State {
                    state: ConnectionState::Disconnected { .. },
                } => down = true,
                AccountEvent::State {
                    state: ConnectionState::Online { .. },
                } if down => return,
                _ => {}
            }
        }
    })
    .await;
}

#[tokio::test]
async fn a_guest_resumes_its_session_after_a_reconnect() {
    let server = TestServer::builder().room("#a").room("#b").start().await;
    let proxy = Proxy::start(server.addr()).await;
    let (client, addr) = trusting_client(&server, proxy.addr(), 50);
    let sam = client.add_guest(&addr, "sam").unwrap();
    let events = sam.subscribe();
    sam.connect().await.unwrap();
    sam.join("#a").await.unwrap();
    sam.join("#b").await.unwrap();
    sam.part("#b", "").await.unwrap();
    within("sync", sam.wait_synced()).await.unwrap();

    proxy.cut();
    // Back online, still in #a and not #b (4.2).
    reconnected(&events).await;
    within("sync", sam.wait_synced()).await.unwrap();
    let a = sam.conversation("#a").unwrap().info().unwrap().unwrap();
    let b = sam.conversation("#b").unwrap().info().unwrap().unwrap();
    assert!(a.joined && !b.joined, "{a:?} {b:?}");
    // Live messages arrive again.
    let mut ann = guest_in(&server, "ann", "#a").await;
    post(&mut ann, "#a", "after the reconnect").await;
    wait_for_text(&sam.conversation("#a").unwrap(), "after the reconnect").await;
    // The session was resumed: nothing was recorded for the reconnect.
    assert_eq!(verbs_of(&server, "#a", "~sam").await, ["JOIN"]);
    assert_eq!(verbs_of(&server, "#b", "~sam").await, ["JOIN", "PART"]);
    // No Left notice for #a.
    let mut notices = Vec::new();
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(50), events.next()).await {
        if let AccountEvent::Notice { notice } = e {
            notices.push(notice);
        }
    }
    assert!(
        !notices
            .iter()
            .any(|n| matches!(n, Notice::Left { conversation } if conversation == "#a")),
        "{notices:?}"
    );
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn a_room_dropped_and_created_again_is_not_mixed() {
    let mut server = TestServer::builder().room("#a").start().await;
    let (client, addr) = trusting_client(&server, server.addr(), 50);
    let mut ann = guest_in(&server, "ann", "#a").await;
    for i in 0..5 {
        post(&mut ann, "#a", &format!("old {i}")).await;
    }
    drop(ann);
    let sam = client.add_guest(&addr, "sam").unwrap();
    sam.connect().await.unwrap();
    sam.join("#a").await.unwrap();
    within("sync", sam.wait_synced()).await.unwrap();
    let a = sam.conversation("#a").unwrap();
    let old_id = a.info().unwrap().unwrap().id.unwrap();
    sam.disconnect().await;
    // Written for the old room while offline.
    let stale = a.send("meant for the old room").await.unwrap();

    // The room is dropped and created again: a new id, seqs from 1 (10.4).
    server
        .restart_with(|config| {
            let db = rusqlite::Connection::open(config.database_path()).unwrap();
            db.pragma_update(None, "foreign_keys", "ON").unwrap();
            db.execute("DELETE FROM conversations WHERE room = '#a'", [])
                .unwrap();
        })
        .await;
    let mut bob = guest_in(&server, "bob", "#a").await;
    post(&mut bob, "#a", "new 0").await;

    sam.connect().await.unwrap();
    within("sync", sam.wait_synced()).await.unwrap();
    let info = a.info().unwrap().unwrap();
    assert_ne!(info.id.as_deref(), Some(old_id.as_str()));
    // Only the new room's events, the same as the server's.
    assert_eq!(a.export().unwrap(), server_history(&server, "#a").await);
    assert!(
        a.messages(None, 50).unwrap().iter().all(|m| !m
            .text
            .as_deref()
            .unwrap_or("")
            .starts_with("old"))
    );
    // The message written for the old room is not sent into the new one.
    let entry = within("outbox", sam.wait_outbox(stale.id)).await.unwrap();
    assert!(
        matches!(
            &entry.status,
            OutboxStatus::Failed {
                maybe_sent: false,
                ..
            }
        ),
        "{entry:?}"
    );
    client.shutdown().await;
    server.stop().await;
}

/// A connection cut while messages come and go: the guest resumes its
/// session, nothing is recorded for the cut, and the cache ends up with
/// exactly the server's events (4.2, 7.1).
#[tokio::test]
async fn a_cut_connection_resumes_without_losing_or_repeating_anything() {
    let server = TestServer::builder().room("#a").start().await;
    let proxy = Proxy::start(server.addr()).await;
    let (client, addr) = trusting_client(&server, proxy.addr(), 5);
    let mut ann = guest_in(&server, "ann", "#a").await;
    let sam = client.add_guest(&addr, "sam").unwrap();
    let events = sam.subscribe();
    sam.connect().await.unwrap();
    sam.join("#a").await.unwrap();
    within("sync", sam.wait_synced()).await.unwrap();
    let a = sam.conversation("#a").unwrap();

    for round in 0..3 {
        let sent = a.send(&format!("sam {round} before")).await.unwrap();
        within("sent", sam.wait_outbox(sent.id)).await.unwrap();
        proxy.cut();
        // While sam is away.
        for i in 0..7 {
            post(&mut ann, "#a", &format!("ann {round}.{i}")).await;
        }
        reconnected(&events).await;
        let sent = a.send(&format!("sam {round} after")).await.unwrap();
        let sent = within("sent", sam.wait_outbox(sent.id)).await.unwrap();
        assert!(matches!(sent.status, OutboxStatus::Sent { .. }), "{sent:?}");
    }
    within("sync", sam.wait_synced()).await.unwrap();
    within("the cache matching the server", async {
        while a.export().unwrap() != server_history(&server, "#a").await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let mut verbs = verbs_of(&server, "#a", "~sam").await;
    verbs.dedup();
    assert_eq!(verbs, ["JOIN", "MSG"]);
    assert_eq!(verbs_of(&server, "#a", "~sam").await.len(), 1 + 6);
    // Own messages are not unread; ann's 21 are.
    assert_eq!(a.info().unwrap().unwrap().unread, 21);
    client.shutdown().await;
    server.stop().await;
}

/// A later run of the app, on the same cache, resumes the session too: it
/// keeps the token in the cache.
#[tokio::test]
async fn a_new_run_of_the_app_resumes_the_session() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    let server = TestServer::builder().room("#a").start().await;
    let addr = addr_of(server.addr());
    for run in 0..3 {
        let client = Client::open(&path, options(50)).unwrap();
        client
            .accept_fingerprint(&addr, &server.fingerprint().to_string())
            .unwrap();
        let sam = match client.accounts().unwrap().pop() {
            Some(sam) => sam,
            None => client.add_guest(&addr, "sam").unwrap(),
        };
        assert_eq!(within("connect", sam.connect()).await.unwrap(), "~sam");
        if run == 0 {
            sam.join("#a").await.unwrap();
        }
        within("sync", sam.wait_synced()).await.unwrap();
        let a = sam.conversation("#a").unwrap();
        assert!(a.info().unwrap().unwrap().joined);
        let sent = a.send(&format!("run {run}")).await.unwrap();
        within("sent", sam.wait_outbox(sent.id)).await.unwrap();
        // Disconnecting sends QUIT; the session waits to be resumed.
        client.shutdown().await;
    }
    assert_eq!(
        verbs_of(&server, "#a", "~sam").await,
        ["JOIN", "MSG", "MSG", "MSG"]
    );
    server.stop().await;
}

/// Once the session has ended and someone else has the name, the guest
/// signs in under a numbered name, joins its rooms again, and its own
/// messages under that name are still not unread.
#[tokio::test]
async fn after_its_session_ends_a_guest_takes_a_numbered_name() {
    let server = TestServer::builder()
        .room("#a")
        .guest_resume(Duration::from_millis(100))
        .start()
        .await;
    let (client, addr) = trusting_client(&server, server.addr(), 50);
    let sam = client.add_guest(&addr, "sam").unwrap();
    sam.connect().await.unwrap();
    sam.join("#a").await.unwrap();
    within("sync", sam.wait_synced()).await.unwrap();
    sam.disconnect().await;
    within("the session ending", async {
        while verbs_of(&server, "#a", "~sam").await != ["JOIN", "PART"] {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    // Someone else takes the name.
    let mut other = guest_in(&server, "sam", "#a").await;
    post(&mut other, "#a", "I am the new sam").await;
    post(&mut other, "#a", "really").await;

    assert_eq!(within("connect", sam.connect()).await.unwrap(), "~sam2");
    within("sync", sam.wait_synced()).await.unwrap();
    let a = sam.conversation("#a").unwrap();
    assert!(a.info().unwrap().unwrap().joined);
    assert_eq!(verbs_of(&server, "#a", "~sam2").await, ["JOIN"]);
    let sent = a.send("I am sam, now sam2").await.unwrap();
    within("sent", sam.wait_outbox(sent.id)).await.unwrap();
    within("sync", sam.wait_synced()).await.unwrap();
    // The account is still ~sam, but its own messages are ~sam2's: only
    // the other sam's two are unread.
    assert_eq!(sam.uid(), "~sam");
    assert_eq!(a.info().unwrap().unwrap().unread, 2);
    client.shutdown().await;
    server.stop().await;
}
