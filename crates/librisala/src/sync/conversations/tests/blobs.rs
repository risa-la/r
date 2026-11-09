//! Commits, GroupInfos and Welcomes too long for a line go as blobs (2.3,
//! 12.12), against the in-memory server, with the line limit lowered so
//! that a two-device group passes it. `client/conversations/server_tests.rs`
//! runs the same paths against `risalad`, past the real limit.

use super::*;

/// A line limit that a commit adding a device, and a Welcome, pass, and a
/// short message does not.
const LIMIT: usize = 8 * 1024;

fn config(limit: usize) -> Config {
    Config {
        self_conversation: false,
        line_limit: limit,
        ..Config::immediate()
    }
}

/// How many BLOBs each kind of connection of device `d` sent.
fn blob_commands(net: &Net, d: usize, slot: Slot) -> usize {
    net.server
        .log
        .iter()
        .filter(|((dd, s), verb)| *dd == d && *s == slot && verb == "BLOB")
        .count()
}

/// A private room's commit that adds a device, and the Welcome that
/// carries its tree, go as blobs stored over the anonymous connection; the
/// device joins, and messages that fit go inline as before.
#[test]
fn a_private_room_past_the_line_limit_goes_by_blobs() {
    let mut net = Net::new();
    let alice = net.device_with("alice", "alice@example.org", config(LIMIT));
    let bob = net.device_with("bob", "bob@example.net", config(LIMIT));
    net.connect(alice);
    net.connect(bob);
    let a = net
        .job(
            alice,
            Job::PrivateRoom {
                name: "big".into(),
                members: vec!["bob@example.net".parse().unwrap()],
            },
        )
        .unwrap();
    net.tick();
    let b = net.same_conv(bob, alice, a).expect("bob joined");
    // The commit and the Welcome, on the anonymous connection, with the
    // room's box and token.
    assert!(
        net.server.blob_commands >= 2,
        "{}",
        net.server.blob_commands
    );
    assert!(blob_commands(&net, alice, Slot::Anonymous(0)) >= 2);
    assert_eq!(blob_commands(&net, alice, Slot::SignedIn), 0);

    net.say(alice, a, "hello");
    net.say(bob, b, "hi");
    assert_eq!(
        net.texts(bob, b),
        [
            ("alice@example.org".to_owned(), "hello".to_owned()),
            ("bob@example.net".to_owned(), "hi".to_owned()),
        ]
    );
    assert_eq!(net.texts(alice, a), net.texts(bob, b));
    assert_eq!(net.epoch(alice, a), net.epoch(bob, b));
}

/// Posts wait, as made and in order, while their blobs are being stored:
/// their rows stay sent, they are not made again, and BLOB is not sent
/// again. Here messages pass a limit lowered below their length.
#[test]
fn posts_wait_for_their_blobs_in_order() {
    let mut net = Net::new();
    let alice = net.device_with("alice", "alice@example.org", config(LIMIT));
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let a = net
        .job(
            alice,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let b = net.same_conv(bob, alice, a).unwrap();
    net.devices[alice].config.line_limit = 2 * 1024;
    net.restart(alice);
    let before = blob_commands(&net, alice, Slot::Anonymous(0));

    // No PUT lands for now.
    net.hold_puts
        .store(true, std::sync::atomic::Ordering::SeqCst);
    net.say(alice, a, "one");
    net.say(alice, a, "two");
    for _ in 0..3 {
        net.advance(1_000);
    }
    assert_eq!(blob_commands(&net, alice, Slot::Anonymous(0)), before + 1);
    assert!(net.texts(bob, b).is_empty());
    let account = net.devices[alice].account;
    let rows: Vec<_> = net
        .write(alice, |tx| Ok(tx.account_outbox(account)?))
        .into_iter()
        .filter(|r| r.conv == a && r.kind == OutboxKind::Message)
        .collect();
    assert_eq!(rows.len(), 2);
    // The first was made once and waits for its blob; the second waits
    // with it, made in the same batch, or behind it, not made yet.
    assert_eq!((rows[0].state, rows[0].attempts), (OutboxState::Sent, 1));
    assert!(rows.iter().all(|r| r.attempts <= 1), "made once");

    // The PUTs land: the messages, in order.
    net.hold_puts
        .store(false, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..3 {
        net.tick();
    }
    assert_eq!(
        net.texts(bob, b),
        [
            ("alice@example.org".to_owned(), "one".to_owned()),
            ("alice@example.org".to_owned(), "two".to_owned()),
        ]
    );
    assert_eq!(blob_commands(&net, alice, Slot::Anonymous(0)), before + 2);
}

/// A public room's commit and its GroupInfo, too long for a line, are
/// stored over the anonymous connection, and posted on the signed-in one
/// (12.6).
#[test]
fn a_public_rooms_commit_and_groupinfo_go_by_blobs() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let room: Room = "#general".parse().unwrap();
    let a = net
        .job(alice, Job::PublicRoom { room: room.clone() })
        .expect("created");
    // From now on, Alice's lines are short.
    net.devices[alice].config.line_limit = 4 * 1024;
    net.restart(alice);
    let b = net
        .job_over(
            bob,
            Job::JoinPublic {
                room,
                new_group: false,
            },
            5,
        )
        .expect("joined");
    // The commit, its GroupInfo, and the Welcome for Bob's join.
    assert_eq!(blob_commands(&net, alice, Slot::Anonymous(0)), 3);
    assert_eq!(blob_commands(&net, alice, Slot::SignedIn), 0);
    assert_eq!(net.server.room("#general"), Some((2, 1)));
    assert_eq!(net.epoch(alice, a), 1);
    assert_eq!(net.epoch(bob, b), 1);
}

/// A device's own post that went as a blob, and comes back as a blob-ref,
/// is applied from its outbox, not fetched back (12.12).
#[test]
fn an_own_post_in_a_blob_is_not_fetched_back() {
    let mut net = Net::new();
    let alice = net.device_with("alice", "alice@example.org", config(LIMIT));
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let a = net
        .job(
            alice,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let b = net.same_conv(bob, alice, a).unwrap();
    // From now on the server sends posts as blob-refs, and Alice's
    // messages pass her line limit.
    net.server.blob_posts = true;
    net.devices[alice].config.line_limit = 2 * 1024;
    net.restart(alice);
    net.devices[alice].hooks.fetched.lock().unwrap().clear();
    let before = blob_commands(&net, alice, Slot::Anonymous(0));
    net.say(alice, a, "mine");
    for _ in 0..3 {
        net.tick();
    }
    assert_eq!(blob_commands(&net, alice, Slot::Anonymous(0)), before + 1);
    assert_eq!(
        net.texts(bob, b),
        [("alice@example.org".to_owned(), "mine".to_owned())]
    );
    assert!(!net.devices[bob].hooks.fetched.lock().unwrap().is_empty());
    assert_eq!(*net.devices[alice].hooks.fetched.lock().unwrap(), []);
    // Applied in order: nothing of it is pending in Alice's outbox.
    let pending = net.write(alice, |tx| Ok(tx.pending_outbox(a)?));
    assert!(
        pending.iter().all(|r| r.kind != OutboxKind::Message),
        "{pending:?}"
    );
}
