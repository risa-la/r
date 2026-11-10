//! Leaving (6.1): a leaving device makes no commit but its leave commit; a
//! device with no other identity in the group leaves locally, once it has
//! removed its identity's other leaves; and in a direct conversation both
//! sides leave once one posts its SelfRemove.

use risala_mls::framing::ContentType;
use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls::prelude::GroupId;

use crate::store::keychecks::{CheckKind, KeyCheckRow};

use super::*;

const MINUTE: u64 = 60 * 1000;
const DAY: u64 = 24 * 60 * MINUTE;

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn posts(net: &Net, d: usize, conv: ConversationId, kind: ContentType) -> usize {
    let mailbox = net.devices[d].store.mailbox_rows(conv).unwrap()[0].mailbox;
    net.server
        .posts(&mailbox)
        .into_iter()
        .filter(|p| p.1 == kind)
        .count()
}

/// This device's commits queued and not done.
fn queued_commits(net: &Net, d: usize, conv: ConversationId) -> usize {
    net.write(d, |tx| {
        Ok(tx
            .pending_outbox(conv)?
            .into_iter()
            .filter(|o| o.kind == OutboxKind::Commit)
            .count())
    })
}

fn has_group(net: &Net, d: usize, conv: ConversationId) -> bool {
    let group_id = net.devices[d]
        .store
        .conversation_row(conv)
        .unwrap()
        .unwrap()
        .group_id;
    net.write(d, |tx| {
        Ok(
            MlsGroup::load(&tx.mls_storage(), &GroupId::from_slice(&group_id))
                .unwrap()
                .is_some(),
        )
    })
}

fn unfollows(net: &Net, d: usize) -> usize {
    net.server
        .log
        .iter()
        .filter(|((who, _), verb)| *who == d && verb == "UNFOLLOW")
        .count()
}

fn leave(net: &mut Net, d: usize, conv: ConversationId) -> bool {
    let own = net.devices[d].uid.clone();
    let now = net.clock.now().unix_millis();
    let left = net.write(d, |tx| group::leave(tx, conv, &own, now));
    net.tick();
    left
}

/// 6.1: while its SelfRemove waits for a commit, a leaving device makes no
/// commit: it adds nobody, by any job, and makes no new display name, no
/// repair of a failed key check, and no weekly fresh-leaf commit. Once
/// Bob's device commits the SelfRemove, Alice has left the room.
#[test]
fn a_leaving_device_makes_no_commit_but_its_leave_commit() {
    let mut net = Net::new();
    let laptop = net.device("alice", "alice@example.org");
    let phone = net.device_of("alice-phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    for d in [laptop, phone, bob] {
        net.connect(d);
    }
    let a = net
        .job(
            laptop,
            Job::PrivateRoom {
                name: "planning".into(),
                members: vec![uid("bob@example.net")],
            },
        )
        .unwrap();
    net.tick();
    let b = net.same_conv(bob, laptop, a).unwrap();
    let p = net.same_conv(phone, laptop, a).unwrap();
    assert_eq!(net.leaves(bob, b).len(), 3);

    // Bob is away: nobody commits the laptop's SelfRemove.
    net.disconnect(bob);
    assert!(!leave(&mut net, laptop, a));
    assert_eq!(net.state(laptop, a), ConvState::Leaving);
    assert_eq!(net.state(phone, p), ConvState::Left);
    let commits = posts(&net, laptop, a, ContentType::Commit);

    // No job adds anyone: not the identity's other device back.
    let alice = uid("alice@example.org");
    let device = net.devices[phone].device_id.as_slice().try_into().unwrap();
    for job in [
        Job::Invite {
            conv: a,
            uids: vec![alice.clone()],
        },
        Job::Replace {
            conv: a,
            uid: alice.clone(),
            device,
        },
    ] {
        assert!(net.job(laptop, job).is_err());
    }

    // A new display name.
    let now = net.clock.now().unix_millis();
    net.write(laptop, |tx| {
        group::queue_intent(
            tx,
            a,
            &Intent {
                display_name: Some("Alice".into()),
                ..Intent::default()
            },
            now,
        )
    });
    net.tick();
    assert_eq!(queued_commits(&net, laptop, a), 0, "dropped");

    // A key check of Bob's device that failed, whose repair is due.
    let bob_leaf = net.devices[laptop]
        .store
        .leaf_rows(a)
        .unwrap()
        .into_iter()
        .find(|l| l.uid.as_str() == "bob@example.net")
        .unwrap();
    let row = KeyCheckRow {
        conv: a,
        uid: bob_leaf.uid.clone(),
        device_id: bob_leaf.device_id.unwrap(),
        kind: CheckKind::Committer,
        signature_key: bob_leaf.signature_key.clone(),
        init_key: None,
        encryption_key: None,
        binding: None,
        first_needed: now,
        failed: false,
        repair_at: None,
        warned: false,
    };
    net.write(laptop, |tx| Ok(tx.fail_check(&row, Some(now))?));
    net.advance(MINUTE);
    assert_eq!(queued_commits(&net, laptop, a), 0, "no repair");

    // A week and a day: the weekly fresh-leaf commit is due (12.7).
    net.advance(8 * DAY);
    net.advance(11 * MINUTE);
    assert_eq!(queued_commits(&net, laptop, a), 0, "no fresh-leaf commit");
    assert_eq!(posts(&net, laptop, a, ContentType::Commit), commits);
    assert_eq!(net.state(laptop, a), ConvState::Leaving);

    // Bob's device comes back and commits the SelfRemove: Alice has left,
    // and Bob stays in the room.
    net.connect(bob);
    for _ in 0..3 {
        net.advance(MINUTE);
    }
    assert_eq!(net.state(laptop, a), ConvState::Left);
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert_eq!(net.state(bob, b), ConvState::Active);
    assert_eq!(net.leaves(bob, b), ["bob@example.net"]);
    assert!(net.devices[bob].store.departed(b, &alice).unwrap());
}

/// 5.1, 6.1: in a direct conversation nobody commits a SelfRemove. The
/// leaving device removes its identity's other leaf, posts its SelfRemove
/// and forgets the group at once, though Bob is away; Bob's device, once
/// it sees the SelfRemove, leaves too, by itself, with no commit and no
/// move, and notes that Alice left.
#[test]
fn both_sides_leave_a_direct_conversation_that_one_leaves() {
    let mut net = Net::new();
    let laptop = net.device("alice", "alice@example.org");
    let phone = net.device_of("alice-phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    for d in [laptop, phone, bob] {
        net.connect(d);
    }
    let a = net
        .job(
            laptop,
            Job::Direct {
                peer: uid("bob@example.net"),
            },
        )
        .unwrap();
    let b = net.same_conv(bob, laptop, a).unwrap();
    let p = net.same_conv(phone, laptop, a).unwrap();
    assert_eq!(net.leaves(bob, b).len(), 3);

    net.disconnect(bob);
    let unfollowed = unfollows(&net, laptop);
    assert!(!leave(&mut net, laptop, a), "after the leave commit");
    net.advance(MINUTE);
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert_eq!(net.state(laptop, a), ConvState::Left, "without waiting");
    assert!(!has_group(&net, laptop, a));
    assert!(unfollows(&net, laptop) > unfollowed);
    assert_eq!(posts(&net, laptop, a, ContentType::Proposal), 1);
    let commits = posts(&net, laptop, a, ContentType::Commit);

    let unfollowed = unfollows(&net, bob);
    net.connect(bob);
    for _ in 0..3 {
        net.advance(MINUTE);
    }
    assert_eq!(net.state(bob, b), ConvState::Left);
    assert!(!has_group(&net, bob, b));
    assert!(unfollows(&net, bob) > unfollowed);
    assert!(
        net.devices[bob]
            .store
            .departed(b, &uid("alice@example.org"))
            .unwrap()
    );
    assert_eq!(queued_commits(&net, bob, b), 0);
    assert_eq!(
        posts(&net, laptop, a, ContentType::Commit),
        commits,
        "nobody committed the SelfRemove, nor moved"
    );
}

/// 6.1: a device alone in a group leaves by itself: it forgets the group
/// and unfollows its mailbox, and posts nothing, since nobody could commit
/// its SelfRemove.
#[test]
fn a_lone_device_leaves_by_itself() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    net.connect(alice);
    let room = net
        .job(
            alice,
            Job::PrivateRoom {
                name: "notes".into(),
                members: Vec::new(),
            },
        )
        .unwrap();
    net.tick();
    let before = (
        posts(&net, alice, room, ContentType::Commit),
        posts(&net, alice, room, ContentType::Proposal),
    );
    let unfollowed = unfollows(&net, alice);
    assert!(leave(&mut net, alice, room), "left at once");
    assert_eq!(net.state(alice, room), ConvState::Left);
    assert!(!has_group(&net, alice, room));
    assert!(unfollows(&net, alice) > unfollowed);
    net.advance(MINUTE);
    assert_eq!(
        (
            posts(&net, alice, room, ContentType::Commit),
            posts(&net, alice, room, ContentType::Proposal),
        ),
        before
    );
}

/// Alice's laptop and phone, alone in a private room, and the room on
/// each.
fn alone_in_a_room(net: &mut Net) -> (usize, usize, ConversationId, ConversationId) {
    let laptop = net.device("alice", "alice@example.org");
    let phone = net.device_of("alice-phone", laptop);
    net.connect(laptop);
    net.connect(phone);
    let room = net
        .job(
            laptop,
            Job::PrivateRoom {
                name: "notes".into(),
                members: Vec::new(),
            },
        )
        .unwrap();
    net.tick();
    let p = net
        .same_conv(phone, laptop, room)
        .expect("the phone joined");
    assert_eq!(net.leaves(laptop, room).len(), 2);
    (laptop, phone, room, p)
}

/// 6.1: a device whose identity's devices are alone in a group leaves
/// locally, with no SelfRemove, but first commits the removal of its
/// identity's other leaves, so that none of them can later replace its
/// stale leaf (12.7) and Welcome it back. The phone, removed, treats the
/// room as left, and adds nobody back.
#[test]
fn a_lone_identity_removes_its_other_leaves_before_leaving_locally() {
    let mut net = Net::new();
    let (laptop, phone, room, p) = alone_in_a_room(&mut net);
    let commits = posts(&net, laptop, room, ContentType::Commit);
    let unfollowed = unfollows(&net, laptop);
    assert!(!leave(&mut net, laptop, room), "after the commit");
    net.advance(MINUTE);
    assert_eq!(net.state(laptop, room), ConvState::Left);
    assert!(!has_group(&net, laptop, room));
    assert!(unfollows(&net, laptop) > unfollowed);
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert!(!has_group(&net, phone, p));
    assert_eq!(posts(&net, laptop, room, ContentType::Commit), commits + 1);
    assert_eq!(posts(&net, laptop, room, ContentType::Proposal), 0);

    // Past retention plus a day: nobody replaces the laptop's leaf, and
    // neither device is back in the room.
    for _ in 0..9 {
        net.advance(DAY);
    }
    assert_eq!(posts(&net, laptop, room, ContentType::Commit), commits + 1);
    assert_eq!(net.state(laptop, room), ConvState::Left);
    assert_eq!(net.state(phone, p), ConvState::Left);
    let group = net.devices[laptop]
        .store
        .conversation_row(room)
        .unwrap()
        .unwrap()
        .group_id;
    for d in [laptop, phone] {
        assert!(
            !net.convs(d)
                .iter()
                .any(|c| c.group_id == group && c.state.in_group()),
            "welcomed back"
        );
    }
}

/// 6.1: offline, the leaving device waits to post its leave commit. It
/// makes no other commit meanwhile, and forgets the group once the commit
/// is applied.
#[test]
fn a_lone_identitys_leave_commit_waits_until_it_is_online() {
    let mut net = Net::new();
    let (laptop, phone, room, p) = alone_in_a_room(&mut net);
    let commits = posts(&net, laptop, room, ContentType::Commit);
    net.disconnect(laptop);
    assert!(!leave(&mut net, laptop, room));
    net.advance(MINUTE);
    assert!(net.write(laptop, |tx| group::leaving(tx, room)));
    assert!(has_group(&net, laptop, room));
    assert_eq!(net.state(phone, p), ConvState::Active);
    assert_eq!(posts(&net, laptop, room, ContentType::Commit), commits);

    // A new display name meanwhile is dropped.
    let now = net.clock.now().unix_millis();
    net.write(laptop, |tx| {
        group::queue_intent(
            tx,
            room,
            &Intent {
                display_name: Some("Alice".into()),
                ..Intent::default()
            },
            now,
        )
    });
    net.connect(laptop);
    net.advance(MINUTE);
    assert_eq!(net.state(laptop, room), ConvState::Left);
    assert!(!has_group(&net, laptop, room));
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert_eq!(posts(&net, laptop, room, ContentType::Commit), commits + 1);
}

/// 6.1: a device that was away when its identity's other device left
/// locally finds its own removal when it comes back: it treats the room
/// as left, and commits nothing.
#[test]
fn an_own_device_that_was_away_finds_the_room_left() {
    let mut net = Net::new();
    let (laptop, phone, room, p) = alone_in_a_room(&mut net);
    let commits = posts(&net, laptop, room, ContentType::Commit);
    net.disconnect(phone);
    assert!(!leave(&mut net, laptop, room));
    net.advance(MINUTE);
    assert_eq!(net.state(laptop, room), ConvState::Left);
    assert_eq!(posts(&net, laptop, room, ContentType::Commit), commits + 1);

    net.connect(phone);
    for _ in 0..3 {
        net.advance(MINUTE);
    }
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert!(!has_group(&net, phone, p));
    assert_eq!(queued_commits(&net, phone, p), 0);
    assert_eq!(posts(&net, laptop, room, ContentType::Commit), commits + 1);
    assert_eq!(posts(&net, laptop, room, ContentType::Proposal), 0);
}

/// 5.1, 6.1: once Bob leaves a direct conversation, Alice's devices leave
/// too, by themselves, but one of them first removes the other's leaf;
/// both show the conversation as left by Bob.
#[test]
fn own_devices_remove_each_other_when_the_peer_leaves() {
    let mut net = Net::new();
    let laptop = net.device("alice", "alice@example.org");
    let phone = net.device_of("alice-phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    for d in [laptop, phone, bob] {
        net.connect(d);
    }
    let a = net
        .job(
            laptop,
            Job::Direct {
                peer: uid("bob@example.net"),
            },
        )
        .unwrap();
    let b = net.same_conv(bob, laptop, a).unwrap();
    let p = net.same_conv(phone, laptop, a).unwrap();
    assert_eq!(net.leaves(bob, b).len(), 3);
    let commits = posts(&net, laptop, a, ContentType::Commit);

    assert!(!leave(&mut net, bob, b), "after the SelfRemove");
    for _ in 0..3 {
        net.advance(MINUTE);
    }
    assert_eq!(net.state(bob, b), ConvState::Left);
    let bob_uid = uid("bob@example.net");
    for (d, c) in [(laptop, a), (phone, p)] {
        assert_eq!(net.state(d, c), ConvState::Left);
        assert!(!has_group(&net, d, c));
        assert!(net.devices[d].store.departed(c, &bob_uid).unwrap());
        assert_eq!(queued_commits(&net, d, c), 0);
    }
    // Both may have posted a leave commit for the epoch; the first won and
    // removed the other device, whose commit was not made again.
    let after = posts(&net, laptop, a, ContentType::Commit);
    assert!((commits + 1..=commits + 2).contains(&after), "{after}");
}

/// 6.1: a leave commit that fails the device's own group checks does not
/// drop the leave: the laptop leaves locally for good, and posts its
/// SelfRemove, which Bob or the phone commits.
#[test]
fn a_leave_commit_that_fails_its_own_checks_still_leaves() {
    let mut net = Net::new();
    let laptop = net.device("alice", "alice@example.org");
    let phone = net.device_of("alice-phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    for d in [laptop, phone, bob] {
        net.connect(d);
    }
    let a = net
        .job(
            laptop,
            Job::PrivateRoom {
                name: "planning".into(),
                members: vec![uid("bob@example.net")],
            },
        )
        .unwrap();
    net.tick();
    let b = net.same_conv(bob, laptop, a).unwrap();
    let p = net.same_conv(phone, laptop, a).unwrap();
    assert_eq!(net.leaves(bob, b).len(), 3);
    let proposals = posts(&net, laptop, a, ContentType::Proposal);
    let commits = posts(&net, laptop, a, ContentType::Commit);

    // The laptop leaves, and its leave commit, which would remove the
    // phone's leaf, fails its own checks. (The others are away meanwhile,
    // since every device here would fail its checks.)
    net.disconnect(bob);
    net.disconnect(phone);
    group::FAIL_OWN_CHECKS.set(true);
    let own = uid("alice@example.org");
    assert!(!leave(&mut net, laptop, a));
    group::FAIL_OWN_CHECKS.set(false);
    assert_eq!(net.state(laptop, a), ConvState::Left);
    assert!(!has_group(&net, laptop, a));
    assert!(net.devices[laptop].store.departed(a, &own).unwrap());
    assert_eq!(queued_commits(&net, laptop, a), 0);
    assert_eq!(posts(&net, laptop, a, ContentType::Commit), commits);
    assert_eq!(
        posts(&net, laptop, a, ContentType::Proposal),
        proposals + 1,
        "its SelfRemove is posted"
    );

    // Bob or the phone commits it: the laptop's leaf is gone, the phone's
    // stays.
    net.connect(bob);
    net.connect(phone);
    for _ in 0..3 {
        net.advance(MINUTE);
    }
    assert_eq!(net.leaves(bob, b).len(), 2);
    assert_eq!(net.leaves(phone, p).len(), 2);
    assert_eq!(net.state(phone, p), ConvState::Active);
    assert_eq!(net.epoch(bob, b), net.epoch(phone, p));
}

/// 6.1: in a public room too, a device that leaves first removes its
/// identity's other leaves, in a commit the server takes, then posts its
/// SelfRemove, which Alice commits.
#[test]
fn a_device_leaving_a_public_room_removes_its_other_leaves_first() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let laptop = net.device("bob", "bob@example.net");
    let phone = net.device_of("bob-phone", laptop);
    for d in [alice, laptop, phone] {
        net.connect(d);
    }
    let room: Room = "#general".parse().unwrap();
    let a = net
        .job(alice, Job::PublicRoom { room: room.clone() })
        .expect("created");
    let mut joined = Vec::new();
    for d in [laptop, phone] {
        joined.push(
            net.job_over(
                d,
                Job::JoinPublic {
                    room: room.clone(),
                    new_group: false,
                },
                5,
            )
            .expect("joined"),
        );
    }
    let (l, p) = (joined[0], joined[1]);
    net.tick();
    assert_eq!(net.leaves(alice, a).len(), 3);
    let commits = posts(&net, alice, a, ContentType::Commit);

    assert!(!leave(&mut net, laptop, l));
    for _ in 0..12 {
        net.advance(MINUTE);
    }
    assert!(
        posts(&net, alice, a, ContentType::Commit) >= commits + 2,
        "the leave commit, then Alice's commit of the SelfRemove"
    );
    assert_eq!(net.state(laptop, l), ConvState::Left);
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert_eq!(net.leaves(alice, a), ["alice@example.org"]);
    assert_eq!(net.state(alice, a), ConvState::Active);
}
