//! Leaving (6.1): a leaving device makes no commit but its leave commit; a
//! device with no other identity in the group leaves locally; and in a
//! direct conversation both sides leave once one posts its SelfRemove.

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

/// 6.1: a device whose identity's devices are alone in a group leaves
/// locally too, with no commit and no SelfRemove; its other device stays.
#[test]
fn a_lone_identity_leaves_locally_without_a_commit() {
    let mut net = Net::new();
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
    let commits = posts(&net, laptop, room, ContentType::Commit);
    assert!(leave(&mut net, laptop, room), "left at once");
    net.advance(MINUTE);
    assert_eq!(net.state(laptop, room), ConvState::Left);
    assert!(!has_group(&net, laptop, room));
    assert_eq!(net.state(phone, p), ConvState::Active);
    assert_eq!(posts(&net, laptop, room, ContentType::Commit), commits);
    assert_eq!(posts(&net, laptop, room, ContentType::Proposal), 0);
}
