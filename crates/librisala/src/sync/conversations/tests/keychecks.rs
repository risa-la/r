//! The key checks of 12.7 acting in the engine (task R2, LR-C2), and
//! Welcomes for a group the device has (LR-C1), against the in-memory
//! server.

use super::*;

fn peer(uid: &str) -> Job {
    Job::Direct {
        peer: uid.parse().unwrap(),
    }
}

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

/// Gives device `d` key facts of its own, as another device may have
/// accepted other records (12.7). Call before it connects.
fn own_facts(net: &mut Net, d: usize) -> KnownKeys {
    let keys = net.keys.copy();
    let key = SigningKey::generate().unwrap();
    net.devices[d].device_id = key.device_id().as_bytes().to_vec();
    keys.add(&net.devices[d].uid, &key);
    net.keys.add(&net.devices[d].uid, &key);
    net.server.signed_in.insert(
        (d, Slot::SignedIn),
        (
            net.devices[d].uid.to_string(),
            net.devices[d].device_id.clone(),
        ),
    );
    net.devices[d].engine = ConversationEngine::new(
        Config {
            self_conversation: false,
            ..Config::immediate()
        },
        Arc::new(TestHooks {
            keys: keys.clone(),
            key,
            confirm: true,
            distrust: Default::default(),
            blobs: net.server.blobs.clone(),
            blob_mode: net.blob_mode.clone(),
        }),
        Arc::new(net.clock.clone()),
    );
    keys
}

fn checks(net: &Net, d: usize, conv: ConversationId) -> usize {
    net.devices[d]
        .store
        .write_with(|tx| -> Result<_, EngineError> { Ok(tx.conversation_checks(conv)?) })
        .unwrap()
        .0
        .len()
}

fn has_event(net: &Net, d: usize, f: impl Fn(&ConversationEvent) -> bool) -> bool {
    net.events(d).iter().any(|e| match e {
        Event::Conversation(c) => f(c),
        _ => false,
    })
}

/// 12.7: a leaf added while the device could not check it holds sending:
/// nothing is posted while it is unchecked. A record still pending 2 hours
/// later counts as failed, and the leaf is removed, for a check; then
/// sending goes on, and the removed leaf never read what was held.
#[test]
fn an_unchecked_add_holds_sending_and_is_removed_after_two_hours() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    // Bob's key file cannot be read: his device is added unchecked.
    net.keys.set_unknown(&uid("bob@example.net"), true);
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    let b = net.same_conv(bob, alice, a).expect("bob joined");
    assert!(has_event(&net, alice, |e| matches!(
        e,
        ConversationEvent::SendingHeld { conversation } if *conversation == a
    )));
    assert_eq!(checks(&net, alice, a), 1);
    net.say(alice, a, "not for an unchecked leaf");
    net.advance(30 * 60 * 1000);
    assert!(net.texts(bob, b).is_empty(), "nothing was posted");
    // Still pending 2 hours after it was first needed: failed, repaired.
    for _ in 0..10 {
        net.advance(10 * 60 * 1000);
    }
    assert!(has_event(&net, alice, |e| matches!(
        e,
        ConversationEvent::KeyCheckFailed { conversation, uid, repairing: true }
            if *conversation == a && uid.as_str() == "bob@example.net"
    )));
    assert_eq!(net.leaves(alice, a), ["alice@example.org"]);
    assert_eq!(net.state(bob, b), ConvState::Left);
    assert!(
        net.texts(bob, b).is_empty(),
        "the removed leaf read nothing"
    );
    // The check goes with the leaf, at the next look.
    net.advance(61 * 1000);
    assert_eq!(checks(&net, alice, a), 0);
    assert!(has_event(&net, alice, |e| matches!(
        e,
        ConversationEvent::SendingResumed { conversation } if *conversation == a
    )));
}

/// 12.7: once the facts are known and the check passes, sending goes on.
#[test]
fn sending_goes_on_once_the_add_is_checked() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    net.keys.set_unknown(&uid("bob@example.net"), true);
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    let b = net.same_conv(bob, alice, a).unwrap();
    net.say(alice, a, "hello");
    net.advance(2 * 60 * 1000);
    assert!(net.texts(bob, b).is_empty());
    // Bob's record is accepted now.
    net.keys.set_unknown(&uid("bob@example.net"), false);
    net.advance(61 * 1000);
    assert_eq!(
        net.texts(bob, b),
        [("alice@example.org".into(), "hello".into())]
    );
    assert_eq!(checks(&net, alice, a), 0);
    assert_eq!(net.leaves(alice, a).len(), 2, "nobody was removed");
}

/// 12.7: an add that fails the checks of a device that did not make it,
/// here of a device that device has seen removed by record, is repaired by
/// it: the leaf is removed for a check, and the user told.
#[test]
fn a_failed_add_by_another_member_is_removed_for_a_check() {
    let mut net = Net::new();
    let laptop = net.device("laptop", "alice@example.org");
    let phone = net.device_of("phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    let bob_keys = own_facts(&mut net, bob);
    // Bob has accepted a record that removed the phone; the laptop has not.
    let phone_id: [u8; 48] = net.devices[phone].device_id.clone().try_into().unwrap();
    bob_keys.remove(&uid("alice@example.org"), &phone_id);
    net.connect(laptop);
    net.connect(bob);
    let a = net.job(laptop, peer("bob@example.net")).unwrap();
    let b = net.same_conv(bob, laptop, a).unwrap();
    assert_eq!(net.leaves(laptop, a).len(), 2);
    // The laptop adds the phone.
    net.connect(phone);
    net.job(
        laptop,
        Job::Invite {
            conv: a,
            uids: vec![uid("alice@example.org")],
        },
    )
    .unwrap();
    net.advance(60 * 1000);
    net.advance(60 * 1000);
    assert!(has_event(&net, bob, |e| matches!(
        e,
        ConversationEvent::KeyCheckFailed { conversation, uid, repairing: true }
            if *conversation == b && uid.as_str() == "alice@example.org"
    )));
    assert_eq!(net.leaves(bob, b).len(), 2, "the phone's leaf is gone");
    assert_eq!(net.leaves(laptop, a).len(), 2);
}

/// 12.7: a committer whose device was removed by record is removed, as an
/// impostor's leaf.
#[test]
fn a_committer_removed_by_record_is_removed() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    let alice_keys = own_facts(&mut net, alice);
    net.connect(alice);
    net.connect(bob);
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    let b = net.same_conv(bob, alice, a).unwrap();
    // Alice accepts a record that removed Bob's device; Bob's device then
    // commits.
    let bob_id: [u8; 48] = net.devices[bob].device_id.clone().try_into().unwrap();
    alice_keys.remove(&uid("bob@example.net"), &bob_id);
    net.write(bob, |tx| {
        group::queue_intent(
            tx,
            b,
            &Intent {
                new_leaf_key: true,
                ..Intent::default()
            },
            START,
        )?;
        Ok(())
    });
    net.tick();
    net.advance(60 * 1000);
    net.advance(60 * 1000);
    assert!(has_event(&net, alice, |e| matches!(
        e,
        ConversationEvent::KeyCheckFailed { conversation, uid, repairing: true }
            if *conversation == a && uid.as_str() == "bob@example.net"
    )));
    assert_eq!(net.leaves(alice, a), ["alice@example.org"]);
}

/// The commits of this device's outbox in `conv`, done or not, but moves
/// (7.8).
fn own_commits(net: &Net, d: usize, conv: ConversationId) -> u32 {
    net.write(d, |tx| {
        Ok(tx
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM outbox
                 WHERE conv = ?1 AND kind = 'commit' AND move_box IS NULL",
                [conv.0],
                |r| r.get(0),
            )
            .map_err(crate::store::StoreError::from)?)
    })
}

/// 12.7, 12.14: a failed check is repaired by exactly one removal commit,
/// even when the device's upkeep queued a removal of the same leaf by key
/// file while the repair waited: the repair is not queued again, and
/// only the removal and the move that follows it (7.8) are posted.
#[test]
fn a_failed_check_makes_exactly_one_removal_commit() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    let alice_keys = own_facts(&mut net, alice);
    net.connect(alice);
    net.connect(bob);
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    let b = net.same_conv(bob, alice, a).unwrap();
    let mailbox = net.devices[alice].store.mailbox_rows(a).unwrap()[0].mailbox;
    let commits = |net: &Net| {
        net.server
            .posts(&mailbox)
            .into_iter()
            .filter(|p| p.1 == risala_mls::framing::ContentType::Commit)
            .count()
    };
    // Alice accepts a record that removed Bob's device; Bob's device then
    // commits, and fails Alice's committer check.
    let bob_id: [u8; 48] = net.devices[bob].device_id.clone().try_into().unwrap();
    alice_keys.remove(&uid("bob@example.net"), &bob_id);
    net.write(bob, |tx| {
        group::queue_intent(
            tx,
            b,
            &Intent {
                new_leaf_key: true,
                ..Intent::default()
            },
            START,
        )?;
        Ok(())
    });
    net.tick();
    assert_eq!(checks(&net, alice, a), 1);
    let before = commits(&net);
    let queued = own_commits(&net, alice, a);
    // Meanwhile the upkeep removes the leaves of devices removed by
    // record (12.14), here before the repair is due.
    net.write(alice, |tx| {
        group::queue_intent(
            tx,
            a,
            &Intent {
                remove: vec![("bob@example.net".into(), Some(bob_id))],
                ..Intent::default()
            },
            START,
        )?;
        Ok(())
    });
    for _ in 0..5 {
        net.advance(60 * 1000);
    }
    assert!(has_event(&net, alice, |e| matches!(
        e,
        ConversationEvent::KeyCheckFailed { conversation, uid, repairing: true }
            if *conversation == a && uid.as_str() == "bob@example.net"
    )));
    assert_eq!(net.leaves(alice, a), ["alice@example.org"]);
    assert_eq!(commits(&net), before + 2, "the removal, then the move");
    assert_eq!(
        own_commits(&net, alice, a),
        queued + 1,
        "the repair was not queued again"
    );
    assert_eq!(checks(&net, alice, a), 0);
}

/// LR-C1: a Welcome whose group id is that of a conversation the device
/// has, but that does not continue it, is refused, and the conversation
/// stays as it was. Here a device of someone else under Bob's uid (as the
/// server could make) creates a group with Alice; Alice's conversation
/// with Bob is made to carry that group's id, as a server that chose it
/// would.
#[test]
fn a_welcome_reusing_a_known_group_id_is_refused() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    let fake = net.device("fake", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    net.say(alice, a, "for bob");
    net.disconnect(alice);
    net.connect(fake);
    let f = net
        .job(fake, peer("alice@example.org"))
        .expect("the group is made");
    let fake_group = net.devices[fake]
        .store
        .conversation_row(f)
        .unwrap()
        .unwrap()
        .group_id;
    let before = net.devices[alice]
        .store
        .conversation_row(a)
        .unwrap()
        .unwrap();
    // Alice's conversation carries that group id, at an epoch before the
    // Welcome's, so only the signer tells the groups apart.
    net.write(alice, |tx| {
        tx.conn()
            .execute(
                "UPDATE conversations SET group_id = ?1, epoch = 0 WHERE id = ?2",
                rusqlite::params![fake_group, a.0],
            )
            .map_err(crate::store::StoreError::from)?;
        Ok(())
    });
    net.connect(alice);
    net.tick();
    assert!(has_event(&net, alice, |e| matches!(
        e,
        ConversationEvent::WelcomeForKnownGroupRefused { conversation, .. } if *conversation == a
    )));
    let after = net.devices[alice]
        .store
        .conversation_row(a)
        .unwrap()
        .unwrap();
    assert_eq!(after.state, before.state);
    assert_eq!(after.peer, before.peer);
    assert_eq!(after.epoch, 0, "no epoch from the Welcome");
    assert_eq!(net.leaves(alice, a).len(), 2);
    assert_eq!(net.convs(alice).len(), 1, "and no new conversation from it");
    assert_eq!(net.texts(alice, a).len(), 1);
}
