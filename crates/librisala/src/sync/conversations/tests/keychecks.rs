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
pub(super) fn own_facts(net: &mut Net, d: usize) -> KnownKeys {
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
            puts: Default::default(),
            blobs: net.server.blobs.clone(),
            blob_mode: net.blob_mode.clone(),
            hold_puts: net.hold_puts.clone(),
            fetched: Default::default(),
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

/// Alice's laptop and Bob in a direct conversation, and Alice's phone,
/// with key facts of its own, joined to it by the laptop.
struct Three {
    net: Net,
    laptop: usize,
    phone: usize,
    bob: usize,
    /// The conversation on the laptop, the phone and Bob's device.
    a: ConversationId,
    p: ConversationId,
    b: ConversationId,
    phone_keys: KnownKeys,
}

fn three(before_join: impl FnOnce(&mut Net, &KnownKeys, usize)) -> Three {
    let mut net = Net::new();
    let laptop = net.device("laptop", "alice@example.org");
    let phone = net.device_of("phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    let phone_keys = own_facts(&mut net, phone);
    before_join(&mut net, &phone_keys, phone);
    net.connect(laptop);
    for d in 3..net.devices.len() {
        net.connect(d);
    }
    net.connect(bob);
    let a = net.job(laptop, peer("bob@example.net")).unwrap();
    let b = net.same_conv(bob, laptop, a).unwrap();
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
    let p = net.same_conv(phone, laptop, a).expect("the phone joined");
    Three {
        net,
        laptop,
        phone,
        bob,
        a,
        p,
        b,
        phone_keys,
    }
}

/// Bob's second device, connected, and added by Alice's laptop, which
/// knows it.
fn add_bob_tablet(t: &mut Three) -> usize {
    let tablet = t.net.device_of("tablet", t.bob);
    // Its record is in Bob's key file, for the phone too, once it reads.
    let key = SigningKey::from_seed(*t.net.devices[tablet].hooks.key.seed());
    t.phone_keys.add(&uid("bob@example.net"), &key);
    t.net.connect(tablet);
    t.net
        .job(
            t.laptop,
            Job::Invite {
                conv: t.a,
                uids: vec![uid("bob@example.net")],
            },
        )
        .unwrap();
    t.net.advance(60 * 1000);
    tablet
}

fn held(net: &Net, d: usize, conv: ConversationId) -> bool {
    net.devices[d]
        .store
        .write_with(|tx| -> Result<_, EngineError> { Ok(tx.sending_held(conv)?) })
        .unwrap()
        .0
}

/// 12.7: a leaf added while the device could not check it holds sending:
/// nothing is posted while it is unchecked. Here Bob's new device's record
/// is pending for the phone, whose key file of Bob reads. Still pending 2
/// hours later, it counts as failed, and the leaf is removed, for a check;
/// then sending goes on, and the removed leaf never read what was held.
#[test]
fn an_unchecked_add_holds_sending_and_is_removed_after_two_hours() {
    let mut t = three(|_, _, _| {});
    t.phone_keys.set_unknown(&uid("bob@example.net"), true);
    let tablet = add_bob_tablet(&mut t);
    let tb = t
        .net
        .same_conv(tablet, t.laptop, t.a)
        .expect("tablet joined");
    let (net, phone, p, b) = (&mut t.net, t.phone, t.p, t.b);
    assert_eq!(net.leaves(phone, p).len(), 4);
    assert!(has_event(net, phone, |e| matches!(
        e,
        ConversationEvent::SendingHeld { conversation } if *conversation == p
    )));
    assert_eq!(checks(net, phone, p), 1);
    net.say(phone, p, "not for an unchecked leaf");
    net.advance(30 * 60 * 1000);
    assert!(net.texts(tablet, tb).is_empty(), "nothing was posted");
    assert!(net.texts(t.bob, b).is_empty(), "nothing was posted");
    // Still pending 2 hours after it was first needed: failed, repaired.
    for _ in 0..10 {
        net.advance(10 * 60 * 1000);
    }
    assert!(has_event(net, phone, |e| matches!(
        e,
        ConversationEvent::KeyCheckFailed { conversation, uid, repairing: true }
            if *conversation == p && uid.as_str() == "bob@example.net"
    )));
    assert_eq!(net.leaves(phone, p).len(), 3, "the tablet's leaf is gone");
    assert_eq!(net.state(tablet, tb), ConvState::Left);
    assert!(
        net.texts(tablet, tb).is_empty(),
        "the removed leaf read nothing"
    );
    // The check goes with the leaf, at the next look.
    net.advance(61 * 1000);
    assert_eq!(checks(net, phone, p), 0);
    assert!(has_event(net, phone, |e| matches!(
        e,
        ConversationEvent::SendingResumed { conversation } if *conversation == p
    )));
    // Then the move that follows a removal (7.8), and what was held.
    for _ in 0..15 {
        net.advance(60 * 1000);
    }
    assert!(net.texts(t.bob, b).contains(&(
        "alice@example.org".into(),
        "not for an unchecked leaf".into()
    )));
}

/// 12.7: once the facts are known and the check passes, sending goes on.
#[test]
fn sending_goes_on_once_the_add_is_checked() {
    let mut t = three(|_, _, _| {});
    t.phone_keys.set_unknown(&uid("bob@example.net"), true);
    let tablet = add_bob_tablet(&mut t);
    let tb = t.net.same_conv(tablet, t.laptop, t.a).unwrap();
    let (net, phone, p) = (&mut t.net, t.phone, t.p);
    net.say(phone, p, "hello");
    net.advance(2 * 60 * 1000);
    assert!(net.texts(tablet, tb).is_empty());
    // The tablet's record is accepted now.
    t.phone_keys.set_unknown(&uid("bob@example.net"), false);
    net.advance(61 * 1000);
    assert_eq!(
        net.texts(tablet, tb),
        [("alice@example.org".into(), "hello".into())]
    );
    assert_eq!(checks(net, phone, p), 0);
    assert_eq!(net.leaves(phone, p).len(), 4, "nobody was removed");
}

/// 12.5, 12.14: a device never adds an identity whose key file it has
/// never read: the direct conversation is not made, and Bob gets nothing.
#[test]
fn an_outage_on_first_contact_refuses_the_add() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    net.keys.set_unknown(&uid("bob@example.net"), true);
    net.keys.set_unreadable(&uid("bob@example.net"), true);
    let made = net.job(alice, peer("bob@example.net"));
    assert!(made.is_err(), "{made:?}");
    net.advance(60 * 1000);
    assert!(net.convs(bob).is_empty(), "Bob was not added");
    // Once the key file is read, it works.
    net.keys.set_unknown(&uid("bob@example.net"), false);
    net.keys.set_unreadable(&uid("bob@example.net"), false);
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    assert!(net.same_conv(bob, alice, a).is_some());
}

/// 12.14: during an outage after a good read, the devices of that read
/// are added and checked as before: nothing waits.
#[test]
fn an_outage_after_a_good_read_keeps_cached_devices() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    net.keys.set_unreadable(&uid("bob@example.net"), true);
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    let b = net.same_conv(bob, alice, a).expect("Bob was added");
    assert_eq!(checks(&net, alice, a), 0);
    assert!(!held(&net, alice, a));
    net.say(alice, a, "hello");
    net.advance(60 * 1000);
    assert_eq!(
        net.texts(bob, b),
        [("alice@example.org".into(), "hello".into())]
    );
}

/// 12.7: an outage never fails a check. The phone cannot read Bob's key
/// file and never could: the tablet's add stays pending past 2 hours,
/// sending stays held, the user is warned once, and nothing is removed.
/// Once the file is read, the check passes and sending goes on.
#[test]
fn an_outage_past_two_hours_warns_and_removes_no_added_leaf() {
    let mut t = three(|_, _, _| {});
    t.phone_keys.set_unknown(&uid("bob@example.net"), true);
    t.phone_keys.set_unreadable(&uid("bob@example.net"), true);
    let tablet = add_bob_tablet(&mut t);
    let tb = t.net.same_conv(tablet, t.laptop, t.a).unwrap();
    let (net, phone, p) = (&mut t.net, t.phone, t.p);
    net.say(phone, p, "after the outage");
    for _ in 0..30 {
        net.advance(10 * 60 * 1000);
    }
    let warnings = net
        .events(phone)
        .iter()
        .filter(|e| {
            matches!(e, Event::Conversation(ConversationEvent::KeyFileUnavailable {
                conversation, uid
            }) if *conversation == p && uid.as_str() == "bob@example.net")
        })
        .count();
    assert_eq!(warnings, 1, "warned once");
    assert!(!has_event(net, phone, |e| matches!(
        e,
        ConversationEvent::KeyCheckFailed { .. }
    )));
    assert_eq!(net.leaves(phone, p).len(), 4, "nothing removed");
    assert!(held(net, phone, p), "sending still held");
    assert!(net.texts(tablet, tb).is_empty());
    // The key file is read again: the check passes.
    t.phone_keys.set_unknown(&uid("bob@example.net"), false);
    t.phone_keys.set_unreadable(&uid("bob@example.net"), false);
    net.advance(61 * 1000);
    assert_eq!(checks(net, phone, p), 0);
    assert_eq!(
        net.texts(tablet, tb),
        [("alice@example.org".into(), "after the outage".into())]
    );
}

/// 12.7: a committer counts as checked as far as the records accepted go.
/// The phone cannot read Bob's key file and never could: Bob's commit
/// leaves a check pending past 2 hours, the user is warned once, and Bob
/// is not removed, nor his messages hidden, nor the phone's sending held.
#[test]
fn an_outage_past_two_hours_warns_and_removes_no_committer() {
    let mut t = three(|_, _, _| {});
    t.phone_keys.set_unknown(&uid("bob@example.net"), true);
    t.phone_keys.set_unreadable(&uid("bob@example.net"), true);
    let (net, phone, p, b) = (&mut t.net, t.phone, t.p, t.b);
    net.write(t.bob, |tx| {
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
    assert_eq!(checks(net, phone, p), 1, "the committer's check waits");
    assert!(!held(net, phone, p));
    for _ in 0..30 {
        net.advance(10 * 60 * 1000);
    }
    let warnings = net
        .events(phone)
        .iter()
        .filter(|e| {
            matches!(e, Event::Conversation(ConversationEvent::KeyFileUnavailable {
                conversation, uid
            }) if *conversation == p && uid.as_str() == "bob@example.net")
        })
        .count();
    assert_eq!(warnings, 1, "warned once");
    assert!(!has_event(net, phone, |e| matches!(
        e,
        ConversationEvent::KeyCheckFailed { .. }
    )));
    assert_eq!(net.leaves(phone, p).len(), 3, "nothing removed");
    net.say(t.bob, b, "still here");
    net.advance(60 * 1000);
    assert!(
        net.texts(phone, p)
            .contains(&("bob@example.net".into(), "still here".into())),
        "not hidden"
    );
    net.say(phone, p, "and so am I");
    net.advance(60 * 1000);
    assert!(
        net.texts(t.bob, b)
            .contains(&("alice@example.org".into(), "and so am I".into())),
        "not held"
    );
}

/// 12.7, Joining: a device that joins by Welcome checks every leaf already
/// there, and sends nothing until each passes: here Bob's record is
/// pending for the phone when it joins.
#[test]
fn a_joiner_holds_sending_until_the_leaves_there_pass() {
    let mut t = three(|_, keys, _| keys.set_unknown(&uid("bob@example.net"), true));
    let (net, phone, p, b) = (&mut t.net, t.phone, t.p, t.b);
    assert!(has_event(net, phone, |e| matches!(
        e,
        ConversationEvent::SendingHeld { conversation } if *conversation == p
    )));
    assert_eq!(checks(net, phone, p), 1, "Bob's leaf only");
    net.say(phone, p, "from the phone");
    net.advance(60 * 1000);
    assert!(
        !net.texts(t.bob, b)
            .iter()
            .any(|(_, text)| text == "from the phone"),
        "held"
    );
    // Bob's record is accepted now.
    t.phone_keys.set_unknown(&uid("bob@example.net"), false);
    net.advance(61 * 1000);
    assert_eq!(checks(net, phone, p), 0);
    assert!(has_event(net, phone, |e| matches!(
        e,
        ConversationEvent::SendingResumed { conversation } if *conversation == p
    )));
    assert!(
        net.texts(t.bob, b)
            .contains(&("alice@example.org".into(), "from the phone".into()))
    );
    assert_eq!(net.leaves(phone, p).len(), 3);
}

/// 12.7, Joining: a leaf already in the group whose device is not current
/// for the joiner, a device under Bob's uid that his key file does not
/// list, fails the check, and the joiner removes it, for a check.
#[test]
fn a_joiner_removes_a_fake_leaf_already_there() {
    let mut t = three(|net, _, _| {
        // Known to the laptop and to Bob's device, not to the phone.
        net.device("fake", "bob@example.net");
    });
    let (net, phone, p, a) = (&mut t.net, t.phone, t.p, t.a);
    assert_eq!(net.leaves(t.laptop, a).len(), 4, "the fake was added");
    for _ in 0..3 {
        net.advance(60 * 1000);
    }
    assert!(has_event(net, phone, |e| matches!(
        e,
        ConversationEvent::KeyCheckFailed { conversation, uid, repairing: true }
            if *conversation == p && uid.as_str() == "bob@example.net"
    )));
    assert_eq!(net.leaves(phone, p).len(), 3, "the fake is gone");
    assert_eq!(net.leaves(t.laptop, a).len(), 3);
    let fake_id = net.devices[3].device_id.clone();
    assert!(
        !net.devices[phone]
            .store
            .leaf_rows(p)
            .unwrap()
            .iter()
            .any(|l| l.device_id.map(|d| d.to_vec()) == Some(fake_id.clone()))
    );
    assert_eq!(checks(net, phone, p), 0);
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
