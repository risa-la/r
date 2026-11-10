//! Posts that expired before a device applied them (7.4, 7.5): the device
//! can no longer follow the group, and applies nothing after the gap.

use super::*;

/// Alice's private room with Bob and Carol, and a message everyone read.
fn team() -> (Net, usize, usize, usize, ConversationId) {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    let carol = net.device("carol", "carol@example.com");
    for d in [alice, bob, carol] {
        net.connect(d);
    }
    let a = net
        .job(
            alice,
            Job::PrivateRoom {
                name: "team".into(),
                members: vec![
                    "bob@example.net".parse().unwrap(),
                    "carol@example.com".parse().unwrap(),
                ],
            },
        )
        .unwrap();
    net.tick();
    net.same_conv(bob, alice, a).expect("bob is in");
    net.same_conv(carol, alice, a).expect("carol is in");
    net.say(alice, a, "hello");
    (net, alice, bob, carol, a)
}

/// Makes a commit in device `d`'s group of `conv` by hand, as a device
/// that has not seen the newest commit, and posts it with its send token.
/// Returns its seq.
fn commit_by_hand(net: &mut Net, d: usize, conv: ConversationId) -> u64 {
    let crypto = Arc::new(risala_mls::RisalaCrypto::new().unwrap());
    let now = net.clock.now().unix_millis();
    let (message, next, token, mailbox) = net.write(d, |tx| {
        let row = tx.conversation(conv)?;
        let p = tx.mls(&crypto);
        let mut group = risala_mls::openmls::group::MlsGroup::load(
            risala_mls::openmls_traits::OpenMlsProvider::storage(&p),
            &risala_mls::openmls::prelude::GroupId::from_slice(&row.group_id),
        )
        .unwrap()
        .unwrap();
        let token = risala_mls::token::SendToken::of_group(&group, crypto.as_ref()).unwrap();
        let state = tx.group_history(conv)?;
        let profile = risala_mls::profile::RisalaProfile::new("", now).unwrap();
        let out = risala_mls::group::commit(
            &p,
            &mut group,
            &profile,
            &state,
            risala_mls::group::Changes::default(),
        )
        .unwrap();
        Ok((
            out.message,
            out.next_token_hash,
            token,
            tx.current_mailbox(conv)?.mailbox,
        ))
    });
    net.server.now = now;
    let (response, live) = net.server.handle(
        (d, Slot::Anonymous(0)),
        Command::Post {
            mailbox,
            token: PostToken::Send(SendTokenText::from_bytes(*token.as_bytes())),
            message: OrBlob::Inline(MlsMessage::from_bytes(&message).unwrap()),
            live: false,
            groupinfo: None,
            next: Some(TokenHash::from_bytes(next)),
            cid: None,
        },
    );
    let End::Ok(ok) = &response.end else {
        panic!("{:?}", response.end)
    };
    net.deliver(live);
    ok.seq().unwrap().unwrap().get()
}

fn current_box(net: &Net, d: usize, conv: ConversationId) -> BoxName {
    net.devices[d]
        .store
        .mailbox_rows(conv)
        .unwrap()
        .into_iter()
        .find(|m| m.current)
        .unwrap()
        .mailbox
}

fn cannot_follow(net: &Net, d: usize, conv: ConversationId) -> bool {
    net.events(d).iter().any(|e| {
        matches!(
            e,
            Event::Conversation(ConversationEvent::CannotFollow { conversation })
                if *conversation == conv
        )
    })
}

#[test]
fn a_commit_that_lost_is_not_applied_after_a_gap() {
    let (mut net, alice, bob, carol, a) = team();
    let b = net.same_conv(bob, alice, a).unwrap();
    let c = net.same_conv(carol, alice, a).unwrap();
    let epoch = net.epoch(bob, b);
    net.disconnect(bob);
    net.disconnect(carol);
    // Alice commits for the epoch, and wins it.
    net.write(alice, |tx| {
        group::queue_intent(
            tx,
            a,
            &Intent {
                display_name: Some("Alice".into()),
                ..Intent::default()
            },
            START,
        )?;
        Ok(())
    });
    net.tick();
    assert_eq!(net.epoch(alice, a), epoch + 1);
    let mailbox = current_box(&net, alice, a);
    let won = net.server.posts(&mailbox).len() as u64;
    // Carol has not seen it, and commits for the same epoch: hers lost.
    let lost = commit_by_hand(&mut net, carol, c);
    assert_eq!(lost, won + 1);
    // Retention expires Alice's commit, but not yet Carol's. Bob wrote a
    // message while away.
    net.server.expire(&mailbox, won);
    net.say(bob, b, "anyone?");
    // Bob comes back: his first post after the gap is the commit that lost.
    // He cannot tell, so he applies nothing after the gap (7.4, 7.5).
    net.connect(bob);
    net.tick();
    assert_eq!(
        net.epoch(bob, b),
        epoch,
        "the commit that lost is not applied"
    );
    assert_eq!(net.state(bob, b), ConvState::Lost);
    assert!(cannot_follow(&net, bob, b));
    // He posts nothing there, and no longer follows the mailbox.
    assert!(
        net.server
            .posts(&mailbox)
            .iter()
            .all(|(seq, _)| *seq <= lost)
    );
    assert!(!net.devices[bob].engine.follows.contains_key(&mailbox));
}

#[test]
fn a_device_that_lost_a_direct_conversation_is_welcomed_back() {
    let mut net = Net::new();
    let laptop = net.device("laptop", "alice@example.org");
    let phone = net.device_of("phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    for d in [laptop, phone, bob] {
        net.connect(d);
    }
    let a = net
        .job(
            laptop,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let p = net.same_conv(phone, laptop, a).expect("the phone is in");
    let b = net.same_conv(bob, laptop, a).expect("bob is in");
    net.say(bob, b, "hi");
    // The phone is away for longer than retention, and retention expires
    // what it missed.
    net.disconnect(phone);
    net.say(bob, b, "while you were away");
    for _ in 0..8 {
        net.advance(24 * 60 * 60 * 1000);
    }
    let mailbox = current_box(&net, laptop, a);
    let head = net.server.posts(&mailbox).last().unwrap().0;
    net.server.expire(&mailbox, head);
    // Back, it finds the gap, and can no longer follow the conversation.
    net.connect(phone);
    net.tick();
    assert_eq!(net.state(phone, p), ConvState::Lost);
    assert!(cannot_follow(&net, phone, p));
    // The laptop replaces its leaf (12.7), and the Welcome brings it back.
    // Posts that expired before the Welcome do not count.
    let device: [u8; 48] = net.devices[phone].device_id.clone().try_into().unwrap();
    net.job(
        laptop,
        Job::Replace {
            conv: a,
            uid: net.devices[phone].uid.clone(),
            device,
        },
    )
    .unwrap();
    net.tick();
    assert_eq!(net.state(phone, p), ConvState::Active);
    assert_eq!(net.epoch(phone, p), net.epoch(laptop, a));
    net.say(bob, b, "welcome back");
    assert!(
        net.texts(phone, p)
            .contains(&("bob@example.net".into(), "welcome back".into()))
    );
    net.say(phone, p, "thanks");
    assert!(
        net.texts(bob, b)
            .contains(&("alice@example.org".into(), "thanks".into()))
    );
}

#[test]
fn a_device_welcomed_after_posts_expired_follows_the_group() {
    let (mut net, alice, _, _, a) = team();
    net.say(alice, a, "before dave");
    let mailbox = current_box(&net, alice, a);
    let head = net.server.posts(&mailbox).last().unwrap().0;
    net.server.expire(&mailbox, head);
    // Dave joins by Welcome. The posts before it expired, which is no gap
    // for him (12.8): they are from before he joined.
    let dave = net.device("dave", "dave@example.com");
    net.connect(dave);
    net.job(
        alice,
        Job::Invite {
            conv: a,
            uids: vec!["dave@example.com".parse().unwrap()],
        },
    )
    .unwrap();
    net.tick();
    let d = net.same_conv(dave, alice, a).expect("dave is in");
    assert_eq!(net.state(dave, d), ConvState::Active);
    assert!(!cannot_follow(&net, dave, d));
    net.say(alice, a, "hello dave");
    assert!(
        net.texts(dave, d)
            .contains(&("alice@example.org".into(), "hello dave".into()))
    );
    // Once he has caught up, posts that expire unread count for him too.
    net.disconnect(dave);
    net.say(alice, a, "unread");
    let head = net.server.posts(&mailbox).last().unwrap().0;
    net.server.expire(&mailbox, head);
    net.connect(dave);
    net.tick();
    assert_eq!(net.state(dave, d), ConvState::Lost);
}

#[test]
fn a_public_room_lost_to_expired_posts_is_joined_again_by_proposal() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let room: Room = "#general".parse().unwrap();
    let a = net
        .job(alice, Job::PublicRoom { room: room.clone() })
        .expect("created");
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
    net.disconnect(bob);
    // Alice commits while Bob is away, and every post expires.
    let now = net.clock.now().unix_millis();
    net.write(alice, |tx| {
        group::queue_intent(tx, a, &Intent::default(), now)?;
        Ok(())
    });
    net.tick();
    let epoch = net.epoch(alice, a);
    let mailbox = current_box(&net, alice, a);
    let head = net.server.posts(&mailbox).last().unwrap().0;
    net.server.expire(&mailbox, head);
    // Bob finds nothing after his sync point up to the head: he cannot
    // follow the room, and joins again by proposal, not by a resync
    // commit, which would remove Alice's leaf (6.1, 12.7).
    net.connect(bob);
    net.tick();
    assert!(cannot_follow(&net, bob, b));
    assert!(!net.events(bob).iter().any(|e| matches!(
        e,
        Event::Conversation(ConversationEvent::InvalidCommitAccepted { .. })
    )));
    for _ in 0..5 {
        net.advance(60_000);
    }
    assert_eq!(net.state(bob, b), ConvState::Active);
    assert!(net.epoch(bob, b) > epoch, "added again by Alice's commit");
    assert_eq!(net.epoch(bob, b), net.epoch(alice, a));
    assert!(
        net.leaves(alice, a)
            .contains(&"alice@example.org".to_string())
    );
    assert!(
        !net.server
            .log
            .iter()
            .any(|((d, s), verb)| *d == bob && *s == Slot::SignedIn && verb == "POST"),
        "no external commit"
    );
}
