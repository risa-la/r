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

/// Alice's laptop and phone, in their conversation with themselves and in
/// a direct conversation with Bob.
fn own_devices_and_bob() -> (Net, usize, usize, usize, ConversationId) {
    let mut net = Net::new();
    let laptop = net.device("laptop", "alice@example.org");
    let phone = net.device_of("phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    for d in [laptop, phone, bob] {
        net.connect(d);
    }
    let me = net.job(laptop, Job::WithYourself).unwrap();
    net.same_conv(phone, laptop, me).expect("the phone is in");
    let a = net
        .job(
            laptop,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    net.same_conv(phone, laptop, a).expect("the phone is in");
    net.same_conv(bob, laptop, a).expect("bob is in");
    (net, laptop, phone, bob, a)
}

/// Expires every post of the current mailbox of device `d`'s `conv`.
fn expire_all(net: &mut Net, d: usize, conv: ConversationId) {
    let mailbox = current_box(net, d, conv);
    let head = net.server.posts(&mailbox).last().unwrap().0;
    net.server.expire(&mailbox, head);
}

fn left(net: &Net, d: usize, conv: ConversationId) -> bool {
    net.events(d).iter().any(|e| {
        matches!(
            e,
            Event::Conversation(ConversationEvent::Left { conversation })
                if *conversation == conv
        )
    })
}

/// The `RESYNC <box> <seq>` requests device `d` holds from its own
/// devices, waiting for their random wait (12.9): the box and seq each
/// named, by conversation.
fn resyncs_held(net: &Net, d: usize) -> Vec<(ConversationId, BoxName, u64)> {
    let mut held: Vec<_> = net.devices[d]
        .engine
        .own_resyncs
        .iter()
        .map(|((conv, _), (mailbox, seq))| (*conv, *mailbox, *seq))
        .collect();
    held.sort_by_key(|(c, _, s)| (c.0, *s));
    held
}

/// Device `d` waits up to 10 minutes before it replaces a leaf that asked
/// with RESYNC, as outside tests (12.7).
fn real_commit_wait(net: &mut Net, d: usize) {
    net.devices[d].engine.config.max_commit_wait_ms = 10 * 60 * 1000;
}

/// 7.4, 12.7: a device that finds a gap asks its own devices at once with
/// `RESYNC <box> <seq>`; the laptop replaces its leaf without waiting for
/// the leaf to go stale, or for an hour, and the Welcome brings it back.
/// Every post up to the head expired, so the RESYNC names the head (7.5,
/// 12.9), which the laptop has applied.
#[test]
fn a_lost_device_asks_its_own_devices_and_is_welcomed_back() {
    let (mut net, laptop, phone, bob, a) = own_devices_and_bob();
    let p = net.same_conv(phone, laptop, a).unwrap();
    let b = net.same_conv(bob, laptop, a).unwrap();
    net.disconnect(phone);
    net.say(bob, b, "while you were away");
    let mailbox = current_box(&net, laptop, a);
    let head = net.server.posts(&mailbox).last().unwrap().0;
    expire_all(&mut net, laptop, a);
    let before = net.epoch(laptop, a);
    let started = net.clock.now().unix_millis();
    real_commit_wait(&mut net, laptop);
    net.connect(phone);
    net.tick();
    assert!(cannot_follow(&net, phone, p));
    assert_eq!(resyncs_held(&net, laptop), [(a, mailbox, head)]);
    for _ in 0..11 {
        net.advance(60_000);
    }
    assert!(
        net.epoch(laptop, a) > before,
        "the laptop replaced the phone's leaf"
    );
    assert!(net.clock.now().unix_millis() - started < 60 * 60 * 1000);
    assert_eq!(net.state(phone, p), ConvState::Active);
    assert_eq!(net.epoch(phone, p), net.epoch(laptop, a));
    assert_eq!(net.leaves(bob, b).len(), 3);
    net.say(bob, b, "welcome back");
    assert!(
        net.texts(phone, p)
            .contains(&("bob@example.net".into(), "welcome back".into()))
    );
}

/// 6.1, 7.5: the user leaves a conversation the device has lost. It is
/// left locally at once, marked departed, and a Welcome back from a device
/// of its own identity is refused: here the laptop's, which answers the
/// RESYNC the phone sent before, while the phone's LEAVE waits for it to be
/// online. Once it is, the laptop leaves too.
#[test]
fn a_lost_conversation_the_user_leaves_refuses_a_welcome_back_from_an_own_device() {
    let (mut net, laptop, phone, bob, a) = own_devices_and_bob();
    let p = net.same_conv(phone, laptop, a).unwrap();
    let b = net.same_conv(bob, laptop, a).unwrap();
    net.disconnect(phone);
    net.say(bob, b, "while you were away");
    expire_all(&mut net, laptop, a);
    // The laptop, which read everything, is away when the phone asks.
    net.disconnect(laptop);
    net.connect(phone);
    net.tick();
    assert_eq!(net.state(phone, p), ConvState::Lost);
    // The user leaves while the phone is offline: its LEAVE waits.
    net.disconnect(phone);
    let own = net.devices[phone].uid.clone();
    let now = net.clock.now().unix_millis();
    assert!(net.write(phone, |tx| group::leave(tx, p, &own, now)));
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert!(net.devices[phone].store.departed(p, &own).unwrap());
    // The laptop comes back and answers the RESYNC.
    let before = net.epoch(laptop, a);
    net.connect(laptop);
    for _ in 0..3 {
        net.advance(60_000);
    }
    assert!(
        net.epoch(laptop, a) > before,
        "the laptop replaced the phone's leaf"
    );
    assert_eq!(net.leaves(bob, b).len(), 3);
    // The phone refuses the Welcome, and posts its LEAVE: the laptop leaves
    // the direct conversation, and so does Bob, as for any leave.
    let seen = net.events(phone).len();
    net.connect(phone);
    for _ in 0..3 {
        net.advance(60_000);
    }
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert!(!net.events(phone)[seen..].iter().any(|e| matches!(
        e,
        Event::Conversation(ConversationEvent::Joined { conversation }) if *conversation == p
    )));
    assert_eq!(net.state(laptop, a), ConvState::Left);
    assert!(left(&net, laptop, a));
    assert_eq!(net.state(bob, b), ConvState::Left);
    assert!(net.devices[bob].store.departed(b, &own).unwrap());
}

/// Bob's private room with Alice's laptop and phone, which share their
/// conversation with themselves.
fn bobs_room_with_own_devices() -> (Net, usize, usize, usize, ConversationId) {
    let mut net = Net::new();
    let laptop = net.device("laptop", "alice@example.org");
    let phone = net.device_of("phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    for d in [laptop, phone, bob] {
        net.connect(d);
    }
    let me = net.job(laptop, Job::WithYourself).unwrap();
    net.same_conv(phone, laptop, me).expect("the phone is in");
    let b = net
        .job(
            bob,
            Job::PrivateRoom {
                name: "team".into(),
                members: vec!["alice@example.org".parse().unwrap()],
            },
        )
        .unwrap();
    net.tick();
    net.same_conv(laptop, bob, b).expect("the laptop is in");
    net.same_conv(phone, bob, b).expect("the phone is in");
    assert_eq!(net.leaves(bob, b).len(), 3);
    (net, laptop, phone, bob, b)
}

/// The phone finds posts of Bob's room expired unread while the laptop is
/// away, and the user leaves the room on it: it leaves locally for good,
/// and posts `LEAVE <box>` to the laptop. Returns the phone's and the
/// laptop's conversations.
fn phone_lost_and_left(
    net: &mut Net,
    laptop: usize,
    phone: usize,
    bob: usize,
    b: ConversationId,
) -> (ConversationId, ConversationId) {
    let p = net.same_conv(phone, bob, b).unwrap();
    let l = net.same_conv(laptop, bob, b).unwrap();
    net.disconnect(phone);
    net.say(bob, b, "while you were away");
    expire_all(net, bob, b);
    net.disconnect(laptop);
    net.connect(phone);
    net.tick();
    assert_eq!(net.state(phone, p), ConvState::Lost);
    let own = net.devices[phone].uid.clone();
    let now = net.clock.now().unix_millis();
    assert!(net.write(phone, |tx| group::leave(tx, p, &own, now)));
    net.tick();
    assert_eq!(net.state(phone, p), ConvState::Left);
    (p, l)
}

/// 6.1: a lost device leaves, and tells the laptop with LEAVE, which makes
/// the usual leave commit: it removes the phone's leaf, and Bob commits the
/// laptop's SelfRemove. The RESYNC the phone sent when it found the gap is
/// not answered, so nobody Welcomes anyone back, and Alice has left.
#[test]
fn a_lost_device_that_leaves_has_its_own_devices_leave_and_nobody_is_welcomed_back() {
    let (mut net, laptop, phone, bob, b) = bobs_room_with_own_devices();
    let (p, l) = phone_lost_and_left(&mut net, laptop, phone, bob, b);
    let alice = net.devices[phone].uid.clone();
    let epoch = net.epoch(bob, b);
    let seen = net.events(phone).len();
    net.connect(laptop);
    for _ in 0..5 {
        net.advance(60_000);
    }
    assert_eq!(net.state(laptop, l), ConvState::Left);
    assert!(left(&net, laptop, l));
    assert_eq!(net.leaves(bob, b), ["bob@example.net"]);
    assert_eq!(net.state(bob, b), ConvState::Active);
    assert!(net.devices[bob].store.departed(b, &alice).unwrap());
    assert!(
        net.epoch(bob, b) >= epoch + 2,
        "the laptop's leave commit, then Bob's commit of its SelfRemove"
    );
    for _ in 0..10 {
        net.advance(60_000);
    }
    assert_eq!(net.leaves(bob, b), ["bob@example.net"]);
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert_eq!(net.state(laptop, l), ConvState::Left);
    assert!(
        !net.events(phone)[seen..]
            .iter()
            .any(|e| matches!(e, Event::Conversation(ConversationEvent::Joined { .. })))
    );
}

/// The phone has left Bob's room for good and the laptop has left it too;
/// Bob invites Alice again. Returns the phone's and the laptop's
/// conversations, and the id of the invitation the phone holds.
fn invited_back(
    net: &mut Net,
    laptop: usize,
    phone: usize,
    bob: usize,
    b: ConversationId,
) -> (ConversationId, ConversationId, i64) {
    let (p, l) = phone_lost_and_left(net, laptop, phone, bob, b);
    let alice = net.devices[phone].uid.clone();
    net.connect(laptop);
    for _ in 0..5 {
        net.advance(60_000);
    }
    assert_eq!(net.leaves(bob, b), ["bob@example.net"]);
    let seen = net.events(phone).len();
    net.job(
        bob,
        Job::Invite {
            conv: b,
            uids: vec![alice.clone()],
        },
    )
    .unwrap();
    for _ in 0..3 {
        net.advance(60_000);
    }
    let invitation = net.events(phone)[seen..]
        .iter()
        .find_map(|e| match e {
            Event::Conversation(ConversationEvent::Invited {
                invitation,
                conversation,
                by,
                ..
            }) if *conversation == p && by.as_str() == "bob@example.net" => Some(*invitation),
            _ => None,
        })
        .expect("the phone was told of the invitation");
    (p, l, invitation)
}

/// The Welcomes device `d` holds for its user.
fn held(net: &Net, d: usize) -> Vec<crate::store::conversations::HeldWelcome> {
    net.devices[d]
        .store
        .held_welcome_rows(net.devices[d].account)
        .unwrap()
}

/// Whether device `d` can still open the held Welcome `held` with its
/// KeyPackage's private keys, and counts that KeyPackage as unused.
fn has_key_package(net: &Net, d: usize, held: &crate::store::conversations::HeldWelcome) -> bool {
    let account = net.devices[d].account;
    let crypto = Arc::new(risala_mls::RisalaCrypto::new().unwrap());
    net.write(d, |tx| {
        let opened = risala_mls::welcome::open_sealed_welcome(
            &tx.mls(&crypto),
            &held.welcome,
            std::slice::from_ref(&held.reference),
        );
        let listed = tx.key_package_refs(account)?.contains(&held.reference);
        Ok(opened.is_ok() && listed)
    })
}

/// 6.1: a Welcome from another member into a group the device left for
/// good is an invitation, held for the user and never joined on its own:
/// it cannot be told from that member's replacement of the device's leaf.
/// The laptop, which left in the usual way, is back at once, as after any
/// leave. Accepting the invitation joins.
#[test]
fn an_invitation_back_after_leaving_for_good_is_held_until_accepted() {
    let (mut net, laptop, phone, bob, b) = bobs_room_with_own_devices();
    let (p, l, invitation) = invited_back(&mut net, laptop, phone, bob, b);
    let alice = net.devices[phone].uid.clone();
    assert_eq!(net.state(laptop, l), ConvState::Active);
    // Held, not joined.
    for _ in 0..3 {
        net.advance(60_000);
    }
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert!(net.devices[phone].store.departed(p, &alice).unwrap());
    let holds = held(&net, phone);
    assert_eq!(holds.len(), 1);
    assert_eq!(holds[0].id, invitation);
    assert!(has_key_package(&net, phone, &holds[0]));
    assert_eq!(
        net.server
            .pending_welcomes(&alice, &net.devices[phone].device_id),
        0,
        "deleted from the server once held"
    );
    net.say(bob, b, "are you there?");
    assert!(
        net.texts(phone, p)
            .iter()
            .all(|(_, t)| t != "are you there?")
    );
    // Accepted, it is joined.
    let cx = net.cx(phone);
    let (joined, actions) = net.devices[phone].engine.accept_held(&cx, invitation);
    net.act(phone, actions);
    net.run();
    assert_eq!(joined, Ok(p));
    assert!(held(&net, phone).is_empty());
    for _ in 0..3 {
        net.advance(60_000);
    }
    assert_eq!(net.state(phone, p), ConvState::Active);
    assert!(!net.devices[phone].store.departed(p, &alice).unwrap());
    assert_eq!(net.leaves(bob, b).len(), 3);
    net.say(bob, b, "welcome back");
    assert!(
        net.texts(phone, p)
            .contains(&("bob@example.net".into(), "welcome back".into()))
    );
}

/// 6.1, 12.8: a declined invitation is forgotten, with its KeyPackage's
/// private keys, and the device stays out.
#[test]
fn a_declined_invitation_is_forgotten() {
    let (mut net, laptop, phone, bob, b) = bobs_room_with_own_devices();
    let (p, _, invitation) = invited_back(&mut net, laptop, phone, bob, b);
    let holds = held(&net, phone);
    assert_eq!(holds.len(), 1);
    assert!(has_key_package(&net, phone, &holds[0]));
    net.write(phone, |tx| {
        let held = tx.held_welcome(invitation)?.unwrap();
        group::forget_held(tx, &held)
    });
    assert!(held(&net, phone).is_empty());
    assert!(!has_key_package(&net, phone, &holds[0]));
    net.say(bob, b, "are you there?");
    for _ in 0..3 {
        net.advance(60_000);
    }
    assert_eq!(net.state(phone, p), ConvState::Left);
    assert!(
        net.texts(phone, p)
            .iter()
            .all(|(_, t)| t != "are you there?")
    );
    // Nothing is left to accept.
    let cx = net.cx(phone);
    let (joined, _) = net.devices[phone].engine.accept_held(&cx, invitation);
    assert!(joined.is_err());
}

/// 12.8: an invitation the user does not answer expires after the
/// retention period, as the server's Welcomes do, with its KeyPackage's
/// keys.
#[test]
fn an_invitation_not_answered_expires_after_retention() {
    let (mut net, laptop, phone, bob, b) = bobs_room_with_own_devices();
    let (p, _, _) = invited_back(&mut net, laptop, phone, bob, b);
    let holds = held(&net, phone);
    let retention = net.devices[phone].engine.config.retention_ms;
    net.advance(retention - 20 * 60_000);
    net.advance(10 * 60_000);
    assert_eq!(held(&net, phone).len(), 1, "not yet");
    net.advance(20 * 60_000);
    assert!(held(&net, phone).is_empty());
    assert!(!has_key_package(&net, phone, &holds[0]));
    assert_eq!(net.state(phone, p), ConvState::Left);
}

/// 6.1, 7.5: a device whose SelfRemove waits for a commit, and that finds
/// posts expired unread, leaves locally rather than being lost: it is
/// marked departed and told it left, not that it cannot follow.
#[test]
fn a_lost_device_that_was_leaving_leaves_locally() {
    let (mut net, alice, bob, carol, a) = team();
    let b = net.same_conv(bob, alice, a).unwrap();
    net.disconnect(bob);
    net.disconnect(carol);
    let own = net.devices[alice].uid.clone();
    let now = net.clock.now().unix_millis();
    assert!(!net.write(alice, |tx| group::leave(tx, a, &own, now)));
    net.tick();
    assert_eq!(net.state(alice, a), ConvState::Leaving);
    // Bob commits the SelfRemove while Alice is away, and says goodbye;
    // all of it expires before Alice is back.
    net.disconnect(alice);
    net.connect(bob);
    net.tick();
    net.say(bob, b, "bye alice");
    expire_all(&mut net, alice, a);
    net.connect(alice);
    net.tick();
    assert_eq!(net.state(alice, a), ConvState::Left);
    assert!(net.devices[alice].store.departed(a, &own).unwrap());
    assert!(left(&net, alice, a));
    assert!(!cannot_follow(&net, alice, a));
}

/// 6.1, 7.5: a public room the user leaves while the device cannot follow
/// it is not joined again.
#[test]
fn a_lost_public_room_the_user_leaves_is_not_joined_again() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device_with(
        "bob",
        "bob@example.net",
        Config {
            self_conversation: false,
            max_commit_wait_ms: 10 * 60 * 1000,
            ..Config::immediate()
        },
    );
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
    let now = net.clock.now().unix_millis();
    net.write(alice, |tx| {
        group::queue_intent(tx, a, &Intent::default(), now)?;
        Ok(())
    });
    net.tick();
    expire_all(&mut net, alice, a);
    net.connect(bob);
    net.tick();
    assert!(cannot_follow(&net, bob, b));
    assert_eq!(net.state(bob, b), ConvState::Lost);
    let own = net.devices[bob].uid.clone();
    let now = net.clock.now().unix_millis();
    assert!(net.write(bob, |tx| group::leave(tx, b, &own, now)));
    let posts = |net: &Net| {
        net.server
            .log
            .iter()
            .filter(|((d, _), verb)| *d == bob && verb == "POST")
            .count()
    };
    let before = posts(&net);
    for _ in 0..12 {
        net.advance(60_000);
    }
    assert_eq!(net.state(bob, b), ConvState::Left);
    assert_eq!(posts(&net), before, "no join proposal");
    assert!(!net.devices[bob].engine.stuck.contains_key(&b));
}

/// 12.7: own devices keep every box the group has had, so a lost device's
/// RESYNC that names the box from before a move still finds the group,
/// even once the old mailbox is no longer followed (7.8).
#[test]
fn a_resync_naming_a_box_from_before_a_move_finds_the_group() {
    let mut net = Net::new();
    let laptop = net.device("laptop", "alice@example.org");
    let phone = net.device_of("phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    let carol = net.device("carol", "carol@example.com");
    for d in [laptop, phone, bob, carol] {
        net.connect(d);
    }
    let me = net.job(laptop, Job::WithYourself).unwrap();
    net.same_conv(phone, laptop, me).expect("the phone is in");
    let a = net
        .job(
            laptop,
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
    let p = net.same_conv(phone, laptop, a).expect("the phone is in");
    let old_box = current_box(&net, phone, p);
    // The phone goes away. The laptop removes Carol, and the group moves
    // (7.8).
    net.disconnect(phone);
    let carol_device: [u8; 48] = net.devices[carol].device_id.clone().try_into().unwrap();
    let now = net.clock.now().unix_millis();
    net.write(laptop, |tx| {
        group::queue_intent(
            tx,
            a,
            &Intent {
                remove: vec![("carol@example.com".into(), Some(carol_device))],
                ..Intent::default()
            },
            now,
        )?;
        Ok(())
    });
    net.tick();
    assert_ne!(current_box(&net, laptop, a), old_box, "the group moved");
    // A day on, the laptop no longer follows the old mailbox, and its posts
    // expire before the phone is back.
    for _ in 0..25 {
        net.advance(60 * 60 * 1000);
    }
    assert!(
        net.devices[laptop]
            .store
            .mailbox_rows(a)
            .unwrap()
            .iter()
            .all(|m| m.mailbox != old_box),
        "no longer followed"
    );
    let head = net.server.posts(&old_box).last().unwrap().0;
    net.server.expire(&old_box, head);
    let before = net.epoch(laptop, a);
    // The phone finds the gap, and asks with RESYNC naming the old box: the
    // laptop finds the group by it and replaces the phone's leaf.
    net.connect(phone);
    net.tick();
    assert!(cannot_follow(&net, phone, p));
    for _ in 0..3 {
        net.advance(60_000);
    }
    assert!(
        net.epoch(laptop, a) > before,
        "the laptop replaced the phone's leaf"
    );
    assert_eq!(net.state(phone, p), ConvState::Active);
    assert_eq!(net.epoch(phone, p), net.epoch(laptop, a));
    let b = net.same_conv(bob, laptop, a).unwrap();
    net.say(bob, b, "welcome back");
    assert!(
        net.texts(phone, p)
            .contains(&("bob@example.net".into(), "welcome back".into()))
    );
}

/// 7.4, 12.9: a RESYNC that names the first seq found after a gap, a post
/// the server still keeps. The laptop holds it through a restart.
#[test]
fn a_lost_device_names_the_first_post_after_the_gap() {
    let (mut net, laptop, phone, bob, a) = own_devices_and_bob();
    let p = net.same_conv(phone, laptop, a).unwrap();
    let b = net.same_conv(bob, laptop, a).unwrap();
    net.disconnect(phone);
    net.say(bob, b, "expired");
    expire_all(&mut net, laptop, a);
    net.say(bob, b, "kept");
    let mailbox = current_box(&net, laptop, a);
    let kept = net.server.posts(&mailbox).last().unwrap().0;
    real_commit_wait(&mut net, laptop);
    net.connect(phone);
    net.tick();
    assert!(cannot_follow(&net, phone, p));
    assert_eq!(resyncs_held(&net, laptop), [(a, mailbox, kept)]);
    // The request outlives a restart of the laptop's app (LR-M4), and is
    // then answered.
    let before = net.epoch(laptop, a);
    net.restart(laptop);
    assert_eq!(resyncs_held(&net, laptop), [(a, mailbox, kept)]);
    for _ in 0..11 {
        net.advance(60_000);
    }
    assert!(resyncs_held(&net, laptop).is_empty());
    assert!(
        net.epoch(laptop, a) > before,
        "the laptop replaced the phone's leaf"
    );
    assert_eq!(net.state(phone, p), ConvState::Active);
}

/// 12.9: for a RESYNC in the group's current mailbox, an own device first
/// applies the posts there up to its seq. One naming a seq past the head
/// waits until that post is in; one naming the head, as a device whose
/// posts all expired sends, is acted on at once.
#[test]
fn a_resync_waits_for_the_posts_up_to_its_seq() {
    let (mut net, laptop, phone, bob, a) = own_devices_and_bob();
    let b = net.same_conv(bob, laptop, a).unwrap();
    let me = net
        .convs(phone)
        .into_iter()
        .find(|c| c.kind == ConvKind::WithYourself)
        .unwrap()
        .id;
    let mailbox = current_box(&net, laptop, a);
    let head = net.server.posts(&mailbox).last().unwrap().0;
    let before = net.epoch(laptop, a);
    net.lines(
        phone,
        me,
        vec![ContentLine::Resync {
            mailbox: Some(mailbox),
            seq: risala_proto::names::Seq::new(head + 1).unwrap(),
        }],
        false,
    );
    for _ in 0..3 {
        net.advance(60_000);
    }
    assert_eq!(net.epoch(laptop, a), before, "seq {} is not in", head + 1);
    // Bob's message is that post: the laptop applies it, then acts.
    net.say(bob, b, "hello");
    for _ in 0..3 {
        net.advance(60_000);
    }
    let after = net.epoch(laptop, a);
    assert!(after > before, "the laptop replaced the phone's leaf");
    // The head itself is applied already.
    let head = net.server.posts(&mailbox).last().unwrap().0;
    net.lines(
        phone,
        me,
        vec![ContentLine::Resync {
            mailbox: Some(mailbox),
            seq: risala_proto::names::Seq::new(head).unwrap(),
        }],
        false,
    );
    for _ in 0..3 {
        net.advance(60_000);
    }
    assert!(net.epoch(laptop, a) > after, "replaced again");
}
