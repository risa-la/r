//! Recovery paths (7.8, 12.7, 12.8), guests' report conversations (12.7,
//! 5.8) and posts that come as blob-refs (12.12), against the in-memory
//! server.

use std::sync::atomic::Ordering;

use risala_proto::command::Command;

use super::*;

fn peer(uid: &str) -> Job {
    Job::Direct {
        peer: uid.parse().unwrap(),
    }
}

#[test]
fn a_refused_welcome_is_told_and_the_device_added_again() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    // 12.8: the server refuses the first Welcome; the committer cannot know
    // who holds the device's place, tells its user, and adds it again.
    net.server.refuse_welcomes = 1;
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    net.tick();
    assert!(net.events(alice).iter().any(|e| matches!(
        e,
        Event::Conversation(ConversationEvent::WelcomeRefused { uid: Some(u), .. })
            if u.as_str() == "bob@example.net"
    )));
    let b = net.same_conv(bob, alice, a).expect("bob joined after all");
    assert_eq!(net.epoch(bob, b), net.epoch(alice, a));
    assert_eq!(net.epoch(alice, a), 2, "the add, then the replacement");
    net.say(alice, a, "there you are");
    assert_eq!(
        net.texts(bob, b),
        [("alice@example.org".into(), "there you are".into())]
    );
}

#[test]
fn a_server_that_refuses_every_welcome_cannot_loop_the_group() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    net.server.refuse_welcomes = usize::MAX;
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    net.tick();
    // One replacement, not one per refusal.
    assert_eq!(net.epoch(alice, a), 2);
}

/// Alice's laptop and phone, and Bob, in a direct conversation and the
/// laptop's and phone's conversation with themselves.
fn two_devices_and_bob() -> (Net, usize, usize, usize, ConversationId, ConversationId) {
    let mut net = Net::new();
    let laptop = net.device("laptop", "alice@example.org");
    let phone = net.device_of("phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    for d in [laptop, phone, bob] {
        net.connect(d);
    }
    let me = net.job(laptop, Job::WithYourself).unwrap();
    net.same_conv(phone, laptop, me).expect("the phone is in");
    let direct = net.job(laptop, peer("bob@example.net")).unwrap();
    net.same_conv(phone, laptop, direct)
        .expect("the phone is in");
    net.same_conv(bob, laptop, direct).expect("bob is in");
    (net, laptop, phone, bob, me, direct)
}

#[test]
fn a_resync_nobody_answers_goes_to_the_own_devices_after_an_hour() {
    let (mut net, laptop, phone, bob, _, direct) = two_devices_and_bob();
    let p = net.same_conv(phone, laptop, direct).unwrap();
    let before = net.epoch(laptop, direct);
    // The phone cannot follow the direct conversation, and posted RESYNC
    // there an hour ago (12.7).
    let now = net.clock.now().unix_millis();
    net.devices[phone].engine.resync_since.insert(p, (now, 1));
    net.advance(60 * 60 * 1000 + 1);
    // It asked its own devices with `RESYNC <box> <seq>` in the
    // conversation with itself; the laptop replaced its leaf, and the phone
    // is welcomed back into the conversation it has.
    let after = net.epoch(laptop, direct);
    assert!(after > before, "the laptop committed a replacement");
    assert_eq!(net.epoch(phone, p), after);
    assert_eq!(net.state(phone, p), ConvState::Active);
    assert_eq!(
        net.leaves(bob, net.same_conv(bob, laptop, direct).unwrap())
            .len(),
        3
    );
    net.say(
        bob,
        net.same_conv(bob, laptop, direct).unwrap(),
        "still here?",
    );
    assert!(
        net.texts(phone, p)
            .contains(&("bob@example.net".into(), "still here?".into()))
    );
}

#[test]
fn the_own_identitys_stale_leaves_are_replaced() {
    let (mut net, laptop, phone, bob, _, direct) = two_devices_and_bob();
    let p = net.same_conv(phone, laptop, direct).unwrap();
    net.disconnect(phone);
    // 12.7: a leaf of the own identity older than retention plus a day is
    // replaced, by removing it and adding the device again.
    let before = net.epoch(laptop, direct);
    for _ in 0..9 {
        net.advance(24 * 60 * 60 * 1000);
    }
    assert!(net.epoch(laptop, direct) > before);
    net.connect(phone);
    net.tick();
    assert_eq!(net.epoch(phone, p), net.epoch(laptop, direct));
    let b = net.same_conv(bob, laptop, direct).unwrap();
    net.say(bob, b, "welcome back");
    assert!(
        net.texts(phone, p)
            .contains(&("bob@example.net".into(), "welcome back".into()))
    );
}

#[test]
fn any_member_moves_the_mailbox_if_the_remover_did_not() {
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
                members: vec!["bob@example.net".parse().unwrap()],
            },
        )
        .unwrap();
    net.job(
        alice,
        Job::Invite {
            conv: a,
            uids: vec!["carol@example.com".parse().unwrap()],
        },
    )
    .unwrap();
    net.tick();
    let b = net.same_conv(bob, alice, a).unwrap();
    net.same_conv(carol, alice, a).expect("carol is in");
    let old_box = net.devices[bob].store.mailbox_rows(b).unwrap()[0].mailbox;
    // Alice removes Carol, and goes away before she can move the group:
    // her commit is made and posted by hand.
    net.disconnect(alice);
    let crypto = Arc::new(risala_mls::RisalaCrypto::new().unwrap());
    let (message, next, token, mailbox) = net.write(alice, |tx| {
        let row = tx.conversation(a)?;
        let p = tx.mls(&crypto);
        let mut group = risala_mls::openmls::group::MlsGroup::load(
            risala_mls::openmls_traits::OpenMlsProvider::storage(&p),
            &risala_mls::openmls::prelude::GroupId::from_slice(&row.group_id),
        )
        .unwrap()
        .unwrap();
        let carol_leaf = tx
            .conversation(a)
            .ok()
            .and_then(|_| {
                crate::store::conversations::read::leaves(tx.conn(), a)
                    .ok()?
                    .into_iter()
                    .find(|l| l.uid.as_str() == "carol@example.com")
            })
            .unwrap()
            .leaf;
        let token = risala_mls::token::SendToken::of_group(&group, crypto.as_ref()).unwrap();
        let state = tx.group_history(a)?;
        let profile = risala_mls::profile::RisalaProfile::new("", START + 60_000).unwrap();
        let out = risala_mls::group::commit(
            &p,
            &mut group,
            &profile,
            &state,
            risala_mls::group::Changes {
                remove: vec![risala_mls::openmls::prelude::LeafNodeIndex::new(carol_leaf)],
                ..Default::default()
            },
        )
        .unwrap();
        Ok((
            out.message,
            out.next_token_hash,
            token,
            tx.current_mailbox(a)?.mailbox,
        ))
    });
    net.server.now = net.clock.now().unix_millis();
    let (response, live) = net.server.handle(
        (alice, Slot::Anonymous(0)),
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
    assert!(matches!(response.end, End::Ok(_)), "{:?}", response.end);
    net.deliver(live);
    assert_eq!(net.leaves(bob, b).len(), 2, "carol is out");
    // 7.8: no move within 10 minutes of the removal: Bob's device makes it.
    net.advance(5 * 60 * 1000);
    assert_eq!(
        net.devices[bob].store.mailbox_rows(b).unwrap()[0].mailbox,
        old_box
    );
    net.advance(6 * 60 * 1000);
    let rows = net.devices[bob].store.mailbox_rows(b).unwrap();
    let current = rows.iter().find(|m| m.current).unwrap().mailbox;
    assert_ne!(current, old_box, "the group moved");
}

#[test]
fn a_device_alone_in_its_epoch_after_a_day_warns_and_asks_to_be_added_again() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    let b = net.same_conv(bob, alice, a).unwrap();
    // Bob joined two days ago and has seen nobody post in his epoch since
    // (12.8).
    let joined = net.clock.now().unix_millis();
    net.write(bob, |tx| {
        tx.set_joined(b, joined)?;
        Ok(())
    });
    net.clock.advance(2 * 24 * 60 * 60 * 1000);
    let cx = net.cx(bob);
    let engine = &mut net.devices[bob].engine;
    let me = engine.me(&cx).unwrap();
    let mut out = Vec::new();
    engine.check_branch(&cx, &me, b, &mut out);
    assert!(out.iter().any(|a| matches!(
        a,
        Action::Emit(Event::Conversation(
            ConversationEvent::MaybeOtherBranch { .. }
        ))
    )));
    let adds = out
        .iter()
        .filter(|a| {
            matches!(
                a,
                Action::Send {
                    command: Command::KeyPkg(risala_proto::command::KeyPkgCommand::Add { .. }),
                    ..
                }
            )
        })
        .count();
    assert_eq!(adds, 10, "fresh KeyPackages, to be added again");
    // Once is enough.
    let mut again = Vec::new();
    engine.check_branch(&cx, &me, b, &mut again);
    assert!(again.is_empty());
    // A device that has seen others post in its epoch does not warn.
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    let b = net.same_conv(bob, alice, a).unwrap();
    net.say(alice, a, "hi");
    net.clock.advance(2 * 24 * 60 * 60 * 1000);
    let cx = net.cx(bob);
    let engine = &mut net.devices[bob].engine;
    let me = engine.me(&cx).unwrap();
    let mut out = Vec::new();
    engine.check_branch(&cx, &me, b, &mut out);
    assert!(out.is_empty());
}

#[test]
fn a_guests_report_conversation_waits_for_an_owner_to_accept_it() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    let sam = net.guest("sam", "~sam");
    for d in [alice, bob, sam] {
        net.connect(d);
    }
    // Alice owns a public room that lets guests in; Bob owns none.
    net.job(
        alice,
        Job::PublicRoom {
            room: "#general".parse().unwrap(),
        },
    )
    .unwrap();
    // Identities do not make report conversations, and guests do nothing
    // else (4.2, 5.8).
    assert!(
        net.job(
            alice,
            Job::Report {
                peer: "bob@example.net".parse().unwrap()
            }
        )
        .is_err()
    );
    assert!(net.job(sam, peer("alice@example.org")).is_err());

    let s = net
        .job(
            sam,
            Job::Report {
                peer: "alice@example.org".parse().unwrap(),
            },
        )
        .expect("the guest made it");
    net.tick();
    // 12.7: Alice's device holds it until she accepts.
    assert!(net.same_conv(alice, sam, s).is_none());
    let offer = net
        .events(alice)
        .iter()
        .find_map(|e| match e {
            Event::Conversation(ConversationEvent::ReportOffered { offer, guest, .. })
                if guest.as_str() == "~sam" =>
            {
                Some(*offer)
            }
            _ => None,
        })
        .expect("offered");
    let cx = net.cx(alice);
    let (joined, actions) = net.devices[alice].engine.accept_held(&cx, offer);
    net.act(alice, actions);
    net.run();
    let a = joined.expect("accepted");
    assert_eq!(net.same_conv(alice, sam, s), Some(a));
    let row = net.devices[alice]
        .store
        .conversation_row(a)
        .unwrap()
        .unwrap();
    assert_eq!(row.kind, ConvKind::Direct);
    assert_eq!(row.peer.unwrap().as_str(), "~sam");
    // Only REPORT lines count from the guest (5.8): its TEXT is ignored.
    net.say(sam, s, "look at this");
    assert!(net.texts(alice, a).is_empty());

    // Bob, who owns no public room here, never takes one.
    let s2 = net
        .job(
            sam,
            Job::Report {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .expect("the guest made it");
    net.tick();
    assert!(net.same_conv(bob, sam, s2).is_none());
    assert!(!net.events(bob).iter().any(|e| matches!(
        e,
        Event::Conversation(ConversationEvent::ReportOffered { .. })
    )));
}

#[test]
fn posts_that_come_as_blobs_are_fetched_through_the_blob_store() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let a = net.job(alice, peer("bob@example.net")).unwrap();
    let b = net.same_conv(bob, alice, a).unwrap();
    net.server.blob_posts = true;

    // 12.12: the blob store has it.
    net.say(alice, a, "in a blob");
    assert_eq!(
        net.texts(bob, b),
        [("alice@example.org".into(), "in a blob".into())]
    );

    // Still being fetched: the mailbox waits, and goes on once it is in.
    net.blob_mode.store(1, Ordering::SeqCst);
    net.say(alice, a, "later");
    net.say(alice, a, "and after");
    assert_eq!(net.texts(bob, b).len(), 1);
    net.blob_mode.store(0, Ordering::SeqCst);
    net.tick();
    let texts: Vec<String> = net.texts(bob, b).into_iter().map(|(_, t)| t).collect();
    assert_eq!(texts, ["in a blob", "later", "and after"]);

    // No blob store: the post is skipped, and shows as a gap.
    net.blob_mode.store(2, Ordering::SeqCst);
    net.say(alice, a, "lost");
    net.blob_mode.store(0, Ordering::SeqCst);
    net.say(alice, a, "found");
    let texts: Vec<String> = net.texts(bob, b).into_iter().map(|(_, t)| t).collect();
    assert_eq!(texts.last().map(String::as_str), Some("found"));
    assert!(!texts.contains(&"lost".to_string()));
    assert!(!net.devices[bob].store.gap_rows(b).unwrap().is_empty());
}
