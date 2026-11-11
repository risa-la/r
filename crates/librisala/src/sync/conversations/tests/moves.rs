//! Moving a mailbox after a removal (7.8): messages do not wait for the
//! move.

use risala_mls::framing::ContentType;
use risala_mls::message::{MessageHistory, Moved, SenderLog};
use risala_proto::command::Command;

use super::*;
use crate::store::conversations::MailboxRow;
use crate::store::messages::{MessageLog, OutboxState};

/// Alice's private room with Bob and Carol.
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
    (net, alice, bob, carol, a)
}

/// Device `d`, offline, removes the leaf of `device` from its group of
/// `conv` by hand, and posts the commit, so that it does not move the
/// group itself (7.8).
fn remove_by_hand(net: &mut Net, d: usize, conv: ConversationId, device: [u8; 48]) {
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
        let leaf = crate::store::conversations::read::leaves(tx.conn(), conv)?
            .into_iter()
            .find(|l| l.device_id == Some(device))
            .unwrap()
            .leaf;
        let token = risala_mls::token::SendToken::of_group(&group, crypto.as_ref()).unwrap();
        let state = tx.group_history(conv)?;
        let profile = risala_mls::profile::RisalaProfile::new("", now).unwrap();
        let out = risala_mls::group::commit(
            &p,
            &mut group,
            &profile,
            &state,
            risala_mls::group::Changes {
                remove: vec![risala_mls::openmls::prelude::LeafNodeIndex::new(leaf)],
                ..Default::default()
            },
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
    assert!(matches!(response.end, End::Ok(_)), "{:?}", response.end);
    net.deliver(live);
}

/// Device `d` writes `text` in `conv`, encrypted in its current epoch,
/// and keeps it instead of posting it.
fn write_unposted(net: &mut Net, d: usize, conv: ConversationId, text: &str) -> Vec<u8> {
    let uid = net.devices[d].uid.clone();
    let now = net.clock.now().unix_millis();
    let id = net.write(d, |tx| {
        content::queue_lines(
            tx,
            conv,
            &uid,
            vec![ContentLine::Text(Text::new(text))],
            false,
            now,
        )
    });
    let cx = net.cx(d);
    let engine = &mut net.devices[d].engine;
    let me = engine.me(&cx).unwrap();
    let mut out = Vec::new();
    engine
        .write(&cx, &me, &mut out, |tx, c| {
            let row = tx
                .pending_outbox(conv)?
                .into_iter()
                .find(|r| r.message_id == Some(id))
                .unwrap();
            let conv_row = tx.conversation(conv)?;
            let (post, _) = group::encrypt(tx, c, &conv_row, row.body.as_ref().unwrap())?;
            tx.update_outbox(row.id, OutboxState::Done, None, None, None)?;
            Ok(post)
        })
        .unwrap()
}

fn mailboxes(net: &Net, d: usize, conv: ConversationId) -> Vec<MailboxRow> {
    net.devices[d].store.mailbox_rows(conv).unwrap()
}

#[test]
fn messages_queued_before_a_move_go_first_in_the_current_epoch() {
    let (mut net, alice, bob, carol, a) = team();
    let b = net.same_conv(bob, alice, a).unwrap();
    let old_box = mailboxes(&net, alice, a)[0].mailbox;
    let carol_device: [u8; 48] = net.devices[carol].device_id.clone().try_into().unwrap();
    let epoch = net.epoch(alice, a);
    // Alice removes Carol, with a message queued behind the removal. Once
    // the removal wins, she moves the group (7.8); the message does not
    // wait for the move, but goes at once, in the epoch the removal made.
    let now = net.clock.now().unix_millis();
    let uid = net.devices[alice].uid.clone();
    net.write(alice, |tx| {
        group::queue_intent(
            tx,
            a,
            &Intent {
                remove: vec![("carol@example.com".into(), Some(carol_device))],
                ..Intent::default()
            },
            now,
        )?;
        content::queue_lines(
            tx,
            a,
            &uid,
            vec![ContentLine::Text(Text::new("carol is out"))],
            false,
            now,
        )?;
        Ok(())
    });
    net.tick();
    let posts = net.server.posts(&old_box);
    let kinds: Vec<ContentType> = posts.iter().map(|(_, k)| *k).collect();
    let n = kinds.len();
    assert_eq!(
        kinds[n - 3..],
        [
            ContentType::Commit,
            ContentType::Application,
            ContentType::Commit
        ],
        "the removal, the message, then the move"
    );
    assert_eq!(net.epoch(alice, a), epoch + 2, "removed, then moved");
    let current = mailboxes(&net, bob, b)
        .into_iter()
        .find(|m| m.current)
        .unwrap()
        .mailbox;
    assert_ne!(current, old_box, "the group moved");
    assert!(
        net.texts(bob, b)
            .contains(&("alice@example.org".into(), "carol is out".into()))
    );
    // Carol cannot read it.
    let c = net.same_conv(carol, alice, a).unwrap();
    assert_eq!(net.state(carol, c), ConvState::Left);
    assert!(net.texts(carol, c).iter().all(|(_, t)| t != "carol is out"));
}

#[test]
fn messages_do_not_wait_for_the_move_after_another_members_removal() {
    let (mut net, alice, bob, carol, a) = team();
    let b = net.same_conv(bob, alice, a).unwrap();
    let old_box = mailboxes(&net, alice, a)[0].mailbox;
    let carol_device: [u8; 48] = net.devices[carol].device_id.clone().try_into().unwrap();
    let epoch = net.epoch(bob, b);
    // Alice removes Carol and goes away before she moves the group: Bob's
    // device would move it only after the fallback wait (7.8). Her commit
    // is made and posted by hand.
    net.disconnect(alice);
    remove_by_hand(&mut net, alice, a, carol_device);
    assert_eq!(net.epoch(bob, b), epoch + 1, "carol is out");
    // Bob's message goes at once, in the epoch of the removal.
    net.say(bob, b, "carol is out");
    let posts = net.server.posts(&old_box);
    assert_eq!(posts.last().unwrap().1, ContentType::Application);
    assert_eq!(net.epoch(bob, b), epoch + 1, "no move yet");
    // The fallback moves the group later.
    net.advance(21 * 60 * 1000);
    assert!(net.epoch(bob, b) > epoch + 1, "moved by the fallback");
}

#[test]
fn a_late_message_in_the_old_mailbox_is_judged_as_of_the_move() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    let carol = net.device("carol", "carol@example.com");
    let laptop = net.device_of("carol's laptop", carol);
    let dave = net.device("dave", "dave@example.com");
    for d in [alice, bob, carol, laptop, dave] {
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
                    "dave@example.com".parse().unwrap(),
                ],
            },
        )
        .unwrap();
    net.tick();
    let b = net.same_conv(bob, alice, a).unwrap();
    let c = net.same_conv(carol, alice, a).unwrap();
    let l = net.same_conv(laptop, alice, a).unwrap();
    let old_box = mailboxes(&net, bob, b)[0].mailbox;
    // Alice removes Dave and goes away; the others move the group after
    // the fallback wait (7.8). Before the move, Carol writes a message that
    // the server holds back.
    let dave_device: [u8; 48] = net.devices[dave].device_id.clone().try_into().unwrap();
    net.disconnect(alice);
    remove_by_hand(&mut net, alice, a, dave_device);
    let late = write_unposted(&mut net, carol, c, "late but readable");
    net.advance(21 * 60 * 1000);
    let moved = mailboxes(&net, bob, b)
        .into_iter()
        .find(|m| m.current)
        .unwrap();
    assert_ne!(moved.mailbox, old_box, "the group moved");
    // In the new mailbox, Carol's laptop removes her phone's leaf.
    let carol_device: [u8; 48] = net.devices[carol].device_id.clone().try_into().unwrap();
    net.disconnect(laptop);
    remove_by_hand(&mut net, laptop, l, carol_device);
    assert!(
        net.epoch(bob, b) > moved.first_epoch,
        "carol's phone is out"
    );
    // Only now does the server hand out the message, in the old mailbox,
    // after the move. As of the move, its sender had not been removed, so
    // Bob shows it, as a device that read it before the removal would
    // (12.9).
    let t = net.clock.now().unix_millis();
    net.server.inject_post(&old_box, t, late);
    net.disconnect(bob);
    net.connect(bob);
    net.tick();
    assert!(
        net.texts(bob, b)
            .contains(&("carol@example.com".into(), "late but readable".into())),
        "{:?}",
        net.texts(bob, b)
    );
}

/// Two devices that apply a late post in the old mailbox and the new
/// mailbox's commits in different orders agree on reading it: each keeps
/// the secrets of the old mailbox's last epochs while it follows it, and
/// judges the post as of the move (12.9).
#[test]
fn devices_agree_on_a_late_message_whatever_they_apply_first() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    let carol = net.device("carol", "carol@example.com");
    let dave = net.device("dave", "dave@example.com");
    let erin = net.device("erin", "erin@example.net");
    for d in [alice, bob, carol, dave, erin] {
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
                    "dave@example.com".parse().unwrap(),
                    "erin@example.net".parse().unwrap(),
                ],
            },
        )
        .unwrap();
    net.tick();
    let b = net.same_conv(bob, alice, a).unwrap();
    let c = net.same_conv(carol, alice, a).unwrap();
    let e = net.same_conv(erin, alice, a).unwrap();
    let old_box = mailboxes(&net, bob, b)[0].mailbox;
    // Carol writes a message that the server holds back.
    let late = write_unposted(&mut net, carol, c, "late but readable");
    // Alice removes Dave, then moves the group (7.8).
    let dave_device: [u8; 48] = net.devices[dave].device_id.clone().try_into().unwrap();
    let now = net.clock.now().unix_millis();
    net.write(alice, |tx| {
        group::queue_intent(
            tx,
            a,
            &Intent {
                remove: vec![("dave@example.com".into(), Some(dave_device))],
                ..Intent::default()
            },
            now,
        )?;
        Ok(())
    });
    net.tick();
    let moved = mailboxes(&net, bob, b)
        .into_iter()
        .find(|m| m.current)
        .unwrap();
    assert_ne!(moved.mailbox, old_box, "the group moved");
    assert_eq!(net.epoch(erin, e), moved.first_epoch);
    // Only now does the server hand out Carol's message, in the old
    // mailbox. Erin fetches it at once, two epochs after its own.
    net.server.inject_post(&old_box, now, late);
    let readable = (
        "carol@example.com".to_owned(),
        "late but readable".to_owned(),
    );
    net.disconnect(erin);
    net.connect(erin);
    net.tick();
    assert!(
        net.texts(erin, e).contains(&readable),
        "{:?}",
        net.texts(erin, e)
    );
    // Bob first applies two more commits, in the new mailbox, and only
    // then fetches the old one. As of the move, the message is as readable
    // for him as for Erin.
    for (d, conv) in [(carol, c), (bob, b)] {
        let now = net.clock.now().unix_millis();
        net.write(d, |tx| {
            group::queue_intent(tx, conv, &Intent::default(), now)?;
            Ok(())
        });
        net.tick();
    }
    assert_eq!(net.epoch(bob, b), moved.first_epoch + 2);
    assert!(!net.texts(bob, b).contains(&readable));
    net.disconnect(bob);
    net.connect(bob);
    net.tick();
    assert!(
        net.texts(bob, b).contains(&readable),
        "{:?}",
        net.texts(bob, b)
    );

    // The store lists the move while the old mailbox is followed, and keeps
    // a slot's removals as risala-mls gives them; a day on, the move goes.
    let moves = |net: &Net| net.write(bob, |tx| Ok(MessageLog::new(tx.conn(), b).moves()));
    assert_eq!(
        moves(&net),
        vec![Moved {
            from: 0,
            to: moved.first_epoch
        }]
    );
    let removals = net.write(bob, |tx| {
        let leaf = risala_mls::openmls::prelude::LeafNodeIndex::new(40);
        let mut log = MessageLog::new(tx.conn(), b);
        log.set_sender(
            leaf,
            SenderLog {
                removals: vec![3, 9],
                ..SenderLog::default()
            },
        );
        let removals = log.sender(leaf).removals;
        log.finish()?;
        Ok(removals)
    });
    assert_eq!(removals, vec![3, 9]);
    net.advance(24 * 60 * 60 * 1000 + 60_000);
    assert!(moves(&net).is_empty());
}

/// A device that was offline for more than 2 hours, from just after a
/// removal to well after the move that came within the hour of it, reads a
/// late post in the old mailbox as the others do. Past epochs go by the
/// posts' `t` alone, judged in the old mailbox as of the move, never by
/// the device's own clock (12.9).
#[test]
fn a_device_offline_across_a_move_reads_a_late_post_as_the_others_do() {
    const MINUTE: u64 = 60 * 1000;
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    let carol = net.device("carol", "carol@example.com");
    let dave = net.device("dave", "dave@example.com");
    let erin = net.device("erin", "erin@example.net");
    for d in [alice, bob, carol, dave, erin] {
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
                    "dave@example.com".parse().unwrap(),
                    "erin@example.net".parse().unwrap(),
                ],
            },
        )
        .unwrap();
    net.tick();
    let b = net.same_conv(bob, alice, a).unwrap();
    let c = net.same_conv(carol, alice, a).unwrap();
    let e = net.same_conv(erin, alice, a).unwrap();
    let old_box = mailboxes(&net, bob, b)[0].mailbox;
    // Carol writes a message that the server holds back. Alice removes
    // Dave and goes away, so the others move the group after the fallback
    // wait (7.8). Bob applies the removal and goes offline at once.
    let late = write_unposted(&mut net, carol, c, "late but readable");
    let dave_device: [u8; 48] = net.devices[dave].device_id.clone().try_into().unwrap();
    net.disconnect(alice);
    remove_by_hand(&mut net, alice, a, dave_device);
    let epoch = net.epoch(bob, b);
    net.disconnect(bob);
    net.advance(21 * MINUTE);
    let moved = mailboxes(&net, erin, e)
        .into_iter()
        .find(|m| m.current)
        .unwrap();
    assert_ne!(moved.mailbox, old_box, "the group moved");
    assert_eq!(net.epoch(bob, b), epoch, "bob has not seen the move");
    // Within the hour of the removal, the server hands out Carol's message
    // in the old mailbox, after the move, and Erin reads it.
    net.advance(9 * MINUTE);
    let t = net.clock.now().unix_millis();
    net.server.inject_post(&old_box, t, late);
    net.disconnect(erin);
    net.connect(erin);
    net.tick();
    let readable = (
        "carol@example.com".to_owned(),
        "late but readable".to_owned(),
    );
    assert!(net.texts(erin, e).contains(&readable));
    // Bob's app runs on, offline, for more than 2 hours: its upkeep runs
    // with no connection. Then he is back, and reads it too.
    net.clock.advance(2 * 60 * MINUTE + 10 * MINUTE);
    let cx = net.cx(bob);
    let now = net.clock.now();
    let actions = net.devices[bob].engine.handle(&cx, &Input::Tick { now });
    assert!(
        actions.iter().all(|a| !matches!(a, Action::Send { .. })),
        "offline"
    );
    net.connect(bob);
    net.tick();
    assert!(
        net.texts(bob, b).contains(&readable),
        "{:?}",
        net.texts(bob, b)
    );
}

/// 7.4: posts that expired unread in a mailbox the group has moved away
/// from are not a gap. The device has applied every commit there, the
/// move included (7.8), so it goes on following the group, and asks
/// nobody to replace its leaf.
#[test]
fn posts_expired_in_the_mailbox_moved_from_are_not_a_gap() {
    let (mut net, alice, bob, carol, a) = team();
    let b = net.same_conv(bob, alice, a).unwrap();
    let old_box = mailboxes(&net, alice, a)[0].mailbox;
    let carol_device: [u8; 48] = net.devices[carol].device_id.clone().try_into().unwrap();
    // Two messages of Alice's, written before the move, that the server
    // holds back.
    let first = write_unposted(&mut net, alice, a, "held back");
    let second = write_unposted(&mut net, alice, a, "late");
    // Alice removes Carol, and the group moves (7.8).
    let now = net.clock.now().unix_millis();
    net.write(alice, |tx| {
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
    let current = mailboxes(&net, bob, b)
        .into_iter()
        .find(|m| m.current)
        .unwrap()
        .mailbox;
    assert_ne!(current, old_box, "the group moved");
    // While Bob is away, the server hands both out late in the old
    // mailbox, and the first expires before Bob reads it.
    net.disconnect(bob);
    let t = net.clock.now().unix_millis();
    let seq = net.server.inject_post(&old_box, t, first);
    net.server.inject_post(&old_box, t, second);
    net.server.expire(&old_box, seq);
    net.connect(bob);
    net.tick();
    assert!(
        mailboxes(&net, bob, b)
            .iter()
            .any(|m| m.mailbox == old_box && m.sync_point > seq),
        "Bob read the old mailbox past the gap"
    );
    assert_eq!(net.state(bob, b), ConvState::Active);
    assert!(!net.events(bob).iter().any(|e| matches!(
        e,
        Event::Conversation(ConversationEvent::CannotFollow { conversation }) if *conversation == b
    )));
    // It goes on in the group.
    net.say(alice, a, "still here");
    assert!(
        net.texts(bob, b)
            .contains(&("alice@example.org".into(), "still here".into()))
    );
}
