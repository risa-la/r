//! Moving a mailbox after a removal (7.8): messages do not wait for the
//! move.

use risala_mls::framing::ContentType;
use risala_proto::command::Command;

use super::*;
use crate::store::conversations::MailboxRow;

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
    let crypto = Arc::new(risala_mls::RisalaCrypto::new().unwrap());
    let now = net.clock.now().unix_millis();
    let (message, next, token) = net.write(alice, |tx| {
        let row = tx.conversation(a)?;
        let p = tx.mls(&crypto);
        let mut group = risala_mls::openmls::group::MlsGroup::load(
            risala_mls::openmls_traits::OpenMlsProvider::storage(&p),
            &risala_mls::openmls::prelude::GroupId::from_slice(&row.group_id),
        )
        .unwrap()
        .unwrap();
        let carol_leaf = crate::store::conversations::read::leaves(tx.conn(), a)?
            .into_iter()
            .find(|l| l.device_id == Some(carol_device))
            .unwrap()
            .leaf;
        let token = risala_mls::token::SendToken::of_group(&group, crypto.as_ref()).unwrap();
        let state = tx.group_history(a)?;
        let profile = risala_mls::profile::RisalaProfile::new("", now).unwrap();
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
        Ok((out.message, out.next_token_hash, token))
    });
    net.server.now = now;
    let (response, live) = net.server.handle(
        (alice, Slot::Anonymous(0)),
        Command::Post {
            mailbox: old_box,
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
