//! Scenarios with two and three devices.

use risala_mls::framing::ContentType;
use risala_proto::content::{ContentLine, Target as TextTarget, Text};

use super::*;

fn alice_and_bob() -> (Net, usize, usize) {
    let mut net = Net::new();
    let a = net.device("alice", "alice@example.org");
    let b = net.device("bob", "bob@example.net");
    net.connect(a);
    net.connect(b);
    (net, a, b)
}

#[test]
fn key_packages_are_uploaded_on_sign_in() {
    let (net, a, _) = alice_and_bob();
    let dev = &net.devices[a];
    // Ten ordinary ones and one of last resort (12.5).
    assert_eq!(
        net.server
            .key_package_count("alice@example.org", &dev.device_id),
        11
    );
}

#[test]
fn direct_conversation_between_two_devices() {
    let (mut net, a, b) = alice_and_bob();
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let row = net.devices[a]
        .store
        .conversation_row(conv)
        .unwrap()
        .unwrap();
    assert_eq!(row.kind, ConvKind::Direct);
    assert_eq!(row.state, ConvState::Active);
    assert_eq!(row.epoch, 1);
    let bconv = net.same_conv(b, a, conv).expect("bob joined by Welcome");
    let brow = net.devices[b]
        .store
        .conversation_row(bconv)
        .unwrap()
        .unwrap();
    assert_eq!(brow.peer.unwrap().as_str(), "alice@example.org");
    assert_eq!(brow.kind, ConvKind::Direct);
    assert_eq!(net.leaves(b, bconv).len(), 2);

    net.say(a, conv, "hello bob");
    assert_eq!(
        net.texts(b, bconv),
        vec![("alice@example.org".into(), "hello bob".into())]
    );
    net.say(b, bconv, "hi alice");
    assert_eq!(
        net.texts(a, conv),
        vec![
            ("alice@example.org".into(), "hello bob".into()),
            ("bob@example.net".into(), "hi alice".into())
        ]
    );
    // Own messages get their seq once their post is applied.
    let own = net.messages(a, conv);
    assert!(own.iter().all(|m| m.seq.is_some()), "{own:?}");
    // The Welcome is gone from the server once used (12.8).
    let bob = &net.devices[b];
    assert_eq!(net.server.pending_welcomes(&bob.uid, &bob.device_id), 0);
    // Everything was posted as PrivateMessages: commit, then messages.
    let mailbox = net.devices[a].store.mailbox_rows(conv).unwrap()[0].mailbox;
    let kinds: Vec<ContentType> = net
        .server
        .posts(&mailbox)
        .into_iter()
        .map(|p| p.1)
        .collect();
    assert_eq!(
        kinds,
        [
            ContentType::Commit,
            ContentType::Application,
            ContentType::Application
        ]
    );
}

#[test]
fn three_devices_two_of_one_identity() {
    let mut net = Net::new();
    let a1 = net.device("alice1", "alice@example.org");
    let a2 = net.device("alice2", "alice@example.org");
    let b = net.device("bob", "bob@example.net");
    for d in [a1, a2, b] {
        net.connect(d);
    }
    let conv = net
        .job(
            a1,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let c2 = net
        .same_conv(a2, a1, conv)
        .expect("alice's other device was added");
    let cb = net.same_conv(b, a1, conv).expect("bob was added");
    assert_eq!(net.leaves(a1, conv).len(), 3);
    net.say(b, cb, "to both of you");
    assert_eq!(net.texts(a1, conv).len(), 1);
    assert_eq!(net.texts(a2, c2).len(), 1);
    net.say(a2, c2, "from my phone");
    assert_eq!(net.texts(b, cb).len(), 2);
    // Alice's first device sees its other device's message too.
    assert_eq!(net.texts(a1, conv)[1].1, "from my phone");
}

#[test]
fn private_room_invite_remove_and_topic() {
    let mut net = Net::new();
    let a = net.device("alice", "alice@example.org");
    let b = net.device("bob", "bob@example.net");
    let c = net.device("carol", "carol@example.com");
    for d in [a, b, c] {
        net.connect(d);
    }
    let room = net
        .job(
            a,
            Job::PrivateRoom {
                name: "Plans".into(),
                members: vec!["bob@example.net".parse().unwrap()],
            },
        )
        .unwrap();
    let rb = net.same_conv(b, a, room).unwrap();
    assert_eq!(net.convs(b)[0].name, "Plans");
    assert_eq!(net.convs(b)[0].kind, ConvKind::Private);
    // An owner invites carol (6.1).
    net.job(
        a,
        Job::Invite {
            conv: room,
            uids: vec!["carol@example.com".parse().unwrap()],
        },
    )
    .unwrap();
    net.tick();
    let rc = net.same_conv(c, a, room).expect("carol was invited");
    net.say(c, rc, "thanks for having me");
    assert_eq!(net.texts(a, room).len(), 1);
    assert_eq!(net.texts(b, rb).len(), 1);

    // The topic, by a GroupContextExtensions proposal (6.2).
    let ext = {
        let cx = net.cx(a);
        let me = net.devices[a].engine.me(&cx).unwrap();
        let _ = me;
        let row = net.devices[a]
            .store
            .conversation_row(room)
            .unwrap()
            .unwrap();
        let mut out = Vec::new();
        net.devices[a]
            .engine
            .write(
                &cx,
                &net.devices[a].engine.me.clone().unwrap(),
                &mut out,
                |tx, c| {
                    let g = group::load(tx, c, &row.group_id)?;
                    Ok(risala_mls::group::conversation(&g).unwrap())
                },
            )
            .unwrap()
    };
    let mut new = ext.clone();
    new.topic = "Saturday".into();
    let now = net.clock.now().unix_millis();
    net.write(a, |tx| {
        group::queue_intent(
            tx,
            room,
            &Intent {
                conversation: Some(new.encode()),
                ..Intent::default()
            },
            now,
        )
    });
    net.tick();
    assert_eq!(net.convs(b)[0].topic, "Saturday");

    // Alice has started the last three epochs: her next commit waits until
    // ten minutes after her last (12.7, streaks).
    net.advance(11 * 60 * 1000);
    let now = net.clock.now().unix_millis();
    // Removing carol: her device is out, and reads nothing more.
    net.write(a, |tx| {
        group::queue_intent(
            tx,
            room,
            &Intent {
                remove: vec![(
                    "carol@example.com".into(),
                    Some(net.devices[c].device_id.clone().try_into().unwrap()),
                )],
                ..Intent::default()
            },
            now,
        )
    });
    net.tick();
    assert_eq!(net.state(c, rc), ConvState::Left);
    assert_eq!(net.leaves(b, rb).len(), 2);
    // The remover moves the group to a new mailbox (7.8), which carol
    // never learns of: after another wait, since alice started the last
    // three epochs again.
    net.advance(11 * 60 * 1000);
    let old_box = net.devices[c].store.mailbox_rows(rc).unwrap()[0].mailbox;
    let new_box = net.devices[b].store.mailbox_rows(rb).unwrap()[0].clone();
    assert!(new_box.current);
    assert_ne!(new_box.mailbox, old_box);
    assert_eq!(
        net.devices[a].store.mailbox_rows(room).unwrap()[0].mailbox,
        new_box.mailbox
    );
    net.say(b, rb, "carol is gone");
    assert_eq!(net.texts(a, room).len(), 2);
    assert_eq!(net.texts(c, rc).len(), 1);
    // Nothing more was posted to the old mailbox after the move.
    let old_posts = net.server.posts(&old_box);
    assert_eq!(old_posts.last().unwrap().1, ContentType::Commit);
}

#[test]
fn racing_commits_the_first_valid_one_wins() {
    let (mut net, a, b) = alice_and_bob();
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let cb = net.same_conv(b, a, conv).unwrap();
    // Both queue a fresh-leaf commit for the same epoch before either
    // sees the other's.
    let now = net.clock.now().unix_millis();
    net.write(a, |tx| {
        group::queue_intent(tx, conv, &Intent::default(), now)
    });
    net.write(b, |tx| group::queue_intent(tx, cb, &Intent::default(), now));
    net.queue.push_back((a, super::Owned::Tick));
    net.queue.push_back((b, super::Owned::Tick));
    net.run();
    net.tick();
    let mailbox = net.devices[a].store.mailbox_rows(conv).unwrap()[0].mailbox;
    let commits = net
        .server
        .posts(&mailbox)
        .into_iter()
        .filter(|p| p.1 == ContentType::Commit)
        .count();
    // The creation, the two racing commits, and the loser's made again.
    assert_eq!(commits, 4);
    assert_eq!(net.epoch(a, conv), 3);
    assert_eq!(net.epoch(b, cb), 3);
    net.say(a, conv, "still here?");
    net.say(b, cb, "yes");
    assert_eq!(net.texts(a, conv).len(), 2);
    assert_eq!(net.texts(b, cb).len(), 2);
}

#[test]
fn leaving_with_self_remove() {
    let (mut net, a, b) = alice_and_bob();
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let cb = net.same_conv(b, a, conv).unwrap();
    // Bob leaves: a SelfRemove, which alice commits (6.1).
    let now = net.clock.now().unix_millis();
    net.write(b, |tx| {
        tx.set_state(cb, ConvState::Leaving)?;
        group::queue_self_remove(tx, cb, now)
    });
    net.tick();
    net.tick();
    assert_eq!(net.state(b, cb), ConvState::Left);
    assert_eq!(net.leaves(a, conv), vec!["alice@example.org".to_owned()]);
}

#[test]
fn edits_reactions_and_deletes() {
    let (mut net, a, b) = alice_and_bob();
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let cb = net.same_conv(b, a, conv).unwrap();
    let id = net.say(a, conv, "helo");
    let mid = risala_proto::content::MessageId::from_bytes(id);
    net.lines(
        a,
        conv,
        vec![ContentLine::Text(Text {
            text: "hello".into(),
            target: Some(TextTarget::Edit(mid)),
            file: None,
        })],
        false,
    );
    net.lines(
        b,
        cb,
        vec![ContentLine::Text(Text {
            text: "👍".into(),
            target: Some(TextTarget::React(mid)),
            file: None,
        })],
        false,
    );
    let bob_view = net.messages(b, cb);
    assert_eq!(bob_view.len(), 3);
    assert!(
        bob_view
            .iter()
            .any(|m| m.edit_of == Some(id) && m.text.as_deref() == Some("hello"))
    );
    // Bob cannot delete alice's message in a direct conversation (5.4).
    net.lines(b, cb, vec![ContentLine::Delete { id: mid }], false);
    assert!(
        !net.messages(a, conv)
            .iter()
            .find(|m| m.message_id == id)
            .unwrap()
            .deleted
    );
    // Alice can: the message, its edit and its reaction are erased.
    net.lines(a, conv, vec![ContentLine::Delete { id: mid }], false);
    let bob_view = net.messages(b, cb);
    assert!(
        bob_view.iter().all(|m| m.deleted && m.text.is_none()),
        "{bob_view:?}"
    );
}

#[test]
fn typing_is_live_and_not_kept() {
    let (mut net, a, b) = alice_and_bob();
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let mailbox = net.devices[a].store.mailbox_rows(conv).unwrap()[0].mailbox;
    let before = net.server.posts(&mailbox).len();
    net.lines(a, conv, vec![ContentLine::Typing], true);
    assert_eq!(net.server.posts(&mailbox).len(), before);
    assert!(net.devices[b].events.iter().any(|e| matches!(
        e,
        Event::Conversation(ConversationEvent::Typing { uid, .. }) if uid.as_str() == "alice@example.org"
    )));
}

#[test]
fn catching_up_after_being_offline() {
    let (mut net, a, b) = alice_and_bob();
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let cb = net.same_conv(b, a, conv).unwrap();
    net.disconnect(b);
    for i in 0..75 {
        net.say(a, conv, &format!("message {i}"));
    }
    net.connect(b);
    net.tick();
    let texts = net.texts(b, cb);
    assert_eq!(texts.len(), 75);
    assert_eq!(texts[74].1, "message 74");
    let mb = net.devices[b].store.mailbox_rows(cb).unwrap()[0].clone();
    assert_eq!(mb.sync_point, 76);
    // FETCH went in pages of 50 (7.1, 7.4).
    let fetches = net
        .server
        .log
        .iter()
        .filter(|(conn, verb)| conn.0 == b && verb == "FETCH")
        .count();
    assert!(fetches >= 2, "{fetches}");
}

#[test]
fn a_stale_post_is_sent_again() {
    let (mut net, a, b) = alice_and_bob();
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let cb = net.same_conv(b, a, conv).unwrap();
    let mailbox = net.devices[a].store.mailbox_rows(conv).unwrap()[0].mailbox;
    net.server.stale_next.insert(mailbox.to_string());
    let posts = |net: &Net| {
        net.server
            .log
            .iter()
            .filter(|(c, v)| c.0 == a && v == "POST")
            .count()
    };
    let before = posts(&net);
    net.say(a, conv, "once");
    net.tick();
    // Refused with ERR stale, then posted again after TOKEN put the
    // epoch's hash back (7.2, 12.9), and shown once.
    assert_eq!(posts(&net) - before, 2);
    assert!(net.server.log.iter().any(|(c, v)| c.0 == a && v == "TOKEN"));
    assert_eq!(
        net.texts(b, cb),
        vec![("alice@example.org".into(), "once".into())]
    );
}

#[test]
fn self_conversation_carries_read_markers_and_blocks() {
    let mut net = Net::new();
    let a1 = net.device("alice1", "alice@example.org");
    let a2 = net.device("alice2", "alice@example.org");
    let b = net.device("bob", "bob@example.net");
    for d in [a1, a2, b] {
        net.connect(d);
    }
    let me = net.job(a1, Job::WithYourself).unwrap();
    let me2 = net
        .same_conv(a2, a1, me)
        .expect("the other device was added");
    assert_eq!(
        net.convs(a2).iter().find(|c| c.id == me2).unwrap().kind,
        ConvKind::WithYourself
    );
    let conv = net
        .job(
            a1,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let c2 = net.same_conv(a2, a1, conv).unwrap();
    let cb = net.same_conv(b, a1, conv).unwrap();
    net.say(b, cb, "one");
    net.say(b, cb, "two");
    // Alice reads on her first device; the second learns it (7.7).
    let seq = net.messages(a1, conv).last().unwrap().seq.unwrap();
    let mailbox = net.devices[a1].store.mailbox_rows(conv).unwrap()[0].mailbox;
    let check = {
        let row = net.devices[a1]
            .store
            .conversation_row(conv)
            .unwrap()
            .unwrap();
        let cx = net.cx(a1);
        let me = net.devices[a1].engine.me(&cx).unwrap();
        let mut out = Vec::new();
        net.devices[a1]
            .engine
            .write(&cx, &me, &mut out, |tx, c| group::epoch_check(tx, c, &row))
            .unwrap()
    };
    net.lines(
        a1,
        me,
        vec![ContentLine::Read {
            mailbox,
            seq: risala_proto::names::Seq::new(seq).unwrap(),
            check: risala_proto::content::EpochCheck::from_bytes(check),
        }],
        false,
    );
    let row2 = net.devices[a2].store.conversation_row(c2).unwrap().unwrap();
    assert_eq!(row2.read_seq, seq);
    // A block on one device reaches the other (5.7).
    net.lines(
        a1,
        me,
        vec![ContentLine::Block("eve@example.com".parse().unwrap())],
        false,
    );
    assert_eq!(
        net.devices[a2]
            .store
            .block_rows(net.devices[a2].account)
            .unwrap(),
        vec!["eve@example.com".to_owned()]
    );
}

#[test]
fn self_lines_from_unconfirmed_leaves_are_ignored() {
    let mut net = Net::new();
    let a1 = net.device("alice1", "alice@example.org");
    let a2 = net.device_with(
        "alice2",
        "alice@example.org",
        Config {
            self_conversation: false,
            ..Config::immediate()
        },
    );
    // The second device confirms nobody (12.9).
    let key = SigningKey::generate().unwrap();
    net.devices[a2].device_id = key.device_id().as_bytes().to_vec();
    net.server.signed_in.insert(
        (a2, Slot::SignedIn),
        (
            "alice@example.org".into(),
            net.devices[a2].device_id.clone(),
        ),
    );
    net.devices[a2].engine = ConversationEngine::new(
        Config {
            self_conversation: false,
            ..Config::immediate()
        },
        Arc::new(TestHooks {
            key,
            confirm: false,
        }),
        Arc::new(net.clock.clone()),
    );
    net.connect(a1);
    net.connect(a2);
    let me = net.job(a1, Job::WithYourself).unwrap();
    net.same_conv(a2, a1, me).unwrap();
    net.lines(
        a1,
        me,
        vec![ContentLine::Block("eve@example.com".parse().unwrap())],
        false,
    );
    assert!(
        net.devices[a2]
            .store
            .block_rows(net.devices[a2].account)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn welcomes_from_blocked_identities_are_refused() {
    let (mut net, a, b) = alice_and_bob();
    let account = net.devices[b].account;
    let now = net.clock.now().unix_millis();
    net.write(b, |tx| {
        Ok(tx.set_block(account, "alice@example.org", true, now)?)
    });
    net.job(
        a,
        Job::Direct {
            peer: "bob@example.net".parse().unwrap(),
        },
    )
    .unwrap();
    assert!(net.convs(b).is_empty());
    let bob = &net.devices[b];
    assert_eq!(net.server.pending_welcomes(&bob.uid, &bob.device_id), 0);
}

#[test]
fn a_last_resort_join_commits_a_new_leaf_key_first() {
    let (mut net, a, b) = alice_and_bob();
    // Use up bob's ordinary KeyPackages.
    for _ in 0..10 {
        net.server.handle(
            (a, SINGLE_USE_SLOT),
            risala_proto::command::Command::KeyPkg(risala_proto::command::KeyPkgCommand::Get {
                uid: "bob@example.net".parse().unwrap(),
            }),
        );
    }
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let cb = net.same_conv(b, a, conv).unwrap();
    net.tick();
    let row = net.devices[b].store.conversation_row(cb).unwrap().unwrap();
    assert!(!row.last_resort, "the new leaf key was committed");
    assert_eq!(net.epoch(a, conv), 2);
    net.say(b, cb, "with a key of my own");
    assert_eq!(net.texts(a, conv).len(), 1);
}

#[test]
fn a_gap_in_a_senders_messages_is_noted() {
    let (mut net, a, b) = alice_and_bob();
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let cb = net.same_conv(b, a, conv).unwrap();
    net.say(a, conv, "one");
    // Alice writes a message that never reaches the server.
    let uid = net.devices[a].uid.clone();
    let now = net.clock.now().unix_millis();
    net.write(a, |tx| {
        let id = content::queue_lines(
            tx,
            conv,
            &uid,
            vec![ContentLine::Text(Text::new("lost"))],
            false,
            now,
        )?;
        tx.conn()
            .execute("DELETE FROM outbox WHERE message_id = ?1", [&id[..]])
            .map_err(crate::store::StoreError::from)?;
        Ok(())
    });
    net.say(a, conv, "three");
    let gaps = net.devices[b].store.gap_rows(cb).unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(
        (gaps[0].first, gaps[0].last, gaps[0].expired),
        (2, 2, false)
    );
}

#[test]
fn a_leaf_is_refreshed_weekly() {
    let (mut net, a, b) = alice_and_bob();
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let cb = net.same_conv(b, a, conv).unwrap();
    assert_eq!(net.epoch(a, conv), 1);
    // Eight days on, each device commits a fresh leaf (12.7).
    net.advance(8 * 24 * 60 * 60 * 1000);
    net.tick();
    assert_eq!(net.epoch(a, conv), 3);
    assert_eq!(net.epoch(b, cb), 3);
    // And not again the next day.
    net.advance(24 * 60 * 60 * 1000);
    assert_eq!(net.epoch(a, conv), 3);
}

#[test]
fn two_direct_conversations_become_one() {
    let (mut net, a, b) = alice_and_bob();
    // Both start one at about the same time (5.1).
    let ca = net
        .job(
            a,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    // Bob's device does not see alice's yet: it makes its own, as if the
    // Welcome had not arrived.
    let bob_first = net.same_conv(b, a, ca).unwrap();
    net.write(b, |tx| {
        tx.set_state(bob_first, ConvState::Left)?;
        Ok(())
    });
    let cb = net
        .job(
            b,
            Job::Direct {
                peer: "alice@example.org".parse().unwrap(),
            },
        )
        .unwrap();
    net.write(b, |tx| {
        tx.set_state(bob_first, ConvState::Active)?;
        Ok(())
    });
    net.tick();
    net.tick();
    // Alice joined bob's too, and left the one with the higher group id.
    let active: Vec<_> = net
        .convs(a)
        .into_iter()
        .filter(|c| {
            c.kind == ConvKind::Direct && c.state.in_group() && c.state != ConvState::Leaving
        })
        .collect();
    assert_eq!(active.len(), 1, "{active:?}");
    let low = std::cmp::min(
        net.devices[a]
            .store
            .conversation_row(ca)
            .unwrap()
            .unwrap()
            .group_id,
        net.devices[b]
            .store
            .conversation_row(cb)
            .unwrap()
            .unwrap()
            .group_id,
    );
    assert_eq!(active[0].group_id, low);
}
