//! Public rooms against the in-memory server (6.1, 7.3, 12.6-12.8): a room
//! created, listed and joined by proposal, guests and GONE, the name that
//! leads elsewhere, an owner's rejoin, and a resync after a commit the
//! devices cannot apply.

use risala_proto::command::Command;
use risala_proto::server::ServerLine;

use super::*;

const ROOM: &str = "#general";

fn room() -> Room {
    ROOM.parse().unwrap()
}

/// Alice creates `#general`, and Bob joins it.
fn room_with_two(net: &mut Net) -> (usize, usize, ConversationId, ConversationId) {
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let a = net
        .job(alice, Job::PublicRoom { room: room() })
        .expect("created");
    let b = net
        .job_over(
            bob,
            Job::JoinPublic {
                room: room(),
                new_group: false,
            },
            5,
        )
        .expect("joined");
    (alice, bob, a, b)
}

#[test]
fn a_public_room_is_created_listed_joined_by_proposal_and_talked_in() {
    let mut net = Net::new();
    let (alice, bob, a, b) = room_with_two(&mut net);
    assert_eq!(net.state(alice, a), ConvState::Active);
    assert_eq!(net.state(bob, b), ConvState::Active);
    // The server holds the room's group: two members, in epoch 1.
    assert_eq!(net.server.room(ROOM), Some((2, 1)));
    assert_eq!(net.epoch(alice, a), 1);
    assert_eq!(net.epoch(bob, b), 1);
    let mut leaves = net.leaves(bob, b);
    leaves.sort();
    assert_eq!(leaves, ["alice@example.org", "bob@example.net"]);

    // LIST shows it (6.1).
    let (response, _) = net.server.handle(
        (0, Slot::Anonymous(0)),
        Command::List {
            after: None,
            limit: None,
        },
    );
    assert!(matches!(
        &response.lines[0].line,
        ServerLine::Room { room, members: 2, .. } if room.as_str() == ROOM
    ));

    // 12.6: the creator's commit went on its signed-in connection; Bob's
    // join proposal and WELCOME GET on connections of their own.
    let posts_by = |d: usize, slot: Slot| {
        net.server
            .log
            .iter()
            .filter(|((dd, s), verb)| *dd == d && *s == slot && verb == "POST")
            .count()
    };
    assert!(
        posts_by(alice, Slot::SignedIn) >= 1,
        "the commit, signed in"
    );
    assert!(posts_by(bob, SINGLE_USE_SLOT) >= 1, "the join, on its own");
    assert!(
        net.server
            .log
            .iter()
            .any(|((d, s), verb)| *d == bob && *s == SINGLE_USE_SLOT && verb == "WELCOME"),
        "WELCOME GET on a connection of its own"
    );
    assert!(
        net.server
            .log
            .iter()
            .any(|((d, s), verb)| *d == alice && *s == Slot::SignedIn && verb == "WELCOME"),
        "WELCOME PUT on the committer's signed-in connection"
    );

    // 7.3: an identity's messages in a public room show once its period's
    // pseudonym is pinned, which leaf confirmation (C3) does from ATTEST.
    net.say(alice, a, "before the pin");
    assert!(net.texts(bob, b).is_empty(), "withheld until ATTEST");
    net.pin(bob, b, alice, a);
    net.say(alice, a, "hello room");
    assert_eq!(
        net.texts(bob, b),
        [("alice@example.org".into(), "hello room".into())]
    );
    net.say(bob, b, "hi");
    net.pin(alice, a, bob, b);
    net.say(bob, b, "hi again");
    assert!(
        net.texts(alice, a)
            .contains(&("bob@example.net".into(), "hi again".into()))
    );
}

#[test]
fn daily_pseudonyms_change_with_the_period() {
    let mut net = Net::new();
    let (alice, bob, a, b) = room_with_two(&mut net);
    net.say(alice, a, "one");
    let first = net.devices[alice]
        .store
        .conversation_row(a)
        .unwrap()
        .unwrap()
        .pseudonym;
    net.say(alice, a, "two");
    let same = net.devices[alice]
        .store
        .conversation_row(a)
        .unwrap()
        .unwrap()
        .pseudonym;
    assert_eq!(first, same, "one pseudonym for the period");
    net.advance(24 * 60 * 60 * 1000);
    net.say(alice, a, "three");
    let next = net.devices[alice]
        .store
        .conversation_row(a)
        .unwrap()
        .unwrap()
        .pseudonym;
    assert_ne!(first, next, "a new pseudonym for the next period (7.3)");
    let _ = (bob, b);
}

#[test]
fn guests_join_post_and_are_removed_when_gone() {
    let mut net = Net::new();
    let (alice, bob, a, b) = room_with_two(&mut net);
    let sam = net.guest("sam", "~sam");
    net.connect(sam);
    let s = net
        .job_over(
            sam,
            Job::JoinPublic {
                room: room(),
                new_group: false,
            },
            5,
        )
        .expect("the guest joined");
    assert_eq!(net.server.room(ROOM).unwrap().0, 3);
    assert!(net.leaves(alice, a).contains(&"~sam".to_string()));
    // A guest posts from its guest connection, and its first message of the
    // period pins its pseudonym (7.3).
    net.say(sam, s, "hi from a guest");
    assert!(
        net.texts(alice, a)
            .contains(&("~sam".into(), "hi from a guest".into()))
    );
    // Its leaf never commits (12.6): nothing it queued was posted signed in.
    assert!(
        !net.server
            .log
            .iter()
            .any(|((d, s), _)| *d == sam && *s == Slot::SignedIn)
    );

    // GONE (6.1): a full client removes the guest's leaf.
    let lines = net.server.gone("~sam");
    assert!(!lines.is_empty());
    net.deliver(lines);
    net.tick();
    assert!(!net.leaves(alice, a).contains(&"~sam".to_string()));
    assert!(!net.leaves(bob, b).contains(&"~sam".to_string()));
    assert_eq!(net.server.room(ROOM).unwrap().0, 2);
}

#[test]
fn a_name_that_leads_to_another_group_is_not_joined_silently() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    net.job(alice, Job::PublicRoom { room: room() })
        .expect("created");
    // Bob joined a #general before, with another group (6.1).
    net.write(bob, |tx| {
        let account = net.devices[bob].account;
        tx.set_room_group(account, ROOM, &[7; 32])?;
        Ok(())
    });
    let err = net
        .job_over(
            bob,
            Job::JoinPublic {
                room: room(),
                new_group: false,
            },
            2,
        )
        .unwrap_err();
    assert!(err.contains("different group"), "{err}");
    // Once the user chooses to, it joins.
    net.job_over(
        bob,
        Job::JoinPublic {
            room: room(),
            new_group: true,
        },
        5,
    )
    .expect("joined anew");
}

#[test]
fn an_owner_whose_proposal_nobody_commits_rejoins_by_external_commit() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    net.connect(alice);
    net.job(alice, Job::PublicRoom { room: room() })
        .expect("created");
    // Alice's only full client goes away; her phone joins.
    net.disconnect(alice);
    let phone = net.device_of("phone", alice);
    net.connect(phone);
    // 12.7: after 30 minutes without a commit, an owner joins by external
    // commit instead.
    let p = net
        .job_over(
            phone,
            Job::JoinPublic {
                room: room(),
                new_group: false,
            },
            0,
        )
        .unwrap_err();
    assert!(p.contains("did not finish"), "{p}");
    for _ in 0..40 {
        net.advance(60_000);
    }
    let conv = net
        .convs(phone)
        .into_iter()
        .find(|c| c.kind == ConvKind::Public)
        .unwrap();
    assert_eq!(conv.state, ConvState::Active);
    assert_eq!(net.server.room(ROOM), Some((2, 1)));
    assert!(
        net.server
            .log
            .iter()
            .any(|((d, s), verb)| *d == phone && *s == Slot::SignedIn && verb == "POST"),
        "the external commit, signed in"
    );
}

#[test]
fn a_room_whose_server_took_an_invalid_commit_is_resynced() {
    let mut net = Net::new();
    let (alice, bob, a, b) = room_with_two(&mut net);
    // Mallory joins, then posts a commit whose `next` is wrong: the server
    // takes it (it cannot check `next`), and the members cannot (12.7).
    let mallory = net.device("mallory", "mallory@example.com");
    net.connect(mallory);
    let m = net
        .job_over(
            mallory,
            Job::JoinPublic {
                room: room(),
                new_group: false,
            },
            5,
        )
        .expect("mallory joined");
    net.tick();
    let epoch = net.epoch(alice, a);
    assert_eq!(net.epoch(mallory, m), epoch);
    assert_eq!(net.epoch(bob, b), epoch);
    net.disconnect(mallory);
    let crypto = Arc::new(risala_mls::RisalaCrypto::new().unwrap());
    let (message, group_info, mailbox) = net.write(mallory, |tx| {
        let row = tx.conversation(m)?;
        let p = tx.mls(&crypto);
        let mut group = risala_mls::openmls::group::MlsGroup::load(
            risala_mls::openmls_traits::OpenMlsProvider::storage(&p),
            &risala_mls::openmls::prelude::GroupId::from_slice(&row.group_id),
        )
        .unwrap()
        .unwrap();
        let state = tx.group_history(m)?;
        let profile = risala_mls::profile::RisalaProfile::new("", START + 1).unwrap();
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
            out.group_info.unwrap(),
            tx.current_mailbox(m)?.mailbox,
        ))
    });
    let token = net.write(mallory, |tx| {
        let row = tx.conversation(m)?;
        let p = tx.mls(&crypto);
        let group = risala_mls::openmls::group::MlsGroup::load(
            risala_mls::openmls_traits::OpenMlsProvider::storage(&p),
            &risala_mls::openmls::prelude::GroupId::from_slice(&row.group_id),
        )
        .unwrap()
        .unwrap();
        Ok(risala_mls::token::SendToken::of_group(&group, crypto.as_ref()).unwrap())
    });
    net.server.now = net.clock.now().unix_millis();
    let (response, live) = net.server.handle(
        (mallory, Slot::SignedIn),
        Command::Post {
            mailbox,
            token: PostToken::Send(SendTokenText::from_bytes(*token.as_bytes())),
            message: OrBlob::Inline(MlsMessage::from_bytes(&message).unwrap()),
            live: false,
            groupinfo: Some(OrBlob::Inline(
                risala_proto::mls::GroupInfo::from_bytes(&group_info).unwrap(),
            )),
            next: Some(TokenHash::from_bytes([9; 48])),
            cid: None,
        },
    );
    assert!(matches!(response.end, End::Ok(_)), "{:?}", response.end);
    net.deliver(live);
    // The members tell their users, and recover: one resync commit, and the
    // other joins again by proposal (12.7).
    for d in [alice, bob] {
        assert!(
            net.events(d).iter().any(|e| matches!(
                e,
                Event::Conversation(ConversationEvent::InvalidCommitAccepted { .. })
            )),
            "{} was told",
            net.devices[d].name
        );
    }
    for _ in 0..5 {
        net.advance(60_000);
    }
    assert_eq!(net.state(alice, a), ConvState::Active);
    assert_eq!(net.state(bob, b), ConvState::Active);
    assert_eq!(net.epoch(alice, a), net.epoch(bob, b));
    assert!(net.epoch(alice, a) > epoch + 1);
    // Mallory's leaf, which signed the bad commit's GroupInfo, is gone.
    // Whoever joined again removes its earlier leaf in its next commit
    // (12.7).
    for (d, conv) in [(alice, a), (bob, b)] {
        let now = net.clock.now().unix_millis();
        net.write(d, |tx| {
            group::queue_intent(tx, conv, &Intent::default(), now)?;
            Ok(())
        });
        net.tick();
    }
    let mut leaves = net.leaves(alice, a);
    leaves.sort();
    assert_eq!(leaves, ["alice@example.org", "bob@example.net"]);
    assert_eq!(net.leaves(bob, b).len(), 2);
    // They talk again.
    net.say(alice, a, "back");
    net.pin(bob, b, alice, a);
    net.say(alice, a, "back again");
    assert!(
        net.texts(bob, b)
            .contains(&("alice@example.org".into(), "back again".into()))
    );
}

/// 6.1: leaving a public room while joining it gives the join up: the room
/// is left, the join's leaf key forgotten, and its job ends. When Alice
/// commits the proposal later, Bob does not fetch the Welcome.
#[test]
fn leaving_a_room_while_joining_it_gives_the_join_up() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    net.connect(alice);
    let a = net
        .job(alice, Job::PublicRoom { room: room() })
        .expect("created");
    // Alice is away: nobody commits Bob's join proposal.
    net.disconnect(alice);
    let bob = net.device("bob", "bob@example.net");
    net.connect(bob);
    let cx = net.cx(bob);
    let (job, actions) = net.devices[bob].engine.start(
        &cx,
        Job::JoinPublic {
            room: room(),
            new_group: false,
        },
    );
    net.act(bob, actions);
    net.run();
    net.tick();
    let b = net
        .convs(bob)
        .into_iter()
        .find(|c| c.kind == ConvKind::Public)
        .unwrap()
        .id;
    assert_eq!(net.state(bob, b), ConvState::Joining);
    let join = net.write(bob, |tx| Ok(tx.join_of(b)?)).expect("a join");
    let leaf_key = risala_mls::keypackage::read_key_package(&join.key_package)
        .unwrap()
        .unverified_credential()
        .signature_key
        .as_slice()
        .to_vec();
    let has_leaf_key = |net: &Net| {
        net.write(bob, |tx| {
            Ok(risala_mls::mldsa::LeafKey::load(
                &tx.mls_storage(),
                risala_mls::mldsa::KEY_PACKAGE_SCOPE,
                &leaf_key,
            )
            .unwrap()
            .is_some())
        })
    };
    assert!(has_leaf_key(&net));

    let own = net.devices[bob].uid.clone();
    let now = net.clock.now().unix_millis();
    assert!(net.write(bob, |tx| group::leave(tx, b, &own, now)));
    net.tick();
    assert_eq!(net.state(bob, b), ConvState::Left);
    assert!(net.write(bob, |tx| Ok(tx.join_of(b)?)).is_none());
    assert!(!has_leaf_key(&net));
    assert_eq!(
        net.job_result(bob, job),
        Some(Err("left while joining".into()))
    );

    // Alice commits the proposal; Bob asks for no Welcome and stays out.
    let asked = |net: &Net| {
        net.server
            .log
            .iter()
            .filter(|((d, _), verb)| *d == bob && (verb == "GROUPINFO" || verb == "WELCOME"))
            .count()
    };
    let before = asked(&net);
    net.connect(alice);
    for _ in 0..12 {
        net.advance(60_000);
    }
    assert!(net.leaves(alice, a).contains(&"bob@example.net".to_owned()));
    assert_eq!(asked(&net), before);
    assert_eq!(net.state(bob, b), ConvState::Left);
}
