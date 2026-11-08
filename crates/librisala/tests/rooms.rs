//! Running rooms against a real server: invitations, kicks and bans
//! (6.3, 6.4), reports (5.8), ADMIN DROP and the other ADMIN commands
//! (Section 10).
//!
//! The identities are hosted by the test server, under `chat.test` (see
//! `common`). `op@chat.test` is an operator, from the configuration.

mod common;

use common::*;
use librisala::client::{
    Account, AccountEvent, AccountEvents, ClientError, Conversation, EventKind, Notice,
    OutboxStatus, ReportInfo, Role,
};
use risala_server::testing::TestServer;

const OP: &str = "op@chat.test";

async fn server() -> TestServer {
    hosted_server(&["#general"], |c| c.operators = vec![OP.into()]).await
}

/// The server's error code.
fn code<T: std::fmt::Debug>(r: Result<T, ClientError>) -> String {
    match r {
        Err(e) => e.code().unwrap_or_else(|| panic!("{e:?}")).to_owned(),
        Ok(t) => panic!("expected an error, got {t:?}"),
    }
}

/// Waits for a notice.
async fn notice(what: &str, events: &AccountEvents) -> Notice {
    event(what, events, |e| match e {
        AccountEvent::Notice { notice } => Some(notice.clone()),
        _ => None,
    })
    .await
}

/// Waits for a report.
async fn report(what: &str, events: &AccountEvents) -> ReportInfo {
    event(what, events, |e| match e {
        AccountEvent::Report { report } => Some(report.clone()),
        _ => None,
    })
    .await
}

/// Whether the cache counts the account as in the room.
fn joined(conv: &Conversation) -> bool {
    conv.info().unwrap().is_some_and(|i| i.joined)
}

/// The kinds and subjects of the room's stored events, for comparing.
fn kinds(conv: &Conversation) -> Vec<(EventKind, Option<String>)> {
    conv.messages(None, 200)
        .unwrap()
        .messages
        .into_iter()
        .map(|m| (m.kind, m.subject))
        .collect()
}

/// Sends `text` and waits until the server has it.
async fn say(account: &Account, room: &str, text: &str) -> u64 {
    let conv = account.conversation(room).unwrap();
    let entry = conv.send(text).await.unwrap();
    match within("sending", account.wait_outbox(entry.id))
        .await
        .unwrap()
        .status
    {
        OutboxStatus::Sent { seq } => seq,
        other => panic!("{other:?}"),
    }
}

/// Waits until the account has stored event `seq` of `room`.
async fn has(account: &Account, room: &str, seq: u64) {
    let conv = account.conversation(room).unwrap();
    until(
        &format!("{} has {seq}", account.uid()),
        &account.subscribe(),
        || conv.info().unwrap().is_some_and(|i| i.newest >= seq),
    )
    .await;
}

#[tokio::test]
async fn a_moderator_invites_kicks_and_bans() {
    let server = server().await;
    // Alice makes #club, so she owns it, makes it private and bob a mod.
    let alice = registered_in(&server, "alice", "#club").await;
    let bob = registered_in(&server, "bob", "#club").await;
    let club = alice.conversation("#club").unwrap();
    within("SET", club.set_setting("public", "no"))
        .await
        .unwrap();
    within("ROLE", club.set_role("bob@chat.test", Role::Moderator))
        .await
        .unwrap();
    // Changing nothing records nothing: a plain OK, with no seq.
    assert_eq!(
        within("SET again", club.set_setting("public", "no"))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        within(
            "ROLE again",
            club.set_role("bob@chat.test", Role::Moderator)
        )
        .await
        .unwrap(),
        None
    );
    // Her cache knows she owns the room she made from JOIN's answer
    // (6.1), and INFO agrees.
    assert_eq!(club.info().unwrap().unwrap().role, Some(Role::Owner));
    let info = within("INFO", club.room_info()).await.unwrap();
    assert_eq!(info.role, Some(Role::Owner));
    assert_eq!(club.info().unwrap().unwrap().role, Some(Role::Owner));
    let roles = within("ROLES", club.roles()).await.unwrap();
    let mut roles: Vec<_> = roles.into_iter().map(|r| (r.uid, r.role)).collect();
    roles.sort();
    assert_eq!(
        roles,
        [
            ("alice@chat.test".to_owned(), Role::Owner),
            ("bob@chat.test".to_owned(), Role::Moderator)
        ]
    );
    let b_club = bob.conversation("#club").unwrap();
    until("bob learns his role", &bob.subscribe(), || {
        b_club.info().unwrap().unwrap().role == Some(Role::Moderator)
    })
    .await;
    until("bob learns the setting", &bob.subscribe(), || {
        b_club
            .info()
            .unwrap()
            .unwrap()
            .settings
            .iter()
            .any(|s| s.key == "public" && s.value == "no")
    })
    .await;

    // Carol, on two devices, cannot see the private room until invited.
    let carol = registered(&server, "carol").await;
    let carol_b = second_device(&server, &carol).await;
    assert_eq!(code(carol.join("#club").await), "not-found");
    let events = carol.subscribe();
    let events_b = carol_b.subscribe();
    let invited = within("INVITE", b_club.invite("carol@chat.test"))
        .await
        .unwrap();
    assert!(invited.is_some());
    for e in [&events, &events_b] {
        assert_eq!(
            notice("carol hears of the invitation", e).await,
            Notice::Invited {
                room: "#club".into(),
                by: "bob@chat.test".into()
            }
        );
    }
    // A notification, not history: carol is not in the room.
    let c_club = carol.conversation("#club").unwrap();
    assert!(!joined(&c_club));
    assert!(kinds(&c_club).is_empty());
    // She may see INFO before joining (6.2).
    let info = within("INFO", c_club.room_info()).await.unwrap();
    assert!(!info.joined);
    assert_eq!(info.role, None);

    within("joining", carol.join("#club")).await.unwrap();
    within("syncing", carol.wait_synced()).await.unwrap();
    // The JOIN's snapshot told her cache the settings, and the members
    // she learns carry their roles.
    let settings = c_club.info().unwrap().unwrap().settings;
    assert!(
        settings
            .iter()
            .any(|s| s.key == "public" && s.value == "no"),
        "{settings:?}"
    );
    let members = within("MEMBERS", c_club.members()).await.unwrap();
    let mut roles: Vec<_> = members.into_iter().map(|m| (m.uid, m.role)).collect();
    roles.sort();
    assert_eq!(
        roles,
        [
            ("alice@chat.test".to_owned(), Role::Owner),
            ("bob@chat.test".to_owned(), Role::Moderator),
            ("carol@chat.test".to_owned(), Role::Member)
        ]
    );
    let c_b_club = carol_b.conversation("#club").unwrap();
    until("carol's other device joins too", &events_b, || {
        joined(&c_b_club)
    })
    .await;
    // Inviting a member records nothing.
    assert_eq!(
        within("INVITE", b_club.invite("carol@chat.test"))
            .await
            .unwrap(),
        None
    );
    // Moderators act only on plain members.
    assert_eq!(code(b_club.kick("alice@chat.test", "").await), "forbidden");
    assert_eq!(code(b_club.ban("alice@chat.test", "").await), "forbidden");

    let members = within("MEMBERS", b_club.members()).await.unwrap();
    assert!(members.iter().any(|m| m.uid == "carol@chat.test"));

    // Bob kicks carol: both her devices stop treating the room as joined,
    // and the KICK is not stored as her history.
    let kicked = within("KICK", b_club.kick("carol@chat.test", "calm down"))
        .await
        .unwrap();
    for e in [&events, &events_b] {
        assert_eq!(
            notice("carol hears of the kick", e).await,
            Notice::Kicked {
                room: "#club".into(),
                by: "bob@chat.test".into(),
                reason: "calm down".into()
            }
        );
    }
    // The cached members follow: she is no longer one, in anyone's cache.
    until("bob's cache drops carol", &bob.subscribe(), || {
        !b_club
            .cached_members()
            .unwrap()
            .iter()
            .any(|m| m.uid == "carol@chat.test")
    })
    .await;
    for conv in [&c_club, &c_b_club] {
        assert!(!joined(conv));
        assert!(!kinds(conv).contains(&(EventKind::Kick, Some("carol@chat.test".into()))));
    }
    // Everyone else stores it.
    has(&alice, "#club", kicked).await;
    assert!(kinds(&club).contains(&(EventKind::Kick, Some("carol@chat.test".into()))));
    // Room messages no longer reach her.
    let after = say(&alice, "#club", "carol is gone").await;
    has(&bob, "#club", after).await;
    assert!(c_club.info().unwrap().unwrap().newest < after);
    // She is still out after reconnecting: SYNC does not list the room.
    carol.disconnect().await;
    within("connecting", carol.connect()).await.unwrap();
    within("syncing", carol.wait_synced()).await.unwrap();
    assert!(!joined(&c_club));
    // The invitation was used up: the room is private again to her.
    assert_eq!(code(carol.join("#club").await), "not-found");
    // KICK of a non-member is not-found.
    assert_eq!(code(b_club.kick("carol@chat.test", "").await), "not-found");

    // Invited again, she joins, and is banned.
    within("INVITE", b_club.invite("carol@chat.test"))
        .await
        .unwrap();
    within("joining", carol.join("#club")).await.unwrap();
    within("syncing", carol.wait_synced()).await.unwrap();
    assert!(joined(&c_club));
    let events = carol.subscribe();
    within("BAN", b_club.ban("carol@chat.test", "spam"))
        .await
        .unwrap();
    assert_eq!(
        notice("carol hears of the ban", &events).await,
        Notice::Banned {
            room: "#club".into(),
            by: "bob@chat.test".into(),
            reason: "spam".into()
        }
    );
    assert!(!joined(&c_club));
    // BAN again records nothing, and replaces the reason.
    assert_eq!(
        within("BAN again", b_club.ban("carol@chat.test", "flood"))
            .await
            .unwrap(),
        None
    );
    let bans = within("BANS", b_club.bans()).await.unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(
        (bans[0].uid.as_str(), bans[0].reason.as_str()),
        ("carol@chat.test", "flood")
    );
    // A banned identity cannot be invited, and cannot join.
    assert_eq!(code(b_club.invite("carol@chat.test").await), "forbidden");
    assert!(
        ["forbidden", "not-found"].contains(&code(carol.join("#club").await).as_str()),
        "banned"
    );
    // UNBAN, then an invitation lets her back in.
    within("UNBAN", b_club.unban("carol@chat.test"))
        .await
        .unwrap();
    assert!(within("BANS", b_club.bans()).await.unwrap().is_empty());
    assert_eq!(code(b_club.unban("carol@chat.test").await), "not-found");
    within("INVITE", b_club.invite("carol@chat.test"))
        .await
        .unwrap();
    within("joining", carol.join("#club")).await.unwrap();
    within("syncing", carol.wait_synced()).await.unwrap();
    assert!(joined(&c_club));
    server.stop().await;
}

#[tokio::test]
async fn reports_reach_reviewers_and_resolving_reaches_the_other_device() {
    let server = server().await;
    let alice = registered_in(&server, "alice", "#club").await;
    let alice_b = second_device(&server, &alice).await;
    let bob = registered_in(&server, "bob", "#club").await;
    let club = alice.conversation("#club").unwrap();
    // JOIN's answer told alice she created and owns #club (6.1), and bob
    // that he is a plain member.
    assert_eq!(club.info().unwrap().unwrap().role, Some(Role::Owner));
    let b_info = bob.conversation("#club").unwrap().info().unwrap().unwrap();
    assert_eq!(b_info.role, Some(Role::Member));
    within("ROLE", club.set_role("bob@chat.test", Role::Moderator))
        .await
        .unwrap();
    // The operator is not in the room; reports reach it anyway.
    let op = registered(&server, "op").await;
    let carol = registered_in(&server, "carol", "#club").await;
    let dave = registered_in(&server, "dave", "#club").await;
    // Bob leaves, keeping his role, and still reviews (5.8).
    within("parting", bob.part("#club", "")).await.unwrap();

    let spam = say(&dave, "#club", "cheap pills").await;
    has(&carol, "#club", spam).await;
    let reviewers = [&alice, &alice_b, &bob, &op];
    let events: Vec<AccountEvents> = reviewers.iter().map(|a| a.subscribe()).collect();
    let others = [carol.subscribe(), dave.subscribe()];
    let c_club = carol.conversation("#club").unwrap();
    let club_id = c_club.info().unwrap().unwrap().id.unwrap();
    let id = within("REPORT", c_club.report(spam, "spam")).await.unwrap();
    // Reporting again gets the same id; your own message is forbidden.
    assert_eq!(
        within("REPORT", c_club.report(spam, "spam")).await.unwrap(),
        id
    );
    let own = say(&carol, "#club", "mine").await;
    assert_eq!(code(c_club.report(own, "").await), "forbidden");

    for (who, e) in reviewers.iter().zip(&events) {
        let r = report(&format!("{} gets the report", who.uid()), e).await;
        assert_eq!(r.id, id);
        assert_eq!(r.conversation, "#club");
        // The room's id, so an older room's reports can be told apart.
        assert_eq!(r.conversation_id, Some(club_id.clone()));
        assert_eq!(r.seq, spam);
        assert_eq!(r.reason, "spam");
        assert!(!r.encrypted);
        // Only operators learn who reported it.
        let expect = (who.uid() == OP).then(|| "carol@chat.test".to_owned());
        assert_eq!(r.reporter, expect, "{}", who.uid());
        let m = r.message.as_ref().unwrap();
        assert_eq!(
            (m.seq, m.from.as_str(), m.text.as_str()),
            (spam, "dave@chat.test", "cheap pills")
        );
    }
    // The copy is not stored as an event of the room.
    let a_club = alice.conversation("#club").unwrap();
    let stored = a_club.export().unwrap();
    assert_eq!(
        stored
            .iter()
            .filter(|l| l.starts_with(&format!("@seq={spam};")))
            .count(),
        1
    );
    assert!(!stored.iter().any(|l| l.contains("report=")), "{stored:?}");

    // The lists: room reviewers without the reporter, operators with it.
    let listed = within("REPORTS", a_club.reports()).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].conversation_id, Some(club_id.clone()));
    assert_eq!(
        (listed[0].id.as_str(), &listed[0].reporter),
        (id.as_str(), &None)
    );
    let listed = within("REPORTS", bob.conversation("#club").unwrap().reports())
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    let listed = within("ADMIN REPORTS", op.admin().reports()).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].reporter.as_deref(), Some("carol@chat.test"));
    assert_eq!(code(c_club.reports().await), "forbidden");
    assert_eq!(code(carol.admin().reports().await), "forbidden");

    // Deleting the message leaves the report's copy.
    within("deleting", async {
        let entry = a_club.delete(spam).await.unwrap();
        alice.wait_outbox(entry.id).await.unwrap()
    })
    .await;
    let listed = within("REPORTS", a_club.reports()).await.unwrap();
    assert_eq!(
        listed[0].message.as_ref().unwrap().text,
        "cheap pills",
        "{listed:?}"
    );

    // Alice resolves it on device A: everyone else hears, her device B
    // included; device A does not.
    assert_eq!(code(carol.resolve_report(&id).await), "not-found");
    within("RESOLVE", alice.resolve_report(&id)).await.unwrap();
    for (who, e) in reviewers.iter().zip(&events).skip(1) {
        let resolved = event(&format!("{} hears RESOLVED", who.uid()), e, |e| match e {
            AccountEvent::ReportResolved { id } => Some(id.clone()),
            _ => None,
        })
        .await;
        assert_eq!(resolved, id);
    }
    assert!(
        within("REPORTS", a_club.reports())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        within("ADMIN REPORTS", op.admin().reports())
            .await
            .unwrap()
            .is_empty()
    );
    // Neither the reporter nor the author heard any of it, and device A
    // did not hear its own RESOLVED. A round trip on each connection
    // first, so that whatever the server sent before has been handled.
    for a in [&carol, &dave, &alice] {
        within("INFO", a.server_info()).await.unwrap();
    }
    for e in others.iter().chain([&events[0]]) {
        for e in drain(e).await {
            assert!(!matches!(e, AccountEvent::ReportResolved { .. }), "{e:?}");
        }
    }
    for e in &others {
        // Drained above; nothing about reports came before either.
        assert!(drain(e).await.is_empty());
    }
    server.stop().await;
}

/// The events already waiting.
async fn drain(events: &AccountEvents) -> Vec<AccountEvent> {
    let mut out = Vec::new();
    while let Ok(Some(e)) =
        tokio::time::timeout(std::time::Duration::from_millis(1), events.next()).await
    {
        out.push(e);
    }
    out
}

#[tokio::test]
async fn an_operator_drops_a_room_and_every_client_removes_it() {
    let server = server().await;
    let alice = registered_in(&server, "alice", "#club").await;
    let alice_b = second_device(&server, &alice).await;
    let bob = registered_in(&server, "bob", "#club").await;
    let carol = registered_in(&server, "carol", "#club").await;
    let club = alice.conversation("#club").unwrap();
    within("ROLE", club.set_role("bob@chat.test", Role::Moderator))
        .await
        .unwrap();
    let last = say(&carol, "#club", "hello").await;
    for a in [&alice, &alice_b, &bob] {
        has(a, "#club", last).await;
    }
    // Bob, a moderator, leaves: the DROP reaches him too, and his cache
    // drops the history he kept.
    within("parting", bob.part("#club", "")).await.unwrap();
    within("syncing", bob.wait_synced()).await.unwrap();
    assert!(!joined(&bob.conversation("#club").unwrap()));
    // Dave was in the room, but is offline when it is dropped.
    let dave = registered_in(&server, "dave", "#club").await;
    dave.disconnect().await;

    let op = registered(&server, "op").await;
    let members = [&alice, &alice_b, &bob, &carol];
    let events: Vec<AccountEvents> = members.iter().map(|a| a.subscribe()).collect();
    within("ADMIN DROP", op.admin().drop_room("#club", "closed down"))
        .await
        .unwrap();
    for (who, e) in members.iter().zip(&events) {
        assert_eq!(
            notice(&format!("{} hears of the drop", who.uid()), e).await,
            Notice::Dropped {
                room: "#club".into(),
                reason: "closed down".into()
            }
        );
        let conv = who.conversation("#club").unwrap();
        until(&format!("{} removes the room", who.uid()), e, || {
            conv.info().unwrap().is_none()
        })
        .await;
        assert!(conv.messages(None, 50).unwrap().messages.is_empty());
    }
    assert_eq!(code(op.admin().drop_room("#club", "").await), "not-found");

    // Someone makes a new #club. Dave missed the DROP: SYNC no longer
    // lists the old room, so he has left it, and its history is kept.
    let erin = registered_in(&server, "erin", "#club").await;
    say(&erin, "#club", "a new room").await;
    let d_club = dave.conversation("#club").unwrap();
    let old_id = d_club.info().unwrap().unwrap().id;
    let events = dave.subscribe();
    within("connecting", dave.connect()).await.unwrap();
    within("syncing", dave.wait_synced()).await.unwrap();
    assert_eq!(
        notice("dave hears he left", &events).await,
        Notice::Left {
            conversation: "#club".into()
        }
    );
    assert!(!joined(&d_club));
    // Joining the new room starts it afresh, without the old history.
    within("joining", dave.join("#club")).await.unwrap();
    within("syncing", dave.wait_synced()).await.unwrap();
    let info = d_club.info().unwrap().unwrap();
    assert_ne!(info.id, old_id);
    let texts: Vec<_> = d_club
        .messages(None, 50)
        .unwrap()
        .messages
        .into_iter()
        .filter_map(|m| m.text)
        .collect();
    assert_eq!(texts, ["a new room"]);

    // A room from the configuration comes back at once, empty, with a new
    // id; the old DROP does not touch it.
    let general = alice.join("#general").await.unwrap();
    within("syncing", alice.wait_synced()).await.unwrap();
    let old = general.info().unwrap().unwrap().id;
    let events = alice.subscribe();
    within("ADMIN DROP", op.admin().drop_room("#general", ""))
        .await
        .unwrap();
    assert!(matches!(
        notice("alice hears of the drop", &events).await,
        Notice::Dropped { .. }
    ));
    within("joining", alice.join("#general")).await.unwrap();
    within("syncing", alice.wait_synced()).await.unwrap();
    let new = general.info().unwrap().unwrap().id;
    assert_ne!(new, old);
    server.stop().await;
}

#[tokio::test]
async fn admin_commands_round_trip() {
    let server = server().await;
    let op = registered_in(&server, "op", "#general").await;
    let alice = registered_in(&server, "alice", "#general").await;
    let carol = registered(&server, "carol").await;
    let admin = op.admin();
    // The sign-in said who is an operator (op=yes, 4.5).
    assert!(op.is_operator());
    assert!(!alice.is_operator());

    // Non-operators get forbidden for every ADMIN command.
    assert_eq!(code(alice.admin().operators().await), "forbidden");
    assert_eq!(code(alice.admin().notice("hi").await), "forbidden");

    // OPS, OP, DEOP (10.1).
    assert_eq!(within("OPS", admin.operators()).await.unwrap(), [OP]);
    within("OP", admin.add_operator("alice@chat.test"))
        .await
        .unwrap();
    let mut ops = within("OPS", admin.operators()).await.unwrap();
    ops.sort();
    assert_eq!(ops, ["alice@chat.test", OP]);
    assert_eq!(
        within("OPS", alice.admin().operators())
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(code(admin.remove_operator(OP).await), "forbidden");
    within("DEOP", admin.remove_operator("alice@chat.test"))
        .await
        .unwrap();
    assert_eq!(
        code(admin.remove_operator("alice@chat.test").await),
        "not-found"
    );
    assert_eq!(code(alice.admin().operators().await), "forbidden");
    assert!(matches!(
        admin.add_operator("~sam").await,
        Err(ClientError::Server { .. })
    ));

    // WHO (10.3): both connections, signed in.
    let who = within("WHO", admin.connections()).await.unwrap();
    let mut uids: Vec<_> = who.iter().filter_map(|c| c.uid.clone()).collect();
    uids.sort();
    assert_eq!(uids, ["alice@chat.test", "carol@chat.test", OP]);
    assert!(
        who.iter()
            .all(|c| c.address == "127.0.0.1" && c.since_ms > 0)
    );

    // NOTICE reaches every connection, the sender's too.
    let events = [alice.subscribe(), op.subscribe()];
    within("NOTICE", admin.notice("maintenance at noon"))
        .await
        .unwrap();
    for e in &events {
        assert_eq!(
            notice("the notice", e).await,
            Notice::Server {
                text: "maintenance at noon".into()
            }
        );
    }

    // ROOMS (10.4), private ones too, paged.
    let club = alice.join("#club").await.unwrap();
    within("SET", club.set_setting("public", "no"))
        .await
        .unwrap();
    let listed = within("LIST", alice.list_rooms(None, None)).await.unwrap();
    assert!(listed.rooms.iter().all(|r| r.room != "#club"));
    let page = within("ROOMS", admin.rooms(None, Some(1))).await.unwrap();
    assert_eq!(page.rooms.len(), 1);
    assert_eq!(page.rooms[0].room, "#club");
    assert!(page.more);
    let page = within("ROOMS", admin.rooms(Some("#club".into()), None))
        .await
        .unwrap();
    assert_eq!(
        page.rooms
            .iter()
            .map(|r| r.room.as_str())
            .collect::<Vec<_>>(),
        ["#general"]
    );
    assert!(!page.more);

    // PURGE (10.4): alice's messages, as DELETE.
    let general = op.conversation("#general").unwrap();
    let a = say(&alice, "#general", "one").await;
    let b = say(&alice, "#general", "two").await;
    has(&op, "#general", b).await;
    assert_eq!(
        within("PURGE", admin.purge("alice@chat.test", Some(1)))
            .await
            .unwrap(),
        2
    );
    until("op sees them deleted", &op.subscribe(), || {
        let ms = general.messages(None, 50).unwrap().messages;
        ms.iter()
            .filter(|m| m.seq == a || m.seq == b)
            .all(|m| m.deleted)
    })
    .await;
    assert_eq!(
        within("PURGE", admin.purge("alice@chat.test", None))
            .await
            .unwrap(),
        0
    );

    // KEYS, ADDKEY, DELKEY (10.5).
    let keys = within("KEYS", admin.keys("alice@chat.test")).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert!(!keys[0].this_device);
    let mine = within("KEYS", admin.keys(OP)).await.unwrap();
    assert!(mine[0].this_device);
    let (spare, _) = device(&server);
    spare
        .create_device_key("alice@chat.test", false)
        .await
        .unwrap();
    let line = spare.key_line("alice@chat.test", "spare").unwrap();
    within("ADDKEY", admin.add_key("alice@chat.test", &line, "spare"))
        .await
        .unwrap();
    let keys = within("KEYS", admin.keys("alice@chat.test")).await.unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().any(|k| k.label == "spare"));
    within("DELKEY", admin.remove_key("alice@chat.test", &line))
        .await
        .unwrap();
    assert_eq!(
        within("KEYS", admin.keys("alice@chat.test"))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(code(admin.keys("nobody@chat.test").await), "not-found");

    // SET (10.6), shown in INFO at once.
    within("SET", admin.set("retention", "30")).await.unwrap();
    within("SET", admin.set("registration", "closed"))
        .await
        .unwrap();
    within("SET", admin.set("guests", "no")).await.unwrap();
    let info = within("INFO", alice.server_info()).await.unwrap();
    assert_eq!(info.retention_days, Some(30));
    assert_eq!(info.registration, None);
    assert!(!info.guests);
    assert!(matches!(
        admin.set("guests", "maybe").await,
        Err(ClientError::Invalid(_))
    ));

    // BAN, BANS, UNBAN (10.2). A banned identity is disconnected and
    // cannot sign in again.
    within("BAN", admin.ban("*@spam.test", "spam"))
        .await
        .unwrap();
    within("BAN", admin.ban("carol@chat.test", ""))
        .await
        .unwrap();
    let mut bans: Vec<_> = within("BANS", admin.bans())
        .await
        .unwrap()
        .into_iter()
        .map(|b| (b.target, b.reason))
        .collect();
    bans.sort();
    assert_eq!(
        bans,
        [
            ("*@spam.test".to_owned(), "spam".to_owned()),
            ("carol@chat.test".to_owned(), String::new())
        ]
    );
    until("carol is signed out", &carol.subscribe(), || {
        !carol.state().is_online()
    })
    .await;
    let err = within("signing in", carol.connect()).await.unwrap_err();
    assert_eq!(err.code(), Some("forbidden"), "{err:?}");
    within("UNBAN", admin.unban("carol@chat.test"))
        .await
        .unwrap();
    assert_eq!(code(admin.unban("carol@chat.test").await), "not-found");
    within("signing in", carol.connect()).await.unwrap();

    // DISCONNECT (10.3).
    within("DISCONNECT", admin.disconnect("carol@chat.test", "bye"))
        .await
        .unwrap();
    assert_eq!(
        code(admin.disconnect("nobody@chat.test", "").await),
        "not-found"
    );

    // UNREGISTER (10.5).
    within("UNREGISTER", admin.unregister("carol@chat.test"))
        .await
        .unwrap();
    assert_eq!(code(admin.keys("carol@chat.test").await), "not-found");
    server.stop().await;
}

/// ADMIN BAN of a connected guest bans its address and closes its
/// connection; the client stops trying until the user connects again.
/// `ADMIN SET guests no` ends guest sessions the same way (10.2, 10.6).
#[tokio::test]
async fn server_wide_bans_and_closing_to_guests_stop_a_guest_client() {
    let server = server().await;
    let op = registered(&server, "op").await;
    let admin = op.admin();
    let (client, addr) = trusting_client(&server, server.addr(), 50);
    let sam = client.add_guest(&addr, "sam").unwrap();
    within("connecting", sam.connect()).await.unwrap();
    within("joining", sam.join("#general")).await.unwrap();
    within("syncing", sam.wait_synced()).await.unwrap();

    let events = sam.subscribe();
    within("ADMIN BAN", admin.ban("~sam", "spam"))
        .await
        .unwrap();
    let bans = within("BANS", admin.bans()).await.unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(
        (bans[0].target.as_str(), bans[0].reason.as_str()),
        ("127.0.0.1", "spam")
    );
    until("sam gives up", &events, || {
        matches!(
            sam.state(),
            librisala::client::ConnectionState::Failed { .. }
        )
    })
    .await;
    let err = within("connecting", sam.connect()).await.unwrap_err();
    assert_eq!(err.code(), Some("forbidden"), "{err:?}");

    within("ADMIN UNBAN", admin.unban("127.0.0.1"))
        .await
        .unwrap();
    within("connecting", sam.connect()).await.unwrap();
    within("syncing", sam.wait_synced()).await.unwrap();

    let events = sam.subscribe();
    within("ADMIN SET", admin.set("guests", "no"))
        .await
        .unwrap();
    until("sam gives up", &events, || {
        matches!(
            sam.state(),
            librisala::client::ConnectionState::Failed { .. }
        )
    })
    .await;
    assert!(within("connecting", sam.connect()).await.is_err());
    within("ADMIN SET", admin.set("guests", "yes"))
        .await
        .unwrap();
    within("connecting", sam.connect()).await.unwrap();
    client.shutdown().await;
    server.stop().await;
}
