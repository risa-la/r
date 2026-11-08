//! Rooms and reports against a scripted TLS server
//! (5.4, 5.8, 6.2-6.4, 8.4, 8.5), through the client API.

use super::people_tests::{ALICE, HOST, ev, quit, setup, sign_in, until, within};
use super::*;

const REPORTED: &str = "2026-11-06T15:44:10.230Z";

/// Signs in, with #general (id k1) holding messages 1 and 2.
async fn synced(peer: &mut crate::conn::tests::server::Peer) {
    sign_in(peer).await;
    peer.expect("@ref=2 SYNC").await;
    peer.expect("@ref=3 BLOCKS").await;
    peer.send("@ref=2 CONV #general k1 2 0").await;
    peer.send("@ref=2 OK").await;
    peer.send("@ref=3 OK").await;
    peer.expect("@ref=4 HISTORY #general after=0 limit=50")
        .await;
    peer.send(&format!(
        "@ref=4;{}",
        &ev(1, "from=bob@example.net MSG #general spam spam")[1..]
    ))
    .await;
    peer.send(&format!(
        "@ref=4;{}",
        &ev(2, "from=alice@example.org MSG #general oops")[1..]
    ))
    .await;
    peer.send("@ref=4 OK id=k1 more=0").await;
}

/// Expects `command` with `ref`, and answers it: the live `events` first,
/// then `ok`, which is a whole final line after the ref.
async fn answer(
    peer: &mut crate::conn::tests::server::Peer,
    r: u32,
    command: &str,
    events: &[String],
    last: &str,
) {
    peer.expect(&format!("@ref={r} {command}")).await;
    for e in events {
        peer.send(e).await;
    }
    peer.send(&format!("@ref={r} {last}")).await;
}

#[tokio::test]
async fn rooms_and_reports() {
    let (client, server) = setup(|_, mut peer| async move {
        synced(&mut peer).await;
        let p = &mut peer;
        let me = "from=alice@example.org";
        answer(
            p,
            5,
            "DELETE #general 2",
            &[ev(3, &format!("{me} DELETE #general 2"))],
            "OK seq=3",
        )
        .await;
        answer(
            p,
            6,
            "SET #general topic lunch at noon",
            &[ev(4, &format!("{me} SET #general topic lunch at noon"))],
            "OK seq=4",
        )
        .await;
        p.expect("@ref=7 INFO #general").await;
        p.send("@ref=7 SET #general topic lunch at noon").await;
        p.send("@ref=7 SET #general public no").await;
        p.send("@ref=7 OK id=k1 members=3 head=4 role=owner joined=yes")
            .await;
        answer(
            p,
            8,
            "ROLE #general bob@example.net mod",
            &[ev(5, &format!("{me} ROLE #general bob@example.net mod"))],
            "OK seq=5",
        )
        .await;
        answer(
            p,
            9,
            "ROLES #general",
            &[
                "@ref=9 ROLE #general alice@example.org owner".into(),
                "@ref=9 ROLE #general bob@example.net mod".into(),
            ],
            "OK",
        )
        .await;
        answer(
            p,
            10,
            "INVITE #general carol@example.com",
            &[ev(6, &format!("{me} INVITE #general carol@example.com"))],
            "OK seq=6",
        )
        .await;
        answer(p, 11, "INVITE #general bob@example.net", &[], "OK").await;
        answer(
            p,
            12,
            r"KICK #general bob@example.net too loud",
            &[ev(
                7,
                &format!(r"{me} KICK #general bob@example.net too loud"),
            )],
            "OK seq=7",
        )
        .await;
        answer(
            p,
            13,
            "BAN #general troll@example.com",
            &[ev(8, &format!("{me} BAN #general troll@example.com"))],
            "OK seq=8",
        )
        .await;
        answer(
            p,
            14,
            "BANS #general",
            &["@ref=14 BAN #general troll@example.com spam".into()],
            "OK",
        )
        .await;
        answer(
            p,
            15,
            "UNBAN #general troll@example.com",
            &[ev(9, &format!("{me} UNBAN #general troll@example.com"))],
            "OK seq=9",
        )
        .await;
        answer(p, 16, "REPORT #general 1 spam", &[], "OK id=p4x8n2").await;
        // 5.8: a reviewer's two lines, then a notice and another
        // reviewer's resolution.
        p.send(&format!(
            "@report=p4x8n2;t={REPORTED} REPORT #general 1 spam"
        ))
        .await;
        p.send(&format!(
            "@report=p4x8n2;{}",
            &ev(1, "from=bob@example.net MSG #general spam spam")[1..]
        ))
        .await;
        p.send("NOTICE maintenance at 10").await;
        answer(
            p,
            17,
            "REPORTS #general",
            &[
                format!("@ref=17;report=p4x8n2;t={REPORTED} REPORT #general 1 spam"),
                format!(
                    "@ref=17;report=p4x8n2;{}",
                    &ev(1, "from=bob@example.net MSG #general spam spam")[1..]
                ),
            ],
            "OK",
        )
        .await;
        answer(p, 18, "RESOLVE p4x8n2", &[], "OK").await;
        p.send("RESOLVED w7c1m5").await;
        answer(
            p,
            19,
            "INFO",
            &[],
            "OK version=1 guests=yes register=example.org retention=30 push=no upload=no",
        )
        .await;
        answer(
            p,
            20,
            "KICK #general dave@example.org",
            &[],
            "ERR not-found",
        )
        .await;
        quit(peer).await;
    })
    .await;
    let alice = client.add_identity(HOST, ALICE).unwrap();
    let events = alice.subscribe();
    within(alice.connect()).await.unwrap();
    within(alice.wait_synced()).await.unwrap();
    let general = alice.conversation("#general").unwrap();

    // 5.4.
    let entry = within(general.delete(2)).await.unwrap();
    assert_eq!(entry.deletes, Some(2));
    assert_eq!(entry.text, "");
    let entry = within(alice.wait_outbox(entry.id)).await.unwrap();
    assert_eq!(entry.status, OutboxStatus::Sent { seq: 3 });
    let page = general.messages(None, 10).unwrap();
    let oops = page.messages.iter().find(|m| m.seq == 2).unwrap();
    assert!(oops.deleted);
    assert_eq!(oops.text.as_deref(), Some(""));
    // A DELETE is not a timeline item, while queued or after.
    assert!(page.messages.iter().all(|m| m.outbox.is_none()));

    // 6.2.
    assert_eq!(within(general.set_topic("lunch at noon")).await.unwrap(), 4);
    assert_eq!(general.info().unwrap().unwrap().topic, "lunch at noon");
    let info = within(general.room_info()).await.unwrap();
    assert_eq!(
        (
            info.id.as_str(),
            info.members,
            info.head,
            info.role.as_str()
        ),
        ("k1", 3, 4, "owner")
    );
    assert!(info.joined);
    assert_eq!(info.settings.len(), 2);
    assert!(
        general
            .info()
            .unwrap()
            .unwrap()
            .settings
            .contains(&Setting {
                key: "public".into(),
                value: "no".into()
            })
    );
    // A bad value is refused before anything is sent.
    assert!(matches!(
        general.set_setting("public", "maybe").await,
        Err(ClientError::Invalid(_))
    ));

    // 6.3.
    assert_eq!(
        within(general.set_role("bob@example.net", "mod"))
            .await
            .unwrap(),
        5
    );
    let roles: Vec<(String, String)> = within(general.roles())
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.uid, r.role))
        .collect();
    assert_eq!(
        roles,
        [
            ("alice@example.org".into(), "owner".into()),
            ("bob@example.net".into(), "mod".into())
        ]
    );
    assert!(matches!(
        general.set_role("bob@example.net", "king").await,
        Err(ClientError::Invalid(_))
    ));

    // 6.4.
    assert_eq!(
        within(general.invite("carol@example.com")).await.unwrap(),
        Some(6)
    );
    assert_eq!(
        within(general.invite("bob@example.net")).await.unwrap(),
        None
    );
    assert_eq!(
        within(general.kick("bob@example.net", "too loud"))
            .await
            .unwrap(),
        7
    );
    assert_eq!(
        within(general.ban("troll@example.com", "")).await.unwrap(),
        8
    );
    let bans = within(general.bans()).await.unwrap();
    assert_eq!(
        bans,
        [BanInfo {
            uid: "troll@example.com".into(),
            reason: "spam".into()
        }]
    );
    assert_eq!(within(general.unban("troll@example.com")).await.unwrap(), 9);
    // The events were stored before each answer.
    let kinds: Vec<(u64, EventKind, Option<String>)> = general
        .messages(None, 20)
        .unwrap()
        .messages
        .into_iter()
        .filter(|m| m.seq > 4)
        .map(|m| (m.seq, m.kind, m.subject))
        .collect();
    let some = |s: &str| Some(s.to_owned());
    assert_eq!(
        kinds,
        [
            (5, EventKind::Role, some("bob@example.net")),
            (6, EventKind::Invite, some("carol@example.com")),
            (7, EventKind::Kick, some("bob@example.net")),
            (8, EventKind::Ban, some("troll@example.com")),
            (9, EventKind::Unban, some("troll@example.com")),
        ]
    );
    let bob = general
        .cached_members()
        .unwrap()
        .into_iter()
        .find(|m| m.uid == "bob@example.net");
    assert!(bob.is_none(), "kicked: {bob:?}");

    // 5.8.
    assert_eq!(within(general.report(1, "spam")).await.unwrap(), "p4x8n2");
    let report = until(&events, |e| match e {
        AccountEvent::Report { report } => Some(report.clone()),
        _ => None,
    })
    .await;
    assert_eq!(
        (report.id.as_str(), report.conversation.as_str(), report.seq),
        ("p4x8n2", "#general", 1)
    );
    assert_eq!(report.reason, "spam");
    assert_eq!(report.reporter, None);
    assert!(!report.encrypted);
    assert_eq!(report.time, REPORTED);
    let copy = report.message.clone().unwrap();
    assert_eq!(
        (copy.seq, copy.from.as_str(), copy.text.as_str()),
        (1, "bob@example.net", "spam spam")
    );
    assert!(
        copy.line.starts_with("@report=p4x8n2;seq=1;"),
        "{}",
        copy.line
    );
    // The copy is not a new event: the message is as it was.
    assert_eq!(general.messages(None, 1).unwrap().messages[0].seq, 9);
    // 8.4.
    let notice = until(&events, |e| match e {
        AccountEvent::Notice { notice } => Some(notice.clone()),
        _ => None,
    })
    .await;
    assert_eq!(
        notice,
        Notice::Server {
            text: "maintenance at 10".into()
        }
    );
    let reports = within(general.reports()).await.unwrap();
    assert_eq!(reports, [report]);
    within(alice.resolve_report("p4x8n2")).await.unwrap();
    let resolved = until(&events, |e| match e {
        AccountEvent::ReportResolved { id } => Some(id.clone()),
        _ => None,
    })
    .await;
    assert_eq!(resolved, "w7c1m5");

    // 8.5.
    assert_eq!(
        within(alice.server_info()).await.unwrap(),
        ServerInfo {
            version: 1,
            guests: true,
            registration: Some("example.org".into()),
            retention_days: Some(30),
            push: false,
            upload: None,
        }
    );

    // Refusals are the server's codes.
    let err = within(general.kick("dave@example.org", ""))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("not-found"));
    // Rooms only.
    let direct = alice.conversation("bob@example.net").unwrap();
    assert!(matches!(
        direct.kick("bob@example.net", "").await,
        Err(ClientError::Invalid(_))
    ));
    alice.disconnect().await;
    // Offline, nothing can be asked; a deletion is queued.
    assert_eq!(
        general.roles().await.unwrap_err(),
        ClientError::NotConnected
    );
    let queued = general.delete(1).await.unwrap();
    assert_eq!(queued.status, OutboxStatus::Queued);
    assert!(
        general
            .timeline(10)
            .unwrap()
            .items()
            .iter()
            .all(|m| m.outbox.is_none())
    );
    server.done().await;
}

#[tokio::test]
async fn invitations_kicks_bans_and_drops_are_notices() {
    // 6.4, 10.4: these reach the app as notices, not as history.
    let (client, server) = setup(|_, mut peer| async move {
        sign_in(&mut peer).await;
        peer.expect("@ref=2 SYNC").await;
        peer.expect("@ref=3 BLOCKS").await;
        peer.send("@ref=2 CONV #general k1 1 0").await;
        peer.send("@ref=2 CONV #ops k2 1 0").await;
        peer.send("@ref=2 OK").await;
        peer.send("@ref=3 OK").await;
        for (r, room, id) in [(4, "#general", "k1"), (5, "#ops", "k2")] {
            peer.expect(&format!("@ref={r} HISTORY {room} after=0 limit=50"))
                .await;
            peer.send(&format!(
                "@ref={r};{}",
                &ev(1, &format!("from=bob@example.net MSG {room} hi"))[1..]
            ))
            .await;
            peer.send(&format!("@ref={r} OK id={id} more=0")).await;
        }
        let bob = "from=bob@example.net";
        peer.send(&ev(1, &format!("{bob} INVITE #secret alice@example.org")))
            .await;
        peer.send(&ev(
            2,
            &format!("{bob} KICK #general alice@example.org rude"),
        ))
        .await;
        peer.send(&ev(2, &format!("{bob} BAN #ops alice@example.org")))
            .await;
        peer.send("@id=k9 DROP #general an older room").await;
        peer.send("@id=k1 DROP #general gone").await;
        quit(peer).await;
    })
    .await;
    let alice = client.add_identity(HOST, ALICE).unwrap();
    let events = alice.subscribe();
    within(alice.connect()).await.unwrap();
    let notice = || {
        until(&events, |e| match e {
            AccountEvent::Notice { notice } => Some(notice.clone()),
            _ => None,
        })
    };
    let bob = "bob@example.net".to_owned();
    assert_eq!(
        notice().await,
        Notice::Invited {
            room: "#secret".into(),
            by: bob.clone()
        }
    );
    assert_eq!(
        notice().await,
        Notice::Kicked {
            room: "#general".into(),
            by: bob.clone(),
            reason: "rude".into()
        }
    );
    assert_eq!(
        notice().await,
        Notice::Banned {
            room: "#ops".into(),
            by: bob,
            reason: String::new()
        }
    );
    // The DROP for another id was ignored; this one removes the room.
    assert_eq!(
        notice().await,
        Notice::Dropped {
            room: "#general".into(),
            reason: "gone".into()
        }
    );
    assert!(
        alice
            .conversation("#secret")
            .unwrap()
            .info()
            .unwrap()
            .is_none()
    );
    assert!(
        alice
            .conversation("#general")
            .unwrap()
            .info()
            .unwrap()
            .is_none()
    );
    // Banned: not a member, and the BAN is not its history.
    let ops = alice.conversation("#ops").unwrap();
    let info = ops.info().unwrap().unwrap();
    assert!(!info.joined);
    let seqs: Vec<u64> = ops
        .messages(None, 10)
        .unwrap()
        .messages
        .iter()
        .map(|m| m.seq)
        .collect();
    assert_eq!(seqs, [1]);
    alice.disconnect().await;
    server.done().await;
}
