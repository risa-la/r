//! Every ADMIN command (Section 10) over TLS against a whole server, and
//! UNREGISTER `purge=yes` (4.8): operators, server bans checked after the
//! signature, connections, notices, rooms and DROP of a room from the
//! configuration, PURGE, hosted identities and server settings, including
//! `ADMIN SET guests no` with guests connected and waiting.
//!
//! The hub's own tests (`src/core/admin_tests.rs` and others) cover each
//! rule at every edge, without sockets.

mod common;

use std::time::Duration;

use common::{Session, command, exchange, expect, join, recv, until_closed, value};
use risala_server::testing::{TestClient, TestIdentity, TestServer};

/// Presence changes held for an hour, so that no PRESENCE line turns up.
const NO_PRESENCE: (Duration, Duration) = (Duration::from_secs(30), Duration::from_secs(3600));

const HOUR: Duration = Duration::from_secs(60 * 60);

/// A server that hosts `example.org`, lets identities at `example.net`,
/// `sub.example.net` and `example.com` sign in, and has `op@example.com` as its
/// operator, with a stopped clock and the room `#general`.
async fn server() -> TestServer {
    TestServer::builder()
        .identity_domain("example.org")
        .key_domains(&["example.net", "sub.example.net", "example.com"])
        .operator("op@example.com")
        .room("#general")
        .presence(NO_PRESENCE.0, NO_PRESENCE.1)
        .guest_resume(Duration::from_secs(600))
        .manual_clock()
        .start()
        .await
}

/// A session with `names` registered at `example.org` and signed in, and
/// the operator signed in as `op`. Returns their identities too, the
/// operator's last.
async fn people(server: &TestServer, names: &[&str]) -> (Session, Vec<TestIdentity>) {
    let mut s = Session::new();
    let mut ids = Vec::new();
    for name in names {
        let (id, conn) = server.register(name).await;
        s.add(name, conn);
        ids.push(id);
    }
    let op = server.identity("op@example.com");
    s.add("op", server.sign_in(&op).await);
    ids.push(op);
    (s, ids)
}

/// Connects and reads the greeting, without signing in.
async fn anonymous(server: &TestServer) -> TestClient {
    let mut c = server.connect().await;
    let greeting = recv(&mut c).await;
    assert!(greeting.starts_with("RISALA 1 "), "{greeting}");
    c
}

/// The server's INFO line (8.5), from a connection that has not signed in.
async fn server_info(server: &TestServer) -> String {
    let mut c = anonymous(server).await;
    command(&mut c, "info").await.remove(0)
}

/// Connects and sends `GUEST <name>`, returning the client and the answer.
async fn try_guest(server: &TestServer, name: &str) -> (TestClient, String) {
    let mut c = anonymous(server).await;
    c.send(&format!("guest {name}")).await.unwrap();
    let answer = recv(&mut c).await;
    (c, answer)
}

/// Connects and sends AUTH for `who`, signed for `host` rather than for
/// the server when it is not the server's name, so that the signature
/// does not verify. Returns the answer.
async fn auth_signed_for(server: &TestServer, who: &TestIdentity, host: &str) -> String {
    let mut c = server.connect().await;
    let greeting = recv(&mut c).await;
    let nonce = greeting.split(' ').nth(3).unwrap().parse().unwrap();
    c.send(&who.auth_line(host, &nonce)).await.unwrap();
    recv(&mut c).await
}

/// Connects and sends REGISTER for `who`, signed for `host`. Returns the
/// answer.
async fn register_signed_for(server: &TestServer, who: &TestIdentity, host: &str) -> String {
    let mut c = server.connect().await;
    let greeting = recv(&mut c).await;
    let nonce = greeting.split(' ').nth(3).unwrap().parse().unwrap();
    c.send(&who.register_line(host, &nonce)).await.unwrap();
    recv(&mut c).await
}

// ---------------------------------------------------------------------------
// Operators and connections (10.1, 10.3)

#[tokio::test(flavor = "multi_thread")]
async fn operators_and_connections() {
    let server = server().await;
    let (mut s, ids) = people(&server, &["alice", "bob"]).await;
    let (alice, bob, op) = (&ids[0], &ids[1], &ids[2]);
    // A configured operator learns it when signing in (4.5).
    let (_c, answer) = server.auth(op).await;
    assert_eq!(answer, "OK uid=op@example.com op=yes");
    let (_, answer) = server.auth(&TestIdentity::new("x@example.org")).await;
    assert!(answer.starts_with("ERR auth-failed"), "{answer}");

    // Every ADMIN command is forbidden to others, guests included.
    s.add("sam", server.guest("sam").await);
    for who in ["alice", "sam"] {
        for line in [
            "admin ops",
            "admin op bob@example.org",
            "admin who",
            "admin notice hi",
            "admin rooms",
            "admin reports",
            "admin bans",
            "admin set guests no",
            "admin purge bob@example.org",
            "admin keys bob@example.org",
        ] {
            exchange(&mut s, who, line, &["ERR forbidden{..}"]).await;
        }
    }

    exchange(&mut s, "op", "admin ops", &["OP op@example.com", "OK"]).await;
    exchange(&mut s, "op", "admin op ~sam", &["ERR forbidden{..}"]).await;
    exchange(&mut s, "op", "admin op alice@example.org", &["OK"]).await;
    exchange(
        &mut s,
        "alice",
        "admin ops",
        &["OP alice@example.org", "OP op@example.com", "OK"],
    )
    .await;
    // At once, on the connection already open, and on the next sign-in.
    let (_c, answer) = server.auth(alice).await;
    assert_eq!(answer, "OK uid=alice@example.org op=yes");
    exchange(
        &mut s,
        "op",
        "admin deop op@example.com",
        &["ERR forbidden{..}"],
    )
    .await;
    exchange(&mut s, "alice", "admin deop alice@example.org", &["OK"]).await;
    exchange(&mut s, "alice", "admin ops", &["ERR forbidden{..}"]).await;
    exchange(
        &mut s,
        "op",
        "admin deop alice@example.org",
        &["ERR not-found{..}"],
    )
    .await;

    // WHO lists every connection, signed in or not.
    let mut anon = anonymous(&server).await;
    let who = command(s.client("op"), "admin who").await;
    assert_eq!(who.last().unwrap(), "OK", "{who:?}");
    let mut uids: Vec<&str> = who[..who.len() - 1]
        .iter()
        .map(|l| {
            let mut parts = l.split(' ');
            assert_eq!(parts.next(), Some("CONNECTION"), "{l}");
            let uid = parts.next().unwrap();
            assert!(parts.next().unwrap().starts_with("127.0.0.1:"), "{l}");
            assert!(parts.next().unwrap().ends_with('Z'), "{l}");
            uid
        })
        .collect();
    uids.sort_unstable();
    // Each auth above left a connection open.
    uids.dedup();
    assert_eq!(
        uids,
        [
            "-",
            "alice@example.org",
            "bob@example.org",
            "op@example.com",
            "~sam"
        ]
    );

    // NOTICE reaches every connection, the operator's own and the
    // anonymous one too.
    exchange(
        &mut s,
        "op",
        "admin notice Down at 22:00",
        &["NOTICE Down at 22:00", "OK"],
    )
    .await;
    for who in ["alice", "bob", "sam"] {
        expect(&mut s, who, "NOTICE Down at 22:00").await;
    }
    assert_eq!(recv(&mut anon).await, "NOTICE Down at 22:00");

    // DISCONNECT closes every connection of the uid, with the reason.
    let phone = server.new_device(bob).await;
    let mut bob_phone = server.sign_in(&phone).await;
    exchange(
        &mut s,
        "op",
        "admin disconnect bob@example.org go away",
        &["OK"],
    )
    .await;
    assert_eq!(until_closed(s.client("bob")).await, ["BYE go away"]);
    assert_eq!(until_closed(&mut bob_phone).await, ["BYE go away"]);
    s.take("bob");
    // They may come back.
    let _bob = server.sign_in(bob).await;
    // For a guest, the session ends too: the name is free at once.
    exchange(&mut s, "op", "admin disconnect ~sam", &["OK"]).await;
    let bye = until_closed(s.client("sam")).await;
    assert_eq!(bye.len(), 1, "{bye:?}");
    assert!(bye[0].starts_with("BYE"), "{bye:?}");
    s.take("sam");
    let _sam = server.guest("sam").await;
    exchange(
        &mut s,
        "op",
        "admin disconnect ~nobody",
        &["ERR not-found{..}"],
    )
    .await;
    exchange(
        &mut s,
        "op",
        "admin disconnect carol@example.org",
        &["ERR not-found{..}"],
    )
    .await;
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Server bans (10.2)

/// Identity and domain bans close open connections, and AUTH and REGISTER
/// check them only after the signature, so that only the key's holder
/// learns of a ban.
#[tokio::test(flavor = "multi_thread")]
async fn server_bans_are_checked_after_the_signature() {
    let server = server().await;
    let (mut s, _) = people(&server, &["alice"]).await;
    let dan = server.identity("dan@example.net");
    s.add("dan", server.sign_in(&dan).await);
    join(&mut s, "alice", "#general").await;

    exchange(&mut s, "op", "admin ban dan@example.net spam", &["OK"]).await;
    // BYE carries the ban's reason.
    assert_eq!(until_closed(s.client("dan")).await, ["BYE spam"]);
    s.take("dan");
    assert!(
        auth_signed_for(&server, &dan, "other.example")
            .await
            .starts_with("ERR auth-failed"),
    );
    assert!(
        auth_signed_for(&server, &dan, server.hostname())
            .await
            .starts_with("ERR forbidden"),
    );
    // A key that is not dan's learns nothing either.
    let stranger = dan.new_key();
    assert!(
        auth_signed_for(&server, &stranger, server.hostname())
            .await
            .starts_with("ERR auth-failed"),
    );

    // A domain ban covers its subdomains.
    let erin = server.identity("erin@sub.example.net");
    let mut erin_conn = server.sign_in(&erin).await;
    exchange(&mut s, "op", "admin ban *@example.net", &["OK"]).await;
    assert_eq!(
        until_closed(&mut erin_conn).await,
        ["BYE banned from this server"]
    );
    assert!(
        auth_signed_for(&server, &erin, "other.example")
            .await
            .starts_with("ERR auth-failed"),
    );
    assert!(
        auth_signed_for(&server, &erin, server.hostname())
            .await
            .starts_with("ERR forbidden"),
    );
    // Others are untouched.
    exchange(&mut s, "alice", "info", &["OK version=1{..}"]).await;

    // REGISTER of a banned name, likewise.
    exchange(&mut s, "op", "admin ban mallory@example.org", &["OK"]).await;
    let mallory = TestIdentity::new("mallory@example.org");
    assert!(
        register_signed_for(&server, &mallory, "other.example")
            .await
            .starts_with("ERR auth-failed"),
    );
    assert!(
        register_signed_for(&server, &mallory, server.hostname())
            .await
            .starts_with("ERR forbidden"),
    );

    exchange(
        &mut s,
        "op",
        "admin bans",
        &[
            "SERVERBAN *@example.net",
            "SERVERBAN dan@example.net spam",
            "SERVERBAN mallory@example.org",
            "OK",
        ],
    )
    .await;
    exchange(&mut s, "op", "admin unban dan@example.net", &["OK"]).await;
    exchange(
        &mut s,
        "op",
        "admin unban dan@example.net",
        &["ERR not-found{..}"],
    )
    .await;
    exchange(&mut s, "op", "admin unban *@example.net", &["OK"]).await;
    let _dan = server.sign_in(&dan).await;
    let _erin = server.sign_in(&erin).await;
    s.settled().await;
    server.stop().await;
}

/// A ban of a connected guest bans its address, which stops guests but
/// not identities (10.2).
#[tokio::test(flavor = "multi_thread")]
async fn a_guest_ban_bans_its_address() {
    let server = server().await;
    let (mut s, ids) = people(&server, &["alice"]).await;
    s.add("sam", server.guest("sam").await);
    exchange(&mut s, "op", "admin ban ~nobody", &["ERR not-found{..}"]).await;
    exchange(&mut s, "op", "admin ban ~sam flooding", &["OK"]).await;
    let bye = until_closed(s.client("sam")).await;
    assert_eq!(bye, ["BYE flooding"]);
    s.take("sam");
    exchange(
        &mut s,
        "op",
        "admin bans",
        &["SERVERBAN 127.0.0.1 flooding", "OK"],
    )
    .await;
    let (_c, answer) = try_guest(&server, "kim").await;
    assert!(answer.starts_with("ERR forbidden"), "{answer}");
    // Identities from the same address still sign in.
    let _alice = server.sign_in(&ids[0]).await;
    exchange(&mut s, "op", "admin unban ~sam", &["ERR not-found{..}"]).await;
    exchange(&mut s, "op", "admin unban 127.0.0.1", &["OK"]).await;
    let mut kim = server.guest("kim").await;

    // A prefix ban ends the sessions inside it.
    exchange(&mut s, "op", "admin ban 127.0.0.0/8 lab", &["OK"]).await;
    assert_eq!(until_closed(&mut kim).await, ["BYE lab"]);
    let (_c, answer) = try_guest(&server, "lee").await;
    assert!(answer.starts_with("ERR forbidden"), "{answer}");
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Server settings (10.6)

/// `ADMIN SET guests no` ends every guest session, connected or waiting to
/// be resumed, with their PARTs (4.2, 10.6).
#[tokio::test(flavor = "multi_thread")]
async fn admin_set_guests_no_ends_guest_sessions() {
    let server = server().await;
    let (mut s, _) = people(&server, &["alice"]).await;
    let ok = join(&mut s, "alice", "#general").await;
    s.bind("id", &value(&ok, "id"));
    s.add("sam", server.guest("sam").await);
    join(&mut s, "sam", "#general").await;
    expect(
        &mut s,
        "alice",
        "@seq=2;t={*};from=~sam;id={id} JOIN #general",
    )
    .await;
    let (mut kim, kim_token) = server.guest_session("kim", None).await;
    let lines = command(&mut kim, "join #general").await;
    assert!(lines.last().unwrap().starts_with("OK id="), "{lines:?}");
    expect(
        &mut s,
        "alice",
        "@seq=3;t={*};from=~kim;id={id} JOIN #general",
    )
    .await;
    expect(
        &mut s,
        "sam",
        "@seq=3;t={*};from=~kim;id={id} JOIN #general",
    )
    .await;
    // kim's connection goes; the session waits to be resumed.
    kim.send("quit").await.unwrap();
    until_closed(&mut kim).await;

    assert!(server_info(&server).await.contains(" guests=yes "));
    exchange(&mut s, "op", "admin set guests no", &["OK"]).await;
    // sam may see kim leave first.
    let lines = until_closed(s.client("sam")).await;
    assert_eq!(lines.last().unwrap(), "BYE guests are no longer allowed");
    assert!(lines.len() <= 2, "{lines:?}");
    s.take("sam");
    // Both leave #general, in some order.
    let mut parts = vec![recv(s.client("alice")).await, recv(s.client("alice")).await];
    parts.sort_unstable();
    for (line, who) in parts.iter().zip(["kim", "sam"]) {
        assert!(
            line.ends_with(&format!(";from=~{who} PART #general")),
            "{parts:?}"
        );
    }
    assert!(server_info(&server).await.contains(" guests=no "));
    let (_c, answer) = try_guest(&server, "lee").await;
    assert!(answer.starts_with("ERR forbidden"), "{answer}");

    // Back on, kim's token resumes nothing: its session ended.
    exchange(&mut s, "op", "admin set guests yes ", &["OK"]).await;
    let (_kim, _) = server.guest_session("kim", Some(&kim_token)).await;
    exchange(
        &mut s,
        "alice",
        "info #general",
        &[
            "*",
            "*",
            "*",
            "*",
            "*",
            "OK id={id} members=1 head=5 role=member joined=yes",
        ],
    )
    .await;

    // The other settings, as INFO shows them.
    exchange(&mut s, "op", "admin set registration closed", &["OK"]).await;
    exchange(&mut s, "op", r"admin set welcome Hello\sthere ", &["OK"]).await;
    exchange(&mut s, "op", "admin set retention forever", &["OK"]).await;
    exchange(
        &mut s,
        "op",
        "admin set colour blue",
        &["ERR not-supported{..}"],
    )
    .await;
    let info = server_info(&server).await;
    assert!(info.contains(" register=no "), "{info}");
    assert!(info.contains(" retention=forever "), "{info}");
    let greeting = recv(&mut server.connect().await).await;
    assert!(greeting.ends_with(r" Hello\sthere "), "{greeting}");
    let (_, answer) = server.auth(&TestIdentity::new("zed@example.org")).await;
    assert!(answer.starts_with("ERR auth-failed"), "{answer}");
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Rooms and content (10.4)

/// ADMIN ROOMS lists every room; ADMIN DROP of a room from the
/// configuration creates it again at once, empty, with a new id.
#[tokio::test(flavor = "multi_thread")]
async fn rooms_and_drop_of_a_configured_room() {
    let server = server().await;
    let (mut s, _) = people(&server, &["alice", "bob"]).await;
    let ok = join(&mut s, "alice", "#general").await;
    let old_id = value(&ok, "id");
    join(&mut s, "bob", "#general").await;
    expect(
        &mut s,
        "alice",
        "@seq=2;t={*};from=bob@example.org;id={*} JOIN #general",
    )
    .await;
    join(&mut s, "alice", "#secret").await;
    exchange(&mut s, "alice", "set #secret public no", &["*", "OK seq=2"]).await;
    exchange(
        &mut s,
        "alice",
        "set #secret topic Hush",
        &["*", "OK seq=3"],
    )
    .await;

    exchange(&mut s, "bob", "list", &["ROOM #general 2", "OK more=0"]).await;
    exchange(
        &mut s,
        "op",
        "admin rooms",
        &["ROOM #general 2", "ROOM #secret 1 Hush", "OK more=0"],
    )
    .await;
    exchange(
        &mut s,
        "op",
        "admin rooms limit=1",
        &["ROOM #general 2", "OK more=1"],
    )
    .await;
    exchange(
        &mut s,
        "op",
        "admin rooms after=#general limit=1",
        &["ROOM #secret 1 Hush", "OK more=0"],
    )
    .await;

    exchange(&mut s, "op", "admin drop #nowhere", &["ERR not-found{..}"]).await;
    exchange(&mut s, "op", "admin drop #general cleanup", &["OK"]).await;
    for who in ["alice", "bob"] {
        expect(&mut s, who, &format!("@id={old_id} DROP #general cleanup")).await;
    }
    let lines = command(s.client("bob"), "info #general").await;
    let ok = lines.last().unwrap();
    assert_ne!(value(ok, "id"), old_id, "{lines:?}");
    assert!(
        ok.ends_with(" members=0 head=0 role=none joined=no"),
        "{lines:?}"
    );
    exchange(&mut s, "bob", "sync", &["OK"]).await;
    exchange(&mut s, "bob", "history #general", &["OK id={*} more=0"]).await;
    let ok = join(&mut s, "bob", "#general").await;
    assert_ne!(value(&ok, "id"), old_id);
    assert!(ok.ends_with(" head=1"), "{ok}");
    exchange(
        &mut s,
        "op",
        "admin rooms",
        &["ROOM #general 1", "ROOM #secret 1 Hush", "OK more=0"],
    )
    .await;
    s.settled().await;
    server.stop().await;
}

/// ADMIN PURGE deletes a uid's messages in every room, with the operator
/// as `from`, optionally only the last hours; a guest uid covers every
/// session under the name. A reported message keeps its report's copy.
#[tokio::test(flavor = "multi_thread")]
async fn purge() {
    let server = server().await;
    let (mut s, _) = people(&server, &["alice", "bob"]).await;
    for room in ["#a", "#b"] {
        join(&mut s, "alice", room).await;
        join(&mut s, "bob", room).await;
        expect(
            &mut s,
            "alice",
            &format!("@seq=2;t={{*}};from=bob@example.org;id={{*}} JOIN {room}"),
        )
        .await;
    }
    s.play(
        "bob C: msg #a one
         bob S: @seq=3;t={*};from=bob@example.org MSG #a one
         bob S: OK seq=3
         alice S: @seq=3;t={*};from=bob@example.org MSG #a one
         bob C: @edit=3 msg #a one!
         bob S: @seq=4;t={*};from=bob@example.org;edit=3 MSG #a one!
         bob S: OK seq=4
         alice S: @seq=4;t={*};from=bob@example.org;edit=3 MSG #a one!
         alice C: @react=3 msg #a 👍
         alice S: @seq=5;t={*};from=alice@example.org;react=3 MSG #a 👍
         alice S: OK seq=5
         bob S: @seq=5;t={*};from=alice@example.org;react=3 MSG #a 👍
         alice C: @reply=3 msg #a nice
         alice S: @seq=6;t={*};from=alice@example.org;reply=3 MSG #a nice
         alice S: OK seq=6
         bob S: @seq=6;t={*};from=alice@example.org;reply=3 MSG #a nice
         bob C: msg #b two
         bob S: @seq=3;t={*};from=bob@example.org MSG #b two
         bob S: OK seq=3
         alice S: @seq=3;t={*};from=bob@example.org MSG #b two",
    )
    .await;
    exchange(
        &mut s,
        "alice",
        "report #b 3 rude",
        &[
            "@report={rid};t={*} REPORT #b 3 rude",
            "*MSG #b two",
            "OK id={rid}",
        ],
    )
    .await;
    expect(
        &mut s,
        "op",
        "@report={rid};t={*};from=alice@example.org REPORT #b 3 rude",
    )
    .await;
    expect(
        &mut s,
        "op",
        "@report={rid};seq=3;t={*};from=bob@example.org MSG #b two",
    )
    .await;

    server.advance(2 * HOUR);
    exchange(
        &mut s,
        "bob",
        "msg #b three",
        &["*MSG #b three", "OK seq=4"],
    )
    .await;
    expect(
        &mut s,
        "alice",
        "@seq=4;t={*};from=bob@example.org MSG #b three",
    )
    .await;

    // The last hour: only "three".
    exchange(
        &mut s,
        "op",
        "admin purge bob@example.org hours=1",
        &["OK deleted=1"],
    )
    .await;
    for who in ["alice", "bob"] {
        expect(&mut s, who, "@seq=5;t={*};from=op@example.com DELETE #b 4").await;
    }
    // Everything: "one" (with its edit and alice's reaction, uncounted)
    // and "two".
    exchange(
        &mut s,
        "op",
        "admin purge bob@example.org",
        &["OK deleted=2"],
    )
    .await;
    for who in ["alice", "bob"] {
        expect(&mut s, who, "@seq=7;t={*};from=op@example.com DELETE #a 3").await;
    }
    for who in ["alice", "bob"] {
        expect(&mut s, who, "@seq=6;t={*};from=op@example.com DELETE #b 3").await;
    }
    exchange(
        &mut s,
        "op",
        "admin purge bob@example.org",
        &["OK deleted=0"],
    )
    .await;
    exchange(
        &mut s,
        "alice",
        "history #a after=2",
        &[
            "@seq=3;t={*};from=bob@example.org;deleted MSG #a",
            "@seq=4;t={*};from=bob@example.org;edit=3;deleted MSG #a",
            "@seq=5;t={*};from=alice@example.org;react=3;deleted MSG #a",
            "@seq=6;t={*};from=alice@example.org;reply=3 MSG #a nice",
            "@seq=7;t={*};from=op@example.com DELETE #a 3",
            "OK id={*} more=0",
        ],
    )
    .await;
    // The report's copy is untouched.
    exchange(
        &mut s,
        "op",
        "admin reports",
        &[
            "@report={rid};t={*};from=alice@example.org REPORT #b 3 rude",
            "@report={rid};seq=3;t={*};from=bob@example.org MSG #b two",
            "OK",
        ],
    )
    .await;

    // A guest name: every session under it.
    let mut sam = server.guest("sam").await;
    command(&mut sam, "join #a").await;
    expect(&mut s, "alice", "@seq=8;t={*};from=~sam;id={*} JOIN #a").await;
    expect(&mut s, "bob", "@seq=8;t={*};from=~sam;id={*} JOIN #a").await;
    command(&mut sam, "msg #a first sam").await;
    exchange(&mut s, "op", "admin disconnect ~sam", &["OK"]).await;
    until_closed(&mut sam).await;
    let mut sam = server.guest("sam").await;
    command(&mut sam, "join #a").await;
    command(&mut sam, "msg #a second sam").await;
    for who in ["alice", "bob"] {
        expect(&mut s, who, "@seq=9;t={*};from=~sam MSG #a first sam").await;
        expect(&mut s, who, "@seq=10;t={*};from=~sam PART #a").await;
        expect(&mut s, who, "@seq=11;t={*};from=~sam;id={*} JOIN #a").await;
        expect(&mut s, who, "@seq=12;t={*};from=~sam MSG #a second sam").await;
    }
    exchange(&mut s, "op", "admin purge ~sam", &["OK deleted=2"]).await;
    for who in ["alice", "bob"] {
        expect(&mut s, who, "@seq=13;t={*};from=op@example.com DELETE #a 9").await;
        expect(
            &mut s,
            who,
            "@seq=14;t={*};from=op@example.com DELETE #a 12",
        )
        .await;
    }
    s.settled().await;
    server.stop().await;
}

/// UNREGISTER `purge=yes` (4.8): the identity leaves its rooms, and its
/// messages are deleted with itself as `from`. ADMIN UNREGISTER (10.5)
/// leaves them, and ADMIN PURGE can still remove them afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn unregister_with_and_without_purge() {
    let server = server().await;
    let (mut s, ids) = people(&server, &["alice", "bob", "carol"]).await;
    let bob = &ids[1];
    join(&mut s, "alice", "#a").await;
    join(&mut s, "bob", "#a").await;
    expect(
        &mut s,
        "alice",
        "@seq=2;t={*};from=bob@example.org;id={*} JOIN #a",
    )
    .await;
    join(&mut s, "carol", "#a").await;
    for who in ["alice", "bob"] {
        expect(
            &mut s,
            who,
            "@seq=3;t={*};from=carol@example.org;id={*} JOIN #a",
        )
        .await;
    }
    for (who, text, seq) in [("bob", "b1", 4), ("carol", "c1", 5), ("bob", "b2", 6)] {
        exchange(
            &mut s,
            who,
            &format!("msg #a {text}"),
            &["*", &format!("OK seq={seq}")],
        )
        .await;
        for other in ["alice", "bob", "carol"] {
            if other != who {
                expect(
                    &mut s,
                    other,
                    &format!("@seq={seq};t={{*}};from={who}@example.org MSG #a {text}"),
                )
                .await;
            }
        }
    }
    let phone = server.new_device(bob).await;
    let mut bob_phone = server.sign_in(&phone).await;

    exchange(
        &mut s,
        "bob",
        "unregister alice@example.org purge=yes",
        &["ERR forbidden{..}"],
    )
    .await;
    s.client("bob")
        .send("unregister bob@example.org purge=yes")
        .await
        .unwrap();
    let mut lines = until_closed(s.client("bob")).await;
    s.take("bob");
    let bye = lines.pop().unwrap();
    assert_eq!(bye, "BYE identity deleted");
    assert_eq!(lines.pop().unwrap(), "OK");
    let phone_lines = until_closed(&mut bob_phone).await;
    assert_eq!(
        phone_lines.last().unwrap(),
        "BYE identity deleted",
        "{phone_lines:?}"
    );
    for who in ["alice", "carol"] {
        s.play(&format!(
            "{who} S: @seq=7;t={{*}};from=bob@example.org PART #a
             {who} S: @seq=8;t={{*}};from=bob@example.org DELETE #a 4
             {who} S: @seq=9;t={{*}};from=bob@example.org DELETE #a 6"
        ))
        .await;
    }
    // bob is gone: a new sign-in with his key fails.
    let (_c, answer) = server.auth(bob).await;
    assert!(answer.starts_with("ERR auth-failed"), "{answer}");

    // ADMIN UNREGISTER keeps carol's messages, until they are purged.
    exchange(&mut s, "op", "admin unregister carol@example.org", &["OK"]).await;
    let lines = until_closed(s.client("carol")).await;
    assert_eq!(lines.last().unwrap(), "BYE identity deleted", "{lines:?}");
    s.take("carol");
    expect(
        &mut s,
        "alice",
        "@seq=10;t={*};from=carol@example.org PART #a",
    )
    .await;
    exchange(
        &mut s,
        "alice",
        "history #a after=4 limit=1",
        &[
            "@seq=5;t={*};from=carol@example.org MSG #a c1",
            "OK id={*} more=1",
        ],
    )
    .await;
    exchange(
        &mut s,
        "op",
        "admin purge carol@example.org",
        &["OK deleted=1"],
    )
    .await;
    expect(
        &mut s,
        "alice",
        "@seq=11;t={*};from=op@example.com DELETE #a 5",
    )
    .await;
    // The name is not given out again (4.8, 10.5).
    let again = TestIdentity::new("carol@example.org");
    assert!(
        register_signed_for(&server, &again, server.hostname())
            .await
            .starts_with("ERR "),
    );
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Hosted identities (10.5)

#[tokio::test(flavor = "multi_thread")]
async fn hosted_identities() {
    let server = server().await;
    let (mut s, ids) = people(&server, &["alice"]).await;
    let alice = &ids[0];
    let keys = command(s.client("op"), "admin keys alice@example.org").await;
    assert_eq!(keys, [format!("KEY {}", alice.public_key()), "OK".into()]);
    exchange(
        &mut s,
        "op",
        "admin keys op@example.com",
        &["ERR not-found{..}"],
    )
    .await;
    exchange(
        &mut s,
        "op",
        "admin keys nobody@example.org",
        &["ERR not-found{..}"],
    )
    .await;

    // An operator adds a key for alice, who lost hers.
    let new = alice.new_key();
    exchange(
        &mut s,
        "op",
        &format!(
            "admin addkey alice@example.org {} recovered",
            new.public_key()
        ),
        &["OK"],
    )
    .await;
    let mut recovered = server.sign_in(&new).await;
    let mut keys = command(&mut recovered, "key list").await;
    assert_eq!(keys.pop().unwrap(), "OK");
    keys.sort_unstable();
    let mut want = [
        format!("KEY {}", alice.public_key()),
        format!("KEY {} recovered", new.public_key()),
    ];
    want.sort_unstable();
    assert_eq!(keys, want);
    // DELKEY closes that key's connections, and may remove the last key.
    exchange(
        &mut s,
        "op",
        &format!("admin delkey alice@example.org {}", alice.public_key()),
        &["OK"],
    )
    .await;
    assert_eq!(
        until_closed(s.client("alice")).await,
        ["BYE this device's key was removed"]
    );
    s.take("alice");
    exchange(
        &mut s,
        "op",
        &format!("admin delkey alice@example.org {}", new.public_key()),
        &["OK"],
    )
    .await;
    assert_eq!(
        until_closed(&mut recovered).await,
        ["BYE this device's key was removed"]
    );
    exchange(&mut s, "op", "admin keys alice@example.org", &["OK"]).await;
    let (_c, answer) = server.auth(&new).await;
    assert!(answer.starts_with("ERR auth-failed"), "{answer}");
    exchange(&mut s, "op", "admin unregister alice@example.org", &["OK"]).await;
    exchange(
        &mut s,
        "op",
        "admin keys alice@example.org",
        &["ERR not-found{..}"],
    )
    .await;
    s.settled().await;
    server.stop().await;
}

/// A guest in a room from the configuration when it is dropped: its
/// session ending later records nothing in the new room (4.2, 10.4).
#[tokio::test(flavor = "multi_thread")]
async fn a_guest_in_a_dropped_room() {
    let server = server().await;
    let (mut s, _) = people(&server, &["alice"]).await;
    s.add("sam", server.guest("sam").await);
    let ok = join(&mut s, "sam", "#general").await;
    let old_id = value(&ok, "id");
    exchange(&mut s, "op", "admin drop #general", &["OK"]).await;
    expect(&mut s, "sam", &format!("@id={old_id} DROP #general")).await;
    // The new room is empty; the guest is not in it.
    exchange(&mut s, "sam", "msg #general hi", &["ERR {..}"]).await;
    let ok = join(&mut s, "alice", "#general").await;
    assert!(ok.ends_with(" head=1"), "{ok}");
    // The guest's session ends: no PART in the new room.
    exchange(&mut s, "op", "admin disconnect ~sam", &["OK"]).await;
    until_closed(s.client("sam")).await;
    s.take("sam");
    exchange(
        &mut s,
        "alice",
        "history #general",
        &[
            "@seq=1;t={*};from=alice@example.org;id={*} JOIN #general",
            "OK id={*} more=0",
        ],
    )
    .await;
    // A new guest of that name joins the new room as anyone would.
    s.add("sam", server.guest("sam").await);
    join(&mut s, "sam", "#general").await;
    expect(
        &mut s,
        "alice",
        "@seq=2;t={*};from=~sam;id={*} JOIN #general",
    )
    .await;
    s.settled().await;
    server.stop().await;
}

/// What M4 stores survives a restart: room settings, roles, invitations,
/// bans, deleted messages, reports, operators, server bans and server
/// settings.
#[tokio::test(flavor = "multi_thread")]
async fn m4_state_survives_a_restart() {
    let mut server = server().await;
    let (mut s, ids) = people(&server, &["alice", "bob", "carol", "dave"]).await;
    let ok = join(&mut s, "alice", "#p").await;
    let id = value(&ok, "id");
    for line in [
        "set #p public no",
        "set #p topic Private",
        "set #p retention 7",
        "set #p guests read",
    ] {
        let lines = command(s.client("alice"), line).await;
        assert!(lines.last().unwrap().starts_with("OK seq="), "{lines:?}");
    }
    for who in ["bob", "carol"] {
        command(s.client("alice"), &format!("invite #p {who}@example.org")).await;
        expect(&mut s, who, &format!("*INVITE #p {who}@example.org")).await;
    }
    join(&mut s, "bob", "#p").await;
    expect(&mut s, "alice", "*JOIN #p").await;
    command(s.client("alice"), "role #p bob@example.org mod").await;
    expect(&mut s, "bob", "*ROLE #p bob@example.org mod").await;
    command(s.client("bob"), "part #p").await;
    expect(&mut s, "alice", "*PART #p").await;
    command(s.client("alice"), "ban #p dave@example.org troll").await;
    exchange(&mut s, "alice", "msg #p gone soon", &["*", "OK seq=12"]).await;
    exchange(&mut s, "alice", "msg #p rude", &["*", "OK seq=13"]).await;
    exchange(&mut s, "alice", "delete #p 12", &["*", "OK seq=14"]).await;
    // bob is a moderator, so a reviewer of his own report.
    exchange(
        &mut s,
        "bob",
        "report #p 13 rude",
        &[
            "@report={rid};t={*} REPORT #p 13 rude",
            "*MSG #p rude",
            "OK id={rid}",
        ],
    )
    .await;
    expect(&mut s, "alice", "*REPORT #p 13 rude").await;
    expect(&mut s, "alice", "*MSG #p rude").await;
    expect(&mut s, "op", "*REPORT #p 13 rude").await;
    expect(&mut s, "op", "*MSG #p rude").await;
    exchange(&mut s, "op", "admin op carol@example.org", &["OK"]).await;
    exchange(&mut s, "op", "admin ban spam@example.net", &["OK"]).await;
    exchange(&mut s, "op", "admin ban 198.51.100.0/24 proxies", &["OK"]).await;
    exchange(&mut s, "op", "admin set retention 90", &["OK"]).await;
    exchange(&mut s, "op", "admin set registration closed", &["OK"]).await;
    exchange(&mut s, "op", "admin set welcome Hi", &["OK"]).await;
    s.settled().await;
    drop(s);

    server.restart().await;
    let mut s = Session::new();
    for (name, who) in ["alice", "bob", "carol", "dave", "op"].iter().zip(&ids) {
        s.add(name, server.sign_in(who).await);
    }
    exchange(
        &mut s,
        "alice",
        "info #p",
        &[
            "SET #p topic Private",
            "SET #p public no",
            "SET #p guests read",
            "SET #p retention 7",
            "SET #p e2ee no",
            &format!("OK id={id} members=1 head=14 role=owner joined=yes"),
        ],
    )
    .await;
    exchange(
        &mut s,
        "bob",
        "roles #p",
        &[
            "ROLE #p alice@example.org owner",
            "ROLE #p bob@example.org mod",
            "OK",
        ],
    )
    .await;
    exchange(
        &mut s,
        "bob",
        "bans #p",
        &["BAN #p dave@example.org troll", "OK"],
    )
    .await;
    // carol's invitation still lets her in; dave's ban keeps him out.
    exchange(&mut s, "dave", "join #p", &["ERR {..}"]).await;
    join(&mut s, "carol", "#p").await;
    expect(&mut s, "alice", "*JOIN #p").await;
    exchange(
        &mut s,
        "alice",
        "history #p after=11 limit=2",
        &[
            "@seq=12;t={*};from=alice@example.org;deleted MSG #p",
            "@seq=13;t={*};from=alice@example.org MSG #p rude",
            "OK id={*} more=1",
        ],
    )
    .await;
    exchange(&mut s, "alice", "delete #p 12", &["OK seq=14"]).await;
    exchange(
        &mut s,
        "bob",
        "reports #p",
        &[
            "@report={rid};t={*} REPORT #p 13 rude",
            "*MSG #p rude",
            "OK",
        ],
    )
    .await;
    exchange(&mut s, "bob", "report #p 13 again", &["OK id={rid}"]).await;
    // carol is still an operator; op is, from the configuration.
    exchange(
        &mut s,
        "carol",
        "admin ops",
        &["OP carol@example.org", "OP op@example.com", "OK"],
    )
    .await;
    exchange(
        &mut s,
        "op",
        "admin bans",
        &[
            "SERVERBAN 198.51.100.0/24 proxies",
            "SERVERBAN spam@example.net",
            "OK",
        ],
    )
    .await;
    let info = server_info(&server).await;
    assert!(info.contains(" register=no "), "{info}");
    assert!(info.contains(" retention=90 "), "{info}");
    let greeting = recv(&mut server.connect().await).await;
    assert!(greeting.ends_with(" Hi"), "{greeting}");
    s.settled().await;
    server.stop().await;
}
