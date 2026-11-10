//! The greeting (4.1), ANON and GUEST (4.2), guest sessions, and PING,
//! PONG and QUIT (11).

use std::time::Duration;

use risala_proto::connection::ConnectionKind;
use risala_proto::names::Uid;

use super::*;
use crate::core::state::Who;
use crate::store::AdminStore as _;

#[tokio::test]
async fn the_greeting_names_the_host_and_a_fresh_nonce() {
    let mut h = Harness::new();
    let mut a = h.open("203.0.113.7:51000", Some("chat.example.org"));
    let mut b = h.open("203.0.113.8:51000", Some("chat.example.org"));
    let a = a.raw_lines();
    let b = b.raw_lines();
    assert_eq!(a.len(), 1);
    let words: Vec<&str> = a[0].split(' ').collect();
    assert_eq!(words[..3], ["RISALA", "1", "chat.example.org"]);
    // 32 random bytes in lower-case hex (4.1: 16 to 64).
    let nonce = words[3];
    assert_eq!(nonce.len(), 64);
    assert!(
        nonce
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    );
    assert_eq!(words[4..], ["Welcome!"]);
    // Unique to the connection.
    assert_ne!(b[0].split(' ').nth(3), Some(nonce));

    // Another name the client sent in SNI, or the server's own without SNI.
    let mut other = h.open("203.0.113.7:51001", Some("risala.example.org"));
    assert_eq!(
        other.lines(),
        ["RISALA 1 risala.example.org <nonce> Welcome!"]
    );
    let mut bare = h.open("203.0.113.7:51002", None);
    assert_eq!(bare.lines(), ["RISALA 1 chat.example.org <nonce> Welcome!"]);
}

/// The welcome text of ADMIN SET outlasts the configuration's (10.6), and
/// a greeting without one has no text.
#[tokio::test]
async fn the_greeting_has_the_stored_welcome() {
    let store = SqliteStore::open_in_memory().unwrap();
    store
        .save_setting(&"welcome Hello there".parse().unwrap())
        .unwrap();
    let mut h = Harness::on(config(), timers(), store);
    let mut c = h.open("203.0.113.7:51000", Some("chat.example.org"));
    assert_eq!(c.lines(), ["RISALA 1 chat.example.org <nonce> Hello there"]);

    let mut config = config();
    config.server.welcome.clear();
    let mut h = Harness::with(config, timers());
    let mut c = h.open("203.0.113.7:51000", Some("chat.example.org"));
    assert_eq!(c.lines(), ["RISALA 1 chat.example.org <nonce>"]);
}

/// A connection becomes one kind once, and stays it (4.1).
#[tokio::test]
async fn anon_makes_a_connection_anonymous_once() {
    let mut h = Harness::new();
    let mut c = h.connect();
    assert_eq!(c.handle.kind(), ConnectionKind::New);
    h.send(&c, "@ref=a anon").await;
    assert_eq!(c.lines(), ["@ref=a OK"]);
    assert_eq!(c.handle.kind(), ConnectionKind::Anonymous);
    for line in ["anon", "guest sam", "auth alice@example.org AAAA"] {
        // AUTH's signature does not matter: the kind is checked first.
        let line = if line.starts_with("auth") {
            format!("auth alice@example.org {}AAA=", "A".repeat(3224))
        } else {
            line.to_owned()
        };
        h.send(&c, &line).await;
        assert_eq!(c.lines(), ["ERR already-authenticated"], "{line}");
    }
    assert_eq!(c.handle.kind(), ConnectionKind::Anonymous);
    assert!(h.hub.guest_sessions().is_empty());
}

/// ANON is refused while the server allows no anonymous connections
/// (10.6), and the connection stays new.
#[tokio::test]
async fn anon_can_be_turned_off() {
    let mut config = config();
    config.server.anon = false;
    let mut h = Harness::with(config, timers());
    let mut c = h.connect();
    h.send(&c, "anon").await;
    assert_eq!(c.lines(), ["ERR forbidden anonymous connections are off"]);
    assert_eq!(c.handle.kind(), ConnectionKind::New);
    h.send(&c, "guest sam").await;
    assert_eq!(c.lines(), ["OK uid=~sam token=<token>"]);
}

#[tokio::test]
async fn guest_starts_a_session() {
    let mut h = Harness::new();
    let (c, token) = h.guest("sam").await;
    assert_eq!(c.handle.kind(), ConnectionKind::Guest);
    // The token is an id with at least 128 bits of randomness (4.2).
    assert_eq!(h.hub.guest_sessions(), ["~sam".parse::<Uid>().unwrap()]);
    assert_eq!(token.len(), crate::core::TOKEN_LEN);
    assert!(token.parse::<risala_proto::names::Id>().is_ok());
    // The server keeps only its hash (Section 14).
    {
        let reg = h.inner().reg();
        let session = &reg.sessions[&"~sam".parse::<Uid>().unwrap()];
        assert!(session.token.matches(token.as_bytes()));
        assert_eq!(session.conn, Some(c.id));
    }
    // The name is taken while the session lasts, with or without a token
    // that does not match, in any case (3.5).
    let mut other = h.connect();
    for line in ["guest sam", "guest SAM token=wrong", "guest sam token=AAAA"] {
        h.send(&other, line).await;
        assert_eq!(other.lines(), ["ERR name-taken"], "{line}");
    }
    assert_eq!(other.handle.kind(), ConnectionKind::New);
    // A token that matches no session is ignored (4.2).
    h.send(&other, &format!("guest bea token={token}")).await;
    assert_eq!(other.lines(), ["OK uid=~bea token=<token>"]);
}

#[tokio::test]
async fn guests_can_be_turned_off() {
    let mut config = config();
    config.server.guests = false;
    let mut h = Harness::with(config, timers());
    let mut c = h.connect();
    h.send(&c, "guest sam").await;
    assert_eq!(c.lines(), ["ERR forbidden guests are not allowed"]);
    assert_eq!(c.handle.kind(), ConnectionKind::New);
    assert!(h.hub.guest_sessions().is_empty());
}

/// A guest whose connection drops resumes its session with its token, and
/// gets a new one; the old one stops working (4.2).
#[tokio::test]
async fn a_closed_guest_resumes_with_its_token() {
    let mut h = Harness::new();
    let (c, token) = h.guest("sam").await;
    h.close(c).await;
    // The session waits, and holds the name.
    let mut other = h.connect();
    h.send(&other, "guest sam").await;
    assert_eq!(other.lines(), ["ERR name-taken"]);

    let mut back = h.connect();
    h.send(&back, &format!("guest sam token={token}")).await;
    let ok = back.raw_lines();
    let new_token = value(&ok[0], "token");
    assert_eq!(ok, [format!("OK uid=~sam token={new_token} resumed=yes")]);
    assert_ne!(new_token, token);
    assert_eq!(back.handle.kind(), ConnectionKind::Guest);

    // The old token no longer resumes it.
    h.close(back).await;
    let mut again = h.connect();
    h.send(&again, &format!("guest sam token={token}")).await;
    assert_eq!(again.lines(), ["ERR name-taken"]);
    h.send(&again, &format!("guest sam token={new_token}"))
        .await;
    assert_eq!(again.lines(), ["OK uid=~sam token=<token> resumed=yes"]);
}

/// Resuming a session that another connection still has closes that one
/// with BYE, and runs none of its commands from then on (4.2).
#[tokio::test]
async fn resuming_takes_the_session_from_its_connection() {
    let mut h = Harness::new();
    let (mut first, token) = h.guest("sam").await;
    let mut second = h.connect();
    h.send(&second, &format!("guest sam token={token}")).await;
    assert_eq!(second.lines(), ["OK uid=~sam token=<token> resumed=yes"]);
    assert_eq!(
        first.lines(),
        [format!("<close> BYE {}", crate::core::BYE_RESUMED)]
    );
    h.send(&first, "ping").await;
    assert!(first.lines().is_empty());
    // Its closing does not start the resume period: the session is
    // connected elsewhere.
    h.close(first).await;
    {
        let reg = h.inner().reg();
        let session = &reg.sessions[&"~sam".parse::<Uid>().unwrap()];
        assert_eq!(session.conn, Some(second.id));
        assert!(session.expiry.is_none());
    }
    h.send(&second, "ping").await;
    assert_eq!(second.lines(), [format!("@t={} OK", h.inner().now())]);
}

/// Once the resume period is over, the session ends and the name is free
/// (4.2). QUIT closes the connection like any other close.
#[tokio::test(start_paused = true)]
async fn a_session_ends_after_its_resume_period() {
    let mut h = Harness::with(config(), short_resume());
    let (mut c, token) = h.guest("sam").await;
    h.send(&c, "quit").await;
    assert_eq!(c.lines(), ["OK", "<close>"]);
    h.close(c).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(h.hub.guest_sessions().len(), 1);
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Let the expiry and its store call finish.
    for _ in 0..100 {
        if h.hub.guest_sessions().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(h.hub.guest_sessions().is_empty());
    let mut c = h.connect();
    h.send(&c, &format!("guest sam token={token}")).await;
    assert_eq!(c.lines(), ["OK uid=~sam token=<token>"]);
}

/// Ending a session closes its connection with BYE and frees the name at
/// once (4.2, 10.3).
#[tokio::test]
async fn ending_a_session_closes_its_connection() {
    let mut h = Harness::new();
    let (mut c, _) = h.guest("sam").await;
    h.end("sam").await;
    assert_eq!(c.lines(), ["<close> BYE bye"]);
    assert!(h.hub.guest_sessions().is_empty());
    assert!(
        !h.hub
            .end_guest_session(&"~sam".parse().unwrap(), "again")
            .await
    );
    // Its commands are not run any more.
    h.send(&c, "ping").await;
    assert!(c.lines().is_empty());
    let (_, _) = h.guest("sam").await;
}

#[tokio::test]
async fn ping_pong_and_quit() {
    let mut h = Harness::new();
    let mut c = h.connect();
    h.send(&c, "ping").await;
    h.send(&c, "@ref=p PING token").await;
    h.send(&c, "PONG token").await;
    // The OK carries the server's time, as posts do (11, 3.2).
    let t = h.inner().now();
    assert_eq!(
        c.lines(),
        [format!("@t={t} OK"), format!("@ref=p;t={t} OK")]
    );
    h.clock.advance(Duration::from_secs(5));
    h.send(&c, "PING").await;
    assert_eq!(c.lines(), [format!("@t={} OK", h.inner().now())]);
    h.send(&c, "@ref=q quit see you").await;
    assert_eq!(c.lines(), ["@ref=q OK", "<close>"]);
}

/// A connection that has not chosen a kind when its time is up is closed
/// (4.1); one that has is not.
#[tokio::test(start_paused = true)]
async fn new_connections_have_a_time_to_choose_a_kind() {
    let mut h = Harness::new();
    let mut idle = h.connect();
    let mut anon = h.anon().await;
    let mut pinging = h.connect();
    h.send(&pinging, "ping").await;
    assert_eq!(pinging.lines(), [format!("@t={} OK", h.inner().now())]);
    tokio::time::sleep(Duration::from_secs(119)).await;
    assert!(idle.lines().is_empty());
    tokio::time::sleep(Duration::from_secs(2)).await;
    let bye = format!("<close> BYE {}", crate::core::BYE_SIGN_IN_TIMEOUT);
    assert_eq!(idle.lines(), std::slice::from_ref(&bye));
    assert_eq!(pinging.lines(), [bye]);
    assert!(anon.lines().is_empty());
    // A closed connection is forgotten.
    h.close(idle).await;
    assert!(!h.inner().reg().conns.contains_key(&ConnId(1)));
}

/// Signing in is a kind too, with its device (4.6), and leaves the
/// connection's line limits to the network layer (2.3).
#[tokio::test]
async fn kinds_reach_the_network_layer() {
    let mut h = Harness::new();
    let c = h.signed_in_as("alice@example.org");
    assert_eq!(c.handle.kind(), ConnectionKind::SignedIn);
    let reg = h.inner().reg();
    assert!(
        matches!(&reg.conns[&c.id].who, Who::SignedIn(d) if d.uid.as_str() == "alice@example.org")
    );
    assert_eq!(reg.conns_of(&"alice@example.org".parse().unwrap()).len(), 1);
    // The greeting's nonce waits for AUTH or REGISTER (4.6).
    assert!(reg.conns[&c.id].nonce.is_some());
}

/// One network address may hold only so many guest sessions, those
/// waiting to be resumed included (4.2).
#[tokio::test]
async fn guest_sessions_per_address() {
    let mut config = config();
    config.limits.guests_per_address = 2;
    let mut h = Harness::with(config, timers());
    let (a, _) = h.guest("ann").await;
    h.guest("ben").await;
    let mut c = h.connect();
    h.send(&c, "GUEST cat").await;
    assert_eq!(c.lines(), ["@retry=60 ERR rate-limited"]);
    // A session waiting to be resumed still counts.
    h.close(a).await;
    h.send(&c, "GUEST cat").await;
    assert_eq!(c.lines(), ["@retry=60 ERR rate-limited"]);
    // Another address has its own.
    let mut far = h.connect_from("198.51.100.9:4000");
    h.send(&far, "GUEST cat").await;
    assert!(far.lines()[0].starts_with("OK uid=~cat"));
}
