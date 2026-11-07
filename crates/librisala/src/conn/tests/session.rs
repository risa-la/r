//! Session transcripts: greeting, sign-in, responses, keepalive, closing.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::auth::SecretKey;
use risala_proto::command::Command;
use risala_proto::error::ErrorCode;
use risala_proto::server::ServerLine;

use super::server::{Peer, ScriptServer, ServerCert, TestCa};
use super::{chat_test, options, store};
use crate::addr::{ServerAddr, TrustRecord, TrustStore};
use crate::conn::{CloseReason, CommandError, End, Error, Session, SessionOptions};

// Appendix B.
const PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
    MC4CAQAwBQYDK2VwBCIEIMEfrlxZLhO+Z9yW9uhQBNMukoYV968f06bF2eoKtsuo\n\
    -----END PRIVATE KEY-----\n";
const NONCE: &str = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e";
const SIGNATURE: &str =
    "Hk+S5Vd7ciW57dRNS3AhcvZkYNLmj+kkgJUxOYvCrbEQSBk0UDdH+cSBXF6YvCSU85FRVPaURwsQdbV/SAK0CQ==";
const PUBLIC: &str = "J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY=";

/// A pinned self-signed server at `addr` running `script` once.
async fn run<F, Fut>(addr: &ServerAddr, script: F) -> (ScriptServer, Arc<dyn TrustStore>, TestCa)
where
    F: Fn(usize, Peer) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let cert = ServerCert::self_signed(addr.host());
    let trust = store();
    trust
        .set(addr, TrustRecord::Pinned(cert.fingerprint))
        .unwrap();
    let server = ScriptServer::start(cert, 1, script).await;
    (server, trust, TestCa::new())
}

async fn open(
    addr: &ServerAddr,
    server: &ScriptServer,
    trust: &Arc<dyn TrustStore>,
    ca: &TestCa,
    tweak: impl FnOnce(&mut SessionOptions),
) -> Result<Session, Error> {
    let mut opts = options(ca, server);
    tweak(&mut opts);
    Session::connect(addr, trust.clone(), opts).await
}

#[tokio::test]
async fn greeting() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let g = &session.info().greeting;
    assert_eq!(g.version, 1);
    assert_eq!(g.host.as_str(), "chat.test");
    assert_eq!(g.nonce.as_str(), NONCE);
    assert_eq!(g.message, "welcome");
    assert_eq!(session.uid(), None);
    // Dropping the session closes the connection.
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn wrong_protocol_version_is_refused() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.send(&format!("RISALA 2 chat.test {NONCE}")).await;
        // The client closes the connection (3.8).
        peer.expect_eof().await;
    })
    .await;
    let err = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap_err();
    assert!(matches!(err, Error::UnsupportedVersion(2)), "{err:?}");
    assert!(err.is_permanent());
    server.done().await;
}

#[tokio::test]
async fn bad_greetings() {
    let addr = chat_test();
    let cert = ServerCert::self_signed("chat.test");
    let trust = store();
    trust
        .set(&addr, TrustRecord::Pinned(cert.fingerprint))
        .unwrap();
    let server = ScriptServer::start(cert, 4, |i, mut peer: Peer| async move {
        match i {
            0 => peer.send("NOTICE hello").await,
            1 => peer.send("BYE too many connections").await,
            2 => peer.send("RISALA 1 chat.test 12").await,
            _ => {}
        }
        peer.close().await;
    })
    .await;
    let ca = TestCa::new();
    let err = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap_err();
    assert!(matches!(err, Error::BadGreeting(_)), "{err:?}");
    let err = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap_err();
    assert!(
        matches!(&err, Error::Closed(CloseReason::Server { bye: Some(m) }) if m == "too many connections"),
        "{err:?}"
    );
    let err = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap_err();
    assert!(matches!(err, Error::BadGreeting(_)), "{err:?}");
    let err = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap_err();
    assert!(
        matches!(err, Error::Closed(CloseReason::Server { bye: None })),
        "{err:?}"
    );
    server.done().await;
}

#[tokio::test]
async fn guest_sign_in() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        peer.expect("@ref=1 GUEST sam").await;
        peer.send("@ref=1 OK uid=~sam").await;
        peer.expect("@ref=2 GUEST sam").await;
        peer.send("@ref=2 ERR already-authenticated").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let name = "sam".parse().unwrap();
    let uid = session.guest(&name).await.unwrap();
    assert_eq!(uid.as_str(), "~sam");
    assert_eq!(session.uid(), Some(uid));
    let err = session.guest(&name).await.unwrap_err();
    assert!(
        matches!(&err, Error::Rejected(e) if e.code() == Some(&ErrorCode::AlreadyAuthenticated)),
        "{err:?}"
    );
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn auth_signs_with_the_sni_host() {
    // The greeting names another host. The client signs the host it sent
    // in SNI (4.5), which gives exactly Appendix B's signature.
    let addr: ServerAddr = "chat.example.org".parse().unwrap();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        assert_eq!(peer.sni.as_deref(), Some("chat.example.org"));
        peer.send(&format!("RISALA 1 evil.example.net {NONCE}"))
            .await;
        peer.expect(&format!("@ref=1 AUTH alice@example.org {SIGNATURE}"))
            .await;
        peer.send("@ref=1 OK uid=alice@example.org").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let key = SecretKey::from_pkcs8_pem(PEM).unwrap();
    let identity = "alice@example.org".parse().unwrap();
    let uid = session.auth(&identity, &key).await.unwrap();
    assert_eq!(uid.as_str(), "alice@example.org");
    assert_eq!(session.uid(), Some(uid));
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn auth_failure_uses_up_the_nonce() {
    let addr: ServerAddr = "chat.example.org".parse().unwrap();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.send(&format!("RISALA 1 chat.example.org {NONCE}"))
            .await;
        peer.expect(&format!("@ref=1 AUTH alice@example.org {SIGNATURE}"))
            .await;
        peer.send("@ref=1 ERR auth-failed no key matched").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let key = SecretKey::from_pkcs8_pem(PEM).unwrap();
    let identity = "alice@example.org".parse().unwrap();
    let err = session.auth(&identity, &key).await.unwrap_err();
    assert!(
        matches!(&err, Error::Rejected(CommandError::Server(e)) if e.code == ErrorCode::AuthFailed),
        "{err:?}"
    );
    assert!(err.is_permanent());
    // A second try needs a new connection (4.5).
    let err = session.auth(&identity, &key).await.unwrap_err();
    assert!(matches!(err, Error::NonceUsed), "{err:?}");
    assert_eq!(session.uid(), None);
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn register_signs_the_new_uid() {
    let addr: ServerAddr = "chat.example.org".parse().unwrap();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.send(&format!("RISALA 1 chat.example.org {NONCE}"))
            .await;
        peer.expect("@ref=1 INFO").await;
        peer.send(
            "@ref=1 OK version=1 guests=yes register=example.org retention=forever push=no upload=no",
        )
        .await;
        peer.expect(&format!("@ref=2 REGISTER alice {PUBLIC} {SIGNATURE}"))
            .await;
        peer.send("@ref=2 OK uid=alice@example.org").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let key = SecretKey::from_pkcs8_pem(PEM).unwrap();
    let uid = session
        .register(&"alice".parse().unwrap(), &key)
        .await
        .unwrap();
    assert_eq!(uid.as_str(), "alice@example.org");
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn register_needs_an_identity_domain() {
    let addr: ServerAddr = "chat.example.org".parse().unwrap();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        peer.expect("@ref=1 INFO").await;
        peer.send("@ref=1 OK version=1 guests=yes register=no")
            .await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let key = SecretKey::from_pkcs8_pem(PEM).unwrap();
    let err = session
        .register(&"alice".parse().unwrap(), &key)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoRegistration), "{err:?}");
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn responses_are_matched_with_live_events_interleaved() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        peer.expect("@ref=1 HISTORY #general after=8811 limit=2")
            .await;
        peer.expect("@ref=2 MSG #general hello").await;
        // Live events and response lines, interleaved (3.6).
        peer.send("@seq=8814;t=2026-11-06T15:41:03.000Z;from=~ann MSG #general first live")
            .await;
        peer.send("@ref=1;seq=8812;t=2026-11-06T15:40:58.120Z;from=~sam;id=k3f9q2 JOIN #general")
            .await;
        peer.send("PRESENCE online ~bob").await;
        peer.send(
            "@ref=1;seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam;reply=8810 MSG #general hi",
        )
        .await;
        peer.send("@ref=1 OK id=k3f9q2 more=1").await;
        // The event MSG caused comes before its OK.
        peer.send("@seq=8815;t=2026-11-06T15:41:04.000Z;from=~me MSG #general hello")
            .await;
        peer.send("@ref=2 OK seq=8815").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let mut incoming = session.take_incoming().unwrap();
    assert!(session.take_incoming().is_none());

    let history = session.request(Command::History {
        conv: "#general".parse().unwrap(),
        after: Some(8811),
        before: None,
        limit: std::num::NonZeroU64::new(2),
    });
    let msg = session.request(Command::Msg {
        conv: "#general".parse().unwrap(),
        text: "hello".into(),
        relation: None,
        file: None,
        cid: None,
    });
    let (history, msg) = tokio::join!(history, msg);

    let history = history.unwrap();
    let seqs: Vec<u64> = history
        .lines
        .iter()
        .map(|m| match &m.line {
            ServerLine::Event(e) => e.meta.as_ref().unwrap().seq.get(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(seqs, [8812, 8813]);
    assert!(
        history
            .lines
            .iter()
            .all(|m| m.ref_.as_ref().unwrap().as_str() == "1")
    );
    let ok = history.ok().unwrap();
    assert_eq!(ok.more().unwrap(), Some(true));
    assert_eq!(ok.value("id"), Some("k3f9q2"));

    let msg = msg.unwrap();
    assert!(msg.lines.is_empty());
    assert_eq!(msg.ok().unwrap().seq().unwrap().unwrap().get(), 8815);

    // Everything else arrived in order, and was queued before the
    // responses returned.
    let verbs: Vec<String> = (0..3)
        .map(|_| incoming.try_recv().unwrap().to_line().to_string())
        .collect();
    assert_eq!(
        verbs,
        [
            "@seq=8814;t=2026-11-06T15:41:03.000Z;from=~ann MSG #general first live",
            "PRESENCE online ~bob",
            "@seq=8815;t=2026-11-06T15:41:04.000Z;from=~me MSG #general hello",
        ]
    );
    assert!(incoming.try_recv().is_err());
    drop(session);
    // The queue ends when the connection closes.
    assert!(incoming.recv().await.is_none());
    server.done().await;
}

#[tokio::test]
async fn unparseable_final_responses_end_their_command() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        for r in 1..=4 {
            peer.expect(&format!("@ref={r} PING")).await;
        }
        peer.send("@ref=1 OK seq").await;
        peer.send("ERR").await;
        peer.send("@ref=3;;bad OK").await;
        // Unparseable lines that are not OK or ERR are ignored (2.3).
        peer.send("MSG").await;
        peer.send("@ref=4 OK").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let ping = || session.request(Command::Ping { token: None });
    let (a, b, c, d) = tokio::join!(ping(), ping(), ping(), ping());
    for (r, line) in [(a, "@ref=1 OK seq"), (b, "ERR"), (c, "@ref=3;;bad OK")] {
        let r = r.unwrap();
        assert_eq!(r.end, End::Unparseable(line.into()));
        assert_eq!(r.ok().unwrap_err(), CommandError::Unparseable(line.into()));
    }
    assert!(d.unwrap().is_ok());
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn out_of_order_response_closes_the_session() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        peer.expect("@ref=1 PING").await;
        peer.send("@ref=2 OK").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let err = session
        .request(Command::Ping { token: None })
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Closed(CloseReason::Protocol(_))),
        "{err:?}"
    );
    assert!(matches!(session.closed().await, CloseReason::Protocol(_)));
    let err = session
        .request(Command::Ping { token: None })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Closed(_)), "{err:?}");
    server.done().await;
}

#[tokio::test]
async fn server_ping_is_answered_with_pong() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        peer.send("PING abc123").await;
        peer.expect("PONG abc123").await;
        peer.send("PING x").await;
        peer.expect("PONG x").await;
        peer.send("NOTICE done").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let mut incoming = session.take_incoming().unwrap();
    // PINGs are not passed on.
    let notice = incoming.recv().await.unwrap();
    assert_eq!(notice.to_line().to_string(), "NOTICE done");
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn idle_session_pings_and_closes_when_unanswered() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        // The first keepalive is answered, the second is not.
        peer.expect("@ref=1 PING").await;
        peer.send("@ref=1 OK").await;
        peer.expect("@ref=2 PING").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |o| {
        o.ping_after = Duration::from_millis(50);
        o.ping_timeout = Duration::from_millis(200);
    })
    .await
    .unwrap();
    assert_eq!(session.closed().await, CloseReason::PingTimeout);
    assert!(session.is_closed());
    server.done().await;
}

#[tokio::test]
async fn bye_then_close() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        peer.expect("@ref=1 PING").await;
        peer.send("BYE server shutting down").await;
        peer.close().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let mut incoming = session.take_incoming().unwrap();
    let err = session
        .request(Command::Ping { token: None })
        .await
        .unwrap_err();
    let reason = CloseReason::Server {
        bye: Some("server shutting down".into()),
    };
    assert!(matches!(&err, Error::Closed(r) if *r == reason), "{err:?}");
    assert_eq!(session.closed().await, reason);
    let bye = incoming.recv().await.unwrap();
    assert!(matches!(bye.line, ServerLine::Bye { .. }));
    assert!(incoming.recv().await.is_none());
    server.done().await;
}

#[tokio::test]
async fn quit() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        peer.expect("@ref=1 QUIT see you").await;
        peer.send("@ref=1 OK").await;
        peer.close().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let reason = session.quit("see you").await.unwrap();
    assert_eq!(reason, CloseReason::Server { bye: None });
    server.done().await;
}

#[tokio::test]
async fn local_close_fails_pending_commands() {
    let addr = chat_test();
    let (got_ping, ping_seen) = tokio::sync::oneshot::channel();
    let got_ping = std::sync::Mutex::new(Some(got_ping));
    let (server, trust, ca) = run(&addr, move |_, mut peer| {
        let got_ping = got_ping.lock().unwrap().take().unwrap();
        async move {
            peer.greet().await;
            peer.expect("@ref=1 PING").await;
            got_ping.send(()).unwrap();
            // Never answered; the client closes with close_notify.
            peer.expect_eof().await;
        }
    })
    .await;
    let session = Arc::new(open(&addr, &server, &trust, &ca, |_| {}).await.unwrap());
    let pending = {
        let session = session.clone();
        tokio::spawn(async move { session.request(Command::Ping { token: None }).await })
    };
    ping_seen.await.unwrap();
    session.close();
    let err = pending.await.unwrap().unwrap_err();
    assert!(matches!(err, Error::Closed(CloseReason::Local)), "{err:?}");
    assert_eq!(session.closed().await, CloseReason::Local);
    server.done().await;
}

#[tokio::test]
async fn slow_reader_overflows() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        for i in 0..5 {
            peer.send(&format!("NOTICE note {i}")).await;
        }
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |o| o.incoming_capacity = 2)
        .await
        .unwrap();
    assert_eq!(session.closed().await, CloseReason::Overflow);
    let mut incoming = session.take_incoming().unwrap();
    assert!(incoming.recv().await.is_some());
    assert!(incoming.recv().await.is_some());
    assert!(incoming.recv().await.is_none());
    server.done().await;
}

#[tokio::test]
async fn invalid_requests_are_not_sent() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        peer.expect("@ref=1 PING").await;
        peer.send("@ref=1 OK").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let err = session
        .request(Command::Pong { token: "x".into() })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoResponse), "{err:?}");
    let err = session
        .request(Command::Msg {
            conv: "#a".parse().unwrap(),
            text: String::new(),
            relation: None,
            file: None,
            cid: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCommand(_)), "{err:?}");
    let err = session
        .request(Command::Msg {
            conv: "#a".parse().unwrap(),
            text: "x".repeat(9000),
            relation: None,
            file: None,
            cid: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCommand(_)), "{err:?}");
    // Refs are not used up by rejected requests.
    assert!(
        session
            .request(Command::Ping { token: None })
            .await
            .unwrap()
            .is_ok()
    );
    drop(session);
    server.done().await;
}
