//! Session transcripts: greeting, sign-in, responses, keepalive, closing.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::auth::SecretKey;
use risala_proto::command::Command;
use risala_proto::error::ErrorCode;
use risala_proto::server::{ServerLine, ServerMessage};

use super::server::{Peer, ScriptServer, ServerCert, TestCa};
use super::{SetRecord, chat_test, options, store};
use crate::addr::{ServerAddr, TrustRecord, TrustStore};
use crate::conn::{
    CloseReason, CommandError, ConnectionKind, End, Error, Incoming, Session, SessionOptions,
};

// Appendix B.
use crate::keys::tests::{PEM, SIGNATURE};
const NONCE: &str = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e";

/// A mailbox and a send token, for commands.
const BOX: &str = "ujzdegxdncf32epf3dhodzdoci";
const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// A command from its line.
fn cmd(line: &str) -> Command {
    Command::parse(&risala_proto::line::Line::parse(line).unwrap()).unwrap()
}

/// An anonymous session on a pinned server running `script`, whose first
/// command is ANON.
async fn anonymous<F, Fut>(script: F) -> (Session, ScriptServer)
where
    F: Fn(Peer) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let addr = chat_test();
    let script = Arc::new(script);
    let (server, trust, ca) = run(&addr, move |_, mut peer| {
        let script = script.clone();
        async move {
            peer.greet().await;
            peer.expect("@ref=1 ANON").await;
            peer.send("@ref=1 OK").await;
            script(peer).await;
        }
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    session.anon().await.unwrap();
    (session, server)
}

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

/// The line in an incoming item that must not be a reply.
fn line(item: Incoming) -> ServerMessage {
    item.into_line().expect("a line, not a reply")
}

/// An incoming item as text: a line as on the wire, or `reply <ref>
/// <final line>` with its response lines before it.
fn show(item: Incoming) -> Vec<String> {
    match item {
        Incoming::Line(msg) => vec![msg.to_line().to_string()],
        Incoming::Reply { ref_, response } => {
            let mut out: Vec<String> = response
                .lines
                .iter()
                .map(|m| format!("  {}", m.to_line()))
                .collect();
            let end = match response.end {
                End::Ok(ok) => format!("{ok:?}"),
                End::Err(err) => format!("ERR {}", err.code),
                End::Unparseable(line) => format!("unparseable {line}"),
            };
            out.push(format!("reply {ref_} {end}"));
            out
        }
        Incoming::ServerTime(t) => vec![format!("time {t}")],
    }
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
        peer.send("@ref=1 OK uid=~sam token=k3f9q2").await;
        // The second GUEST never reaches the server.
        peer.expect("@ref=2 LIST").await;
        peer.send("@ref=2 OK").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    assert_eq!(session.kind(), ConnectionKind::New);
    let name = "sam".parse().unwrap();
    let (uid, token, resumed) = session.guest_session(&name, None).await.unwrap();
    assert_eq!(uid.as_str(), "~sam");
    assert_eq!(token.unwrap().to_string(), "k3f9q2");
    assert!(!resumed);
    assert_eq!(session.uid(), Some(uid));
    assert_eq!(session.kind(), ConnectionKind::Guest);
    let err = session.guest(&name).await.unwrap_err();
    assert!(
        matches!(
            err,
            Error::WrongKind {
                verb: "GUEST",
                kind: ConnectionKind::Guest
            }
        ),
        "{err:?}"
    );
    assert!(err.is_permanent());
    let list = cmd("LIST");
    assert!(session.request(list).await.unwrap().is_ok());
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn anon_makes_the_connection_anonymous() {
    let (session, server) = anonymous(|mut peer| async move {
        peer.expect_eof().await;
    })
    .await;
    assert_eq!(session.kind(), ConnectionKind::Anonymous);
    assert_eq!(session.uid(), None);
    assert!(!session.is_operator());
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn commands_go_only_on_connections_that_may_send_them() {
    // Section 13: a new connection may not POST, and nothing is sent;
    // above all a signed-in connection never follows or fetches (4.1).
    let addr: ServerAddr = "chat.example.org".parse().unwrap();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.send(&format!("RISALA 1 chat.example.org {NONCE}"))
            .await;
        peer.expect(&format!("@ref=1 AUTH alice@example.org {SIGNATURE}"))
            .await;
        peer.send("@ref=1 OK uid=alice@example.org op=yes").await;
        peer.expect("@ref=2 BACKUP GET").await;
        peer.send("@ref=2 ERR not-found").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let post = cmd(&format!("POST {BOX} {TOKEN} AAEAAg=="));
    let err = session.request(post.clone()).await.unwrap_err();
    assert!(
        matches!(
            err,
            Error::WrongKind {
                verb: "POST",
                kind: ConnectionKind::New
            }
        ),
        "{err:?}"
    );
    let key = SecretKey::from_pkcs8_pem(PEM).unwrap();
    let identity = "alice@example.org".parse().unwrap();
    session.auth(&identity, &key).await.unwrap();
    assert_eq!(session.kind(), ConnectionKind::SignedIn);
    assert!(session.is_operator());
    // POST passes on a signed-in connection, for a public room's
    // PublicMessages (5.2, 12.6); which connection a post takes is the
    // group engine's to decide.
    drop(post);
    for command in [
        cmd(&format!("FOLLOW {BOX}")),
        cmd(&format!("FETCH {BOX} after=0")),
        cmd("ANON"),
    ] {
        let verb = command.verb();
        let err = session.request(command).await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::WrongKind {
                    kind: ConnectionKind::SignedIn,
                    ..
                }
            ),
            "{verb}: {err:?}"
        );
    }
    let backup = session.request(cmd("BACKUP GET")).await.unwrap();
    assert!(!backup.is_ok());
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
        peer.send("@ref=1 OK version=1 register=example.org").await;
        // The same signed bytes as AUTH for alice@example.org (4.7).
        peer.expect(&format!("@ref=2 REGISTER alice AQ== {SIGNATURE}"))
            .await;
        peer.send("@ref=2 OK uid=alice@example.org").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let key = SecretKey::from_pkcs8_pem(PEM).unwrap();
    let domain = session.identity_domain().await.unwrap();
    assert_eq!(domain.as_str(), "example.org");
    let uid = session
        .register(
            &"alice".parse().unwrap(),
            &domain,
            "AQ==".parse().unwrap(),
            &key,
        )
        .await
        .unwrap();
    assert_eq!(uid.as_str(), "alice@example.org");
    assert_eq!(session.kind(), ConnectionKind::SignedIn);
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
    let err = session.identity_domain().await.unwrap_err();
    assert!(matches!(err, Error::NoRegistration), "{err:?}");
    drop(session);
    server.done().await;
}
#[tokio::test]
async fn responses_are_matched_with_live_posts_interleaved() {
    let (session, server) = anonymous(|mut peer| async move {
        peer.expect(&format!("@ref=2 FETCH {BOX} after=8811 limit=2"))
            .await;
        peer.expect(&format!("@ref=3 POST {BOX} {TOKEN} AAEAAw=="))
            .await;
        // Live posts and response lines, interleaved (3.6).
        peer.send(&format!(
            "@seq=8814;t=2026-11-06T15:41:03.000Z POST {BOX} AAEABA=="
        ))
        .await;
        peer.send(&format!(
            "@ref=2;seq=8812;t=2026-11-06T15:40:58.120Z POST {BOX} AAEAAQ=="
        ))
        .await;
        peer.send("PRESENCE online bob@example.org").await;
        peer.send(&format!(
            "@ref=2;seq=8813;t=2026-11-06T15:41:02.377Z POST {BOX} AAEAAg=="
        ))
        .await;
        peer.send("@ref=2 OK more=1").await;
        // The post a POST made comes before its OK.
        peer.send(&format!(
            "@seq=8815;t=2026-11-06T15:41:04.000Z POST {BOX} AAEAAw=="
        ))
        .await;
        peer.send("@ref=3 OK seq=8815").await;
        peer.expect_eof().await;
    })
    .await;
    let mut incoming = session.take_incoming().unwrap();
    assert!(session.take_incoming().is_none());

    let fetch = session.request(cmd(&format!("FETCH {BOX} after=8811 limit=2")));
    let post = session.request(cmd(&format!("POST {BOX} {TOKEN} AAEAAw==")));
    let (fetch, post) = tokio::join!(fetch, post);

    let fetch = fetch.unwrap();
    let seqs: Vec<u64> = fetch
        .lines
        .iter()
        .map(|m| match &m.line {
            ServerLine::Post(p) => p.seq.unwrap().get(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(seqs, [8812, 8813]);
    assert!(
        fetch
            .lines
            .iter()
            .all(|m| m.ref_.as_ref().unwrap().as_str() == "2")
    );
    assert_eq!(fetch.ok().unwrap().more().unwrap(), Some(true));

    let post = post.unwrap();
    assert!(post.lines.is_empty());
    assert_eq!(post.ok().unwrap().seq().unwrap().unwrap().get(), 8815);

    // Everything else arrived in order, and was queued before the
    // responses returned.
    let lines: Vec<String> = (0..3)
        .map(|_| line(incoming.try_recv().unwrap()).to_line().to_string())
        .collect();
    assert_eq!(
        lines,
        [
            format!("@seq=8814;t=2026-11-06T15:41:03.000Z POST {BOX} AAEABA=="),
            "PRESENCE online bob@example.org".to_owned(),
            format!("@seq=8815;t=2026-11-06T15:41:04.000Z POST {BOX} AAEAAw=="),
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
        peer.send("@t=2026-11-10T09:00:00.000Z PING abc123").await;
        peer.expect("PONG abc123").await;
        peer.send("@t=2026-11-10T09:02:00.000Z PING x").await;
        peer.expect("PONG x").await;
        // A PING without its `t` does not parse, and is ignored (2.3).
        peer.send("PING y").await;
        peer.send("NOTICE done").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |_| {}).await.unwrap();
    let mut incoming = session.take_incoming().unwrap();
    // PINGs are not passed on as lines, only their time (11).
    let mut shown = Vec::new();
    for _ in 0..3 {
        shown.extend(show(incoming.recv().await.unwrap()));
    }
    assert_eq!(
        shown,
        [
            "time 2026-11-10T09:00:00.000Z",
            "time 2026-11-10T09:02:00.000Z",
            "NOTICE done"
        ]
    );
    drop(session);
    server.done().await;
}

/// The OK to the session's own keepalive PING gives the server's time
/// (11), placed where it arrived.
#[tokio::test]
async fn keepalive_ok_gives_the_servers_time() {
    let addr = chat_test();
    let (server, trust, ca) = run(&addr, |_, mut peer| async move {
        peer.greet().await;
        peer.expect("@ref=1 PING").await;
        peer.send("NOTICE before").await;
        peer.send("@ref=1;t=2026-11-10T09:00:00.000Z OK").await;
        peer.send("NOTICE after").await;
        peer.expect_eof().await;
    })
    .await;
    let session = open(&addr, &server, &trust, &ca, |o| {
        o.ping_after = Duration::from_millis(50);
    })
    .await
    .unwrap();
    let mut incoming = session.take_incoming().unwrap();
    let mut shown = Vec::new();
    for _ in 0..3 {
        shown.extend(show(incoming.recv().await.unwrap()));
    }
    assert_eq!(
        shown,
        [
            "NOTICE before",
            "time 2026-11-10T09:00:00.000Z",
            "NOTICE after"
        ]
    );
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
    let bye = line(incoming.recv().await.unwrap());
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
    let (session, server) = anonymous(|mut peer| async move {
        peer.expect("@ref=2 PING").await;
        peer.send("@ref=2 OK").await;
        peer.expect_eof().await;
    })
    .await;
    let err = session
        .request(Command::Pong { token: "x".into() })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoResponse), "{err:?}");
    // Text with a line break cannot be written.
    let err = session
        .request(Command::Quit {
            message: "a\nb".into(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCommand(_)), "{err:?}");
    // POST may be long (2.3), but not over 1 MiB.
    let big = "A".repeat(1024 * 1024);
    let err = session
        .request(cmd(&format!("POST {BOX} {TOKEN} {big}")))
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
#[tokio::test]
async fn sent_replies_keep_their_place_among_live_lines() {
    let (session, server) = anonymous(|mut peer| async move {
        peer.expect(&format!("@ref=2 FOLLOW {BOX}")).await;
        peer.expect("@ref=3 PING").await;
        peer.expect(&format!("@ref=4 FETCH {BOX} after=0")).await;
        peer.send(&format!(
            "@seq=1;t=2026-11-06T15:41:03.000Z POST {BOX} AAEAAQ=="
        ))
        .await;
        peer.send("@ref=2 OK head=1").await;
        peer.send(&format!(
            "@seq=2;t=2026-11-06T15:41:05.000Z POST {BOX} AAEAAg=="
        ))
        .await;
        peer.send("@ref=3 OK").await;
        peer.send(&format!(
            "@ref=4;seq=1;t=2026-11-06T15:41:03.000Z POST {BOX} AAEAAQ=="
        ))
        .await;
        peer.send("@ref=4 ERR internal").await;
        peer.send("NOTICE done").await;
        peer.expect_eof().await;
    })
    .await;
    let mut incoming = session.take_incoming().unwrap();
    assert_eq!(
        session
            .send(cmd(&format!("FOLLOW {BOX}")))
            .unwrap()
            .as_str(),
        "2"
    );
    // A request() in between gets its response through its future.
    let ping = session.request(Command::Ping { token: None });
    let fetch = async { session.send(cmd(&format!("FETCH {BOX} after=0"))) };
    let (ping, fetch) = tokio::join!(ping, fetch);
    assert!(ping.unwrap().is_ok());
    assert_eq!(fetch.unwrap().as_str(), "4");
    let mut got = Vec::new();
    for _ in 0..5 {
        got.extend(show(incoming.recv().await.unwrap()));
    }
    assert_eq!(
        got,
        [
            format!("@seq=1;t=2026-11-06T15:41:03.000Z POST {BOX} AAEAAQ=="),
            format!(
                "reply 2 {:?}",
                risala_proto::server::OkResponse::new().with_head(1u64)
            ),
            format!("@seq=2;t=2026-11-06T15:41:05.000Z POST {BOX} AAEAAg=="),
            format!("  @ref=4;seq=1;t=2026-11-06T15:41:03.000Z POST {BOX} AAEAAQ=="),
            "reply 4 ERR internal".to_owned(),
            "NOTICE done".to_owned(),
        ]
    );
    drop(session);
    // Nothing more: the queue ends with the connection.
    assert!(incoming.recv().await.is_none());
    server.done().await;
}
#[tokio::test]
async fn sent_commands_without_a_reply_end_with_the_queue() {
    let (session, server) = anonymous(|mut peer| async move {
        peer.expect(&format!("@ref=2 FOLLOW {BOX}")).await;
        peer.close().await;
    })
    .await;
    let mut incoming = session.take_incoming().unwrap();
    session.send(cmd(&format!("FOLLOW {BOX}"))).unwrap();
    assert!(incoming.recv().await.is_none());
    assert!(matches!(
        session.send(cmd(&format!("FOLLOW {BOX}"))),
        Err(Error::Closed(_))
    ));
    assert!(matches!(
        session.send(Command::Pong { token: "x".into() }),
        Err(Error::NoResponse)
    ));
    // ANON goes only through anon(), which knows the kind it gives.
    assert!(matches!(
        session.send(Command::Anon),
        Err(Error::WrongKind { verb: "ANON", .. })
    ));
    server.done().await;
}

#[tokio::test]
async fn single_use_connections_carry_one_command() {
    // 4.1: a command that names the device goes on a connection of its
    // own, which closes after it.
    let addr = chat_test();
    let cert = ServerCert::self_signed(addr.host());
    let trust = store();
    trust
        .set(&addr, TrustRecord::Pinned(cert.fingerprint))
        .unwrap();
    let server = ScriptServer::start(cert, 2, |i, mut peer: Peer| async move {
        peer.greet().await;
        if i == 0 {
            // A new connection may send PAIR (4.1).
            peer.expect(&format!("@ref=1 PAIR GET {BOX}")).await;
            peer.send("@ref=1 ERR not-found").await;
        } else {
            peer.expect("@ref=1 ANON").await;
            peer.send("@ref=1 OK").await;
            peer.expect("@ref=2 KEYPKG GET alice@example.org").await;
            peer.send("@ref=2 OK").await;
        }
        peer.expect_eof().await;
    })
    .await;
    let ca = TestCa::new();
    let pair = crate::conn::single_use(
        &addr,
        trust.clone(),
        options(&ca, &server),
        crate::conn::SingleUse::New,
        cmd(&format!("PAIR GET {BOX}")),
    )
    .await
    .unwrap();
    assert!(!pair.is_ok());
    let keypkg = crate::conn::single_use(
        &addr,
        trust,
        options(&ca, &server),
        crate::conn::SingleUse::Anonymous,
        cmd("KEYPKG GET alice@example.org"),
    )
    .await
    .unwrap();
    assert!(keypkg.is_ok());
    server.done().await;
}
