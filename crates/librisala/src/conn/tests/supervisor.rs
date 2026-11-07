//! Reconnects: backoff, signing in again, permanent failures.

use std::sync::Arc;
use std::time::Duration;

use risala_proto::command::Command;
use risala_proto::error::ErrorCode;
use tokio::sync::mpsc;

use super::server::{Peer, ScriptServer, ServerCert, TestCa};
use super::{chat_test, options, store};
use crate::addr::{TrustRecord, TrustStore};
use crate::conn::{
    Backoff, CloseReason, CommandError, Error, GuestSignIn, Supervisor, SupervisorEvent, TrustError,
};

fn fast() -> Backoff {
    Backoff {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(40),
        stable_after: Duration::from_secs(3600),
    }
}

fn guest() -> Arc<GuestSignIn> {
    Arc::new(GuestSignIn("sam".parse().unwrap()))
}

async fn next(events: &mut mpsc::Receiver<SupervisorEvent>) -> SupervisorEvent {
    events.recv().await.expect("an event")
}

async fn pinned(cert: &ServerCert) -> Arc<dyn TrustStore> {
    let trust = store();
    trust
        .set(&chat_test(), TrustRecord::Pinned(cert.fingerprint))
        .unwrap();
    trust
}

#[tokio::test]
async fn reconnects_and_signs_in_again() {
    let cert = ServerCert::self_signed("chat.test");
    let trust = pinned(&cert).await;
    let server = ScriptServer::start(cert, 3, |i, mut peer: Peer| async move {
        peer.greet().await;
        peer.expect("@ref=1 GUEST sam").await;
        match i {
            // Signed in, then the connection drops.
            0 => {
                peer.send("@ref=1 OK uid=~sam").await;
                peer.expect("@ref=2 SYNC").await;
                peer.send("@ref=2 OK").await;
                peer.close().await;
            }
            // A passing failure: try again later.
            1 => {
                peer.send("@ref=1 ERR rate-limited").await;
                peer.expect_eof().await;
            }
            _ => {
                peer.send("@ref=1 OK uid=~sam").await;
                peer.expect_eof().await;
            }
        }
    })
    .await;
    let ca = TestCa::new();
    let (supervisor, mut events) =
        Supervisor::spawn(chat_test(), trust, options(&ca, &server), guest(), fast());

    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connecting { attempt: 0 }
    ));
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connected { .. }
    ));
    let SupervisorEvent::SignedIn { uid, session, .. } = next(&mut events).await else {
        panic!()
    };
    assert_eq!(uid.as_str(), "~sam");
    assert!(session.request(Command::Sync).await.unwrap().is_ok());
    let SupervisorEvent::Disconnected { reason } = next(&mut events).await else {
        panic!()
    };
    assert_eq!(reason, CloseReason::Server { bye: None });
    assert!(session.is_closed());

    // The connection was short, so the next attempt waits.
    let SupervisorEvent::Waiting { delay, error: None } = next(&mut events).await else {
        panic!()
    };
    assert!(delay >= Duration::from_millis(5) && delay <= Duration::from_millis(10));
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connecting { attempt: 1 }
    ));
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connected { .. }
    ));
    // rate-limited is not permanent.
    let SupervisorEvent::Waiting {
        delay,
        error: Some(Error::Rejected(CommandError::Server(err))),
    } = next(&mut events).await
    else {
        panic!()
    };
    assert_eq!(err.code, ErrorCode::RateLimited);
    assert!(delay >= Duration::from_millis(10) && delay <= Duration::from_millis(20));
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connecting { attempt: 2 }
    ));
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connected { .. }
    ));
    let SupervisorEvent::SignedIn { session, .. } = next(&mut events).await else {
        panic!()
    };

    supervisor.stop().await;
    assert!(matches!(next(&mut events).await, SupervisorEvent::Stopped));
    assert!(events.recv().await.is_none());
    assert_eq!(session.closed().await, CloseReason::Local);
    server.done().await;
}

#[test]
fn guest_names_are_numbered_to_fit() {
    let g = |s: &str| GuestSignIn(s.parse().unwrap());
    assert_eq!(g("sam").numbered(1).as_str(), "sam");
    assert_eq!(g("sam").numbered(2).as_str(), "sam2");
    assert_eq!(g("sam").numbered(9).as_str(), "sam9");
    let long = "a".repeat(32);
    assert_eq!(
        g(&long).numbered(2).as_str(),
        format!("{}2", "a".repeat(31))
    );
    // Shortening never leaves a '.' at the end (3.5).
    let dotted = format!("{}.b", "a".repeat(30));
    assert_eq!(
        g(&dotted).numbered(2).as_str(),
        format!("{}2", "a".repeat(30))
    );
}

#[tokio::test]
async fn guest_name_taken_tries_numbered_names() {
    let cert = ServerCert::self_signed("chat.test");
    let trust = pinned(&cert).await;
    let server = ScriptServer::start(cert, 2, |i, mut peer: Peer| async move {
        peer.greet().await;
        match i {
            // The old connection has not gone yet: ~sam and ~sam2 are
            // taken, ~sam3 is free.
            0 => {
                peer.expect("@ref=1 GUEST sam").await;
                peer.send("@ref=1 ERR name-taken").await;
                peer.expect("@ref=2 GUEST sam2").await;
                peer.send("@ref=2 ERR name-taken").await;
                peer.expect("@ref=3 GUEST sam3").await;
                peer.send("@ref=3 OK uid=~sam3").await;
                peer.close().await;
            }
            // Every name is taken: wait, then start again from ~sam.
            _ => {
                for n in 1..=GuestSignIn::MAX_NAMES {
                    let name = if n == 1 {
                        "sam".to_owned()
                    } else {
                        format!("sam{n}")
                    };
                    peer.expect(&format!("@ref={n} GUEST {name}")).await;
                    peer.send(&format!("@ref={n} ERR name-taken")).await;
                }
                peer.expect_eof().await;
            }
        }
    })
    .await;
    let ca = TestCa::new();
    let (supervisor, mut events) =
        Supervisor::spawn(chat_test(), trust, options(&ca, &server), guest(), fast());
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connecting { .. }
    ));
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connected { .. }
    ));
    let SupervisorEvent::SignedIn { uid, .. } = next(&mut events).await else {
        panic!()
    };
    assert_eq!(uid.as_str(), "~sam3");
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Disconnected { .. }
    ));
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Waiting { .. }
    ));
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connecting { .. }
    ));
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connected { .. }
    ));
    let SupervisorEvent::Waiting {
        error: Some(Error::Rejected(CommandError::Server(err))),
        ..
    } = next(&mut events).await
    else {
        panic!()
    };
    assert_eq!(err.code, ErrorCode::NameTaken);
    supervisor.stop().await;
    server.done().await;
}

#[tokio::test]
async fn trust_errors_are_permanent() {
    let cert = ServerCert::self_signed("chat.test");
    let fp = cert.fingerprint;
    let server = ScriptServer::start(cert, 1, |_, _| async {}).await;
    let ca = TestCa::new();
    let (_supervisor, mut events) =
        Supervisor::spawn(chat_test(), store(), options(&ca, &server), guest(), fast());
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connecting { attempt: 0 }
    ));
    let SupervisorEvent::Failed {
        error: Error::Trust(TrustError::Unknown { fingerprint, .. }),
    } = next(&mut events).await
    else {
        panic!()
    };
    assert_eq!(fingerprint, fp);
    assert!(events.recv().await.is_none());
    server.done().await;
}

#[tokio::test]
async fn auth_failed_is_permanent() {
    let cert = ServerCert::self_signed("chat.test");
    let trust = pinned(&cert).await;
    let server = ScriptServer::start(cert, 1, |_, mut peer: Peer| async move {
        peer.greet().await;
        peer.expect("@ref=1 GUEST sam").await;
        peer.send("@ref=1 ERR forbidden guests are not allowed")
            .await;
        peer.expect_eof().await;
    })
    .await;
    let ca = TestCa::new();
    let (_supervisor, mut events) =
        Supervisor::spawn(chat_test(), trust, options(&ca, &server), guest(), fast());
    next(&mut events).await;
    next(&mut events).await;
    let SupervisorEvent::Failed { error } = next(&mut events).await else {
        panic!()
    };
    assert!(
        matches!(&error, Error::Rejected(e) if e.code() == Some(&ErrorCode::Forbidden)),
        "{error:?}"
    );
    assert!(events.recv().await.is_none());
    server.done().await;
}

#[tokio::test]
async fn reconnect_now_skips_the_wait() {
    let cert = ServerCert::self_signed("chat.test");
    let trust = pinned(&cert).await;
    let server = ScriptServer::start(cert, 2, |i, mut peer: Peer| async move {
        if i == 0 {
            // Closes before the greeting: a transient failure.
            peer.close().await;
            return;
        }
        peer.greet().await;
        peer.expect("@ref=1 GUEST sam").await;
        peer.send("@ref=1 OK uid=~sam").await;
        peer.expect_eof().await;
    })
    .await;
    let ca = TestCa::new();
    let slow = Backoff {
        initial: Duration::from_secs(3600),
        max: Duration::from_secs(3600),
        ..Backoff::default()
    };
    let (supervisor, mut events) =
        Supervisor::spawn(chat_test(), trust, options(&ca, &server), guest(), slow);
    next(&mut events).await;
    let SupervisorEvent::Waiting { delay, error } = next(&mut events).await else {
        panic!()
    };
    assert!(delay >= Duration::from_secs(1800));
    assert!(
        matches!(
            error,
            Some(Error::Closed(CloseReason::Server { bye: None }))
        ),
        "{error:?}"
    );
    supervisor.reconnect_now();
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::Connecting { attempt: 1 }
    ));
    next(&mut events).await;
    assert!(matches!(
        next(&mut events).await,
        SupervisorEvent::SignedIn { .. }
    ));
    supervisor.stop().await;
    server.done().await;
}

#[test]
fn backoff_doubles_with_jitter() {
    let b = Backoff {
        initial: Duration::from_secs(1),
        max: Duration::from_secs(60),
        stable_after: Duration::from_secs(60),
    };
    assert_eq!(b.delay(0), Duration::ZERO);
    for (failures, full) in [(1, 1), (2, 2), (3, 4), (7, 60), (40, 60)] {
        let full = Duration::from_secs(full);
        for _ in 0..20 {
            let d = b.delay(failures);
            assert!(d >= full / 2 && d <= full, "{failures}: {d:?}");
        }
    }
}
