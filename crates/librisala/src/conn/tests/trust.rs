//! Every case of 2.2, with a test root CA standing in for the platform.

use risala_proto::fingerprint::Fingerprint;

use super::server::{Peer, ScriptServer, ServerCert, TestCa};
use super::{chat_test, connect, options, store};
use crate::addr::TrustRecord;
use crate::conn::{
    Error, Session, SessionOptions, TrustError, Verified, accept_fingerprint, no_ca_verifier,
};

/// A server that greets and then waits for the client to go.
async fn greeter(cert: ServerCert, conns: usize) -> ScriptServer {
    ScriptServer::start(cert, conns, |_, mut peer: Peer| async move {
        peer.greet().await;
        while peer.recv().await.is_some() {}
    })
    .await
}

fn other_fingerprint() -> Fingerprint {
    Fingerprint::from_bytes([7; 32])
}

#[tokio::test]
async fn unknown_self_signed_is_refused_then_pinned() {
    let ca = TestCa::new();
    let cert = ServerCert::self_signed("chat.test");
    let fp = cert.fingerprint;
    let server = greeter(cert, 2).await;
    let trust = store();

    // Nothing recorded: refused, with the fingerprint to show.
    let err = connect(&ca, &server, &trust).await.unwrap_err();
    assert!(err.is_permanent());
    let Error::Trust(TrustError::Unknown { fingerprint, .. }) = err else {
        panic!("{err:?}")
    };
    assert_eq!(fingerprint, fp);
    assert_eq!(trust.get(&chat_test()).unwrap(), None);

    // The user accepts; the pin matches.
    accept_fingerprint(&*trust, &chat_test(), fingerprint).unwrap();
    let session = connect(&ca, &server, &trust).await.unwrap();
    assert_eq!(
        session.info().verified,
        Verified {
            fingerprint: fp,
            record: TrustRecord::Pinned(fp),
            changed: false,
        }
    );
    assert_eq!(
        trust.get(&chat_test()).unwrap(),
        Some(TrustRecord::Pinned(fp))
    );
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn pin_mismatch_is_refused() {
    let ca = TestCa::new();
    let cert = ServerCert::self_signed("chat.test");
    let fp = cert.fingerprint;
    let server = greeter(cert, 2).await;
    let trust = store();
    let old = TrustRecord::Pinned(other_fingerprint());
    trust.set(&chat_test(), old.clone()).unwrap();

    let err = connect(&ca, &server, &trust).await.unwrap_err();
    let Error::Trust(TrustError::Mismatch {
        recorded,
        presented,
        ..
    }) = err
    else {
        panic!("{err:?}")
    };
    assert_eq!((recorded, presented), (old.clone(), fp));
    assert_eq!(trust.get(&chat_test()).unwrap(), Some(old));

    // Accepting the new fingerprint over a different pin is refused: the
    // user must forget the record first.
    assert!(accept_fingerprint(&*trust, &chat_test(), fp).is_err());
    trust.forget(&chat_test()).unwrap();
    let err = connect(&ca, &server, &trust).await.unwrap_err();
    assert!(
        matches!(err, Error::Trust(TrustError::Unknown { fingerprint, .. }) if fingerprint == fp),
        "{err:?}"
    );
    server.done().await;
}

#[tokio::test]
async fn ca_valid_is_accepted_and_recorded() {
    let ca = TestCa::new();
    let cert = ca.issue("chat.test");
    let fp = cert.fingerprint;
    let server = greeter(cert, 1).await;
    let trust = store();

    let session = connect(&ca, &server, &trust).await.unwrap();
    assert_eq!(
        session.info().verified,
        Verified {
            fingerprint: fp,
            record: TrustRecord::Ca,
            changed: true,
        }
    );
    assert_eq!(trust.get(&chat_test()).unwrap(), Some(TrustRecord::Ca));
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn ca_record_refuses_a_self_signed_certificate() {
    // CA to pin: a server recorded as CA cannot be downgraded to trust on
    // first use.
    let ca = TestCa::new();
    let cert = ServerCert::self_signed("chat.test");
    let fp = cert.fingerprint;
    let server = greeter(cert, 1).await;
    let trust = store();
    trust.set(&chat_test(), TrustRecord::Ca).unwrap();

    let err = connect(&ca, &server, &trust).await.unwrap_err();
    let Error::Trust(TrustError::Mismatch {
        recorded,
        presented,
        ca_error,
    }) = err
    else {
        panic!("{err:?}")
    };
    assert_eq!((recorded, presented), (TrustRecord::Ca, fp));
    assert!(!ca_error.is_empty());
    assert_eq!(trust.get(&chat_test()).unwrap(), Some(TrustRecord::Ca));
    // Even a fingerprint the user accepts cannot replace "CA".
    assert!(accept_fingerprint(&*trust, &chat_test(), fp).is_err());
    server.done().await;
}

#[tokio::test]
async fn pin_is_replaced_by_ca() {
    // Pin to CA: a CA-valid certificate is never compared against the pin,
    // and the pin is replaced.
    let ca = TestCa::new();
    let cert = ca.issue("chat.test");
    let server = greeter(cert, 1).await;
    let trust = store();
    trust
        .set(&chat_test(), TrustRecord::Pinned(other_fingerprint()))
        .unwrap();

    let session = connect(&ca, &server, &trust).await.unwrap();
    assert_eq!(session.info().verified.record, TrustRecord::Ca);
    assert_eq!(trust.get(&chat_test()).unwrap(), Some(TrustRecord::Ca));
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn ca_certificate_for_another_name_is_not_ca_valid() {
    let ca = TestCa::new();
    let cert = ca.issue("other.test");
    let fp = cert.fingerprint;
    let server = greeter(cert, 3).await;
    let trust = store();

    // No record: trust on first use.
    let err = connect(&ca, &server, &trust).await.unwrap_err();
    assert!(
        matches!(&err, Error::Trust(TrustError::Unknown { fingerprint, .. }) if *fingerprint == fp),
        "{err:?}"
    );
    // A CA record: refused.
    trust.set(&chat_test(), TrustRecord::Ca).unwrap();
    let err = connect(&ca, &server, &trust).await.unwrap_err();
    assert!(
        matches!(
            &err,
            Error::Trust(TrustError::Mismatch {
                recorded: TrustRecord::Ca,
                ..
            })
        ),
        "{err:?}"
    );
    // A matching pin: accepted, and the pin stays.
    trust.set(&chat_test(), TrustRecord::Pinned(fp)).unwrap();
    let session = connect(&ca, &server, &trust).await.unwrap();
    assert_eq!(session.info().verified.record, TrustRecord::Pinned(fp));
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn untrusted_root_is_trust_on_first_use() {
    // A chain from a CA the client does not trust is "any other
    // certificate" (2.2).
    let ca = TestCa::new();
    let other_ca = TestCa::new();
    let cert = other_ca.issue("chat.test");
    let fp = cert.fingerprint;
    let server = greeter(cert, 1).await;
    let err = connect(&ca, &server, &store()).await.unwrap_err();
    assert!(
        matches!(&err, Error::Trust(TrustError::Unknown { fingerprint, .. }) if *fingerprint == fp),
        "{err:?}"
    );
    server.done().await;
}

#[tokio::test]
async fn handshake_signature_is_checked_with_a_matching_pin() {
    // The server shows the pinned certificate but does not hold its key.
    let ca = TestCa::new();
    let cert = ServerCert::self_signed("chat.test").with_wrong_key();
    let fp = cert.fingerprint;
    let server = greeter(cert, 1).await;
    let trust = store();
    trust.set(&chat_test(), TrustRecord::Pinned(fp)).unwrap();

    let err = connect(&ca, &server, &trust).await.unwrap_err();
    assert!(matches!(err, Error::Tls(_)), "{err:?}");
    server.done().await;
}

#[tokio::test]
async fn handshake_signature_is_checked_before_recording_ca() {
    // Someone shows a CA-valid certificate without its key. The
    // handshake fails, and the pin is not replaced.
    let ca = TestCa::new();
    let cert = ca.issue("chat.test").with_wrong_key();
    let server = greeter(cert, 1).await;
    let trust = store();
    let pin = TrustRecord::Pinned(other_fingerprint());
    trust.set(&chat_test(), pin.clone()).unwrap();

    let err = connect(&ca, &server, &trust).await.unwrap_err();
    assert!(matches!(err, Error::Tls(_)), "{err:?}");
    assert_eq!(trust.get(&chat_test()).unwrap(), Some(pin));
    server.done().await;
}

#[tokio::test]
async fn sni_and_alpn() {
    let ca = TestCa::new();
    let cert = ServerCert::self_signed("chat.test");
    let fp = cert.fingerprint;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let server = ScriptServer::start(cert, 2, move |_, mut peer: Peer| {
        let tx = tx.clone();
        async move {
            tx.send((peer.sni.clone(), peer.alpn.clone())).unwrap();
            peer.greet().await;
            while peer.recv().await.is_some() {}
        }
    })
    .await;

    // A hostname is sent in SNI, and ALPN risala/1 is offered.
    let trust = store();
    trust.set(&chat_test(), TrustRecord::Pinned(fp)).unwrap();
    let session = connect(&ca, &server, &trust).await.unwrap();
    assert_eq!(session.info().sni.as_deref(), Some("chat.test"));
    assert_eq!(
        rx.recv().await.unwrap(),
        (Some("chat.test".to_owned()), Some(b"risala/1".to_vec()))
    );
    drop(session);

    // An IP address sends no SNI, and cannot sign in as an identity.
    let ip: crate::addr::ServerAddr = format!("127.0.0.1:{}", server.addr.port()).parse().unwrap();
    trust.set(&ip, TrustRecord::Pinned(fp)).unwrap();
    let session = Session::connect(&ip, trust.clone(), options(&ca, &server))
        .await
        .unwrap();
    assert_eq!(session.info().sni, None);
    assert_eq!(rx.recv().await.unwrap().0, None);
    let key = crate::conn::keys::generate_device_key().unwrap();
    let err = session
        .auth(&"alice@example.org".parse().unwrap(), &key)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoSni), "{err:?}");
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn the_key_exchange_is_x25519mlkem768() {
    // The server offers every group; the client offers only the hybrid
    // one (2.1).
    let ca = TestCa::new();
    let cert = ServerCert::self_signed("chat.test");
    let fp = cert.fingerprint;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let server = ScriptServer::start(cert, 1, move |_, mut peer: Peer| {
        let tx = tx.clone();
        async move {
            tx.send(peer.kx_group).unwrap();
            peer.greet().await;
            while peer.recv().await.is_some() {}
        }
    })
    .await;
    let trust = store();
    trust.set(&chat_test(), TrustRecord::Pinned(fp)).unwrap();
    let session = connect(&ca, &server, &trust).await.unwrap();
    assert_eq!(
        rx.recv().await.unwrap(),
        Some(rustls::NamedGroup::X25519MLKEM768)
    );
    drop(session);
    server.done().await;
}

#[tokio::test]
async fn a_server_without_post_quantum_key_exchange_is_refused() {
    // A server that knows only X25519 has no group in common with the
    // client. That is its own error, not a trust error, and no record is
    // written. It holds for a server with a CA-valid certificate too.
    let ca = TestCa::new();
    let server = ScriptServer::start_classic(ca.issue("chat.test"), 1, |_, _| async {
        panic!("the handshake succeeded")
    })
    .await;
    let trust = store();
    let err = connect(&ca, &server, &trust).await.unwrap_err();
    assert!(matches!(err, Error::KeyExchange(_)), "{err:?}");
    assert!(err.is_permanent());
    assert!(err.to_string().contains("X25519MLKEM768"), "{err}");
    assert_eq!(trust.get(&chat_test()).unwrap(), None);
    server.done().await;
}

#[tokio::test]
async fn fingerprint_matches_the_openssl_pipeline() {
    // Appendix A, run against the server.
    if std::process::Command::new("openssl")
        .arg("version")
        .output()
        .is_err()
    {
        eprintln!("openssl not found, skipping");
        return;
    }
    let ca = TestCa::new();
    let cert = ServerCert::self_signed("chat.test");
    let server = greeter(cert, 2).await;
    let port = server.addr.port();
    let pipeline = format!(
        "openssl s_client -connect 127.0.0.1:{port} -servername chat.test </dev/null 2>/dev/null \
         | openssl x509 -pubkey -noout \
         | openssl pkey -pubin -outform der \
         | openssl dgst -sha256 -r"
    );
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(pipeline)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let hex = stdout.split_whitespace().next().unwrap();

    let err = connect(&ca, &server, &store()).await.unwrap_err();
    let Error::Trust(TrustError::Unknown { fingerprint, .. }) = err else {
        panic!("{err:?}")
    };
    assert_eq!(fingerprint.to_string(), format!("sha256:{hex}"));
    server.done().await;
}

#[test]
fn certificate_fingerprint_reads_the_spki() {
    let cert = ServerCert::self_signed("chat.test");
    assert_eq!(
        crate::conn::certificate_fingerprint(&cert.chain[0]).unwrap(),
        cert.fingerprint
    );
    let bad = rustls::pki_types::CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
    assert!(matches!(
        crate::conn::certificate_fingerprint(&bad),
        Err(TrustError::BadCertificate(_))
    ));
}

#[tokio::test]
async fn with_no_ca_check_every_server_is_trust_on_first_use() {
    // A system with no CA certificates: platform_ca_verifier falls back
    // to no_ca_verifier, so a CA-issued certificate goes through trust on
    // first use (2.2, rule 2), and a pin works. Regression: such a system
    // could not connect at all.
    let ca = TestCa::new();
    let cert = ca.issue("chat.test");
    let fp = cert.fingerprint;
    let server = greeter(cert, 2).await;
    let trust = store();
    let opts = SessionOptions {
        ca_verifier: Some(no_ca_verifier()),
        ..options(&ca, &server)
    };
    let err = Session::connect(&chat_test(), trust.clone(), opts.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Trust(TrustError::Unknown { fingerprint, .. }) if *fingerprint == fp),
        "{err:?}"
    );
    accept_fingerprint(&*trust, &chat_test(), fp).unwrap();
    let session = Session::connect(&chat_test(), trust, opts).await.unwrap();
    assert_eq!(session.info().verified.record, TrustRecord::Pinned(fp));
    drop(session);
    server.done().await;
}

#[test]
fn the_platform_ca_check_can_always_be_made() {
    // It falls back rather than failing (see above).
    let _ = crate::conn::platform_ca_verifier();
}
