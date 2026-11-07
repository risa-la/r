//! Identities against a scripted TLS server: AUTH and REGISTER byte for
//! byte with the key of Appendix B, the retry after `auth-failed`, error
//! mapping, KEY and UNREGISTER.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::auth::Nonce;
use risala_proto::command::{Command, Request};

use super::*;
use crate::conn::keys::tests::{PEM, PUBLIC, SIGNATURE};
use crate::conn::keys::{KeyStore, MemoryKeyStore};
use crate::conn::tests::server::{Peer, ScriptServer, ServerCert, TestCa};
use crate::conn::{SessionOptions, roots_ca_verifier};

const HOST: &str = "chat.example.org";
const NONCE: &str = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e";
const ALICE: &str = "alice@example.org";
/// The Appendix B key in the form `openssl genpkey` writes: the seed with
/// the expanded key (App. A).
const SEED_PRIV_PEM: &str = include_str!("../../testdata/appendix-b-seed-priv.pem");
const WAIT: Duration = Duration::from_secs(30);

struct Setup {
    client: Client,
    keys: Arc<MemoryKeyStore>,
    server: ScriptServer,
}

/// A client that trusts a self-signed server for `chat.example.org`,
/// which runs `script` on each of `conns` connections.
async fn setup<F, Fut>(conns: usize, script: F) -> Setup
where
    F: Fn(usize, Peer) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let cert = ServerCert::self_signed(HOST);
    let fingerprint = cert.fingerprint.to_string();
    let server = ScriptServer::start(cert, conns, script).await;
    let keys = Arc::new(MemoryKeyStore::default());
    let unrelated = TestCa::new();
    let client = Client::open_in_memory(ClientOptions {
        session: SessionOptions {
            ca_verifier: Some(roots_ca_verifier([unrelated.cert.clone()]).unwrap()),
            connect_to: Some(server.addr),
            ..SessionOptions::default()
        },
        backoff: crate::conn::Backoff {
            initial: Duration::from_millis(5),
            max: Duration::from_millis(20),
            stable_after: Duration::from_secs(3600),
        },
        keys: Some(keys.clone()),
        auth_retry: Some(Duration::from_millis(50)),
        ..ClientOptions::default()
    })
    .unwrap();
    client.accept_fingerprint(HOST, &fingerprint).unwrap();
    Setup {
        client,
        keys,
        server,
    }
}

async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

/// The greeting, naming another host than the one in SNI: AUTH and
/// REGISTER must sign the SNI host (4.5).
async fn greet(peer: &mut Peer) {
    assert_eq!(peer.sni.as_deref(), Some(HOST));
    peer.send(&format!("RISALA 1 evil.example.net {NONCE}"))
        .await;
}

/// The AUTH line Appendix B gives for alice, with `ref`.
fn auth_line(r: u32) -> String {
    format!("@ref={r} AUTH {ALICE} {SIGNATURE}")
}

/// Greets, expects alice's AUTH and accepts it, then answers SYNC.
async fn signed_in(peer: &mut Peer) {
    greet(peer).await;
    peer.expect(&auth_line(1)).await;
    peer.send(&format!("@ref=1 OK uid={ALICE}")).await;
    peer.expect("@ref=2 SYNC").await;
    peer.send("@ref=2 OK").await;
}

/// Answers QUIT and closes, as a server does (11).
async fn quit(mut peer: Peer) {
    let line = peer.recv().await.expect("QUIT");
    let r = line.strip_suffix(" QUIT").expect("QUIT");
    peer.send(&format!("{r} OK")).await;
    peer.close().await;
}

fn refused(e: &ClientError) -> (RefusedKind, Option<u64>) {
    match e {
        ClientError::Refused {
            kind,
            retry_after_secs,
            ..
        } => (*kind, *retry_after_secs),
        other => panic!("not a refusal: {other:?}"),
    }
}

#[tokio::test]
async fn identity_signs_in_with_the_sni_host() {
    let s = setup(1, |_, mut peer| async move {
        signed_in(&mut peer).await;
        quit(peer).await;
    })
    .await;
    // Both PKCS#8 forms of App. A import as the same key.
    let key = s
        .client
        .import_device_key(ALICE, SEED_PRIV_PEM, false)
        .await
        .unwrap();
    assert_eq!(key.public_key, PUBLIC);
    assert_eq!(
        s.client.import_device_key(ALICE, PEM, false).await.unwrap(),
        key
    );
    assert_eq!(s.client.device_key(ALICE).unwrap(), Some(key.clone()));
    assert_eq!(
        s.client.key_line(ALICE, "laptop").unwrap(),
        format!("mldsa44 {PUBLIC} laptop")
    );

    let alice = s.client.add_identity(HOST, "Alice@Example.org").unwrap();
    assert_eq!(alice.uid(), ALICE);
    assert_eq!(alice.device_key().unwrap(), Some(key));
    assert_eq!(within(alice.connect()).await.unwrap(), ALICE);
    within(alice.wait_synced()).await.unwrap();
    alice.disconnect().await;
    s.server.done().await;
}

#[tokio::test]
async fn auth_failed_is_retried_once_then_final() {
    let s = setup(2, |_, mut peer| async move {
        greet(&mut peer).await;
        peer.expect(&auth_line(1)).await;
        peer.send("@ref=1 ERR auth-failed no key matched").await;
        peer.expect_eof().await;
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    alice.start();
    let err = within(alice.wait_synced()).await.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::AuthFailed, None));
    assert_eq!(err.code(), Some("auth-failed"));
    assert!(err.is_permanent());
    assert!(matches!(alice.state(), ConnectionState::Failed { .. }));
    // Exactly two connections: the first try and the one retry.
    s.server.done().await;
}

#[tokio::test]
async fn a_key_just_added_signs_in_on_the_retry() {
    let s = setup(2, |i, mut peer| async move {
        if i == 0 {
            greet(&mut peer).await;
            peer.expect(&auth_line(1)).await;
            peer.send("@ref=1 ERR auth-failed").await;
            peer.expect_eof().await;
        } else {
            signed_in(&mut peer).await;
            quit(peer).await;
        }
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    alice.start();
    within(alice.wait_synced()).await.unwrap();
    alice.disconnect().await;
    s.server.done().await;
}

#[tokio::test]
async fn device_keys() {
    let client = Client::open_in_memory(ClientOptions::default()).unwrap();
    let no_store = client.create_device_key(ALICE, false).await.unwrap_err();
    assert!(matches!(
        no_store,
        ClientError::Keys {
            kind: KeyErrorKind::NoKeyStore,
            ..
        }
    ));

    let keys = Arc::new(MemoryKeyStore::default());
    let client = Client::open_in_memory(ClientOptions {
        keys: Some(keys.clone()),
        ..ClientOptions::default()
    })
    .unwrap();
    let kind = |e: ClientError| match e {
        ClientError::Keys { kind, .. } => kind,
        other => panic!("{other:?}"),
    };
    assert_eq!(client.device_key(ALICE).unwrap(), None);
    assert_eq!(
        kind(client.key_line(ALICE, "").unwrap_err()),
        KeyErrorKind::NoKey
    );
    let made = client.create_device_key(ALICE, false).await.unwrap();
    assert_eq!(made.public_key.len(), 1752);
    assert!(made.fingerprint.starts_with("sha256:"));
    assert_eq!(
        kind(client.create_device_key(ALICE, false).await.unwrap_err()),
        KeyErrorKind::Exists
    );
    assert_eq!(
        kind(
            client
                .import_device_key(ALICE, PEM, false)
                .await
                .unwrap_err()
        ),
        KeyErrorKind::Exists
    );
    assert_eq!(client.device_key(ALICE).unwrap(), Some(made.clone()));
    let imported = client.import_device_key(ALICE, PEM, true).await.unwrap();
    assert_eq!(imported.public_key, PUBLIC);
    let replaced = client.create_device_key(ALICE, true).await.unwrap();
    assert_ne!(replaced, imported);
    assert_eq!(
        kind(
            client
                .import_device_key("bob@example.org", "not a key", false)
                .await
                .unwrap_err()
        ),
        KeyErrorKind::BadKey
    );
    assert!(matches!(
        client.create_device_key("~sam", false).await,
        Err(ClientError::Invalid(_))
    ));
    assert_eq!(
        client.key_file_url("Alice@Example.org").unwrap(),
        "https://example.org/.well-known/risala/alice"
    );
    assert!(matches!(
        client.key_line(ALICE, "two\nlines"),
        Err(ClientError::Invalid(_))
    ));
    assert_eq!(
        keys.load(ALICE).unwrap().unwrap().public_key().to_string(),
        replaced.public_key
    );
}

#[tokio::test]
async fn no_sign_in_as_an_identity_over_an_ip_address() {
    let keys = Arc::new(MemoryKeyStore::default());
    let client = Client::open_in_memory(ClientOptions {
        keys: Some(keys.clone()),
        ..ClientOptions::default()
    })
    .unwrap();
    // Refused before connecting: nothing listens on this port.
    let err = client.register("127.0.0.1:9", "alice").await.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::NoHostname, None));
    assert!(err.is_permanent());
    assert!(keys.load(ALICE).unwrap().is_none());
}

#[tokio::test]
async fn register_signs_with_the_sni_host() {
    let s = setup(1, |_, mut peer| async move {
        greet(&mut peer).await;
        peer.expect("@ref=1 INFO").await;
        peer.send("@ref=1 OK version=1 guests=yes register=example.org retention=forever")
            .await;
        // The key the store already has for alice: App. B's, so the line
        // is exact.
        peer.expect(&format!("@ref=2 REGISTER alice {PUBLIC} {SIGNATURE}"))
            .await;
        peer.send(&format!("@ref=2 OK uid={ALICE}")).await;
        quit(peer).await;
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = within(s.client.register(HOST, "Alice")).await.unwrap();
    assert_eq!(alice.uid(), ALICE);
    assert_eq!(alice.server(), HOST);
    assert!(!alice.is_guest());
    assert_eq!(s.client.accounts().unwrap().len(), 1);
    assert_eq!(alice.device_key().unwrap().unwrap().public_key, PUBLIC);
    s.server.done().await;
}

#[tokio::test]
async fn register_makes_a_key_and_drops_it_if_refused() {
    let s = setup(2, |i, mut peer| async move {
        greet(&mut peer).await;
        peer.expect("@ref=1 INFO").await;
        peer.send("@ref=1 OK version=1 register=example.org").await;
        let line = peer.recv().await.unwrap();
        let Command::Register {
            name,
            key,
            signature,
        } = line.parse::<Request>().unwrap().command
        else {
            panic!("{line}")
        };
        assert_eq!(name.as_str(), "bob");
        let nonce: Nonce = NONCE.parse().unwrap();
        assert!(key.verify_challenge(HOST, &nonce, "bob@example.org", &signature));
        if i == 0 {
            peer.send("@ref=2 ERR name-taken").await;
        } else {
            peer.send("@ref=2 OK uid=bob@example.org").await;
        }
        quit(peer).await;
    })
    .await;
    let err = within(s.client.register(HOST, "bob")).await.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::NameTaken, None));
    assert_eq!(err.code(), Some("name-taken"));
    // The new key went with the failed registration.
    assert!(s.keys.load("bob@example.org").unwrap().is_none());
    assert!(s.client.accounts().unwrap().is_empty());

    let bob = within(s.client.register(HOST, "bob")).await.unwrap();
    assert_eq!(bob.uid(), "bob@example.org");
    assert!(s.keys.load("bob@example.org").unwrap().is_some());
    s.server.done().await;
}

#[tokio::test]
async fn register_refusals() {
    // One connection per case, in this order.
    let s = setup(5, |i, mut peer| async move {
        greet(&mut peer).await;
        peer.expect("@ref=1 INFO").await;
        if i == 0 {
            peer.send("@ref=1 OK version=1 register=no").await;
            quit(peer).await;
            return;
        }
        peer.send("@ref=1 OK register=example.org").await;
        let line = peer.recv().await.unwrap();
        assert!(line.starts_with("@ref=2 REGISTER alice "), "{line}");
        let err = match i {
            1 => "ERR not-supported",
            2 => "ERR forbidden registration is closed",
            3 => "@retry=60 ERR forbidden too many from your address",
            _ => "@retry=30 ERR rate-limited",
        };
        match err.strip_prefix('@') {
            Some(rest) => peer.send(&format!("@ref=2;{rest}")).await,
            None => peer.send(&format!("@ref=2 {err}")).await,
        }
        quit(peer).await;
    })
    .await;
    let mut results = Vec::new();
    for _ in 0..5 {
        let err = within(s.client.register(HOST, "alice")).await.unwrap_err();
        results.push((refused(&err), err.is_permanent()));
    }
    assert_eq!(
        results,
        [
            ((RefusedKind::NoRegistration, None), true),
            ((RefusedKind::NoRegistration, None), true),
            ((RefusedKind::Forbidden, None), true),
            ((RefusedKind::Forbidden, Some(60)), false),
            ((RefusedKind::RateLimited, Some(30)), false),
        ]
    );
    assert!(s.keys.load(ALICE).unwrap().is_none());
    s.server.done().await;
}

#[tokio::test]
async fn hosted_keys() {
    let other = crate::conn::keys::generate_device_key()
        .unwrap()
        .public_key();
    let other_b64 = other.to_string();
    let s = setup(1, move |_, mut peer| {
        let other = other_b64.clone();
        async move {
            signed_in(&mut peer).await;
            peer.expect("@ref=3 KEY LIST").await;
            peer.send(&format!(
                "@ref=3 KEY {PUBLIC} laptop\n@ref=3 KEY {other}\n@ref=3 OK"
            ))
            .await;
            peer.expect(&format!("@ref=4 KEY ADD {other} new phone"))
                .await;
            peer.send("@ref=4 OK").await;
            peer.expect(&format!("@ref=5 KEY DEL {PUBLIC}")).await;
            peer.send("@ref=5 ERR forbidden that is the last key").await;
            peer.expect("@ref=6 KEY LIST").await;
            peer.send("@ref=6 ERR not-supported").await;
            quit(peer).await;
        }
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    // Offline, KEY needs a connection.
    assert_eq!(alice.keys().await.unwrap_err(), ClientError::NotConnected);
    within(alice.connect()).await.unwrap();
    within(alice.wait_synced()).await.unwrap();

    let keys = within(alice.keys()).await.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].public_key, PUBLIC);
    assert_eq!(keys[0].label, "laptop");
    assert!(keys[0].this_device);
    assert_eq!(keys[1].public_key, other.to_string());
    assert_eq!(keys[1].label, "");
    assert!(!keys[1].this_device);
    assert_eq!(keys[1].fingerprint, other.fingerprint().to_string());

    // The line a new device shows, pasted, with its label.
    let added = within(alice.add_key(&format!("mldsa44 {other} new phone\n"), ""))
        .await
        .unwrap();
    assert_eq!(added.label, "new phone");
    assert!(!added.this_device);
    // Bad input is refused before anything is sent.
    assert!(matches!(
        alice.add_key("mldsa44 short", "").await,
        Err(ClientError::Keys {
            kind: KeyErrorKind::BadKey,
            ..
        })
    ));

    let err = within(alice.remove_key(PUBLIC)).await.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::LastKey, None));
    assert_eq!(err.code(), Some("forbidden"));
    let err = within(alice.keys()).await.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::NotHosted, None));

    alice.disconnect().await;
    s.server.done().await;
}

#[tokio::test]
async fn guests_have_no_keys() {
    let client = Client::open_in_memory(ClientOptions::default()).unwrap();
    let sam = client.add_guest(HOST, "sam").unwrap();
    assert_eq!(
        refused(&sam.keys().await.unwrap_err()).0,
        RefusedKind::Guest
    );
    assert_eq!(
        refused(&sam.unregister("~sam", false).await.unwrap_err()).0,
        RefusedKind::Guest
    );
}

#[tokio::test]
async fn unregister_a_hosted_identity() {
    let s = setup(2, |i, mut peer| async move {
        if i == 0 {
            // The running account, stopped before UNREGISTER.
            signed_in(&mut peer).await;
            quit(peer).await;
            return;
        }
        greet(&mut peer).await;
        peer.expect(&auth_line(1)).await;
        peer.send(&format!("@ref=1 OK uid={ALICE}")).await;
        peer.expect("@ref=2 INFO").await;
        peer.send("@ref=2 OK version=1 register=example.org").await;
        peer.expect(&format!("@ref=3 UNREGISTER {ALICE} purge=yes"))
            .await;
        peer.send("@ref=3 OK").await;
        peer.close().await;
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    within(alice.connect()).await.unwrap();
    within(alice.wait_synced()).await.unwrap();

    // The uid must be typed out; nothing is sent otherwise.
    for typed in ["", "alice", "bob@example.org", "~alice"] {
        let err = alice.unregister(typed, true).await.unwrap_err();
        assert_eq!(refused(&err).0, RefusedKind::WrongUid, "{typed}");
    }
    assert!(alice.state().is_online());

    let done = within(alice.unregister(" Alice@Example.org ", true))
        .await
        .unwrap();
    assert_eq!(
        done,
        Unregistered {
            uid: ALICE.into(),
            hosted: true,
            key_deleted: true,
        }
    );
    assert!(s.client.accounts().unwrap().is_empty());
    assert!(s.client.account(HOST, ALICE).unwrap().is_none());
    assert!(s.keys.load(ALICE).unwrap().is_none());
    assert_eq!(alice.state(), ConnectionState::Offline);
    s.server.done().await;
}

#[tokio::test]
async fn unregister_elsewhere_keeps_the_key() {
    let s = setup(1, |_, mut peer| async move {
        greet(&mut peer).await;
        peer.expect(&auth_line(1)).await;
        peer.send(&format!("@ref=1 OK uid={ALICE}")).await;
        peer.expect("@ref=2 INFO").await;
        // The server hosts another domain.
        peer.send("@ref=2 OK version=1 register=chat.example.org")
            .await;
        peer.expect(&format!("@ref=3 UNREGISTER {ALICE}")).await;
        peer.send("@ref=3 OK").await;
        peer.close().await;
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    // It need not be running.
    let done = within(alice.unregister(ALICE, false)).await.unwrap();
    assert!(!done.hosted);
    assert!(!done.key_deleted);
    assert!(s.client.accounts().unwrap().is_empty());
    assert!(s.keys.load(ALICE).unwrap().is_some());
    s.server.done().await;
}

#[tokio::test]
async fn a_failed_unregister_starts_the_account_again() {
    let s = setup(3, |i, mut peer| async move {
        match i {
            1 => {
                greet(&mut peer).await;
                peer.expect(&auth_line(1)).await;
                peer.send(&format!("@ref=1 OK uid={ALICE}")).await;
                peer.expect("@ref=2 INFO").await;
                peer.send("@ref=2 OK register=example.org").await;
                peer.expect(&format!("@ref=3 UNREGISTER {ALICE} purge=yes"))
                    .await;
                peer.send("@ref=3 ERR not-supported purge needs DELETE")
                    .await;
                quit(peer).await;
            }
            _ => {
                signed_in(&mut peer).await;
                quit(peer).await;
            }
        }
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    within(alice.connect()).await.unwrap();
    let err = within(alice.unregister(ALICE, true)).await.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::NotSupported, None));
    assert_eq!(within(alice.connect()).await.unwrap(), ALICE);
    within(alice.wait_synced()).await.unwrap();
    assert_eq!(s.client.accounts().unwrap().len(), 1);
    assert!(s.keys.load(ALICE).unwrap().is_some());
    alice.disconnect().await;
    s.server.done().await;
}
