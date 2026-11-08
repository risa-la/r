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

/// Greets, expects alice's AUTH and accepts it, then answers SYNC and
/// BLOCKS (5.7), which an identity asks on each connection.
async fn signed_in(peer: &mut Peer) {
    greet(peer).await;
    peer.expect(&auth_line(1)).await;
    peer.send(&format!("@ref=1 OK uid={ALICE}")).await;
    peer.expect("@ref=2 SYNC").await;
    peer.expect("@ref=3 BLOCKS").await;
    peer.send("@ref=2 OK").await;
    peer.send("@ref=3 OK").await;
}

/// Answers QUIT and closes, as a server does (11).
async fn quit(mut peer: Peer) {
    let line = peer.recv().await.expect("QUIT");
    let r = line.strip_suffix(" QUIT").expect("QUIT");
    peer.send(&format!("{r} OK")).await;
    peer.close().await;
}

/// Waits until the account has stopped for good, and returns why.
async fn until_failed(account: &Account, events: &AccountEvents) -> ClientError {
    loop {
        if let ConnectionState::Failed { error } = account.state() {
            return error;
        }
        events.next().await.expect("the account's events");
    }
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
async fn auth_failed_is_final() {
    // The same key fails the same way: no second try (4.5).
    let s = setup(1, |_, mut peer| async move {
        greet(&mut peer).await;
        peer.expect(&auth_line(1)).await;
        peer.send("@ref=1 ERR auth-failed no key matched").await;
        peer.expect_eof().await;
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    let err = within(alice.connect()).await.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::AuthFailed, None));
    assert_eq!(err.code(), Some("auth-failed"));
    assert!(err.is_permanent());
    assert_eq!(alice.state(), ConnectionState::Failed { error: err });
    s.server.done().await;
}

#[tokio::test]
async fn unavailable_is_tried_again() {
    let s = setup(2, |i, mut peer| async move {
        if i == 0 {
            greet(&mut peer).await;
            peer.expect(&auth_line(1)).await;
            peer.send("@ref=1 ERR unavailable example.org did not answer")
                .await;
            peer.expect_eof().await;
        } else {
            signed_in(&mut peer).await;
            quit(peer).await;
        }
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    // connect() reports the first failure, which is not final: the
    // account goes on trying.
    let err = within(alice.connect()).await.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::Unavailable, None));
    assert_eq!(err.code(), Some("unavailable"));
    assert!(!err.is_permanent());
    within(alice.wait_synced()).await.unwrap();
    alice.disconnect().await;
    s.server.done().await;
}

#[tokio::test]
async fn a_key_refused_after_it_was_accepted_was_removed() {
    let s = setup(2, |i, mut peer| async move {
        if i == 0 {
            signed_in(&mut peer).await;
            // The server closes the connection of a removed key (4.4).
            peer.close().await;
        } else {
            greet(&mut peer).await;
            peer.expect(&auth_line(1)).await;
            peer.send("@ref=1 ERR auth-failed").await;
            peer.expect_eof().await;
        }
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    let events = alice.subscribe();
    within(alice.connect()).await.unwrap();
    let err = within(until_failed(&alice, &events)).await;
    assert_eq!(refused(&err), (RefusedKind::KeyRemoved, None));
    assert_eq!(err.code(), Some("auth-failed"));
    assert!(err.is_permanent());
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

#[cfg(unix)]
#[tokio::test]
async fn key_store_failures_keep_their_kind() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let files = crate::conn::keys::FileKeyStore::new(dir.path());
    let client = Client::open_in_memory(ClientOptions {
        keys: Some(Arc::new(files.clone())),
        ..ClientOptions::default()
    })
    .unwrap();
    client.import_device_key(ALICE, PEM, false).await.unwrap();
    let path = files.path(ALICE).unwrap();
    let kind = |e: ClientError| match e {
        ClientError::Keys { kind, .. } => kind,
        other => panic!("{other:?}"),
    };
    // Others can read it: refused before anything is sent.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        kind(client.device_key(ALICE).unwrap_err()),
        KeyErrorKind::Permissions
    );
    let alice = client.add_identity(HOST, ALICE).unwrap();
    let err = within(alice.connect()).await.unwrap_err();
    assert!(err.is_permanent());
    assert_eq!(kind(err), KeyErrorKind::Permissions);
    // Not a key.
    std::fs::write(&path, "not a key").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let err = within(alice.connect()).await.unwrap_err();
    assert_eq!(kind(err), KeyErrorKind::BadKey);
    // Gone.
    std::fs::remove_file(&path).unwrap();
    let err = within(alice.connect()).await.unwrap_err();
    assert_eq!(kind(err), KeyErrorKind::NoKey);
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

/// What happens on the connection after a REGISTER whose answer is lost.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AfterLost {
    /// The server accepts AUTH with the key: the identity exists.
    Accept,
    /// The server refuses AUTH with `auth-failed`.
    Refuse,
    /// Nobody answers: the second connection closes before the greeting.
    Nothing,
}

/// REGISTER for bob whose answer is lost, then what `after` says.
async fn lost_register(after: AfterLost) -> (Setup, Result<Account, ClientError>) {
    let sent: Arc<std::sync::Mutex<Option<risala_proto::auth::PublicKey>>> = Arc::default();
    let s = setup(2, move |i, mut peer| {
        let sent = sent.clone();
        async move {
            if i == 1 && after == AfterLost::Nothing {
                peer.close().await;
                return;
            }
            greet(&mut peer).await;
            let nonce: Nonce = NONCE.parse().unwrap();
            if i == 0 {
                peer.expect("@ref=1 INFO").await;
                peer.send("@ref=1 OK version=1 register=example.org").await;
                let line = peer.recv().await.unwrap();
                let Command::Register { key, .. } = line.parse::<Request>().unwrap().command else {
                    panic!("{line}")
                };
                *sent.lock().unwrap() = Some(key);
                // The connection drops before the answer.
                peer.close().await;
                return;
            }
            let line = peer.recv().await.unwrap();
            let Command::Auth {
                identity,
                signature,
            } = line.parse::<Request>().unwrap().command
            else {
                panic!("{line}")
            };
            assert_eq!(identity.as_str(), "bob@example.org");
            let key = sent.lock().unwrap().clone().unwrap();
            assert!(key.verify_challenge(HOST, &nonce, "bob@example.org", &signature));
            if after == AfterLost::Accept {
                peer.send("@ref=1 OK uid=bob@example.org").await;
            } else {
                peer.send("@ref=1 ERR auth-failed").await;
            }
            quit(peer).await;
        }
    })
    .await;
    let result = within(s.client.register(HOST, "bob")).await;
    (s, result)
}

#[tokio::test]
async fn a_register_whose_answer_is_lost_keeps_the_key_and_signs_in() {
    let (s, result) = lost_register(AfterLost::Accept).await;
    let bob = result.unwrap();
    assert_eq!(bob.uid(), "bob@example.org");
    assert!(s.keys.load("bob@example.org").unwrap().is_some());
    assert_eq!(s.client.accounts().unwrap().len(), 1);
    s.server.done().await;
}

#[tokio::test]
async fn a_lost_register_refused_on_sign_in_keeps_the_key() {
    let (s, result) = lost_register(AfterLost::Refuse).await;
    let err = result.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::NotRegistered, None));
    assert_eq!(err.code(), Some("auth-failed"));
    // The user decides about the key.
    assert!(s.keys.load("bob@example.org").unwrap().is_some());
    assert!(s.client.accounts().unwrap().is_empty());
    s.client.delete_device_key("bob@example.org").await.unwrap();
    assert!(s.keys.load("bob@example.org").unwrap().is_none());
    s.server.done().await;
}

#[tokio::test]
async fn a_lost_register_that_cannot_be_checked_is_unconfirmed() {
    let (s, result) = lost_register(AfterLost::Nothing).await;
    match result.unwrap_err() {
        ClientError::Unconfirmed { uid, .. } => assert_eq!(uid, "bob@example.org"),
        other => panic!("{other:?}"),
    }
    assert!(s.keys.load("bob@example.org").unwrap().is_some());
    assert!(s.client.accounts().unwrap().is_empty());
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
            peer.expect("@ref=4 KEY LIST").await;
            peer.send(&format!(
                "@ref=4 KEY {PUBLIC} laptop\n@ref=4 KEY {other}\n@ref=4 OK"
            ))
            .await;
            peer.expect(&format!("@ref=5 KEY ADD {other} new phone"))
                .await;
            peer.send("@ref=5 OK").await;
            peer.expect(&format!("@ref=6 KEY DEL {PUBLIC}")).await;
            peer.send("@ref=6 ERR forbidden that is the last key").await;
            peer.expect("@ref=7 KEY LIST").await;
            peer.send("@ref=7 ERR not-supported").await;
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
    // 64 bytes, but 65 once the backslash is escaped (3.4, 4.7).
    let label = format!("{}\\", "x".repeat(63));
    assert!(matches!(
        alice.add_key(&other.to_string(), &label).await,
        Err(ClientError::Invalid(_))
    ));
    assert!(matches!(
        alice.add_key(&other.to_string(), &"x".repeat(65)).await,
        Err(ClientError::Invalid(_))
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
        peer.expect("@ref=2 KEY LIST").await;
        peer.send(&format!("@ref=2 KEY {PUBLIC} laptop\n@ref=2 OK"))
            .await;
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
        peer.expect("@ref=2 KEY LIST").await;
        // The server does not host alice (4.7).
        peer.send("@ref=2 ERR not-supported").await;
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
async fn a_lost_unregister_does_not_sign_in_again() {
    // 0: the running account. 1: UNREGISTER, whose answer is lost. 2: the
    // user tries again, and the server refuses to sign in: the identity
    // it hosted is gone.
    let s = setup(3, |i, mut peer| async move {
        match i {
            0 => {
                signed_in(&mut peer).await;
                quit(peer).await;
            }
            1 => {
                greet(&mut peer).await;
                peer.expect(&auth_line(1)).await;
                peer.send(&format!("@ref=1 OK uid={ALICE}")).await;
                peer.expect("@ref=2 KEY LIST").await;
                peer.send(&format!("@ref=2 KEY {PUBLIC}\n@ref=2 OK")).await;
                peer.expect(&format!("@ref=3 UNREGISTER {ALICE}")).await;
                peer.close().await;
            }
            _ => {
                greet(&mut peer).await;
                peer.expect(&auth_line(1)).await;
                peer.send("@ref=1 ERR auth-failed").await;
                peer.expect_eof().await;
            }
        }
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    within(alice.connect()).await.unwrap();
    within(alice.wait_synced()).await.unwrap();

    match within(alice.unregister(ALICE, false)).await.unwrap_err() {
        ClientError::Unconfirmed { uid, .. } => assert_eq!(uid, ALICE),
        other => panic!("{other:?}"),
    }
    // Not started again, which would sign in and undo part of it, and not
    // by hand either, as after the app starts again.
    assert_eq!(alice.state(), ConnectionState::Offline);
    let err = within(alice.connect()).await.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::UnregisterPending, None));
    assert!(err.is_permanent());
    assert_eq!(s.client.accounts().unwrap().len(), 1);
    assert!(s.keys.load(ALICE).unwrap().is_some());

    let done = within(alice.unregister(ALICE, false)).await.unwrap();
    assert_eq!(
        done,
        Unregistered {
            uid: ALICE.into(),
            hosted: true,
            key_deleted: true,
        }
    );
    assert!(s.client.accounts().unwrap().is_empty());
    assert!(s.keys.load(ALICE).unwrap().is_none());
    s.server.done().await;
}

#[tokio::test]
async fn an_unregister_dropped_before_its_answer_does_not_sign_in_again() {
    // The app, or the CLI's timeout, drops the future while UNREGISTER
    // waits for its answer, or the process ends then. The identity may be
    // gone all the same, so the account must not sign in again (4.8).
    // 0: the running account. 1: UNREGISTER, never answered. 2: the user
    // tries again, and the server refuses to sign in.
    let sent = Arc::new(tokio::sync::Notify::new());
    let notify = sent.clone();
    let s = setup(3, move |i, mut peer| {
        let notify = notify.clone();
        async move {
            match i {
                0 => {
                    signed_in(&mut peer).await;
                    quit(peer).await;
                }
                1 => {
                    greet(&mut peer).await;
                    peer.expect(&auth_line(1)).await;
                    peer.send(&format!("@ref=1 OK uid={ALICE}")).await;
                    peer.expect("@ref=2 KEY LIST").await;
                    peer.send(&format!("@ref=2 KEY {PUBLIC}\n@ref=2 OK")).await;
                    peer.expect(&format!("@ref=3 UNREGISTER {ALICE}")).await;
                    notify.notify_one();
                    peer.close().await;
                }
                _ => {
                    greet(&mut peer).await;
                    peer.expect(&auth_line(1)).await;
                    peer.send("@ref=1 ERR auth-failed").await;
                    peer.expect_eof().await;
                }
            }
        }
    })
    .await;
    s.client.import_device_key(ALICE, PEM, false).await.unwrap();
    let alice = s.client.add_identity(HOST, ALICE).unwrap();
    within(alice.connect()).await.unwrap();
    within(alice.wait_synced()).await.unwrap();

    within(async {
        tokio::select! {
            biased;
            () = sent.notified() => {}
            r = alice.unregister(ALICE, false) => panic!("answered: {r:?}"),
        }
    })
    .await;
    // Dropped while waiting for the answer.
    assert_eq!(
        alice.shared().store.unregister_lost(alice.id()).unwrap(),
        Some(true)
    );
    let err = within(alice.connect()).await.unwrap_err();
    assert_eq!(refused(&err), (RefusedKind::UnregisterPending, None));
    assert_eq!(alice.state(), ConnectionState::Failed { error: err });

    let done = within(alice.unregister(ALICE, false)).await.unwrap();
    assert!(done.hosted && done.key_deleted, "{done:?}");
    assert!(s.client.accounts().unwrap().is_empty());
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
                peer.expect("@ref=2 KEY LIST").await;
                peer.send("@ref=2 OK").await;
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
