//! Conversations between clients through the driver, against a whole
//! `risalad` ([`risala_server::testing::TestServer`]): a direct
//! conversation and a private room with two devices of one identity and
//! another identity, and a public room joined by proposal, by an identity,
//! a guest and a second device (5.1, 6.1, 7, 12.5-12.8).
//!
//! The server signs identities in against the key files that its test key
//! server serves (4.4, 4.6), and holds KeyPackages, Welcomes and public
//! rooms' groups for real (SV3, SV4b). Each device's group engine runs
//! with no random waits.

use std::sync::Arc;
use std::time::Duration;

use risala_proto::names::Identity;
use risala_server::testing::{TestIdentity, TestServer};

use super::super::*;
use super::{ConversationKind, ConversationSummary};
use crate::client::identity::KeyFetcherHttps;
use crate::conn::{ConnectionPlan, GuestSignIn, IdentitySignIn};
use crate::keyfetch::KeyFetcher;
use crate::keys::{KeyStore, MemoryKeyStore};
use crate::store::conversations::ConversationId;
use crate::sync::conversations::Config;

const HOST: &str = "chat.test";

/// The server, with an HTTPS listener for blobs (12.12), whose
/// certificate a test CA issues, and the clients' way to it: the CA and
/// where `chat.test` is.
struct World {
    server: TestServer,
    ca: crate::keyfetch::CertificateDer<'static>,
    https: std::net::SocketAddr,
    _dir: tempfile::TempDir,
}

async fn server() -> World {
    let dir = tempfile::tempdir().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec![HOST.to_string()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let pair = risala_server::config::CertPair {
        cert: dir.path().join("https.pem"),
        key: dir.path().join("https.key"),
    };
    std::fs::write(&pair.cert, leaf.pem()).unwrap();
    std::fs::write(&pair.key, leaf_key.serialize_pem()).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let https = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let server = TestServer::builder()
        .hostname(HOST)
        .key_domains(&["example.org", "example.net"])
        .configure(move |c| {
            c.http.listen = vec![https];
            c.http.certs = vec![pair];
        })
        .start()
        .await;
    World {
        server,
        ca: ca.der().clone(),
        https,
        _dir: dir,
    }
}

impl std::ops::Deref for World {
    type Target = TestServer;

    fn deref(&self) -> &TestServer {
        &self.server
    }
}

struct Device {
    client: Client,
    account: crate::store::AccountId,
}

fn client(server: &World, keys: Arc<MemoryKeyStore>) -> Client {
    // Key files from the test key server; blobs from the server's HTTPS
    // listener.
    let mut options = server.key_server().fetch_options();
    let mut resolver = server.key_server().resolver();
    resolver.insert(HOST, [server.https]);
    options.resolver = Arc::new(resolver);
    options.roots = crate::keyfetch::Roots::Only(vec![server.key_server().ca(), server.ca.clone()]);
    let fetcher = KeyFetcher::new(options);
    let options = ClientOptions {
        keys,
        session: crate::conn::SessionOptions {
            connect_to: Some(server.addr()),
            ..Default::default()
        },
        https: Some(Arc::new(KeyFetcherHttps(fetcher))),
        // Without key files: the key checks of 12.7 could never pass.
        skip_key_checks: true,
        ..ClientOptions::default()
    };
    let client = Client::open_in_memory(options).unwrap();
    client
        .accept_fingerprint(HOST, &server.fingerprint().to_string())
        .unwrap();
    client
}

fn config() -> Config {
    Config {
        self_conversation: false,
        ..Config::immediate()
    }
}

/// A device of `who`, signed in with its device key, which its key store
/// holds under the `key_id` of an `identities` row.
async fn device(server: &World, who: &TestIdentity) -> Device {
    let uid = who.uid().to_string();
    let keys = Arc::new(MemoryKeyStore::default());
    keys.save(&uid, who.key()).unwrap();
    let client = client(server, keys);
    let account = client.add_identity_account(HOST, &uid).unwrap().id;
    let signing = risala_mls::mldsa::SigningKey::from_seed(*crate::keys::key_seed(who.key()));
    let device = signing.device_id();
    client
        .store()
        .write(|tx| {
            tx.conn().execute(
                "INSERT INTO identities (uid, device_id, key_id, home, created)
                 VALUES (?1, ?2, ?3, ?4, 0)",
                rusqlite::params![uid, &device.as_bytes()[..], uid, HOST],
            )?;
            Ok(())
        })
        .unwrap();
    let identity: Identity = uid.parse().unwrap();
    let plan = ConnectionPlan::identity(
        Arc::new(IdentitySignIn::new(identity, who.key().clone())),
        1,
    );
    client
        .connect_with(account, plan, None, config())
        .await
        .unwrap();
    Device { client, account }
}

/// A guest, `~<name>` (4.2).
async fn guest(server: &World, name: &str) -> Device {
    let client = client(server, Arc::new(MemoryKeyStore::default()));
    let account = client.add_guest(HOST, name).unwrap().id;
    let session = Arc::new(crate::conn::GuestSession::new(None));
    let plan = ConnectionPlan::guest(Arc::new(GuestSignIn::resuming(
        name.parse().unwrap(),
        session.clone(),
    )));
    client
        .connect_with(account, plan, Some(session), config())
        .await
        .unwrap();
    Device { client, account }
}

/// Joins `#general`, once the device's connections are up.
async fn join_when_connected(d: &Device) -> ConversationId {
    for _ in 0..100 {
        let joined = tokio::time::timeout(
            Duration::from_secs(60),
            d.client.join_public_room(d.account, "#general"),
        )
        .await
        .expect("in time");
        match joined {
            Ok(c) => return c,
            Err(e) if e.to_string().contains("not a public room") => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("{e}"),
        }
    }
    panic!("never connected");
}

/// Waits until `f` holds, checking every 50 ms, for at most 30 seconds.
async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..600 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out: {what}");
}

/// Waits until a device holds KeyPackages on the server (12.5).
async fn uploaded(d: &Device) {
    for _ in 0..600 {
        let n = d.client.store().read(|conn| {
            Ok(
                conn.query_row("SELECT count(*) FROM key_packages", [], |r| {
                    r.get::<_, i64>(0)
                })?,
            )
        });
        if n.is_ok_and(|n| n >= 11) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no KeyPackages uploaded");
}

fn texts(d: &Device, conv: ConversationId) -> Vec<String> {
    d.client
        .messages(conv, None, 50)
        .unwrap()
        .into_iter()
        .filter_map(|m| m.text)
        .collect()
}

/// How many leaves a conversation has: the devices of its members.
fn leaves(d: &Device, conv: ConversationId) -> usize {
    d.client
        .members(conv)
        .unwrap()
        .iter()
        .map(|m| m.devices)
        .sum()
}

fn find(d: &Device, f: impl Fn(&ConversationSummary) -> bool) -> Option<ConversationId> {
    d.client
        .conversations(d.account)
        .unwrap()
        .into_iter()
        .find(|c| f(c))
        .map(|c| c.id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_conversation_and_a_private_room_with_two_devices_against_risalad() {
    let server = server().await;
    let alice_id = server.identity("alice@example.org");
    let phone_id = server.key_server().new_device(&alice_id);
    let bob_id = server.identity("bob@example.net");
    let laptop = device(&server, &alice_id).await;
    let phone = device(&server, &phone_id).await;
    let bob = device(&server, &bob_id).await;
    for d in [&laptop, &phone, &bob] {
        uploaded(d).await;
    }

    // A direct conversation: the laptop adds Bob's device and its own
    // phone, each by its own sealed Welcome (12.8).
    // The server may not hold Bob's KeyPackages yet: try again until it
    // does.
    let mut conv = None;
    for _ in 0..100 {
        match laptop
            .client
            .direct(laptop.account, "bob@example.net")
            .await
        {
            Ok(c) => {
                conv = Some(c);
                break;
            }
            Err(e) if e.to_string().contains("not-found") => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("{e}"),
        }
    }
    let conv = conv.expect("started");
    until("bob and the phone joined", || {
        find(&bob, |c| c.kind == ConversationKind::Direct).is_some()
            && find(&phone, |c| c.kind == ConversationKind::Direct).is_some()
    })
    .await;
    let b = find(&bob, |c| c.kind == ConversationKind::Direct).unwrap();
    let p = find(&phone, |c| c.kind == ConversationKind::Direct).unwrap();
    assert_eq!(
        bob.client.conversation(b).unwrap().name,
        "alice@example.org"
    );
    assert_eq!(bob.client.members(b).unwrap().len(), 2);
    assert_eq!(leaves(&bob, b), 3);

    laptop
        .client
        .send_text(conv, "hello from the laptop", None)
        .await
        .unwrap();
    until("bob and the phone read it", || {
        texts(&bob, b) == ["hello from the laptop"] && texts(&phone, p) == ["hello from the laptop"]
    })
    .await;
    phone
        .client
        .send_text(p, "and from the phone", None)
        .await
        .unwrap();
    until("bob and the laptop read it", || {
        texts(&bob, b).len() == 2 && texts(&laptop, conv).len() == 2
    })
    .await;
    bob.client.send_text(b, "hi both", None).await.unwrap();
    until("both devices read it", || {
        texts(&laptop, conv).len() == 3 && texts(&phone, p).len() == 3
    })
    .await;

    // A private room: created with the identity's other device, then Bob
    // invited (6.1).
    let room = tokio::time::timeout(
        Duration::from_secs(60),
        laptop
            .client
            .create_private_room(laptop.account, "planning"),
    )
    .await
    .expect("in time")
    .unwrap();
    laptop.client.invite(room, "bob@example.net").await.unwrap();
    until("bob and the phone are in the room", || {
        find(&bob, |c| c.kind == ConversationKind::PrivateRoom).is_some()
            && find(&phone, |c| c.kind == ConversationKind::PrivateRoom).is_some()
    })
    .await;
    let br = find(&bob, |c| c.kind == ConversationKind::PrivateRoom).unwrap();
    let pr = find(&phone, |c| c.kind == ConversationKind::PrivateRoom).unwrap();
    assert_eq!(bob.client.conversation(br).unwrap().name, "planning");
    until("bob sees three leaves", || leaves(&bob, br) == 3).await;
    bob.client
        .send_text(br, "room message", None)
        .await
        .unwrap();
    until("both devices read it", || {
        texts(&laptop, room) == ["room message"] && texts(&phone, pr) == ["room message"]
    })
    .await;

    for d in [&laptop, &phone, &bob] {
        d.client.disconnect(d.account).await.unwrap();
    }
    server.server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_public_room_joined_by_proposal_against_risalad() {
    let server = server().await;
    let alice_id = server.identity("alice@example.org");
    let phone_id = server.key_server().new_device(&alice_id);
    let bob_id = server.identity("bob@example.net");
    let alice = device(&server, &alice_id).await;
    let bob = device(&server, &bob_id).await;

    // Created on the signed-in connection, with its group in epoch 0
    // (5.2, 12.6); LIST shows it.
    let a = tokio::time::timeout(
        Duration::from_secs(30),
        alice.client.create_public_room(alice.account, "#general"),
    )
    .await
    .expect("in time")
    .unwrap();
    let rooms = bob
        .client
        .list_public_rooms(bob.account, None)
        .await
        .unwrap();
    assert_eq!(rooms.len(), 1);
    assert_eq!(rooms[0].room.as_str(), "#general");
    assert_eq!(rooms[0].members, 1);

    // Bob joins by proposal: Alice's full client commits it on its
    // signed-in connection, puts the Welcome, and Bob fetches it with the
    // tree of its epoch (6.1, 12.8).
    let b = tokio::time::timeout(
        Duration::from_secs(60),
        bob.client.join_public_room(bob.account, "#general"),
    )
    .await
    .expect("in time")
    .unwrap();
    assert_eq!(
        bob.client.conversation(b).unwrap().kind,
        ConversationKind::PublicRoom
    );
    until("both see two leaves", || {
        leaves(&alice, a) == 2 && leaves(&bob, b) == 2
    })
    .await;

    // An identity's messages in a public room show once its ATTEST pins
    // its pseudonym for the period (7.3, 12.10), which needs key files the
    // devices accept; this test key server's records are not logged, so
    // the room's text is tested with a guest's, which pins by its first
    // message, and identities' on the in-memory server.

    // A guest joins from its guest connection, and its first message of the
    // period pins its pseudonym (7.3).
    let sam = guest(&server, "sam").await;
    let s = join_when_connected(&sam).await;
    sam.client
        .send_text(s, "hello from a guest", None)
        .await
        .unwrap();
    until("alice and bob read the guest", || {
        texts(&alice, a).contains(&"hello from a guest".to_string())
            && texts(&bob, b).contains(&"hello from a guest".to_string())
    })
    .await;

    // Alice's phone joins by itself, as every device does (12.7).
    let phone = device(&server, &phone_id).await;
    let p = join_when_connected(&phone).await;
    until("alice's devices see four leaves", || {
        leaves(&alice, a) == 4 && leaves(&phone, p) == 4
    })
    .await;
    let rooms = bob
        .client
        .list_public_rooms(bob.account, None)
        .await
        .unwrap();
    // 6.1: LIST counts identities and guests with a leaf, not devices.
    assert_eq!(rooms[0].members, 3, "alice, bob and the guest");

    for d in [&alice, &bob, &sam, &phone] {
        d.client.disconnect(d.account).await.unwrap();
    }
    server.server.stop().await;
}
