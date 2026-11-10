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
        // Blobs stored with PUT on the same listener (12.12).
        file_https: Some(Arc::new(
            crate::client::files::TlsFileHttps::new(
                crate::conn::roots_ca_verifier([server.ca.clone()]).unwrap(),
            )
            .connect_to([(HOST.to_owned(), server.https)]),
        )),
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
        // A join looks again soon when its Welcome is not there yet, as
        // when a Welcome in a blob is still being stored (12.12).
        join_poll_ms: 5_000,
        ..Config::immediate()
    }
}

/// A device of `who`, signed in with its device key, which its key store
/// holds under the `key_id` of an `identities` row.
async fn device(server: &World, who: &TestIdentity) -> Device {
    device_knowing(server, who, &[]).await
}

/// Takes the devices of `known` as current in a client's cache, as if
/// their records were witnessed and accepted (4.5), and not due for a
/// fetch: the test key server logs nothing, and a device adds only devices
/// whose records it has accepted (12.5, 12.7; wired by task C5).
fn accept(client: &Client, known: &[&TestIdentity]) {
    use crate::store::identity::{ContactRow, DeviceRow, DeviceState, KeysState};
    let now = crate::clock::Clock::now(&crate::clock::SystemClock).unix_millis();
    client
        .store()
        .write(|tx| {
            for who in known {
                let uid = who.uid().to_string();
                let mut c = tx.contact(&uid)?.unwrap_or_else(|| ContactRow::new(&uid));
                c.keys = KeysState::Keys;
                c.fetched = Some(now);
                c.refreshed = Some(now);
                c.next_check = Some(now + 365 * 24 * 3600 * 1000);
                c.pending = 0;
                tx.put_contact(&c)?;
                let key = who.public_key();
                tx.put_devices(
                    &uid,
                    &[DeviceRow {
                        device_id: *risala_proto::record::DeviceId::of(&key).as_bytes(),
                        device_key: key.as_bytes().to_vec(),
                        attestation_key: Vec::new(),
                        label: "test".into(),
                        added: 0,
                        state: DeviceState::Current,
                    }],
                )?;
            }
            Ok(())
        })
        .unwrap();
}

/// [`device`], knowing the devices of `known` as accepted ([`accept`]).
async fn device_knowing(server: &World, who: &TestIdentity, known: &[&TestIdentity]) -> Device {
    device_knowing_with(server, who, known, config()).await
}

/// [`device_knowing`], with the group engine's `config`.
async fn device_knowing_with(
    server: &World,
    who: &TestIdentity,
    known: &[&TestIdentity],
    config: Config,
) -> Device {
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
    accept(&client, known);
    let d = Device { client, account };
    connect_with(&d, who, config).await;
    d
}

/// Signs a device of `who` in, again after [`Client::disconnect`].
async fn connect(d: &Device, who: &TestIdentity) {
    connect_with(d, who, config()).await;
}

/// [`connect`], with the group engine's `config`.
async fn connect_with(d: &Device, who: &TestIdentity, config: Config) {
    let identity: Identity = who.uid().to_string().parse().unwrap();
    let plan = ConnectionPlan::identity(
        Arc::new(IdentitySignIn::new(identity, who.key().clone())),
        1,
    );
    d.client
        .connect_with(d.account, plan, None, config)
        .await
        .unwrap();
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
    let all = [&alice_id, &phone_id, &bob_id];
    let laptop = device_knowing(&server, &alice_id, &all).await;
    let phone = device_knowing(&server, &phone_id, &all).await;
    let bob = device_knowing(&server, &bob_id, &all).await;
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

/// Device `d`'s conversation in the group of `other`'s `conv`, if it has
/// one, with its state.
fn same(
    d: &Device,
    other: &Device,
    conv: ConversationId,
) -> Option<crate::store::conversations::ConvRow> {
    let group = other
        .client
        .store()
        .conversation_row(conv)
        .unwrap()
        .unwrap()
        .group_id;
    d.client
        .store()
        .conversation_rows(d.account)
        .unwrap()
        .into_iter()
        .find(|r| r.group_id == group)
}

/// Whether device `d` is in the group of `other`'s `conv`.
fn in_group(d: &Device, other: &Device, conv: ConversationId) -> bool {
    same(d, other, conv).is_some_and(|r| r.state.in_group())
}

/// 6.1, 12.7: an identity of two devices leaves a direct conversation and
/// a private room. While the leaving device waits for its SelfRemove to be
/// committed in the room, its upkeep does not add its other device back;
/// once Bob's device has committed it, Bob's upkeep does not add Alice's
/// devices back. In the direct conversation nobody commits the SelfRemove:
/// both sides leave it, and Bob's shows it as left by Alice (5.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_identity_that_leaves_stays_out_against_risalad() {
    use crate::store::conversations::ConvState;

    let server = server().await;
    let alice_id = server.identity("alice@example.org");
    let phone_id = server.key_server().new_device(&alice_id);
    let bob_id = server.identity("bob@example.net");
    let all = [&alice_id, &phone_id, &bob_id];
    let laptop = device_knowing(&server, &alice_id, &all).await;
    let phone = device_knowing(&server, &phone_id, &all).await;
    let bob = device_knowing(&server, &bob_id, &all).await;
    for d in [&laptop, &phone, &bob] {
        uploaded(d).await;
    }
    let mut direct = None;
    for _ in 0..100 {
        match laptop
            .client
            .direct(laptop.account, "bob@example.net")
            .await
        {
            Ok(c) => {
                direct = Some(c);
                break;
            }
            Err(e) if e.to_string().contains("not-found") => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("{e}"),
        }
    }
    let direct = direct.expect("started");
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
    until("everyone is in both", || {
        [direct, room].iter().all(|c| {
            in_group(&phone, &laptop, *c)
                && same(&bob, &laptop, *c).is_some_and(|r| leaves(&bob, r.id) == 3)
        })
    })
    .await;
    let b = same(&bob, &laptop, direct).unwrap().id;
    let br = same(&bob, &laptop, room).unwrap().id;
    // Bob commits in both, so that the laptop's next commits are not held
    // by the streak limit (12.7).
    let epoch = |c| {
        laptop
            .client
            .store()
            .conversation_row(c)
            .unwrap()
            .unwrap()
            .epoch
    };
    let before = (epoch(direct), epoch(room));
    bob.client
        .set_display_name(bob.account, "Bob")
        .await
        .unwrap();
    until("the laptop applied bob's commits", || {
        epoch(direct) > before.0 && epoch(room) > before.1
    })
    .await;

    // Bob is away, so nobody commits the room's SelfRemove yet: the
    // laptop's commits remove the phone, and the laptop waits, leaving the
    // room. In the direct conversation nobody commits it at all: the
    // laptop forgets the group once it has posted it (6.1).
    bob.client.disconnect(bob.account).await.unwrap();
    laptop.client.leave(direct).await.unwrap();
    laptop.client.leave(room).await.unwrap();
    let leaving = |c| {
        laptop
            .client
            .store()
            .conversation_row(c)
            .unwrap()
            .unwrap()
            .state
            == ConvState::Leaving
    };
    until("the phone is out of both, and the laptop leaving", || {
        !in_group(&phone, &laptop, direct)
            && !in_group(&phone, &laptop, room)
            && !in_group(&laptop, &laptop, direct)
            && leaving(room)
    })
    .await;
    // The upkeep stands down while a commit of the device is pending:
    // run it once none is, so that it acts on the conversation it leaves.
    let committing_on = |d: &Device, c| {
        d.client
            .store()
            .write(|tx| tx.pending_outbox(c))
            .unwrap()
            .0
            .iter()
            .any(|o| o.kind == crate::store::messages::OutboxKind::Commit)
    };
    let committing = |c| committing_on(&laptop, c);
    until("the laptop has no commit pending", || !committing(room)).await;
    for _ in 0..3 {
        laptop.client.maintain(laptop.account).await.unwrap();
        phone.client.maintain(phone.account).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!in_group(&phone, &laptop, direct), "the phone came back");
    assert!(!in_group(&phone, &laptop, room), "the phone came back");
    assert!(!in_group(&laptop, &laptop, direct) && leaving(room));
    // Nor did it queue a commit to add it: made after its SelfRemove, MLS
    // refuses it, and it would hold the SelfRemove back for good. And 7.8:
    // a leaving device makes no move; the move follows the commit of its
    // SelfRemove, by another member.
    for c in [direct, room] {
        assert!(!committing(c), "a leaving device queued a commit");
    }

    // Bob's device comes back: it commits the room's SelfRemove, and
    // leaves the direct conversation by itself, as Alice did. Alice has
    // left both, and stays out.
    connect(&bob, &bob_id).await;
    let bob_in = |c| {
        bob.client
            .store()
            .conversation_row(c)
            .unwrap()
            .unwrap()
            .state
            .in_group()
    };
    until(
        "bob committed the room's SelfRemove, and left the other",
        || !bob_in(b) && leaves(&bob, br) == 1 && !in_group(&laptop, &laptop, room),
    )
    .await;
    // Bob's device moves the room (7.8); its upkeep then runs.
    until("bob has no commit pending", || {
        !committing_on(&bob, b) && !committing_on(&bob, br)
    })
    .await;
    for _ in 0..3 {
        bob.client.maintain(bob.account).await.unwrap();
        laptop.client.maintain(laptop.account).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!bob_in(b), "bob's side came back");
    assert_eq!(leaves(&bob, br), 1, "alice's devices were added back");
    // 5.1, 6.1: Bob's side of the direct conversation left it too, and
    // shows it as left by Alice; the room, which Bob is still in, stays.
    let summary = bob.client.conversation(b).unwrap();
    assert!(!summary.active && summary.left_by_peer, "{summary:?}");
    let summary = bob.client.conversation(br).unwrap();
    assert!(summary.active && !summary.left_by_peer, "{summary:?}");
    for c in [direct, room] {
        assert!(!in_group(&laptop, &laptop, c));
        assert!(!in_group(&phone, &laptop, c));
    }

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

/// `n` uids of 227 bytes each, to ban: enough of them make the extension
/// nearly as long as it may be, 512 KiB (12.4).
fn long_uids(n: usize) -> Vec<risala_proto::names::Uid> {
    let domain = format!(
        "{}.{}.{}.example.org",
        "b".repeat(60),
        "c".repeat(60),
        "d".repeat(60)
    );
    (0..n)
        .map(|i| {
            format!("u{i:05}{}@{domain}", "a".repeat(26))
                .parse()
                .unwrap()
        })
        .collect()
}

/// How many bans `d` holds in `conv`'s extension (12.4).
fn bans(d: &Device, conv: ConversationId) -> usize {
    let row = d.client.store().conversation_row(conv).unwrap().unwrap();
    d.client.extension(&row).unwrap().bans.len()
}

/// Commits a ban of `uids` in `conv` by device `d`, an owner, and checks
/// that the extension is within 512 KiB (12.4), but that two of it are
/// too long for a line in base64 (2.3), as a public room's commit and its
/// GroupInfo are.
async fn ban_all(d: &Device, conv: ConversationId, uids: Vec<risala_proto::names::Uid>) {
    let row = d.client.store().conversation_row(conv).unwrap().unwrap();
    let mut ext = d.client.extension(&row).unwrap();
    ext.bans = uids;
    let encoded = ext.encode();
    assert!(encoded.len() <= risala_mls::conversation::MAX_EXTENSION_LEN);
    assert!(2 * encoded.len() / 3 * 4 > risala_proto::frame::MAX_LONG_CLIENT_LINE);
    d.client
        .commit(
            conv,
            crate::sync::conversations::wire::Intent {
                conversation: Some(encoded),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

/// How many bans make the extension nearly 512 KiB (12.4).
const BANS: usize = 2_250;

/// 12.12: in a private room, a commit too long for a line, here one that
/// bans thousands of identities, goes as a blob stored over the anonymous
/// connection, and so does a sealed Welcome that carries the room's
/// GroupInfo with them; the members apply the commit, and a device added
/// afterwards joins. The extension's 512 KiB (12.4) keeps a small room's
/// commit within the long-line limit of 2.3, so alice's limit is lowered
/// to 256 KiB; the server takes the blobs as it would larger ones.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_private_rooms_commit_and_welcome_past_the_line_limit_against_risalad() {
    let server = server().await;
    let alice_id = server.identity("alice@example.org");
    let bob_id = server.identity("bob@example.net");
    let carol_id = server.identity("carol@example.org");
    let all = [&alice_id, &bob_id, &carol_id];
    let lowered = Config {
        line_limit: 256 * 1024,
        ..config()
    };
    let alice = device_knowing_with(&server, &alice_id, &all, lowered).await;
    let bob = device_knowing(&server, &bob_id, &all).await;
    let carol = device_knowing(&server, &carol_id, &all).await;
    for d in [&alice, &bob, &carol] {
        uploaded(d).await;
    }
    let room = tokio::time::timeout(
        Duration::from_secs(60),
        alice.client.create_private_room(alice.account, "big"),
    )
    .await
    .expect("in time")
    .unwrap();
    alice.client.invite(room, "bob@example.net").await.unwrap();
    until("bob is in the room", || in_group(&bob, &alice, room)).await;
    let b = same(&bob, &alice, room).unwrap().id;

    ban_all(&alice, room, long_uids(BANS)).await;
    // Each device applies the commit as it comes back in order, Alice's
    // too, whenever its FETCH gets there.
    until("bob and alice applied the commit", || {
        bans(&bob, b) == BANS && bans(&alice, room) == BANS
    })
    .await;

    // Carol's Welcome carries the GroupInfo, and with it the bans.
    alice
        .client
        .invite(room, "carol@example.org")
        .await
        .unwrap();
    until("carol is in the room", || in_group(&carol, &alice, room)).await;
    let c = same(&carol, &alice, room).unwrap().id;
    assert_eq!(bans(&carol, c), BANS);
    carol.client.send_text(c, "made it", None).await.unwrap();
    until("alice and bob read carol", || {
        texts(&alice, room) == ["made it"] && texts(&bob, b) == ["made it"]
    })
    .await;

    for d in [&alice, &bob, &carol] {
        d.client.disconnect(d.account).await.unwrap();
    }
    server.server.stop().await;
}

/// 12.6, 12.12: in a public room, a commit and its GroupInfo too long for
/// a line together, past the real limit of 2.3, go as blobs, stored over
/// the anonymous connection and posted on the signed-in one, which the
/// server reads whole to check; a device that joins afterwards gets the
/// room's GroupInfo and its Welcome, with the bans.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_public_rooms_commit_and_groupinfo_past_the_line_limit_against_risalad() {
    let server = server().await;
    let alice_id = server.identity("alice@example.org");
    let bob_id = server.identity("bob@example.net");
    let carol_id = server.identity("carol@example.org");
    let alice = device(&server, &alice_id).await;
    let bob = device(&server, &bob_id).await;
    let a = tokio::time::timeout(
        Duration::from_secs(30),
        alice.client.create_public_room(alice.account, "#general"),
    )
    .await
    .expect("in time")
    .unwrap();
    let b = join_when_connected(&bob).await;
    until("both see two leaves", || {
        leaves(&alice, a) == 2 && leaves(&bob, b) == 2
    })
    .await;

    ban_all(&alice, a, long_uids(BANS)).await;
    until("bob applied the commit", || bans(&bob, b) == BANS).await;

    // Carol joins by proposal, from the room's GroupInfo, and her Welcome
    // carries the bans.
    let carol = device(&server, &carol_id).await;
    let c = join_when_connected(&carol).await;
    assert_eq!(bans(&carol, c), BANS);
    until("everyone sees three leaves", || {
        leaves(&alice, a) == 3 && leaves(&bob, b) == 3 && leaves(&carol, c) == 3
    })
    .await;

    for d in [&alice, &bob, &carol] {
        d.client.disconnect(d.account).await.unwrap();
    }
    server.server.stop().await;
}

/// `Client::unsettled` waits for the KeyPackages a device uploads when it
/// signs in (12.5): once it says none are left, another identity can start
/// a direct conversation with it at the first try.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settled_means_key_packages_are_on_the_server_against_risalad() {
    let server = server().await;
    let alice_id = server.identity("alice@example.org");
    let bob_id = server.identity("bob@example.net");
    let all = [&alice_id, &bob_id];
    let alice = device_knowing(&server, &alice_id, &all).await;
    let bob = device_knowing(&server, &bob_id, &all).await;
    until("bob's KeyPackages are uploaded", || {
        bob.client.is_settled(bob.account).unwrap()
    })
    .await;
    assert!(!bob.client.unsettled(bob.account).unwrap().key_packages);
    alice
        .client
        .direct(alice.account, "bob@example.net")
        .await
        .expect("bob's KeyPackages are on the server");
    // After disconnecting, nothing is known of them, and nothing waits.
    bob.client.disconnect(bob.account).await.unwrap();
    assert!(!bob.client.unsettled(bob.account).unwrap().key_packages);
}
