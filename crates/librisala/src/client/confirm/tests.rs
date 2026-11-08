//! Leaf confirmation between real clients (12.7, 12.10): each runs the
//! driver over TLS to the group engine's in-memory server
//! ([`crate::sync::conversations::tests::server`]), which stands in for
//! `risalad` until its mailbox and Welcome areas land, on a clock the test
//! moves.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use risala_mls::confirm::AttestationKey;
use risala_proto::command::{Command, Request};
use risala_proto::names::Identity;
use risala_proto::server::{OkResponse, ServerLine, ServerMessage};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::super::*;
use crate::clock::ManualClock;
use crate::conn::tests::server::TestCa;
use crate::conn::{ConnectionPlan, End, IdentitySignIn, Slot, roots_ca_verifier};
use crate::keys::{KeyStore, MemoryKeyStore, generate_device_key, key_seed};
use crate::store::conversations::ConversationId;
use crate::sync::conversations::Config;
use crate::sync::conversations::tests::server::FakeServer;

const MIN: u64 = 60_000;
const HOUR: u64 = 60 * MIN;
const DAY: u64 = 24 * HOUR;

/// 2026-11-09 (period 20766) at 10:00 UTC.
const MORNING: u64 = 20766 * DAY + 10 * HOUR;

struct Shared {
    server: FakeServer,
    outbound: HashMap<(usize, Slot), mpsc::UnboundedSender<String>>,
    devices: HashMap<String, Vec<u8>>,
}

#[derive(Debug)]
struct Fixed(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn render(message: ServerMessage) -> String {
    message.to_line().to_string()
}

async fn serve(ca: &TestCa, shared: Arc<Mutex<Shared>>) -> std::net::SocketAddr {
    let cert = ca.issue("chat.test");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let key = Arc::new(rustls::sign::CertifiedKey::new(cert.chain, cert.key));
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(key)));
    config.alpn_protocols = vec![risala_proto::ALPN.to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut n = 0;
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            n += 1;
            let (acceptor, shared) = (acceptor.clone(), shared.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                connection(n, tls, shared).await;
            });
        }
    });
    addr
}

async fn connection(
    n: usize,
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    shared: Arc<Mutex<Shared>>,
) {
    let (read, mut write) = tokio::io::split(tls);
    let mut lines = BufReader::new(read).lines();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if write
                .write_all(format!("{line}\n").as_bytes())
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let _ = tx.send("RISALA 1 chat.test 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e hi".into());
    let mut conn = (n, Slot::Anonymous(0));
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(request) = line.parse::<Request>() else {
            continue;
        };
        let ref_ = request.ref_.clone();
        let reply = |end: ServerLine| {
            render(ServerMessage {
                ref_: ref_.clone(),
                line: end,
            })
        };
        let mut s = shared.lock().unwrap();
        match request.command {
            Command::Anon => {
                s.outbound.insert(conn, tx.clone());
                let _ = tx.send(reply(ServerLine::Ok(OkResponse::new())));
            }
            Command::Auth { identity, .. } => {
                conn = (n, Slot::SignedIn);
                let device = s.devices[identity.to_uid().as_str()].clone();
                s.server
                    .signed_in
                    .insert(conn, (identity.to_uid().to_string(), device));
                s.outbound.insert(conn, tx.clone());
                let _ = tx.send(reply(ServerLine::Ok(OkResponse::new())));
            }
            Command::Ping { .. } | Command::Pong { .. } | Command::Quit { .. } => {}
            command => {
                let (response, live) = s.server.handle(conn, command);
                for (to, message) in live {
                    if let Some(out) = s.outbound.get(&to) {
                        let _ = out.send(render(message));
                    }
                }
                for mut message in response.lines {
                    message.ref_ = ref_.clone();
                    let _ = tx.send(render(message));
                }
                let end = match response.end {
                    End::Ok(ok) => ServerLine::Ok(ok),
                    End::Err(e) => ServerLine::Err(e),
                    End::Unparseable(_) => unreachable!(),
                };
                let _ = tx.send(reply(end));
            }
        }
    }
    shared.lock().unwrap().server.close(conn);
}

/// A device of an identity, with its keys' public halves.
struct Person {
    uid: String,
    client: Client,
    account: crate::store::AccountId,
    device_id: [u8; 48],
    device_key: Vec<u8>,
    attestation_key: Vec<u8>,
}

/// The server, the CA and the clock every client shares.
struct World {
    ca: TestCa,
    shared: Arc<Mutex<Shared>>,
    addr: std::net::SocketAddr,
    clock: ManualClock,
}

impl World {
    async fn new(start: u64) -> World {
        let ca = TestCa::new();
        let shared = Arc::new(Mutex::new(Shared {
            server: FakeServer::new(start),
            outbound: HashMap::new(),
            devices: HashMap::new(),
        }));
        let addr = serve(&ca, shared.clone()).await;
        World {
            ca,
            shared,
            addr,
            clock: ManualClock::new(start),
        }
    }

    /// Moves every clock on, the server's too.
    fn advance(&self, ms: u64) {
        self.clock.advance(ms);
        self.shared.lock().unwrap().server.now += ms;
    }

    /// A client of `uid`, with its device key and attestation key in its
    /// key store as the identity area keeps them.
    async fn person(&self, uid: &str) -> Person {
        let keys = Arc::new(MemoryKeyStore::default());
        let key = generate_device_key().unwrap();
        keys.save(uid, &key).unwrap();
        let attest = generate_device_key().unwrap();
        keys.save(&format!("{uid}.attest"), &attest).unwrap();
        let signing = risala_mls::mldsa::SigningKey::from_seed(*key_seed(&key));
        let device = risala_mls::identity::DeviceId::of_device_key(signing.public_key());
        let attestation_key = AttestationKey::from_seed(key_seed(&attest))
            .public_key()
            .to_vec();
        self.shared
            .lock()
            .unwrap()
            .devices
            .insert(uid.to_owned(), device.0.to_vec());
        let options = ClientOptions {
            keys,
            ca_verifier: Some(roots_ca_verifier([self.ca.cert.clone()]).unwrap()),
            session: crate::conn::SessionOptions {
                connect_to: Some(self.addr),
                ..Default::default()
            },
            clock: Arc::new(self.clock.clone()),
            ..ClientOptions::default()
        };
        let client = Client::open_in_memory(options).unwrap();
        let account = client.add_identity_account("chat.test", uid).unwrap().id;
        client
            .store()
            .write(|tx| {
                tx.conn().execute(
                    "INSERT INTO identities (uid, device_id, key_id, created) VALUES (?1, ?2, ?3, 0)",
                    rusqlite::params![uid, &device.0[..], uid],
                )?;
                Ok(())
            })
            .unwrap();
        let identity: Identity = uid.parse().unwrap();
        let plan = ConnectionPlan::identity(Arc::new(IdentitySignIn::new(identity, key)), 1);
        let config = Config {
            self_conversation: false,
            ..Config::immediate()
        };
        client
            .connect_with(account, plan, None, config)
            .await
            .unwrap();
        Person {
            uid: uid.to_owned(),
            client,
            account,
            device_id: device.0,
            device_key: signing.public_key().to_vec(),
            attestation_key,
        }
    }

    /// Waits until every person has its KeyPackages on the server (12.5).
    async fn key_packages(&self, people: &[&Person]) {
        until(|| {
            let s = self.shared.lock().unwrap();
            people.iter().all(|p| {
                s.server
                    .key_package_count(&p.uid, &s.devices[p.uid.as_str()])
                    == 11
            })
        })
        .await;
    }

    /// Moves the clock on by `step` until `f` holds, letting the clients
    /// settle after each step, at most `steps` times.
    async fn advance_until(
        &self,
        people: &[&Person],
        step: u64,
        steps: usize,
        mut f: impl FnMut() -> bool,
    ) {
        for _ in 0..steps {
            self.settle(people).await;
            if f() {
                return;
            }
            self.advance(step);
        }
        self.settle(people).await;
        assert!(f(), "not reached after {steps} steps");
    }

    /// Waits until the clients have nothing to do at the clock's time:
    /// nothing in their outboxes, and no Confirmer due, twice in a row a
    /// tick apart, for at most 30 seconds.
    async fn settle(&self, people: &[&Person]) {
        let now = self.clock.now().unix_millis();
        let idle = |p: &Person| {
            p.client
                .store()
                .read(|conn| {
                    let busy: i64 = conn.query_row(
                        "SELECT (SELECT count(*) FROM outbox
                                 WHERE state IN ('queued', 'sent', 'posted')
                                   AND conv IN (SELECT id FROM conversations
                                                WHERE state IN ('creating', 'active')))
                              + (SELECT count(*) FROM confirmers WHERE wake <= ?1)",
                        [now as i64],
                        |r| r.get(0),
                    )?;
                    Ok(busy == 0)
                })
                .unwrap()
        };
        let mut quiet = 0;
        for _ in 0..25 {
            tokio::time::sleep(Duration::from_millis(1_200)).await;
            if people.iter().all(|p| idle(p)) {
                quiet += 1;
                if quiet == 2 {
                    return;
                }
            } else {
                quiet = 0;
            }
        }
    }
}

/// Tells `p`'s cache of another device, as the identity area does once it
/// has accepted its record (4.4, 4.5): the columns of the identity area's
/// sketch, or of its own table.
fn add_device(p: &Person, uid: &str, device_id: &[u8], device_key: &[u8], attestation_key: &[u8]) {
    p.client
        .store()
        .write(|tx| {
            let sketch = tx.conn().execute(
                "INSERT INTO devices (uid, device_id, device_key, attestation_key, label, added_by)
                 VALUES (?1, ?2, ?3, ?4, 'test', x'00')",
                rusqlite::params![uid, device_id, device_key, attestation_key],
            );
            if sketch.is_err() {
                tx.conn().execute(
                    "INSERT INTO devices
                         (uid, device_id, device_key, attestation_key, label, added, state)
                     VALUES (?1, ?2, ?3, ?4, 'test', 0, 'current')",
                    rusqlite::params![uid, device_id, device_key, attestation_key],
                )?;
            }
            Ok(())
        })
        .unwrap();
}

/// Every person learns every other's device.
fn introduce(people: &[&Person]) {
    for p in people {
        for q in people {
            if p.uid != q.uid {
                add_device(p, &q.uid, &q.device_id, &q.device_key, &q.attestation_key);
            }
        }
    }
}

/// Waits until `f` holds, checking every 50 ms, for at most 30 seconds.
async fn until(mut f: impl FnMut() -> bool) {
    for _ in 0..600 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out");
}

/// The conversation `p` is in, once it has one.
async fn only_conversation(p: &Person) -> ConversationId {
    until(|| !p.client.conversations(p.account).unwrap().is_empty()).await;
    p.client.conversations(p.account).unwrap()[0].id
}

/// Whether `p` has confirmed `uid`'s leaf in `conv`.
fn confirmed(p: &Person, conv: ConversationId, uid: &str) -> bool {
    p.client
        .leaf_status(conv)
        .unwrap()
        .iter()
        .any(|l| l.uid.as_str() == uid && l.confirmed)
}

/// Whether every message `p` received in `conv` shows as verified.
fn all_verified(p: &Person, conv: ConversationId) -> bool {
    p.client
        .messages(conv, None, 100)
        .unwrap()
        .iter()
        .filter(|m| !m.own)
        .all(|m| m.verified)
}

fn received(p: &Person, conv: ConversationId) -> usize {
    p.client
        .messages(conv, None, 100)
        .unwrap()
        .iter()
        .filter(|m| !m.own)
        .count()
}

async fn stop(people: &[&Person]) {
    for p in people {
        p.client.disconnect(p.account).await.unwrap();
    }
}

/// Two devices confirm each other's leaves pairwise (12.10): each
/// challenges the other once it has shown something, the challenge rides
/// in its next message, and an answer that rides in none goes on its own
/// within 10 minutes. Once confirmed, earlier messages show as verified.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_clients_confirm_each_other() {
    let w = World::new(MORNING).await;
    let alice = w.person("alice@example.org").await;
    let bob = w.person("bob@example.net").await;
    introduce(&[&alice, &bob]);
    w.key_packages(&[&alice, &bob]).await;

    let conv = tokio::time::timeout(
        Duration::from_secs(30),
        alice.client.direct(alice.account, "bob@example.net"),
    )
    .await
    .expect("in time")
    .unwrap();
    let bconv = only_conversation(&bob).await;
    // Nobody has sent: nobody is challenged (12.10).
    assert!(!confirmed(&alice, conv, "bob@example.net"));
    assert!(!confirmed(&bob, bconv, "alice@example.org"));

    alice.client.send_text(conv, "hello", None).await.unwrap();
    until(|| received(&bob, bconv) == 1).await;
    assert!(!all_verified(&bob, bconv), "unverified until confirmed");

    // Bob's reply carries his CHALLENGE to Alice; hers carries her ANSWER.
    bob.client.send_text(bconv, "hi", None).await.unwrap();
    until(|| received(&alice, conv) == 1).await;
    alice
        .client
        .send_text(conv, "how are you", None)
        .await
        .unwrap();
    until(|| received(&bob, bconv) == 2).await;
    until(|| confirmed(&bob, bconv, "alice@example.org") && all_verified(&bob, bconv)).await;

    // Alice challenged Bob in her message too. Bob sends nothing more, so
    // his ANSWER goes on its own within 10 minutes.
    assert!(!confirmed(&alice, conv, "bob@example.net"));
    w.advance_until(&[&alice, &bob], 2 * MIN, 10, || {
        confirmed(&alice, conv, "bob@example.net") && all_verified(&alice, conv)
    })
    .await;
    assert!(alice.client.confirm_warnings(conv).unwrap().is_empty());
    assert!(bob.client.confirm_warnings(bconv).unwrap().is_empty());
    stop(&[&alice, &bob]).await;
}

/// Three devices in a private room: a leaf that makes an authority commit
/// is challenged at once and answers within a minute (12.7), and every
/// member that sends is confirmed by every other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_clients_confirm_each_other() {
    let w = World::new(MORNING).await;
    let alice = w.person("alice@example.org").await;
    let bob = w.person("bob@example.net").await;
    let carol = w.person("carol@example.com").await;
    introduce(&[&alice, &bob, &carol]);
    w.key_packages(&[&alice, &bob, &carol]).await;

    let room = alice
        .client
        .create_private_room(alice.account, "plans")
        .await
        .unwrap();
    for uid in ["bob@example.net", "carol@example.com"] {
        tokio::time::timeout(Duration::from_secs(30), alice.client.invite(room, uid))
            .await
            .expect("in time")
            .unwrap();
    }
    let broom = only_conversation(&bob).await;
    let croom = only_conversation(&carol).await;
    until(|| {
        bob.client.leaf_status(broom).unwrap().len() == 3
            && carol.client.leaf_status(croom).unwrap().len() == 3
    })
    .await;

    // A topic needs a role: Bob and Carol challenge Alice within a minute,
    // and she answers within a minute.
    alice.client.set_topic(room, "lunch").await.unwrap();
    until(|| {
        bob.client.conversation(broom).unwrap().topic.as_deref() == Some("lunch")
            && carol.client.conversation(croom).unwrap().topic.as_deref() == Some("lunch")
    })
    .await;
    w.advance_until(&[&alice, &bob, &carol], MIN + 1_000, 10, || {
        confirmed(&bob, broom, "alice@example.org") && confirmed(&carol, croom, "alice@example.org")
    })
    .await;

    // Everyone sends; everyone confirms everyone.
    bob.client.send_text(broom, "from bob", None).await.unwrap();
    carol
        .client
        .send_text(croom, "from carol", None)
        .await
        .unwrap();
    until(|| received(&alice, room) == 2).await;
    w.advance_until(&[&alice, &bob, &carol], 2 * MIN, 20, || {
        let all = [
            (&alice, room, ["bob@example.net", "carol@example.com"]),
            (&bob, broom, ["alice@example.org", "carol@example.com"]),
            (&carol, croom, ["alice@example.org", "bob@example.net"]),
        ];
        all.iter().all(|(p, c, others)| {
            // Alice sent no TEXT: the others confirmed her for her commit.
            others.iter().all(|o| confirmed(p, *c, o)) && all_verified(p, *c)
        })
    })
    .await;
    for (p, c) in [(&alice, room), (&bob, broom), (&carol, croom)] {
        assert!(p.client.confirm_warnings(c).unwrap().is_empty());
    }
    stop(&[&alice, &bob, &carol]).await;
}

/// A leaf whose device does not hold the attestation key its key file
/// names answers wrongly: it is an impostor (12.7). The device warns, and
/// after a random wait of up to 10 minutes removes the leaf for a check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_answer_makes_an_impostor_who_is_removed() {
    let w = World::new(MORNING).await;
    let alice = w.person("alice@example.org").await;
    let bob = w.person("bob@example.net").await;
    // Alice's view of Bob's device has an attestation key Bob does not
    // hold, as if someone had added a leaf in his name with a key of its
    // own.
    let other = AttestationKey::generate().unwrap();
    add_device(
        &alice,
        &bob.uid,
        &bob.device_id,
        &bob.device_key,
        other.public_key(),
    );
    add_device(
        &bob,
        &alice.uid,
        &alice.device_id,
        &alice.device_key,
        &alice.attestation_key,
    );
    w.key_packages(&[&alice, &bob]).await;

    let conv = tokio::time::timeout(
        Duration::from_secs(30),
        alice.client.direct(alice.account, "bob@example.net"),
    )
    .await
    .expect("in time")
    .unwrap();
    let bconv = only_conversation(&bob).await;
    bob.client.send_text(bconv, "it is me", None).await.unwrap();
    until(|| received(&alice, conv) == 1).await;

    let impostor = || {
        alice
            .client
            .leaf_status(conv)
            .unwrap()
            .iter()
            .any(|l| l.uid.as_str() == "bob@example.net" && l.impostor)
    };
    w.advance_until(&[&alice, &bob], 2 * MIN, 15, impostor)
        .await;
    assert!(!confirmed(&alice, conv, "bob@example.net"));
    assert!(!all_verified(&alice, conv));
    let warnings = alice.client.confirm_warnings(conv).unwrap();
    assert_eq!(warnings.len(), 1);
    assert_eq!(
        (warnings[0].kind.as_str(), warnings[0].detail.as_str()),
        ("impostor", "wrong-answer")
    );

    // Alice removes the leaf; Bob is out of the conversation.
    w.advance_until(&[&alice, &bob], 2 * MIN, 15, || {
        !bob.client.conversation(bconv).unwrap().active
            && !alice
                .client
                .leaf_status(conv)
                .unwrap()
                .iter()
                .any(|l| l.uid.as_str() == "bob@example.net")
    })
    .await;
    stop(&[&alice, &bob]).await;
}

/// 2026-11-09 (period 20766) at 20:00 UTC, four hours before it ends.
const EVENING: u64 = 20766 * DAY + 20 * HOUR;

/// A conversation's extension as `p` holds it (12.4).
fn extension(p: &Person, conv: ConversationId) -> risala_mls::RisalaConversation {
    use risala_mls::openmls_traits::OpenMlsProvider as _;
    let row = p.client.store().conversation_row(conv).unwrap().unwrap();
    let crypto = Arc::new(risala_mls::RisalaCrypto::new().unwrap());
    p.client
        .store()
        .read(|conn| {
            let provider = crate::store::mls::read_provider(conn, &crypto);
            let group = risala_mls::openmls::group::MlsGroup::load(
                provider.storage(),
                &risala_mls::openmls::prelude::GroupId::from_slice(&row.group_id),
            )
            .unwrap()
            .unwrap();
            Ok(risala_mls::group::conversation(&group).unwrap())
        })
        .unwrap()
}

/// An owner moves a private room to epochal confirmation (6.2), as one
/// does at 256 members.
async fn go_epochal(p: &Person, conv: ConversationId) {
    let mut ext = extension(p, conv);
    ext.confirm = risala_mls::conversation::ConfirmMode::Epochal;
    let intent = crate::sync::conversations::wire::Intent {
        conversation: Some(ext.encode()),
        ..Default::default()
    };
    let now = p.client.options().clock.now().unix_millis();
    p.client
        .store()
        .write_with(|tx| crate::sync::conversations::group::queue_intent(tx, conv, &intent, now))
        .unwrap();
    p.client.kick(p.account).await;
}

/// The signature key of `uid`'s leaf in `conv`, as `p` sees it.
fn leaf_key(p: &Person, conv: ConversationId, uid: &str) -> Vec<u8> {
    p.client
        .store()
        .leaf_rows(conv)
        .unwrap()
        .into_iter()
        .find(|l| l.uid.as_str() == uid)
        .unwrap()
        .signature_key
}

/// An epochal room across period boundaries (12.10): a leaf that used
/// authority attests within the hour; a member's first message of a period
/// carries its ATTEST; a confirmation lapses after its period's grace
/// hour; a device rotates its leaf before it sends in a new period; and
/// every period key that attested is revealed, so nobody is warned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_epochal_room_across_periods() {
    let w = World::new(EVENING).await;
    let alice = w.person("alice@example.org").await;
    let bob = w.person("bob@example.net").await;
    introduce(&[&alice, &bob]);
    w.key_packages(&[&alice, &bob]).await;
    let room = alice
        .client
        .create_private_room(alice.account, "big")
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(30),
        alice.client.invite(room, "bob@example.net"),
    )
    .await
    .expect("in time")
    .unwrap();
    let broom = only_conversation(&bob).await;
    until(|| bob.client.leaf_status(broom).unwrap().len() == 2).await;

    go_epochal(&alice, room).await;
    until(|| extension(&bob, broom).confirm == risala_mls::conversation::ConfirmMode::Epochal)
        .await;
    // Alice's commit used authority: she attests within the hour, in a
    // message of its own.
    w.advance_until(&[&alice, &bob], 2 * MIN, 10, || {
        confirmed(&bob, broom, "alice@example.org")
    })
    .await;

    // Bob's first message carries his ATTEST.
    bob.client.send_text(broom, "evening", None).await.unwrap();
    until(|| received(&alice, room) == 1).await;
    until(|| confirmed(&alice, room, "bob@example.net") && all_verified(&alice, room)).await;

    // 02:00 the next day: the grace hour of the period before is over, so
    // its attestations confirm nothing more.
    w.advance(6 * HOUR);
    until(|| !confirmed(&alice, room, "bob@example.net")).await;
    until(|| !confirmed(&bob, broom, "alice@example.org")).await;

    // Alice sends: she first rotates her leaf, then her message carries
    // the new period's ATTEST.
    let old = leaf_key(&bob, broom, "alice@example.org");
    alice.client.send_text(room, "morning", None).await.unwrap();
    until(|| received(&bob, broom) == 1).await;
    until(|| confirmed(&bob, broom, "alice@example.org") && all_verified(&bob, broom)).await;
    assert_ne!(leaf_key(&bob, broom, "alice@example.org"), old);

    // Two and a half days on: every period key that attested was
    // revealed within a day of 3 hours after its period, and every ATTEST
    // was valid, so nobody is warned (a missing REVEAL is warned about 2
    // days after it was due).
    for _ in 0..30 {
        w.advance(2 * HOUR);
        w.settle(&[&alice, &bob]).await;
    }
    assert_eq!(alice.client.confirm_warnings(room).unwrap(), vec![]);
    assert_eq!(bob.client.confirm_warnings(broom).unwrap(), vec![]);
    // The REVEALs did arrive: each device holds the other's attestations
    // as revealed.
    for (p, conv) in [(&alice, room), (&bob, broom)] {
        let state: String = p
            .client
            .store()
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT CAST(state AS TEXT) FROM confirmers WHERE conv = ?1",
                    [conv.get()],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert!(state.contains("\"revealed\":true"), "{}", p.uid);
    }
    stop(&[&alice, &bob]).await;
}
