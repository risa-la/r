//! Transcript tests of identities (4.3-4.8, 6.1, 6.3, 7.1, 7.6), through
//! the [`Handler`] trait, with key files from a [`MemoryFetcher`] and
//! hosted key files published to a [`MemoryPublisher`].
//!
//! Keys are Appendix B's test key and keys made from fixed seeds, and
//! every signature is the deterministic variant, so the tests do not
//! depend on randomness.

use std::sync::Arc;
use std::time::Duration;

use risala_proto::auth::{Nonce, PublicKey, SecretKey};
use risala_proto::command::Request;
use risala_proto::error::ErrorCode;
use risala_proto::names::{Identity, Room, Seq, Uid};
use risala_proto::types::RoomSetting;

use super::tests::{Client, Harness, T, config, start, stored, timers, value};
use super::*;
use crate::config::RoomCreation;
use crate::store::SqliteStore;

/// The hostname clients connect to, as they send it in SNI.
const HOST: &str = "chat.example.org";

/// Appendix B's private key: the seed, in hex.
const APPENDIX_B_SEED: &str = "c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8";

/// Device keys: 0 is Appendix B's, the rest come from fixed seeds.
fn secret(n: u8) -> SecretKey {
    if n == 0 {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&APPENDIX_B_SEED[2 * i..2 * i + 2], 16).unwrap();
        }
        SecretKey::from_seed(seed)
    } else {
        SecretKey::from_seed([n; 32])
    }
}

fn public(n: u8) -> PublicKey {
    secret(n).public_key()
}

fn identity(s: &str) -> Identity {
    s.parse().unwrap()
}

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

/// A server whose identity domain is `example.org`, with registration
/// open, `op@example.net` as an operator, and the rooms `#general` and
/// `#private` (not public).
fn id_config() -> Config {
    let mut c = config();
    c.rooms = vec!["#general".into(), "#private".into()];
    c.identity_domain = Some("example.org".into());
    c.server.registration = true;
    c.operators = vec!["op@example.net".into()];
    c
}

/// A hub, its key file fetcher and its publisher.
struct World {
    h: Harness,
    fetcher: Arc<MemoryFetcher>,
    publisher: Arc<MemoryPublisher>,
}

impl World {
    fn new() -> World {
        World::with(id_config())
    }

    fn with(config: Config) -> World {
        let store = SqliteStore::open_in_memory().unwrap();
        for room in &config.rooms {
            store.ensure_room(&room.parse().unwrap(), start()).unwrap();
        }
        let private: Room = "#private".parse().unwrap();
        if let Some(r) = store.room(&private).unwrap() {
            store
                .append(
                    r.key,
                    &crate::store::NewEvent {
                        t: start(),
                        from: uid("op@example.net"),
                        kind: crate::store::EventKind::Set(RoomSetting::Public(false)),
                        cid: None,
                    },
                )
                .unwrap();
        }
        World::on(config, Arc::new(store))
    }

    fn on(config: Config, store: Arc<dyn Store>) -> World {
        let fetcher = Arc::new(MemoryFetcher::new());
        let publisher = Arc::new(MemoryPublisher::new());
        let clock = Arc::new(ManualClock::new(start()));
        let keys = KeyServices::shared(fetcher.clone(), publisher.clone());
        let hub = Hub::build(config, store.clone(), clock.clone(), timers(), keys).unwrap();
        World {
            h: Harness {
                hub,
                store,
                clock,
                next: 0,
            },
            fetcher,
            publisher,
        }
    }

    /// A new connection with SNI `sni`, and its greeting's nonce.
    fn dial(&mut self, sni: Option<&str>) -> (Client, Nonce) {
        let mut c = self.h.connect_sni(sni, 4096);
        let greeting = c.lines();
        let nonce = greeting[0].split(' ').nth(3).unwrap().parse().unwrap();
        (c, nonce)
    }

    /// A new connection, signed in as `who` with key `n`, whose key file
    /// the fetcher has (or which the server hosts).
    async fn sign_in(&mut self, who: &str, n: u8) -> Client {
        let (mut c, nonce) = self.dial(Some(HOST));
        self.send(&c, &auth(who, n, HOST, &nonce)).await;
        let ok = c.lines();
        assert_eq!(ok.len(), 1, "{ok:?}");
        assert!(ok[0].starts_with(&format!("OK uid={who}")), "{ok:?}");
        c
    }

    /// Registers `<name>@example.org` with key `n` on a new connection.
    async fn register(&mut self, name: &str, n: u8) -> Client {
        let (mut c, nonce) = self.dial(Some(HOST));
        self.send(&c, &register(name, n, HOST, &nonce)).await;
        assert_eq!(c.lines(), [format!("OK uid={name}@example.org")]);
        c
    }

    async fn send(&self, c: &Client, line: &str) {
        self.h.send(c, line).await;
    }
}

/// `AUTH <who> <signature>`, signed with key `n` for `host` and `nonce`.
fn auth(who: &str, n: u8, host: &str, nonce: &Nonce) -> String {
    let sig = secret(n).sign_challenge(host, nonce, who);
    format!("auth {who} {sig}")
}

/// `REGISTER <name> <key> <signature>` for `<name>@example.org`.
fn register(name: &str, n: u8, host: &str, nonce: &Nonce) -> String {
    let who = format!("{name}@example.org");
    let sig = secret(n).sign_challenge(host, nonce, &who);
    format!("register {name} {} {sig}", public(n))
}

/// The keys of a published key file.
fn published(w: &World, name: &str) -> Option<Vec<(PublicKey, Option<String>)>> {
    w.publisher.get(name).map(|keys| {
        keys.into_iter()
            .map(|e| (e.key().clone(), e.label().map(str::to_owned)))
            .collect()
    })
}

// ---------------------------------------------------------------------------
// AUTH (4.5)

#[tokio::test]
async fn auth_with_a_key_file() {
    let mut w = World::new();
    w.fetcher
        .set(&identity("bob@example.net"), vec![public(1), public(0)]);
    // Appendix B's key, listed second.
    let mut bob = w.sign_in("bob@example.net", 0).await;
    assert_eq!(w.fetcher.calls(), [(identity("bob@example.net"), false)]);
    // Signed in: commands that need it work, and signing in again does not.
    w.send(&bob, "sync").await;
    assert_eq!(bob.lines(), ["OK"]);
    w.send(&bob, "guest sam").await;
    assert_eq!(bob.lines(), ["ERR already-authenticated already signed in"]);
    // The server knows the identity now (5.1).
    let known =
        w.h.store
            .identity(&uid("bob@example.net"))
            .unwrap()
            .unwrap();
    assert!(!known.hosted);
    assert_eq!(known.first_seen, start());
}

/// Every way AUTH fails gets `ERR auth-failed`, and leaves the connection
/// not signed in.
#[tokio::test]
async fn auth_failures() {
    let mut w = World::new();
    let bob = identity("bob@example.net");
    w.fetcher.set(&bob, vec![public(1)]);
    let failed = "ERR auth-failed the signature did not verify";

    // A key the file does not list. The server fetches again once (4.4).
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &auth("bob@example.net", 2, HOST, &nonce)).await;
    assert_eq!(c.lines(), [failed]);
    assert_eq!(
        w.fetcher.calls(),
        [(bob.clone(), false), (bob.clone(), true)]
    );
    w.send(&c, "sync").await;
    assert_eq!(c.lines(), ["ERR not-authenticated sign in first"]);

    // The nonce is used up, even by an AUTH that failed (4.5).
    w.send(&c, &auth("bob@example.net", 1, HOST, &nonce)).await;
    assert_eq!(
        c.lines(),
        ["ERR auth-failed this connection's nonce was used up; reconnect"]
    );

    // A signature over another nonce: a replay from another connection.
    let (mut c, _) = w.dial(Some(HOST));
    let (_, other_nonce) = w.dial(Some(HOST));
    w.send(&c, &auth("bob@example.net", 1, HOST, &other_nonce))
        .await;
    assert_eq!(c.lines(), [failed]);

    // A signature for another host: one meant for another server (4.5).
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &auth("bob@example.net", 1, "chat.example.net", &nonce))
        .await;
    assert_eq!(c.lines(), [failed]);

    // A signature for another identity.
    w.fetcher.set(&identity("eve@example.net"), vec![public(1)]);
    let (mut c, nonce) = w.dial(Some(HOST));
    let sig = secret(1).sign_challenge(HOST, &nonce, "bob@example.net");
    w.send(&c, &format!("auth eve@example.net {sig}")).await;
    assert_eq!(c.lines(), [failed]);

    // No key file: fetching fails, and is not tried again.
    let carol = identity("carol@example.com");
    w.fetcher.fail(&carol);
    let before = w.fetcher.calls().len();
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &auth("carol@example.com", 1, HOST, &nonce))
        .await;
    assert_eq!(c.lines(), [failed]);
    assert_eq!(w.fetcher.calls()[before..], [(carol, false)]);

    // Without SNI there is no host to check against.
    let (mut c, nonce) = w.dial(None);
    w.send(&c, &auth("bob@example.net", 1, HOST, &nonce)).await;
    assert_eq!(
        c.lines(),
        ["ERR auth-failed connect with SNI to sign in as an identity"]
    );

    // A guest uid does not parse: the network layer answers bad-syntax.
    let sig = secret(1).sign_challenge(HOST, &nonce, "~sam");
    let err = format!("auth ~sam {sig}").parse::<Request>().unwrap_err();
    assert_eq!(err.code(), ErrorCode::BadSyntax);

    // A REGISTER that fails uses up the nonce too.
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &register("bob", 1, "elsewhere.example", &nonce))
        .await;
    assert_eq!(c.lines(), [failed]);
    w.send(&c, &auth("bob@example.net", 1, HOST, &nonce)).await;
    assert_eq!(
        c.lines(),
        ["ERR auth-failed this connection's nonce was used up; reconnect"]
    );
}

/// AUTH and REGISTER work only on connections whose SNI names this
/// server: its hostname, or a name on one of its certificates (4.5).
/// Otherwise a server could relay this one's nonce to its own users under
/// its own name, and sign in here with the signatures it gets back.
#[tokio::test]
async fn sign_ins_need_the_servers_name_in_sni() {
    let mut w = World::new();
    let bob = identity("bob@example.net");
    w.fetcher.set(&bob, vec![public(1)]);
    let refused = "ERR auth-failed connect with this server's name in SNI";

    // evil.example connects here with its own name in SNI, and has bob
    // sign the challenge for it.
    let evil = "evil.example";
    let mut c = w.h.connect_info(Some(evil), false, 4096);
    let nonce: Nonce = c.lines()[0].split(' ').nth(3).unwrap().parse().unwrap();
    w.send(&c, &auth("bob@example.net", 1, evil, &nonce)).await;
    assert_eq!(c.lines(), [refused]);
    // The nonce is used up all the same.
    w.send(&c, &auth("bob@example.net", 1, HOST, &nonce)).await;
    assert_eq!(
        c.lines(),
        ["ERR auth-failed this connection's nonce was used up; reconnect"]
    );
    let mut c = w.h.connect_info(Some(evil), false, 4096);
    let nonce: Nonce = c.lines()[0].split(' ').nth(3).unwrap().parse().unwrap();
    w.send(&c, &register("alice", 0, evil, &nonce)).await;
    assert_eq!(c.lines(), [refused]);
    assert_eq!(published(&w, "alice"), None);
    assert_eq!(w.fetcher.calls(), []);

    // The hostname in any case, with a trailing dot, and names on the
    // certificates, which the network layer checks.
    for (sni, certified) in [("Chat.Example.org.", false), ("other.example.org", true)] {
        let mut c = w.h.connect_info(Some(sni), certified, 4096);
        let nonce: Nonce = c.lines()[0].split(' ').nth(3).unwrap().parse().unwrap();
        w.send(&c, &auth("bob@example.net", 1, sni, &nonce)).await;
        assert_eq!(c.lines(), ["OK uid=bob@example.net"], "{sni}");
    }
}

/// A key file that does not arrive in time fails AUTH, without holding up
/// anyone else.
#[tokio::test(start_paused = true)]
async fn auth_gives_up_on_a_slow_key_host() {
    let mut w = World::new();
    w.fetcher.hang(&identity("slow@example.com"));
    let mut sam = w.h.guest("sam").await;
    w.send(&sam, "join #general").await;
    sam.lines();
    let (mut c, nonce) = w.dial(Some(HOST));
    let hub = w.h.hub.clone();
    let id = c.id;
    let line = auth("slow@example.com", 1, HOST, &nonce);
    let task = tokio::spawn(async move { hub.command(id, line.parse().unwrap()).await });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    // Rooms go on meanwhile.
    w.send(&sam, "msg #general still here").await;
    assert_eq!(sam.lines().last().unwrap(), "OK seq=2");
    task.await.unwrap();
    assert_eq!(c.lines(), ["ERR auth-failed the signature did not verify"]);
}

/// A key added to a key file that the server has cached works at once:
/// the server fetches the file again before failing (4.4).
#[tokio::test]
async fn a_new_key_works_despite_the_cache() {
    let mut w = World::new();
    let bob = identity("bob@example.net");
    w.fetcher.set(&bob, vec![public(1), public(2)]);
    w.fetcher.set_cached(&bob, vec![public(1)]);
    let _phone = w.sign_in("bob@example.net", 2).await;
    assert_eq!(
        w.fetcher.calls(),
        [(bob.clone(), false), (bob.clone(), true)]
    );
    // The cache is fresh now.
    let _laptop = w.sign_in("bob@example.net", 1).await;
    assert_eq!(w.fetcher.calls().len(), 3);
    assert_eq!(w.fetcher.calls()[2], (bob, false));
}

/// A device whose key has gone from the key file is closed when the server
/// next fetches the file (4.4).
#[tokio::test]
async fn a_device_whose_key_was_removed_is_closed() {
    let mut w = World::new();
    let bob = identity("bob@example.net");
    w.fetcher.set(&bob, vec![public(1), public(2)]);
    let mut lost = w.sign_in("bob@example.net", 1).await;
    let mut phone = w.sign_in("bob@example.net", 2).await;
    w.fetcher.set(&bob, vec![public(2), public(3)]);
    let mut laptop = w.sign_in("bob@example.net", 3).await;
    assert_eq!(lost.lines(), ["<close> BYE this device's key was removed"]);
    assert_eq!(phone.lines(), Vec::<String>::new());
    w.send(&laptop, "sync").await;
    assert_eq!(laptop.lines(), ["OK"]);
}

#[tokio::test]
async fn operators_learn_it_when_they_sign_in() {
    let mut w = World::new();
    w.fetcher.set(&identity("op@example.net"), vec![public(1)]);
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &auth("op@example.net", 1, HOST, &nonce)).await;
    assert_eq!(c.lines(), ["OK uid=op@example.net op=yes"]);
}

/// Hosted identities sign in with the server's own records, and nothing
/// is fetched (4.5).
#[tokio::test]
async fn hosted_identities_use_their_stored_keys() {
    let mut w = World::new();
    w.register("alice", 0).await;
    let _laptop = w.sign_in("alice@example.org", 0).await;
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &auth("alice@example.org", 1, HOST, &nonce))
        .await;
    assert_eq!(c.lines(), ["ERR auth-failed the signature did not verify"]);
    // An unknown name under the identity domain is not fetched either.
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &auth("nobody@example.org", 1, HOST, &nonce))
        .await;
    assert_eq!(c.lines(), ["ERR auth-failed the signature did not verify"]);
    assert_eq!(w.fetcher.calls(), []);
}

// ---------------------------------------------------------------------------
// REGISTER (4.6)

#[tokio::test]
async fn register_creates_a_hosted_identity() {
    let mut w = World::new();
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, "info").await;
    assert_eq!(
        c.lines(),
        ["OK version=1 guests=yes register=example.org retention=forever push=no upload=no"]
    );
    w.send(
        &c,
        &format!("@ref=r {}", register("Alice", 0, HOST, &nonce)),
    )
    .await;
    assert_eq!(c.lines(), ["@ref=r OK uid=alice@example.org"]);
    // Signed in at once.
    w.send(&c, "join #general").await;
    assert!(c.lines()[0].contains(";from=alice@example.org;"));
    // The key file is published (4.6).
    assert_eq!(published(&w, "alice"), Some(vec![(public(0), None)]));
    let record =
        w.h.store
            .identity(&uid("alice@example.org"))
            .unwrap()
            .unwrap();
    assert!(record.hosted);

    // The name is taken now, whoever asks.
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &register("alice", 1, HOST, &nonce)).await;
    assert_eq!(c.lines(), ["ERR name-taken that name is registered"]);
}

#[tokio::test]
async fn register_needs_an_identity_domain() {
    let mut c = id_config();
    c.identity_domain = None;
    let mut w = World::with(c);
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, "info").await;
    w.send(&c, &register("alice", 0, HOST, &nonce)).await;
    assert_eq!(
        c.lines(),
        [
            "OK version=1 guests=yes register=no retention=forever push=no upload=no",
            "ERR not-supported this server does not offer registration",
        ]
    );
    // The REGISTER used up the nonce (4.5).
    w.send(&c, &auth("bob@example.net", 1, HOST, &nonce)).await;
    assert_eq!(
        c.lines(),
        ["ERR auth-failed this connection's nonce was used up; reconnect"]
    );
}

#[tokio::test]
async fn register_can_be_closed() {
    let mut c = id_config();
    c.server.registration = false;
    let mut w = World::with(c);
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, "info").await;
    w.send(&c, &register("alice", 0, HOST, &nonce)).await;
    assert_eq!(
        c.lines(),
        [
            "OK version=1 guests=yes register=no retention=forever push=no upload=no",
            "ERR forbidden registration is closed",
        ]
    );
    assert_eq!(published(&w, "alice"), None);
}

#[tokio::test]
async fn register_checks_the_signature_with_the_new_key() {
    let mut w = World::new();
    let (mut c, nonce) = w.dial(Some(HOST));
    // Signed with key 1, but naming key 0 as the identity's key.
    let sig = secret(1).sign_challenge(HOST, &nonce, "alice@example.org");
    w.send(&c, &format!("register alice {} {sig}", public(0)))
        .await;
    assert_eq!(c.lines(), ["ERR auth-failed the signature did not verify"]);
    // Signed for another name.
    let (mut c, nonce) = w.dial(Some(HOST));
    let sig = secret(0).sign_challenge(HOST, &nonce, "bob@example.org");
    w.send(&c, &format!("register alice {} {sig}", public(0)))
        .await;
    assert_eq!(c.lines(), ["ERR auth-failed the signature did not verify"]);
    // The name is still free.
    w.register("alice", 0).await;
}

#[tokio::test]
async fn registrations_are_limited_per_address() {
    let mut c = id_config();
    c.limits.registrations_per_hour = 2;
    let mut w = World::with(c);
    w.register("one", 1).await;
    // Failures do not count.
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &register("one", 2, HOST, &nonce)).await;
    assert_eq!(c.lines(), ["ERR name-taken that name is registered"]);
    w.h.clock.advance(Duration::from_secs(600));
    w.register("two", 2).await;
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(
        &c,
        &format!("@ref=x {}", register("three", 3, HOST, &nonce)),
    )
    .await;
    // The first registration is an hour old in 3000 seconds.
    assert_eq!(
        c.lines(),
        ["@ref=x;retry=3000 ERR rate-limited too many registrations from this address"]
    );
    w.h.clock.advance(Duration::from_secs(3000));
    w.register("three", 3).await;
}

/// A name that was unregistered can never be registered again (4.8, 10.5).
#[tokio::test]
async fn an_unregistered_name_stays_reserved() {
    let mut w = World::new();
    let mut c = w.register("alice", 0).await;
    w.send(&c, "unregister alice@example.org").await;
    assert_eq!(c.lines(), ["OK", "<close> BYE identity deleted"]);
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &register("alice", 1, HOST, &nonce)).await;
    assert_eq!(c.lines(), ["ERR name-taken that name was used before"]);
}

/// The state of [`World::register`] survives a restart, and the key files
/// are published again when the hub starts.
#[tokio::test]
async fn hosted_key_files_are_published_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("risala.db");
    let mut w = World::on(id_config(), Arc::new(SqliteStore::open(&path).unwrap()));
    w.register("alice", 0).await;
    drop(w);
    let w = World::on(id_config(), Arc::new(SqliteStore::open(&path).unwrap()));
    assert_eq!(published(&w, "alice"), Some(vec![(public(0), None)]));
}

// ---------------------------------------------------------------------------
// KEY (4.7)

#[tokio::test]
async fn keys_of_a_hosted_identity() {
    let mut w = World::new();
    let mut laptop = w.register("alice", 0).await;
    w.send(&laptop, "@ref=1 key list").await;
    assert_eq!(
        laptop.lines(),
        [format!("@ref=1 KEY {}", public(0)), "@ref=1 OK".into()]
    );
    w.h.clock.advance(Duration::from_secs(1));
    w.send(&laptop, &format!("key add {} my phone ", public(1)))
        .await;
    assert_eq!(laptop.lines(), ["OK"]);
    // The label is plain text in the key file (4.4), and trimmed.
    assert_eq!(
        published(&w, "alice"),
        Some(vec![
            (public(0), None),
            (public(1), Some("my phone".into()))
        ])
    );
    w.send(&laptop, "key list").await;
    assert_eq!(
        laptop.lines(),
        [
            format!("KEY {}", public(0)),
            format!("KEY {} my phone ", public(1)),
            "OK".into()
        ]
    );
    // A label that cannot go in a key file.
    w.send(&laptop, &format!("key add {} two\\nlines", public(2)))
        .await;
    assert_eq!(
        laptop.lines(),
        ["ERR bad-syntax the label cannot go in a key file"]
    );

    // The new device signs in with its key.
    let mut phone = w.sign_in("alice@example.org", 1).await;

    // The phone removes the laptop's key: the laptop is closed (4.7).
    w.send(&phone, &format!("@ref=d key del {}", public(0)))
        .await;
    assert_eq!(phone.lines(), ["@ref=d OK"]);
    assert_eq!(
        laptop.lines(),
        ["<close> BYE this device's key was removed"]
    );
    assert_eq!(
        published(&w, "alice"),
        Some(vec![(public(1), Some("my phone".into()))])
    );
    // The laptop's key no longer signs in.
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &auth("alice@example.org", 0, HOST, &nonce))
        .await;
    assert_eq!(c.lines(), ["ERR auth-failed the signature did not verify"]);

    // The last key stays (4.7), and an unknown key is not found.
    w.send(&phone, &format!("key del {}", public(1))).await;
    w.send(&phone, &format!("key del {}", public(0))).await;
    assert_eq!(
        phone.lines(),
        [
            "ERR forbidden an identity's last key cannot be deleted",
            "ERR not-found no such key",
        ]
    );

    // Deleting this device's own key closes it after the OK.
    w.h.clock.advance(Duration::from_secs(1));
    w.send(&phone, &format!("key add {}", public(2))).await;
    w.send(&phone, &format!("key del {}", public(1))).await;
    assert_eq!(
        phone.lines(),
        ["OK", "OK", "<close> BYE this device's key was removed"]
    );
    assert_eq!(published(&w, "alice"), Some(vec![(public(2), None)]));
}

#[tokio::test]
async fn key_commands_need_a_hosted_identity() {
    let mut w = World::new();
    w.fetcher.set(&identity("bob@example.net"), vec![public(1)]);
    let mut bob = w.sign_in("bob@example.net", 1).await;
    w.send(&bob, "key list").await;
    w.send(&bob, &format!("key add {}", public(2))).await;
    let refused = "ERR not-supported this server does not host your identity; edit your key file";
    assert_eq!(bob.lines(), [refused, refused]);
    let mut sam = w.h.guest("sam").await;
    w.send(&sam, "key list").await;
    assert_eq!(sam.lines(), ["ERR forbidden not for guests"]);
}

#[tokio::test]
async fn an_identity_has_at_most_64_keys() {
    let mut w = World::new();
    let mut c = w.register("alice", 0).await;
    for n in 1..64 {
        w.send(&c, &format!("key add {}", public(n))).await;
    }
    assert!(c.lines().iter().all(|l| l == "OK"));
    w.send(&c, &format!("key add {}", public(64))).await;
    assert_eq!(c.lines(), ["ERR forbidden an identity has at most 64 keys"]);
    assert_eq!(published(&w, "alice").unwrap().len(), 64);
}

// ---------------------------------------------------------------------------
// UNREGISTER (4.8)

#[tokio::test]
async fn unregister_deletes_a_hosted_identity() {
    let mut w = World::new();
    let mut laptop = w.register("alice", 0).await;
    w.send(&laptop, &format!("key add {}", public(1))).await;
    w.send(&laptop, "join #general").await;
    w.send(&laptop, "join #mine").await;
    let id = value(laptop.lines().last().unwrap(), "id");
    let mut phone = w.sign_in("alice@example.org", 1).await;
    let mut sam = w.h.guest("sam").await;
    w.send(&sam, "join #general").await;
    sam.lines();
    laptop.lines();
    phone.lines();
    let key = w.h.room_key("#general");
    w.h.store
        .set_read_marker(key, &uid("alice@example.org"), Seq::new(1).unwrap())
        .unwrap();

    w.send(&laptop, "unregister bob@example.net").await;
    w.send(&laptop, "unregister alice@example.org purge=yes")
        .await;
    assert_eq!(
        laptop.lines(),
        [
            "ERR forbidden type your own identity to delete it",
            "ERR not-supported purge=yes is not supported yet",
        ]
    );

    w.send(&laptop, "@ref=u unregister ALICE@example.org").await;
    let part_general = format!("@seq=3;t={T};from=alice@example.org PART #general");
    let part_mine = format!("@seq=2;t={T};from=alice@example.org PART #mine");
    assert_eq!(
        laptop.lines(),
        [
            part_general.clone(),
            part_mine.clone(),
            "@ref=u OK".into(),
            "<close> BYE identity deleted".into()
        ]
    );
    assert_eq!(
        phone.lines(),
        [
            part_general.clone(),
            part_mine,
            "<close> BYE identity deleted".into()
        ]
    );
    assert_eq!(sam.lines(), [part_general]);

    // Gone: its record, keys, key file, read markers and roles.
    let alice = uid("alice@example.org");
    assert_eq!(w.h.store.identity(&alice).unwrap(), None);
    assert_eq!(w.h.store.hosted_keys(&alice).unwrap(), None);
    assert!(w.h.store.read_markers(&alice).unwrap().is_empty());
    assert_eq!(published(&w, "alice"), None);
    w.send(&sam, "info #mine").await;
    assert_eq!(
        sam.lines().last().unwrap(),
        &format!("OK id={id} members=0 head=2 role=none joined=no")
    );
    let mine = w.h.store.room(&"#mine".parse().unwrap()).unwrap().unwrap();
    assert!(mine.roles.is_empty());
    // Its keys sign in no more.
    let (mut c, nonce) = w.dial(Some(HOST));
    w.send(&c, &auth("alice@example.org", 1, HOST, &nonce))
        .await;
    assert_eq!(c.lines(), ["ERR auth-failed the signature did not verify"]);
}

/// Other identities are only forgotten: signing in again starts afresh
/// (4.8).
#[tokio::test]
async fn unregister_forgets_other_identities() {
    let mut w = World::new();
    w.fetcher.set(&identity("bob@example.net"), vec![public(1)]);
    let mut bob = w.sign_in("bob@example.net", 1).await;
    w.send(&bob, "join #general").await;
    bob.lines();
    w.send(&bob, "unregister bob@example.net").await;
    assert_eq!(
        bob.lines(),
        [
            format!("@seq=2;t={T};from=bob@example.net PART #general"),
            "OK".into(),
            "<close> BYE identity deleted".into()
        ]
    );
    assert_eq!(w.h.store.identity(&uid("bob@example.net")).unwrap(), None);
    let mut bob = w.sign_in("bob@example.net", 1).await;
    w.send(&bob, "sync").await;
    assert_eq!(bob.lines(), ["OK"]);
    assert!(
        w.h.store
            .identity(&uid("bob@example.net"))
            .unwrap()
            .is_some()
    );
}

// ---------------------------------------------------------------------------
// Membership (6.1, 7.1)

#[tokio::test]
async fn every_device_gets_the_events_of_its_rooms() {
    let mut w = World::new();
    w.fetcher
        .set(&identity("bob@example.net"), vec![public(1), public(2)]);
    let mut laptop = w.sign_in("bob@example.net", 1).await;
    let mut phone = w.sign_in("bob@example.net", 2).await;
    w.send(&laptop, "join #general").await;
    let id = value(laptop.lines().last().unwrap(), "id");
    // The other device gets the JOIN live, with no JOIN of its own.
    let join = format!("@seq=1;t={T};from=bob@example.net;id={id} JOIN #general");
    assert_eq!(phone.lines(), [join]);
    w.send(&phone, "msg #general from my phone").await;
    let msg = format!("@seq=2;t={T};from=bob@example.net MSG #general from my phone");
    assert_eq!(phone.lines(), [msg.clone(), "OK seq=2".into()]);
    assert_eq!(laptop.lines(), [msg]);
    // A device that signs in later is in the room from the start (7.1).
    let mut desktop = w.sign_in("bob@example.net", 1).await;
    w.send(&desktop, "sync").await;
    assert_eq!(
        desktop.lines(),
        [format!("CONV #general {id} 2 0"), "OK".into()]
    );
    let sam = w.h.guest("sam").await;
    w.send(&sam, "join #general").await;
    let join = format!("@seq=3;t={T};from=~sam;id={id} JOIN #general");
    for device in [&mut laptop, &mut phone, &mut desktop] {
        assert_eq!(device.lines(), std::slice::from_ref(&join));
    }
    // A JOIN from a member changes nothing.
    w.send(&phone, "join #general").await;
    assert_eq!(phone.lines().last().unwrap(), &format!("OK id={id} head=3"));
    assert_eq!(laptop.lines(), Vec::<String>::new());
    // Leaving on one device leaves on all.
    w.send(&laptop, "part #general").await;
    let part = format!("@seq=4;t={T};from=bob@example.net PART #general");
    assert_eq!(phone.lines(), std::slice::from_ref(&part));
    w.send(&sam, "msg #general gone?").await;
    assert_eq!(desktop.lines(), [part]);
    w.send(&desktop, "sync").await;
    assert_eq!(desktop.lines(), ["OK"]);
}

#[tokio::test]
async fn membership_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("risala.db");
    let open = || {
        let store = SqliteStore::open(&path).unwrap();
        store
            .ensure_room(&"#general".parse().unwrap(), start())
            .unwrap();
        let w = World::on(id_config(), Arc::new(store));
        w.fetcher.set(&identity("bob@example.net"), vec![public(1)]);
        w
    };
    let mut w = open();
    let mut bob = w.sign_in("bob@example.net", 1).await;
    w.send(&bob, "join #general").await;
    let id = value(bob.lines().last().unwrap(), "id");
    drop(w);

    let mut w = open();
    let mut bob = w.sign_in("bob@example.net", 1).await;
    w.send(&bob, "sync").await;
    assert_eq!(
        bob.lines(),
        [format!("CONV #general {id} 1 0"), "OK".into()]
    );
    let mut sam = w.h.guest("sam").await;
    w.send(&sam, "join #general").await;
    assert_eq!(
        bob.lines(),
        [format!("@seq=2;t={T};from=~sam;id={id} JOIN #general")]
    );
    w.send(&sam, "info #general").await;
    assert!(sam.lines().last().unwrap().contains(" members=2 "));
}

#[tokio::test]
async fn sync_reports_read_markers() {
    let mut w = World::new();
    w.fetcher.set(&identity("bob@example.net"), vec![public(1)]);
    let mut bob = w.sign_in("bob@example.net", 1).await;
    w.send(&bob, "join #general").await;
    let id = value(bob.lines().last().unwrap(), "id");
    for n in 0..3 {
        w.send(&bob, &format!("msg #general {n}")).await;
    }
    bob.lines();
    let key = w.h.room_key("#general");
    w.h.store
        .set_read_marker(key, &uid("bob@example.net"), Seq::new(3).unwrap())
        .unwrap();
    w.send(&bob, "sync").await;
    assert_eq!(
        bob.lines(),
        [format!("CONV #general {id} 4 3"), "OK".into()]
    );
}

// ---------------------------------------------------------------------------
// Creating rooms and the rules for identities (6.1, 6.3)

#[tokio::test]
async fn joining_a_new_room_creates_it() {
    let mut w = World::new();
    w.fetcher
        .set(&identity("bob@example.net"), vec![public(1), public(2)]);
    let mut bob = w.sign_in("bob@example.net", 1).await;
    let mut phone = w.sign_in("bob@example.net", 2).await;
    w.send(&bob, "@ref=j join #new").await;
    let lines = bob.lines();
    let id = value(lines.last().unwrap(), "id");
    let join = format!("@seq=1;t={T};from=bob@example.net;id={id} JOIN #new");
    let mut expected = vec![join.clone()];
    expected.extend(
        super::tests::default_settings("#new")
            .into_iter()
            .map(|l| format!("@ref=j {l}")),
    );
    expected.push(format!("@ref=j OK id={id} head=1"));
    assert_eq!(lines, expected);
    assert_eq!(phone.lines(), [join]);
    // The creator is the owner (6.3).
    w.send(&bob, "info #new").await;
    assert_eq!(
        bob.lines().last().unwrap(),
        &format!("OK id={id} members=1 head=1 role=owner joined=yes")
    );
    // Others join it as any public room; the LIST shows it.
    let mut sam = w.h.guest("sam").await;
    w.send(&sam, "list").await;
    assert!(sam.lines().contains(&"ROOM #new 1".to_string()));
    w.send(&sam, "join #new").await;
    assert!(sam.lines()[0].starts_with("@seq=2;"));
}

#[tokio::test]
async fn room_creation_follows_the_policy() {
    for (policy, may) in [
        (RoomCreation::Identities, [true, true, true]),
        (RoomCreation::Hosted, [true, false, true]),
        (RoomCreation::Operators, [false, false, true]),
        (RoomCreation::Nobody, [false, false, false]),
    ] {
        let mut c = id_config();
        c.room_creation = policy;
        let mut w = World::with(c);
        w.fetcher.set(&identity("bob@example.net"), vec![public(1)]);
        w.fetcher.set(&identity("op@example.net"), vec![public(2)]);
        let alice = w.register("alice", 0).await;
        let bob = w.sign_in("bob@example.net", 1).await;
        let op = w.sign_in("op@example.net", 2).await;
        for ((mut c, room), may) in [(alice, "#a"), (bob, "#b"), (op, "#c")]
            .into_iter()
            .zip(may)
        {
            w.send(&c, &format!("join {room}")).await;
            let last = c.lines().last().unwrap().clone();
            if may {
                assert!(last.starts_with("OK id="), "{policy:?} {room}: {last}");
            } else {
                assert_eq!(last, "ERR not-found no such room", "{policy:?} {room}");
            }
        }
    }
}

/// Owners keep their role after PART, and can come back to a private room
/// (6.1, 6.3). Operators may enter any room (6.3, 10). Invitations open a
/// private room, and bans close a public one (6.4).
#[tokio::test]
async fn who_may_read_and_join() {
    let mut w = World::new();
    for (who, n) in [
        ("bob@example.net", 1),
        ("op@example.net", 2),
        ("eve@example.net", 3),
    ] {
        w.fetcher.set(&identity(who), vec![public(n)]);
    }
    let mut bob = w.sign_in("bob@example.net", 1).await;
    let mut op = w.sign_in("op@example.net", 2).await;
    let mut eve = w.sign_in("eve@example.net", 3).await;

    // Bob's own room, made private, which he then leaves.
    w.send(&bob, "join #bob").await;
    let id = value(bob.lines().last().unwrap(), "id");
    w.h.room_state("#bob", |info| {
        info.settings.apply(&RoomSetting::Public(false))
    })
    .await;
    w.send(&bob, "part #bob").await;
    w.send(&bob, "info #bob").await;
    assert_eq!(
        bob.lines().last().unwrap(),
        &format!("OK id={id} members=0 head=2 role=owner joined=no")
    );
    w.send(&bob, "history #bob").await;
    assert_eq!(bob.lines().last().unwrap(), &format!("OK id={id} more=0"));
    w.send(&bob, "join #bob").await;
    assert!(bob.lines().last().unwrap().starts_with("OK id="));

    // Eve cannot see it; the operator can, and may join.
    w.send(&eve, "info #bob").await;
    w.send(&eve, "join #bob").await;
    w.send(&eve, "history #bob").await;
    assert_eq!(eve.lines(), ["ERR not-found no such room"; 3]);
    w.send(&op, "history #bob").await;
    assert_eq!(op.lines().last().unwrap(), &format!("OK id={id} more=0"));
    w.send(&op, "join #bob").await;
    assert!(op.lines().last().unwrap().starts_with("OK id="));

    // An invitation lets Eve see it, look at INFO and join, but not read
    // its history before joining (6.2, 7.2).
    let eve_uid = uid("eve@example.net");
    let invited = eve_uid.clone();
    w.h.room_state("#bob", move |info| {
        info.invites.insert(invited);
    })
    .await;
    w.send(&eve, "info #bob").await;
    let info = eve.lines();
    assert!(
        info.last().unwrap().ends_with(" role=none joined=no"),
        "{info:?}"
    );
    w.send(&eve, "history #bob").await;
    assert_eq!(eve.lines(), ["ERR forbidden join the room first"]);
    w.send(&eve, "join #bob").await;
    assert!(eve.lines().last().unwrap().starts_with("OK id="));

    // A ban closes a public room, to reading too.
    let banned = eve_uid.clone();
    w.h.room_state("#general", move |info| {
        info.bans.insert(banned);
    })
    .await;
    w.send(&eve, "join #general").await;
    w.send(&eve, "history #general").await;
    assert_eq!(
        eve.lines(),
        [
            "ERR forbidden you are banned from this room",
            "ERR forbidden you are banned from this room"
        ]
    );

    // The configured private room: hidden from Bob, open to the operator.
    bob.lines();
    w.send(&bob, "join #private").await;
    assert_eq!(bob.lines(), ["ERR not-found no such room"]);
    w.send(&op, "join #private").await;
    assert!(op.lines().last().unwrap().starts_with("OK id="));
}

// ---------------------------------------------------------------------------
// cids (7.6)

/// An identity's cids hold across its connections and devices for 24
/// hours, in the conversation they were first sent to.
#[tokio::test]
async fn cids_hold_across_connections() {
    let mut w = World::new();
    w.fetcher
        .set(&identity("bob@example.net"), vec![public(1), public(2)]);
    let mut laptop = w.sign_in("bob@example.net", 1).await;
    w.send(&laptop, "join #general").await;
    w.send(&laptop, "join #other").await;
    laptop.lines();
    let cid = "cid=0123456789abcdef";
    w.send(&laptop, &format!("@{cid} msg #general hi")).await;
    assert_eq!(laptop.lines().last().unwrap(), "OK seq=2");
    w.h.close(laptop).await;

    // Resent from another device: the same seq, and no new event.
    let mut phone = w.sign_in("bob@example.net", 2).await;
    w.send(&phone, &format!("@ref=1;{cid} msg #general hi"))
        .await;
    assert_eq!(phone.lines(), ["@ref=1 OK seq=2"]);
    assert_eq!(
        stored(&w.h, "#general"),
        ["bob@example.net JOIN", "bob@example.net MSG"]
    );
    // Another conversation is another message.
    w.send(&phone, &format!("@{cid} msg #other hi")).await;
    assert_eq!(phone.lines().last().unwrap(), "OK seq=2");
    assert_eq!(stored(&w.h, "#other").len(), 2);

    // After 24 hours, it is a new message.
    w.h.clock.advance(Duration::from_secs(24 * 60 * 60 + 1));
    w.send(&phone, &format!("@ref=2;{cid} msg #general hi"))
        .await;
    assert_eq!(phone.lines().last().unwrap(), "@ref=2 OK seq=3");
}

// ---------------------------------------------------------------------------

impl Harness {
    /// The store's key for `room`.
    fn room_key(&self, room: &str) -> crate::store::ConvKey {
        self.store
            .room(&room.parse().unwrap())
            .unwrap()
            .unwrap()
            .key
    }

    /// Changes a room's state in memory, as the commands of M4 will.
    async fn room_state(&self, room: &str, f: impl FnOnce(&mut state::RoomInfo)) {
        let entry = self.hub.inner.room_entry(&room.parse().unwrap()).unwrap();
        let mut st = entry.lock().await;
        f(st.room_info_mut().unwrap());
    }
}
