//! The identity area (4.4-4.9, 10.5): AUTH, REGISTER, KEYS PUT, hosted key
//! files, pins, PAIR, UNREGISTER and ADMIN UNREGISTER.

use std::sync::Arc;
use std::time::Duration;

use risala_keylog::checkpoint::LogOrigin;
use risala_keylog::testlog::MemoryLog;
use risala_proto::auth::Nonce;
use risala_proto::chain::NoHandoffs;
use risala_proto::keyfile::{EntryError, KeyFile, KeyFileState, LogLine};
use risala_proto::record::LogEntry;

use super::*;
use crate::core::HostedKeyFile;
use crate::keyfiles::{Body, MemoryFetcher, MemoryPublisher};
use crate::store::{IdentityStore as _, KeyLogStore as _};
use crate::testing::{TestChain, TestIdentity, test_log_key};

/// The configuration of these tests: `chat.example.org`, hosting
/// identities at `example.org`, with `op@example.org` as an operator.
fn id_config() -> Config {
    let mut c = config();
    c.identity_domain = Some("example.org".into());
    c.server.registration = true;
    c
}

/// A hub that hosts `example.org` and fetches key files from memory.
struct Ids {
    h: Harness,
    fetcher: Arc<MemoryFetcher>,
    publisher: Arc<MemoryPublisher>,
}

impl Ids {
    fn new() -> Ids {
        Ids::with(id_config())
    }

    fn with(config: Config) -> Ids {
        let fetcher = Arc::new(MemoryFetcher::new());
        let publisher = Arc::new(MemoryPublisher::new());
        let keys = KeyServices::shared(fetcher.clone(), publisher.clone());
        let h = Harness::with_keys(
            config,
            timers(),
            SqliteStore::open_in_memory().unwrap(),
            keys,
        );
        Ids {
            h,
            fetcher,
            publisher,
        }
    }

    /// The server's key log.
    fn log(&self) -> LogLine {
        self.h
            .hub
            .key_log()
            .expect("a server with an identity domain has a log")
    }

    /// A new connection with SNI `sni`, and its greeting's nonce.
    fn open(&mut self, sni: Option<&str>) -> (Client, Nonce) {
        let mut c = self.h.open("203.0.113.7:51000", sni);
        let greeting = c.raw_lines();
        let nonce = greeting[0].split(' ').nth(3).unwrap().parse().unwrap();
        (c, nonce)
    }

    /// A new connection to `chat.example.org`, and its nonce.
    fn connect(&mut self) -> (Client, Nonce) {
        self.open(Some("chat.example.org"))
    }

    /// Sends AUTH for `who` on a new connection, and returns it with the
    /// answer.
    async fn auth(&mut self, who: &TestIdentity) -> (Client, Vec<String>) {
        let (mut c, nonce) = self.connect();
        self.h
            .send(&c, &who.auth_line("chat.example.org", &nonce))
            .await;
        let lines = c.lines();
        (c, lines)
    }

    /// Registers `<name>@example.org` with a new chain naming the server's
    /// log.
    async fn register(&mut self, name: &str) -> (Client, TestChain, TestIdentity) {
        let (chain, device) = TestChain::new(&format!("{name}@example.org"), &self.log().log);
        let (mut c, nonce) = self.connect();
        self.h
            .send(
                &c,
                &chain.register_line(&device, "chat.example.org", &nonce),
            )
            .await;
        let lines = c.lines();
        let ok = format!("OK uid={name}@example.org");
        assert!(
            lines == [ok.clone()] || lines == [format!("{ok} op=yes")],
            "{lines:?}"
        );
        (c, chain, device)
    }

    /// The key file the hub serves for `name`.
    fn hosted(&self, name: &str) -> HostedKeyFile {
        self.h.hub.hosted_key_file(&name.parse().unwrap()).unwrap()
    }

    /// Checks the hosted key file of `chain`'s identity as a reader would
    /// (4.4), with the entries of the server's own log, and returns its
    /// chain.
    fn read_hosted(&self, chain: &TestChain) -> risala_proto::chain::Chain {
        let HostedKeyFile::File(bytes) = self.hosted(chain.identity().name()) else {
            panic!("no key file for {}", chain.identity());
        };
        let file = KeyFile::parse(&bytes).unwrap();
        assert_eq!(file.last_log(), &self.log());
        let store = self.h.store.clone();
        let mut entries = |_: &LogLine, index: u64| {
            store
                .log_entries(1, index, 1)
                .unwrap()
                .into_iter()
                .next()
                .map(|e| e.entry)
                .ok_or(EntryError::Missing)
        };
        match file.check(
            chain.identity(),
            &mut entries,
            &NoHandoffs,
            T.parse().unwrap(),
        ) {
            KeyFileState::Keys(chain) => *chain,
            other => panic!("{other:?}"),
        }
    }
}

/// A chain at `example.net`, whose key file names a log there.
fn outside(name: &str) -> (TestChain, TestIdentity) {
    TestChain::new(
        &format!("{name}@example.net"),
        &test_log_key("example.net", 1, [5; 32]),
    )
}

// ---------------------------------------------------------------------------
// REGISTER (4.7) and hosted key files

/// REGISTER creates the identity, logs its records, publishes its key
/// file, and signs the connection in (4.7).
#[tokio::test]
async fn register_signs_in_and_publishes() {
    let mut ids = Ids::new();
    let (mut c, chain, _device) = ids.register("alice").await;
    assert_eq!(
        c.handle.kind(),
        risala_proto::connection::ConnectionKind::SignedIn
    );
    // The records are in the log, in order.
    assert_eq!(ids.h.store.log_size(1).unwrap(), 2);
    let read = ids.read_hosted(&chain);
    assert_eq!(read.records(), chain.records());
    // The key file is published, as served.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let HostedKeyFile::File(served) = ids.hosted("alice") else {
        panic!()
    };
    assert_eq!(ids.publisher.get("alice"), Some(served));
    assert!(ids.h.store.knows(&chain.identity().to_uid()).unwrap());
    // Only the connection that registered is signed in: it may send what a
    // signed-in connection may.
    ids.h.send(&c, "ANON").await;
    assert_eq!(c.lines(), ["ERR already-authenticated"]);
    assert_eq!(ids.hosted("bob"), HostedKeyFile::NotFound);
}

/// A name is registered once, ever (4.7, 4.9).
#[tokio::test]
async fn register_name_taken() {
    let mut ids = Ids::new();
    let (alice, _, _) = ids.register("alice").await;
    let (chain, device) = TestChain::new("alice@example.org", &ids.log().log);
    let (mut c, nonce) = ids.connect();
    ids.h
        .send(
            &c,
            &chain.register_line(&device, "chat.example.org", &nonce),
        )
        .await;
    assert_eq!(c.lines(), ["ERR name-taken"]);
    // Still taken after UNREGISTER.
    ids.h.send(&alice, "UNREGISTER alice@example.org").await;
    let (mut c, nonce) = ids.connect();
    ids.h
        .send(
            &c,
            &chain.register_line(&device, "chat.example.org", &nonce),
        )
        .await;
    assert_eq!(c.lines(), ["ERR name-taken"]);
}

/// REGISTER's records must be a `master` and a `device` record for the
/// uid, naming the server's current log (4.7).
#[tokio::test]
async fn register_invalid_records() {
    let mut ids = Ids::new();
    let elsewhere = test_log_key("other.example", 1, [1; 32]);
    let (other_log, device) = TestChain::new("alice@example.org", &elsewhere);
    let (wrong_uid, device2) = TestChain::new("alice@example.net", &ids.log().log);
    let (mut three, device3) = TestChain::new("alice@example.org", &ids.log().log);
    three.add_device("device2");
    let (good, device4) = TestChain::new("alice@example.org", &ids.log().log);

    for (line, why) in [
        (
            other_log.register_line(
                &device,
                "chat.example.org",
                &Nonce::from_bytes(&[0; 16]).unwrap(),
            ),
            "other log",
        ),
        (
            wrong_uid.register_line(
                &device2,
                "chat.example.org",
                &Nonce::from_bytes(&[0; 16]).unwrap(),
            ),
            "wrong uid",
        ),
    ] {
        let (mut c, _) = ids.connect();
        ids.h.send(&c, &line).await;
        let lines = c.lines();
        assert_eq!(lines.len(), 1, "{why}");
        assert!(lines[0].starts_with("ERR invalid"), "{why}: {lines:?}");
    }
    // Three records.
    let (mut c, nonce) = ids.connect();
    let line = format!(
        "REGISTER alice {} {}",
        TestChain::payload(three.records()),
        device3.sign("chat.example.org", &nonce)
    );
    ids.h.send(&c, &line).await;
    assert!(c.lines()[0].starts_with("ERR invalid"));
    // Not records at all.
    let (mut c, nonce) = ids.connect();
    let line = format!(
        "REGISTER alice AAAA {}",
        device4.sign("chat.example.org", &nonce)
    );
    ids.h.send(&c, &line).await;
    assert!(c.lines()[0].starts_with("ERR invalid"));
    // A valid chain, but signed by another key than its device's.
    let (mut c, nonce) = ids.connect();
    let line = format!(
        "REGISTER alice {} {}",
        TestChain::payload(&good.records()[..2]),
        device.sign("chat.example.org", &nonce)
    );
    ids.h.send(&c, &line).await;
    assert_eq!(c.lines(), ["ERR auth-failed"]);
    // Nothing was logged.
    assert_eq!(ids.h.store.log_size(1).unwrap(), 0);
    assert_eq!(ids.hosted("alice"), HostedKeyFile::NotFound);
}

/// REGISTER checks the host name like AUTH (4.6 step 1, 4.7), and uses up
/// the nonce.
#[tokio::test]
async fn register_checks_the_host_and_nonce() {
    let mut ids = Ids::new();
    let (chain, device) = TestChain::new("alice@example.org", &ids.log().log);
    for sni in [Some("chat.example.net"), None] {
        let (mut c, nonce) = ids.open(sni);
        ids.h
            .send(
                &c,
                &chain.register_line(&device, "chat.example.net", &nonce),
            )
            .await;
        let lines = c.lines();
        assert!(
            lines[0].starts_with("ERR auth-failed"),
            "{sni:?}: {lines:?}"
        );
    }
    // A REGISTER that fails uses up the nonce: a second one on the same
    // connection fails, even if it would have passed.
    let (mut c, nonce) = ids.connect();
    ids.h
        .send(
            &c,
            &chain.register_line(
                &device,
                "chat.example.org",
                &Nonce::from_bytes(&[1; 16]).unwrap(),
            ),
        )
        .await;
    assert_eq!(c.lines(), ["ERR auth-failed"]);
    ids.h
        .send(
            &c,
            &chain.register_line(&device, "chat.example.org", &nonce),
        )
        .await;
    assert!(c.lines()[0].starts_with("ERR auth-failed"));
}

/// A server without an identity domain offers no registration; one whose
/// registration is closed refuses it (4.7, 10.6).
#[tokio::test]
async fn register_not_offered_or_closed() {
    let mut ids = Ids::with(config());
    let log = test_log_key("chat.example.org", 1, [1; 32]);
    let (chain, device) = TestChain::new("alice@example.org", &log);
    let (mut c, nonce) = ids.connect();
    ids.h
        .send(
            &c,
            &chain.register_line(&device, "chat.example.org", &nonce),
        )
        .await;
    assert!(c.lines()[0].starts_with("ERR not-supported"));

    let mut closed = id_config();
    closed.server.registration = false;
    let mut ids = Ids::with(closed);
    let (chain, device) = TestChain::new("alice@example.org", &ids.log().log);
    let (mut c, nonce) = ids.connect();
    ids.h
        .send(
            &c,
            &chain.register_line(&device, "chat.example.org", &nonce),
        )
        .await;
    assert_eq!(c.lines(), ["ERR forbidden registration is closed"]);
}

/// Registrations are limited per network address, those in progress
/// included, with a `retry` tag (4.7).
#[tokio::test]
async fn register_is_rate_limited() {
    let mut config = id_config();
    config.limits.registrations_per_hour = 1;
    let mut ids = Ids::with(config);
    ids.register("alice").await;
    let (chain, device) = TestChain::new("bob@example.org", &ids.log().log);
    let (mut c, nonce) = ids.connect();
    ids.h
        .send(
            &c,
            &chain.register_line(&device, "chat.example.org", &nonce),
        )
        .await;
    let lines = c.raw_lines();
    assert!(lines[0].starts_with("@retry="), "{lines:?}");
    assert!(lines[0].ends_with(" ERR rate-limited"), "{lines:?}");
}

// ---------------------------------------------------------------------------
// AUTH (4.6)

/// A hosted identity signs in with its own records; an operator gets
/// `op=yes` (4.6, 10.1).
#[tokio::test]
async fn auth_hosted() {
    let mut ids = Ids::new();
    let (_c, _chain, device) = ids.register("alice").await;
    let (c, lines) = ids.auth(&device).await;
    assert_eq!(lines, ["OK uid=alice@example.org"]);
    assert_eq!(
        c.handle.kind(),
        risala_proto::connection::ConnectionKind::SignedIn
    );
    let (_c, _chain, op) = ids.register("op").await;
    let (_, lines) = ids.auth(&op).await;
    assert_eq!(lines, ["OK uid=op@example.org op=yes"]);
    // A key no record lists does not sign in, nor does a name never
    // registered.
    let (_, lines) = ids.auth(&TestIdentity::new("alice@example.org")).await;
    assert_eq!(lines, ["ERR auth-failed"]);
    let (_, lines) = ids.auth(&TestIdentity::new("nobody@example.org")).await;
    assert_eq!(lines, ["ERR auth-failed"]);
    // Nothing was fetched for them.
    assert!(ids.fetcher.calls().is_empty());
}

/// AUTH is refused for a host name the server does not serve, or no SNI
/// (4.6 step 1), and any AUTH that parses uses up the nonce (4.6).
#[tokio::test]
async fn auth_host_and_nonce() {
    let mut ids = Ids::new();
    let (_c, _chain, device) = ids.register("alice").await;
    for sni in [Some("chat.example.net"), None] {
        let (mut c, nonce) = ids.open(sni);
        ids.h
            .send(&c, &device.auth_line("chat.example.net", &nonce))
            .await;
        let lines = c.lines();
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("ERR auth-failed wrong host name"),
            "{sni:?}: {lines:?}"
        );
    }
    let (mut c, nonce) = ids.connect();
    let wrong = Nonce::from_bytes(&[1; 16]).unwrap();
    ids.h
        .send(&c, &device.auth_line("chat.example.org", &wrong))
        .await;
    assert_eq!(c.lines(), ["ERR auth-failed"]);
    ids.h
        .send(&c, &device.auth_line("chat.example.org", &nonce))
        .await;
    assert_eq!(
        c.lines(),
        ["ERR auth-failed this connection's nonce is used up; reconnect"]
    );
    // A guest uid is not an identity: the line does not parse, and gets
    // `bad-syntax`.
    let line = device.auth_line("chat.example.org", &nonce);
    let guest = line.replacen("alice@example.org", "~alice", 1);
    let req: Result<risala_proto::command::Request, _> = guest.parse();
    assert!(req.is_err());
}

/// Another server's identity signs in with its key file (4.4, 4.6); the
/// master key and device-signing key never sign in.
#[tokio::test]
async fn auth_with_a_key_file() {
    let mut ids = Ids::new();
    let (chain, device) = outside("bob");
    ids.fetcher.set(chain.identity(), chain.key_file());
    let (_, lines) = ids.auth(&device).await;
    assert_eq!(lines, ["OK uid=bob@example.net"]);
    // A key the file does not list.
    let (_, lines) = ids.auth(&TestIdentity::new("bob@example.net")).await;
    assert_eq!(lines, ["ERR auth-failed"]);
}

/// The three states of 4.4: keys missing gets `auth-failed`, an outage
/// `unavailable` (4.6).
#[tokio::test]
async fn auth_keys_missing_and_outages() {
    let mut ids = Ids::new();
    let (chain, device) = outside("bob");
    let bob = chain.identity().clone();
    let missing: Vec<(&str, Body)> = vec![
        ("404", Body::Gone(404)),
        ("410", Body::Gone(410)),
        ("too large", Body::TooLarge),
        (
            "another version",
            Body::File(Arc::from(&b"risala-keys/2\n"[..])),
        ),
        (
            "not valid",
            Body::File(Arc::from(
                chain.key_file().replace("- ", "-  ").into_bytes(),
            )),
        ),
    ];
    for (why, body) in missing {
        ids.fetcher.set_body(&bob, body);
        let (_, lines) = ids.auth(&device).await;
        assert_eq!(lines, ["ERR auth-failed"], "{why}");
    }
    ids.fetcher.fail(&bob);
    let (_, lines) = ids.auth(&device).await;
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("ERR unavailable"), "{lines:?}");
    // The file is fine again: nothing was pinned or removed meanwhile.
    ids.fetcher.set(&bob, chain.key_file());
    let (_, lines) = ids.auth(&device).await;
    assert_eq!(lines, ["OK uid=bob@example.net"]);
}

/// A record more than 10 minutes ahead of the server's clock makes the
/// fetch an outage (4.4).
#[tokio::test]
async fn auth_record_ahead_is_an_outage() {
    let mut ids = Ids::new();
    let (chain, device) = outside("bob");
    ids.fetcher.set(chain.identity(), chain.key_file());
    // The clock is set back before the records were made.
    ids.h.clock.set("2025-12-31T23:00:00.000Z".parse().unwrap());
    let (_, lines) = ids.auth(&device).await;
    assert!(lines[0].starts_with("ERR unavailable"), "{lines:?}");
}

/// A signature that does not verify against a cached file gets the file
/// fetched again once (4.4).
#[tokio::test]
async fn auth_refetches_once() {
    let mut ids = Ids::new();
    let (mut chain, _first) = outside("bob");
    let old = chain.key_file();
    let phone = chain.add_device("phone");
    let bob = chain.identity().clone();
    ids.fetcher.set(&bob, chain.key_file());
    ids.fetcher.set_cached(&bob, old);
    let (_, lines) = ids.auth(&phone).await;
    assert_eq!(lines, ["OK uid=bob@example.net"]);
    assert_eq!(ids.fetcher.calls(), [(bob.clone(), false), (bob, true)]);
}

/// The server pins the first chain it accepts: a chain with another
/// master key, or one that does not hold the head, makes the keys missing
/// until ADMIN UNREGISTER clears the pin (4.6, 10.5).
#[tokio::test]
async fn auth_pins() {
    let mut ids = Ids::new();
    let (mut chain, device) = outside("bob");
    let bob = chain.identity().clone();
    let first = chain.clone();
    ids.fetcher.set(&bob, chain.key_file());
    assert_eq!(ids.auth(&device).await.1, ["OK uid=bob@example.net"]);
    // The chain grows: the pin follows it.
    let phone = chain.add_device("phone");
    ids.fetcher.set(&bob, chain.key_file());
    assert_eq!(ids.auth(&phone).await.1, ["OK uid=bob@example.net"]);
    let pin = ids.h.store.pin(&bob).unwrap().unwrap();
    assert_eq!(pin.head, chain.head().hash());
    // A rollback to the older chain: keys missing.
    ids.fetcher.set(&bob, first.key_file());
    assert_eq!(ids.auth(&device).await.1, ["ERR auth-failed"]);
    // Another chain, with another master key: keys missing.
    let (other, other_device) = outside("bob");
    ids.fetcher.set(&bob, other.key_file());
    assert_eq!(ids.auth(&other_device).await.1, ["ERR auth-failed"]);
    // Until an operator clears the pin.
    let mut op = ids.h.signed_in_as("op@example.org");
    ids.h.send(&op, "ADMIN UNREGISTER bob@example.net").await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(ids.h.store.pin(&bob).unwrap(), None);
    assert_eq!(ids.auth(&other_device).await.1, ["OK uid=bob@example.net"]);
}

/// A device removed by record no longer signs in, and a fresh read that
/// shows it removed closes its connections (4.4).
#[tokio::test]
async fn auth_removed_device() {
    let mut ids = Ids::new();
    let (mut chain, device) = outside("bob");
    let phone = chain.add_device("phone");
    let bob = chain.identity().clone();
    ids.fetcher.set(&bob, chain.key_file());
    let (mut phone_conn, lines) = ids.auth(&phone).await;
    assert_eq!(lines, ["OK uid=bob@example.net"]);
    chain.remove_devices(&[&phone]);
    ids.fetcher.set(&bob, chain.key_file());
    assert_eq!(ids.auth(&phone).await.1, ["ERR auth-failed"]);
    assert_eq!(
        phone_conn.lines(),
        [format!("<close> BYE {}", crate::core::BYE_KEYS_CHANGED)]
    );
    // The other device is not touched.
    assert_eq!(ids.auth(&device).await.1, ["OK uid=bob@example.net"]);
}

/// Records listed by index come from their log's entry bundles, under a
/// checkpoint the log signed (4.4, 4.5).
#[tokio::test]
async fn auth_with_logged_records() {
    let mut ids = Ids::new();
    let seed = [6; 32];
    let origin = LogOrigin::new("example.net", 1).unwrap();
    let mut memory = MemoryLog::new(&origin, &seed);
    let log = test_log_key("example.net", 1, seed);
    assert_eq!(memory.vkey().to_string(), log.vkey());
    let (mut chain, device) = TestChain::new("bob@example.net", &log);
    let phone = chain.add_device("phone");
    let bob = chain.identity().clone();
    // Some other entries first, then the first two records.
    for n in 0..300u16 {
        memory.append(&n.to_be_bytes());
    }
    let indices: Vec<u64> = chain.records()[..2]
        .iter()
        .map(|r| memory.append(&LogEntry::Record(r.clone()).encode()))
        .collect();
    let junk = memory.append(b"junk");
    let memory = Arc::new(std::sync::Mutex::new(memory));
    let served = memory.clone();
    ids.fetcher
        .serve_log("https://example.net/risala-log/1", move |path| {
            let log = served.lock().unwrap();
            if path == "checkpoint" {
                return Some(log.checkpoint(1_767_225_600).to_text().into_bytes());
            }
            log.serve(path)
        });
    let logged = |i: usize| indices.get(i).copied();
    ids.fetcher.set(&bob, chain.key_file_logged(&logged));
    assert_eq!(ids.auth(&device).await.1, ["OK uid=bob@example.net"]);
    assert_eq!(ids.auth(&phone).await.1, ["OK uid=bob@example.net"]);

    // An index whose entry is another record: keys missing.
    let wrong = |i: usize| indices.get(i).map(|&x| if i == 1 { junk } else { x });
    ids.fetcher.set(&bob, chain.key_file_logged(&wrong));
    assert_eq!(ids.auth(&device).await.1, ["ERR auth-failed"]);
    // An index past the log's checkpoint: keys missing.
    let past = |i: usize| indices.get(i).map(|&x| if i == 1 { 5000 } else { x });
    ids.fetcher.set(&bob, chain.key_file_logged(&past));
    assert_eq!(ids.auth(&device).await.1, ["ERR auth-failed"]);
    // The log cannot be reached: an outage. (A file read before is not
    // checked again: logs never remove entries.)
    let first = |i: usize| (i == 0).then(|| indices[0]);
    ids.fetcher.set(&bob, chain.key_file_logged(&first));
    ids.fetcher.fail_log("https://example.net/risala-log/1");
    assert!(ids.auth(&device).await.1[0].starts_with("ERR unavailable"));
}

// ---------------------------------------------------------------------------
// KEYS PUT (4.7)

/// KEYS PUT adds records to a hosted chain, logs them, answers RECORD
/// lines, and republishes the key file; the same records again get OK
/// and no lines (4.7).
#[tokio::test]
async fn keys_put_hosted() {
    let mut ids = Ids::new();
    let (mut alice, mut chain, _device) = ids.register("alice").await;
    let phone = chain.add_device("phone");
    let line = chain.keys_put_line(2);
    ids.h.send(&alice, &line).await;
    let hash = chain.head().hash();
    assert_eq!(alice.lines(), [format!("RECORD 2 {hash}"), "OK".into()]);
    ids.h.send(&alice, &line).await;
    assert_eq!(alice.lines(), ["OK"]);
    // The whole chain again is the same.
    ids.h.send(&alice, &chain.keys_put_line(0)).await;
    assert_eq!(alice.lines(), ["OK"]);
    assert_eq!(ids.read_hosted(&chain).records(), chain.records());
    tokio::time::sleep(Duration::from_millis(50)).await;
    let HostedKeyFile::File(served) = ids.hosted("alice") else {
        panic!()
    };
    assert_eq!(ids.publisher.get("alice"), Some(served));
    // The new device signs in.
    assert_eq!(ids.auth(&phone).await.1, ["OK uid=alice@example.org"]);
}

/// KEYS PUT works on new, anonymous and signed-in connections (4.7, 13).
#[tokio::test]
async fn keys_put_on_every_kind() {
    let mut ids = Ids::new();
    let (_alice, mut chain, _) = ids.register("alice").await;
    chain.add_device("a");
    let (mut new, _) = ids.connect();
    ids.h.send(&new, &chain.keys_put_line(2)).await;
    assert_eq!(new.lines().last().unwrap(), "OK");
    chain.add_device("b");
    let mut anon = ids.h.anon().await;
    ids.h.send(&anon, &chain.keys_put_line(3)).await;
    assert_eq!(anon.lines().last().unwrap(), "OK");
    chain.add_device("c");
    let mut signed = ids.h.signed_in_as("carol@example.net");
    ids.h.send(&signed, &chain.keys_put_line(4)).await;
    assert_eq!(signed.lines().last().unwrap(), "OK");
    let (mut guest, _) = ids.h.guest("sam").await;
    ids.h.send(&guest, &chain.keys_put_line(4)).await;
    assert_eq!(guest.lines(), ["ERR wrong-connection"]);
    assert_eq!(ids.read_hosted(&chain).len(), 5);
}

/// KEYS PUT's errors (4.7).
#[tokio::test]
async fn keys_put_errors() {
    let mut ids = Ids::new();
    let (mut alice, chain, _) = ids.register("alice").await;
    // `<after>` names a record the server does not hold.
    let mut other = chain.clone();
    other.add_device("x");
    let mut forked = chain.clone();
    forked.add_device("y");
    let line = format!(
        "KEYS PUT {} {}",
        forked.head().hash(),
        TestChain::payload(&other.records()[2..])
    );
    ids.h.send(&alice, &line).await;
    assert!(alice.lines()[0].starts_with("ERR not-found"));
    // A fork: another record after the same one.
    ids.h.send(&alice, &other.keys_put_line(2)).await;
    assert_eq!(alice.lines().last().unwrap(), "OK");
    ids.h.send(&alice, &forked.keys_put_line(2)).await;
    assert!(alice.lines()[0].starts_with("ERR forbidden"));
    // A record whose signature does not verify.
    let mut bad = other.clone();
    bad.add_device("z");
    let mut bytes = bad.head().encoded().to_vec();
    let n = bytes.len();
    bytes[n - 1] ^= 1;
    let broken = risala_proto::record::Record::decode(&bytes).unwrap();
    let line = format!(
        "KEYS PUT {} {}",
        other.head().hash(),
        TestChain::payload(&[broken])
    );
    ids.h.send(&alice, &line).await;
    assert!(alice.lines()[0].starts_with("ERR invalid"));
    // Not records.
    ids.h.send(&alice, "KEYS PUT - AAAA").await;
    assert!(alice.lines()[0].starts_with("ERR invalid"));
    // A blob that is not held.
    let blob = risala_proto::names::BlobRef::of(b"nothing");
    ids.h.send(&alice, &format!("KEYS PUT - {blob}")).await;
    assert!(alice.lines()[0].starts_with("ERR not-found"));
    // An identity at the identity domain that is not registered here.
    let (carol, _) = TestChain::new("carol@example.org", &ids.log().log);
    ids.h.send(&alice, &carol.keys_put_line(0)).await;
    assert!(alice.lines()[0].starts_with("ERR forbidden"));
    // A chain that names another log.
    let (dave, _) = outside("dave");
    ids.h.send(&alice, &dave.keys_put_line(0)).await;
    assert!(alice.lines()[0].starts_with("ERR not-supported"));
}

/// Another server's identity whose key file names this log may log its
/// chain here; one whose key file does not name it, or does not list
/// the records, may not (4.7).
#[tokio::test]
async fn keys_put_outside_identity() {
    let mut ids = Ids::new();
    let (mut chain, device) = TestChain::new("erin@example.net", &ids.log().log);
    let erin = chain.identity().clone();
    let mut anon = ids.h.anon().await;
    // No key file: forbidden.
    ids.h.send(&anon, &chain.keys_put_line(0)).await;
    assert!(anon.lines()[0].starts_with("ERR forbidden"));
    // A key file that lists the records unlogged.
    ids.fetcher.set(&erin, chain.key_file());
    ids.h.send(&anon, &chain.keys_put_line(0)).await;
    let lines = anon.lines();
    assert_eq!(
        lines,
        [
            format!("RECORD 0 {}", chain.records()[0].hash()),
            format!("RECORD 1 {}", chain.records()[1].hash()),
            "OK".into()
        ]
    );
    // A new record that the key file does not list: forbidden.
    chain.add_device("phone");
    ids.h.send(&anon, &chain.keys_put_line(2)).await;
    assert!(anon.lines()[0].starts_with("ERR forbidden"));
    // Once listed by index, the key file reads from this log, and the
    // identity signs in.
    let logged = |i: usize| (i < 2).then_some(i as u64);
    ids.fetcher.set(&erin, chain.key_file_logged(&logged));
    ids.h.send(&anon, &chain.keys_put_line(2)).await;
    assert_eq!(anon.lines().len(), 2);
    let all = |i: usize| (i < 3).then_some(i as u64);
    ids.fetcher.set(&erin, chain.key_file_logged(&all));
    assert_eq!(ids.auth(&device).await.1, ["OK uid=erin@example.net"]);
    // A key file whose last log line names another log: forbidden.
    let elsewhere = test_log_key("example.net", 2, [9; 32]);
    chain.move_to(&elsewhere);
    let moved = chain.key_file_logged(&all);
    ids.fetcher.set(&erin, moved.as_bytes());
    ids.h.send(&anon, &chain.keys_put_line(3)).await;
    assert!(anon.lines()[0].starts_with("ERR forbidden"));
}

/// Removing a device by record closes its connections, and `retire`
/// closes them all (4.4, 4.9).
#[tokio::test]
async fn keys_put_closes_removed_devices() {
    let mut ids = Ids::new();
    let (mut alice, mut chain, device) = ids.register("alice").await;
    let phone = chain.add_device("phone");
    ids.h.send(&alice, &chain.keys_put_line(2)).await;
    alice.lines();
    let (mut phone_conn, lines) = ids.auth(&phone).await;
    assert_eq!(lines, ["OK uid=alice@example.org"]);
    // The phone has a KeyPackage, which goes with it (12.8).
    use crate::store::KeysStore as _;
    use crate::store::keys::NewKeyPackage;
    let uid: Uid = "alice@example.org".parse().unwrap();
    let phone_id = *risala_proto::record::DeviceId::of(&phone.public_key()).as_bytes();
    let now = ids.h.inner().now();
    ids.h
        .store
        .add_key_package(
            &NewKeyPackage {
                uid: uid.clone(),
                device: phone_id,
                key_package_ref: [1; 48],
                key_package: vec![1, 2, 3],
                last_resort: true,
                not_after: Timestamp::MAX,
            },
            10,
            now,
        )
        .unwrap();
    let held = |ids: &Ids| {
        ids.h
            .store
            .count_key_packages(&uid, &phone_id, now)
            .unwrap()
            .last_resort
    };
    assert!(held(&ids));
    chain.remove_devices(&[&phone]);
    ids.h.send(&alice, &chain.keys_put_line(3)).await;
    assert_eq!(alice.lines().last().unwrap(), "OK");
    assert_eq!(
        phone_conn.lines(),
        [format!("<close> BYE {}", crate::core::BYE_KEYS_CHANGED)]
    );
    assert!(!held(&ids));
    assert_eq!(ids.auth(&phone).await.1, ["ERR auth-failed"]);
    let (mut again, _) = ids.auth(&device).await;
    again.lines();
    chain.retire();
    let (mut new, _) = ids.connect();
    ids.h.send(&new, &chain.keys_put_line(4)).await;
    assert_eq!(new.lines().last().unwrap(), "OK");
    assert_eq!(
        again.lines(),
        [format!("<close> BYE {}", crate::core::BYE_KEYS_CHANGED)]
    );
    assert_eq!(ids.auth(&device).await.1, ["ERR auth-failed"]);
}

// ---------------------------------------------------------------------------
// Server bans (10.2), presence (8.3) and push (9.1), from the misc and
// admin areas

/// AUTH and REGISTER answer `forbidden` for a banned identity, but only
/// once its signature verifies (10.2). Signing in tells presence (8.3),
/// and UNREGISTER deletes the account's push subscriptions (9.1).
#[tokio::test]
async fn bans_presence_and_push_at_sign_in() {
    use crate::core::misc::presence::presence_of;
    use crate::store::{MiscStore as _, PushTarget};
    use risala_proto::types::Presence;

    let mut ids = Ids::new();
    let (_alice, _chain, device) = ids.register("alice").await;
    let mut op = ids.h.signed_in_as("op@example.org");
    ids.h.send(&op, "ADMIN BAN alice@example.org").await;
    ids.h.send(&op, "ADMIN BAN bob@example.org").await;
    assert_eq!(op.lines(), ["OK", "OK"]);
    let (_, lines) = ids.auth(&device).await;
    assert_eq!(lines, ["ERR forbidden"]);
    // A key that does not verify hears auth-failed, not that it is banned.
    let (_, lines) = ids.auth(&TestIdentity::new("alice@example.org")).await;
    assert_eq!(lines, ["ERR auth-failed"]);
    let (chain, bob) = TestChain::new("bob@example.org", &ids.log().log);
    let (mut c, nonce) = ids.connect();
    ids.h
        .send(&c, &chain.register_line(&bob, "chat.example.org", &nonce))
        .await;
    assert_eq!(c.lines(), ["ERR forbidden"]);

    // Unbanned, Alice signs in, and is online for whoever watches, since
    // her presence is on.
    ids.h.send(&op, "ADMIN UNBAN alice@example.org").await;
    assert_eq!(op.lines(), ["OK"]);
    let uid: Uid = "alice@example.org".parse().unwrap();
    ids.h.store.set_presence(&uid, true).unwrap();
    let (mut alice, lines) = ids.auth(&device).await;
    assert_eq!(lines, ["OK uid=alice@example.org"]);
    assert_eq!(presence_of(ids.h.inner(), &uid), Presence::Online);

    // Her account subscription goes when she unregisters.
    let keys = super::misc::Keys::new();
    ids.h
        .send(
            &alice,
            &format!("PUSH ADD https://p.example/a t {} {}", keys.key, keys.auth),
        )
        .await;
    assert_eq!(alice.lines(), ["OK"]);
    let target = PushTarget::Device {
        uid: uid.clone(),
        device: risala_proto::record::DeviceId::of(&device.public_key()),
    };
    let now = T.parse().unwrap();
    assert_eq!(
        ids.h.store.push_subscriptions(&target, now).unwrap().len(),
        1
    );
    ids.h.send(&alice, "UNREGISTER alice@example.org").await;
    assert!(
        ids.h
            .store
            .push_subscriptions(&target, now)
            .unwrap()
            .is_empty()
    );
    assert!(!ids.h.store.presence_on(&uid).unwrap());
}

// UNREGISTER (4.9) and ADMIN UNREGISTER (10.5)

/// UNREGISTER must name the connection's own identity; it deletes the
/// identity, answers OK, then closes all of its connections; a hosted key
/// file then answers 410 (4.9).
#[tokio::test]
async fn unregister() {
    let mut ids = Ids::new();
    let (mut alice, _chain, device) = ids.register("alice").await;
    let (mut other, _) = ids.auth(&device).await;
    ids.h.send(&alice, "UNREGISTER bob@example.org").await;
    assert!(alice.lines()[0].starts_with("ERR forbidden"));
    ids.h.send(&alice, "UNREGISTER alice@example.org").await;
    ids.h.send(&alice, "PING").await;
    assert_eq!(
        alice.lines(),
        [
            "OK",
            &format!("<close> BYE {}", crate::core::BYE_UNREGISTERED)
        ]
    );
    assert_eq!(
        other.lines(),
        [format!("<close> BYE {}", crate::core::BYE_UNREGISTERED)]
    );
    assert_eq!(ids.hosted("alice"), HostedKeyFile::Gone);
    assert!(
        !ids.h
            .store
            .knows(&"alice@example.org".parse().unwrap())
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(ids.publisher.get("alice"), None);
    // Its keys are missing now.
    assert_eq!(ids.auth(&device).await.1, ["ERR auth-failed"]);
    // UNREGISTER is for signed-in connections only.
    let mut anon = ids.h.anon().await;
    ids.h.send(&anon, "UNREGISTER alice@example.org").await;
    assert_eq!(anon.lines(), ["ERR wrong-connection"]);
}

/// A hosted identity whose chain ends with `retire` keeps its key file
/// after UNREGISTER, so that contacts learn of it (4.9).
#[tokio::test]
async fn unregister_after_retire_keeps_the_key_file() {
    let mut ids = Ids::new();
    let (mut alice, mut chain, _) = ids.register("alice").await;
    chain.retire();
    ids.h.send(&alice, &chain.keys_put_line(2)).await;
    assert_eq!(alice.lines().last().unwrap(), "OK");
    let mut op = ids.h.signed_in_as("op@example.org");
    ids.h.send(&op, "ADMIN UNREGISTER alice@example.org").await;
    assert_eq!(op.lines(), ["OK"]);
    let read = ids.read_hosted(&chain);
    assert!(read.is_retired());
}

/// ADMIN UNREGISTER deletes a hosted identity and closes its connections;
/// an unknown uid gets not-found; others get forbidden (10.5).
#[tokio::test]
async fn admin_unregister() {
    let mut ids = Ids::new();
    let (mut alice, _, _) = ids.register("alice").await;
    let mut someone = ids.h.signed_in_as("someone@example.net");
    ids.h
        .send(&someone, "ADMIN UNREGISTER alice@example.org")
        .await;
    assert_eq!(someone.lines(), ["ERR forbidden"]);
    let mut op = ids.h.signed_in_as("op@example.org");
    ids.h.send(&op, "ADMIN UNREGISTER alice@example.org").await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(
        alice.lines(),
        [format!("<close> BYE {}", crate::core::BYE_UNREGISTERED)]
    );
    assert_eq!(ids.hosted("alice"), HostedKeyFile::Gone);
    ids.h.send(&op, "ADMIN UNREGISTER alice@example.org").await;
    assert_eq!(op.lines(), ["ERR not-found"]);
    ids.h.send(&op, "ADMIN UNREGISTER nobody@example.net").await;
    assert_eq!(op.lines(), ["ERR not-found"]);
    // The name stays taken (10.5).
    let (chain, device) = TestChain::new("alice@example.org", &ids.log().log);
    let (mut c, nonce) = ids.connect();
    ids.h
        .send(
            &c,
            &chain.register_line(&device, "chat.example.org", &nonce),
        )
        .await;
    assert_eq!(c.lines(), ["ERR name-taken"]);
}

// ---------------------------------------------------------------------------
// PAIR (4.8)

const PAIR_ID: &str = "ujzdegxdncf32epf3dhodzdoci";

/// PAIR PUT stores data for 10 minutes; the same data again gets OK, other
/// data `name-taken`; PAIR GET answers a PAIR line, or `not-found` (4.8).
#[tokio::test]
async fn pair_put_and_get() {
    let mut ids = Ids::new();
    let data = format!("{}AA==", "A".repeat(8000));
    let (mut new, _) = ids.connect();
    ids.h.send(&new, &format!("PAIR GET {PAIR_ID}")).await;
    assert_eq!(new.lines(), ["ERR not-found"]);
    ids.h
        .send(&new, &format!("PAIR PUT {PAIR_ID} {data}"))
        .await;
    assert_eq!(new.lines(), ["OK"]);
    ids.h
        .send(&new, &format!("PAIR PUT {PAIR_ID} {data}"))
        .await;
    assert_eq!(new.lines(), ["OK"]);
    ids.h.send(&new, &format!("PAIR PUT {PAIR_ID} BBBB")).await;
    assert_eq!(new.lines(), ["ERR name-taken"]);
    let mut anon = ids.h.anon().await;
    ids.h.send(&anon, &format!("PAIR GET {PAIR_ID}")).await;
    assert_eq!(
        anon.lines(),
        [format!("PAIR {PAIR_ID} {data}"), "OK".into()]
    );
    let mut signed = ids.h.signed_in_as("alice@example.org");
    ids.h
        .send(&signed, &format!("PAIR GET {}", PAIR_ID.to_uppercase()))
        .await;
    assert_eq!(signed.lines().len(), 2);
    let (mut guest, _) = ids.h.guest("sam").await;
    ids.h.send(&guest, &format!("PAIR GET {PAIR_ID}")).await;
    assert_eq!(guest.lines(), ["ERR wrong-connection"]);

    // After 10 minutes it is gone, and the id may hold other data.
    ids.h.clock.advance(Duration::from_secs(10 * 60));
    ids.h.send(&anon, &format!("PAIR GET {PAIR_ID}")).await;
    assert_eq!(anon.lines(), ["ERR not-found"]);
    ids.h.send(&anon, &format!("PAIR PUT {PAIR_ID} BBBB")).await;
    assert_eq!(anon.lines(), ["OK"]);
    // Only the hash of the id is kept (Section 14).
    let stored: Vec<Vec<u8>> = {
        let conn = ids.h.store.raw();
        let mut select = conn.prepare("SELECT id_hash FROM pairing").unwrap();
        select
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let id: risala_proto::names::PairId = PAIR_ID.parse().unwrap();
    assert!(
        stored
            .iter()
            .all(|h| h.len() == 48 && h[..16] != id.as_bytes()[..])
    );
}

/// PAIR PUT is limited per address and in size.
#[tokio::test]
async fn pair_limits() {
    let mut ids = Ids::new();
    let mut anon = ids.h.anon().await;
    let big = format!(
        "{}AA==",
        "A".repeat(crate::core::identity::MAX_PAIR_DATA / 3 * 4 + 4)
    );
    ids.h
        .send(&anon, &format!("PAIR PUT {PAIR_ID} {big}"))
        .await;
    assert!(anon.lines()[0].starts_with("ERR too-long"));
    for n in 0..crate::core::identity::PAIR_PUTS_PER_WINDOW {
        let id = risala_proto::names::PairId::from_bytes([u8::try_from(n).unwrap(); 16]);
        ids.h.send(&anon, &format!("PAIR PUT {id} AAAA")).await;
        assert_eq!(anon.lines(), ["OK"], "{n}");
    }
    ids.h.send(&anon, &format!("PAIR PUT {PAIR_ID} AAAA")).await;
    assert!(anon.raw_lines()[0].ends_with("ERR rate-limited"));
}

// ---------------------------------------------------------------------------
// Limits on KEYS PUT and AUTH (4.4, 4.6, 4.7)

/// KEYS PUT is limited per network address (4.7: MUST), and every one
/// whose records decode uses up a slot.
#[tokio::test]
async fn keys_put_is_rate_limited() {
    let mut config = id_config();
    config.limits.keys_puts_per_hour = 2;
    let mut ids = Ids::with(config);
    let (chain, _) = TestChain::new("erin@example.net", &ids.log().log);
    ids.fetcher.set(chain.identity(), chain.key_file());
    let mut anon = ids.h.anon().await;
    ids.h.send(&anon, &chain.keys_put_line(0)).await;
    assert_eq!(anon.lines().last().unwrap(), "OK");
    // Records the server has: OK, but a slot all the same.
    ids.h.send(&anon, &chain.keys_put_line(0)).await;
    assert_eq!(anon.lines(), ["OK"]);
    ids.h.send(&anon, &chain.keys_put_line(0)).await;
    assert!(anon.lines()[0].ends_with("ERR rate-limited"));
    // Another network address has its own.
    let mut far = ids.h.connect_from("198.51.100.9:4000");
    ids.h.send(&far, "ANON").await;
    ids.h.send(&far, &chain.keys_put_line(0)).await;
    assert_eq!(far.lines(), ["OK", "OK"]);
}

/// A KEYS PUT whose records are a blob uses up its slot once the server
/// has read the blob, even if the blob holds no records (4.7, PLAN item
/// 63); one whose blob the server does not hold does not.
#[tokio::test]
async fn keys_put_uses_a_slot_for_any_blob_read() {
    let mut config = id_config();
    config.limits.keys_puts_per_hour = 2;
    let mut ids = Ids::with(config);
    let mut anon = ids.h.anon().await;
    let missing = risala_proto::names::BlobRef::of(b"not held");
    for _ in 0..3 {
        ids.h.send(&anon, &format!("KEYS PUT - {missing}")).await;
        assert!(anon.lines()[0].starts_with("ERR not-found"));
    }
    let junk = hold_blob(&ids.h, b"no records here", None);
    for _ in 0..2 {
        ids.h.send(&anon, &format!("KEYS PUT - {junk}")).await;
        assert!(anon.lines()[0].starts_with("ERR invalid"));
    }
    ids.h.send(&anon, &format!("KEYS PUT - {junk}")).await;
    assert!(anon.lines()[0].ends_with("ERR rate-limited"));
}

/// The server logs so many new outside identities a day per registered
/// domain, and none if it logs only those it hosts (4.5, 4.7).
#[tokio::test]
async fn outside_identities_are_limited() {
    let mut config = id_config();
    config.limits.outside_identities_per_day = 1;
    let mut ids = Ids::with(config);
    let log = ids.log().log;
    let (mut erin, _) = TestChain::new("erin@example.net", &log);
    let (frank, _) = TestChain::new("frank@sub.example.net", &log);
    let (gina, _) = TestChain::new("gina@example.com", &log);
    for chain in [&erin, &frank, &gina] {
        ids.fetcher.set(chain.identity(), chain.key_file());
    }
    let mut anon = ids.h.anon().await;
    ids.h.send(&anon, &erin.keys_put_line(0)).await;
    assert_eq!(anon.lines().last().unwrap(), "OK");
    // A second new identity under example.net today.
    ids.h.send(&anon, &frank.keys_put_line(0)).await;
    assert!(anon.lines()[0].ends_with("ERR rate-limited"));
    // Another registered domain, and more records of one already logged.
    ids.h.send(&anon, &gina.keys_put_line(0)).await;
    assert_eq!(anon.lines().last().unwrap(), "OK");
    erin.add_device("phone");
    ids.fetcher.set(erin.identity(), erin.key_file());
    ids.h.send(&anon, &erin.keys_put_line(2)).await;
    assert_eq!(anon.lines().last().unwrap(), "OK");
    // A day later, another.
    ids.h.clock.advance(Duration::from_secs(24 * 60 * 60));
    ids.h.send(&anon, &frank.keys_put_line(0)).await;
    assert_eq!(anon.lines().last().unwrap(), "OK");

    // A server that logs only the identities it hosts.
    let mut config = id_config();
    config.limits.log_outside_identities = false;
    let mut ids = Ids::with(config);
    let (erin, _) = TestChain::new("erin@example.net", &ids.log().log);
    ids.fetcher.set(erin.identity(), erin.key_file());
    let mut anon = ids.h.anon().await;
    ids.h.send(&anon, &erin.keys_put_line(0)).await;
    assert!(anon.lines()[0].starts_with("ERR not-supported"));
    assert!(ids.fetcher.calls().is_empty());
}

/// KEYS PUT fetches an outside identity's key file without holding the
/// lock that REGISTER, KEYS PUT and UNREGISTER take, so a slow key server
/// holds up nobody else (4.7).
#[tokio::test]
async fn keys_put_fetches_outside_the_lock() {
    let mut ids = Ids::new();
    let (chain, _) = TestChain::new("erin@example.net", &ids.log().log);
    let held = ids.fetcher.hold(chain.identity(), chain.key_file());
    let mut anon = ids.h.anon().await;
    let (alice, device) = TestChain::new("alice@example.org", &ids.log().log);
    let (mut c, nonce) = ids.connect();
    let register = alice.register_line(&device, "chat.example.org", &nonce);
    let h = &ids.h;
    let put = chain.keys_put_line(0);
    let both = async {
        tokio::join!(h.send(&anon, &put), async {
            // REGISTER finishes while KEYS PUT waits for the key file.
            h.send(&c, &register).await;
            held.notify_one();
        })
    };
    tokio::time::timeout(Duration::from_secs(10), both)
        .await
        .expect("REGISTER waited for KEYS PUT's fetch");
    assert_eq!(c.lines(), ["OK uid=alice@example.org"]);
    assert_eq!(anon.lines().last().unwrap(), "OK");
}

/// AUTHs that may fetch a key file are limited per network address; a
/// hosted identity's are not (4.4, 4.6).
#[tokio::test]
async fn fetching_auths_are_rate_limited() {
    let mut config = id_config();
    config.limits.fetching_auths_per_hour = 1;
    let mut ids = Ids::with(config);
    let (chain, device) = outside("bob");
    ids.fetcher.set(chain.identity(), chain.key_file());
    assert_eq!(ids.auth(&device).await.1, ["OK uid=bob@example.net"]);
    let lines = ids.auth(&device).await.1;
    assert!(lines[0].ends_with("ERR rate-limited"), "{lines:?}");
    let (_, _, alice) = ids.register("alice").await;
    assert_eq!(ids.auth(&alice).await.1, ["OK uid=alice@example.org"]);
}
