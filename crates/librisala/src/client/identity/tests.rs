//! Tests of the identity area, against an in-memory world: a fake risala
//! server over TLS that answers INFO, REGISTER, AUTH, KEYS PUT, PAIR and
//! UNREGISTER the way 4.6-4.9 say, backed by a key log in memory
//! (`risala-keylog`'s `MemoryLog`) with three witnesses, and the key files
//! and the log served through [`Https`].
//!
//! The server tasks SV1 and SV2 had not landed when these were written,
//! so the server is a fake built from `risala-proto`'s chain checks
//! (`check_register`, `keys_put`); task C5 runs the end-to-end tests
//! against `risalad`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use risala_keylog::checkpoint::{LogOrigin, SignedCheckpoint};
use risala_keylog::testlog::{MemoryLog, TestWitness};
use risala_keylog::witnessing::WitnessConfig;
use risala_proto::auth::{Nonce, SecretKey};
use risala_proto::chain::{Chain, NoHandoffs, check_register, keys_put};
use risala_proto::command::{Command, KeysPutRecords, PairCommand, Request};
use risala_proto::content::ContentLine;
use risala_proto::keyfile::KeyFile;
use risala_proto::names::{BlobRef, Identity};
use risala_proto::record::{LogKey, Record, RecordBody, RecordContent, decode_records};

use super::*;
use crate::client::ClientOptions;
use crate::clock::{Clock as _, ManualClock};
use crate::conn::tests::server::{Peer, ScriptServer, TestCa};
use crate::conn::{Session, SessionOptions, roots_ca_verifier};
use crate::keys::KeyNames;

const HOST: &str = "chat.test";
const DOMAIN: &str = "example.test";
const LOG_URL: &str = "https://chat.test/risala-log/1";
const NONCE: &str = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e";
/// 2026-11-09, in ms.
const START: u64 = 1_794_182_400_000;

/// The world the client talks to: the server's state, its key log and
/// witnesses, the key files it hosts, and anything a test overrides.
struct World {
    clock: ManualClock,
    log: MemoryLog,
    witnesses: Vec<TestWitness>,
    /// The checkpoint the log serves, with cosignatures.
    checkpoint: SignedCheckpoint,
    /// Whether new records get a witnessed checkpoint at once.
    witness_at_once: bool,
    /// The chains the server holds, by uid.
    chains: HashMap<String, Chain>,
    /// Log indices of records, by hash.
    indices: HashMap<BlobRef, u64>,
    /// Hosted key files, by name, and whether to keep them as they are.
    key_files: HashMap<String, Vec<u8>>,
    frozen: bool,
    /// The relay's data.
    pairs: HashMap<String, String>,
    /// URLs that answer something else.
    overrides: HashMap<String, Fetched>,
    /// Every URL fetched.
    fetched: Vec<String>,
    /// The host's second log, after a hand-off, with its checkpoint.
    second: Option<(MemoryLog, SignedCheckpoint)>,
}

fn origin() -> LogOrigin {
    LogOrigin::new(HOST, 1).unwrap()
}

fn witness(i: u8) -> TestWitness {
    TestWitness::with_config(
        &format!("w{i}.test"),
        &[0x40 + i; 32],
        WitnessConfig {
            min_interval: 0,
            new_hosts: None,
            ..WitnessConfig::default()
        },
    )
}

impl World {
    fn new(clock: ManualClock) -> World {
        let log = MemoryLog::new(&origin(), &[7; 32]);
        let mut world = World {
            clock,
            checkpoint: log.checkpoint(1),
            log,
            witnesses: (1..=3).map(witness).collect(),
            witness_at_once: true,
            chains: HashMap::new(),
            indices: HashMap::new(),
            key_files: HashMap::new(),
            frozen: false,
            pairs: HashMap::new(),
            overrides: HashMap::new(),
            fetched: Vec::new(),
            second: None,
        };
        world.publish();
        world
    }

    fn now_s(&self) -> u64 {
        self.clock.now().unix_millis() / 1000
    }

    /// The log's key, as key files name it.
    fn log_key(&self) -> LogKey {
        LogKey::from_vkey(&self.log.vkey().to_string()).unwrap()
    }

    fn witness_vkeys(&self) -> Vec<String> {
        self.witnesses
            .iter()
            .map(|w| w.vkey().to_string())
            .collect()
    }

    /// A new checkpoint of the whole log, cosigned by the witnesses now.
    fn publish(&mut self) {
        let ts = self.now_s().max(1);
        let mut cp = self.log.checkpoint(ts);
        let results = self.log.witness(&mut cp, &mut self.witnesses, ts);
        assert!(results.iter().all(Result::is_ok), "{results:?}");
        self.checkpoint = cp;
    }

    /// Writes the hosted key file of `uid` from the chain held.
    fn write_key_file(&mut self, uid: &str) {
        if self.frozen {
            return;
        }
        let chain = &self.chains[uid];
        let indices = &self.indices;
        let file =
            KeyFile::from_chain(chain, &|i| indices.get(&chain.records()[i].hash()).copied())
                .unwrap();
        let name = uid.split('@').next().unwrap().to_owned();
        self.key_files.insert(name, file.to_text().into_bytes());
    }

    fn append(&mut self, uid: &str, record: &Record) -> u64 {
        let index = self.log.append_record(uid, record.encoded());
        self.indices.insert(record.hash(), index);
        index
    }

    fn after_append(&mut self, uid: &str) {
        self.write_key_file(uid);
        if self.witness_at_once {
            self.publish();
        }
    }

    fn get(&mut self, url: &str) -> Fetched {
        self.fetched.push(url.to_owned());
        if let Some(f) = self.overrides.get(url) {
            return f.clone();
        }
        let well_known = format!("https://{DOMAIN}/.well-known/risala/");
        if let Some(name) = url.strip_prefix(&well_known) {
            return match self.key_files.get(name) {
                Some(body) => Fetched::Body(body.clone()),
                None => Fetched::Gone(404),
            };
        }
        if let Some((log, checkpoint)) = &self.second
            && let Some(path) = url.strip_prefix(&format!("https://{}/", log.origin()))
        {
            if path == "checkpoint" {
                return Fetched::Body(checkpoint.to_text().into_bytes());
            }
            return match log.serve(path) {
                Some(body) => Fetched::Body(body),
                None => Fetched::Gone(404),
            };
        }
        if let Some(path) = url.strip_prefix(&format!("{LOG_URL}/")) {
            if path == "checkpoint" {
                return Fetched::Body(self.checkpoint.to_text().into_bytes());
            }
            return match self.log.serve(path) {
                Some(body) => Fetched::Body(body),
                None => Fetched::Gone(404),
            };
        }
        Fetched::Failed(format!("no such host: {url}"))
    }

    /// The server's answer to one request line.
    fn answer(&mut self, line: &str, sni: &str) -> Vec<String> {
        let request: Request = line.parse().expect("a request");
        let r = request
            .ref_
            .map(|r| format!("@ref={r} "))
            .unwrap_or_default();
        let ok = |extra: &str| vec![format!("{r}OK{extra}")];
        let err = |code: &str| vec![format!("{r}ERR {code}")];
        match request.command {
            Command::Info { .. } => ok(&format!(
                " register={DOMAIN} log={LOG_URL} log-key={}",
                self.log.vkey()
            )),
            Command::Register {
                name,
                records,
                signature,
            } => {
                let uid: Identity = format!("{name}@{DOMAIN}").parse().unwrap();
                let records = decode_records(&records.decode()).unwrap();
                if self.chains.contains_key(uid.as_str()) {
                    return err("name-taken");
                }
                let Ok(chain) = check_register(&uid, &records, &self.log_key()) else {
                    return err("invalid");
                };
                let key = &chain.devices().values().next().unwrap().keys.device_key;
                let nonce: Nonce = NONCE.parse().unwrap();
                if !key.verify_challenge(sni, &nonce, uid.as_str(), &signature) {
                    return err("auth-failed");
                }
                for record in &records {
                    self.append(uid.as_str(), record);
                }
                self.chains.insert(uid.as_str().to_owned(), chain);
                self.after_append(uid.as_str());
                ok(&format!(" uid={uid}"))
            }
            Command::Auth {
                identity,
                signature,
            } => {
                let nonce: Nonce = NONCE.parse().unwrap();
                let ok_key = self.chains.get(identity.as_str()).is_some_and(|c| {
                    c.devices().values().any(|d| {
                        d.keys.device_key.verify_challenge(
                            sni,
                            &nonce,
                            identity.as_str(),
                            &signature,
                        )
                    })
                });
                if ok_key {
                    ok(&format!(" uid={identity}"))
                } else {
                    err("auth-failed")
                }
            }
            Command::KeysPut { after, records } => {
                let KeysPutRecords::Inline(records) = records else {
                    return err("not-supported");
                };
                let Ok(records) = decode_records(&records.decode()) else {
                    return err("invalid");
                };
                let uid = records[0].content().uid.as_str().to_owned();
                let held = self.chains.get(&uid);
                match keys_put(held, after.as_ref(), &records, &self.log_key(), &NoHandoffs) {
                    Ok(put) => {
                        let mut out = Vec::new();
                        for i in &put.to_append {
                            let record = put.chain.records()[*i].clone();
                            let index = self.append(&uid, &record);
                            out.push(format!("{r}RECORD {index} {}", record.hash()));
                        }
                        self.chains.insert(uid.clone(), put.chain);
                        self.after_append(&uid);
                        out.push(format!("{r}OK"));
                        out
                    }
                    Err(e) => err(match e {
                        risala_proto::chain::KeysPutError::NotFound => "not-found",
                        risala_proto::chain::KeysPutError::Forbidden => "forbidden",
                        _ => "invalid",
                    }),
                }
            }
            Command::Pair(PairCommand::Put { id, data }) => match self.pairs.get(&id.to_string()) {
                Some(held) if *held != data.to_string() => err("name-taken"),
                _ => {
                    self.pairs.insert(id.to_string(), data.to_string());
                    ok("")
                }
            },
            Command::Pair(PairCommand::Get { id }) => match self.pairs.get(&id.to_string()) {
                Some(data) => vec![format!("{r}PAIR {id} {data}"), format!("{r}OK")],
                None => err("not-found"),
            },
            Command::Unregister { .. } => ok(""),
            Command::Quit { .. } => vec![format!("{r}OK")],
            other => panic!("the fake server does not know {other:?}"),
        }
    }
}

/// HTTPS from the world.
struct WorldHttps(Arc<Mutex<World>>);

impl Https for WorldHttps {
    fn get<'a>(&'a self, url: &'a str, _max: usize) -> crate::conn::BoxFuture<'a, Fetched> {
        let got = self.0.lock().unwrap().get(url);
        Box::pin(async move { got })
    }
}

/// The world with a fake server running.
struct Setup {
    world: Arc<Mutex<World>>,
    clock: ManualClock,
    ca: TestCa,
    server: ScriptServer,
}

impl Setup {
    async fn new() -> Setup {
        let clock = ManualClock::new(START);
        let world = Arc::new(Mutex::new(World::new(clock.clone())));
        let ca = TestCa::new();
        let w = world.clone();
        let server = ScriptServer::start(ca.issue(HOST), 10_000, move |_, peer: Peer| {
            serve(w.clone(), peer)
        })
        .await;
        Setup {
            world,
            clock,
            ca,
            server,
        }
    }

    /// A client of this world, with the world's witnesses as its policy.
    fn client(&self) -> Client {
        let options = ClientOptions {
            ca_verifier: Some(roots_ca_verifier([self.ca.cert.clone()]).unwrap()),
            session: SessionOptions {
                connect_to: Some(self.server.addr),
                ..Default::default()
            },
            clock: Arc::new(self.clock.clone()),
            https: Some(Arc::new(WorldHttps(self.world.clone()))),
            ..ClientOptions::default()
        };
        let c = Client::open_in_memory(options).unwrap();
        let vkeys = self.world.lock().unwrap().witness_vkeys();
        c.set_witness_policy(&vkeys, 2).unwrap();
        c
    }

    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    /// A client with a new identity `name@example.test`, and its recovery
    /// key.
    async fn identity(&self, name: &str) -> (Client, String, String) {
        let c = self.client();
        let new = c.create_identity(HOST, name, "laptop").await.unwrap();
        (c, new.uid.to_string(), new.recovery_key.to_string())
    }
}

async fn serve(world: Arc<Mutex<World>>, mut peer: Peer) {
    peer.send(&format!("RISALA 1 {HOST} {NONCE} welcome")).await;
    let sni = peer.sni.clone().unwrap_or_default();
    while let Some(line) = peer.recv().await {
        let quit = line.contains("QUIT");
        let out = world.lock().unwrap().answer(&line, &sni);
        for l in out {
            peer.send(&l).await;
        }
        if quit {
            break;
        }
    }
}

fn id(uid: &str) -> Identity {
    uid.parse().unwrap()
}

#[tokio::test]
async fn creating_an_identity() {
    let s = Setup::new().await;
    let (c, uid, recovery) = s.identity("alice").await;
    assert_eq!(uid, "alice@example.test");
    // 52 characters of base32 in groups of four (4.8).
    assert_eq!(recovery.len(), 52 + 12);
    assert!(c.check_recovery_key(&uid, &recovery).unwrap());
    assert!(
        c.check_recovery_key(&uid, &recovery.to_uppercase().replace(' ', "-"))
            .unwrap()
    );

    let own = c.own_identities().unwrap();
    assert_eq!(own.len(), 1);
    assert_eq!(own[0].uid.as_str(), uid);
    assert_eq!(c.accounts().unwrap().len(), 1);
    // The device keeps its secrets, but never the recovery or master key.
    let names = KeyNames::new(&uid);
    for id in names.all() {
        assert!(c.options().keys.load_seed(&id).unwrap().is_some(), "{id}");
    }

    // The server logged both records and published the key file; the
    // device accepts them once they are witnessed (4.5).
    let contact = c.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.keys, KeysStatus::Keys);
    assert_eq!(contact.pending, 0);
    assert!(!contact.stale);
    assert_eq!(contact.devices.len(), 1);
    let me = &contact.devices[0];
    assert!(me.accepted && me.this_device && !me.removed);
    assert_eq!(me.label, "laptop");
    assert_eq!(me.id, own[0].device);
    assert_eq!(me.short.len(), 8);
    let rows = c.store().records(&uid).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| r.accepted && r.mine && r.log_index.is_some())
    );

    // The device signs in with a hedged signature (4.6).
    let account = c.accounts().unwrap()[0].id;
    let sign_in = c.identity_sign_in(account).await.unwrap();
    let session = Session::connect(&HOST.parse().unwrap(), c.trust(), c.session_options())
        .await
        .unwrap();
    sign_in.establish(&session).await.unwrap();
    session.close();

    // The same name again is refused, and leaves nothing behind.
    let other = s.client();
    assert!(other.create_identity(HOST, "alice", "x").await.is_err());
    assert!(other.own_identities().unwrap().is_empty());
}

#[tokio::test]
async fn safety_numbers_and_verification() {
    let s = Setup::new().await;
    let (_alice, uid, _) = s.identity("alice").await;
    let (bob, bob_uid, _) = s.identity("bob").await;
    let alice_by_bob = bob.contact(&uid).await.unwrap();
    assert!(!alice_by_bob.verified);
    let number = bob.safety_number(&uid).unwrap();
    assert_eq!(number.digits.len(), 40 + 7);
    assert!(number.qr.starts_with("RISALA-FP:"));
    // Another identity's code does not verify this one.
    bob.contact(&bob_uid).await.unwrap();
    let wrong = bob.safety_number(&bob_uid).unwrap();
    assert!(matches!(
        bob.mark_verified(&uid, Some(&wrong.qr)),
        Err(Error::Identity(IdentityError::SafetyNumberMismatch))
    ));
    bob.mark_verified(&uid, Some(&number.qr)).unwrap();
    assert!(bob.contact(&uid).await.unwrap().verified);
    // The mark goes to Bob's other devices with a PIN line (12.9).
    let lines = bob.take_self_lines(&bob_uid).unwrap();
    assert!(
        lines
            .iter()
            .any(|l| matches!(l, ContentLine::Pin(p) if p.uid.as_str() == uid && p.verified)),
        "{lines:?}"
    );
}

#[tokio::test]
async fn records_wait_for_a_witnessed_checkpoint() {
    let s = Setup::new().await;
    s.world().witness_at_once = false;
    let (c, uid, _) = s.identity("alice").await;
    // Logged, but in no witnessed checkpoint yet: pending (4.5).
    let contact = c.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.keys, KeysStatus::Unknown);
    assert!(
        c.identity_devices(&uid)
            .unwrap()
            .iter()
            .all(|d| !d.accepted)
    );
    s.world().publish();
    let contact = c.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.keys, KeysStatus::Keys);
    assert_eq!(contact.pending, 0);
    assert!(contact.devices.iter().all(|d| d.accepted));
}

#[tokio::test]
async fn a_witness_list_that_does_not_fit_the_log() {
    let s = Setup::new().await;
    let (c, uid, _) = s.identity("alice").await;
    // Witnesses the log does not use.
    let others: Vec<String> = (4..=6).map(|i| witness(i).vkey().to_string()).collect();
    c.set_witness_policy(&others, 2).unwrap();
    let mut events = c.subscribe();
    let contact = c.refresh_identity(&uid).await.unwrap();
    assert!(contact.witness_problem);
    assert!(contact.devices.iter().all(|d| !d.accepted));
    let mut told = false;
    while let Ok(e) = events.try_recv() {
        told |= matches!(e, Event::Identity(IdentityEvent::WitnessListProblem { .. }));
    }
    assert!(told);
    // k must be more than half the list (4.5).
    assert!(c.set_witness_policy(&others, 1).is_err());
    assert!(c.set_witness_policy(&others, 4).is_err());
}

#[tokio::test]
async fn freshness_and_staleness() {
    let s = Setup::new().await;
    let (c, uid, _) = s.identity("alice").await;
    assert!(!c.refresh_identity(&uid).await.unwrap().stale);
    // Eight days with no new checkpoint: the log's cosignatures are old,
    // so the view is not refreshed, and goes stale (4.5).
    s.clock.advance(8 * DAY_MS);
    let contact = c.refresh_identity(&uid).await.unwrap();
    assert!(contact.stale);
    assert!(!c.may_add_devices(&uid).unwrap());
    // Sending goes on (4.5).
    assert_eq!(
        c.send_check(&uid, ConversationKind::Direct).unwrap(),
        SendCheck::Send
    );
    // A fresh checkpoint makes it fresh again.
    s.world().publish();
    let contact = c.refresh_identity(&uid).await.unwrap();
    assert!(!contact.stale);
    assert!(c.may_add_devices(&uid).unwrap());
}

#[tokio::test]
async fn the_three_states() {
    let s = Setup::new().await;
    let (_alice, uid, _) = s.identity("alice").await;
    let bob = s.client();
    let contact = bob.contact(&uid).await.unwrap();
    assert_eq!(contact.keys, KeysStatus::Keys);
    assert_eq!(
        bob.send_check(&uid, ConversationKind::Direct).unwrap(),
        SendCheck::Send
    );

    // An outage changes nothing (4.4).
    let url = format!("https://{DOMAIN}/.well-known/risala/alice");
    s.world()
        .overrides
        .insert(url.clone(), Fetched::Failed("timeout".into()));
    let contact = bob.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.keys, KeysStatus::Keys);
    s.world()
        .overrides
        .insert(url.clone(), Fetched::Status(503));
    assert_eq!(
        bob.refresh_identity(&uid).await.unwrap().keys,
        KeysStatus::Keys
    );

    // Keys missing: gone, or not valid. Nothing is removed, but sending
    // stops outside public rooms and warns in them (4.4, 12.14).
    for answer in [
        Fetched::Gone(410),
        Fetched::TooLarge,
        Fetched::Body(b"risala-keys/2\n".to_vec()),
        Fetched::Body(b"risala-keys/1\nnonsense\n".to_vec()),
    ] {
        s.world().overrides.insert(url.clone(), answer.clone());
        let contact = bob.refresh_identity(&uid).await.unwrap();
        assert!(matches!(contact.keys, KeysStatus::Missing(_)), "{answer:?}");
        assert_eq!(contact.stopped, Some(StopReason::KeysMissing));
        assert_eq!(
            bob.send_check(&uid, ConversationKind::Direct).unwrap(),
            SendCheck::Stop(StopReason::KeysMissing)
        );
        assert_eq!(
            bob.send_check(&uid, ConversationKind::PublicRoom).unwrap(),
            SendCheck::Warn(StopReason::KeysMissing)
        );
        assert!(contact.devices.iter().all(|d| d.accepted && !d.removed));
    }
    // A valid file again.
    s.world().overrides.clear();
    assert_eq!(
        bob.refresh_identity(&uid).await.unwrap().keys,
        KeysStatus::Keys
    );
    assert_eq!(
        bob.send_check(&uid, ConversationKind::Direct).unwrap(),
        SendCheck::Send
    );
}

#[tokio::test]
async fn a_record_not_in_the_log_makes_the_keys_missing() {
    let s = Setup::new().await;
    let (_alice, uid, _) = s.identity("alice").await;
    let bob = s.client();
    // The file says entry 0 holds the second record, and entry 1 the
    // first: neither matches the log (4.4).
    let url = format!("https://{DOMAIN}/.well-known/risala/alice");
    let text = String::from_utf8(s.world().key_files["alice"].clone()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let (a, b) = (lines[2], lines[3]);
    let (ha, hb) = (&a[2..], &b[2..]);
    let wrong = text
        .replace(a, &format!("0 {hb}"))
        .replace(b, &format!("1 {ha}"));
    s.world()
        .overrides
        .insert(url, Fetched::Body(wrong.into_bytes()));
    let contact = bob.refresh_identity(&uid).await.unwrap();
    assert!(
        matches!(contact.keys, KeysStatus::Missing(_)),
        "{contact:?}"
    );
}

#[tokio::test]
async fn pairing_a_device() {
    let s = Setup::new().await;
    let (alice, uid, _) = s.identity("alice").await;
    alice.refresh_identity(&uid).await.unwrap();
    let phone = s.client();
    let offer = phone.start_pairing(HOST, "phone").await.unwrap();
    assert!(offer.qr.starts_with("RISALA-PAIR:"));

    let request = alice.scan_pairing(&uid, &offer.qr).await.unwrap();
    assert_eq!(request.label, "phone");
    // A changed code does not open (4.8).
    let mut bad = offer.qr.clone();
    let last = bad.pop().unwrap();
    bad.push(if last == 'A' { 'B' } else { 'A' });
    assert!(alice.scan_pairing(&uid, &bad).await.is_err());

    alice.confirm_pairing(&uid, false).await.unwrap();
    // The phone shows the identity and its devices to confirm, and holds
    // nothing of it before (4.8 step 5; LR-H4).
    let shown = phone.finish_pairing().await.unwrap();
    assert_eq!(shown.uid.as_str(), uid);
    assert_eq!(shown.devices.len(), 2);
    assert!(
        shown
            .devices
            .iter()
            .any(|d| d.this_device && d.label == "phone" && d.id == request.device)
    );
    assert!(shown.devices.iter().any(|d| !d.this_device && d.label == "laptop"));
    assert!(phone.store().own_identity(&uid).unwrap().is_none());
    assert!(phone.accounts().unwrap().is_empty());
    let joined = phone.accept_pairing().await.unwrap();
    assert_eq!(joined.uid.as_str(), uid);
    assert_eq!(joined.device, request.device);

    // The phone holds the identity's keys, and sees both devices.
    let names = KeyNames::new(&phone.store().own_identity(&uid).unwrap().unwrap().key_id);
    for id in names.all() {
        assert!(
            phone.options().keys.load_seed(&id).unwrap().is_some(),
            "{id}"
        );
    }
    let devices = phone.identity_devices(&uid).unwrap();
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().all(|d| d.accepted));
    assert!(devices.iter().any(|d| d.this_device && d.label == "phone"));
    // It can sign in.
    let account = phone.accounts().unwrap()[0].id;
    let session = Session::connect(
        &HOST.parse().unwrap(),
        phone.trust(),
        phone.session_options(),
    )
    .await
    .unwrap();
    phone
        .identity_sign_in(account)
        .await
        .unwrap()
        .establish(&session)
        .await
        .unwrap();
    session.close();
    // Alice's device announces the record to the identity's others (4.5).
    let lines = alice.take_self_lines(&uid).unwrap();
    assert!(
        lines.iter().any(|l| matches!(l, ContentLine::Record(_))),
        "{lines:?}"
    );
}

/// Alice on a laptop with a paired phone.
/// Puts a conversation with yourself of `uid` in `client`'s cache, with a
/// leaf for each device, those of other devices confirmed (12.10), as the
/// group engine and leaf confirmation keep them. Returns its id.
fn self_conversation(client: &Client, uid: &str, leaves: &[(u32, [u8; 48])]) -> i64 {
    client
        .store()
        .write(|tx| {
            let account: i64 = tx.conn().query_row(
                "SELECT id FROM accounts WHERE uid = ?1",
                [uid],
                |r| r.get(0),
            )?;
            tx.conn().execute(
                "INSERT INTO conversations (account, group_id, kind, pseudonym, created)
                 VALUES (?1, ?2, 'self', ?3, 0)",
                rusqlite::params![account, &[7u8; 32][..], &[0u8; 16][..]],
            )?;
            let conv = tx.conn().last_insert_rowid();
            for (leaf, device) in leaves {
                let key = vec![*leaf as u8; 32];
                tx.conn().execute(
                    "INSERT INTO leaves (conv, leaf, uid, device_id, signature_key)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![conv, leaf, uid, &device[..], key],
                )?;
                tx.conn().execute(
                    "INSERT INTO leaf_confirmations (conv, leaf, signature_key, state)
                     VALUES (?1, ?2, ?3, 'confirmed')",
                    rusqlite::params![conv, leaf, key],
                )?;
            }
            Ok(conv)
        })
        .unwrap()
        .0
}

async fn alice_with_phone(s: &Setup) -> (Client, Client, String, String, DeviceId) {
    let (alice, uid, recovery) = s.identity("alice").await;
    alice.refresh_identity(&uid).await.unwrap();
    let phone = s.client();
    let offer = phone.start_pairing(HOST, "phone").await.unwrap();
    let request = alice.scan_pairing(&uid, &offer.qr).await.unwrap();
    alice.confirm_pairing(&uid, false).await.unwrap();
    phone.finish_pairing().await.unwrap();
    phone.accept_pairing().await.unwrap();
    alice.refresh_identity(&uid).await.unwrap();
    (alice, phone, uid, recovery, request.device)
}

#[tokio::test]
async fn removing_a_device() {
    let s = Setup::new().await;
    let (alice, phone, uid, recovery, phone_id) = alice_with_phone(&s).await;
    let bob = s.client();
    assert_eq!(bob.contact(&uid).await.unwrap().devices.len(), 2);

    // The recovery key is needed (4.8).
    let other = "a".repeat(52);
    assert!(matches!(
        alice.remove_device(&uid, phone_id, &other).await,
        Err(Error::Identity(IdentityError::WrongRecoveryKey))
    ));
    let mut events = alice.subscribe();
    alice
        .remove_device(&uid, phone_id, &recovery)
        .await
        .unwrap();
    let mut generation = None;
    while let Ok(e) = events.try_recv() {
        if let Event::Identity(IdentityEvent::NewGeneration { generation: g, .. }) = e {
            generation = Some(g);
        }
    }
    assert_eq!(generation, Some(1));
    assert_eq!(
        alice
            .store()
            .own_identity(&uid)
            .unwrap()
            .unwrap()
            .backup_generation,
        1
    );

    // Once accepted, the phone is removed for everyone (4.4).
    for c in [&alice, &bob] {
        let devices = c.refresh_identity(&uid).await.unwrap().devices;
        let phone = devices.iter().find(|d| d.id == phone_id).unwrap();
        assert!(phone.removed, "{devices:?}");
    }
    // The new keys go to the other devices (4.8, step 3), once the
    // conversation with yourself holds none but current, confirmed ones
    // (12.9): here, once the phone's leaf is gone from it.
    let laptop_id = alice
        .store()
        .own_identity(&uid)
        .unwrap()
        .unwrap()
        .device_id;
    self_conversation(&alice, &uid, &[(0, laptop_id)]);
    let lines = alice.take_self_lines(&uid).unwrap();
    assert!(
        lines
            .iter()
            .any(|l| matches!(l, ContentLine::SigningKey(_)))
    );
    assert!(
        lines
            .iter()
            .any(|l| matches!(l, ContentLine::BackupKey { generation: 1, .. }))
    );
    // The removed phone can no longer sign in (4.6).
    let account = phone.accounts().unwrap()[0].id;
    let session = Session::connect(
        &HOST.parse().unwrap(),
        phone.trust(),
        phone.session_options(),
    )
    .await
    .unwrap();
    assert!(
        phone
            .identity_sign_in(account)
            .await
            .unwrap()
            .establish(&session)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn recovering_an_identity() {
    let s = Setup::new().await;
    let (alice, uid, recovery) = s.identity("alice").await;
    alice.refresh_identity(&uid).await.unwrap();
    let laptop_id = alice.own_identities().unwrap()[0].device;

    let new = s.client();
    assert!(matches!(
        new.recover(HOST, &uid, &"a".repeat(52), "new laptop").await,
        Err(Error::Identity(IdentityError::WrongRecoveryKey))
    ));
    let own = new
        .recover(HOST, &uid, &recovery, "new laptop")
        .await
        .unwrap();
    assert_eq!(own.uid.as_str(), uid);
    let contact = new.refresh_identity(&uid).await.unwrap();
    let old = contact.devices.iter().find(|d| d.id == laptop_id).unwrap();
    assert!(old.removed);
    let me = contact.devices.iter().find(|d| d.this_device).unwrap();
    assert!(me.accepted);
    assert_eq!(
        new.store()
            .own_identity(&uid)
            .unwrap()
            .unwrap()
            .backup_generation,
        1
    );
    assert_eq!(new.restorable_backup_generation(&uid).unwrap(), Some(0));

    // LR-M6: a removal after the recovery moves the chain on, not the
    // generation to restore, which is the one before this device's own
    // recovery record.
    let phone = s.client();
    let offer = phone.start_pairing(HOST, "phone").await.unwrap();
    let request = new.scan_pairing(&uid, &offer.qr).await.unwrap();
    new.confirm_pairing(&uid, false).await.unwrap();
    phone.finish_pairing().await.unwrap();
    phone.accept_pairing().await.unwrap();
    new.refresh_identity(&uid).await.unwrap();
    new.remove_device(&uid, request.device, &recovery)
        .await
        .unwrap();
    new.refresh_identity(&uid).await.unwrap();
    assert_eq!(
        new.store()
            .own_identity(&uid)
            .unwrap()
            .unwrap()
            .backup_generation,
        2
    );
    assert_eq!(new.restorable_backup_generation(&uid).unwrap(), Some(0));
    // A device that was not recovered has nothing to restore this way.
    assert_eq!(phone.restorable_backup_generation(&uid).unwrap(), None);
}

#[tokio::test]
async fn a_rollback_is_a_fork() {
    let s = Setup::new().await;
    let (alice, phone, uid, _, _) = alice_with_phone(&s).await;
    drop((alice, phone));
    let bob = s.client();
    assert_eq!(bob.contact(&uid).await.unwrap().devices.len(), 2);
    // A valid key file that leaves out the head: only the first records.
    let chain = s.world().chains[&uid].clone();
    let short = super::verify::prefix_chain(&chain, 2).unwrap();
    let text = {
        let w = s.world();
        KeyFile::from_chain(&short, &|i| {
            w.indices.get(&short.records()[i].hash()).copied()
        })
        .unwrap()
        .to_text()
    };
    s.world().overrides.insert(
        format!("https://{DOMAIN}/.well-known/risala/alice"),
        Fetched::Body(text.into_bytes()),
    );
    let mut events = bob.subscribe();
    let contact = bob.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.stopped, Some(StopReason::Fork));
    // A fork stops only direct conversations; rooms keep sending and
    // stop trusting the identity's leaves (4.5, 12.14).
    assert_eq!(
        bob.send_check(&uid, ConversationKind::PublicRoom).unwrap(),
        SendCheck::Warn(StopReason::Fork)
    );
    assert!(!bob.can_check(&uid).unwrap());
    assert!(!bob.may_add_devices(&uid).unwrap());
    let mut told = false;
    while let Ok(e) = events.try_recv() {
        told |= matches!(e, Event::Identity(IdentityEvent::Fork { .. }));
    }
    assert!(told);
    assert_eq!(bob.forks(&uid).unwrap().len(), 1);
    // The phone's device stays as it was: nothing moves while forked.
    assert_eq!(bob.identity_devices(&uid).unwrap().len(), 2);
}

#[tokio::test]
async fn a_logged_record_left_out_of_the_key_file() {
    let s = Setup::new().await;
    let (alice, uid, _) = s.identity("alice").await;
    alice.refresh_identity(&uid).await.unwrap();
    let bob = s.client();
    bob.contact(&uid).await.unwrap();
    // The host logs a new record but keeps serving the old file (4.5,
    // Freshness, step 2).
    s.world().frozen = true;
    let phone = s.client();
    let offer = phone.start_pairing(HOST, "phone").await.unwrap();
    alice.scan_pairing(&uid, &offer.qr).await.unwrap();
    alice.confirm_pairing(&uid, false).await.unwrap();
    let contact = bob.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.stopped, Some(StopReason::Fork));
}

#[tokio::test]
async fn a_new_master_key() {
    let s = Setup::new().await;
    let (alice, uid, recovery) = s.identity("alice").await;
    alice.refresh_identity(&uid).await.unwrap();
    let bob = s.client();
    bob.contact(&uid).await.unwrap();
    bob.mark_verified(&uid, None).unwrap();

    // Alice changes her recovery key: a later master record signed by
    // both master keys (4.8).
    let identity = id(&uid);
    let old = risala_proto::recovery::RecoveryKey::parse(&recovery)
        .unwrap()
        .master_key(&identity);
    let new = risala_proto::recovery::RecoveryKey::from_bytes([9; 32]).master_key(&identity);
    let signing = SecretKey::from_seed([10; 32]);
    let (chain, _) = alice.own_chain(&identity).unwrap();
    let record = Record::sign_rotation(
        RecordContent {
            uid: identity.clone(),
            previous: Some(chain.head_hash()),
            time: chain.head().content().time + 1000,
            body: RecordBody::Master {
                master_key: new.public_key(),
                signing_key: signing.public_key(),
                log: chain.log().clone(),
            },
        },
        &old,
        &new,
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let line = format!(
        "@ref=1 KEYS PUT {} {}",
        chain.head_hash(),
        risala_proto::binary::EncodedRecords::from_bytes(&risala_proto::record::encode_records(&[
            record
        ]))
        .unwrap()
    );
    let answer = s.world().answer(&line, HOST);
    assert!(answer.last().unwrap().ends_with("OK"), "{answer:?}");

    let mut events = bob.subscribe();
    let contact = bob.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.stopped, Some(StopReason::NewMasterKey));
    assert!(!contact.verified);
    assert_eq!(
        bob.send_check(&uid, ConversationKind::Direct).unwrap(),
        SendCheck::Stop(StopReason::NewMasterKey)
    );
    assert_eq!(
        bob.send_check(&uid, ConversationKind::PublicRoom).unwrap(),
        SendCheck::Warn(StopReason::NewMasterKey)
    );
    let mut told = false;
    while let Ok(e) = events.try_recv() {
        told |= matches!(e, Event::Identity(IdentityEvent::NewMasterKey { .. }));
    }
    assert!(told);
    let before = bob.safety_number(&uid).unwrap();
    bob.acknowledge_new_master_key(&uid).unwrap();
    assert_eq!(
        bob.send_check(&uid, ConversationKind::Direct).unwrap(),
        SendCheck::Send
    );
    assert_ne!(bob.safety_number(&uid).unwrap(), before);
    assert!(!bob.contact(&uid).await.unwrap().verified);
}

#[tokio::test]
async fn watching_own_records() {
    let s = Setup::new().await;
    let (alice, phone, uid, _, _) = alice_with_phone(&s).await;
    // The phone pairs a tablet; its RECORD line never reaches the laptop.
    let tablet = s.client();
    let offer = tablet.start_pairing(HOST, "tablet").await.unwrap();
    phone.refresh_identity(&uid).await.unwrap();
    phone.scan_pairing(&uid, &offer.qr).await.unwrap();
    phone.confirm_pairing(&uid, false).await.unwrap();
    let lines = phone.take_self_lines(&uid).unwrap();
    let ContentLine::Record(tablet_record) = lines
        .iter()
        .find(|l| matches!(l, ContentLine::Record(_)))
        .unwrap()
        .clone()
    else {
        unreachable!()
    };

    // Within a day, nothing is said. (The laptop's daily watch sees the
    // record now.)
    let mut events = alice.subscribe();
    alice.refresh_identity(&uid).await.unwrap();
    alice.identity_maintenance().await.unwrap();
    s.clock.advance(DAY_MS / 2);
    s.world().publish();
    alice.identity_maintenance().await.unwrap();
    assert!(
        !alice
            .take_self_lines(&uid)
            .unwrap()
            .iter()
            .any(|l| matches!(l, ContentLine::Alert(_)))
    );

    // A day after it was witnessed, a record nobody announced is an alert
    // (4.5).
    s.clock.advance(DAY_MS / 2 + 1000);
    alice.identity_maintenance().await.unwrap();
    let lines = alice.take_self_lines(&uid).unwrap();
    assert!(
        lines
            .iter()
            .any(|l| matches!(l, ContentLine::Alert(h) if *h == tablet_record)),
        "{lines:?}"
    );
    let mut alerted = false;
    while let Ok(e) = events.try_recv() {
        alerted |= matches!(e, Event::Identity(IdentityEvent::Alert { .. }));
    }
    assert!(alerted);

    // On the phone, which announced it itself, nothing.
    phone.identity_maintenance().await.unwrap();
    assert!(
        !phone
            .take_self_lines(&uid)
            .unwrap()
            .iter()
            .any(|l| matches!(l, ContentLine::Alert(_)))
    );
}

#[tokio::test]
async fn an_announced_record_is_no_alert() {
    let s = Setup::new().await;
    let (alice, phone, uid, _, _) = alice_with_phone(&s).await;
    let tablet = s.client();
    let offer = tablet.start_pairing(HOST, "tablet").await.unwrap();
    phone.refresh_identity(&uid).await.unwrap();
    phone.scan_pairing(&uid, &offer.qr).await.unwrap();
    phone.confirm_pairing(&uid, false).await.unwrap();
    // The phone's RECORD line reaches the laptop.
    let lines = phone.take_self_lines(&uid).unwrap();
    alice.handle_self_lines(&uid, &lines).unwrap();
    alice.identity_maintenance().await.unwrap();
    s.clock.advance(DAY_MS + 1000);
    s.world().publish();
    alice.identity_maintenance().await.unwrap();
    assert!(
        !alice
            .take_self_lines(&uid)
            .unwrap()
            .iter()
            .any(|l| matches!(l, ContentLine::Alert(_)))
    );
}

#[tokio::test]
async fn keys_from_the_conversation_with_yourself() {
    let s = Setup::new().await;
    let (alice, phone, uid, recovery, phone_id) = alice_with_phone(&s).await;
    // A third device that stays.
    let tablet = s.client();
    let offer = tablet.start_pairing(HOST, "tablet").await.unwrap();
    alice.refresh_identity(&uid).await.unwrap();
    alice.scan_pairing(&uid, &offer.qr).await.unwrap();
    alice.confirm_pairing(&uid, false).await.unwrap();
    tablet.finish_pairing().await.unwrap();
    tablet.accept_pairing().await.unwrap();
    alice.take_self_lines(&uid).unwrap();
    drop(phone);
    // The laptop's conversation with yourself, with the phone's and the
    // tablet's leaves, both confirmed (12.10).
    let tablet_id = tablet
        .store()
        .own_identity(&uid)
        .unwrap()
        .unwrap()
        .device_id;
    let laptop_id = alice
        .store()
        .own_identity(&uid)
        .unwrap()
        .unwrap()
        .device_id;
    let conv = self_conversation(
        &alice,
        &uid,
        &[(0, laptop_id), (1, phone_id.0), (2, tablet_id)],
    );

    alice
        .remove_device(&uid, phone_id, &recovery)
        .await
        .unwrap();
    // LR-C3, 12.9: the new device-signing key and backup key never reach
    // the removed phone: not while the record is pending, nor once it is
    // accepted while the phone's leaf is still in the conversation with
    // yourself, only once the commit that removed it has won.
    let lines = alice.take_self_lines(&uid).unwrap();
    assert!(!lines.iter().any(|l| matches!(
        l,
        ContentLine::SigningKey(_) | ContentLine::BackupKey { .. }
    )));
    alice.refresh_identity(&uid).await.unwrap();
    let lines = alice.take_self_lines(&uid).unwrap();
    assert!(!lines.iter().any(|l| matches!(
        l,
        ContentLine::SigningKey(_) | ContentLine::BackupKey { .. }
    )));
    alice
        .store()
        .write(|tx| {
            tx.conn()
                .execute("DELETE FROM leaves WHERE conv = ?1 AND leaf = 1", [conv])?;
            Ok(())
        })
        .unwrap();
    let lines = alice.take_self_lines(&uid).unwrap();
    // Before the signing record is accepted, the tablet ignores the keys.
    let keys: Vec<ContentLine> = lines
        .iter()
        .filter(|l| {
            matches!(
                l,
                ContentLine::SigningKey(_) | ContentLine::BackupKey { .. }
            )
        })
        .cloned()
        .collect();
    assert_eq!(keys.len(), 2);
    let tablet_names = KeyNames::new(&tablet.store().own_identity(&uid).unwrap().unwrap().key_id);
    let before = tablet
        .options()
        .keys
        .load_seed(&tablet_names.signing())
        .unwrap();
    // Once accepted, it takes them.
    tablet.refresh_identity(&uid).await.unwrap();
    tablet.handle_self_lines(&uid, &keys).unwrap();
    let after = tablet
        .options()
        .keys
        .load_seed(&tablet_names.signing())
        .unwrap();
    assert_ne!(before.map(|s| *s), after.as_ref().map(|s| **s));
    assert_eq!(
        tablet
            .store()
            .own_identity(&uid)
            .unwrap()
            .unwrap()
            .backup_generation,
        1
    );
    // A seed that is not the current key is ignored.
    tablet
        .handle_self_lines(
            &uid,
            &[ContentLine::SigningKey(
                risala_proto::content::SigningSeed::from_bytes([3; 32]),
            )],
        )
        .unwrap();
    assert_eq!(
        tablet
            .options()
            .keys
            .load_seed(&tablet_names.signing())
            .unwrap()
            .map(|s| *s),
        after.as_ref().map(|s| **s)
    );
    // The tablet can now pair a device itself.
    let watch = s.client();
    let offer = watch.start_pairing(HOST, "watch").await.unwrap();
    tablet.scan_pairing(&uid, &offer.qr).await.unwrap();
    tablet.confirm_pairing(&uid, false).await.unwrap();
    watch.finish_pairing().await.unwrap();
    watch.accept_pairing().await.unwrap();
}

#[tokio::test]
async fn records_asks_and_answers() {
    let s = Setup::new().await;
    let (alice, phone, uid, _, _) = alice_with_phone(&s).await;
    // A RECORDS question gets the records this device knows were
    // announced (4.5, 12.9).
    alice.take_self_lines(&uid).unwrap();
    alice
        .handle_self_lines(&uid, &[ContentLine::Records(None)])
        .unwrap();
    let lines = alice.take_self_lines(&uid).unwrap();
    let [ContentLine::Records(Some(hashes))] = &lines[..] else {
        panic!("{lines:?}")
    };
    assert_eq!(hashes.len(), 3);
    phone.handle_self_lines(&uid, &lines).unwrap();
    assert_eq!(phone.store().announced(&uid).unwrap().len(), 3);
    // An ALERT is shown.
    let mut events = phone.subscribe();
    phone
        .handle_self_lines(&uid, &[ContentLine::Alert(hashes[0])])
        .unwrap();
    assert!(matches!(
        events.try_recv(),
        Ok(Event::Identity(IdentityEvent::Alert { .. }))
    ));
}

#[tokio::test]
async fn pins_from_the_conversation_with_yourself() {
    let s = Setup::new().await;
    let (_bob, bob_uid, _) = s.identity("bob").await;
    let (alice, phone, uid, _, _) = alice_with_phone(&s).await;
    alice.contact(&bob_uid).await.unwrap();
    alice.mark_verified(&bob_uid, None).unwrap();
    let pins: Vec<ContentLine> = alice
        .take_self_lines(&uid)
        .unwrap()
        .into_iter()
        .filter(|l| matches!(l, ContentLine::Pin(p) if p.uid.as_str() == bob_uid))
        .collect();
    assert!(!pins.is_empty());
    // The phone takes the pin and the verified mark, and checks Bob's
    // records itself (12.9).
    phone.handle_self_lines(&uid, &pins).unwrap();
    let contact = phone.contact(&bob_uid).await.unwrap();
    assert!(contact.verified);
    assert_eq!(contact.keys, KeysStatus::Keys);
    assert_eq!(
        phone
            .send_check(&bob_uid, ConversationKind::Direct)
            .unwrap(),
        SendCheck::Send
    );

    // A pin of another master key is a new master key.
    let carol = s.client();
    let mut wrong = pins[0].clone();
    if let ContentLine::Pin(p) = &mut wrong {
        p.master = BlobRef::of(b"another key");
    }
    carol
        .create_identity(HOST, "carol", "laptop")
        .await
        .unwrap();
    carol
        .handle_self_lines("carol@example.test", &[wrong])
        .unwrap();
    assert_eq!(
        carol.contact(&bob_uid).await.unwrap().stopped,
        Some(StopReason::NewMasterKey)
    );
}

#[tokio::test]
async fn unregistering() {
    let s = Setup::new().await;
    let (alice, _, _) = s.identity("alice").await;
    let account = alice.accounts().unwrap()[0].id;
    alice.unregister(account).await.unwrap();
}

#[tokio::test]
async fn pairing_needs_a_named_server() {
    // A PairingCode names a server address, which is never an IP address
    // (2.1, 4.8).
    let s = Setup::new().await;
    let phone = s.client();
    assert!(matches!(
        phone.start_pairing("127.0.0.1", "phone").await,
        Err(Error::Invalid { .. })
    ));
}

/// LR-H4, 4.8 step 5: someone who saw the QR code answers first with a
/// bundle of an identity of their own. The new device shows that identity
/// and its devices before it takes anything; the user refuses, and the
/// device holds nothing of it.
#[tokio::test]
async fn a_bundle_for_another_identity_is_shown_and_can_be_refused() {
    let s = Setup::new().await;
    let (_alice, alice_uid, _) = s.identity("alice").await;
    let (mallory, mallory_uid, _) = s.identity("mallory").await;
    mallory.refresh_identity(&mallory_uid).await.unwrap();
    let phone = s.client();
    let offer = phone.start_pairing(HOST, "phone").await.unwrap();
    // Mallory photographed the code, and answers first.
    mallory.scan_pairing(&mallory_uid, &offer.qr).await.unwrap();
    mallory.confirm_pairing(&mallory_uid, false).await.unwrap();
    let shown = phone.finish_pairing().await.unwrap();
    assert_eq!(shown.uid.as_str(), mallory_uid);
    assert_ne!(shown.uid.as_str(), alice_uid);
    assert!(shown.devices.iter().any(|d| d.label == "laptop"));
    // Nothing is taken, and nothing signs in, before the user confirms.
    assert!(phone.store().own_identity(&mallory_uid).unwrap().is_none());
    assert!(phone.accounts().unwrap().is_empty());
    phone.decline_pairing().unwrap();
    assert!(phone.store().latest_pairing(true, None).unwrap().is_none());
    assert!(matches!(
        phone.accept_pairing().await,
        Err(Error::Identity(IdentityError::Pairing(_)))
    ));
    assert!(phone.store().own_identity(&mallory_uid).unwrap().is_none());
}

#[tokio::test]
async fn pairings_expire() {
    let s = Setup::new().await;
    let phone = s.client();
    phone.start_pairing(HOST, "phone").await.unwrap();
    s.clock.advance(11 * 60 * 1000);
    phone.identity_maintenance().await.unwrap();
    assert!(matches!(
        phone.finish_pairing().await,
        Err(Error::Identity(IdentityError::Pairing(_)))
    ));
}

#[tokio::test]
async fn back_after_a_day_asks_first() {
    let s = Setup::new().await;
    let (alice, _phone, uid, _, _) = alice_with_phone(&s).await;
    alice.identity_maintenance().await.unwrap();
    alice.take_self_lines(&uid).unwrap();
    // Offline for two days: it asks its own devices with RECORDS before
    // it alerts for anything (4.5).
    s.clock.advance(2 * DAY_MS);
    s.world().publish();
    alice.identity_maintenance().await.unwrap();
    let lines = alice.take_self_lines(&uid).unwrap();
    assert!(lines.contains(&ContentLine::Records(None)), "{lines:?}");
    assert!(!lines.iter().any(|l| matches!(l, ContentLine::Alert(_))));
}

#[tokio::test]
async fn a_log_that_forks_stops_every_identity_in_it() {
    let s = Setup::new().await;
    let (_alice, uid, _) = s.identity("alice").await;
    let (_carol, carol_uid, _) = s.identity("carol").await;
    let bob = s.client();
    bob.contact(&uid).await.unwrap();
    bob.contact(&carol_uid).await.unwrap();
    // The log shows another tree of the same size, which witnesses that
    // lost their state (or were compromised) cosign (4.5).
    {
        let mut w = s.world();
        let size = w.log.size();
        let mut other = MemoryLog::new(&origin(), &[7; 32]);
        for i in 0..size {
            other.append(format!("not the same entry {i}").as_bytes());
        }
        w.log = other;
        w.witnesses = (1..=3).map(witness).collect();
        w.publish();
    }
    let mut events = bob.subscribe();
    let contact = bob.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.stopped, Some(StopReason::Fork));
    let mut told = false;
    while let Ok(e) = events.try_recv() {
        told |= matches!(e, Event::Identity(IdentityEvent::Fork { .. }));
    }
    assert!(told);
    // Carol's records are in the same log: her too, without a fetch.
    assert_eq!(
        bob.send_check(&carol_uid, ConversationKind::Direct)
            .unwrap(),
        SendCheck::Stop(StopReason::Fork)
    );
    assert!(!bob.forks(&carol_uid).unwrap().is_empty());
}

#[tokio::test]
async fn removed_stays_removed() {
    let s = Setup::new().await;
    let (alice, _phone, uid, recovery, phone_id) = alice_with_phone(&s).await;
    alice
        .remove_device(&uid, phone_id, &recovery)
        .await
        .unwrap();
    let bob = s.client();
    bob.contact(&uid).await.unwrap();
    // Whatever is written later, a device once removed by record stays
    // removed for this reader (4.4).
    let mut row = bob
        .store()
        .devices(&uid)
        .unwrap()
        .into_iter()
        .find(|d| d.device_id == phone_id.0)
        .unwrap();
    assert_eq!(row.state, crate::store::identity::DeviceState::Removed);
    row.state = crate::store::identity::DeviceState::Current;
    bob.store()
        .write(|tx| tx.put_devices(&uid, std::slice::from_ref(&row)))
        .unwrap();
    let phone = bob
        .identity_devices(&uid)
        .unwrap()
        .into_iter()
        .find(|d| d.id == phone_id)
        .unwrap();
    assert!(phone.removed && !phone.accepted);
}

#[tokio::test]
async fn records_follow_a_hand_off() {
    let s = Setup::new().await;
    let (alice, uid, _) = s.identity("alice").await;
    let bob = s.client();
    assert_eq!(bob.contact(&uid).await.unwrap().devices.len(), 1);

    // The host hands its log 1 off to log 2 (4.5, 4.10).
    let origin2 = LogOrigin::new(HOST, 2).unwrap();
    let mut log2 = MemoryLog::new(&origin2, &[8; 32]);
    {
        let mut w = s.world();
        let key2 = log2.key();
        w.log.hand_off(&key2);
        w.publish();
        let cp = w.checkpoint.clone();
        let World { log, witnesses, .. } = &mut *w;
        assert!(log.send_handoff(&cp, witnesses).iter().all(Result::is_ok));
    }

    // Alice's next record goes into log 2, with no record of its own for
    // the move.
    let identity = id(&uid);
    let (chain, _) = alice.own_chain(&identity).unwrap();
    let own = alice.store().own_identity(&uid).unwrap().unwrap();
    let seed = alice
        .options()
        .keys
        .load_seed(&KeyNames::new(&own.key_id).signing())
        .unwrap()
        .unwrap();
    let signing = SecretKey::from_seed(*seed);
    let keys = risala_proto::record::DeviceKeys {
        device_key: SecretKey::from_seed([11; 32]).public_key(),
        attestation_key: crate::keys::attestation_public_key(&[12; 32]),
        label: "tablet".into(),
    };
    let record = Record::sign(
        RecordContent {
            uid: identity.clone(),
            previous: Some(chain.head_hash()),
            time: chain.head().content().time + 1000,
            body: RecordBody::Device(keys),
        },
        &signing,
        [3; 32],
    )
    .unwrap();
    let log2_key = LogKey::from_vkey(&log2.vkey().to_string()).unwrap();
    let mut chain2 = chain.clone();
    chain2
        .push(&record, Some(&log2_key), &|_: &LogKey, _: &LogKey| true)
        .unwrap();
    {
        let mut w = s.world();
        let index = log2.append_record(&uid, record.encoded());
        w.indices.insert(record.hash(), index);
        let ts = w.now_s();
        let mut cp2 = log2.checkpoint(ts);
        let results = log2.witness(&mut cp2, &mut w.witnesses, ts);
        assert!(results.iter().all(Result::is_ok), "{results:?}");
        let indices = w.indices.clone();
        let file = KeyFile::from_chain(&chain2, &|i| {
            indices.get(&chain2.records()[i].hash()).copied()
        })
        .unwrap();
        w.key_files
            .insert("alice".into(), file.to_text().into_bytes());
        w.second = Some((log2, cp2));
    }

    let contact = bob.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.stopped, None, "{contact:?}");
    assert_eq!(contact.pending, 0, "{contact:?}");
    assert_eq!(contact.devices.len(), 2);
    assert!(contact.devices.iter().all(|d| d.accepted));
    assert!(!contact.stale);
    let log1 = bob.store().log(&origin().to_string()).unwrap().unwrap();
    assert!(log1.handoff.is_some());
}

#[tokio::test]
async fn a_key_file_with_another_first_master_key_is_a_new_master_key() {
    let s = Setup::new().await;
    let (_alice, uid, _) = s.identity("alice").await;
    let bob = s.client();
    let before = bob.contact(&uid).await.unwrap();
    assert_eq!(before.devices.len(), 1);

    // The domain's controller serves a whole new chain for alice, with
    // another master key, in another host's log: not a rollback, but a new
    // master key, which waits for the user (4.4, 4.5).
    let identity = id(&uid);
    let origin_b = LogOrigin::new("other.test", 1).unwrap();
    let mut log_b = MemoryLog::new(&origin_b, &[9; 32]);
    let key_b = LogKey::from_vkey(&log_b.vkey().to_string()).unwrap();
    let master = risala_proto::recovery::RecoveryKey::from_bytes([5; 32]).master_key(&identity);
    let signing = SecretKey::from_seed([6; 32]);
    let now = s.clock.now().unix_millis();
    let first = Record::sign(
        RecordContent {
            uid: identity.clone(),
            previous: None,
            time: now,
            body: RecordBody::Master {
                master_key: master.public_key(),
                signing_key: signing.public_key(),
                log: key_b,
            },
        },
        &master,
        [1; 32],
    )
    .unwrap();
    let device = Record::sign(
        RecordContent {
            uid: identity.clone(),
            previous: Some(first.hash()),
            time: now + 1,
            body: RecordBody::Device(risala_proto::record::DeviceKeys {
                device_key: SecretKey::from_seed([13; 32]).public_key(),
                attestation_key: crate::keys::attestation_public_key(&[14; 32]),
                label: "intruder".into(),
            }),
        },
        &signing,
        [2; 32],
    )
    .unwrap();
    let chain_b = Chain::replay(&identity, &[first.clone(), device.clone()]).unwrap();
    {
        let mut w = s.world();
        let mut indices = HashMap::new();
        for r in [&first, &device] {
            indices.insert(r.hash(), log_b.append_record(&uid, r.encoded()));
        }
        let ts = w.now_s();
        let mut cp = log_b.checkpoint(ts);
        let results = log_b.witness(&mut cp, &mut w.witnesses, ts);
        assert!(results.iter().all(Result::is_ok), "{results:?}");
        let file = KeyFile::from_chain(&chain_b, &|i| {
            indices.get(&chain_b.records()[i].hash()).copied()
        })
        .unwrap();
        w.key_files
            .insert("alice".into(), file.to_text().into_bytes());
        w.second = Some((log_b, cp));
    }
    let contact = bob.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.stopped, Some(StopReason::NewMasterKey));
    assert!(bob.forks(&uid).unwrap().is_empty());
    // Nothing moves until the user acknowledges it.
    assert_eq!(contact.devices, before.devices);
    assert_eq!(
        bob.send_check(&uid, ConversationKind::PrivateRoom).unwrap(),
        SendCheck::Stop(StopReason::NewMasterKey)
    );
    bob.acknowledge_new_master_key(&uid).unwrap();
    let contact = bob.refresh_identity(&uid).await.unwrap();
    assert_eq!(contact.stopped, None, "{contact:?}");
    assert_eq!(contact.devices.len(), 1);
    assert_eq!(contact.devices[0].label, "intruder");
}
