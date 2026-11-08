//! The key log (4.5) and witnessing (4.10): appending, serving tiles and
//! hints, checkpoints witnessed by an in-process test witness and by a
//! second hub in witness mode, and hand-offs, checked with the device's
//! code in `risala-keylog`.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use risala_keylog::addcheckpoint::AddCheckpoint;
use risala_keylog::client::{LogView, accept_handoff, accept_record};
use risala_keylog::cosig::Cosigner;
use risala_keylog::hint::{UidHint, parse_next, uid_hint_path};
use risala_keylog::testlog::{TestWitness, WitnessRefusal};
use risala_keylog::tile::{TileSet, bundle_for_entry, decode_bundle};
use risala_keylog::{Freshness, WitnessPolicy};
use risala_proto::auth::SecretKey;
use risala_proto::chain::Handoffs as _;
use risala_proto::record::{LogKey, Record, RecordBody, RecordContent};

use super::super::keylog::{
    AppendError, Posted, Transport, append_records, check_config, index_of, witness_round,
};
use super::super::{Clock as _, Hub, ManualClock};
use super::{T, config, timers};
use crate::config::{Config, LogWitness};
use crate::keyfiles::KeyServices;
use crate::store::{KeyLogStore as _, SqliteStore};

const HOST: &str = "chat.example.org";
const LOG_SEED: [u8; 32] = [1; 32];
/// The witness hub's key.
const HUB_W: &str = "witness-b.test/risala-witness";
const HUB_W_SEED: [u8; 32] = [7; 32];
const HUB_W_URL: &str = "https://witness-b.test/risala-witness";
/// The test witness of `risala-keylog`.
const TEST_W: &str = "witness-t.test/w";
const TEST_W_SEED: [u8; 32] = [8; 32];
const TEST_W_URL: &str = "https://witness-t.test/w";

fn origin(n: u64) -> String {
    format!("{HOST}/risala-log/{n}")
}

/// The verifier key of log 1, whose seed the tests set.
fn log1_vkey() -> String {
    Cosigner::from_seed(&origin(1), &LOG_SEED)
        .unwrap()
        .vkey()
        .to_string()
}

fn hub_w_vkey() -> String {
    Cosigner::from_seed(HUB_W, &HUB_W_SEED)
        .unwrap()
        .vkey()
        .to_string()
}

fn test_w_vkey() -> String {
    Cosigner::from_seed(TEST_W, &TEST_W_SEED)
        .unwrap()
        .vkey()
        .to_string()
}

/// A configuration with the log on, sending to `witnesses`.
fn log_config(witnesses: &[(String, &str)], k: Option<usize>, number: Option<u64>) -> Config {
    let mut c = config();
    c.log.enabled = Some(true);
    c.log.witnesses = witnesses
        .iter()
        .map(|(vkey, url)| LogWitness {
            vkey: vkey.clone(),
            url: (*url).to_owned(),
        })
        .collect();
    c.log.k = k;
    c.log.number = number;
    c
}

/// Both witnesses, k = 2.
fn both() -> Config {
    log_config(
        &[(test_w_vkey(), TEST_W_URL), (hub_w_vkey(), HUB_W_URL)],
        None,
        None,
    )
}

/// A store whose log 1 has the tests' key.
fn log_store(path: Option<&Path>) -> SqliteStore {
    let store = match path {
        Some(p) => SqliteStore::open(p).unwrap(),
        None => SqliteStore::open_in_memory().unwrap(),
    };
    store.first_log_key(LOG_SEED, T.parse().unwrap()).unwrap();
    store
}

fn hub_on(config: Config, store: SqliteStore, clock: &Arc<ManualClock>) -> Hub {
    Hub::build(
        config,
        Arc::new(store),
        clock.clone(),
        timers(),
        KeyServices::default(),
    )
    .unwrap()
}

/// A hub in witness mode that enrols log 1 of `chat.example.org`.
fn witness_hub(clock: &Arc<ManualClock>) -> Hub {
    let mut c = config();
    c.hostname = "witness-b.test".into();
    c.witness.enabled = true;
    c.witness.logs = vec![log1_vkey()];
    let store = SqliteStore::open_in_memory().unwrap();
    store.witness_seed(HUB_W_SEED, T.parse().unwrap()).unwrap();
    hub_on(c, store, clock)
}

/// The witnesses, as the log reaches them: requests go straight to the
/// test witness and to the witness hub, with no network.
struct Witnesses {
    test: Mutex<TestWitness>,
    hub: Hub,
    clock: Arc<ManualClock>,
    /// URL prefixes that do not answer.
    down: Mutex<HashSet<&'static str>>,
}

impl Witnesses {
    fn new(clock: &Arc<ManualClock>) -> Arc<Witnesses> {
        Arc::new(Witnesses {
            test: Mutex::new(TestWitness::new(TEST_W, &TEST_W_SEED)),
            hub: witness_hub(clock),
            clock: clock.clone(),
            down: Mutex::new(HashSet::new()),
        })
    }

    fn set_down(&self, url: &'static str, down: bool) {
        let mut d = self.down.lock().unwrap();
        if down {
            d.insert(url);
        } else {
            d.remove(url);
        }
    }

    fn test_witness(&self, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let mut w = self.test.lock().unwrap();
        let now = self.clock.now().unix_millis() / 1000;
        let answer = match path {
            "add-checkpoint" => {
                // The operator gave the test witness log 1's key.
                let log1 = risala_keylog::LogKey::from_vkey_str(&log1_vkey()).unwrap();
                let req = AddCheckpoint::parse(body).unwrap();
                let key = (req.checkpoint.checkpoint().origin() == origin(1)).then_some(&log1);
                w.add_checkpoint_body(body, key, now)
                    .map(String::into_bytes)
            }
            "risala/handoff" => w.handoff_body(body).map(|()| Vec::new()),
            _ => return (404, Vec::new()),
        };
        match answer {
            Ok(body) => (200, body),
            Err(WitnessRefusal::Conflict(n)) => (409, format!("{n}\n").into_bytes()),
            Err(e) => (e.status(), Vec::new()),
        }
    }
}

impl Transport for Witnesses {
    fn post<'a>(&'a self, url: &'a str, body: Vec<u8>) -> Posted<'a> {
        Box::pin(async move {
            if self.down.lock().unwrap().iter().any(|d| url.starts_with(d)) {
                return Err("connection refused".into());
            }
            if let Some(path) = url.strip_prefix(&format!("{TEST_W_URL}/")) {
                return Ok(self.test_witness(path, &body));
            }
            if let Some(path) = url.strip_prefix("https://witness-b.test") {
                let answer = self.hub.witness_request(path, body).await.unwrap();
                return Ok((answer.status, answer.body));
            }
            Err(format!("no witness at {url}"))
        })
    }
}

fn secret(seed: u8) -> SecretKey {
    SecretKey::from_seed([seed; 32])
}

/// A first `master` record of `uid`, naming `log`.
fn master(uid: &str, seed: u8, log: &LogKey) -> Record {
    let content = RecordContent {
        uid: uid.parse().unwrap(),
        previous: None,
        time: 1_790_000_000_000 + u64::from(seed),
        body: RecordBody::Master {
            master_key: secret(seed).public_key(),
            signing_key: secret(seed.wrapping_add(100)).public_key(),
            log: log.clone(),
        },
    };
    Record::sign_deterministic(content, &secret(seed)).unwrap()
}

/// A record after `previous`, signed by the master key of `seed`.
fn next(previous: &Record, seed: u8, body: RecordBody) -> Record {
    let content = RecordContent {
        uid: previous.content().uid.clone(),
        previous: Some(previous.hash()),
        time: previous.content().time + 1000,
        body,
    };
    Record::sign_deterministic(content, &secret(seed)).unwrap()
}

fn now(hub: &Hub) -> u64 {
    hub.inner.now().unix_millis() / 1000
}

async fn get(hub: &Hub, path: &str) -> (u16, Vec<u8>) {
    let a = hub.serve_log(path).await.expect("a log path");
    (a.status, a.body)
}

/// The witnessed checkpoint log `n` serves, under `policy`.
async fn witnessed(
    hub: &Hub,
    n: u64,
    key: &risala_keylog::LogKey,
    policy: &WitnessPolicy,
) -> risala_keylog::WitnessedCheckpoint {
    let (status, body) = get(hub, &format!("/risala-log/{n}/checkpoint")).await;
    assert_eq!(status, 200);
    policy
        .verify(key, &body, Freshness::fresh(now(hub)))
        .unwrap()
}

/// Fetches `tiles` of log `n` into a set, as a device does.
async fn fetch(hub: &Hub, n: u64, tiles: &[risala_keylog::TileId], set: &mut TileSet) {
    for t in set.missing(tiles) {
        let (status, data) = get(hub, &format!("/risala-log/{n}/{}", t.path())).await;
        assert_eq!(status, 200, "{}", t.path());
        set.insert(t, data).unwrap();
    }
}

/// Entry `index` of log `n`, from its entry bundle.
async fn entry(hub: &Hub, n: u64, index: u64, size: u64) -> Vec<u8> {
    let bundle = bundle_for_entry(index, size).unwrap();
    let (status, data) = get(hub, &format!("/risala-log/{n}/{}", bundle.path())).await;
    assert_eq!(status, 200);
    decode_bundle(&data).unwrap()[(index % 256) as usize].clone()
}

fn policy() -> WitnessPolicy {
    WitnessPolicy::from_vkeys(&[test_w_vkey(), hub_w_vkey()], 2).unwrap()
}

/// The hub starts log 1, with a key that stays (4.5).
#[tokio::test]
async fn the_log_starts_empty_with_its_own_key() {
    let clock = Arc::new(ManualClock::new(T.parse().unwrap()));
    let hub = hub_on(both(), SqliteStore::open_in_memory().unwrap(), &clock);
    let log = &hub.inner.keylog;
    assert_eq!(log.size(), Some(0));
    let key = log.current_log().unwrap();
    assert_eq!(key.origin(), origin(1));
    assert_eq!(log.vkey().unwrap(), key.vkey());
    assert_eq!(
        log.url().as_deref(),
        Some("https://chat.example.org/risala-log/1")
    );
    assert_eq!(hub.inner.store.log_keys().unwrap().len(), 1);
    // No checkpoint until the first round.
    assert_eq!(get(&hub, "/risala-log/1/checkpoint").await.0, 404);
    assert_eq!(get(&hub, "/risala-log/2/checkpoint").await.0, 404);
    assert_eq!(get(&hub, "/risala-log/01/checkpoint").await.0, 404);
    assert_eq!(get(&hub, "/risala-log/1/risala/next").await.0, 404);
    assert_eq!(hub.serve_log("/.well-known/risala/a").await, None);

    // A server without an identity domain keeps no log by default.
    let plain = hub_on(config(), SqliteStore::open_in_memory().unwrap(), &clock);
    assert_eq!(plain.inner.keylog.current_log(), None);
    assert_eq!(plain.inner.keylog.url(), None);
    assert_eq!(get(&plain, "/risala-log/1/checkpoint").await.0, 404);
    let alice = master("alice@example.org", 1, &key);
    assert!(matches!(
        append_records(
            &plain.inner,
            &"alice@example.org".parse().unwrap(),
            vec![alice]
        )
        .await,
        Err(AppendError::NoLog)
    ));
}

/// Records are appended in chain order, each following the newest the
/// log holds of its uid (4.5), and served as entry bundles and hints.
#[tokio::test]
async fn records_append_and_are_served() {
    let clock = Arc::new(ManualClock::new(T.parse().unwrap()));
    let hub = hub_on(both(), log_store(None), &clock);
    let inner = &hub.inner;
    let log = inner.keylog.current_log().unwrap();
    let alice_id = "alice@example.org".parse().unwrap();
    let m = master("alice@example.org", 1, &log);
    let r = next(&m, 1, RecordBody::Retire);
    let logged = append_records(inner, &alice_id, vec![m.clone()])
        .await
        .unwrap();
    assert_eq!(logged.len(), 1);
    assert_eq!((logged[0].log.clone(), logged[0].index), (log.clone(), 0));

    // A second first master record, a fork of the master record, a
    // record of another uid: refused, and nothing is appended.
    let again = master("alice@example.org", 2, &log);
    let fork = next(&m, 1, RecordBody::Log(log.clone()));
    for bad in [vec![again], vec![r.clone(), fork.clone()], vec![m.clone()]] {
        assert!(matches!(
            append_records(inner, &alice_id, bad).await,
            Err(AppendError::DoesNotFollow)
        ));
    }
    let bob = master("bob@example.org", 3, &log);
    assert!(matches!(
        append_records(inner, &alice_id, vec![bob.clone()]).await,
        Err(AppendError::WrongUid)
    ));
    assert_eq!(inner.keylog.size(), Some(1));

    let logged = append_records(inner, &"bob@example.org".parse().unwrap(), vec![bob])
        .await
        .unwrap();
    assert_eq!(logged[0].index, 1);
    let logged = append_records(inner, &alice_id, vec![r.clone()])
        .await
        .unwrap();
    assert_eq!(logged[0].index, 2);
    // A record after the newest, even with equal content to another, is
    // refused once something follows its `previous` (4.5).
    assert!(matches!(
        append_records(inner, &alice_id, vec![fork]).await,
        Err(AppendError::DoesNotFollow)
    ));
    assert_eq!(
        index_of(inner, r.hash()).await.unwrap().map(|l| l.index),
        Some(2)
    );
    assert_eq!(
        index_of(inner, r.content().previous.unwrap())
            .await
            .unwrap()
            .map(|l| l.index),
        Some(0)
    );

    // Hints (4.5).
    let (status, body) = get(
        &hub,
        &format!("/risala-log/1/{}", uid_hint_path("alice@example.org")),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(UidHint::parse(&body).unwrap().indices(), [0, 2]);
    let carol = format!("/risala-log/1/{}", uid_hint_path("carol@example.org"));
    assert_eq!(get(&hub, &carol).await.0, 404);
    assert_eq!(get(&hub, "/risala-log/1/risala/uid/ABC").await.0, 404);
    // Entry bundles and hash tiles.
    let (status, bundle) = get(&hub, "/risala-log/1/tile/entries/000.p/3").await;
    assert_eq!(status, 200);
    let entries = decode_bundle(&bundle).unwrap();
    assert_eq!(
        risala_proto::record::LogEntry::decode(&entries[2]).unwrap(),
        risala_proto::record::LogEntry::Record(r)
    );
    assert_eq!(get(&hub, "/risala-log/1/tile/entries/000.p/4").await.0, 404);
    assert_eq!(get(&hub, "/risala-log/1/tile/0/000.p/3").await.0, 200);
    assert_eq!(get(&hub, "/risala-log/1/tile/0/000").await.0, 404);
    assert_eq!(get(&hub, "/risala-log/1/tile/0/0").await.0, 404);
}

/// A checkpoint is cosigned by the test witness and by a hub in witness
/// mode, and a device accepts a record from the served checkpoint and
/// tiles (4.5, 4.10).
#[tokio::test]
async fn a_witnessed_checkpoint_proves_records() {
    let clock = Arc::new(ManualClock::new(T.parse().unwrap()));
    let hub = hub_on(both(), log_store(None), &clock);
    let witnesses = Witnesses::new(&clock);
    hub.inner.keylog.set_transport(witnesses.clone());
    let inner = &hub.inner;
    let log = inner.keylog.current_log().unwrap();
    // More than one tile's worth of entries.
    let mut records = Vec::new();
    for i in 0..260u32 {
        let uid = format!("u{i}@example.org");
        let record = master(&uid, (i % 250) as u8, &log);
        append_records(inner, &uid.parse().unwrap(), vec![record.clone()])
            .await
            .unwrap();
        records.push(record);
    }
    assert!(witness_round(inner).await);
    let key = risala_keylog::LogKey::from_vkey_str(&log.vkey()).unwrap();
    let wc = witnessed(&hub, 1, &key, &policy()).await;
    assert_eq!(wc.checkpoint().size(), 260);
    assert_eq!(wc.witnesses().len(), 2);
    // The witness hub keeps what it cosigned.
    let row = witnesses
        .hub
        .inner
        .store
        .witness_log(&origin(1))
        .unwrap()
        .unwrap();
    assert_eq!((row.size, row.vkey), (260, log1_vkey()));

    // A device proves entries 3 and 258 from the tiles.
    let mut view = LogView::new(key.clone(), wc.clone()).unwrap();
    for index in [3u64, 258] {
        let mut set = TileSet::new();
        fetch(
            &hub,
            1,
            &view.tiles_for_entry(wc.checkpoint(), index),
            &mut set,
        )
        .await;
        let e = entry(&hub, 1, index, 260).await;
        let record = &records[index as usize];
        let got = accept_record(
            &mut view,
            wc.clone(),
            &e,
            index,
            record.hash().hash(),
            &mut set.reader(260),
            now(&hub),
        )
        .unwrap();
        assert_eq!(got, record.encoded());
    }
    // A full tile is served once complete.
    assert_eq!(get(&hub, "/risala-log/1/tile/0/000").await.0, 200);
    assert_eq!(get(&hub, "/risala-log/1/tile/entries/000").await.0, 200);

    // Nothing new: the round has nothing to do until the refresh.
    assert!(witness_round(inner).await);
    let same = get(&hub, "/risala-log/1/checkpoint").await.1;
    assert_eq!(same, wc.signed().to_text().into_bytes());

    // A new record, then a round 10 seconds later: the witnesses get a
    // consistency proof from 260, and the device a consistent checkpoint.
    clock.advance(Duration::from_secs(11));
    let alice = master("alice@example.org", 251, &log);
    append_records(inner, &"alice@example.org".parse().unwrap(), vec![alice])
        .await
        .unwrap();
    assert!(witness_round(inner).await);
    let wc2 = witnessed(&hub, 1, &key, &policy()).await;
    assert_eq!(wc2.checkpoint().size(), 261);
    let mut set = TileSet::new();
    fetch(&hub, 1, &view.tiles_for(wc2.checkpoint()), &mut set).await;
    view.check(wc2, &mut set.reader(261)).unwrap();

    // An hour later the log gets a fresh checkpoint of the same size.
    clock.advance(Duration::from_secs(3600));
    assert!(witness_round(inner).await);
    let wc3 = witnessed(&hub, 1, &key, &policy()).await;
    assert_eq!(wc3.checkpoint().size(), 261);
    assert!(wc3.witnessed_at() > wc.witnessed_at());
}

/// Without k cosignatures the checkpoint is not served as witnessed, and
/// the round is tried again; once a witness is back, it is (4.5).
#[tokio::test]
async fn a_witness_that_is_down_is_retried() {
    let clock = Arc::new(ManualClock::new(T.parse().unwrap()));
    let hub = hub_on(both(), log_store(None), &clock);
    let witnesses = Witnesses::new(&clock);
    hub.inner.keylog.set_transport(witnesses.clone());
    let key = risala_keylog::LogKey::from_vkey_str(&log1_vkey()).unwrap();
    witnesses.set_down(HUB_W_URL, true);
    assert!(!witness_round(&hub.inner).await);
    // The log serves what it has: its own signature and one cosignature.
    let (status, body) = get(&hub, "/risala-log/1/checkpoint").await;
    assert_eq!(status, 200);
    assert!(
        policy()
            .verify(&key, &body, Freshness::fresh(now(&hub)))
            .is_err()
    );
    let one = WitnessPolicy::from_vkeys(&[test_w_vkey()], 1).unwrap();
    assert!(one.verify(&key, &body, Freshness::fresh(now(&hub))).is_ok());

    clock.advance(Duration::from_secs(15));
    witnesses.set_down(HUB_W_URL, false);
    assert!(witness_round(&hub.inner).await);
    witnessed(&hub, 1, &key, &policy()).await;
}

/// After a restart the log does not know what each witness cosigned, and
/// follows their 409 answers (TLOG-WITNESS); it keeps serving its newest
/// witnessed checkpoint from the store.
#[tokio::test]
async fn a_restarted_log_follows_the_witnesses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("risala.db");
    let clock = Arc::new(ManualClock::new(T.parse().unwrap()));
    let witnesses = Witnesses::new(&clock);
    let key = risala_keylog::LogKey::from_vkey_str(&log1_vkey()).unwrap();
    let log = {
        let hub = hub_on(both(), log_store(Some(&path)), &clock);
        hub.inner.keylog.set_transport(witnesses.clone());
        let log = hub.inner.keylog.current_log().unwrap();
        let m = master("alice@example.org", 1, &log);
        append_records(&hub.inner, &"alice@example.org".parse().unwrap(), vec![m])
            .await
            .unwrap();
        assert!(witness_round(&hub.inner).await);
        log
    };
    let hub = hub_on(both(), SqliteStore::open(&path).unwrap(), &clock);
    hub.inner.keylog.set_transport(witnesses.clone());
    assert_eq!(hub.inner.keylog.current_log(), Some(log.clone()));
    assert_eq!(hub.inner.keylog.size(), Some(1));
    let before = witnessed(&hub, 1, &key, &policy()).await;
    clock.advance(Duration::from_secs(11));
    let bob = master("bob@example.org", 2, &log);
    append_records(&hub.inner, &"bob@example.org".parse().unwrap(), vec![bob])
        .await
        .unwrap();
    assert!(witness_round(&hub.inner).await);
    let after = witnessed(&hub, 1, &key, &policy()).await;
    assert_eq!(after.checkpoint().size(), 2);
    let mut view = LogView::new(key, before).unwrap();
    let mut set = TileSet::new();
    fetch(&hub, 1, &view.tiles_for(after.checkpoint()), &mut set).await;
    view.check(after, &mut set.reader(2)).unwrap();
}

/// Raising `log.number` hands log 1 off to log 2 (4.5): the hand-off is
/// log 1's last entry, both witnesses take it (4.10) and enrol log 2, a
/// device follows it, and chains continue in log 2.
#[tokio::test]
async fn a_hand_off_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("risala.db");
    let clock = Arc::new(ManualClock::new(T.parse().unwrap()));
    let witnesses = Witnesses::new(&clock);
    let key1 = risala_keylog::LogKey::from_vkey_str(&log1_vkey()).unwrap();
    let (log1, m) = {
        let hub = hub_on(both(), log_store(Some(&path)), &clock);
        hub.inner.keylog.set_transport(witnesses.clone());
        let log1 = hub.inner.keylog.current_log().unwrap();
        let m = master("alice@example.org", 1, &log1);
        append_records(
            &hub.inner,
            &"alice@example.org".parse().unwrap(),
            vec![m.clone()],
        )
        .await
        .unwrap();
        assert!(witness_round(&hub.inner).await);
        (log1, m)
    };
    let seen = {
        let hub = hub_on(both(), SqliteStore::open(&path).unwrap(), &clock);
        witnessed(&hub, 1, &key1, &policy()).await
    };

    // The operator raises the number. Two at once, or down, is refused.
    for bad in [Some(3), Some(0)] {
        let mut c = both();
        c.log.number = bad;
        assert!(
            Hub::build(
                c,
                Arc::new(SqliteStore::open(&path).unwrap()),
                clock.clone(),
                timers(),
                KeyServices::default()
            )
            .is_err()
        );
    }
    clock.advance(Duration::from_secs(11));
    let mut c = both();
    c.log.number = Some(2);
    let hub = hub_on(c.clone(), SqliteStore::open(&path).unwrap(), &clock);
    hub.inner.keylog.set_transport(witnesses.clone());
    let inner = &hub.inner;
    let log2 = inner.keylog.current_log().unwrap();
    assert_eq!(log2.origin(), origin(2));
    assert_eq!(inner.keylog.logs(), [log1.clone(), log2.clone()]);
    assert_eq!(
        inner.keylog.url().as_deref(),
        Some("https://chat.example.org/risala-log/2")
    );
    assert!(inner.keylog.handoffs().handed_off(&log1, &log2));
    assert!(!inner.keylog.handoffs().handed_off(&log2, &log1));
    let (status, body) = get(&hub, "/risala-log/1/risala/next").await;
    assert_eq!(status, 200);
    let index = parse_next(&body).unwrap();
    assert_eq!(index, 1);

    // Chains continue in log 2, after their newest record in log 1.
    let alice_id = "alice@example.org".parse().unwrap();
    assert!(matches!(
        append_records(
            inner,
            &alice_id,
            vec![master("alice@example.org", 9, &log2)]
        )
        .await,
        Err(AppendError::DoesNotFollow)
    ));
    let r = next(&m, 1, RecordBody::Retire);
    let logged = append_records(inner, &alice_id, vec![r.clone()])
        .await
        .unwrap();
    assert_eq!((logged[0].log.clone(), logged[0].index), (log2.clone(), 0));

    // One round: log 1's last checkpoint and the hand-off go to both
    // witnesses, then log 2's first checkpoint, which both enrol.
    assert!(witness_round(inner).await);
    assert_eq!(
        witnesses
            .hub
            .inner
            .store
            .witness_log(&origin(1))
            .unwrap()
            .unwrap()
            .handoff
            .map(|(i, _)| i),
        Some(1)
    );
    let w1 = witnessed(&hub, 1, &key1, &policy()).await;
    assert_eq!(w1.checkpoint().size(), 2);
    let key2 = risala_keylog::LogKey::from_vkey_str(&log2.vkey()).unwrap();
    let w2 = witnessed(&hub, 2, &key2, &policy()).await;
    assert_eq!(w2.checkpoint().size(), 1);

    // A device that saw log 1 at size 1 follows the hand-off.
    let mut view = LogView::new(key1.clone(), seen).unwrap();
    let mut set = TileSet::new();
    fetch(
        &hub,
        1,
        &view.tiles_for_entry(w1.checkpoint(), index),
        &mut set,
    )
    .await;
    let e = entry(&hub, 1, index, 2).await;
    let next_key = accept_handoff(&mut view, w1, &e, index, &mut set.reader(2)).unwrap();
    assert_eq!(next_key, key2);
    // And accepts the record in log 2.
    let mut view2 = LogView::new(key2, w2.clone()).unwrap();
    let mut set = TileSet::new();
    fetch(
        &hub,
        2,
        &view2.tiles_for_entry(w2.checkpoint(), 0),
        &mut set,
    )
    .await;
    let e = entry(&hub, 2, 0, 1).await;
    accept_record(
        &mut view2,
        w2,
        &e,
        0,
        r.hash().hash(),
        &mut set.reader(1),
        now(&hub),
    )
    .unwrap();

    // Log 1 is done: later rounds leave it alone, and witnesses cosign no
    // larger tree of it.
    clock.advance(Duration::from_secs(3600));
    assert!(witness_round(inner).await);
    assert_eq!(
        witnessed(&hub, 1, &key1, &policy())
            .await
            .checkpoint()
            .size(),
        2
    );
    // A restart with the same number keeps log 2.
    drop(hub);
    let hub = hub_on(c, SqliteStore::open(&path).unwrap(), &clock);
    assert_eq!(hub.inner.keylog.current_log(), Some(log2));
}

/// The witness's own requests (4.10): an unknown log 1 is not enrolled,
/// a bad body is refused, and a 409 carries the witness's size.
#[tokio::test]
async fn the_witness_answers_by_the_rules() {
    let clock = Arc::new(ManualClock::new(T.parse().unwrap()));
    let witness = witness_hub(&clock);
    assert!(witness.inner.keylog.witness_vkey().is_some());
    let other = Cosigner::from_seed("other.example/risala-log/1", &[3; 32]).unwrap();
    let cp = risala_keylog::Checkpoint::new(other.name(), 0, risala_keylog::merkle::empty_root())
        .unwrap();
    let mut sc = risala_keylog::SignedCheckpoint::unsigned(cp);
    sc.push_signature(other.cosign(sc.checkpoint(), now(&witness), [0; 32]))
        .unwrap();
    let body = AddCheckpoint {
        old_size: 0,
        proof: vec![],
        checkpoint: sc,
    }
    .to_body()
    .into_bytes();
    let ask = |path: &'static str, body: Vec<u8>| {
        let w = witness.clone();
        async move { w.witness_request(path, body).await.unwrap() }
    };
    assert_eq!(
        ask("/risala-witness/add-checkpoint", body).await.status,
        404
    );
    assert_eq!(
        ask("/risala-witness/add-checkpoint", b"junk".to_vec())
            .await
            .status,
        400
    );
    assert_eq!(
        ask("/risala-witness/risala/handoff", b"junk".to_vec())
            .await
            .status,
        400
    );
    assert_eq!(ask("/risala-witness/other", Vec::new()).await.status, 404);
    assert_eq!(
        witness.witness_request("/elsewhere", Vec::new()).await,
        None
    );

    // Log 1 of chat.example.org, which the operator configured, enrols;
    // then a request from the wrong old size gets 409 with the size.
    let log = risala_keylog::testlog::MemoryLog::new(&origin(1).parse().unwrap(), &LOG_SEED);
    let enrol = AddCheckpoint {
        old_size: 0,
        proof: vec![],
        checkpoint: log.checkpoint(now(&witness)),
    };
    let a = ask(
        "/risala-witness/add-checkpoint",
        enrol.to_body().into_bytes(),
    )
    .await;
    assert_eq!(a.status, 200);
    clock.advance(Duration::from_secs(11));
    let mut log = log;
    log.append(b"x");
    let wrong = AddCheckpoint {
        old_size: 1,
        proof: vec![],
        checkpoint: log.checkpoint(now(&witness)),
    };
    let a = ask(
        "/risala-witness/add-checkpoint",
        wrong.to_body().into_bytes(),
    )
    .await;
    assert_eq!((a.status, a.content_type), (409, "text/x.tlog.size"));
    assert_eq!(a.body, b"0\n");

    // A hub that is not a witness has no witness paths.
    let plain = hub_on(config(), SqliteStore::open_in_memory().unwrap(), &clock);
    assert_eq!(
        plain
            .witness_request("/risala-witness/add-checkpoint", Vec::new())
            .await,
        None
    );
}

#[test]
fn log_and_witness_configuration() {
    let good = both();
    assert!(
        check_config(&good)
            .unwrap()
            .iter()
            .any(|w| w.contains("HTTPS"))
    );
    let mut none = log_config(&[], None, None);
    none.http.listen = vec!["127.0.0.1:0".parse().unwrap()];
    assert!(check_config(&none).unwrap()[0].contains("no witnesses"));
    let bad = |f: &dyn Fn(&mut Config)| {
        let mut c = both();
        f(&mut c);
        check_config(&c).unwrap_err()
    };
    assert!(bad(&|c| c.log.k = Some(3)).contains("log.k"));
    assert!(bad(&|c| c.log.k = Some(0)).contains("log.k"));
    assert!(bad(&|c| c.log.url = Some("http://chat.example.org".into())).contains("log.url"));
    assert!(bad(&|c| c.log.url = Some("https://chat.example.org/x".into())).contains("log.url"));
    assert!(bad(&|c| c.log.witnesses[0].vkey = "nonsense".into()).contains("verifier key"));
    assert!(bad(&|c| c.log.witnesses[0].url = "https://w.example/".into()).contains("https://"));
    assert!(bad(&|c| c.log.witnesses[1].vkey = test_w_vkey()).contains("twice"));
    assert!(bad(&|c| c.log.refresh_secs = 90_000).contains("refresh_secs"));
    assert!(bad(&|c| c.hostname = "Chat.Example.org".into()).contains("hostname"));
    assert!(
        bad(&|c| {
            c.witness.enabled = true;
            c.witness.logs = vec!["nonsense".into()];
        })
        .contains("witness.logs")
    );
    let log2 = Cosigner::from_seed(&origin(2), &[2; 32])
        .unwrap()
        .vkey()
        .to_string();
    assert!(
        bad(&|c| {
            c.witness.enabled = true;
            c.witness.logs = vec![log2.clone()];
        })
        .contains("hand-off")
    );
    // The whole configuration refuses it too.
    let mut c = both();
    c.log.k = Some(5);
    assert!(c.validate().is_err());
}
