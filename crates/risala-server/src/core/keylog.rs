//! The key log (4.5) and witnessing (4.10).
//!
//! **The log.** A server that hosts identities keeps a key log, an
//! append-only Merkle tree of LogEntries, with the origin
//! `<hostname>/risala-log/<n>` and an ML-DSA-44 key that is generated once
//! and kept in the store. It has no commands of its own: REGISTER and
//! KEYS PUT (`identity`) append to it through [`append_records`], once
//! the chain checks of 4.7 have passed. The log itself checks only what is
//! its own (4.5, "Appending"): each record follows the newest record of
//! its uid that the host's logs hold, so no `previous` is followed twice
//! and no second first `master` record of a uid is taken.
//!
//! **Serving.** The HTTPS listener serves each log the server has run
//! under `/risala-log/<n>`: its checkpoint, hash tiles and entry bundles
//! [TLOG-TILES], the hints `risala/uid/<hash>` and `risala/next`, and its
//! key file `risala/key` ([`Hub::serve_log`]). The URL prefix of the current log, and its
//! verifier key, are what INFO reports as `log=` and `log-key=`
//! ([`State::url`], [`State::vkey`]).
//!
//! **Witnessing.** [`maintain`] signs a checkpoint after each new record
//! (at most every 10 seconds, the witnesses' limit) and at least every
//! `log.refresh_secs` otherwise, and asks every configured witness to
//! cosign it with [TLOG-WITNESS]'s `add-checkpoint`. A checkpoint with `k`
//! cosignatures is witnessed, and is the one served; until the log has
//! one, it serves its newest checkpoint with only its own signature.
//! Failed rounds are retried within 5 minutes, so a new record is in a
//! witnessed checkpoint well within the hour 4.5 allows.
//!
//! **Hand-offs.** Raising `log.number` by one hands the current log off at
//! the next start (4.5): its last entry names the next log and its new
//! key, and from then on records go into the next log. The old log gets a
//! witnessed checkpoint whose last entry is the hand-off, which is shown
//! to each witness with `POST <prefix>/risala/handoff` (4.10) before the
//! next log's first checkpoint reaches it. The old log is served for ever.
//!
//! **Witness mode.** With `[witness] enabled`, the server is also a
//! witness for other servers' logs (4.10), at `/risala-witness`: a
//! [`WitnessCore`] over the store ([`Hub::witness_request`]). It enrols a
//! host's first log with the key it fetches from
//! `https://<host>/risala-log/1/risala/key`, through the hub's
//! [`KeyFetcher`](crate::keyfiles::KeyFetcher), and each later log with the
//! key of the hand-off it took.

use crate::keyfiles::DynKeyFetcher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use risala_keylog::addcheckpoint::AddCheckpoint;
use risala_keylog::checkpoint::{Checkpoint, LogOrigin, SignedCheckpoint};
use risala_keylog::cosig::{CosignatureVerifier, Cosigner};
use risala_keylog::handoff::HandoffRequest;
use risala_keylog::hint::{KEY_PATH, NEXT_PATH, UID_PATH, UidHint, log_key_body, next_body};
use risala_keylog::merkle::{Hash, leaf_hash};
use risala_keylog::note::NoteSignature;
use risala_keylog::proof::{consistency_proof, inclusion_proof, tree_hash};
use risala_keylog::tile::{HashTiles, TILE_WIDTH, TileId, TileKind, encode_bundle};
use risala_keylog::witnessing::{
    CoreError, Handoff, LogKeyFetcher, LogState, MIN_INTERVAL, WitnessConfig as CoreConfig,
    WitnessCore, WitnessRefusal, WitnessStore,
};
use risala_proto::auth::PublicKey;
use risala_proto::chain::Handoffs;
use risala_proto::names::Identity;
use risala_proto::record::{LogEntry as ProtoEntry, LogKey, MAX_CHAIN_LEN, Record};
use risala_proto::time::Timestamp;

use super::state::ConnEntry;
use super::{Clock, Hub, Inner};
use crate::config::Config;
use crate::handler::ConnId;
use crate::store::keylog::{CheckpointRow, LoggedRecord, WitnessLogRow};
use crate::store::{LogEntry, Store, StoreError};

/// The path under which the logs are served: `/risala-log/<n>/…` (4.5).
pub const LOG_PATH: &str = "/risala-log/";

/// The path under which the server's witness takes requests (4.10).
pub const WITNESS_PATH: &str = "/risala-witness";

/// How long a witness has to answer a request.
pub const WITNESS_TIMEOUT: Duration = Duration::from_secs(10);

/// The first wait before a failed witnessing round is tried again.
const RETRY_MIN: Duration = Duration::from_secs(15);

/// The longest wait before a failed witnessing round is tried again, so
/// that a new record gets a witnessed checkpoint within the hour (4.5).
const RETRY_MAX: Duration = Duration::from_secs(300);

/// The most bytes of a witness's response that are read.
pub const MAX_WITNESS_RESPONSE: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Configuration

/// A witness the log sends its checkpoints to.
#[derive(Debug, Clone)]
struct Target {
    verifier: CosignatureVerifier,
    /// The URL prefix, without a `/` at the end.
    url: String,
}

/// The log's settings, from `[log]`.
#[derive(Debug, Clone)]
struct Settings {
    host: String,
    /// `https://<host>[:<port>]`.
    base_url: String,
    witnesses: Vec<Target>,
    k: usize,
    refresh: u64,
    number: Option<u64>,
}

/// Whether `url` is `https://<host>[:<port>]` and maybe a path, with no
/// `/` at the end, query or fragment.
fn https_url(url: &str, path_ok: bool) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    !authority.is_empty()
        && !url.ends_with('/')
        && !url.contains(['?', '#', ' ', '\\'])
        && (path_ok || path.is_empty())
}

fn settings(config: &Config) -> Result<Option<Settings>, String> {
    let log = &config.log;
    if !log.enabled.unwrap_or(config.identity_domain.is_some()) {
        return Ok(None);
    }
    let host = config.hostname.clone();
    LogOrigin::new(&host, 1).map_err(|_| {
        format!(
            "hostname {host:?} cannot name a key log: a log's origin is \
             <hostname>/risala-log/<n>, with the hostname in lower case (4.5)"
        )
    })?;
    let base_url = log.url.clone().unwrap_or_else(|| format!("https://{host}"));
    if !https_url(&base_url, false) {
        return Err(format!(
            "log.url {base_url:?} must be https://<host>[:<port>], with no path"
        ));
    }
    let mut witnesses = Vec::new();
    for w in &log.witnesses {
        let verifier = CosignatureVerifier::from_vkey_str(&w.vkey).map_err(|e| {
            format!(
                "log.witnesses: {:?} is not an ML-DSA-44 verifier key: {e}",
                w.vkey
            )
        })?;
        if !https_url(&w.url, true) {
            return Err(format!(
                "log.witnesses: {:?} must be an https:// URL prefix without a / at the end",
                w.url
            ));
        }
        if witnesses
            .iter()
            .any(|t: &Target| t.verifier.name() == verifier.name())
        {
            return Err(format!("log.witnesses names {} twice", verifier.name()));
        }
        witnesses.push(Target {
            verifier,
            url: w.url.clone(),
        });
    }
    let n = witnesses.len();
    let k = log.k.unwrap_or(if n == 0 { 0 } else { n / 2 + 1 });
    if k > n || (n > 0 && k == 0) {
        return Err(format!(
            "log.k is {k}, but must be 1 to {n}, the number of witnesses"
        ));
    }
    if !(60..=43_200).contains(&log.refresh_secs) {
        return Err(format!(
            "log.refresh_secs is {}, but must be 60 to 43200 (4.5)",
            log.refresh_secs
        ));
    }
    if log.number == Some(0) {
        return Err("log.number starts at 1 (4.5)".into());
    }
    Ok(Some(Settings {
        host,
        base_url,
        witnesses,
        k,
        refresh: log.refresh_secs,
        number: log.number,
    }))
}

/// The witness's name, from `[witness]`.
fn witness_settings(config: &Config) -> Result<Option<String>, String> {
    let w = &config.witness;
    if !w.enabled {
        return Ok(None);
    }
    let name = w
        .name
        .clone()
        .unwrap_or_else(|| format!("{}{WITNESS_PATH}", config.hostname));
    if !risala_keylog::note::is_valid_key_name(&name) {
        return Err(format!("witness.name {name:?} is not a key name"));
    }
    Ok(Some(name))
}

/// Checks `[log]` and `[witness]`, and returns warnings, for
/// [`Config::validate`].
pub(crate) fn check_config(config: &Config) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    let log = settings(config)?;
    let witness = witness_settings(config)?;
    if let Some(log) = &log {
        if log.witnesses.is_empty() {
            warnings.push(
                "the key log has no witnesses: devices accept no record of it until \
                 log.witnesses names some (4.5)"
                    .into(),
            );
        }
        if config.http.listen.is_empty() {
            warnings.push(format!(
                "the key log is served only by the HTTPS listener: serve {}{LOG_PATH} \
                 from it, or proxy that path to it (4.5)",
                log.base_url
            ));
        }
    }
    if witness.is_some() && config.http.listen.is_empty() {
        warnings.push("witness.enabled is on, but there is no HTTPS listener (4.10)".into());
    }
    Ok(warnings)
}

// ---------------------------------------------------------------------------
// State

/// What the key log keeps in memory.
pub(crate) struct State {
    log: Option<LogSide>,
    witness: Option<WitnessSide>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("log", &self.log.is_some())
            .field("witness", &self.witness.is_some())
            .finish()
    }
}

/// The server's own logs.
struct LogSide {
    settings: Settings,
    logs: Mutex<Logs>,
    /// The size of each log that each witness last cosigned, by witness and
    /// log number, as far as the log knows; 0 when it does not.
    known: Mutex<HashMap<(usize, u64), u64>>,
    /// Woken by each append, so that a witnessed checkpoint follows soon.
    wake: tokio::sync::Notify,
    /// How requests reach the witnesses.
    transport: RwLock<Arc<dyn Transport>>,
}

/// Every log the server has run, by number. The last is the current one.
struct Logs {
    runs: BTreeMap<u64, Run>,
}

impl Logs {
    fn current(&self) -> &Run {
        self.runs
            .values()
            .next_back()
            .expect("there is always a log")
    }

    fn current_mut(&mut self) -> &mut Run {
        self.runs
            .values_mut()
            .next_back()
            .expect("there is always a log")
    }
}

/// One log.
struct Run {
    origin: LogOrigin,
    cosigner: Cosigner,
    key: LogKey,
    tiles: HashTiles,
    /// The index of its hand-off entry, which is its last.
    handoff: Option<u64>,
    /// Its newest witnessed checkpoint's size, and when it was signed, in
    /// seconds.
    witnessed: Option<(u64, u64)>,
    /// The checkpoint served at `<prefix>/checkpoint`.
    served: Option<Arc<str>>,
    /// The witnesses, by position in the list, that took its hand-off.
    took_handoff: BTreeSet<usize>,
}

impl Run {
    fn new(host: &str, number: u64, seed: &[u8; 32]) -> Result<Run, StoreError> {
        let origin = LogOrigin::new(host, number)
            .map_err(|e| StoreError::Setup(format!("log origin of {host:?}: {e}")))?;
        let cosigner = Cosigner::from_seed(&origin.to_string(), seed)
            .map_err(|e| StoreError::Setup(format!("log key: {e}")))?;
        let key = LogKey::new(
            &origin.to_string(),
            PublicKey::from_bytes(cosigner.public_key()),
        )
        .map_err(|e| StoreError::Setup(format!("log key: {e}")))?;
        Ok(Run {
            origin,
            cosigner,
            key,
            tiles: HashTiles::new(),
            handoff: None,
            witnessed: None,
            served: None,
            took_handoff: BTreeSet::new(),
        })
    }

    fn number(&self) -> u64 {
        self.origin.number()
    }

    fn size(&self) -> u64 {
        self.tiles.size()
    }

    fn root_at(&self, size: u64) -> Hash {
        tree_hash(size, &mut &self.tiles).expect("the log has every node of its own tree")
    }
}

/// The server as a witness.
struct WitnessSide {
    core: Mutex<WitnessCore<StoreWitness, HubLogKeys>>,
}

/// How the witness fetches the key file of a host's first log (4.10):
/// through the hub's key fetcher, under the rules for fetching key files
/// (4.4). The witness calls it on the blocking pool, holding its lock, for
/// at most [`KEY_FETCH_TIMEOUT`](crate::keyfiles::KEY_FETCH_TIMEOUT), and
/// at most once a minute for each origin.
struct HubLogKeys(Arc<dyn DynKeyFetcher>);

impl LogKeyFetcher for HubLogKeys {
    fn fetch_log_key(&mut self, url: &str) -> Option<Vec<u8>> {
        let handle = tokio::runtime::Handle::try_current().ok()?;
        let fetch = tokio::time::timeout(
            crate::keyfiles::KEY_FETCH_TIMEOUT,
            self.0.fetch_log_boxed(url),
        );
        match handle.block_on(fetch) {
            Ok(Ok(crate::keyfiles::UrlBody::Ok(body))) => Some(body),
            Ok(Ok(_)) => {
                tracing::info!(url, "no log key file to enrol (4.10)");
                None
            }
            Ok(Err(e)) => {
                tracing::info!(url, error = %e, "fetching a log key file failed (4.10)");
                None
            }
            Err(_) => {
                tracing::info!(url, "fetching a log key file timed out (4.10)");
                None
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Seconds since 1970, as cosignatures carry them.
fn secs(t: Timestamp) -> u64 {
    t.unix_millis() / 1000
}

fn random_seed() -> Result<[u8; 32], StoreError> {
    crate::secret::random_bytes().map_err(|e| StoreError::Setup(format!("random bytes: {e}")))
}

impl State {
    /// Loads the logs when the hub starts: starts log 1 on a new server,
    /// hands off when `log.number` asks for the next log (4.5), and
    /// rebuilds each log's tree from its entries. Loads or makes the
    /// witness key in witness mode.
    pub(crate) fn load(
        config: &Config,
        store: &Arc<dyn Store>,
        clock: &dyn Clock,
        fetcher: Arc<dyn DynKeyFetcher>,
    ) -> Result<State, StoreError> {
        let now = clock.now();
        let log = match settings(config).map_err(StoreError::Setup)? {
            Some(settings) => Some(LogSide::load(config, settings, &**store, now)?),
            None => None,
        };
        let witness = match witness_settings(config).map_err(StoreError::Setup)? {
            Some(name) => {
                let seed = store.witness_seed(random_seed()?, now)?;
                let cosigner = Cosigner::from_seed(&name, &seed)
                    .map_err(|e| StoreError::Setup(format!("witness key: {e}")))?;
                let core = WitnessCore::new(
                    cosigner,
                    StoreWitness(store.clone()),
                    HubLogKeys(fetcher),
                    CoreConfig::default(),
                );
                tracing::info!(vkey = %core.vkey(), "acting as a key log witness (4.10)");
                Some(WitnessSide {
                    core: Mutex::new(core),
                })
            }
            None => None,
        };
        Ok(State { log, witness })
    }

    /// The current log, as a chain's `master` or `log` record names it
    /// (4.4), or `None` if the server keeps no log.
    #[allow(
        dead_code,
        reason = "the API of the identity area (SV1) and INFO (SV5)"
    )]
    pub(crate) fn current_log(&self) -> Option<LogKey> {
        let side = self.log.as_ref()?;
        Some(lock(&side.logs).current().key.clone())
    }

    /// The URL prefix of the current log, `log=` in INFO (8.5).
    #[allow(
        dead_code,
        reason = "the API of the identity area (SV1) and INFO (SV5)"
    )]
    pub(crate) fn url(&self) -> Option<String> {
        let side = self.log.as_ref()?;
        let n = lock(&side.logs).current().number();
        Some(format!("{}{LOG_PATH}{n}", side.settings.base_url))
    }

    /// The URL prefix of log `number`, if the server has run it.
    #[allow(
        dead_code,
        reason = "the API of the identity area (SV1) and INFO (SV5)"
    )]
    pub(crate) fn url_of(&self, number: u64) -> Option<String> {
        let side = self.log.as_ref()?;
        lock(&side.logs)
            .runs
            .contains_key(&number)
            .then(|| format!("{}{LOG_PATH}{number}", side.settings.base_url))
    }

    /// The verifier key of the current log, `log-key=` in INFO (8.5), and
    /// what a key file's `log` line names (4.4).
    #[allow(
        dead_code,
        reason = "the API of the identity area (SV1) and INFO (SV5)"
    )]
    pub(crate) fn vkey(&self) -> Option<String> {
        Some(self.current_log()?.vkey())
    }

    /// The number of entries in the current log.
    #[allow(
        dead_code,
        reason = "the API of the identity area (SV1) and INFO (SV5)"
    )]
    pub(crate) fn size(&self) -> Option<u64> {
        let side = self.log.as_ref()?;
        Some(lock(&side.logs).current().size())
    }

    /// Every log the server has run, oldest first. Each one before the
    /// current one has handed off to the next (4.5).
    #[allow(
        dead_code,
        reason = "the API of the identity area (SV1) and INFO (SV5)"
    )]
    pub(crate) fn logs(&self) -> Vec<LogKey> {
        self.log.as_ref().map_or_else(Vec::new, |side| {
            lock(&side.logs)
                .runs
                .values()
                .map(|r| r.key.clone())
                .collect()
        })
    }

    /// The server's own hand-offs, for the chain checks of KEYS PUT
    /// ([`risala_proto::chain::keys_put`]): a chain in one of the server's
    /// logs continues in each later one (4.5).
    #[allow(
        dead_code,
        reason = "the API of the identity area (SV1) and INFO (SV5)"
    )]
    pub(crate) fn handoffs(&self) -> OwnHandoffs {
        OwnHandoffs { logs: self.logs() }
    }

    /// The witness's verifier key, for its operator to publish (4.10), in
    /// witness mode.
    #[allow(
        dead_code,
        reason = "the API of the identity area (SV1) and INFO (SV5)"
    )]
    pub(crate) fn witness_vkey(&self) -> Option<String> {
        let w = self.witness.as_ref()?;
        Some(lock(&w.core).vkey().to_string())
    }

    /// Replaces how requests reach the witnesses, for tests.
    #[cfg(test)]
    pub(crate) fn set_transport(&self, transport: Arc<dyn Transport>) {
        if let Some(side) = &self.log {
            *side.transport.write().unwrap_or_else(|e| e.into_inner()) = transport;
        }
    }
}

impl LogSide {
    fn load(
        config: &Config,
        settings: Settings,
        store: &dyn Store,
        now: Timestamp,
    ) -> Result<LogSide, StoreError> {
        let mut rows = store.first_log_key(random_seed()?, now)?;
        let current = rows.last().expect("log 1 was started").number;
        if let Some(wanted) = settings.number {
            if wanted < current {
                return Err(StoreError::Setup(format!(
                    "log.number is {wanted}, but the server already runs log {current}; \
                     a log number never goes down (4.5)"
                )));
            }
            if wanted > current + 1 {
                return Err(StoreError::Setup(format!(
                    "log.number is {wanted}, but the server runs log {current}: \
                     hand off one log at a time (4.5)"
                )));
            }
            if wanted == current + 1 {
                let seed = random_seed()?;
                let next = Run::new(&settings.host, wanted, &seed)?;
                let entry = ProtoEntry::Handoff(next.key.clone()).encode();
                let index = store.hand_off(current, &entry, seed, now)?;
                tracing::warn!(
                    from = current,
                    to = wanted,
                    index,
                    "the key log handed off to the next log (4.5)"
                );
                rows = store.log_keys()?;
            }
        }
        let mut runs = BTreeMap::new();
        for row in rows {
            let mut run = Run::new(&settings.host, row.number, &row.seed)?;
            const PAGE: u64 = 10_000;
            loop {
                let page = store.log_entries(row.number, run.size(), PAGE)?;
                for e in &page {
                    if e.record.is_none()
                        && let Ok(ProtoEntry::Handoff(_)) = ProtoEntry::decode(&e.entry)
                    {
                        run.handoff = Some(run.size());
                    }
                    run.tiles.push(leaf_hash(&e.entry));
                }
                if (page.len() as u64) < PAGE {
                    break;
                }
            }
            let newest = store.log_checkpoint(row.number, false)?;
            let witnessed = store.log_checkpoint(row.number, true)?;
            if let Some(w) = &witnessed {
                run.witnessed = Some((w.size, secs(w.signed)));
            }
            run.served = witnessed
                .or(newest)
                .filter(|c| c.size <= run.size())
                .map(|c| Arc::from(c.note));
            runs.insert(row.number, run);
        }
        let logs = Logs { runs };
        tracing::info!(
            origin = %logs.current().origin,
            size = logs.current().size(),
            vkey = %logs.current().key.vkey(),
            "key log loaded (4.5)"
        );
        let transport: Arc<dyn Transport> = Arc::new(
            crate::http::keylog::HttpsPoster::new(&config.keys.extra_roots)
                .map_err(|e| StoreError::Setup(format!("the key log's HTTPS client: {e}")))?,
        );
        Ok(LogSide {
            settings,
            logs: Mutex::new(logs),
            known: Mutex::new(HashMap::new()),
            wake: tokio::sync::Notify::new(),
            transport: RwLock::new(transport),
        })
    }

    fn transport(&self) -> Arc<dyn Transport> {
        self.transport
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// The server's own logs as hand-offs (4.5): every log before the current
/// one handed off to the next.
#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "the API of the identity area (SV1) and INFO (SV5)"
)]
pub(crate) struct OwnHandoffs {
    logs: Vec<LogKey>,
}

impl Handoffs for OwnHandoffs {
    fn handed_off(&self, from: &LogKey, to: &LogKey) -> bool {
        from.number() < to.number() && self.logs.contains(from) && self.logs.contains(to)
    }
}

/// What a key log keeps about one connection: nothing.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Connection `id` has closed.
pub(super) fn conn_closed(_inner: &Arc<Inner>, _id: ConnId, _conn: &ConnEntry) {}

// ---------------------------------------------------------------------------
// Appending

/// Where a record is in the key log.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the API of the identity area (SV1) and INFO (SV5)"
)]
pub(crate) struct Logged {
    /// The log.
    pub(crate) log: LogKey,
    /// The entry's index in it.
    pub(crate) index: u64,
}

/// Why the log did not append records.
#[derive(Debug, thiserror::Error)]
#[allow(
    dead_code,
    reason = "the API of the identity area (SV1) and INFO (SV5)"
)]
pub(crate) enum AppendError {
    /// The server keeps no key log.
    #[error("the server keeps no key log")]
    NoLog,
    /// A record is of another uid than the one given.
    #[error("a record is of another uid")]
    WrongUid,
    /// A record does not follow the newest record of its uid that the
    /// host's logs hold (4.5): its `previous` is already followed, or it is
    /// a first `master` record of a uid the host already holds.
    #[error("the record does not follow the newest record the log holds of its uid")]
    DoesNotFollow,
    /// The uid would have more entries in the log than a chain may have
    /// records (4.4).
    #[error("the uid has too many entries")]
    TooMany,
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Appends `records`, in chain order, to the current log as record entries
/// of `uid`, and returns where each one went.
///
/// This is how REGISTER and KEYS PUT log records (4.7), once the chain
/// checks have passed ([`risala_proto::chain::check_register`],
/// [`risala_proto::chain::keys_put`], which decides which records go into
/// this log). The log checks only its own rules (4.5): every record is of
/// `uid`, and each follows the newest record of `uid` that the host's logs
/// hold, if they hold any. Records are appended all or none. A witnessed
/// checkpoint that includes them follows within the hour ([`maintain`]).
#[allow(
    dead_code,
    reason = "the API of the identity area (SV1) and INFO (SV5)"
)]
pub(crate) async fn append_records(
    inner: &Arc<Inner>,
    uid: &Identity,
    records: Vec<Record>,
) -> Result<Vec<Logged>, AppendError> {
    if inner.keylog.log.is_none() {
        return Err(AppendError::NoLog);
    }
    let task = {
        let inner = inner.clone();
        let uid = uid.clone();
        tokio::task::spawn_blocking(move || append_blocking(&inner, &uid, &records))
    };
    let logged = task.await.map_err(|e| StoreError::Task(e.to_string()))??;
    if let Some(side) = &inner.keylog.log {
        side.wake.notify_one();
    }
    Ok(logged)
}

fn append_blocking(
    inner: &Inner,
    uid: &Identity,
    records: &[Record],
) -> Result<Vec<Logged>, AppendError> {
    let side = inner.keylog.log.as_ref().ok_or(AppendError::NoLog)?;
    if records.is_empty() {
        return Ok(Vec::new());
    }
    // Appends happen one at a time, under the lock, so the checks and the
    // append see the same log.
    let mut logs = lock(&side.logs);
    let run = logs.current_mut();
    let number = run.number();
    let store = &*inner.store;
    let uid_s = uid.to_uid();
    let mut newest = store.log_newest_record(&uid_s)?;
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        let content = record.content();
        if content.uid != *uid {
            return Err(AppendError::WrongUid);
        }
        if newest.is_some() && content.previous != newest {
            return Err(AppendError::DoesNotFollow);
        }
        let hash = record.hash();
        newest = Some(hash);
        entries.push(LogEntry {
            entry: ProtoEntry::Record(record.clone()).encode(),
            record: Some(LoggedRecord {
                uid: uid_s.clone(),
                hash,
            }),
        });
    }
    let held = store
        .log_uid_indices(number, &crate::store::keylog::uid_hash(uid.as_str()))?
        .len();
    if held + records.len() > MAX_CHAIN_LEN {
        return Err(AppendError::TooMany);
    }
    let first = store.append_entries(number, &entries, inner.now())?;
    for e in &entries {
        run.tiles.push(leaf_hash(&e.entry));
    }
    Ok((first..)
        .take(entries.len())
        .map(|index| Logged {
            log: run.key.clone(),
            index,
        })
        .collect())
}

#[cfg(test)]
impl Hub {
    /// [`append_records`], for tests outside `core`.
    pub(crate) async fn append_for_tests(
        &self,
        uid: &Identity,
        records: Vec<Record>,
    ) -> Result<Vec<Logged>, AppendError> {
        append_records(&self.inner, uid, records).await
    }

    /// The key log's verifier key, for tests outside `core`.
    pub(crate) fn log_vkey(&self) -> Option<String> {
        self.inner.keylog.vkey()
    }
}

/// Where a record is logged, if any of the server's logs holds it.
#[allow(
    dead_code,
    reason = "the API of the identity area (SV1) and INFO (SV5)"
)]
pub(crate) async fn index_of(
    inner: &Arc<Inner>,
    hash: risala_proto::names::BlobRef,
) -> Result<Option<Logged>, StoreError> {
    let Some(side) = &inner.keylog.log else {
        return Ok(None);
    };
    let found = inner.db(move |s| s.log_record_index(&hash)).await?;
    Ok(found.and_then(|(number, index)| {
        let logs = lock(&side.logs);
        let run = logs.runs.get(&number)?;
        Some(Logged {
            log: run.key.clone(),
            index,
        })
    }))
}

// ---------------------------------------------------------------------------
// Witnessing

/// A response's status and body, or why there was none.
pub(crate) type Posted<'a> =
    Pin<Box<dyn Future<Output = Result<(u16, Vec<u8>), String>> + Send + 'a>>;

/// How the log reaches its witnesses: an HTTPS POST (4.5, [TLOG-WITNESS]).
pub(crate) trait Transport: Send + Sync {
    /// POSTs `body` to `url`, and returns the response's status and body.
    fn post<'a>(&'a self, url: &'a str, body: Vec<u8>) -> Posted<'a>;
}

/// Signs a checkpoint of the first `size` entries of log `number` at
/// `now`.
fn sign(logs: &Logs, number: u64, size: u64, now: u64) -> Option<SignedCheckpoint> {
    let run = logs.runs.get(&number)?;
    let cp = Checkpoint::new(&run.origin.to_string(), size, run.root_at(size)).ok()?;
    let mut sc = SignedCheckpoint::unsigned(cp);
    let rnd = crate::secret::random_bytes().ok()?;
    sc.push_signature(run.cosigner.cosign(sc.checkpoint(), now, rnd))
        .ok()?;
    Some(sc)
}

/// Asks witness `i` to cosign `sc`, a checkpoint of log `number`, with
/// `add-checkpoint` (4.5, [TLOG-WITNESS]), following its `409` answer once.
/// Returns its cosignature, checked.
async fn ask(inner: &Inner, i: usize, number: u64, sc: &SignedCheckpoint) -> Option<NoteSignature> {
    let side = inner.keylog.log.as_ref()?;
    let target = side.settings.witnesses.get(i)?;
    let size = sc.checkpoint().size();
    let mut old = lock(&side.known).get(&(i, number)).copied().unwrap_or(0);
    let url = format!("{}/add-checkpoint", target.url);
    for _ in 0..2 {
        if old > size {
            tracing::warn!(
                witness = target.verifier.name(),
                old,
                size,
                "a witness has cosigned a larger tree of the log than it has"
            );
            return None;
        }
        let proof = {
            let logs = lock(&side.logs);
            let run = logs.runs.get(&number)?;
            consistency_proof(old, size, &mut &run.tiles).ok()?
        };
        let body = AddCheckpoint {
            old_size: old,
            proof,
            checkpoint: sc.clone(),
        }
        .to_body()
        .into_bytes();
        let transport = side.transport();
        let answer = tokio::time::timeout(WITNESS_TIMEOUT, transport.post(&url, body)).await;
        let (status, body) = match answer {
            Ok(Ok(answer)) => answer,
            Ok(Err(e)) => {
                tracing::info!(witness = target.verifier.name(), error = %e, "witness unreachable");
                return None;
            }
            Err(_) => {
                tracing::info!(witness = target.verifier.name(), "witness timed out");
                return None;
            }
        };
        match status {
            200 => {
                let text = String::from_utf8(body).ok()?;
                let sigs = NoteSignature::parse_lines(&text).ok()?;
                let sig = sigs.into_iter().find(|s| {
                    target.verifier.matches(s)
                        && target
                            .verifier
                            .verify(sc.checkpoint(), s)
                            .is_ok_and(|ts| ts != 0)
                });
                if sig.is_some() {
                    lock(&side.known).insert((i, number), size);
                } else {
                    tracing::warn!(
                        witness = target.verifier.name(),
                        "a witness answered without a valid cosignature"
                    );
                }
                return sig;
            }
            409 => {
                let n = std::str::from_utf8(&body)
                    .ok()
                    .and_then(|s| s.trim_end_matches('\n').parse::<u64>().ok());
                match n {
                    Some(n) if n != old => old = n,
                    _ => return None,
                }
                lock(&side.known).insert((i, number), old);
            }
            status => {
                tracing::info!(
                    witness = target.verifier.name(),
                    status,
                    log = number,
                    "a witness refused a checkpoint"
                );
                return None;
            }
        }
    }
    None
}

/// Shows witness `i` the hand-off of log `number`, whose checkpoint `sc`
/// ends with it (4.10). Returns whether it took it.
async fn send_handoff(inner: &Inner, i: usize, number: u64, sc: &SignedCheckpoint) -> bool {
    let Some(side) = inner.keylog.log.as_ref() else {
        return false;
    };
    let Some(target) = side.settings.witnesses.get(i) else {
        return false;
    };
    let size = sc.checkpoint().size();
    let request = {
        let logs = lock(&side.logs);
        let Some(run) = logs.runs.get(&number) else {
            return false;
        };
        let Some(index) = run.handoff.filter(|i| i + 1 == size) else {
            return false;
        };
        let Ok(proof) = inclusion_proof(index, size, &mut &run.tiles) else {
            return false;
        };
        (index, proof)
    };
    let entry = match inner.db(move |s| s.log_entries(number, request.0, 1)).await {
        Ok(mut e) if e.len() == 1 => e.remove(0).entry,
        _ => return false,
    };
    let body = HandoffRequest {
        index: request.0,
        entry,
        proof: request.1,
        checkpoint: sc.clone(),
    }
    .to_body()
    .into_bytes();
    let url = format!("{}/{}", target.url, risala_keylog::handoff::HANDOFF_PATH);
    let transport = side.transport();
    match tokio::time::timeout(WITNESS_TIMEOUT, transport.post(&url, body)).await {
        Ok(Ok((200, _))) => true,
        Ok(Ok((status, _))) => {
            tracing::info!(
                witness = target.verifier.name(),
                status,
                "a witness refused a hand-off"
            );
            false
        }
        _ => {
            tracing::info!(
                witness = target.verifier.name(),
                "a witness did not take a hand-off"
            );
            false
        }
    }
}

/// One witnessing round: for each log that needs one, a new checkpoint,
/// sent to every witness; for a log that handed off, its last checkpoint
/// and the hand-off, to each witness that has not taken it (4.5, 4.10).
///
/// Returns `true` if every log is done: the current one has a witnessed
/// checkpoint of all its entries, and each old one has one that ends with
/// its hand-off, which every witness took.
pub(crate) async fn witness_round(inner: &Arc<Inner>) -> bool {
    let Some(side) = inner.keylog.log.as_ref() else {
        return true;
    };
    let now = secs(inner.now()).max(1);
    let n = side.settings.witnesses.len();
    let numbers: Vec<u64> = lock(&side.logs).runs.keys().copied().collect();
    let current = *numbers.last().expect("there is always a log");
    let mut done = true;
    for number in numbers {
        let old = number != current;
        // What this log needs.
        let (size, fresh, handed) = {
            let logs = lock(&side.logs);
            let run = &logs.runs[&number];
            let size = run.size();
            let fresh = run.witnessed.is_some_and(|(s, at)| {
                s == size && (old || now.saturating_sub(at) < side.settings.refresh)
            });
            (size, fresh, run.took_handoff.len() == n)
        };
        if fresh && (!old || handed) {
            continue;
        }
        let Some(mut sc) = sign(&lock(&side.logs), number, size, now) else {
            tracing::error!(log = number, "could not sign a checkpoint");
            done = false;
            continue;
        };
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..n {
            let (inner, sc) = (inner.clone(), sc.clone());
            tasks.spawn(async move { (i, ask(&inner, i, number, &sc).await) });
        }
        let mut sigs = BTreeMap::new();
        while let Some(result) = tasks.join_next().await {
            if let Ok((i, Some(sig))) = result {
                sigs.insert(i, sig);
            }
        }
        let count = sigs.len();
        for sig in sigs.into_values() {
            if sc.push_signature(sig).is_err() {
                break;
            }
        }
        let witnessed = count >= side.settings.k;
        let note = sc.to_text();
        let row = CheckpointRow {
            size,
            note: note.clone(),
            witnessed,
            signed: inner.now(),
        };
        if let Err(e) = inner.db(move |s| s.put_log_checkpoint(number, &row)).await {
            tracing::error!(error = %e, "storing a checkpoint");
            done = false;
            continue;
        }
        {
            let mut logs = lock(&side.logs);
            let run = logs.runs.get_mut(&number).expect("logs are never removed");
            if witnessed {
                run.witnessed = Some((size, now));
                run.served = Some(Arc::from(note));
            } else if run.witnessed.is_none() {
                run.served = Some(Arc::from(note));
            }
        }
        if !witnessed {
            tracing::info!(
                log = number,
                size,
                cosignatures = count,
                k = side.settings.k,
                "the checkpoint did not get enough cosignatures; trying again later"
            );
            done = false;
            continue;
        }
        tracing::debug!(
            log = number,
            size,
            cosignatures = count,
            "witnessed checkpoint"
        );
        if old {
            // Each witness of the old log takes its hand-off before the next
            // log's first checkpoint reaches it (4.10).
            let missing: Vec<usize> = {
                let logs = lock(&side.logs);
                let took = &logs.runs[&number].took_handoff;
                (0..n).filter(|i| !took.contains(i)).collect()
            };
            for i in missing {
                if send_handoff(inner, i, number, &sc).await {
                    lock(&side.logs)
                        .runs
                        .get_mut(&number)
                        .expect("logs are never removed")
                        .took_handoff
                        .insert(i);
                } else {
                    done = false;
                }
            }
        }
    }
    done
}

/// How long until the current log's witnessed checkpoint needs refreshing.
fn until_refresh(inner: &Inner) -> Duration {
    let Some(side) = inner.keylog.log.as_ref() else {
        return Duration::MAX;
    };
    let now = secs(inner.now());
    let at = lock(&side.logs).current().witnessed.map_or(0, |(_, at)| at);
    let due = at.saturating_add(side.settings.refresh);
    Duration::from_secs(due.saturating_sub(now).max(MIN_INTERVAL))
}

/// The area's background work: a witnessed checkpoint soon after each new
/// record, within the hour at worst, and every `log.refresh_secs`
/// otherwise (4.5); hand-offs to the witnesses (4.10).
pub(super) async fn maintain(inner: Arc<Inner>) {
    let Some(side) = inner.keylog.log.as_ref() else {
        return;
    };
    let mut retry = RETRY_MIN;
    loop {
        let started = tokio::time::Instant::now();
        let wait = if witness_round(&inner).await {
            retry = RETRY_MIN;
            until_refresh(&inner)
        } else {
            let wait = retry;
            retry = (retry * 2).min(RETRY_MAX);
            wait
        };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = side.wake.notified() => {}
        }
        // Witnesses take a checkpoint of one log at most every 10 seconds.
        tokio::time::sleep_until(started + Duration::from_secs(MIN_INTERVAL)).await;
    }
}

// ---------------------------------------------------------------------------
// Serving

/// An answer to an HTTPS request for the log or the witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    /// The status code.
    pub(crate) status: u16,
    /// The `Content-Type`.
    pub(crate) content_type: &'static str,
    /// The body.
    pub(crate) body: Vec<u8>,
    /// Whether the body never changes (full tiles), for `Cache-Control`.
    pub(crate) immutable: bool,
}

impl Answer {
    fn ok(content_type: &'static str, body: Vec<u8>) -> Answer {
        Answer {
            status: 200,
            content_type,
            body,
            immutable: false,
        }
    }

    fn status(status: u16) -> Answer {
        Answer {
            status,
            content_type: "text/plain; charset=utf-8",
            body: format!("{status}\n").into_bytes(),
            immutable: false,
        }
    }
}

const TEXT: &str = "text/plain; charset=utf-8";
const BINARY: &str = "application/octet-stream";

/// Parses `<n>` as a number with no leading zeros.
fn log_number(s: &str) -> Option<u64> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse().ok()
}

/// Parses a uid hint's `<hash>`: 64 lower-case hex digits.
fn uid_hash_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

impl Hub {
    /// Answers `GET <path>` for a log, if `path` is under
    /// [`LOG_PATH`]: a log's checkpoint, tiles, entry bundles and hints
    /// (4.5, [TLOG-TILES]). `None` if the path is not the log's.
    pub(crate) async fn serve_log(&self, path: &str) -> Option<Answer> {
        let rest = path.strip_prefix(LOG_PATH)?;
        let inner = &self.inner;
        let Some(side) = &inner.keylog.log else {
            return Some(Answer::status(404));
        };
        let (n, rest) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(number) = log_number(n) else {
            return Some(Answer::status(404));
        };
        // What can be answered from memory.
        let tile = {
            let logs = lock(&side.logs);
            let Some(run) = logs.runs.get(&number) else {
                return Some(Answer::status(404));
            };
            if rest == "checkpoint" {
                return Some(match &run.served {
                    Some(note) => Answer::ok(TEXT, note.as_bytes().to_vec()),
                    None => Answer::status(404),
                });
            }
            if rest == NEXT_PATH {
                return Some(match run.handoff {
                    Some(index) => Answer::ok(TEXT, next_body(index).into_bytes()),
                    None => Answer::status(404),
                });
            }
            // Every log serves its key, for witnesses to enrol it (4.5).
            if rest == KEY_PATH {
                return Some(match risala_keylog::LogKey::new(run.cosigner.verifier()) {
                    Ok(key) => Answer::ok(TEXT, log_key_body(&key).into_bytes()),
                    Err(_) => Answer::status(500),
                });
            }
            if rest.starts_with(UID_PATH) {
                None
            } else {
                let Ok(tile) = TileId::parse(rest) else {
                    return Some(Answer::status(404));
                };
                if let TileKind::Hashes(_) = tile.kind() {
                    return Some(match run.tiles.tile(&tile) {
                        Some(data) => Answer {
                            immutable: !tile.is_partial(),
                            ..Answer::ok(BINARY, data)
                        },
                        None => Answer::status(404),
                    });
                }
                // An entry bundle, if the log has its entries.
                let end = tile
                    .index()
                    .checked_mul(TILE_WIDTH)
                    .and_then(|s| s.checked_add(u64::from(tile.width())));
                if end.is_none_or(|end| end > run.size()) {
                    return Some(Answer::status(404));
                }
                Some(tile)
            }
        };
        if let Some(tile) = tile {
            let (start, width) = (tile.index() * TILE_WIDTH, u64::from(tile.width()));
            let entries = match inner.db(move |s| s.log_entries(number, start, width)).await {
                Ok(entries) => entries,
                Err(e) => {
                    tracing::error!(error = %e, "reading log entries");
                    return Some(Answer::status(500));
                }
            };
            if entries.len() as u64 != width {
                return Some(Answer::status(404));
            }
            let entries: Vec<Vec<u8>> = entries.into_iter().map(|e| e.entry).collect();
            return Some(match encode_bundle(&entries) {
                Ok(data) => Answer {
                    immutable: !tile.is_partial(),
                    ..Answer::ok(BINARY, data)
                },
                Err(_) => Answer::status(500),
            });
        }
        // risala/uid/<hash>
        let Some(hash) = rest.strip_prefix(UID_PATH).and_then(uid_hash_hex) else {
            return Some(Answer::status(404));
        };
        let indices = match inner.db(move |s| s.log_uid_indices(number, &hash)).await {
            Ok(i) => i,
            Err(e) => {
                tracing::error!(error = %e, "reading a uid hint");
                return Some(Answer::status(500));
            }
        };
        if indices.is_empty() {
            return Some(Answer::status(404));
        }
        Some(match UidHint::new(indices) {
            Ok(hint) => Answer::ok(TEXT, hint.to_body().into_bytes()),
            Err(_) => Answer::status(500),
        })
    }

    /// Answers `POST <path>` for the server's witness, if `path` is under
    /// [`WITNESS_PATH`] and the server is a witness: `add-checkpoint`
    /// [TLOG-WITNESS] and `risala/handoff` (4.10). `None` if the path is
    /// not the witness's.
    pub(crate) async fn witness_request(&self, path: &str, body: Vec<u8>) -> Option<Answer> {
        let rest = path.strip_prefix(WITNESS_PATH)?.strip_prefix('/')?;
        let inner = self.inner.clone();
        inner.keylog.witness.as_ref()?;
        let handoff = match rest {
            "add-checkpoint" => false,
            risala_keylog::handoff::HANDOFF_PATH => true,
            _ => return Some(Answer::status(404)),
        };
        let task = tokio::task::spawn_blocking(move || {
            let witness = inner.keylog.witness.as_ref().expect("checked above");
            let now = secs(inner.now());
            if handoff {
                return match lock(&witness.core).handoff_body(&body) {
                    Ok(()) => Answer::ok(TEXT, Vec::new()),
                    Err(e) => refusal(&e),
                };
            }
            let Ok(req) = AddCheckpoint::parse(&body) else {
                return Answer::status(400);
            };
            let Ok(rnd) = crate::secret::random_bytes() else {
                return Answer::status(500);
            };
            let result = lock(&witness.core).add_checkpoint(&req, now, rnd);
            match result {
                Ok(sigs) => Answer::ok(
                    TEXT,
                    sigs.iter()
                        .map(NoteSignature::to_line)
                        .collect::<String>()
                        .into_bytes(),
                ),
                Err(e) => refusal(&e),
            }
        });
        Some(task.await.unwrap_or_else(|_| Answer::status(500)))
    }
}

/// A witness's refusal as an answer: `409` carries the witness's size, as
/// `text/x.tlog.size` [TLOG-WITNESS].
fn refusal(e: &CoreError<StoreError>) -> Answer {
    match e {
        CoreError::Refused(WitnessRefusal::Conflict(size)) => Answer {
            status: 409,
            content_type: "text/x.tlog.size",
            body: format!("{size}\n").into_bytes(),
            immutable: false,
        },
        CoreError::Store(e) => {
            tracing::error!(error = %e, "witness store");
            Answer::status(500)
        }
        e => Answer::status(e.status()),
    }
}

// ---------------------------------------------------------------------------
// The witness's store

/// The witness's [`WitnessStore`], on the server's store (4.10).
struct StoreWitness(Arc<dyn Store>);

fn corrupt(what: &str) -> StoreError {
    StoreError::Corrupt(format!("witness log {what} does not parse"))
}

impl WitnessStore for StoreWitness {
    type Error = StoreError;

    fn log(&mut self, origin: &LogOrigin) -> Result<Option<LogState>, StoreError> {
        let Some(row) = self.0.witness_log(&origin.to_string())? else {
            return Ok(None);
        };
        let key = risala_keylog::LogKey::from_vkey_str(&row.vkey).map_err(|_| corrupt("key"))?;
        let handoff = match row.handoff {
            Some((index, next)) => Some(Handoff {
                index,
                next: risala_keylog::LogKey::from_vkey_str(&next)
                    .map_err(|_| corrupt("hand-off"))?,
            }),
            None => None,
        };
        Ok(Some(LogState {
            key,
            size: row.size,
            root: Hash(row.root),
            domain: row.domain,
            enrolled_at: row.enrolled_at,
            last_cosigned: row.last_cosigned,
            handoff,
        }))
    }

    fn put_log(&mut self, state: &LogState) -> Result<(), StoreError> {
        self.0.put_witness_log(&WitnessLogRow {
            origin: state.origin().to_string(),
            vkey: state.key.verifier().vkey().to_string(),
            size: state.size,
            root: *state.root.as_bytes(),
            domain: state.domain.clone(),
            enrolled_at: state.enrolled_at,
            last_cosigned: state.last_cosigned,
            handoff: state
                .handoff
                .as_ref()
                .map(|h| (h.index, h.next.verifier().vkey().to_string())),
        })
    }

    fn hosts_enrolled_since(&mut self, domain: &str, since: u64) -> Result<u64, StoreError> {
        self.0.witness_hosts_enrolled_since(domain, since)
    }
}
