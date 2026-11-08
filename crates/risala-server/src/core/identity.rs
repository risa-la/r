//! Identities (4.4-4.9, 10.5): AUTH, REGISTER, KEYS PUT, PAIR PUT and
//! PAIR GET, UNREGISTER and ADMIN UNREGISTER, and the key files of the
//! identities the server hosts.
//!
//! # Whose keys
//!
//! - A **hosted** identity, `<name>@<identity domain>` (4.7), has the
//!   chain of records the server holds: the one REGISTER started and
//!   KEYS PUT continued. The server publishes its key file, and answers
//!   410 for it once it is unregistered, unless its chain ends with a
//!   `retire` record (4.9).
//! - Any **other** identity has the chain of its key file (4.4), fetched
//!   through [`Inner::key_files`](super::Inner), with the records it lists
//!   by index fetched from their logs. The server **pins** the master key
//!   of the first chain it reads for it and its newest record (4.6): a
//!   key file whose chain does not hold the pinned head, or starts with
//!   another master key, makes the identity's keys missing until ADMIN
//!   UNREGISTER clears the pin (10.5).
//!
//! A read gives one of the three states of 4.4: keys, keys missing, or an
//! outage. AUTH answers `auth-failed` for keys missing and `unavailable`
//! for an outage. The server does not check inclusion proofs or
//! witnesses for the records it reads (a SHOULD in 4.6): it checks that
//! each record listed by index is the entry at that index of a log
//! whose checkpoint the log signed.
//!
//! # Changing chains
//!
//! REGISTER, KEYS PUT, UNREGISTER and ADMIN UNREGISTER take the area's
//! write lock, so that two changes to chains never interleave. Records
//! go to the key log first ([`log_records`], which keeps the index of a
//! record the log already holds), then to the store, so a crash in
//! between leaves nothing that a second try cannot finish.
//!
//! # Pairing
//!
//! PAIR PUT keeps its data for 10 minutes, under the SHA-384 hash of its
//! id, which is a bearer secret (4.8, 14).

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use risala_proto::auth::{Nonce, PublicKey, Signature};
use risala_proto::binary::{EncodedRecords, PairData};
use risala_proto::chain::{Chain, KeysPutError, Pin, check_register, keys_put};
use risala_proto::command::{Command, KeysPutRecords, PairCommand};
use risala_proto::error::ErrorCode;
use risala_proto::keyfile::{
    EntryError, KeyFile, KeyFileError, KeyFileState, Listing, LogLine, Missing,
};
use risala_proto::names::{BlobRef, Identity, Name, PairId, Uid};
use risala_proto::record::{LogKey, Record, RecordError, decode_records};
use risala_proto::server::{ErrResponse, OkResponse, ServerLine};
use risala_proto::time::Timestamp;
use sha2::{Digest as _, Sha384};

use super::command::{Cx, Reply, err, misrouted};
use super::rate::{WindowLimit, network};
use super::state::{ConnEntry, Device, Who};
use super::{Inner, admin, keylog, keys, misc};
use crate::config::Config;
use crate::handler::ConnId;
use crate::keyfiles::{Body, FetchError, KEY_FETCH_TIMEOUT, UrlBody};
use crate::store::identity::{PairPut, StoredRecord};
use crate::store::{Store, StoreError};

/// How long PAIR PUT keeps its data (4.8).
pub const PAIR_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// The most bytes of pairing data PAIR PUT keeps. A NewDevice is about
/// 6 KiB and a SealedBundle less (4.8). (4.8 sets no limit besides the
/// line's; a choice to confirm.)
pub const MAX_PAIR_DATA: usize = 64 * 1024;

/// How many PAIR PUTs one network address may make in
/// [`PAIR_WINDOW`] (4.2: the server limits what each address stores).
pub const PAIR_PUTS_PER_WINDOW: u32 = 30;

/// The window of [`PAIR_PUTS_PER_WINDOW`].
pub const PAIR_WINDOW: Duration = Duration::from_secs(10 * 60);

/// The BYE text for the connections of an identity that was unregistered
/// (4.9, 10.5).
pub const BYE_UNREGISTERED: &str = "identity deleted";

/// The BYE text for a connection whose device was removed by record, or
/// whose identity's keys went missing (4.4).
pub const BYE_KEYS_CHANGED: &str = "device key no longer valid";

/// The most chains read from key files kept in memory, so that a key
/// file that has not changed is not checked again at each AUTH.
const READ_CACHE: usize = 4096;

/// What the HTTPS listener serves for a hosted identity's key file (4.3,
/// 4.7, 4.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedKeyFile {
    /// The key file: 200.
    File(Vec<u8>),
    /// The identity was unregistered, and its chain does not end with a
    /// `retire` record: 410 (4.9).
    Gone,
    /// The server hosts no such identity: 404.
    NotFound,
}

/// What the identity area keeps in memory.
pub(crate) struct State {
    /// Held while a chain changes: REGISTER, KEYS PUT, UNREGISTER.
    write: tokio::sync::Mutex<()>,
    /// Registrations per network address in the last hour, in progress
    /// ones included (4.7).
    registrations: WindowLimit<IpAddr>,
    /// PAIR PUTs per network address.
    pair_puts: WindowLimit<IpAddr>,
    /// The chains the store holds, replayed, by identity.
    chains: Mutex<HashMap<Identity, Arc<Chain>>>,
    /// The chains last read from key files, by identity, with the hash of
    /// the file they came from.
    reads: Mutex<HashMap<Identity, (BlobRef, Arc<Chain>)>>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State").finish_non_exhaustive()
    }
}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(_config: &Config, _store: &dyn Store) -> Result<State, StoreError> {
        Ok(State {
            write: tokio::sync::Mutex::new(()),
            registrations: WindowLimit::new(Duration::from_secs(60 * 60)),
            pair_puts: WindowLimit::new(PAIR_WINDOW),
            chains: Mutex::new(HashMap::new()),
            reads: Mutex::new(HashMap::new()),
        })
    }

    fn chains(&self) -> std::sync::MutexGuard<'_, HashMap<Identity, Arc<Chain>>> {
        self.chains.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn reads(&self) -> std::sync::MutexGuard<'_, HashMap<Identity, (BlobRef, Arc<Chain>)>> {
        self.reads.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// What the identity area keeps about one connection.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Handles AUTH, REGISTER, KEYS PUT, PAIR and UNREGISTER.
pub(super) async fn handle(cx: &Cx, command: Command) -> Reply {
    match command {
        Command::Auth {
            identity,
            signature,
        } => auth(cx, &identity, &signature).await,
        Command::Register {
            name,
            records,
            signature,
        } => register(cx, &name, &records, &signature).await,
        Command::KeysPut { after, records } => keys_put_command(cx, after.as_ref(), &records).await,
        Command::Pair(PairCommand::Put { id, data }) => pair_put(cx, &id, &data).await,
        Command::Pair(PairCommand::Get { id }) => pair_get(cx, &id).await,
        Command::Unregister { uid } => unregister(cx, &uid).await,
        other => misrouted("identity", &other),
    }
}

// ---------------------------------------------------------------------------
// Errors

fn fail(code: ErrorCode, message: &str) -> ErrResponse {
    err(code).with_message(message)
}

fn internal(e: impl std::fmt::Display) -> ErrResponse {
    tracing::error!("identity: {e}");
    err(ErrorCode::Internal)
}

// ---------------------------------------------------------------------------
// Signing in (4.6)

/// What sign-in needs from the connection: the greeting's nonce, which
/// this uses up (4.6), and the SNI hostname, if it is one the server
/// serves.
struct SignInBytes {
    nonce: Option<Nonce>,
    host: Option<String>,
}

/// Uses up the connection's nonce, and checks its SNI (4.6, step 1).
fn take_sign_in(cx: &Cx) -> SignInBytes {
    let mut reg = cx.inner.reg();
    let Some(conn) = reg.conns.get_mut(&cx.conn) else {
        return SignInBytes {
            nonce: None,
            host: None,
        };
    };
    let nonce = conn.nonce.take();
    let host = conn.info.sni.clone().filter(|sni| {
        conn.info.sni_certified || sni.eq_ignore_ascii_case(&cx.inner.config.hostname)
    });
    SignInBytes { nonce, host }
}

/// The error for a sign-in that cannot be checked here: no nonce left,
/// or a host name the server does not serve (4.6, step 1).
fn sign_in_bytes(cx: &Cx) -> Result<(Nonce, String), ErrResponse> {
    let SignInBytes { nonce, host } = take_sign_in(cx);
    let Some(nonce) = nonce else {
        return Err(fail(
            ErrorCode::AuthFailed,
            "this connection's nonce is used up; reconnect",
        ));
    };
    let Some(host) = host else {
        return Err(fail(
            ErrorCode::AuthFailed,
            "wrong host name: this server does not serve the name you connected to",
        ));
    };
    Ok((nonce, host.to_ascii_lowercase()))
}

/// `AUTH <identity> <signature>` (4.6).
async fn auth(cx: &Cx, identity: &Identity, signature: &Signature) -> Reply {
    let (nonce, host) = sign_in_bytes(cx)?;
    let verifies = |chain: &Chain| {
        chain
            .devices()
            .values()
            .map(|d| &d.keys.device_key)
            .find(|key| key.verify_challenge(&host, &nonce, identity.as_str(), signature))
            .cloned()
    };
    let mut view = keys_of(&cx.inner, identity, false).await;
    // A signature that does not verify against a cached file, or a cached
    // file that is not accepted, gets the file fetched again once (4.4).
    let retry = match &view {
        View::Keys { chain, cached } => *cached && verifies(chain).is_none(),
        View::Missing { cached, .. } | View::Outage { cached, .. } => *cached,
    };
    if retry {
        view = keys_of(&cx.inner, identity, true).await;
    }
    let key = match &view {
        View::Keys { chain, .. } => verifies(chain),
        View::Missing { why, .. } => {
            tracing::debug!(conn = cx.conn.0, %identity, why, "AUTH: keys missing");
            None
        }
        View::Outage { why, .. } => {
            tracing::debug!(conn = cx.conn.0, %identity, why, "AUTH: outage");
            return Err(fail(
                ErrorCode::Unavailable,
                "the identity's key file could not be fetched; try again later",
            ));
        }
    };
    let Some(key) = key else {
        return Err(err(ErrorCode::AuthFailed));
    };
    // A banned identity learns it only once its signature verifies (10.2).
    if admin::banned(&cx.inner, &identity.to_uid()) {
        return Err(err(ErrorCode::Forbidden));
    }
    sign_in(cx, identity, key).await
}

/// Signs the connection in as `identity` with device key `key` (4.6).
async fn sign_in(cx: &Cx, identity: &Identity, key: PublicKey) -> Reply {
    let uid = identity.to_uid();
    let device = Device {
        uid: uid.clone(),
        key,
    };
    if !cx.inner.reg().set_who(cx.conn, Who::SignedIn(device)) {
        return Err(err(ErrorCode::Internal));
    }
    let now = cx.inner.now();
    let noted = uid.clone();
    cx.db(move |store| store.note_sign_in(&noted, now)).await?;
    tracing::debug!(conn = cx.conn.0, "signed in");
    Ok(OkResponse::new()
        .with_uid(&uid)
        .with_op(admin::is_operator(&cx.inner, &uid)))
}

/// What the server knows of an identity's keys (4.4).
enum View {
    /// Keys: the current ones of `chain`.
    Keys { chain: Arc<Chain>, cached: bool },
    /// Keys missing: nobody signs in with them.
    Missing { why: String, cached: bool },
    /// An outage: nothing is known.
    Outage { why: String, cached: bool },
}

/// The device ids (4.4) of `identity`'s current devices, for KEYPKG GET
/// (12.5): none if its keys are missing, and `None` for an outage, when
/// the server cannot fetch its key file and has no valid cached copy.
pub(crate) async fn current_devices(
    inner: &Arc<Inner>,
    identity: &Identity,
) -> Option<Vec<[u8; 48]>> {
    match keys_of(inner, identity, false).await {
        View::Keys { chain, .. } => Some(chain.devices().keys().map(|id| *id.as_bytes()).collect()),
        View::Missing { .. } => Some(Vec::new()),
        View::Outage { why, .. } => {
            tracing::debug!(%identity, "no current devices: {why}");
            None
        }
    }
}

/// Whether the server hosts identities at `identity`'s domain (4.7).
fn at_identity_domain(inner: &Inner, identity: &Identity) -> bool {
    inner
        .identity_domain
        .as_ref()
        .is_some_and(|d| d.as_str() == identity.domain())
}

/// The keys of `identity` (4.6, step 3): a hosted identity's from the
/// server's own records, any other's from its key file, under the pin.
async fn keys_of(inner: &Arc<Inner>, identity: &Identity, refresh: bool) -> View {
    if at_identity_domain(inner, identity) {
        return hosted_keys(inner, identity).await;
    }
    let (view, fresh) = read_key_file(inner, identity, refresh).await;
    // A read that was not from a cache says what the keys are now: close
    // the connections that it shows are no longer valid (4.4).
    if fresh {
        match &view {
            View::Keys { chain, .. } => {
                let chain = chain.clone();
                close_devices(inner, &identity.to_uid(), |key| {
                    chain.device_by_key(key).is_some()
                });
            }
            View::Missing { .. } => close_devices(inner, &identity.to_uid(), |_| false),
            View::Outage { .. } => {}
        }
    }
    view
}

/// The keys of a hosted identity: its chain, if it is registered and has
/// not been unregistered (4.7, 4.9).
async fn hosted_keys(inner: &Arc<Inner>, identity: &Identity) -> View {
    let missing = |why: &str| View::Missing {
        why: why.to_owned(),
        cached: false,
    };
    let Ok(name) = identity.name().parse::<Name>() else {
        return missing("not a hosted name");
    };
    let inner2 = inner.clone();
    let id = identity.clone();
    let found = inner
        .db(move |store| {
            let Some(hosted) = store.hosted(&name)? else {
                return Ok(None);
            };
            if hosted.unregistered.is_some() {
                return Ok(None);
            }
            stored_chain(&inner2, store, &id)
        })
        .await;
    match found {
        Ok(Some(chain)) => View::Keys {
            chain,
            cached: false,
        },
        Ok(None) => missing("not registered here"),
        Err(e) => {
            tracing::error!("reading a hosted chain: {e}");
            View::Outage {
                why: "store".into(),
                cached: false,
            }
        }
    }
}

/// The chain the store holds for `identity`, replayed, if it holds one.
/// Blocks.
fn stored_chain(
    inner: &Inner,
    store: &dyn Store,
    identity: &Identity,
) -> Result<Option<Arc<Chain>>, StoreError> {
    if let Some(chain) = inner.identity.chains().get(identity) {
        return Ok(Some(chain.clone()));
    }
    let stored = store.chain_records(identity)?;
    if stored.is_empty() {
        return Ok(None);
    }
    let records = stored
        .iter()
        .map(|r| Record::decode(&r.record))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| StoreError::Corrupt(format!("a stored record of {identity}: {e}")))?;
    let chain = Chain::replay_placed(
        identity,
        records.iter().map(|r| (r, None)),
        &inner.keylog.handoffs(),
    )
    .map_err(|e| StoreError::Corrupt(format!("the stored chain of {identity}: {e}")))?;
    let chain = Arc::new(chain);
    inner
        .identity
        .chains()
        .insert(identity.clone(), chain.clone());
    Ok(Some(chain))
}

/// Reads `identity`'s key file (4.4), under the server's pin (4.6).
/// Returns the view, and whether the answer was fetched just now rather
/// than taken from a cache.
async fn read_key_file(inner: &Arc<Inner>, identity: &Identity, refresh: bool) -> (View, bool) {
    let fetch = inner.key_files.fetcher.fetch_boxed(identity, refresh);
    let fetched = match tokio::time::timeout(KEY_FETCH_TIMEOUT, fetch).await {
        Ok(Ok(fetched)) => fetched,
        Ok(Err(e)) => {
            let why = e.to_string();
            return (View::Outage { why, cached: false }, false);
        }
        Err(_) => {
            let why = "timed out".to_owned();
            return (View::Outage { why, cached: false }, false);
        }
    };
    let cached = fetched.cached;
    let missing = |why: String| (View::Missing { why, cached }, !cached);
    let bytes = match fetched.body {
        Body::File(bytes) => bytes,
        Body::TooLarge => return missing("the key file is over 2 MiB".into()),
        Body::Gone(status) => return missing(format!("the key file is gone ({status})")),
    };
    let state = check_key_file(inner, identity, &bytes).await;
    let chain: Arc<Chain> = match state {
        KeyFileState::Keys(chain) => Arc::from(chain),
        KeyFileState::KeysMissing(why) => return missing(describe_missing(&why)),
        KeyFileState::Outage(why) => {
            let why = format!("{why:?}");
            return (View::Outage { why, cached }, false);
        }
    };
    match apply_pin(inner, identity, &chain).await {
        Ok(true) => (View::Keys { chain, cached }, !cached),
        Ok(false) => missing("the key file does not extend the server's pin".into()),
        Err(e) => {
            tracing::error!("pin: {e}");
            let why = "store".to_owned();
            (View::Outage { why, cached }, false)
        }
    }
}

fn describe_missing(why: &Missing) -> String {
    match why {
        Missing::Gone(status) => format!("gone ({status})"),
        Missing::TooLarge => "over 2 MiB".into(),
        Missing::NotKeyFile => "not a risala-keys/1 file".into(),
        Missing::Text(e) => e.to_string(),
        Missing::Chain(e) => e.to_string(),
        Missing::TrailingLog => "a last log line that no log record names".into(),
        Missing::NotInLog(i) => format!("record {i} does not match its log"),
    }
}

/// Parses and checks a key file of `identity` (4.4), with the records it
/// lists by index from their logs. A file the server has checked before
/// is not checked again.
async fn check_key_file(inner: &Arc<Inner>, identity: &Identity, bytes: &[u8]) -> KeyFileState {
    let hash = BlobRef::of(bytes);
    if let Some((seen, chain)) = inner.identity.reads().get(identity)
        && *seen == hash
    {
        return KeyFileState::Keys(Box::new((**chain).clone()));
    }
    let file = match KeyFile::parse(bytes) {
        Ok(file) => file,
        Err(KeyFileError::TooLarge) => return KeyFileState::KeysMissing(Missing::TooLarge),
        Err(KeyFileError::NotKeyFile) => return KeyFileState::KeysMissing(Missing::NotKeyFile),
        Err(e) => return KeyFileState::KeysMissing(Missing::Text(e)),
    };
    let entries = log_entries(inner, &file).await;
    let mut source = |log: &LogLine, index: u64| {
        entries
            .get(&(log.log.clone(), index))
            .cloned()
            .unwrap_or(Err(EntryError::Outage))
    };
    let state = file.check(identity, &mut source, &inner.keylog.handoffs(), inner.now());
    if let KeyFileState::Keys(chain) = &state {
        let mut read = inner.identity.reads();
        if read.len() >= READ_CACHE {
            read.clear();
        }
        read.insert(identity.clone(), (hash, Arc::new((**chain).clone())));
    }
    state
}

type Entries = HashMap<(LogKey, u64), Result<Vec<u8>, EntryError>>;

/// The entries that `file` lists by index, from the server's own log or
/// fetched from the others (4.4).
async fn log_entries(inner: &Arc<Inner>, file: &KeyFile) -> Entries {
    let mut wanted: BTreeMap<String, (LogLine, Vec<u64>)> = BTreeMap::new();
    for (log, listing) in file.listings() {
        if let Listing::Logged { index, .. } = listing {
            wanted
                .entry(log.log.origin().to_owned())
                .or_insert_with(|| (log.clone(), Vec::new()))
                .1
                .push(*index);
        }
    }
    let mut entries = Entries::new();
    for (log, indices) in wanted.into_values() {
        match own_entries(inner, &log.log, indices.clone()).await {
            Ok(Some(mut own)) => {
                for index in indices {
                    let entry = own.remove(&index).ok_or(EntryError::Missing);
                    entries.insert((log.log.clone(), index), entry);
                }
            }
            Ok(None) => entries.extend(remote_entries(inner, &log, &indices).await),
            Err(e) => {
                tracing::error!("reading the key log: {e}");
            }
        }
    }
    entries
}

/// The entries at `indices` of the log of `log`, from its entry bundles
/// [TLOG-TILES], whose sizes come from its checkpoint, which must carry
/// the log's own signature (4.5). A failed fetch is an outage; an index
/// past the checkpoint is a missing entry (4.4).
async fn remote_entries(inner: &Arc<Inner>, log: &LogLine, indices: &[u64]) -> Entries {
    let outage = || {
        indices
            .iter()
            .map(|&i| ((log.log.clone(), i), Err(EntryError::Outage)))
            .collect::<Entries>()
    };
    let fetcher = &inner.key_files.fetcher;
    let url = format!("{}/checkpoint", log.url);
    let size = match fetcher.fetch_log_boxed(&url).await {
        Ok(UrlBody::Ok(bytes)) => match checkpoint_size(&log.log, &bytes) {
            Some(size) => size,
            None => return outage(),
        },
        _ => return outage(),
    };
    let mut bundles: BTreeMap<String, Option<Vec<Vec<u8>>>> = BTreeMap::new();
    let mut entries = Entries::new();
    for &index in indices {
        let key = (log.log.clone(), index);
        let Some(tile) = risala_keylog::tile::bundle_for_entry(index, size) else {
            entries.insert(key, Err(EntryError::Missing));
            continue;
        };
        let path = tile.path();
        if !bundles.contains_key(&path) {
            let url = format!("{}/{path}", log.url);
            let bundle = match fetcher.fetch_log_boxed(&url).await {
                Ok(UrlBody::Ok(bytes)) => risala_keylog::tile::decode_bundle(&bytes).ok(),
                _ => None,
            };
            bundles.insert(path.clone(), bundle);
        }
        let at = usize::try_from(index % risala_keylog::tile::TILE_WIDTH).unwrap_or(usize::MAX);
        let entry = bundles[&path]
            .as_ref()
            .and_then(|bundle| bundle.get(at).cloned())
            .ok_or(EntryError::Outage);
        entries.insert(key, entry);
    }
    entries
}

/// The size of a log's checkpoint, if it is the log's and carries the
/// log's signature with a timestamp that is not zero (4.5).
fn checkpoint_size(log: &LogKey, bytes: &[u8]) -> Option<u64> {
    let signed = risala_keylog::SignedCheckpoint::parse(bytes).ok()?;
    let checkpoint = signed.checkpoint();
    if checkpoint.origin() != log.origin() {
        return None;
    }
    let verifier = risala_keylog::CosignatureVerifier::from_vkey_str(&log.vkey()).ok()?;
    let signed_by_log =
        signed.note().signatures().iter().any(|sig| {
            verifier.matches(sig) && verifier.verify(checkpoint, sig).is_ok_and(|t| t != 0)
        });
    signed_by_log.then(|| checkpoint.size())
}

/// Checks `chain` against the server's pin on `identity`, and moves the
/// pin forward to it, or takes it as the first (4.6). Returns whether the
/// chain is accepted.
async fn apply_pin(
    inner: &Arc<Inner>,
    identity: &Identity,
    chain: &Arc<Chain>,
) -> Result<bool, StoreError> {
    let identity = identity.clone();
    let chain = chain.clone();
    let now = inner.now();
    inner
        .db(move |store| {
            let new = Pin {
                master_key: chain.first_master_key().clone(),
                head: chain.head_hash(),
            };
            match store.pin(&identity)? {
                Some(pin) if pin.master_key != new.master_key || !chain.extends(&pin.head) => {
                    Ok(false)
                }
                Some(pin) if pin == new => Ok(true),
                _ => {
                    store.set_pin(&identity, &new, now)?;
                    Ok(true)
                }
            }
        })
        .await
}

/// Closes the signed-in connections of `uid` whose device key `keep`
/// does not keep (4.4: a device removed by record, or an identity whose
/// keys are missing).
fn close_devices(inner: &Inner, uid: &Uid, keep: impl Fn(&PublicKey) -> bool) {
    let mut reg = inner.reg();
    let ids: Vec<ConnId> = reg.by_uid.get(uid).into_iter().flatten().copied().collect();
    for id in ids {
        let gone = reg
            .conns
            .get(&id)
            .is_some_and(|c| matches!(&c.who, Who::SignedIn(d) if !keep(&d.key)));
        if gone {
            tracing::debug!(conn = id.0, "closing: device key no longer valid");
            reg.detach(id, BYE_KEYS_CHANGED);
        }
    }
}

// ---------------------------------------------------------------------------
// The key log (4.5), through the key log area

/// The server's current key log, as a key file's `log` line names it
/// (4.4), at `https://` and its origin, if it keeps one.
pub(super) fn current_log(inner: &Inner) -> Option<LogLine> {
    Some(LogLine::new(inner.keylog.current_log()?))
}

/// Logs `records` of `identity`, in chain order, and returns the index of
/// each. Records the server's logs already hold keep their index, so a
/// KEYS PUT sent again after a crash between logging and storing its
/// records finishes the work.
async fn log_records(
    inner: &Arc<Inner>,
    identity: &Identity,
    records: Vec<Record>,
) -> Result<Vec<u64>, ErrResponse> {
    let mut indices = Vec::with_capacity(records.len());
    let mut rest = records.into_iter().peekable();
    while let Some(record) = rest.peek() {
        match keylog::index_of(inner, record.hash())
            .await
            .map_err(internal)?
        {
            Some(logged) => {
                indices.push(logged.index);
                rest.next();
            }
            None => break,
        }
    }
    let logged = keylog::append_records(inner, identity, rest.collect())
        .await
        .map_err(|e| match e {
            keylog::AppendError::DoesNotFollow => fail(
                ErrorCode::Forbidden,
                "the log holds another record of the identity in its place",
            ),
            keylog::AppendError::TooMany => {
                fail(ErrorCode::TooLong, "a chain has at most 4096 records")
            }
            e => internal(e),
        })?;
    indices.extend(logged.into_iter().map(|l| l.index));
    Ok(indices)
}

/// The entries at `indices` of `log`, if it is one of the server's own
/// logs: each one it holds, by index. `None` if `log` is not the server's.
async fn own_entries(
    inner: &Arc<Inner>,
    log: &LogKey,
    indices: Vec<u64>,
) -> Result<Option<HashMap<u64, Vec<u8>>>, StoreError> {
    if !inner.keylog.logs().contains(log) {
        return Ok(None);
    }
    let number = log.number();
    inner
        .db(move |store| {
            let mut entries = HashMap::new();
            for index in indices {
                if let Some(entry) = store.log_entries(number, index, 1)?.into_iter().next() {
                    entries.insert(index, entry.entry);
                }
            }
            Ok(Some(entries))
        })
        .await
}

// ---------------------------------------------------------------------------
// Registration (4.7)

/// Decodes REGISTER's and KEYS PUT's records (4.7).
fn decode(bytes: &[u8]) -> Result<Vec<Record>, ErrResponse> {
    decode_records(bytes).map_err(|e| match e {
        RecordError::TooLarge => fail(ErrorCode::TooLong, "a chain has at most 4096 records"),
        e => fail(ErrorCode::Invalid, &format!("records: {e}")),
    })
}

/// Refuses records more than 10 minutes ahead of the server's clock: a
/// reader would treat them as an outage until then (4.4). (4.7 does not
/// say; a choice to confirm.)
fn check_times(inner: &Inner, chain: &Chain) -> Result<(), ErrResponse> {
    match chain.ahead_of(inner.now()) {
        Some(i) => Err(fail(
            ErrorCode::Invalid,
            &format!("record {i}: its time is more than 10 minutes ahead"),
        )),
        None => Ok(()),
    }
}

/// `REGISTER <name> <keyfile> <signature>` (4.7).
async fn register(cx: &Cx, name: &Name, records: &EncodedRecords, signature: &Signature) -> Reply {
    // Any REGISTER that parses uses up the nonce (4.6).
    let bytes = take_sign_in(cx);
    let inner = &cx.inner;
    let (Some(domain), Some(log)) = (inner.identity_domain.clone(), current_log(inner)) else {
        return Err(fail(
            ErrorCode::NotSupported,
            "this server does not offer registration",
        ));
    };
    if !inner.settings().registration {
        return Err(fail(ErrorCode::Forbidden, "registration is closed"));
    }
    let (Some(nonce), Some(host)) = (bytes.nonce, bytes.host) else {
        return Err(fail(
            ErrorCode::AuthFailed,
            "wrong host name, or this connection's nonce is used up",
        ));
    };
    let host = host.to_ascii_lowercase();
    let slot = inner
        .identity
        .registrations
        .take(
            network(cx.peer.ip()),
            inner.config.limits.registrations_per_hour,
            inner.now(),
        )
        .map_err(|retry| err(ErrorCode::RateLimited).with_retry(retry))?;

    let identity = Identity::new(name, &domain);
    let records = decode(&records.decode())?;
    let chain = check_register(&identity, &records, &log.log)
        .map_err(|e| fail(ErrorCode::Invalid, &e.to_string()))?;
    check_times(inner, &chain)?;
    let Some(device) = chain.devices().values().next() else {
        return Err(fail(ErrorCode::Invalid, "no device"));
    };
    let key = device.keys.device_key.clone();
    if !key.verify_challenge(&host, &nonce, identity.as_str(), signature) {
        return Err(err(ErrorCode::AuthFailed));
    }
    // A banned identity learns it only once its signature verifies (10.2).
    if admin::banned(inner, &identity.to_uid()) {
        return Err(err(ErrorCode::Forbidden));
    }

    let _write = inner.identity.write.lock().await;
    let (name2, id2) = (name.clone(), identity.clone());
    let free = cx
        .db(move |store| {
            Ok(store.hosted(&name2)?.is_none() && store.chain_records(&id2)?.is_empty())
        })
        .await?;
    if !free {
        return Err(err(ErrorCode::NameTaken));
    }
    let indices = log_records(inner, &identity, records.clone()).await?;
    let stored: Vec<StoredRecord> = records
        .iter()
        .zip(&indices)
        .map(|(r, &i)| StoredRecord {
            record: r.encoded().to_vec(),
            hash: r.hash(),
            log_index: Some(i),
        })
        .collect();
    let (name2, id2, now) = (name.clone(), identity.clone(), inner.now());
    let registered = cx
        .db(move |store| store.register(&name2, &id2, &stored, now))
        .await?;
    if !registered {
        return Err(err(ErrorCode::NameTaken));
    }
    inner
        .identity
        .chains()
        .insert(identity.clone(), Arc::new(chain));
    if let Some(slot) = slot {
        slot.keep();
    }
    publish(inner, name).await;
    tracing::info!(conn = cx.conn.0, "registered an identity");
    sign_in(cx, &identity, key).await
}

/// Publishes the key file of the hosted identity `name`, or removes it
/// if it is no longer served (4.7, 4.9), through the key file publisher.
async fn publish(inner: &Arc<Inner>, name: &Name) {
    let inner2 = inner.clone();
    let name = name.clone();
    let done = tokio::task::spawn_blocking(move || {
        let publisher = inner2.key_files.publisher.clone();
        match hosted_key_file(&inner2, &name)? {
            HostedKeyFile::File(file) => publisher.publish(&name, &file),
            HostedKeyFile::Gone | HostedKeyFile::NotFound => publisher.remove(&name),
        }
    })
    .await;
    match done {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("publishing a key file: {e}"),
        Err(e) => tracing::error!("publishing a key file: {e}"),
    }
}

/// The key file of the hosted identity `<name>@<identity domain>`, as
/// served at its URL (4.3, 4.7), 410 once it is unregistered without a
/// `retire` record (4.9), or none. Blocks.
pub(super) fn hosted_key_file(inner: &Inner, name: &Name) -> std::io::Result<HostedKeyFile> {
    let io = |e: StoreError| std::io::Error::other(e.to_string());
    let store = &*inner.store;
    let Some(hosted) = store.hosted(name).map_err(io)? else {
        return Ok(HostedKeyFile::NotFound);
    };
    let Some(chain) = stored_chain(inner, store, &hosted.identity).map_err(io)? else {
        return Ok(HostedKeyFile::NotFound);
    };
    if hosted.unregistered.is_some() && !chain.is_retired() {
        return Ok(HostedKeyFile::Gone);
    }
    let stored = store.chain_records(&hosted.identity).map_err(io)?;
    let file = KeyFile::from_chain(&chain, &|i| stored.get(i).and_then(|r| r.log_index))
        .map_err(|e| std::io::Error::other(format!("the key file of {name}: {e}")))?;
    Ok(HostedKeyFile::File(file.to_text().into_bytes()))
}

// ---------------------------------------------------------------------------
// KEYS PUT (4.7)

/// The most bytes of records KEYS PUT reads from a blob: 4096 records,
/// the most a chain has (4.4), of up to 4 KiB each. (4.7 sets no limit of
/// its own; a choice to confirm.)
pub const MAX_RECORDS_BLOB: u64 = 16 * 1024 * 1024;

/// The bytes of a blob that KEYS PUT names (12.12), from the keys area's
/// blob store: `ERR not-found` if it holds no such blob, `ERR too-long`
/// past [`MAX_RECORDS_BLOB`].
async fn blob_bytes(inner: &Arc<Inner>, hash: &BlobRef) -> Result<Vec<u8>, ErrResponse> {
    keys::blob_bytes(inner, hash, MAX_RECORDS_BLOB)
        .await
        .map_err(|why| match why {
            keys::NoBlob::NotFound => fail(ErrorCode::NotFound, "no such blob"),
            why => ErrResponse::from(why),
        })
}

/// `KEYS PUT <after> <records>` (4.7).
async fn keys_put_command(cx: &Cx, after: Option<&BlobRef>, records: &KeysPutRecords) -> Reply {
    let inner = &cx.inner;
    let Some(log) = current_log(inner) else {
        return Err(fail(
            ErrorCode::NotSupported,
            "this server keeps no key log",
        ));
    };
    let bytes = match records {
        KeysPutRecords::Inline(records) => records.decode(),
        KeysPutRecords::Blob(hash) => blob_bytes(inner, hash).await?,
    };
    let records = decode(&bytes)?;
    let identity = records[0].content().uid.clone();
    let hosted = at_identity_domain(inner, &identity);

    let _write = inner.identity.write.lock().await;
    let (inner2, id2) = (inner.clone(), identity.clone());
    let (held, registered) = cx
        .db(move |store| {
            let registered = match id2.name().parse::<Name>() {
                Ok(name) => store.hosted(&name)?.is_some(),
                Err(_) => false,
            };
            Ok((stored_chain(&inner2, store, &id2)?, registered))
        })
        .await?;
    // An identity at the identity domain is one the server hosts, once
    // registered: nobody else's chain goes into the log under its name.
    // (4.7 does not say; a choice to confirm.)
    if hosted && !registered {
        return Err(fail(ErrorCode::Forbidden, "not registered here"));
    }
    let put = keys_put(
        held.as_deref(),
        after,
        &records,
        &log.log,
        &inner.keylog.handoffs(),
    )
    .map_err(|e| match e {
        KeysPutError::NotFound => fail(ErrorCode::NotFound, "the record <after> names is not held"),
        KeysPutError::Invalid(e) => fail(ErrorCode::Invalid, &e.to_string()),
        KeysPutError::Forbidden => fail(
            ErrorCode::Forbidden,
            "a different record in the place of one held",
        ),
        KeysPutError::TooLong => fail(ErrorCode::TooLong, "a chain has at most 4096 records"),
        KeysPutError::NotThisLog => fail(
            ErrorCode::NotSupported,
            "the newest record does not go into this server's log",
        ),
    })?;
    let held_len = held.as_ref().map_or(0, |c| c.len());
    if put.first_new >= put.chain.len() {
        // Records the server already has: OK and no lines.
        return Ok(OkResponse::new());
    }
    check_times(inner, &put.chain)?;
    if !hosted {
        check_named_here(
            inner,
            &identity,
            &log,
            &put.chain.records()[put.first_new..],
        )
        .await?;
    }

    let to_log: Vec<Record> = put
        .to_append
        .iter()
        .map(|&i| put.chain.records()[i].clone())
        .collect();
    let indices = log_records(inner, &identity, to_log).await?;
    let logged: HashMap<usize, u64> = put.to_append.iter().copied().zip(indices).collect();
    let new: Vec<StoredRecord> = (put.first_new..put.chain.len())
        .map(|i| {
            let r = &put.chain.records()[i];
            StoredRecord {
                record: r.encoded().to_vec(),
                hash: r.hash(),
                log_index: logged.get(&i).copied(),
            }
        })
        .collect();
    let lines: Vec<(u64, BlobRef)> = new
        .iter()
        .filter_map(|r| Some((r.log_index?, r.hash)))
        .collect();
    let id2 = identity.clone();
    cx.db(move |store| store.add_records(&id2, held_len, &new))
        .await?;
    let chain = Arc::new(put.chain);
    inner
        .identity
        .chains()
        .insert(identity.clone(), chain.clone());

    if hosted && let Ok(name) = identity.name().parse::<Name>() {
        publish(inner, &name).await;
        // A device removed by record, or every device after `retire`,
        // signs in no more (4.4), and its account push subscriptions go
        // (9.1).
        close_devices(inner, &identity.to_uid(), |key| {
            chain.device_by_key(key).is_some()
        });
        for device in chain.removed().iter().copied() {
            misc::device_removed(inner, device).await;
        }
    }
    for (index, hash) in lines {
        cx.send(ServerLine::Record { index, hash });
    }
    Ok(OkResponse::new())
}

/// For an identity the server does not host: its key file names this log
/// in its last `log` line, and lists the new records (4.7).
async fn check_named_here(
    inner: &Arc<Inner>,
    identity: &Identity,
    log: &LogLine,
    new: &[Record],
) -> Result<(), ErrResponse> {
    let fetch = inner.key_files.fetcher.fetch_boxed(identity, true);
    let fetched = match tokio::time::timeout(KEY_FETCH_TIMEOUT, fetch).await {
        Ok(Ok(fetched)) => fetched,
        Ok(Err(FetchError::Unavailable)) => {
            return Err(fail(
                ErrorCode::NotSupported,
                "this server logs only the identities it hosts",
            ));
        }
        Ok(Err(_)) | Err(_) => {
            return Err(fail(
                ErrorCode::Unavailable,
                "the identity's key file could not be fetched; try again later",
            ));
        }
    };
    let forbidden = |why: &str| Err(fail(ErrorCode::Forbidden, why));
    let Body::File(bytes) = fetched.body else {
        return forbidden("the identity has no key file");
    };
    let Ok(file) = KeyFile::parse(&bytes) else {
        return forbidden("the identity's key file is not valid");
    };
    if file.last_log().log != log.log {
        return forbidden("the identity's key file does not name this log");
    }
    if !new.iter().all(|r| file.lists(&r.hash())) {
        return forbidden("the identity's key file does not list the records");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pairing (4.8)

fn pair_hash(id: &PairId) -> [u8; 48] {
    Sha384::digest(id.as_bytes()).into()
}

/// `PAIR PUT <id> <data>` (4.8).
async fn pair_put(cx: &Cx, id: &PairId, data: &PairData) -> Reply {
    let inner = &cx.inner;
    let data = data.decode();
    if data.len() > MAX_PAIR_DATA {
        return Err(fail(ErrorCode::TooLong, "pairing data is at most 64 KiB"));
    }
    let now = inner.now();
    let slot = inner
        .identity
        .pair_puts
        .take(network(cx.peer.ip()), PAIR_PUTS_PER_WINDOW, now)
        .map_err(|retry| err(ErrorCode::RateLimited).with_retry(retry))?;
    let hash = pair_hash(id);
    let expires = now.checked_add(PAIR_LIFETIME).unwrap_or(Timestamp::MAX);
    let put = cx
        .db(move |store| store.pair_put(&hash, &data, expires, now))
        .await?;
    match put {
        PairPut::Stored => {
            if let Some(slot) = slot {
                slot.keep();
            }
            Ok(OkResponse::new())
        }
        PairPut::Same => Ok(OkResponse::new()),
        PairPut::Taken => Err(err(ErrorCode::NameTaken)),
    }
}

/// `PAIR GET <id>` (4.8).
async fn pair_get(cx: &Cx, id: &PairId) -> Reply {
    let hash = pair_hash(id);
    let now = cx.inner.now();
    let data = cx.db(move |store| store.pair_get(&hash, now)).await?;
    let Some(data) = data else {
        return Err(err(ErrorCode::NotFound));
    };
    let data = PairData::from_bytes(&data).map_err(internal)?;
    cx.send(ServerLine::Pair { id: *id, data });
    Ok(OkResponse::new())
}

// ---------------------------------------------------------------------------
// Deleting an identity (4.9, 10.5)

/// `UNREGISTER <uid>` (4.9): deletes everything the server keeps about
/// the connection's identity, then closes its connections.
async fn unregister(cx: &Cx, uid: &Uid) -> Reply {
    let Some(device) = cx.device() else {
        return Err(err(ErrorCode::WrongConnection));
    };
    if device.uid != *uid {
        return Err(fail(
            ErrorCode::Forbidden,
            "UNREGISTER names the identity the connection is signed in as",
        ));
    }
    delete_identity(cx, uid).await?;
    Ok(OkResponse::new())
}

/// ADMIN UNREGISTER (10.5), for an operator: deletes `uid` as UNREGISTER
/// does, and clears the server's pin of an identity it does not host.
/// A uid the server knows nothing of gets `ERR not-found`. (10.5 does
/// not say; a choice to confirm.)
pub(super) async fn admin_unregister(cx: &Cx, uid: &Uid) -> Reply {
    if uid.to_identity().is_none() {
        return Err(fail(ErrorCode::NotFound, "guests have nothing to delete"));
    }
    if !delete_identity(cx, uid).await? {
        return Err(err(ErrorCode::NotFound));
    }
    tracing::info!(conn = cx.conn.0, "an operator unregistered an identity");
    Ok(OkResponse::new())
}

/// Deletes `uid` (4.9, 10.5): what the store keeps, its hosted key file
/// unless its chain is retired, the server's pin and cached reads, and
/// its connections, which are closed (this one after its reply). Returns
/// whether the server knew anything of it.
async fn delete_identity(cx: &Cx, uid: &Uid) -> Result<bool, ErrResponse> {
    let inner = &cx.inner;
    let Some(identity) = uid.to_identity() else {
        return Ok(false);
    };
    let _write = inner.identity.write.lock().await;
    let (u, now) = (uid.clone(), inner.now());
    let known = cx.db(move |store| store.unregister(&u, now)).await?;
    inner.identity.reads().remove(&identity);
    if at_identity_domain(inner, &identity)
        && let Ok(name) = identity.name().parse::<Name>()
    {
        publish(inner, &name).await;
    }
    {
        let mut reg = inner.reg();
        let ids: Vec<ConnId> = reg.by_uid.get(uid).into_iter().flatten().copied().collect();
        for id in ids {
            if id == cx.conn {
                // This one closes after its reply, and runs nothing more.
                reg.stop(id);
                cx.close_after(BYE_UNREGISTERED);
            } else {
                reg.detach(id, BYE_UNREGISTERED);
            }
        }
    }
    // Its account push subscriptions and presence setting go too (4.9, 9.1).
    misc::identity_removed(inner, uid).await;
    tracing::info!(known, "unregistered an identity");
    Ok(known)
}

// ---------------------------------------------------------------------------
// Connections and background work

/// Connection `id` has closed.
pub(super) fn conn_closed(_inner: &Arc<Inner>, _id: ConnId, _conn: &ConnEntry) {}

/// How often expired pairing data is deleted.
const PAIRING_SWEEP: Duration = Duration::from_secs(60);

/// The area's background work: publishing every hosted key file when the
/// hub starts, and removing the files of names no longer served (4.7,
/// 4.9); then deleting pairing data after its 10 minutes (4.8).
pub(super) async fn maintain(inner: Arc<Inner>) {
    if inner.identity_domain.is_some() {
        publish_all(&inner).await;
    }
    let mut tick = tokio::time::interval(PAIRING_SWEEP);
    loop {
        tick.tick().await;
        let now = inner.now();
        match inner.db(move |store| store.expire_pairing(now)).await {
            Ok(0) => {}
            Ok(n) => tracing::debug!(n, "expired pairing data"),
            Err(e) => tracing::error!("expiring pairing data: {e}"),
        }
    }
}

/// Publishes the key file of every hosted identity, and removes every
/// other file (4.7, 4.9).
async fn publish_all(inner: &Arc<Inner>) {
    let inner2 = inner.clone();
    let done = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let names = inner2
            .store
            .hosted_names()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let publisher = inner2.key_files.publisher.clone();
        let mut served = Vec::new();
        for name in names {
            if let HostedKeyFile::File(file) = hosted_key_file(&inner2, &name)? {
                publisher.publish(&name, &file)?;
                served.push(name);
            }
        }
        publisher.retain(&served)
    })
    .await;
    match done {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("publishing key files: {e}"),
        Err(e) => tracing::error!("publishing key files: {e}"),
    }
}
