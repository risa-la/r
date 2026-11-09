//! Fetching an identity's key file and checking it against the key log
//! (4.4, 4.5, 12.14).
//!
//! A refresh has two halves. [`Verifier::verify`] does the fetches: the
//! key file, each log's newest checkpoint (witnessed under the device's
//! policy and consistent with the newest it has seen), the entry of each
//! `<index> <hash>` line with an inclusion proof from the log's tiles, the
//! log's hand-off if it has one, and the uid's hint. Nothing it fetches is
//! trusted: every entry is proved against a witnessed checkpoint, and the
//! chain is replayed under 4.4. [`apply`] then decides, in one write to
//! the cache, what the device now knows: the three states of 4.4, which
//! records are accepted (4.5), pins and the head, new master keys,
//! rollbacks and forks, devices added and removed, and freshness.

use std::collections::HashMap;
use std::sync::Arc;

use risala_keylog::client::{
    ForkEvidence, LogView, ViewError, accept_handoff, inclusion_tiles, verify_bundle_entry,
};
use risala_keylog::hint::{UidHint, parse_next};
use risala_keylog::tile::{TileId, TileSet, bundle_for_entry, decode_bundle};
use risala_keylog::witness::{Freshness, LogKey as KeylogKey, WitnessError, WitnessPolicy};
use risala_proto::chain::{Chain, Handoffs};
use risala_proto::keyfile::{
    EntryError, KeyFile, KeyFileError, KeyFileState, Listing, LogLine, MAX_KEY_FILE_BYTES,
    MAX_LOG_FETCH_BYTES, Missing, Outage, well_known_url,
};
use risala_proto::names::{BlobRef, Identity};
use risala_proto::record::{LogEntry, LogKey, Record, RecordBody};

use super::https::{Fetched, Https};
use crate::store::identity::{ContactRow, DeviceRow, DeviceState, KeysState, RecordRow};
use crate::store::keylog::ForkKind;
use crate::store::{Store, StoreError, Tx};
use crate::sync::keylog::{
    checkpoint_url, keylog_key, next_url, restore_view, tile_url, uid_hint_url,
};

/// Seven days, in ms: an identity whose view has not been refreshed for
/// this long is stale (4.5).
pub const STALE_AFTER_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// A day, in ms.
pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Why a log could not be used in this refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LogProblem {
    /// No checkpoint of it has k cosignatures from the device's list, and
    /// the device has never seen one that had (4.5): the list does not fit
    /// the log.
    WitnessList,
    /// It forked, now or before (4.5).
    Forked,
    /// Fetching from it failed, or it served something that does not
    /// check: an outage for its records (4.4).
    Outage(String),
}

/// One log, as this refresh sees it.
pub(crate) struct LogState {
    line: LogLine,
    view: Option<LogView>,
    /// Whether the view changed, to keep.
    view_changed: bool,
    /// Whether a checkpoint fetched now was fresh (4.5, Freshness).
    fresh: bool,
    problem: Option<LogProblem>,
    tiles: TileSet,
    /// Full tiles the cache holds, by path.
    kept: HashMap<String, Vec<u8>>,
    /// Full tiles fetched now, to keep.
    fetched: Vec<(String, Vec<u8>)>,
    /// Entry bundles fetched now, by path.
    bundles: HashMap<String, Vec<u8>>,
    fork: Option<Option<ForkEvidence>>,
    handoff: Option<(u64, KeylogKey)>,
}

/// Why an entry could not be had.
enum EntryFail {
    /// Its index is not in the newest witnessed checkpoint yet, or the
    /// log cannot be used: the record is pending.
    NotYet,
    /// Fetching or proving it failed: an outage.
    Outage(String),
}

/// The key file's records that this refresh could read, with what it
/// proved of each.
#[derive(Debug, Clone)]
struct Listed {
    log: LogLine,
    index: Option<u64>,
    /// In a witnessed checkpoint of its log, by an inclusion proof.
    proven: bool,
}

/// What [`Verifier::verify`] found.
pub(crate) enum Verified {
    /// A valid key file (4.4), as far as it could be read.
    Keys(Box<Found>),
    /// Keys missing (4.4), and why.
    Missing(String),
    /// An outage (4.4), and why.
    Outage(String),
    /// No record of the file could be read from its logs: none is in a
    /// witnessed checkpoint yet, no checkpoint of the log has k
    /// cosignatures from the device's list (4.5), or the log forked. The
    /// records are pending; what was learnt of the logs is kept.
    Unread {
        /// Why, for logs.
        why: String,
        /// The logs.
        logs: HashMap<String, LogState>,
    },
}

/// A valid key file and what the logs said about it.
pub(crate) struct Found {
    file: KeyFile,
    /// The chain of the records that could be read, in order.
    chain: Chain,
    /// For each of them, where it is listed and whether it is proven.
    listed: Vec<Listed>,
    /// Records of the file that could not be read yet.
    unread: usize,
    /// The logs, by origin.
    logs: HashMap<String, LogState>,
    /// Logged records of the uid that the file leaves out (4.5,
    /// Freshness, step 2).
    left_out: Vec<Record>,
    /// Whether the uid's hint was read and checked.
    hint_checked: bool,
    /// The origin of the log the file names last.
    current_log: String,
}

/// Fetches what a refresh needs.
pub(crate) struct Verifier {
    https: Arc<dyn Https>,
    policy: Option<WitnessPolicy>,
    store: Store,
    now_ms: u64,
    logs: HashMap<String, LogState>,
}

impl Verifier {
    pub(crate) fn new(
        https: Arc<dyn Https>,
        policy: Option<WitnessPolicy>,
        store: Store,
        now_ms: u64,
    ) -> Verifier {
        Verifier {
            https,
            policy,
            store,
            now_ms,
            logs: HashMap::new(),
        }
    }

    fn now_s(&self) -> u64 {
        self.now_ms / 1000
    }

    /// Fetches the key file of `uid` and checks it against its logs.
    /// `head` is the device's head for it, with its log's origin and
    /// index, for the hint check.
    pub(crate) async fn verify(
        mut self,
        uid: &Identity,
        head: Option<(String, u64)>,
    ) -> Result<Verified, StoreError> {
        let file = match self
            .https
            .get(&well_known_url(uid), MAX_KEY_FILE_BYTES)
            .await
        {
            Fetched::Body(body) => match KeyFile::parse(&body) {
                Ok(file) => file,
                Err(KeyFileError::TooLarge) => return Ok(Verified::Missing("too large".into())),
                Err(KeyFileError::NotKeyFile) => {
                    return Ok(Verified::Missing("not a risala-keys/1 file".into()));
                }
                Err(e) => return Ok(Verified::Missing(format!("not valid: {e}"))),
            },
            Fetched::TooLarge => return Ok(Verified::Missing("too large".into())),
            Fetched::Gone(status) => return Ok(Verified::Missing(format!("HTTP {status}"))),
            Fetched::Status(status) => return Ok(Verified::Outage(format!("HTTP {status}"))),
            Fetched::Failed(why) => return Ok(Verified::Outage(why)),
        };

        for section in file.sections() {
            self.load_log(&section.log).await?;
        }

        // The record of each listing, as far as the logs let us read them.
        let mut records: Vec<(Record, Listed)> = Vec::new();
        let mut unread = 0;
        for (log, listing) in file.listings() {
            if unread > 0 {
                unread += 1;
                continue;
            }
            match listing {
                Listing::Unlogged(record) => records.push((
                    record.clone(),
                    Listed {
                        log: log.clone(),
                        index: None,
                        proven: false,
                    },
                )),
                Listing::Logged { index, hash } => {
                    let origin = log.log.origin().to_owned();
                    match self.proven_entry(&origin, *index).await {
                        Ok(entry) => match LogEntry::decode(&entry) {
                            Ok(LogEntry::Record(record)) if record.hash() == *hash => {
                                records.push((
                                    record,
                                    Listed {
                                        log: log.clone(),
                                        index: Some(*index),
                                        proven: true,
                                    },
                                ));
                            }
                            // The proven entry at that index is not the
                            // record listed: the file does not match the
                            // log (4.4).
                            _ => {
                                return Ok(Verified::Missing(format!(
                                    "entry {index} of {origin} is not the record listed"
                                )));
                            }
                        },
                        Err(EntryFail::NotYet) => unread = 1,
                        Err(EntryFail::Outage(why)) => return Ok(Verified::Outage(why)),
                    }
                }
            }
        }
        if records.is_empty() {
            // Nothing could be read: the first record is not in a
            // witnessed checkpoint yet, or its log cannot be used.
            let problem = file
                .sections()
                .iter()
                .find_map(|s| self.logs.get(s.log.log.origin())?.problem.clone());
            return Ok(match problem {
                Some(LogProblem::Outage(why)) => Verified::Outage(why),
                _ => Verified::Unread {
                    why: format!("{problem:?}"),
                    logs: std::mem::take(&mut self.logs),
                },
            });
        }

        // Replay what could be read. A file read in part is checked as far
        // as it goes; the rest stays pending.
        let to_check = if unread == 0 {
            file.clone()
        } else {
            match truncate(&file, records.len()) {
                Some(f) => f,
                None => return Ok(Verified::Outage("the key file could not be read".into())),
            }
        };
        let entries: HashMap<(String, u64), Vec<u8>> = records
            .iter()
            .filter_map(|(r, l)| {
                l.index.map(|i| {
                    (
                        (l.log.log.origin().to_owned(), i),
                        LogEntry::Record(r.clone()).encode(),
                    )
                })
            })
            .collect();
        let mut source = |log: &LogLine, index: u64| {
            entries
                .get(&(log.log.origin().to_owned(), index))
                .cloned()
                .ok_or(EntryError::Outage)
        };
        let handoffs = self.handoffs();
        let now = risala_proto::time::Timestamp::from_unix_millis(self.now_ms)
            .unwrap_or(risala_proto::time::Timestamp::MAX);
        let chain = match to_check.check(uid, &mut source, &handoffs, now) {
            KeyFileState::Keys(chain) => *chain,
            KeyFileState::KeysMissing(why) => return Ok(Verified::Missing(missing_text(&why))),
            KeyFileState::Outage(Outage::Ahead(i)) => {
                return Ok(Verified::Outage(format!(
                    "record {i} is dated in the future"
                )));
            }
            KeyFileState::Outage(o) => return Ok(Verified::Outage(format!("{o:?}"))),
        };

        // The uid's hint in the log the file names last (4.5, Freshness,
        // step 2).
        let current = file.last_log().clone();
        let current_log = current.log.origin().to_owned();
        let (left_out, hint_checked) = self.check_hint(uid, &current, &file, head).await;

        let listed = records.into_iter().map(|(_, l)| l).collect();
        Ok(Verified::Keys(Box::new(Found {
            file,
            chain,
            listed,
            unread,
            logs: std::mem::take(&mut self.logs),
            left_out,
            hint_checked,
            current_log,
        })))
    }

    /// The hand-offs this device has accepted, for replaying a chain.
    fn handoffs(&self) -> impl Handoffs + use<> {
        let accepted: HashMap<String, String> = self
            .logs
            .values()
            .filter_map(|s| {
                let (_, next) = s.handoff.as_ref()?;
                Some((
                    s.line.log.origin().to_owned(),
                    next.verifier().vkey().to_string(),
                ))
            })
            .collect();
        move |from: &LogKey, to: &LogKey| {
            // Follow the hand-offs from `from` until `to`.
            let mut at = from.vkey();
            let target = to.vkey();
            for _ in 0..64 {
                let Ok(log) = LogKey::from_vkey(&at) else {
                    return false;
                };
                match accepted.get(log.origin()) {
                    Some(next) if *next == target => return true,
                    Some(next) => at = next.clone(),
                    None => return false,
                }
            }
            false
        }
    }

    /// Loads what the device keeps of a log, fetches its newest
    /// checkpoint and checks it (4.5), and follows its hand-off if it has
    /// one.
    async fn load_log(&mut self, line: &LogLine) -> Result<(), StoreError> {
        let origin = line.log.origin().to_owned();
        if self.logs.contains_key(&origin) {
            return Ok(());
        }
        let key = keylog_key(&line.log);
        let row = self.store.log(&origin)?;
        let mut state = LogState {
            line: line.clone(),
            view: None,
            view_changed: false,
            fresh: false,
            problem: None,
            tiles: TileSet::new(),
            kept: self.store.tiles(&origin)?.into_iter().collect(),
            fetched: Vec::new(),
            bundles: HashMap::new(),
            fork: None,
            handoff: None,
        };
        let (Some(key), Some(policy)) = (key, self.policy.clone()) else {
            state.problem = Some(LogProblem::WitnessList);
            self.logs.insert(origin, state);
            return Ok(());
        };
        if let Some(row) = &row {
            // One origin has one key (4.10): a key file that names another
            // key for a log the device knows names a log that no honest
            // witness cosigns.
            if row.vkey != line.log.vkey() {
                state.problem = Some(LogProblem::Outage(format!(
                    "{origin} is named with another key"
                )));
                self.logs.insert(origin, state);
                return Ok(());
            }
            if row.forked {
                state.problem = Some(LogProblem::Forked);
            }
            state.view = restore_view(row, &key, &policy);
            state.handoff = state.view.as_ref().and_then(|v| v.handoff().cloned());
        }
        self.logs.insert(origin.clone(), state);
        if self.logs[&origin].problem.is_some() {
            return Ok(());
        }

        let now_s = self.now_s();
        let fetched = self
            .https
            .get(&checkpoint_url(&line.url), MAX_LOG_FETCH_BYTES)
            .await;
        let witnessed = match fetched {
            Fetched::Body(body) => policy.verify(&key, &body, Freshness::at(now_s)),
            other => {
                self.problem(
                    &origin,
                    LogProblem::Outage(format!("checkpoint: {other:?}")),
                );
                return Ok(());
            }
        };
        let had_view = self.logs[&origin].view.is_some();
        let checkpoint = match witnessed {
            Ok(cp) => cp,
            Err(e) if e.is_witness_list_problem(had_view) => {
                self.problem(&origin, LogProblem::WitnessList);
                return Ok(());
            }
            // Witnessed before, but not this one: the log or its witnesses
            // are behind. Records already proven stay so; new ones wait.
            Err(WitnessError::NotEnoughWitnesses { .. }) => return Ok(()),
            Err(e) => {
                self.problem(&origin, LogProblem::Outage(format!("checkpoint: {e}")));
                return Ok(());
            }
        };
        match self.logs[&origin].view.clone() {
            None => {
                let state = self.logs.get_mut(&origin).expect("loaded");
                state.view = LogView::new(key.clone(), checkpoint).ok();
                state.view_changed = state.view.is_some();
            }
            Some(mut view) => {
                let tiles = view.tiles_for(checkpoint.checkpoint());
                let size = view
                    .newest()
                    .checkpoint()
                    .size()
                    .max(checkpoint.checkpoint().size());
                if let Err(why) = self.fetch_tiles(&origin, &tiles).await {
                    self.problem(&origin, LogProblem::Outage(why));
                    return Ok(());
                }
                let state = self.logs.get_mut(&origin).expect("loaded");
                let checked = view.check(checkpoint, &mut state.tiles.reader(size));
                match checked {
                    Ok(_) => {
                        state.view = Some(view);
                        state.view_changed = true;
                    }
                    Err(ViewError::Fork(evidence)) => {
                        state.fork = Some(Some(*evidence));
                        state.problem = Some(LogProblem::Forked);
                    }
                    Err(ViewError::AfterHandoff) => {
                        state.fork = Some(None);
                        state.problem = Some(LogProblem::Forked);
                    }
                    Err(e) => {
                        state.problem = Some(LogProblem::Outage(format!("consistency: {e}")));
                    }
                }
            }
        }
        let state = self.logs.get_mut(&origin).expect("loaded");
        state.fresh =
            state.view.as_ref().is_some_and(|v| v.is_fresh(now_s)) && state.problem.is_none();
        if state.handoff.is_none() && state.problem.is_none() {
            self.follow_handoff(&origin).await;
        }
        Ok(())
    }

    /// Reads a log's `risala/next` hint, and accepts the hand-off it names
    /// if it is the last entry of the newest witnessed checkpoint (4.5).
    async fn follow_handoff(&mut self, origin: &str) {
        let url = next_url(&self.logs[origin].line.url);
        let Fetched::Body(body) = self.https.get(&url, MAX_LOG_FETCH_BYTES).await else {
            return;
        };
        let Ok(index) = parse_next(&body) else {
            return;
        };
        let Some(view) = self.logs[origin].view.clone() else {
            return;
        };
        let size = view.newest().checkpoint().size();
        if index.checked_add(1) != Some(size) {
            // Not in a witnessed checkpoint yet, or not its last entry.
            return;
        }
        let Ok(entry) = self.bundle_entry(origin, index, size).await else {
            return;
        };
        let tiles = view.tiles_for_entry(view.newest().checkpoint(), index);
        if self.fetch_tiles(origin, &tiles).await.is_err() {
            return;
        }
        let state = self.logs.get_mut(origin).expect("loaded");
        let mut view = view;
        let newest = view.newest().clone();
        if let Ok(next) = accept_handoff(
            &mut view,
            newest,
            &entry,
            index,
            &mut state.tiles.reader(size),
        ) {
            state.handoff = Some((index, next));
            state.view = Some(view);
            state.view_changed = true;
        }
    }

    fn problem(&mut self, origin: &str, problem: LogProblem) {
        if let Some(state) = self.logs.get_mut(origin) {
            state.problem = Some(problem);
            state.fresh = false;
        }
    }

    /// Fetches the hash tiles the log's state does not have, from the
    /// cache's full tiles or the log.
    async fn fetch_tiles(&mut self, origin: &str, tiles: &[TileId]) -> Result<(), String> {
        let missing = self.logs[origin].tiles.missing(tiles);
        for tile in missing {
            let path = tile.path();
            let kept = (!tile.is_partial())
                .then(|| self.logs[origin].kept.get(&path).cloned())
                .flatten();
            let (data, new) = match kept {
                Some(data) => (data, false),
                None => {
                    let url = tile_url(&self.logs[origin].line.url, &tile);
                    match self.https.get(&url, MAX_LOG_FETCH_BYTES).await {
                        Fetched::Body(data) => (data, !tile.is_partial()),
                        other => return Err(format!("tile {path}: {other:?}")),
                    }
                }
            };
            let state = self.logs.get_mut(origin).expect("loaded");
            state
                .tiles
                .insert(tile, data.clone())
                .map_err(|e| format!("tile {path}: {e}"))?;
            if new {
                state.fetched.push((path, data));
            }
        }
        Ok(())
    }

    /// The raw entry at `index` from the entry bundle that holds it in a
    /// tree of `size`, not yet proved.
    async fn bundle_entry(
        &mut self,
        origin: &str,
        index: u64,
        size: u64,
    ) -> Result<Vec<u8>, String> {
        let bundle = bundle_for_entry(index, size).ok_or("not in the tree")?;
        let path = bundle.path();
        let data = match self.logs[origin].bundles.get(&path) {
            Some(data) => data.clone(),
            None => {
                let url = tile_url(&self.logs[origin].line.url, &bundle);
                let Fetched::Body(data) = self.https.get(&url, MAX_LOG_FETCH_BYTES).await else {
                    return Err(format!("entry bundle {path}"));
                };
                self.logs
                    .get_mut(origin)
                    .expect("loaded")
                    .bundles
                    .insert(path.clone(), data.clone());
                data
            }
        };
        let mut entries = decode_bundle(&data).map_err(|e| e.to_string())?;
        let i = (index % risala_keylog::tile::TILE_WIDTH) as usize;
        if i >= entries.len() {
            return Err(format!("entry bundle {path} is short"));
        }
        Ok(entries.swap_remove(i))
    }

    /// The entry at `index` of a log, proved to be in its newest witnessed
    /// checkpoint (4.5, Accepting a record, steps 2 and 3).
    async fn proven_entry(&mut self, origin: &str, index: u64) -> Result<Vec<u8>, EntryFail> {
        let state = &self.logs[origin];
        if state.problem.is_some() {
            return Err(EntryFail::NotYet);
        }
        let Some(view) = &state.view else {
            return Err(EntryFail::NotYet);
        };
        let checkpoint = view.newest().checkpoint().clone();
        let size = checkpoint.size();
        if index >= size {
            return Err(EntryFail::NotYet);
        }
        let bundle = bundle_for_entry(index, size).ok_or(EntryFail::NotYet)?;
        let path = bundle.path();
        let data = match state.bundles.get(&path) {
            Some(data) => data.clone(),
            None => {
                let url = tile_url(&state.line.url, &bundle);
                match self.https.get(&url, MAX_LOG_FETCH_BYTES).await {
                    Fetched::Body(data) => {
                        self.logs
                            .get_mut(origin)
                            .expect("loaded")
                            .bundles
                            .insert(path.clone(), data.clone());
                        data
                    }
                    other => {
                        return Err(EntryFail::Outage(format!("entry bundle {path}: {other:?}")));
                    }
                }
            }
        };
        self.fetch_tiles(origin, &inclusion_tiles(index, size))
            .await
            .map_err(EntryFail::Outage)?;
        let state = self.logs.get_mut(origin).expect("loaded");
        verify_bundle_entry(&data, index, &checkpoint, &mut state.tiles.reader(size))
            .map_err(|e| EntryFail::Outage(format!("entry {index} of {origin}: {e}")))
    }

    /// Reads the uid's hint in the current log, and fetches every entry
    /// after the head that the file does not list (4.5, Freshness, step
    /// 2). Returns the records of the uid among them, and whether the hint
    /// was checked.
    async fn check_hint(
        &mut self,
        uid: &Identity,
        current: &LogLine,
        file: &KeyFile,
        head: Option<(String, u64)>,
    ) -> (Vec<Record>, bool) {
        let origin = current.log.origin().to_owned();
        let url = uid_hint_url(&current.url, uid.as_str());
        let hint = match self.https.get(&url, MAX_LOG_FETCH_BYTES).await {
            Fetched::Body(body) => match UidHint::parse(&body) {
                Ok(hint) => hint,
                Err(_) => return (Vec::new(), false),
            },
            Fetched::Gone(_) => return (Vec::new(), true),
            _ => return (Vec::new(), false),
        };
        let listed: Vec<u64> = file
            .listings()
            .filter(|(log, _)| log.log.origin() == origin)
            .filter_map(|(_, l)| match l {
                Listing::Logged { index, .. } => Some(*index),
                Listing::Unlogged(_) => None,
            })
            .collect();
        let head = head.and_then(|(o, i)| (o == origin).then_some(i));
        let mut left_out = Vec::new();
        let mut checked = true;
        for index in hint.unlisted(head, &listed) {
            match self.proven_entry(&origin, index).await {
                Ok(entry) => {
                    if let Ok(LogEntry::Record(record)) = LogEntry::decode(&entry)
                        && record.content().uid == *uid
                        && !file.lists(&record.hash())
                    {
                        left_out.push(record);
                    }
                }
                // Not witnessed yet: checked next time.
                Err(EntryFail::NotYet) => {}
                Err(EntryFail::Outage(_)) => checked = false,
            }
        }
        (left_out, checked)
    }
}

/// The first `n` listings of `file`, as a key file of their own.
fn truncate(file: &KeyFile, n: usize) -> Option<KeyFile> {
    let mut text = format!("{}\n", risala_proto::keyfile::KEY_FILE_HEADER);
    let mut left = n;
    for section in file.sections() {
        if left == 0 {
            break;
        }
        text.push_str(&format!("{}\n", section.log));
        for listing in section.records.iter().take(left) {
            text.push_str(&format!("{listing}\n"));
            left -= 1;
        }
    }
    KeyFile::parse(text.as_bytes()).ok()
}

fn missing_text(why: &Missing) -> String {
    match why {
        Missing::Chain(e) => format!("the chain is not valid: {e}"),
        other => format!("{other:?}"),
    }
}

/// What a refresh did, for the API and for watching the device's own
/// identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Applied {
    /// A valid key file was taken in.
    Keys {
        /// Records accepted in this refresh.
        newly_accepted: Vec<BlobRef>,
        /// A fork or rollback found in this refresh.
        new_fork: bool,
    },
    /// The keys are missing.
    Missing,
    /// Nothing could be read from the log yet, or it forked.
    Unread {
        /// A fork of the log found in this refresh.
        new_fork: bool,
    },
    /// An outage: nothing changed.
    Outage,
}

/// A random time within the next day after `now`, at least 12 hours
/// ahead, for the next daily fetch (12.14).
pub(crate) fn next_check(now: u64) -> u64 {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    let spread = u64::from_le_bytes(b) % (DAY_MS / 2);
    now + DAY_MS / 2 + spread
}

/// Takes what [`Verifier::verify`] found into the cache (4.4, 4.5).
pub(crate) fn apply(
    tx: &mut Tx<'_>,
    uid: &Identity,
    verified: Verified,
    now: u64,
) -> Result<Applied, StoreError> {
    let mut contact = tx
        .contact(uid.as_str())?
        .unwrap_or_else(|| ContactRow::new(uid.as_str()));
    contact.fetched = Some(now);
    contact.next_check = Some(next_check(now));
    // 12.7: while the key file cannot be read, a key check waiting on it
    // stays pending, and never fails for time.
    contact.outage = matches!(verified, Verified::Outage(_) | Verified::Unread { .. });
    let found = match verified {
        Verified::Outage(why) => {
            tracing::debug!(%uid, %why, "key file fetch: outage");
            tx.put_contact(&contact)?;
            return Ok(Applied::Outage);
        }
        Verified::Unread { why, logs } => {
            tracing::debug!(%uid, %why, "key file: nothing could be read from the log");
            let taken = take_logs(tx, &logs, now)?;
            contact.witness_problem = taken.witness_problem;
            contact.forked |= taken.log_forked;
            tx.put_contact(&contact)?;
            return Ok(Applied::Unread {
                new_fork: taken.new_fork,
            });
        }
        Verified::Missing(why) => {
            tracing::info!(%uid, %why, "key file: keys missing");
            contact.keys = KeysState::Missing(why);
            tx.put_contact(&contact)?;
            return Ok(Applied::Missing);
        }
        Verified::Keys(found) => *found,
    };
    let Found {
        file,
        chain,
        listed,
        unread,
        logs,
        left_out,
        hint_checked,
        current_log,
    } = found;

    let taken = take_logs(tx, &logs, now)?;
    let mut new_fork = taken.new_fork;
    let witness_problem = taken.witness_problem;
    let log_forked = taken.log_forked;

    for record in &left_out {
        let kind = match chain.fork_with(record) {
            Some(i) if chain.records()[i].content().is_first_master() => ForkKind::Masters,
            Some(_) => ForkKind::Records,
            None => ForkKind::Rollback,
        };
        new_fork |= tx.add_fork(Some(uid.as_str()), None, kind, record.encoded(), now)?;
    }
    // A file that does not hold the head (4.4, 4.5): a rollback if its
    // chain starts with the pinned master key, which is a fork, and a new
    // master key if it starts with another, which waits for the user.
    if let Some(head) = &contact.head
        && !file.lists(head)
    {
        let pinned = contact.master_key.as_deref();
        let same_start = pinned.is_some_and(|m| {
            chain.records().iter().any(|r| {
                matches!(&r.content().body,
                    RecordBody::Master { master_key, .. } if master_key.as_bytes()[..] == *m)
            })
        });
        if same_start {
            new_fork |= tx.add_fork(
                Some(uid.as_str()),
                None,
                ForkKind::Rollback,
                head.hash(),
                now,
            )?;
        } else {
            let master = chain.master_key().as_bytes().to_vec();
            if contact.new_master_key.as_ref() != Some(&master) {
                contact.new_master_key = Some(master);
                contact.verified = false;
            }
            contact.keys = KeysState::Keys;
            contact.witness_problem = witness_problem;
            contact.forked |= log_forked;
            contact.pending = (chain.len() + unread) as u64;
            tx.put_contact(&contact)?;
            return Ok(Applied::Keys {
                newly_accepted: Vec::new(),
                new_fork,
            });
        }
    }
    if new_fork || log_forked {
        contact.forked = true;
    }
    contact.witness_problem = witness_problem;
    contact.keys = KeysState::Keys;
    if contact.forked {
        // Nothing moves while a fork stands (4.5): the user resolves it.
        contact.pending = (chain.len() + unread) as u64;
        tx.put_contact(&contact)?;
        return Ok(Applied::Keys {
            newly_accepted: Vec::new(),
            new_fork,
        });
    }

    // Which records are accepted: a prefix of the chain whose records
    // were proven in a fresh log, or were accepted before (4.5).
    let stored = tx.records(uid.as_str())?;
    let before: HashMap<BlobRef, &RecordRow> = stored.iter().map(|r| (r.hash, r)).collect();
    let accepted_len = chain
        .records()
        .iter()
        .zip(&listed)
        // Accepting needs a witnessed checkpoint, not a fresh one (4.5,
        // Witness policy).
        .take_while(|(r, l)| before.get(&r.hash()).is_some_and(|row| row.accepted) || l.proven)
        .count();
    let newly_accepted: Vec<BlobRef> = chain.records()[..accepted_len]
        .iter()
        .map(Record::hash)
        .filter(|h| !before.get(h).is_some_and(|row| row.accepted))
        .collect();

    // The records, with the device's own unlogged ones after them kept
    // (4.7: kept as encoded until the log holds them).
    let mut rows: Vec<RecordRow> = chain
        .records()
        .iter()
        .zip(&listed)
        .enumerate()
        .map(|(i, (record, l))| {
            let old = before.get(&record.hash());
            RecordRow {
                hash: record.hash(),
                position: i as u64,
                record: record.encoded().to_vec(),
                log: (l.log.log.origin().to_owned(), l.log.log.vkey()),
                log_index: l.index.or(old.and_then(|o| o.log_index)),
                accepted: i < accepted_len,
                mine: old.is_some_and(|o| o.mine),
                witnessed: old
                    .and_then(|o| o.witnessed)
                    .or((i < accepted_len).then_some(now)),
            }
        })
        .collect();
    let same_start =
        stored.len() > rows.len() && stored.iter().zip(&rows).all(|(a, b)| a.hash == b.hash);
    if same_start {
        for old in &stored[rows.len()..] {
            if old.mine && old.log_index.is_none() {
                let mut row = old.clone();
                row.accepted = false;
                rows.push(row);
            }
        }
    }
    tx.put_records(uid.as_str(), 0, &rows)?;

    // Devices: current by accepted records, pending by the rest, removed
    // for good by accepted records (4.4).
    let accepted = (accepted_len > 0)
        .then(|| prefix_chain(&chain, accepted_len))
        .flatten();
    let mut devices: Vec<DeviceRow> = Vec::new();
    let full_devices = chain.devices();
    if let Some(acc) = &accepted {
        for (id, d) in acc.devices() {
            devices.push(device_row(
                id.as_bytes(),
                &d.keys,
                d.time,
                DeviceState::Current,
            ));
        }
        for id in acc.removed() {
            let old = tx
                .devices(uid.as_str())?
                .into_iter()
                .find(|d| d.device_id == *id.as_bytes());
            if let Some(mut d) = old {
                d.state = DeviceState::Removed;
                devices.push(d);
            } else if let Some(record) = removed_device_keys(&chain, id) {
                devices.push(record);
            }
        }
    }
    for (id, d) in full_devices {
        let in_accepted = accepted
            .as_ref()
            .is_some_and(|a| a.devices().contains_key(id));
        if !in_accepted {
            devices.push(device_row(
                id.as_bytes(),
                &d.keys,
                d.time,
                DeviceState::Pending,
            ));
        }
    }
    tx.put_devices(uid.as_str(), &devices)?;
    // Devices of a chain the user replaced, after a new master key, go.
    let keep: Vec<[u8; 48]> = devices.iter().map(|d| d.device_id).collect();
    tx.retain_devices(uid.as_str(), &keep)?;

    // Pins and the head (4.5).
    if let Some(acc) = &accepted {
        let master = acc.master_key().as_bytes().to_vec();
        match &contact.master_key {
            None => {
                // First acceptance: pin, unless a PIN line from the
                // identity's own devices says otherwise (12.9).
                if let Some((hash, origin)) = &contact.pin_hint
                    && (BlobRef::of(&master) != *hash || acc.log().origin() != origin)
                {
                    contact.new_master_key = Some(master.clone());
                } else {
                    contact.master_key = Some(master.clone());
                }
                contact.pin_hint = None;
            }
            Some(pinned) if *pinned != master => {
                if contact.new_master_key.as_ref() != Some(&master) {
                    contact.new_master_key = Some(master.clone());
                    contact.verified = false;
                }
            }
            Some(_) => {}
        }
        contact.log_origin = Some(acc.log().origin().to_owned());
        let head = &listed[accepted_len - 1];
        contact.head = Some(acc.head_hash());
        contact.head_index = head.index;
    }
    contact.pending = (chain.len() - accepted_len + unread) as u64;
    let fresh = logs.get(&current_log).is_some_and(|s| s.fresh);
    if fresh && hint_checked {
        contact.refreshed = Some(now);
    }
    tx.put_contact(&contact)?;
    Ok(Applied::Keys {
        newly_accepted,
        new_fork,
    })
}

/// What [`take_logs`] found.
struct TakenLogs {
    new_fork: bool,
    witness_problem: bool,
    log_forked: bool,
}

/// Keeps what a refresh learnt of the logs: newer views, full tiles,
/// accepted hand-offs and forks. A log that forked marks every identity
/// whose records it holds (4.5).
fn take_logs(
    tx: &mut Tx<'_>,
    logs: &HashMap<String, LogState>,
    now: u64,
) -> Result<TakenLogs, StoreError> {
    let mut taken = TakenLogs {
        new_fork: false,
        witness_problem: false,
        log_forked: false,
    };
    for (origin, state) in logs {
        tx.add_log(origin, &state.line.log.vkey())?;
        if let Some(view) = state.view.as_ref().filter(|_| state.view_changed) {
            let newest = view.newest();
            let checked = state.fresh.then_some(now);
            tx.set_log_checkpoint(
                origin,
                &newest.to_text(),
                newest.checkpoint().size(),
                checked,
            )?;
            if let Some((index, next)) = view.handoff() {
                tx.set_log_handoff(origin, *index, &next.verifier().vkey().to_string())?;
            }
        }
        for (path, data) in &state.fetched {
            tx.put_tile(origin, path, data)?;
        }
        if let Some(evidence) = &state.fork {
            tx.set_log_forked(origin)?;
            let bytes = match evidence {
                Some(e) => {
                    let (a, b) = e.checkpoints();
                    format!("{}\n{}", a.to_text(), b.to_text()).into_bytes()
                }
                None => b"the log grew after its hand-off".to_vec(),
            };
            taken.new_fork |=
                tx.add_fork(None, Some(origin), ForkKind::Checkpoints, &bytes, now)?;
            tx.fork_log_contacts(origin)?;
        }
        taken.witness_problem |= state.problem == Some(LogProblem::WitnessList);
        taken.log_forked |= state.problem == Some(LogProblem::Forked);
    }
    Ok(taken)
}

/// The chain of the first `n` records of `chain`, in the same logs.
pub(crate) fn prefix_chain(chain: &Chain, n: usize) -> Option<Chain> {
    let placed: Vec<(&Record, Option<&LogKey>)> = chain
        .records()
        .iter()
        .zip(chain.placements())
        .take(n)
        .map(|(r, l)| (r, Some(l)))
        .collect();
    Chain::replay_placed(chain.uid(), placed, &|_: &LogKey, _: &LogKey| true).ok()
}

fn device_row(
    id: &[u8; 48],
    keys: &risala_proto::record::DeviceKeys,
    added: u64,
    state: DeviceState,
) -> DeviceRow {
    DeviceRow {
        device_id: *id,
        device_key: keys.device_key.as_bytes().to_vec(),
        attestation_key: keys.attestation_key.as_bytes().to_vec(),
        label: keys.label.clone(),
        added,
        state,
    }
}

/// The removed device's row, from the `device` record that added it.
fn removed_device_keys(chain: &Chain, id: &risala_proto::record::DeviceId) -> Option<DeviceRow> {
    chain
        .records()
        .iter()
        .find_map(|r| match &r.content().body {
            risala_proto::record::RecordBody::Device(keys) if keys.device_id() == *id => Some(
                device_row(id.as_bytes(), keys, r.content().time, DeviceState::Removed),
            ),
            _ => None,
        })
}
