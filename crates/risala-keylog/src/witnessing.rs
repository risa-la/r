//! A witness for risala key logs (SPEC 4.10): what it checks before it
//! cosigns a checkpoint, and how it takes a hand-off from one of a host's
//! logs to the next. No I/O: the HTTP side ([TLOG-WITNESS]'s
//! `add-checkpoint`, and `POST <prefix>/risala/handoff`) and the storage
//! are the caller's, through [`WitnessStore`].
//!
//! The rules, on top of [TLOG-WITNESS]:
//!
//! - **Open enrolment.** A log enrols by sending its first checkpoint, with
//!   old size 0. Its origin must be `<host>/risala-log/<n>`, and its
//!   checkpoint signed under an ML-DSA-44 key named after the origin, with
//!   a timestamp that is not zero. Log 1 of a host enrols only if the
//!   witness has never enrolled a log of that host; log `n` > 1 only if
//!   the witness enrolled log `n`-1 and took a hand-off from it to this
//!   origin and key. No origin ever gets a second key.
//! - **Hand-offs.** Log `n`-1 shows the witness its hand-off entry, the
//!   last entry of the newest checkpoint the witness cosigned for it, with
//!   an inclusion proof. From then on the witness cosigns no larger tree of
//!   log `n`-1.
//! - **Limits.** By host: how many new hosts under one registered domain
//!   it enrols, and how fast; and checkpoints of one log no more often
//!   than every 10 seconds.
//! - **Cosignatures** are ML-DSA-44 with the time the witness made them,
//!   never zero.
//!
//! Where the public key of log 1 comes from is not in the requests: an
//! `add-checkpoint` request carries the signed checkpoint but not the key,
//! and ML-DSA signatures do not give it. [`WitnessCore::enrol`] therefore
//! takes it from the caller, which must have it from somewhere it trusts
//! as much as the log's host (for example the host's `INFO log-key=`, SPEC
//! 8.5, over TLS). Log `n` > 1 needs no such key: it comes from the
//! hand-off. (SPEC 4.10 is silent; a choice to confirm.)

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt;

use thiserror::Error;

use crate::addcheckpoint::AddCheckpoint;
use crate::checkpoint::LogOrigin;
use crate::cosig::{CosignatureVerifier, Cosigner};
use crate::entry::LogEntry;
use crate::handoff::HandoffRequest;
use crate::merkle::{Hash, empty_root, leaf_hash};
use crate::note::{NoteSignature, VerifierKey};
use crate::proof::{verify_consistency, verify_inclusion};
use crate::witness::{LogKey, verify_log_signature};

/// How often a witness cosigns checkpoints of one log, at most: once every
/// this many seconds (SPEC 4.10).
pub const MIN_INTERVAL: u64 = 10;

/// What a witness knows of one log it has enrolled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogState {
    /// The log's key, fixed at enrolment for ever.
    pub key: LogKey,
    /// The size of the newest checkpoint the witness cosigned.
    pub size: u64,
    /// Its root.
    pub root: Hash,
    /// The registered domain of the log's host, as the witness's
    /// [`WitnessConfig::registered_domain`] gave it at enrolment.
    pub domain: String,
    /// When the witness enrolled the log, in seconds since 1970.
    pub enrolled_at: u64,
    /// When the witness last cosigned a checkpoint of the log; 0 if never.
    pub last_cosigned: u64,
    /// The hand-off the witness has taken from this log, if any.
    pub handoff: Option<Handoff>,
}

impl LogState {
    /// The log's origin.
    pub fn origin(&self) -> &LogOrigin {
        self.key.origin()
    }
}

/// A hand-off a witness has taken: the entry's index, which is the last
/// entry of the log, and the log that takes over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handoff {
    /// The index of the hand-off entry.
    pub index: u64,
    /// The next log.
    pub next: LogKey,
}

/// Where a witness keeps what it knows of the logs it enrolled. A store
/// never forgets a log, and never changes a log's key: that is what makes
/// "one key per origin ever" and "never enrolled a log of `<host>`" hold
/// (SPEC 4.10).
///
/// Each request reads what it needs and writes at most one log's state,
/// once every check has passed. Callers that serve requests in parallel
/// should handle one request at a time per witness, or run each in a
/// transaction.
pub trait WitnessStore {
    /// Why the store failed.
    type Error;

    /// The state of the log with this origin, if the witness enrolled it.
    fn log(&mut self, origin: &LogOrigin) -> Result<Option<LogState>, Self::Error>;

    /// Stores a log's state, under its origin.
    fn put_log(&mut self, state: &LogState) -> Result<(), Self::Error>;

    /// How many hosts under `domain` the witness has enrolled a first log
    /// of, at or after `since`.
    fn hosts_enrolled_since(&mut self, domain: &str, since: u64) -> Result<u64, Self::Error>;
}

/// A [`WitnessStore`] in memory.
#[derive(Clone, Debug, Default)]
pub struct MemoryWitnessStore {
    logs: BTreeMap<LogOrigin, LogState>,
}

impl MemoryWitnessStore {
    /// An empty store.
    pub fn new() -> MemoryWitnessStore {
        MemoryWitnessStore::default()
    }

    /// Every log, by origin.
    pub fn logs(&self) -> &BTreeMap<LogOrigin, LogState> {
        &self.logs
    }
}

impl WitnessStore for MemoryWitnessStore {
    type Error = Infallible;

    fn log(&mut self, origin: &LogOrigin) -> Result<Option<LogState>, Infallible> {
        Ok(self.logs.get(origin).cloned())
    }

    fn put_log(&mut self, state: &LogState) -> Result<(), Infallible> {
        self.logs.insert(state.origin().clone(), state.clone());
        Ok(())
    }

    fn hosts_enrolled_since(&mut self, domain: &str, since: u64) -> Result<u64, Infallible> {
        Ok(self
            .logs
            .values()
            .filter(|l| l.origin().number() == 1 && l.domain == domain && l.enrolled_at >= since)
            .count() as u64)
    }
}

/// A limit on how many new hosts under one registered domain a witness
/// enrols in a window of time (SPEC 4.10, "Limits").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostLimit {
    /// The most new hosts per registered domain in a window.
    pub max: u64,
    /// The window, in seconds.
    pub window: u64,
}

/// A witness's limits (SPEC 4.10).
#[derive(Clone, Copy)]
pub struct WitnessConfig {
    /// The fewest seconds between two cosignatures of one log; checkpoints
    /// sooner get 429. SPEC 4.10 allows 10.
    pub min_interval: u64,
    /// The limit on new hosts per registered domain, if any.
    pub new_hosts: Option<HostLimit>,
    /// The registered domain of a host, for [`HostLimit`]. The default
    /// takes the last two labels, which is wrong under public suffixes
    /// such as `co.uk`; a witness that limits by domain should use the
    /// Public Suffix List.
    pub registered_domain: fn(&str) -> String,
}

impl Default for WitnessConfig {
    /// Checkpoints at most every 10 seconds, and at most 10 new hosts per
    /// registered domain a day. (The numbers are SPEC 4.10's "MAY"s, and
    /// the daily 10 is a choice to confirm.)
    fn default() -> WitnessConfig {
        WitnessConfig {
            min_interval: MIN_INTERVAL,
            new_hosts: Some(HostLimit {
                max: 10,
                window: 24 * 60 * 60,
            }),
            registered_domain: last_two_labels,
        }
    }
}

impl fmt::Debug for WitnessConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WitnessConfig")
            .field("min_interval", &self.min_interval)
            .field("new_hosts", &self.new_hosts)
            .finish_non_exhaustive()
    }
}

/// The last two labels of a host name, or the whole name if it has fewer.
pub fn last_two_labels(host: &str) -> String {
    let mut dots = host.rmatch_indices('.');
    match (dots.next(), dots.next()) {
        (Some(_), Some((i, _))) => host[i + 1..].to_owned(),
        _ => host.to_owned(),
    }
}

/// Why a witness refused a request, with the HTTP status to answer with.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WitnessRefusal {
    /// 400: the request is malformed, or its old size is larger than the
    /// checkpoint's.
    #[error("400 bad request")]
    BadRequest,
    /// 403: the checkpoint is not signed by the log's key as SPEC 4.5
    /// says, the log may not enrol (SPEC 4.10), or the log has handed off
    /// and the checkpoint is larger than the hand-off's.
    #[error("403 forbidden")]
    Forbidden,
    /// 404: the witness does not know the log, and the request does not
    /// enrol it.
    #[error("404 unknown log")]
    UnknownLog,
    /// 409: the old size is not the size the witness last cosigned, or a
    /// hand-off's checkpoint is not the newest the witness cosigned; the
    /// witness's size is given.
    #[error("409 conflict, the witness is at {0}")]
    Conflict(u64),
    /// 422: the proof does not verify, the checkpoint is not consistent
    /// with what the witness cosigned, or the hand-off entry is wrong.
    #[error("422 unprocessable")]
    Unprocessable,
    /// 429: a limit of SPEC 4.10: too soon after the last checkpoint of the
    /// log, or too many new hosts under its registered domain. (SPEC 4.10
    /// names no status; a choice to confirm.)
    #[error("429 too many requests")]
    TooManyRequests,
}

impl WitnessRefusal {
    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        match self {
            WitnessRefusal::BadRequest => 400,
            WitnessRefusal::Forbidden => 403,
            WitnessRefusal::UnknownLog => 404,
            WitnessRefusal::Conflict(_) => 409,
            WitnessRefusal::Unprocessable => 422,
            WitnessRefusal::TooManyRequests => 429,
        }
    }
}

/// Why a witness did not answer a request with a cosignature.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError<E> {
    /// It refused the request.
    #[error(transparent)]
    Refused(WitnessRefusal),
    /// Its store failed: a 500.
    #[error("witness store: {0}")]
    Store(E),
    /// Its clock says 0, and a cosignature's timestamp is never zero.
    #[error("the witness's clock is not set")]
    Clock,
}

impl<E> CoreError<E> {
    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        match self {
            CoreError::Refused(r) => r.status(),
            CoreError::Store(_) | CoreError::Clock => 500,
        }
    }

    /// The refusal, if it was one.
    pub fn refusal(&self) -> Option<WitnessRefusal> {
        match self {
            CoreError::Refused(r) => Some(*r),
            _ => None,
        }
    }
}

impl<E> From<WitnessRefusal> for CoreError<E> {
    fn from(r: WitnessRefusal) -> CoreError<E> {
        CoreError::Refused(r)
    }
}

/// A witness: its ML-DSA-44 key, its store and its limits.
#[derive(Debug)]
pub struct WitnessCore<S> {
    cosigner: Cosigner,
    store: S,
    config: WitnessConfig,
}

impl<S: WitnessStore> WitnessCore<S> {
    /// A witness that cosigns with `cosigner`.
    pub fn new(cosigner: Cosigner, store: S, config: WitnessConfig) -> WitnessCore<S> {
        WitnessCore {
            cosigner,
            store,
            config,
        }
    }

    /// The verifier for the witness's cosignatures.
    pub fn verifier(&self) -> CosignatureVerifier {
        self.cosigner.verifier()
    }

    /// The witness's verifier key, which it publishes (SPEC 4.10).
    pub fn vkey(&self) -> VerifierKey {
        self.cosigner.vkey()
    }

    /// The store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The store, to change.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// The limits.
    pub fn config(&self) -> &WitnessConfig {
        &self.config
    }

    /// Handles an `add-checkpoint` request at `now`, in seconds since 1970,
    /// and returns the cosignature to answer with. A log `n` > 1 that the
    /// witness has taken a hand-off to enrols this way; log 1 of a host
    /// enrols with [`enrol`](Self::enrol), which supplies its key.
    ///
    /// `rnd` is ML-DSA.Sign's randomness: 32 fresh random bytes.
    pub fn add_checkpoint(
        &mut self,
        req: &AddCheckpoint,
        now: u64,
        rnd: [u8; 32],
    ) -> Result<Vec<NoteSignature>, CoreError<S::Error>> {
        self.cosign(req, None, now, rnd)
    }

    /// Handles an `add-checkpoint` request that may enrol a log whose key
    /// the caller has from elsewhere (see the module's documentation). For
    /// a log the witness knows, or one it took a hand-off to, the key must
    /// be the one it holds, or the request gets 403.
    pub fn enrol(
        &mut self,
        key: &LogKey,
        req: &AddCheckpoint,
        now: u64,
        rnd: [u8; 32],
    ) -> Result<Vec<NoteSignature>, CoreError<S::Error>> {
        self.cosign(req, Some(key), now, rnd)
    }

    /// Handles an `add-checkpoint` request body, and returns the response
    /// body: the cosignature's line. `key` is as for [`enrol`](Self::enrol).
    pub fn add_checkpoint_body(
        &mut self,
        body: &[u8],
        key: Option<&LogKey>,
        now: u64,
        rnd: [u8; 32],
    ) -> Result<String, CoreError<S::Error>> {
        let req = AddCheckpoint::parse(body).map_err(|_| WitnessRefusal::BadRequest)?;
        let sigs = self.cosign(&req, key, now, rnd)?;
        Ok(sigs.iter().map(NoteSignature::to_line).collect())
    }

    fn cosign(
        &mut self,
        req: &AddCheckpoint,
        offered: Option<&LogKey>,
        now: u64,
        rnd: [u8; 32],
    ) -> Result<Vec<NoteSignature>, CoreError<S::Error>> {
        if now == 0 {
            return Err(CoreError::Clock);
        }
        let cp = req.checkpoint.checkpoint();
        let origin: LogOrigin = cp.origin().parse().map_err(|_| WitnessRefusal::Forbidden)?;
        let (mut state, enrolling) = match self.store.log(&origin).map_err(CoreError::Store)? {
            Some(state) => {
                // One key per origin, ever.
                if offered.is_some_and(|k| *k != state.key) {
                    return Err(WitnessRefusal::Forbidden.into());
                }
                (state, false)
            }
            None => {
                if req.old_size != 0 {
                    return Err(WitnessRefusal::UnknownLog.into());
                }
                let key = self.enrolment_key(&origin, offered)?;
                let domain = (self.config.registered_domain)(origin.host());
                let state = LogState {
                    key,
                    size: 0,
                    root: empty_root(),
                    domain,
                    enrolled_at: now,
                    last_cosigned: 0,
                    handoff: None,
                };
                (state, true)
            }
        };

        // Signed by the log's key, as SPEC 4.5 says.
        let ts = verify_log_signature(state.key.verifier(), &req.checkpoint)
            .map_err(|_| WitnessRefusal::Forbidden)?;
        if ts == 0 {
            return Err(WitnessRefusal::Forbidden.into());
        }
        // Devices reject checkpoints with extension lines, which no
        // ML-DSA-44 signature covers, so a witness does not cosign them.
        // (SPEC 4.5 is silent; a choice to confirm.)
        if !cp.extensions().is_empty() {
            return Err(WitnessRefusal::Forbidden.into());
        }
        if req.old_size > cp.size() {
            return Err(WitnessRefusal::BadRequest.into());
        }
        if req.old_size != state.size {
            return Err(WitnessRefusal::Conflict(state.size).into());
        }
        if cp.size() == 0 && *cp.root() != empty_root() {
            return Err(WitnessRefusal::Unprocessable.into());
        }
        // After a hand-off, no larger tree.
        if state.handoff.is_some() && cp.size() > state.size {
            return Err(WitnessRefusal::Forbidden.into());
        }
        // Limits, checked only once the log's signature has verified, so
        // that nobody else can use up a log's allowance.
        if state.last_cosigned != 0
            && now < state.last_cosigned.saturating_add(self.config.min_interval)
        {
            return Err(WitnessRefusal::TooManyRequests.into());
        }
        if enrolling
            && origin.number() == 1
            && let Some(limit) = self.config.new_hosts
        {
            let since = now.saturating_sub(limit.window);
            let n = self
                .store
                .hosts_enrolled_since(&state.domain, since)
                .map_err(CoreError::Store)?;
            if n >= limit.max {
                return Err(WitnessRefusal::TooManyRequests.into());
            }
        }
        verify_consistency(state.size, &state.root, cp.size(), cp.root(), &req.proof)
            .map_err(|_| WitnessRefusal::Unprocessable)?;

        state.size = cp.size();
        state.root = *cp.root();
        state.last_cosigned = now;
        self.store.put_log(&state).map_err(CoreError::Store)?;
        Ok(vec![self.cosigner.cosign(cp, now, rnd)])
    }

    /// The key a log not yet enrolled may enrol with, or why it may not.
    fn enrolment_key(
        &mut self,
        origin: &LogOrigin,
        offered: Option<&LogKey>,
    ) -> Result<LogKey, CoreError<S::Error>> {
        let Some(previous) = origin.previous() else {
            // Log 1: this host has never enrolled a log, since every later
            // log needs the one before it. Its key must come from the
            // caller.
            let key = offered.ok_or(WitnessRefusal::UnknownLog)?;
            if key.origin() != origin {
                return Err(WitnessRefusal::Forbidden.into());
            }
            return Ok(key.clone());
        };
        // Log n > 1: only with a hand-off from log n-1 to this origin and
        // key.
        let prev = self
            .store
            .log(&previous)
            .map_err(CoreError::Store)?
            .ok_or(WitnessRefusal::Forbidden)?;
        let handoff = prev.handoff.ok_or(WitnessRefusal::Forbidden)?;
        if handoff.next.origin() != origin || offered.is_some_and(|k| *k != handoff.next) {
            return Err(WitnessRefusal::Forbidden.into());
        }
        Ok(handoff.next)
    }

    /// Handles a hand-off request, `POST <prefix>/risala/handoff` (SPEC
    /// 4.10). It is accepted, with 200 and an empty body, if:
    ///
    /// - the checkpoint is the newest one of its log that the witness
    ///   cosigned (otherwise 409, with the witness's size);
    /// - the entry is a hand-off entry naming the host's next log, it is
    ///   the checkpoint's last entry, and its inclusion proof verifies
    ///   (otherwise 422).
    ///
    /// Showing the same hand-off again is accepted again.
    pub fn handoff(&mut self, req: &HandoffRequest) -> Result<(), CoreError<S::Error>> {
        let cp = req.checkpoint.checkpoint();
        let origin: LogOrigin = cp.origin().parse().map_err(|_| WitnessRefusal::Forbidden)?;
        let mut state = self
            .store
            .log(&origin)
            .map_err(CoreError::Store)?
            .ok_or(WitnessRefusal::UnknownLog)?;
        let ts = verify_log_signature(state.key.verifier(), &req.checkpoint)
            .map_err(|_| WitnessRefusal::Forbidden)?;
        if ts == 0 {
            return Err(WitnessRefusal::Forbidden.into());
        }
        if cp.size() != state.size || *cp.root() != state.root {
            return Err(WitnessRefusal::Conflict(state.size).into());
        }
        if req.index.checked_add(1) != Some(cp.size()) {
            return Err(WitnessRefusal::Unprocessable.into());
        }
        let next = match LogEntry::decode(&req.entry) {
            Ok(LogEntry::Handoff(next)) => next,
            _ => return Err(WitnessRefusal::Unprocessable.into()),
        };
        if Some(next.origin()) != origin.next().as_ref() {
            return Err(WitnessRefusal::Unprocessable.into());
        }
        verify_inclusion(
            &leaf_hash(&req.entry),
            req.index,
            cp.size(),
            &req.proof,
            cp.root(),
        )
        .map_err(|_| WitnessRefusal::Unprocessable)?;
        let handoff = Handoff {
            index: req.index,
            next,
        };
        if let Some(taken) = &state.handoff {
            // The log's tree has not grown since, so this is the same entry.
            return if *taken == handoff {
                Ok(())
            } else {
                Err(WitnessRefusal::Forbidden.into())
            };
        }
        // One key per origin, ever.
        if let Some(existing) = self
            .store
            .log(handoff.next.origin())
            .map_err(CoreError::Store)?
            && existing.key != handoff.next
        {
            return Err(WitnessRefusal::Forbidden.into());
        }
        state.handoff = Some(handoff);
        self.store.put_log(&state).map_err(CoreError::Store)
    }

    /// Handles a hand-off request body.
    pub fn handoff_body(&mut self, body: &[u8]) -> Result<(), CoreError<S::Error>> {
        let req = HandoffRequest::parse(body).map_err(|_| WitnessRefusal::BadRequest)?;
        self.handoff(&req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_domains() {
        assert_eq!(last_two_labels("chat.example.org"), "example.org");
        assert_eq!(last_two_labels("a.b.chat.example.org"), "example.org");
        assert_eq!(last_two_labels("example.org"), "example.org");
        assert_eq!(last_two_labels("localhost"), "localhost");
    }

    #[test]
    fn statuses() {
        let e: CoreError<Infallible> = WitnessRefusal::TooManyRequests.into();
        assert_eq!(e.status(), 429);
        assert_eq!(e.refusal(), Some(WitnessRefusal::TooManyRequests));
        assert_eq!(CoreError::<Infallible>::Clock.status(), 500);
        assert_eq!(WitnessRefusal::Conflict(3).status(), 409);
    }
}
