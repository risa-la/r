//! The witness policy (SPEC 4.5, 4.10): which checkpoints a device treats
//! as witnessed, and which are fresh.
//!
//! A checkpoint is witnessed when its log's signature verifies and at
//! least k of the device's n witnesses have cosigned it, where k is more
//! than half of n. Both are ML-DSA-44 checkpoint cosignatures (type
//! `0x06`) with a timestamp that is not zero. Signatures of any other
//! type, such as Ed25519, from keys the device does not know, and with a
//! zero timestamp, are ignored, so they never count towards k.
//!
//! A witnessed checkpoint is **fresh** when k of the cosignatures that
//! count are less than 24 hours old (SPEC 4.5, "Freshness"). Logs get a
//! new witnessed checkpoint at least daily, so a device whose newest
//! checkpoint of a log is not fresh does not count an identity's view as
//! refreshed (SPEC 4.10). It still accepts records that a witnessed
//! checkpoint includes: accepting needs a witnessed checkpoint, not a
//! fresh one (SPEC 4.5).

use std::collections::BTreeSet;

use thiserror::Error;

use crate::checkpoint::{CheckpointError, LogOrigin, SignedCheckpoint};
use crate::cosig::{CosigError, CosignatureVerifier};
use crate::merkle::empty_root;
use crate::note::VerifierKey;

/// How far in the future a timestamp may be, in seconds, before a device
/// ignores the signature: ten minutes, the clock difference SPEC 12.9
/// allows for messages. (SPEC 4.5 is silent; a choice to confirm.)
pub const MAX_CLOCK_SKEW: u64 = 600;

/// The age, in seconds, below which k cosignatures must be for a
/// checkpoint to be fresh (SPEC 4.5, "Freshness" and "Watching your own
/// records", 4.10).
pub const FRESH_MAX_AGE: u64 = 24 * 60 * 60;

/// A key log's key: a type `0x06` verifier key whose name is the log's
/// origin, `<host>/risala-log/<n>` (SPEC 4.4, 4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogKey {
    origin: LogOrigin,
    verifier: CosignatureVerifier,
}

impl LogKey {
    /// The log key from the `<vkey>` of a key file's `log` line.
    pub fn from_vkey(vkey: &VerifierKey) -> Result<LogKey, PolicyError> {
        let verifier = CosignatureVerifier::from_vkey(vkey)?;
        LogKey::new(verifier)
    }

    /// Parses the `<vkey>` of a key file's `log` line.
    pub fn from_vkey_str(vkey: &str) -> Result<LogKey, PolicyError> {
        LogKey::new(CosignatureVerifier::from_vkey_str(vkey)?)
    }

    /// The log key for this verifier, whose name must be a log origin.
    pub fn new(verifier: CosignatureVerifier) -> Result<LogKey, PolicyError> {
        let origin = verifier
            .name()
            .parse()
            .map_err(|_| PolicyError::NotALogOrigin)?;
        Ok(LogKey { origin, verifier })
    }

    /// The log's origin.
    pub fn origin(&self) -> &LogOrigin {
        &self.origin
    }

    /// The verifier for the log's signatures.
    pub fn verifier(&self) -> &CosignatureVerifier {
        &self.verifier
    }
}

/// Why a policy or a key is not usable.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// k is not more than half the number of witnesses, or is larger
    /// than it (SPEC 4.5).
    #[error("k must be more than half the number of witnesses, and at most all of them")]
    BadThreshold,
    /// Two witnesses share a name or a public key, so one witness could
    /// count twice.
    #[error("two witnesses share a name or a key")]
    DuplicateWitness,
    /// A log key's name is not `<host>/risala-log/<n>`.
    #[error("the log key's name is not a key log origin")]
    NotALogOrigin,
    /// A key is not an ML-DSA-44 cosignature key.
    #[error(transparent)]
    Key(#[from] CosigError),
}

/// Why a checkpoint is not witnessed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WitnessError {
    /// It is not a signed checkpoint.
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    /// Its origin is not the log's.
    #[error("the checkpoint is for another log")]
    WrongOrigin,
    /// It has extension lines, which no ML-DSA-44 signature covers. (SPEC
    /// 4.5 is silent; [TLOG-CHECKPOINT] says they SHOULD be empty, and
    /// nothing a device could trust them for is signed. A choice to
    /// confirm.)
    #[error("the checkpoint has extension lines")]
    ExtensionLines,
    /// It is of the empty tree, but its root is not the empty tree's,
    /// which [TLOG-WITNESS] has witnesses refuse.
    #[error("an empty tree with another root")]
    EmptyTreeRoot,
    /// Two signature lines have the same key name and id, which
    /// [TLOG-CHECKPOINT] forbids.
    #[error("two signatures from one key")]
    DuplicateSignature,
    /// The log's own signature does not verify. (A witness's cosignature
    /// that does not verify only does not count, SPEC 4.5.)
    #[error("the signature of {0} does not verify")]
    BadSignature(String),
    /// The log has not signed it.
    #[error("the log has not signed the checkpoint")]
    NoLogSignature,
    /// The log's signature is dated in the future.
    #[error("the log's signature is dated in the future")]
    FutureLogSignature,
    /// The log's signature has a zero timestamp, which SPEC 4.5 forbids.
    #[error("the log's signature has a zero timestamp")]
    ZeroLogTimestamp,
    /// Fewer than k witnesses of the policy have cosigned it at all,
    /// whatever the age of their cosignatures. If the device has never
    /// seen a witnessed checkpoint of the log, its witness list does not
    /// fit the log (see [`WitnessError::is_witness_list_problem`]).
    #[error("{have} of {need} witnesses have cosigned")]
    NotEnoughWitnesses {
        /// The witnesses whose cosignatures counted.
        have: usize,
        /// k.
        need: usize,
    },
    /// k witnesses have cosigned it, but fewer than k of them in the last
    /// 24 hours: the log or its witnesses are not keeping up, and the
    /// log's new records stay pending (SPEC 4.10).
    #[error("{fresh} of {need} cosignatures are less than 24 hours old")]
    NotFresh {
        /// The cosignatures less than 24 hours old.
        fresh: usize,
        /// k.
        need: usize,
    },
}

impl WitnessError {
    /// Whether this error, for a log of which the device has no witnessed
    /// checkpoint at all, means that the device's witness list does not
    /// fit the log: fewer than k of its witnesses cosign the log even in
    /// an old checkpoint. The device then shows the user a configuration
    /// problem rather than showing the log's records as pending (SPEC 4.5,
    /// "Witness policy").
    ///
    /// `seen_witnessed` says whether the device holds a witnessed
    /// checkpoint of the log already (a [`LogView`](crate::client::LogView)
    /// for it). If it does, the list once fitted, and the log or its
    /// witnesses are only behind.
    pub fn is_witness_list_problem(&self, seen_witnessed: bool) -> bool {
        !seen_witnessed && matches!(self, WitnessError::NotEnoughWitnesses { .. })
    }
}

/// What a device knows of the time when it checks a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Freshness {
    /// The time now, in seconds since 1970.
    pub now: u64,
    /// If set, at least k counted cosignatures must be younger than this,
    /// in seconds, or the checkpoint is not fresh.
    pub max_age: Option<u64>,
    /// How far in the future a timestamp may be.
    pub max_future: u64,
}

impl Freshness {
    /// Checks at `now`, with no limit on age: whether a checkpoint is
    /// witnessed (SPEC 4.5, "Accepting a record", step 3, which may use an
    /// older checkpoint, consistent with the newest).
    pub fn at(now: u64) -> Freshness {
        Freshness {
            now,
            max_age: None,
            max_future: MAX_CLOCK_SKEW,
        }
    }

    /// Checks at `now` that a checkpoint is witnessed and fresh: k of its
    /// cosignatures less than 24 hours old. For the newest checkpoint a
    /// device fetches when it refreshes an identity, or watches its own
    /// (SPEC 4.5, "Freshness" and "Watching your own records").
    pub fn fresh(now: u64) -> Freshness {
        Freshness {
            now,
            max_age: Some(FRESH_MAX_AGE),
            max_future: MAX_CLOCK_SKEW,
        }
    }

    /// No checks of time at all: for checking evidence after the fact.
    pub fn any() -> Freshness {
        Freshness {
            now: u64::MAX,
            max_age: None,
            max_future: u64::MAX,
        }
    }

    fn not_future(&self, ts: u64) -> bool {
        ts <= self.now.saturating_add(self.max_future)
    }

    /// Whether a cosignature counts at all. One with timestamp zero says
    /// nothing about being the latest checkpoint [TLOG-COSIGNATURE], and
    /// SPEC 4.5 has clients ignore it.
    fn counts(&self, ts: u64) -> bool {
        ts != 0 && self.not_future(ts)
    }

    fn is_fresh(&self, ts: u64) -> bool {
        self.max_age.is_none_or(|age| is_younger(self.now, ts, age))
    }
}

/// A device's witnesses and k (SPEC 4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessPolicy {
    witnesses: Vec<CosignatureVerifier>,
    k: usize,
}

impl WitnessPolicy {
    /// A policy needing `k` of these witnesses, where k is more than half
    /// their number (SPEC 4.5): with each witness enrolling one key per
    /// origin ever (SPEC 4.10), two keys for one origin cannot both get k
    /// cosignatures from one list. Each witness may appear once, by name
    /// and by key.
    pub fn new(
        witnesses: Vec<CosignatureVerifier>,
        k: usize,
    ) -> Result<WitnessPolicy, PolicyError> {
        if k > witnesses.len() || 2 * k <= witnesses.len() {
            return Err(PolicyError::BadThreshold);
        }
        let names: BTreeSet<&str> = witnesses.iter().map(|w| w.name()).collect();
        let keys: BTreeSet<&[u8]> = witnesses.iter().map(|w| &w.public_key()[..]).collect();
        if names.len() != witnesses.len() || keys.len() != witnesses.len() {
            return Err(PolicyError::DuplicateWitness);
        }
        Ok(WitnessPolicy { witnesses, k })
    }

    /// A policy from witnesses' verifier keys, which must all be of type
    /// `0x06`.
    pub fn from_vkeys<S: AsRef<str>>(vkeys: &[S], k: usize) -> Result<WitnessPolicy, PolicyError> {
        let witnesses = vkeys
            .iter()
            .map(|v| CosignatureVerifier::from_vkey_str(v.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        WitnessPolicy::new(witnesses, k)
    }

    /// The witnesses.
    pub fn witnesses(&self) -> &[CosignatureVerifier] {
        &self.witnesses
    }

    /// k.
    pub fn k(&self) -> usize {
        self.k
    }

    /// Parses and checks a signed checkpoint from `log`, as served at
    /// `<prefix>/checkpoint`.
    pub fn verify(
        &self,
        log: &LogKey,
        bytes: &[u8],
        freshness: Freshness,
    ) -> Result<WitnessedCheckpoint, WitnessError> {
        self.verify_signed(log, SignedCheckpoint::parse(bytes)?, freshness)
    }

    /// Checks a signed checkpoint from `log`:
    ///
    /// 1. its origin is the log's, and it has no extension lines;
    /// 2. no key name and id appear on two signature lines;
    /// 3. the log's signature verifies, and its timestamp is neither zero
    ///    nor in the future;
    /// 4. every signature from a witness of the policy verifies, and at
    ///    least k of them have a timestamp that is not zero and not in the
    ///    future ([`WitnessError::NotEnoughWitnesses`]);
    /// 5. if `freshness` sets a maximum age, at least k of those are
    ///    younger ([`WitnessError::NotFresh`]).
    ///
    /// Signatures from keys the policy does not hold are ignored. The log's
    /// own key never counts as a witness, even if the policy lists it.
    pub fn verify_signed(
        &self,
        log: &LogKey,
        signed: SignedCheckpoint,
        freshness: Freshness,
    ) -> Result<WitnessedCheckpoint, WitnessError> {
        let cp = signed.checkpoint();
        if cp.origin() != log.verifier.name() {
            return Err(WitnessError::WrongOrigin);
        }
        if !cp.extensions().is_empty() {
            return Err(WitnessError::ExtensionLines);
        }
        if cp.size() == 0 && *cp.root() != empty_root() {
            return Err(WitnessError::EmptyTreeRoot);
        }
        let sigs = signed.note().signatures();
        let mut seen = BTreeSet::new();
        if !sigs
            .iter()
            .all(|s| seen.insert((s.name.as_str(), s.key_id)))
        {
            return Err(WitnessError::DuplicateSignature);
        }

        let log_timestamp = verify_log_signature(&log.verifier, &signed)?;
        if log_timestamp == 0 {
            return Err(WitnessError::ZeroLogTimestamp);
        }
        if !freshness.not_future(log_timestamp) {
            return Err(WitnessError::FutureLogSignature);
        }

        let mut cosigned = Vec::new();
        for w in &self.witnesses {
            if w.name() == log.verifier.name() && w.key_id() == log.verifier.key_id() {
                continue;
            }
            for sig in sigs.iter().filter(|s| w.matches(s)) {
                // A cosignature that does not verify simply does not count
                // (SPEC 4.5): otherwise whoever can add a line to a
                // checkpoint in transit or in a cache could make a fully
                // witnessed one fail.
                let Ok(ts) = w.verify(cp, sig) else {
                    continue;
                };
                if freshness.counts(ts) {
                    cosigned.push((w.name().to_owned(), ts));
                }
            }
        }
        if cosigned.len() < self.k {
            return Err(WitnessError::NotEnoughWitnesses {
                have: cosigned.len(),
                need: self.k,
            });
        }
        let fresh = cosigned
            .iter()
            .filter(|(_, ts)| freshness.is_fresh(*ts))
            .count();
        if fresh < self.k {
            return Err(WitnessError::NotFresh {
                fresh,
                need: self.k,
            });
        }
        Ok(WitnessedCheckpoint {
            signed,
            log_timestamp,
            cosigned,
            k: self.k,
        })
    }
}

/// Verifies a log's own signature on a checkpoint, as a witness does
/// before it cosigns, and returns its timestamp: the newest, if the log's
/// key signed more than once, and zero if any of them is zero. Signatures
/// from other keys are ignored; every one from the log's key must verify.
pub fn verify_log_signature(
    log: &CosignatureVerifier,
    signed: &SignedCheckpoint,
) -> Result<u64, WitnessError> {
    let mut timestamp = None;
    for sig in signed.note().signatures().iter().filter(|s| log.matches(s)) {
        let ts = log
            .verify(signed.checkpoint(), sig)
            .map_err(|_| WitnessError::BadSignature(log.name().to_owned()))?;
        timestamp = Some(match timestamp {
            None => ts,
            Some(0) => 0,
            Some(_) if ts == 0 => 0,
            Some(t) => t.max(ts),
        });
    }
    timestamp.ok_or(WitnessError::NoLogSignature)
}

/// A checkpoint that a [`WitnessPolicy`] accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessedCheckpoint {
    signed: SignedCheckpoint,
    log_timestamp: u64,
    cosigned: Vec<(String, u64)>,
    k: usize,
}

impl WitnessedCheckpoint {
    /// The checkpoint.
    pub fn checkpoint(&self) -> &crate::checkpoint::Checkpoint {
        self.signed.checkpoint()
    }

    /// The signed checkpoint, with every signature it came with.
    pub fn signed(&self) -> &SignedCheckpoint {
        &self.signed
    }

    /// The timestamp of the log's signature.
    pub fn log_timestamp(&self) -> u64 {
        self.log_timestamp
    }

    /// The witnesses whose cosignatures counted, with their timestamps.
    pub fn witnesses(&self) -> &[(String, u64)] {
        &self.cosigned
    }

    /// The k of the policy it was checked under.
    pub fn k(&self) -> usize {
        self.k
    }

    /// When k witnesses had cosigned it: the k-th newest timestamp of the
    /// cosignatures that counted.
    pub fn witnessed_at(&self) -> u64 {
        let mut ts: Vec<u64> = self.cosigned.iter().map(|(_, t)| *t).collect();
        ts.sort_unstable_by(|a, b| b.cmp(a));
        ts.get(self.k.saturating_sub(1)).copied().unwrap_or(0)
    }

    /// Whether, at `now`, k of its cosignatures are less than 24 hours old
    /// (SPEC 4.5, "Freshness").
    pub fn is_fresh(&self, now: u64) -> bool {
        is_younger(now, self.witnessed_at(), FRESH_MAX_AGE)
    }

    /// The signed checkpoint's text, for keeping. Check it again with
    /// [`WitnessPolicy::verify`] and [`Freshness::any`] when reading it
    /// back.
    pub fn to_text(&self) -> String {
        self.signed.to_text()
    }
}

/// Whether a timestamp is less than `age` seconds before `now`. One in the
/// future, within the allowed skew, is younger.
fn is_younger(now: u64, ts: u64, age: u64) -> bool {
    now.saturating_sub(ts) < age
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::Checkpoint;
    use crate::cosig::Cosigner;
    use crate::merkle::leaf_hash;

    const ORIGIN: &str = "chat.example.org/risala-log/1";
    const NOW: u64 = 1_800_000_000;

    struct Setup {
        log: Cosigner,
        witnesses: Vec<Cosigner>,
        policy: WitnessPolicy,
        key: LogKey,
    }

    fn setup() -> Setup {
        let log = Cosigner::from_seed(ORIGIN, &[1; 32]).unwrap();
        let witnesses: Vec<Cosigner> = (0..3)
            .map(|i| Cosigner::from_seed(&format!("witness{i}.example/w"), &[10 + i; 32]).unwrap())
            .collect();
        let policy =
            WitnessPolicy::new(witnesses.iter().map(Cosigner::verifier).collect(), 2).unwrap();
        let key = LogKey::new(log.verifier()).unwrap();
        Setup {
            log,
            witnesses,
            policy,
            key,
        }
    }

    fn signed(s: &Setup, cp: &Checkpoint, witnesses: &[(usize, u64)]) -> SignedCheckpoint {
        let mut sc = SignedCheckpoint::unsigned(cp.clone());
        sc.push_signature(s.log.cosign(cp, NOW - 10, [0; 32]))
            .unwrap();
        for &(i, ts) in witnesses {
            sc.push_signature(s.witnesses[i].cosign(cp, ts, [0; 32]))
                .unwrap();
        }
        sc
    }

    fn cp() -> Checkpoint {
        Checkpoint::new(ORIGIN, 10, leaf_hash(b"r")).unwrap()
    }

    #[test]
    fn k_of_n() {
        let s = setup();
        let at = Freshness::at(NOW);
        let one = signed(&s, &cp(), &[(0, NOW)]);
        assert_eq!(
            s.policy.verify(&s.key, one.to_text().as_bytes(), at),
            Err(WitnessError::NotEnoughWitnesses { have: 1, need: 2 })
        );
        let two = signed(&s, &cp(), &[(0, NOW), (2, NOW - 5)]);
        let w = s
            .policy
            .verify(&s.key, two.to_text().as_bytes(), at)
            .unwrap();
        assert_eq!(w.checkpoint(), &cp());
        assert_eq!(w.log_timestamp(), NOW - 10);
        assert_eq!(w.witnesses().len(), 2);
        assert_eq!(w.to_text(), two.to_text());
    }

    #[test]
    fn ignores_unknown_keys_and_other_types() {
        let s = setup();
        let mut sc = signed(&s, &cp(), &[(0, NOW)]);
        // A stranger, and a line with a witness's name but another id, as
        // an Ed25519 cosignature from the same witness would have.
        let stranger = Cosigner::from_seed("stranger.example/w", &[99; 32]).unwrap();
        sc.push_signature(stranger.cosign(&cp(), NOW, [0; 32]))
            .unwrap();
        let mut ed = s.witnesses[1].cosign(&cp(), NOW, [0; 32]);
        ed.key_id = crate::note::key_id(&ed.name, 0x04, &[0; 32]);
        ed.signature.truncate(72);
        sc.push_signature(ed).unwrap();
        assert_eq!(
            s.policy
                .verify(&s.key, sc.to_text().as_bytes(), Freshness::at(NOW)),
            Err(WitnessError::NotEnoughWitnesses { have: 1, need: 2 })
        );
    }

    #[test]
    fn rejects_bad_known_signatures() {
        let s = setup();
        let at = Freshness::at(NOW);
        // A witness's cosignature that does not verify does not count, but
        // does not spoil the others (SPEC 4.5).
        let mut sc = signed(&s, &cp(), &[(0, NOW), (1, NOW)]);
        let mut bad = s.witnesses[2].cosign(&cp(), NOW, [0; 32]);
        bad.signature[100] ^= 1;
        sc.push_signature(bad).unwrap();
        let witnessed = s
            .policy
            .verify(&s.key, sc.to_text().as_bytes(), at)
            .unwrap();
        assert_eq!(witnessed.witnesses().len(), 2);
        let mut sc = signed(&s, &cp(), &[(0, NOW)]);
        let mut bad = s.witnesses[2].cosign(&cp(), NOW, [0; 32]);
        bad.signature[100] ^= 1;
        sc.push_signature(bad).unwrap();
        assert_eq!(
            s.policy.verify(&s.key, sc.to_text().as_bytes(), at),
            Err(WitnessError::NotEnoughWitnesses { have: 1, need: 2 })
        );

        // A bad log signature.
        let mut sc = SignedCheckpoint::unsigned(cp());
        let mut log_sig = s.log.cosign(&cp(), NOW, [0; 32]);
        log_sig.signature[50] ^= 1;
        sc.push_signature(log_sig).unwrap();
        assert_eq!(
            s.policy.verify_signed(&s.key, sc, at),
            Err(WitnessError::BadSignature(ORIGIN.into()))
        );

        // No log signature.
        let mut sc = SignedCheckpoint::unsigned(cp());
        for w in &s.witnesses {
            sc.push_signature(w.cosign(&cp(), NOW, [0; 32])).unwrap();
        }
        assert_eq!(
            s.policy.verify_signed(&s.key, sc, at),
            Err(WitnessError::NoLogSignature)
        );

        // The same witness twice.
        let mut sc = signed(&s, &cp(), &[(0, NOW)]);
        sc.push_signature(s.witnesses[0].cosign(&cp(), NOW - 1, [0; 32]))
            .unwrap();
        assert_eq!(
            s.policy.verify_signed(&s.key, sc, at),
            Err(WitnessError::DuplicateSignature)
        );
    }

    #[test]
    fn origin_and_extensions() {
        let s = setup();
        let at = Freshness::at(NOW);
        let other = Checkpoint::new("chat.example.org/risala-log/2", 10, leaf_hash(b"r")).unwrap();
        let sc = signed(&s, &other, &[(0, NOW), (1, NOW)]);
        assert_eq!(
            s.policy.verify_signed(&s.key, sc, at),
            Err(WitnessError::WrongOrigin)
        );

        let with_ext = Checkpoint::from_text(&format!("{}ext\n", cp().to_text())).unwrap();
        let sc = signed(&s, &with_ext, &[(0, NOW), (1, NOW)]);
        assert_eq!(
            s.policy.verify_signed(&s.key, sc, at),
            Err(WitnessError::ExtensionLines)
        );
    }

    #[test]
    fn freshness() {
        let s = setup();
        let day = FRESH_MAX_AGE;
        let sc = signed(&s, &cp(), &[(0, NOW - day + 1), (1, NOW - day)]);
        // Any age counts for being witnessed.
        let w = s
            .policy
            .verify_signed(&s.key, sc.clone(), Freshness::at(NOW))
            .unwrap();
        assert_eq!(w.k(), 2);
        // But k of them must be less than a day old to be fresh.
        assert!(!w.is_fresh(NOW));
        assert!(w.is_fresh(NOW - 1));
        assert_eq!(
            s.policy.verify_signed(&s.key, sc, Freshness::fresh(NOW)),
            Err(WitnessError::NotFresh { fresh: 1, need: 2 })
        );
        // Not being fresh is not a problem with the witness list; too few
        // witnesses at any age is, for a log the device has never seen
        // witnessed.
        assert!(!WitnessError::NotFresh { fresh: 1, need: 2 }.is_witness_list_problem(false));
        let few = WitnessError::NotEnoughWitnesses { have: 1, need: 2 };
        assert!(few.is_witness_list_problem(false));
        assert!(!few.is_witness_list_problem(true));
        // Three cosignatures, two of them fresh.
        let sc = signed(
            &s,
            &cp(),
            &[(0, NOW - 2 * day), (1, NOW - 60), (2, NOW - 120)],
        );
        let w = s
            .policy
            .verify_signed(&s.key, sc, Freshness::fresh(NOW))
            .unwrap();
        assert_eq!(w.witnesses().len(), 3);
        assert!(w.is_fresh(NOW));
        assert_eq!(w.witnessed_at(), NOW - 120);
        assert!(w.is_fresh(NOW + day - 121));
        assert!(!w.is_fresh(NOW + day - 120));
        // Ten minutes ahead is within the skew, more is not.
        let sc = signed(
            &s,
            &cp(),
            &[(0, NOW + MAX_CLOCK_SKEW), (1, NOW + MAX_CLOCK_SKEW + 1)],
        );
        assert_eq!(
            s.policy.verify_signed(&s.key, sc, Freshness::at(NOW)),
            Err(WitnessError::NotEnoughWitnesses { have: 1, need: 2 })
        );
        // A zero timestamp never counts.
        let sc = signed(&s, &cp(), &[(0, 0), (1, NOW)]);
        assert_eq!(
            s.policy.verify_signed(&s.key, sc.clone(), Freshness::any()),
            Err(WitnessError::NotEnoughWitnesses { have: 1, need: 2 })
        );
        // The log's own signature in the future.
        let mut sc = SignedCheckpoint::unsigned(cp());
        sc.push_signature(s.log.cosign(&cp(), NOW + MAX_CLOCK_SKEW + 1, [0; 32]))
            .unwrap();
        sc.push_signature(s.witnesses[0].cosign(&cp(), NOW, [0; 32]))
            .unwrap();
        sc.push_signature(s.witnesses[1].cosign(&cp(), NOW, [0; 32]))
            .unwrap();
        assert_eq!(
            s.policy
                .verify_signed(&s.key, sc.clone(), Freshness::at(NOW)),
            Err(WitnessError::FutureLogSignature)
        );
        assert!(s.policy.verify_signed(&s.key, sc, Freshness::any()).is_ok());
        // The log's own signature with a zero timestamp.
        let mut sc = SignedCheckpoint::unsigned(cp());
        sc.push_signature(s.log.cosign(&cp(), 0, [0; 32])).unwrap();
        sc.push_signature(s.witnesses[0].cosign(&cp(), NOW, [0; 32]))
            .unwrap();
        sc.push_signature(s.witnesses[1].cosign(&cp(), NOW, [0; 32]))
            .unwrap();
        assert_eq!(
            s.policy.verify_signed(&s.key, sc.clone(), Freshness::any()),
            Err(WitnessError::ZeroLogTimestamp)
        );
        // Even next to a signature from the log with a timestamp.
        sc.push_signature(s.log.cosign(&cp(), NOW, [0; 32]))
            .unwrap();
        assert_eq!(
            s.policy.verify_signed(&s.key, sc, Freshness::any()),
            Err(WitnessError::DuplicateSignature)
        );
    }

    #[test]
    fn empty_trees_have_the_empty_root() {
        let s = setup();
        let bogus = Checkpoint::new(ORIGIN, 0, leaf_hash(b"r")).unwrap();
        let sc = signed(&s, &bogus, &[(0, NOW), (1, NOW)]);
        assert_eq!(
            s.policy.verify_signed(&s.key, sc, Freshness::at(NOW)),
            Err(WitnessError::EmptyTreeRoot)
        );
        let empty = Checkpoint::new(ORIGIN, 0, empty_root()).unwrap();
        let sc = signed(&s, &empty, &[(0, NOW), (1, NOW)]);
        assert!(
            s.policy
                .verify_signed(&s.key, sc, Freshness::at(NOW))
                .is_ok()
        );
    }

    #[test]
    fn the_log_is_not_its_own_witness() {
        let s = setup();
        let mut ws: Vec<CosignatureVerifier> = vec![s.log.verifier()];
        ws.push(s.witnesses[0].verifier());
        let policy = WitnessPolicy::new(ws, 2).unwrap();
        let sc = signed(&s, &cp(), &[(0, NOW)]);
        assert_eq!(
            policy.verify_signed(&s.key, sc, Freshness::at(NOW)),
            Err(WitnessError::NotEnoughWitnesses { have: 1, need: 2 })
        );
    }

    #[test]
    fn policies() {
        let s = setup();
        let vs: Vec<CosignatureVerifier> = s.witnesses.iter().map(Cosigner::verifier).collect();
        assert_eq!(
            WitnessPolicy::new(vs.clone(), 0),
            Err(PolicyError::BadThreshold)
        );
        assert_eq!(
            WitnessPolicy::new(vs.clone(), 4),
            Err(PolicyError::BadThreshold)
        );
        // k must be more than half the list.
        assert_eq!(
            WitnessPolicy::new(vs.clone(), 1),
            Err(PolicyError::BadThreshold)
        );
        assert!(WitnessPolicy::new(vs.clone(), 3).is_ok());
        assert!(WitnessPolicy::new(vs[..1].to_vec(), 1).is_ok());
        assert_eq!(
            WitnessPolicy::new(vs[..2].to_vec(), 1),
            Err(PolicyError::BadThreshold)
        );
        let four: Vec<CosignatureVerifier> = (0..4u8)
            .map(|i| {
                Cosigner::from_seed(&format!("w{i}.example/w"), &[60 + i; 32])
                    .unwrap()
                    .verifier()
            })
            .collect();
        assert_eq!(
            WitnessPolicy::new(four.clone(), 2),
            Err(PolicyError::BadThreshold)
        );
        assert!(WitnessPolicy::new(four, 3).is_ok());
        let mut dup = vs.clone();
        dup.push(vs[0].clone());
        assert_eq!(
            WitnessPolicy::new(dup, 3),
            Err(PolicyError::DuplicateWitness)
        );
        // The same key under another name is one witness, not two.
        let alias = CosignatureVerifier::new("alias.example/w", vs[0].public_key()).unwrap();
        let mut dup = vs.clone();
        dup.push(alias);
        assert_eq!(
            WitnessPolicy::new(dup, 3),
            Err(PolicyError::DuplicateWitness)
        );

        let vkeys: Vec<String> = s.witnesses.iter().map(|w| w.vkey().to_string()).collect();
        assert_eq!(WitnessPolicy::from_vkeys(&vkeys, 2).unwrap(), s.policy);
        let mut with_ed = vkeys.clone();
        with_ed
            .push("example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k".into());
        assert_eq!(
            WitnessPolicy::from_vkeys(&with_ed, 2),
            Err(PolicyError::Key(CosigError::WrongKeyType))
        );

        // Log keys must be named for a log origin.
        assert_eq!(
            LogKey::new(s.witnesses[0].verifier()),
            Err(PolicyError::NotALogOrigin)
        );
        assert_eq!(
            LogKey::from_vkey_str(&s.log.vkey().to_string()).unwrap(),
            s.key
        );
    }
}
