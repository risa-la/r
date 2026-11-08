//! What a device does with a key log (SPEC 4.5): proving that a record is
//! in a witnessed checkpoint, keeping the newest witnessed checkpoint of
//! each log consistent with every other it sees, following hand-offs from
//! one of a host's logs to the next, and spotting forks.
//!
//! Every proof is computed from the log's tiles, then verified against a
//! witnessed checkpoint, so the tiles are never trusted. Work out the
//! tiles with [`inclusion_tiles`] or [`consistency_tiles`], fetch them into
//! a [`TileSet`](crate::tile::TileSet), and read them with its
//! [`reader`](crate::tile::TileSet::reader) for the larger tree.

use thiserror::Error;

use crate::checkpoint::{Checkpoint, SignedCheckpoint};
use crate::entry::{EntryError, LogEntry, RECORD_HASH_LEN, record_hash};
use crate::merkle::{Hash, leaf_hash};
use crate::proof::{
    Consistency, HashReader, ProofError, VerifyError, check_seeded_path, consistency_ranges,
    inclusion_proof, inclusion_ranges, nodes_for_ranges, seeded_consistency_path, verify_inclusion,
};
use crate::tile::{
    BundleError, TILE_WIDTH, TileId, TileKind, bundle_for_entry, decode_bundle, tiles_for_nodes,
};
use crate::witness::{Freshness, LogKey, WitnessError, WitnessPolicy, WitnessedCheckpoint};

/// The tiles needed to prove that entry `index` is in the tree of `size`
/// leaves. Empty if the index is not in the tree.
pub fn inclusion_tiles(index: u64, size: u64) -> Vec<TileId> {
    let Some(ranges) = inclusion_ranges(index, size) else {
        return Vec::new();
    };
    tiles_for_nodes(&nodes_for_ranges(&ranges), size)
}

/// The tiles needed to check the tree of `old` leaves against the tree of
/// `new` leaves, in either order: the consistency proof and, so that a
/// failed proof can be told from a fork, the hash of the first `old`
/// leaves.
pub fn consistency_tiles(old: u64, new: u64) -> Vec<TileId> {
    let (old, new) = (old.min(new), old.max(new));
    if old == 0 || old == new {
        return Vec::new();
    }
    let mut ranges = consistency_ranges(old, new).expect("old < new");
    ranges.push((0, old));
    tiles_for_nodes(&nodes_for_ranges(&ranges), new)
}

/// Why an entry could not be shown to be in a checkpoint.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InclusionError<E> {
    /// The proof could not be computed: the index is out of range or a
    /// tile is missing.
    #[error("computing the proof: {0}")]
    Proof(ProofError<E>),
    /// The proof does not verify: the entry is not at that index of the
    /// checkpoint's tree, or the log served wrong tiles.
    #[error("the proof does not verify: {0}")]
    Verify(VerifyError),
    /// An entry bundle is malformed, or does not hold as many entries as
    /// its width.
    #[error("bad entry bundle: {0}")]
    Bundle(BundleError),
}

/// Checks that `entry` is entry `index` of the checkpoint's tree, from a
/// proof computed from `reader` (SPEC 4.5, steps 2 and 3 of "Accepting a
/// record").
pub fn verify_entry<R: HashReader>(
    entry: &[u8],
    index: u64,
    checkpoint: &Checkpoint,
    reader: &mut R,
) -> Result<(), InclusionError<R::Error>> {
    verify_leaf(&leaf_hash(entry), index, checkpoint, reader)
}

fn verify_leaf<R: HashReader>(
    leaf: &Hash,
    index: u64,
    checkpoint: &Checkpoint,
    reader: &mut R,
) -> Result<(), InclusionError<R::Error>> {
    let proof = inclusion_proof(index, checkpoint.size(), reader).map_err(InclusionError::Proof)?;
    verify_inclusion(leaf, index, checkpoint.size(), &proof, checkpoint.root())
        .map_err(InclusionError::Verify)
}

/// Reads an entry bundle that a log served, and checks that each of its
/// entries is in the checkpoint's tree at its place: for reading the
/// entries added since the last check (SPEC 4.5, "Watching your own
/// records"). The bundle must be complete for the checkpoint: full, or as
/// wide as the checkpoint's tree has entries in it.
pub fn verify_bundle<R: HashReader>(
    bundle: &TileId,
    data: &[u8],
    checkpoint: &Checkpoint,
    reader: &mut R,
) -> Result<Vec<Vec<u8>>, InclusionError<R::Error>> {
    if bundle.kind() != TileKind::Entries {
        return Err(InclusionError::Bundle(BundleError::Malformed));
    }
    let entries = decode_bundle(data).map_err(InclusionError::Bundle)?;
    if entries.len() != usize::from(bundle.width()) {
        return Err(InclusionError::Bundle(BundleError::Malformed));
    }
    let first = bundle
        .index()
        .checked_mul(crate::tile::TILE_WIDTH)
        .ok_or(InclusionError::Proof(ProofError::OutOfRange))?;
    for (i, e) in entries.iter().enumerate() {
        verify_entry(e, first + i as u64, checkpoint, reader)?;
    }
    Ok(entries)
}

/// Reads entry `index` from the entry bundle that holds it in the
/// checkpoint's tree, as the log served it, and checks that it is in the
/// tree at that index: for reading a key file's `<index> <hash>` records
/// (SPEC 4.4), and the entries a uid's hint lists (SPEC 4.5). Fetch
/// [`bundle_for_entry`]`(index, checkpoint.size())` and the tiles of
/// [`inclusion_tiles`]`(index, checkpoint.size())`.
pub fn verify_bundle_entry<R: HashReader>(
    data: &[u8],
    index: u64,
    checkpoint: &Checkpoint,
    reader: &mut R,
) -> Result<Vec<u8>, InclusionError<R::Error>> {
    let bundle = bundle_for_entry(index, checkpoint.size())
        .ok_or(InclusionError::Proof(ProofError::OutOfRange))?;
    let mut entries = decode_bundle(data).map_err(InclusionError::Bundle)?;
    if entries.len() != usize::from(bundle.width()) {
        return Err(InclusionError::Bundle(BundleError::Malformed));
    }
    let entry = entries.swap_remove((index % TILE_WIDTH) as usize);
    verify_entry(&entry, index, checkpoint, reader)?;
    Ok(entry)
}

/// Evidence that a log has shown two trees that cannot both be true
/// (SPEC 4.5, "Forks"). Anyone holding the log's key and a witness policy
/// can check it with [`ForkEvidence::verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForkEvidence {
    /// Two witnessed checkpoints of one size with different roots.
    SameSize {
        /// One checkpoint.
        a: SignedCheckpoint,
        /// The other.
        b: SignedCheckpoint,
    },
    /// Two witnessed checkpoints, and hashes from the newer tree that lead
    /// to its root but show that its first `older.size()` leaves do not
    /// have the older root.
    Inconsistent {
        /// The smaller tree.
        older: SignedCheckpoint,
        /// The larger tree.
        newer: SignedCheckpoint,
        /// The consistency proof from the older size to the newer one, with
        /// the newer tree's hash of the older size's leaves in front when
        /// the older size is a power of two.
        path: Vec<Hash>,
    },
}

/// Why fork evidence does not hold up.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// A checkpoint in it is not witnessed under the policy.
    #[error(transparent)]
    NotWitnessed(#[from] WitnessError),
    /// The checkpoints do not show a fork.
    #[error("the checkpoints do not show a fork")]
    NoFork,
}

impl ForkEvidence {
    /// The log's two checkpoints.
    pub fn checkpoints(&self) -> (&SignedCheckpoint, &SignedCheckpoint) {
        match self {
            ForkEvidence::SameSize { a, b } => (a, b),
            ForkEvidence::Inconsistent { older, newer, .. } => (older, newer),
        }
    }

    /// Checks the evidence: both checkpoints are witnessed under `policy`,
    /// at any time, and they cannot both be true.
    pub fn verify(&self, log: &LogKey, policy: &WitnessPolicy) -> Result<(), EvidenceError> {
        let (a, b) = self.checkpoints();
        let a = policy.verify_signed(log, a.clone(), Freshness::any())?;
        let b = policy.verify_signed(log, b.clone(), Freshness::any())?;
        let (a, b) = (a.checkpoint(), b.checkpoint());
        let fork = match self {
            ForkEvidence::SameSize { .. } => a.size() == b.size() && a.root() != b.root(),
            ForkEvidence::Inconsistent { path, .. } => {
                0 < a.size()
                    && a.size() < b.size()
                    && check_seeded_path(a.size(), a.root(), b.size(), b.root(), path)
                        == Consistency::Inconsistent
            }
        };
        if fork {
            Ok(())
        } else {
            Err(EvidenceError::NoFork)
        }
    }
}

/// What checking a checkpoint against the newest one found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// It is larger and consistent, and is now the newest.
    Newer,
    /// It has the same tree as the newest. If k witnesses cosigned it
    /// later than the newest, it takes the newest's place.
    Same,
    /// It is smaller and consistent with the newest, which stays.
    Older,
}

/// Why a checkpoint could not be taken into a [`LogView`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ViewError<E> {
    /// It is for another log.
    #[error("the checkpoint is for another log")]
    WrongLog,
    /// It and the newest checkpoint are a fork (SPEC 4.5).
    #[error("the log has forked")]
    Fork(Box<ForkEvidence>),
    /// The log has handed off, and this checkpoint is larger than the tree
    /// that ends with the hand-off entry. The log appended after its
    /// hand-off, and k witnesses cosigned it, which they never do (SPEC
    /// 4.5, 4.10). The caller treats it as a fork of the log. (SPEC 4.5
    /// does not list it among forks; a choice to confirm.)
    #[error("the log grew after its hand-off")]
    AfterHandoff,
    /// The consistency proof could not be computed, for example because a
    /// tile is missing.
    #[error("computing the consistency proof: {0}")]
    Proof(ProofError<E>),
    /// The log's tiles gave a proof that leads to neither tree's root, so
    /// nothing is known yet. The tiles were wrong; try again later.
    #[error("the log's tiles do not match its checkpoint")]
    Unproven,
}

/// A device's view of one key log: the newest witnessed checkpoint it has
/// seen, which every other witnessed checkpoint of the log must be
/// consistent with (SPEC 4.5, step 4 of "Accepting a record"), and the
/// hand-off to the host's next log, once it has accepted one.
///
/// A log `n` > 1 is valid only with a hand-off from log `n`-1 (SPEC 4.5).
/// [`LogView::new`] does not check that: witnesses enrol log `n` only after
/// such a hand-off (SPEC 4.10), so a checkpoint of it witnessed under the
/// device's policy shows that k witnesses saw one. A device that followed
/// the hand-off itself gets the next log's key from [`accept_handoff`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogView {
    log: LogKey,
    newest: WitnessedCheckpoint,
    handoff: Option<(u64, LogKey)>,
}

impl LogView {
    /// A view that starts from a witnessed checkpoint of `log`.
    pub fn new(
        log: LogKey,
        first: WitnessedCheckpoint,
    ) -> Result<LogView, ViewError<std::convert::Infallible>> {
        LogView::restore(log, first, None)
    }

    /// A view as the device kept it: its newest witnessed checkpoint, and
    /// the hand-off it accepted, as an index and the next log's key.
    pub fn restore(
        log: LogKey,
        newest: WitnessedCheckpoint,
        handoff: Option<(u64, LogKey)>,
    ) -> Result<LogView, ViewError<std::convert::Infallible>> {
        if newest.checkpoint().origin() != log.verifier().name() {
            return Err(ViewError::WrongLog);
        }
        if let Some((index, next)) = &handoff
            && (index.checked_add(1) != Some(newest.checkpoint().size())
                || log.origin().next().as_ref() != Some(next.origin()))
        {
            return Err(ViewError::WrongLog);
        }
        Ok(LogView {
            log,
            newest,
            handoff,
        })
    }

    /// The hand-off the device accepted from this log: the index of the
    /// hand-off entry, and the key of the log that takes over.
    pub fn handoff(&self) -> Option<&(u64, LogKey)> {
        self.handoff.as_ref()
    }

    /// Whether the device may take new records of this log as fresh at
    /// `now`: its newest checkpoint has k cosignatures less than 24 hours
    /// old (SPEC 4.5, 4.10). A log that has handed off gets no more
    /// checkpoints, and its tree is final, so it always may; the freshness
    /// of the identity's view then rests on the log it handed off to.
    pub fn is_fresh(&self, now: u64) -> bool {
        self.handoff.is_some() || self.newest.is_fresh(now)
    }

    /// The log's key.
    pub fn log(&self) -> &LogKey {
        &self.log
    }

    /// The newest witnessed checkpoint seen.
    pub fn newest(&self) -> &WitnessedCheckpoint {
        &self.newest
    }

    /// The tiles [`check`](Self::check) needs for `other`.
    pub fn tiles_for(&self, other: &Checkpoint) -> Vec<TileId> {
        consistency_tiles(self.newest.checkpoint().size(), other.size())
    }

    /// The tiles [`accept_entry`] needs to prove entry `index` in `other`
    /// and check `other` against the newest checkpoint: those of the
    /// larger tree.
    pub fn tiles_for_entry(&self, other: &Checkpoint, index: u64) -> Vec<TileId> {
        let mine = self.newest.checkpoint().size();
        let size = mine.max(other.size());
        let mut ranges = inclusion_ranges(index, other.size()).unwrap_or_default();
        let (old, new) = (mine.min(other.size()), size);
        if 0 < old && old < new {
            ranges.extend(consistency_ranges(old, new).expect("old < new"));
            ranges.push((0, old));
        }
        tiles_for_nodes(&nodes_for_ranges(&ranges), size)
    }

    /// Checks another witnessed checkpoint of the log against the newest,
    /// and keeps it if it is newer and consistent. `reader` reads the
    /// larger of the two trees, from the tiles of
    /// [`tiles_for`](Self::tiles_for).
    ///
    /// A fork leaves the view as it was, and returns the evidence.
    pub fn check<R: HashReader>(
        &mut self,
        other: WitnessedCheckpoint,
        reader: &mut R,
    ) -> Result<Seen, ViewError<R::Error>> {
        if other.checkpoint().origin() != self.log.verifier().name() {
            return Err(ViewError::WrongLog);
        }
        let (mine, theirs) = (self.newest.checkpoint(), other.checkpoint());
        if self.handoff.is_some() && theirs.size() > mine.size() {
            return Err(ViewError::AfterHandoff);
        }
        if mine.size() == theirs.size() {
            if mine.root() == theirs.root() {
                // The same tree, perhaps cosigned again later, as logs do
                // daily when nothing is added: keep the copy witnessed
                // last, so that the view stays fresh.
                if other.witnessed_at() > self.newest.witnessed_at() {
                    self.newest = other;
                }
                return Ok(Seen::Same);
            }
            return Err(ViewError::Fork(Box::new(ForkEvidence::SameSize {
                a: self.newest.signed().clone(),
                b: other.signed().clone(),
            })));
        }
        let other_is_newer = theirs.size() > mine.size();
        let (older, newer) = if other_is_newer {
            (&self.newest, &other)
        } else {
            (&other, &self.newest)
        };
        let (o, n) = (older.checkpoint(), newer.checkpoint());
        if o.size() > 0 {
            let path =
                seeded_consistency_path(o.size(), n.size(), reader).map_err(ViewError::Proof)?;
            match check_seeded_path(o.size(), o.root(), n.size(), n.root(), &path) {
                Consistency::Consistent => {}
                Consistency::Unproven => return Err(ViewError::Unproven),
                Consistency::Inconsistent => {
                    return Err(ViewError::Fork(Box::new(ForkEvidence::Inconsistent {
                        older: older.signed().clone(),
                        newer: newer.signed().clone(),
                        path,
                    })));
                }
            }
        }
        if other_is_newer {
            self.newest = other;
            Ok(Seen::Newer)
        } else {
            Ok(Seen::Older)
        }
    }
}

/// Checks an entry against a key log, from tiles (SPEC 4.5, steps 2 to 4
/// of "Accepting a record"):
///
/// - `checkpoint` is the log's checkpoint, witnessed under the device's
///   policy;
/// - `entry` is at `index` of its tree, by a proof from `reader`;
/// - the checkpoint is consistent with the newest the device has seen,
///   which `view` keeps.
///
/// This checks neither what the entry holds nor freshness: use
/// [`accept_record`] for records and [`accept_handoff`] for hand-offs.
///
/// Fetch the tiles of [`LogView::tiles_for_entry`] into a
/// [`TileSet`](crate::tile::TileSet), and read them with a reader for the
/// larger of the two trees.
pub fn accept_entry<R: HashReader>(
    view: &mut LogView,
    checkpoint: WitnessedCheckpoint,
    entry: &[u8],
    index: u64,
    reader: &mut R,
) -> Result<Seen, AcceptError<R::Error>> {
    verify_entry(entry, index, checkpoint.checkpoint(), reader).map_err(AcceptError::Inclusion)?;
    view.check(checkpoint, reader).map_err(AcceptError::View)
}

/// Checks a record of a key file against its log, as a device does before
/// acting on it (SPEC 4.5, "Accepting a record", steps 2 to 4): the entry
/// at `index` is a record entry whose Record has the SHA-384 hash `hash`,
/// the key file's `<index> <hash>` line; and, as [`accept_entry`] checks,
/// it is in `checkpoint`'s tree, which is consistent with the newest the
/// device has seen.
///
/// Accepting a record needs a witnessed checkpoint, not a fresh one (SPEC
/// 4.5): freshness ([`LogView::is_fresh`]) matters for refreshing an
/// identity's view and for watching one's own records, not here. So a log
/// whose witnesses are slow for a day does not leave every record in it
/// pending, and every device removing its leaves (12.7).
///
/// Step 1 (the key file is valid and extends the device's head) and step 5
/// (the device accepted each hand-off between the log the chain names and
/// this one) are the caller's. On success, the entry's Record is returned.
pub fn accept_record<R: HashReader>(
    view: &mut LogView,
    checkpoint: WitnessedCheckpoint,
    entry: &[u8],
    index: u64,
    hash: &[u8; RECORD_HASH_LEN],
    reader: &mut R,
) -> Result<Vec<u8>, AcceptError<R::Error>> {
    let record = match LogEntry::decode(entry).map_err(AcceptError::Entry)? {
        LogEntry::Record(r) => r,
        LogEntry::Handoff(_) => return Err(AcceptError::NotARecord),
    };
    if record_hash(&record) != *hash {
        return Err(AcceptError::WrongRecord);
    }
    accept_entry(view, checkpoint, entry, index, reader)?;
    Ok(record)
}

/// Checks a hand-off from the view's log to the host's next one, as a
/// device does before it follows it (SPEC 4.5, "Hand-offs"): the entry at
/// `index` is a hand-off entry naming `<host>/risala-log/<n+1>`, it is the
/// last entry of `checkpoint`, a witnessed checkpoint of the log, it is in
/// that checkpoint's tree, and the checkpoint is consistent with the
/// newest the device has seen. Find `index` with the log's `risala/next`
/// hint ([`crate::hint::parse_next`]), and fetch the tiles of
/// [`LogView::tiles_for_entry`].
///
/// On success the view keeps the hand-off, takes no larger checkpoint of
/// the log from then on, and the next log's key is returned: the device
/// starts a view of it from a checkpoint witnessed under that key. Showing
/// the same hand-off again returns the same key.
pub fn accept_handoff<R: HashReader>(
    view: &mut LogView,
    checkpoint: WitnessedCheckpoint,
    entry: &[u8],
    index: u64,
    reader: &mut R,
) -> Result<LogKey, AcceptError<R::Error>> {
    if checkpoint.checkpoint().origin() != view.log.verifier().name() {
        return Err(AcceptError::View(ViewError::WrongLog));
    }
    let next = match LogEntry::decode(entry).map_err(AcceptError::Entry)? {
        LogEntry::Handoff(next) => next,
        LogEntry::Record(_) => return Err(AcceptError::NotAHandoff),
    };
    if view.log.origin().next().as_ref() != Some(next.origin()) {
        return Err(AcceptError::NotAHandoff);
    }
    if index.checked_add(1) != Some(checkpoint.checkpoint().size()) {
        return Err(AcceptError::NotLastEntry);
    }
    // After a hand-off the view takes no larger tree, so only the same
    // hand-off can be shown again.
    if view
        .handoff
        .as_ref()
        .is_some_and(|(i, k)| *i != index || *k != next)
    {
        return Err(AcceptError::NotLastEntry);
    }
    accept_entry(view, checkpoint, entry, index, reader)?;
    // accept_entry kept the checkpoint if it was newer. If the view's
    // newest is larger, the log appended after its hand-off.
    if view.newest.checkpoint().size() != index + 1 {
        return Err(AcceptError::View(ViewError::AfterHandoff));
    }
    view.handoff = Some((index, next.clone()));
    Ok(next)
}

/// Why [`accept_entry`], [`accept_record`] or [`accept_handoff`] did not
/// accept an entry.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AcceptError<E> {
    /// The entry is not shown to be in the checkpoint.
    #[error(transparent)]
    Inclusion(InclusionError<E>),
    /// The checkpoint does not fit the device's view of the log.
    #[error(transparent)]
    View(ViewError<E>),
    /// The entry is not a LogEntry.
    #[error(transparent)]
    Entry(EntryError),
    /// The entry is a hand-off, not a record.
    #[error("the entry is not a record")]
    NotARecord,
    /// The entry's Record does not have the key file's hash.
    #[error("the entry is another record")]
    WrongRecord,
    /// The entry is not a hand-off to the host's next log.
    #[error("the entry is not a hand-off to the next log")]
    NotAHandoff,
    /// The hand-off is not the checkpoint's last entry.
    #[error("the hand-off is not the checkpoint's last entry")]
    NotLastEntry,
}
