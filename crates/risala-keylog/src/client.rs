//! What a device does with a key log (SPEC 4.5): proving that a record is
//! in a witnessed checkpoint, keeping the newest witnessed checkpoint of
//! each log consistent with every other it sees, and spotting forks.
//!
//! Every proof is computed from the log's tiles, then verified against a
//! witnessed checkpoint, so the tiles are never trusted. Work out the
//! tiles with [`inclusion_tiles`] or [`consistency_tiles`], fetch them into
//! a [`TileSet`](crate::tile::TileSet), and read them with its
//! [`reader`](crate::tile::TileSet::reader) for the larger tree.

use thiserror::Error;

use crate::checkpoint::{Checkpoint, SignedCheckpoint};
use crate::merkle::{Hash, leaf_hash};
use crate::proof::{
    Consistency, HashReader, ProofError, VerifyError, check_seeded_path, consistency_ranges,
    inclusion_proof, inclusion_ranges, nodes_for_ranges, seeded_consistency_path, verify_inclusion,
};
use crate::tile::{BundleError, TileId, TileKind, decode_bundle, tiles_for_nodes};
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
    /// It has the same tree as the newest.
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
/// consistent with (SPEC 4.5, step 4 of "Accepting a record").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogView {
    log: LogKey,
    newest: WitnessedCheckpoint,
}

impl LogView {
    /// A view that starts from a witnessed checkpoint of `log`.
    pub fn new(
        log: LogKey,
        first: WitnessedCheckpoint,
    ) -> Result<LogView, ViewError<std::convert::Infallible>> {
        if first.checkpoint().origin() != log.verifier().name() {
            return Err(ViewError::WrongLog);
        }
        Ok(LogView { log, newest: first })
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
        if mine.size() == theirs.size() {
            if mine.root() == theirs.root() {
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

/// Checks a record against a key log, from tiles, as a device does before
/// acting on it (SPEC 4.5, steps 2 to 4 of "Accepting a record"):
///
/// - `checkpoint` is the log's checkpoint, witnessed under the device's
///   policy;
/// - `entry` is at `index` of its tree, by a proof from `reader`;
/// - the checkpoint is consistent with the newest the device has seen,
///   which `view` keeps.
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

/// Why [`accept_entry`] did not accept a record.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AcceptError<E> {
    /// The entry is not shown to be in the checkpoint.
    #[error(transparent)]
    Inclusion(InclusionError<E>),
    /// The checkpoint does not fit the device's view of the log.
    #[error(transparent)]
    View(ViewError<E>),
}
