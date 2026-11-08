//! An in-memory key log and witness, for tests: the log appends entries,
//! serves tiles and entry bundles and signs checkpoints, and the witness
//! cosigns them by the rules of [TLOG-WITNESS]'s `add-checkpoint`.
//!
//! Both sign with ML-DSA-44's deterministic variant, so that tests are
//! repeatable. Real logs and witnesses should use the hedged one.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::addcheckpoint::AddCheckpoint;
use crate::checkpoint::{Checkpoint, LogOrigin, SignedCheckpoint};
use crate::cosig::{CosignatureVerifier, Cosigner};
use crate::merkle::{Hash, empty_root, leaf_hash};
use crate::note::{NoteSignature, VerifierKey};
use crate::proof::{consistency_proof, inclusion_proof, tree_hash, verify_consistency};
use crate::tile::{HashTiles, TILE_WIDTH, TileFetcher, TileId, TileKind, encode_bundle};
use crate::witness::{LogKey, verify_log_signature};

/// A key log in memory.
#[derive(Debug)]
pub struct MemoryLog {
    cosigner: Cosigner,
    tiles: HashTiles,
    entries: Vec<Vec<u8>>,
}

impl MemoryLog {
    /// An empty log with this origin, whose key comes from `seed`.
    pub fn new(origin: &LogOrigin, seed: &[u8; 32]) -> MemoryLog {
        let cosigner =
            Cosigner::from_seed(&origin.to_string(), seed).expect("origins are valid names");
        MemoryLog {
            cosigner,
            tiles: HashTiles::new(),
            entries: Vec::new(),
        }
    }

    /// The log's key.
    pub fn key(&self) -> LogKey {
        LogKey::new(self.cosigner.verifier()).expect("the name is an origin")
    }

    /// The log's verifier key, for a key file's `log` line.
    pub fn vkey(&self) -> VerifierKey {
        self.cosigner.vkey()
    }

    /// Appends an entry, and returns its index.
    pub fn append(&mut self, entry: &[u8]) -> u64 {
        self.tiles.push(leaf_hash(entry));
        self.entries.push(entry.to_vec());
        self.size() - 1
    }

    /// The number of entries.
    pub fn size(&self) -> u64 {
        self.tiles.size()
    }

    /// An entry.
    pub fn entry(&self, index: u64) -> Option<&[u8]> {
        self.entries
            .get(usize::try_from(index).ok()?)
            .map(Vec::as_slice)
    }

    /// The root of the tree of the first `size` entries.
    pub fn root_at(&self, size: u64) -> Option<Hash> {
        (size <= self.size())
            .then(|| tree_hash(size, &mut &self.tiles).expect("the log has every node"))
    }

    /// The checkpoint of the first `size` entries, signed by the log at
    /// `timestamp`.
    pub fn checkpoint_at(&self, size: u64, timestamp: u64) -> Option<SignedCheckpoint> {
        let cp = Checkpoint::new(self.cosigner.name(), size, self.root_at(size)?)
            .expect("the origin is valid");
        let mut sc = SignedCheckpoint::unsigned(cp);
        let sig = self.cosigner.cosign(sc.checkpoint(), timestamp, [0; 32]);
        sc.push_signature(sig).expect("a fresh note has room");
        Some(sc)
    }

    /// The checkpoint of every entry so far, signed by the log.
    pub fn checkpoint(&self, timestamp: u64) -> SignedCheckpoint {
        self.checkpoint_at(self.size(), timestamp)
            .expect("the log has its own size")
    }

    /// The inclusion proof of entry `index` in the tree of `size` entries.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Option<Vec<Hash>> {
        (size <= self.size()).then(|| inclusion_proof(index, size, &mut &self.tiles).ok())?
    }

    /// The consistency proof from `old` entries to `new`.
    pub fn consistency_proof(&self, old: u64, new: u64) -> Option<Vec<Hash>> {
        (new <= self.size()).then(|| consistency_proof(old, new, &mut &self.tiles).ok())?
    }

    /// A tile or entry bundle, as the log would serve it: full tiles once
    /// complete, and partial tiles of every width up to what exists.
    pub fn tile(&self, tile: &TileId) -> Option<Vec<u8>> {
        match tile.kind() {
            TileKind::Hashes(_) => self.tiles.tile(tile),
            TileKind::Entries => {
                let start = usize::try_from(tile.index().checked_mul(TILE_WIDTH)?).ok()?;
                let end = start.checked_add(usize::from(tile.width()))?;
                let entries = self.entries.get(start..end)?;
                Some(encode_bundle(entries).expect("test entries fit"))
            }
        }
    }

    /// Asks each witness to cosign `checkpoint`, as a log does, and adds
    /// their cosignatures to it. A log does not know what a witness last
    /// cosigned, so it starts from old size 0 and follows the witness's
    /// `409` answer. Witnesses that refuse are skipped.
    pub fn witness(
        &self,
        checkpoint: &mut SignedCheckpoint,
        witnesses: &mut [TestWitness],
        timestamp: u64,
    ) -> Vec<Result<(), WitnessRefusal>> {
        let mut results = Vec::new();
        for w in witnesses.iter_mut() {
            let mut old = 0;
            let result = loop {
                let proof = match self.consistency_proof(old, checkpoint.checkpoint().size()) {
                    Some(p) => p,
                    None => break Err(WitnessRefusal::BadRequest),
                };
                let req = AddCheckpoint {
                    old_size: old,
                    proof,
                    checkpoint: checkpoint.clone(),
                };
                match w.add_checkpoint(&req, timestamp) {
                    Ok(sigs) => break Ok(sigs),
                    Err(WitnessRefusal::Conflict(n)) if n != old => old = n,
                    Err(e) => break Err(e),
                }
            };
            results.push(result.map(|sigs| {
                for s in sigs {
                    checkpoint
                        .push_signature(s)
                        .expect("room for the cosignature");
                }
            }));
        }
        results
    }
}

/// A tile the log does not have.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("tile not found")]
pub struct TileNotFound;

impl TileFetcher for &MemoryLog {
    type Error = TileNotFound;

    fn fetch_tile(&mut self, tile: &TileId) -> Result<Vec<u8>, TileNotFound> {
        self.tile(tile).ok_or(TileNotFound)
    }
}

/// Why a witness refused to cosign, with the HTTP status of
/// [TLOG-WITNESS].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WitnessRefusal {
    /// 400: the old size is larger than the checkpoint's.
    #[error("400 bad request")]
    BadRequest,
    /// 403: no valid signature from the log, or a bad one.
    #[error("403 forbidden")]
    Forbidden,
    /// 404: the witness does not know the log.
    #[error("404 unknown log")]
    UnknownLog,
    /// 409: the old size is not the size the witness last cosigned, which
    /// it gives.
    #[error("409 conflict, the witness is at {0}")]
    Conflict(u64),
    /// 422: the consistency proof does not verify, or the checkpoint is
    /// not consistent with what the witness cosigned.
    #[error("422 unprocessable")]
    Unprocessable,
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
        }
    }
}

/// A witness in memory.
#[derive(Debug)]
pub struct TestWitness {
    cosigner: Cosigner,
    logs: BTreeMap<String, (CosignatureVerifier, u64, Hash)>,
}

impl TestWitness {
    /// A witness named `name`, whose key comes from `seed`.
    pub fn new(name: &str, seed: &[u8; 32]) -> TestWitness {
        TestWitness {
            cosigner: Cosigner::from_seed(name, seed).expect("a valid name"),
            logs: BTreeMap::new(),
        }
    }

    /// The verifier for the witness's cosignatures.
    pub fn verifier(&self) -> CosignatureVerifier {
        self.cosigner.verifier()
    }

    /// The witness's verifier key.
    pub fn vkey(&self) -> VerifierKey {
        self.cosigner.vkey()
    }

    /// Starts witnessing a log, from the empty tree.
    pub fn add_log(&mut self, log: &CosignatureVerifier) {
        self.logs
            .entry(log.name().to_owned())
            .or_insert_with(|| (log.clone(), 0, empty_root()));
    }

    /// The size and root the witness last cosigned for a log.
    pub fn latest(&self, origin: &str) -> Option<(u64, Hash)> {
        self.logs.get(origin).map(|(_, n, h)| (*n, *h))
    }

    /// Handles an `add-checkpoint` request at `timestamp`, by the rules of
    /// [TLOG-WITNESS], and returns its cosignature.
    pub fn add_checkpoint(
        &mut self,
        req: &AddCheckpoint,
        timestamp: u64,
    ) -> Result<Vec<NoteSignature>, WitnessRefusal> {
        let cp = req.checkpoint.checkpoint();
        let (log, size, root) = self
            .logs
            .get_mut(cp.origin())
            .ok_or(WitnessRefusal::UnknownLog)?;
        verify_log_signature(log, &req.checkpoint).map_err(|_| WitnessRefusal::Forbidden)?;
        if req.old_size > cp.size() {
            return Err(WitnessRefusal::BadRequest);
        }
        if req.old_size != *size {
            return Err(WitnessRefusal::Conflict(*size));
        }
        if cp.size() == 0 && *cp.root() != empty_root() {
            return Err(WitnessRefusal::Unprocessable);
        }
        verify_consistency(*size, root, cp.size(), cp.root(), &req.proof)
            .map_err(|_| WitnessRefusal::Unprocessable)?;
        *size = cp.size();
        *root = *cp.root();
        Ok(vec![self.cosigner.cosign(cp, timestamp, [0; 32])])
    }

    /// Handles an `add-checkpoint` request body, and returns the response
    /// body: the cosignature's line.
    pub fn add_checkpoint_body(
        &mut self,
        body: &[u8],
        timestamp: u64,
    ) -> Result<String, WitnessRefusal> {
        let req = AddCheckpoint::parse(body).map_err(|_| WitnessRefusal::BadRequest)?;
        let sigs = self.add_checkpoint(&req, timestamp)?;
        Ok(sigs.iter().map(NoteSignature::to_line).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tile::{TileSet, bundles_for_growth, tiles_for_growth};

    fn origin() -> LogOrigin {
        "log.example.org/risala-log/1".parse().unwrap()
    }

    #[test]
    fn witness_follows_the_protocol() {
        let mut log = MemoryLog::new(&origin(), &[1; 32]);
        let mut w = TestWitness::new("witness.example/w", &[2; 32]);
        w.add_log(log.key().verifier());
        for i in 0..5u8 {
            log.append(&[i]);
        }
        let cp5 = log.checkpoint(100);

        // Unknown log.
        let stranger = MemoryLog::new(&"other.example/risala-log/1".parse().unwrap(), &[3; 32]);
        let req = AddCheckpoint {
            old_size: 0,
            proof: vec![],
            checkpoint: stranger.checkpoint(100),
        };
        assert_eq!(w.add_checkpoint(&req, 100), Err(WitnessRefusal::UnknownLog));

        // Signed by another key under the log's name.
        let impostor = MemoryLog::new(&origin(), &[4; 32]);
        let req = AddCheckpoint {
            old_size: 0,
            proof: vec![],
            checkpoint: impostor.checkpoint(100),
        };
        assert_eq!(
            w.add_checkpoint(&req, 100).map_err(|e| e.status()),
            Err(403)
        );

        // A proof when the old size is 0.
        let req = AddCheckpoint {
            old_size: 0,
            proof: vec![empty_root()],
            checkpoint: cp5.clone(),
        };
        assert_eq!(
            w.add_checkpoint(&req, 100),
            Err(WitnessRefusal::Unprocessable)
        );

        let req = AddCheckpoint {
            old_size: 0,
            proof: vec![],
            checkpoint: cp5.clone(),
        };
        let body = w
            .add_checkpoint_body(req.to_body().as_bytes(), 100)
            .unwrap();
        let sigs = NoteSignature::parse_lines(&body).unwrap();
        assert_eq!(w.verifier().verify(cp5.checkpoint(), &sigs[0]), Ok(100));
        assert_eq!(
            w.latest(&origin().to_string()),
            Some((5, log.root_at(5).unwrap()))
        );

        // The log must now say where the witness is.
        log.append(b"x");
        let cp6 = log.checkpoint(200);
        let req = AddCheckpoint {
            old_size: 0,
            proof: vec![],
            checkpoint: cp6.clone(),
        };
        assert_eq!(
            w.add_checkpoint(&req, 200),
            Err(WitnessRefusal::Conflict(5))
        );
        let req = AddCheckpoint {
            old_size: 7,
            proof: vec![],
            checkpoint: cp6.clone(),
        };
        assert_eq!(w.add_checkpoint(&req, 200), Err(WitnessRefusal::BadRequest));
        let bad_proof = vec![empty_root(); 3];
        let req = AddCheckpoint {
            old_size: 5,
            proof: bad_proof,
            checkpoint: cp6.clone(),
        };
        assert_eq!(
            w.add_checkpoint(&req, 200),
            Err(WitnessRefusal::Unprocessable)
        );
        let req = AddCheckpoint {
            old_size: 5,
            proof: log.consistency_proof(5, 6).unwrap(),
            checkpoint: cp6.clone(),
        };
        assert!(w.add_checkpoint(&req, 200).is_ok());

        // The same size again with another root: a fork, refused.
        let mut fork = MemoryLog::new(&origin(), &[1; 32]);
        for i in 0..6u8 {
            fork.append(&[i + 1]);
        }
        let req = AddCheckpoint {
            old_size: 6,
            proof: vec![],
            checkpoint: fork.checkpoint(300),
        };
        assert_eq!(
            w.add_checkpoint(&req, 300),
            Err(WitnessRefusal::Unprocessable)
        );
        // And a larger fork, whatever proof the forked log sends.
        fork.append(b"y");
        let req = AddCheckpoint {
            old_size: 6,
            proof: fork.consistency_proof(6, 7).unwrap(),
            checkpoint: fork.checkpoint(300),
        };
        assert_eq!(
            w.add_checkpoint(&req, 300),
            Err(WitnessRefusal::Unprocessable)
        );
        assert_eq!(
            w.latest(&origin().to_string()),
            Some((6, log.root_at(6).unwrap()))
        );
    }

    #[test]
    fn log_serves_tiles_and_bundles() {
        let mut log = MemoryLog::new(&origin(), &[1; 32]);
        for i in 0..600u32 {
            log.append(&i.to_be_bytes());
        }
        let mut set = TileSet::new();
        set.fetch(&tiles_for_growth(0, 600), &mut &log).unwrap();
        assert_eq!(
            tree_hash(600, &mut set.reader(600)).unwrap(),
            log.root_at(600).unwrap()
        );
        let bundles = bundles_for_growth(0, 600);
        assert_eq!(bundles.len(), 3);
        let last = log.tile(&bundles[2]).unwrap();
        let entries = crate::tile::decode_bundle(&last).unwrap();
        assert_eq!(entries.len(), 88);
        assert_eq!(entries[0], 512u32.to_be_bytes());
        assert_eq!(log.tile(&TileId::entries(2, 89).unwrap()), None);
        assert_eq!(
            (&log).fetch_tile(&TileId::hashes(0, 3, 1).unwrap()),
            Err(TileNotFound)
        );
        assert_eq!(log.entry(599), Some(&599u32.to_be_bytes()[..]));
        assert_eq!(log.inclusion_proof(600, 600), None);
        assert_eq!(log.consistency_proof(10, 601), None);
    }
}
