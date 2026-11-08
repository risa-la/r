//! An in-memory key log and witness, for tests: the log appends entries,
//! serves tiles, entry bundles and its hints, signs checkpoints and hands
//! off to the host's next log; the witness is a [`WitnessCore`] with its
//! state in memory, by the rules of [TLOG-WITNESS] and SPEC 4.10.
//!
//! Both sign with ML-DSA-44's deterministic variant, so that tests are
//! repeatable. Real logs and witnesses should use the hedged one.

use std::collections::BTreeMap;
use std::convert::Infallible;

use thiserror::Error;

use crate::addcheckpoint::AddCheckpoint;
use crate::checkpoint::{Checkpoint, LogOrigin, SignedCheckpoint};
use crate::cosig::{CosignatureVerifier, Cosigner};
use crate::entry::LogEntry;
use crate::handoff::HandoffRequest;
use crate::hint::{NEXT_PATH, UidHint, next_body, uid_hint_path};
use crate::merkle::{Hash, leaf_hash};
use crate::note::{NoteSignature, VerifierKey};
use crate::proof::{consistency_proof, inclusion_proof, tree_hash};
use crate::tile::{HashTiles, TILE_WIDTH, TileFetcher, TileId, TileKind, encode_bundle};
use crate::witness::LogKey;
pub use crate::witnessing::WitnessRefusal;
use crate::witnessing::{CoreError, MemoryWitnessStore, WitnessConfig, WitnessCore};

/// A key log in memory.
#[derive(Debug)]
pub struct MemoryLog {
    origin: LogOrigin,
    cosigner: Cosigner,
    tiles: HashTiles,
    entries: Vec<Vec<u8>>,
    uids: BTreeMap<String, Vec<u64>>,
    handoff: Option<u64>,
}

impl MemoryLog {
    /// An empty log with this origin, whose key comes from `seed`.
    pub fn new(origin: &LogOrigin, seed: &[u8; 32]) -> MemoryLog {
        let cosigner =
            Cosigner::from_seed(&origin.to_string(), seed).expect("origins are valid names");
        MemoryLog {
            origin: origin.clone(),
            cosigner,
            tiles: HashTiles::new(),
            entries: Vec::new(),
            uids: BTreeMap::new(),
            handoff: None,
        }
    }

    /// The log's origin.
    pub fn origin(&self) -> &LogOrigin {
        &self.origin
    }

    /// The log's key.
    pub fn key(&self) -> LogKey {
        LogKey::new(self.cosigner.verifier()).expect("the name is an origin")
    }

    /// The log's verifier key, for a key file's `log` line.
    pub fn vkey(&self) -> VerifierKey {
        self.cosigner.vkey()
    }

    /// Appends an entry as it is, and returns its index. Tests of the tree
    /// itself use any bytes; [`append_record`](Self::append_record) and
    /// [`hand_off`](Self::hand_off) append LogEntries.
    ///
    /// # Panics
    ///
    /// After the log has handed off: it appends nothing more (SPEC 4.5).
    pub fn append(&mut self, entry: &[u8]) -> u64 {
        assert!(
            self.handoff.is_none(),
            "a log appends nothing after its hand-off"
        );
        self.tiles.push(leaf_hash(entry));
        self.entries.push(entry.to_vec());
        self.size() - 1
    }

    /// Appends a record entry for `uid`, which the uid's hint then lists,
    /// and returns its index. The Record is not checked.
    pub fn append_record(&mut self, uid: &str, record: &[u8]) -> u64 {
        let entry = LogEntry::record(record).expect("a record of 1 to 16384 bytes");
        let index = self.append(&entry.encode());
        self.uids.entry(uid.to_owned()).or_default().push(index);
        index
    }

    /// Appends the hand-off entry to `next`, the host's next log, and
    /// returns its index. The log appends nothing after it.
    pub fn hand_off(&mut self, next: &LogKey) -> u64 {
        assert_eq!(
            Some(next.origin()),
            self.origin.next().as_ref(),
            "a hand-off names the host's next log"
        );
        let index = self.append(&LogEntry::Handoff(next.clone()).encode());
        self.handoff = Some(index);
        index
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

    /// The body of `risala/uid/<hash>` for `uid`; `None` for a 404.
    pub fn uid_hint(&self, uid: &str) -> Option<String> {
        let indices = self.uids.get(uid)?;
        Some(UidHint::new(indices.clone()).ok()?.to_body())
    }

    /// The body of `risala/next`; `None` for a 404.
    pub fn next_hint(&self) -> Option<String> {
        self.handoff.map(next_body)
    }

    /// What the log serves at `path` under its URL prefix: tiles, entry
    /// bundles and hints. `None` for a 404.
    pub fn serve(&self, path: &str) -> Option<Vec<u8>> {
        if path == NEXT_PATH {
            return self.next_hint().map(String::into_bytes);
        }
        if let Some(uid) = self.uids.keys().find(|u| uid_hint_path(u) == path) {
            return self.uid_hint(uid).map(String::into_bytes);
        }
        self.tile(&TileId::parse(path).ok()?)
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
    /// `409` answer; a witness that does not know a log 1 is asked to enrol
    /// it, with the log's key. Witnesses that refuse are skipped.
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
                    Err(WitnessRefusal::UnknownLog) if old == 0 && self.origin.number() == 1 => {
                        break w.enrol(&self.key(), &req, timestamp);
                    }
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

    /// The hand-off request for `checkpoint`, a checkpoint of this log
    /// whose last entry is the hand-off; `None` if the log has not handed
    /// off.
    pub fn handoff_request(&self, checkpoint: &SignedCheckpoint) -> Option<HandoffRequest> {
        let index = self.handoff?;
        Some(HandoffRequest {
            index,
            entry: self.entry(index)?.to_vec(),
            proof: self.inclusion_proof(index, checkpoint.checkpoint().size())?,
            checkpoint: checkpoint.clone(),
        })
    }

    /// Shows each witness the hand-off, as a host does before the next
    /// log's first checkpoint (SPEC 4.10), through the request body.
    pub fn send_handoff(
        &self,
        checkpoint: &SignedCheckpoint,
        witnesses: &mut [TestWitness],
    ) -> Vec<Result<(), WitnessRefusal>> {
        let body = self
            .handoff_request(checkpoint)
            .expect("the log has handed off")
            .to_body();
        witnesses
            .iter_mut()
            .map(|w| w.handoff_body(body.as_bytes()))
            .collect()
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

/// A witness in memory: a [`WitnessCore`] over a [`MemoryWitnessStore`],
/// signing deterministically.
#[derive(Debug)]
pub struct TestWitness {
    core: WitnessCore<MemoryWitnessStore>,
}

fn refusal(e: CoreError<Infallible>) -> WitnessRefusal {
    match e {
        CoreError::Refused(r) => r,
        CoreError::Store(never) => match never {},
        CoreError::Clock => panic!("test witnesses need a clock that is not 0"),
    }
}

impl TestWitness {
    /// A witness named `name`, whose key comes from `seed`, with the
    /// default limits.
    pub fn new(name: &str, seed: &[u8; 32]) -> TestWitness {
        TestWitness::with_config(name, seed, WitnessConfig::default())
    }

    /// A witness with these limits.
    pub fn with_config(name: &str, seed: &[u8; 32], config: WitnessConfig) -> TestWitness {
        let cosigner = Cosigner::from_seed(name, seed).expect("a valid name");
        TestWitness {
            core: WitnessCore::new(cosigner, MemoryWitnessStore::new(), config),
        }
    }

    /// The verifier for the witness's cosignatures.
    pub fn verifier(&self) -> CosignatureVerifier {
        self.core.verifier()
    }

    /// The witness's verifier key.
    pub fn vkey(&self) -> VerifierKey {
        self.core.vkey()
    }

    /// The witness's core.
    pub fn core(&self) -> &WitnessCore<MemoryWitnessStore> {
        &self.core
    }

    /// The size and root the witness last cosigned for a log.
    pub fn latest(&self, origin: &str) -> Option<(u64, Hash)> {
        let origin: LogOrigin = origin.parse().ok()?;
        let state = self.core.store().logs().get(&origin)?;
        Some((state.size, state.root))
    }

    /// Handles an `add-checkpoint` request at `timestamp`, and returns its
    /// cosignature.
    pub fn add_checkpoint(
        &mut self,
        req: &AddCheckpoint,
        timestamp: u64,
    ) -> Result<Vec<NoteSignature>, WitnessRefusal> {
        self.core
            .add_checkpoint(req, timestamp, [0; 32])
            .map_err(refusal)
    }

    /// Handles an `add-checkpoint` request that may enrol a log with `key`.
    pub fn enrol(
        &mut self,
        key: &LogKey,
        req: &AddCheckpoint,
        timestamp: u64,
    ) -> Result<Vec<NoteSignature>, WitnessRefusal> {
        self.core
            .enrol(key, req, timestamp, [0; 32])
            .map_err(refusal)
    }

    /// Handles an `add-checkpoint` request body, and returns the response
    /// body: the cosignature's line.
    pub fn add_checkpoint_body(
        &mut self,
        body: &[u8],
        key: Option<&LogKey>,
        timestamp: u64,
    ) -> Result<String, WitnessRefusal> {
        self.core
            .add_checkpoint_body(body, key, timestamp, [0; 32])
            .map_err(refusal)
    }

    /// Handles a hand-off request.
    pub fn handoff(&mut self, req: &HandoffRequest) -> Result<(), WitnessRefusal> {
        self.core.handoff(req).map_err(refusal)
    }

    /// Handles a hand-off request body.
    pub fn handoff_body(&mut self, body: &[u8]) -> Result<(), WitnessRefusal> {
        self.core.handoff_body(body).map_err(refusal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::empty_root;
    use crate::tile::{TileSet, bundles_for_growth, tiles_for_growth};

    fn origin() -> LogOrigin {
        "log.example.org/risala-log/1".parse().unwrap()
    }

    fn req(old_size: u64, proof: Vec<Hash>, checkpoint: &SignedCheckpoint) -> AddCheckpoint {
        AddCheckpoint {
            old_size,
            proof,
            checkpoint: checkpoint.clone(),
        }
    }

    #[test]
    fn witness_follows_the_protocol() {
        let mut log = MemoryLog::new(&origin(), &[1; 32]);
        let mut w = TestWitness::new("witness.example/w", &[2; 32]);
        for i in 0..5u8 {
            log.append(&[i]);
        }
        let cp5 = log.checkpoint(100);

        // A log 1 the witness does not know, without its key.
        assert_eq!(
            w.add_checkpoint(&req(0, vec![], &cp5), 100),
            Err(WitnessRefusal::UnknownLog)
        );
        // Unknown, and not enrolling.
        assert_eq!(
            w.enrol(&log.key(), &req(1, vec![], &cp5), 100),
            Err(WitnessRefusal::UnknownLog)
        );
        // Signed by another key under the log's name.
        let impostor = MemoryLog::new(&origin(), &[4; 32]);
        assert_eq!(
            w.enrol(&log.key(), &req(0, vec![], &impostor.checkpoint(100)), 100)
                .map_err(|e| e.status()),
            Err(403)
        );
        // A key for another origin.
        let other = MemoryLog::new(&"other.example/risala-log/1".parse().unwrap(), &[3; 32]);
        assert_eq!(
            w.enrol(&other.key(), &req(0, vec![], &cp5), 100),
            Err(WitnessRefusal::Forbidden)
        );
        // A proof when the old size is 0.
        assert_eq!(
            w.enrol(&log.key(), &req(0, vec![empty_root()], &cp5), 100),
            Err(WitnessRefusal::Unprocessable)
        );
        // The log's signature with a zero timestamp.
        assert_eq!(
            w.enrol(&log.key(), &req(0, vec![], &log.checkpoint(0)), 100),
            Err(WitnessRefusal::Forbidden)
        );
        // Nothing was enrolled by those.
        assert_eq!(w.latest(&origin().to_string()), None);

        let body = w
            .add_checkpoint_body(
                req(0, vec![], &cp5).to_body().as_bytes(),
                Some(&log.key()),
                100,
            )
            .unwrap();
        let sigs = NoteSignature::parse_lines(&body).unwrap();
        assert_eq!(w.verifier().verify(cp5.checkpoint(), &sigs[0]), Ok(100));
        assert_eq!(
            w.latest(&origin().to_string()),
            Some((5, log.root_at(5).unwrap()))
        );
        // Once enrolled, the key never changes.
        assert_eq!(
            w.enrol(&impostor.key(), &req(5, vec![], &cp5), 200),
            Err(WitnessRefusal::Forbidden)
        );

        // The log must now say where the witness is.
        log.append(b"x");
        let cp6 = log.checkpoint(200);
        assert_eq!(
            w.add_checkpoint(&req(0, vec![], &cp6), 200),
            Err(WitnessRefusal::Conflict(5))
        );
        assert_eq!(
            w.add_checkpoint(&req(7, vec![], &cp6), 200),
            Err(WitnessRefusal::BadRequest)
        );
        assert_eq!(
            w.add_checkpoint(&req(5, vec![empty_root(); 3], &cp6), 200),
            Err(WitnessRefusal::Unprocessable)
        );
        // Ten seconds between checkpoints of one log.
        let good = req(5, log.consistency_proof(5, 6).unwrap(), &cp6);
        assert_eq!(
            w.add_checkpoint(&good, 109),
            Err(WitnessRefusal::TooManyRequests)
        );
        assert!(w.add_checkpoint(&good, 110).is_ok());

        // The same size again with another root: a fork, refused.
        let mut fork = MemoryLog::new(&origin(), &[1; 32]);
        for i in 0..6u8 {
            fork.append(&[i + 1]);
        }
        assert_eq!(
            w.add_checkpoint(&req(6, vec![], &fork.checkpoint(300)), 300),
            Err(WitnessRefusal::Unprocessable)
        );
        // And a larger fork, whatever proof the forked log sends.
        fork.append(b"y");
        let r = req(
            6,
            fork.consistency_proof(6, 7).unwrap(),
            &fork.checkpoint(300),
        );
        assert_eq!(
            w.add_checkpoint(&r, 300),
            Err(WitnessRefusal::Unprocessable)
        );
        assert_eq!(
            w.latest(&origin().to_string()),
            Some((6, log.root_at(6).unwrap()))
        );

        // Extension lines are not cosigned.
        let text = format!("{}ext\n", cp6.checkpoint().to_text());
        let mut with_ext = SignedCheckpoint::unsigned(Checkpoint::from_text(&text).unwrap());
        with_ext
            .push_signature(log.cosigner.cosign(with_ext.checkpoint(), 400, [0; 32]))
            .unwrap();
        assert_eq!(
            w.add_checkpoint(&req(6, vec![], &with_ext), 400),
            Err(WitnessRefusal::Forbidden)
        );
    }

    #[test]
    fn log_serves_tiles_bundles_and_hints() {
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
        assert_eq!(log.serve(&bundles[2].path()), Some(last));

        // Hints.
        assert_eq!(log.serve(NEXT_PATH), None);
        assert_eq!(log.serve(&uid_hint_path("a@example.org")), None);
        let a = log.append_record("a@example.org", b"record 1");
        log.append_record("b@example.org", b"record 2");
        let a2 = log.append_record("a@example.org", b"record 3");
        assert_eq!(
            log.serve(&uid_hint_path("a@example.org")),
            Some(format!("{a}\n{a2}\n").into_bytes())
        );
        assert_eq!(
            LogEntry::decode(log.entry(a).unwrap()),
            Ok(LogEntry::Record(b"record 1".to_vec()))
        );
        let next = MemoryLog::new(&origin().next().unwrap(), &[2; 32]);
        let h = log.hand_off(&next.key());
        assert_eq!(log.serve(NEXT_PATH), Some(format!("{h}\n").into_bytes()));
        assert_eq!(
            LogEntry::decode(log.entry(h).unwrap()),
            Ok(LogEntry::Handoff(next.key()))
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| log.append(b"late"))).is_err()
        );
    }
}
