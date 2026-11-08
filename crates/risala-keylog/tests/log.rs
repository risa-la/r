//! A key log, its witnesses and a device, end to end (SPEC 4.5).

use proptest::prelude::*;
use risala_keylog::checkpoint::SignedCheckpoint;
use risala_keylog::client::{
    AcceptError, ForkEvidence, InclusionError, LogView, Seen, ViewError, accept_entry,
    verify_bundle,
};
use risala_keylog::cosig::Cosigner;
use risala_keylog::merkle::Hash;
use risala_keylog::testlog::{MemoryLog, TestWitness};
use risala_keylog::tile::{TileId, TileSet, bundles_for_growth};
use risala_keylog::witness::{Freshness, WitnessError, WitnessPolicy, WitnessedCheckpoint};
use risala_keylog::{LogKey, LogOrigin};

const NOW: u64 = 1_800_000_000;

fn origin() -> LogOrigin {
    "chat.example.org/risala-log/1".parse().unwrap()
}

struct World {
    log: MemoryLog,
    witnesses: Vec<TestWitness>,
    policy: WitnessPolicy,
}

impl World {
    fn new() -> World {
        let log = MemoryLog::new(&origin(), &[1; 32]);
        // Witnesses enrol the log from its first checkpoint.
        let witnesses: Vec<TestWitness> = (0..3u8)
            .map(|i| TestWitness::new(&format!("witness{i}.example/w"), &[10 + i; 32]))
            .collect();
        let vkeys: Vec<String> = witnesses.iter().map(|w| w.vkey().to_string()).collect();
        let policy = WitnessPolicy::from_vkeys(&vkeys, 2).unwrap();
        World {
            log,
            witnesses,
            policy,
        }
    }

    /// The log's current checkpoint, cosigned by the witnesses it can get.
    fn publish(&mut self, now: u64) -> String {
        let mut cp = self.log.checkpoint(now);
        let results = self.log.witness(&mut cp, &mut self.witnesses, now);
        assert!(results.iter().all(Result::is_ok), "{results:?}");
        cp.to_text()
    }

    fn device_check(&self, served: &str, now: u64) -> Result<WitnessedCheckpoint, WitnessError> {
        self.policy
            .verify(&self.log.key(), served.as_bytes(), Freshness::at(now))
    }
}

fn fetch(log: &MemoryLog, tiles: &[TileId]) -> TileSet {
    let mut set = TileSet::new();
    set.fetch(tiles, &mut &*log).unwrap();
    set
}

#[test]
fn a_device_accepts_records_and_follows_the_log() {
    let mut world = World::new();
    let records: Vec<Vec<u8>> = (0..300u32)
        .map(|i| format!("record {i}").into_bytes())
        .collect();
    for r in &records[..100] {
        world.log.append(r);
    }
    let first = world.publish(NOW);
    let first = world.device_check(&first, NOW + 1).unwrap();
    assert_eq!(first.witnesses().len(), 3);
    let mut view = LogView::new(world.log.key(), first.clone()).unwrap();

    // Record 42 in the first checkpoint.
    let set = fetch(&world.log, &view.tiles_for_entry(first.checkpoint(), 42));
    let seen = accept_entry(
        &mut view,
        first.clone(),
        &records[42],
        42,
        &mut set.reader(100),
    )
    .unwrap();
    assert_eq!(seen, Seen::Same);
    // Not at another index, and not another record.
    assert!(matches!(
        accept_entry(
            &mut view,
            first.clone(),
            &records[42],
            43,
            &mut set.reader(100)
        ),
        Err(AcceptError::Inclusion(_))
    ));
    assert!(matches!(
        accept_entry(
            &mut view,
            first.clone(),
            b"forged",
            42,
            &mut set.reader(100)
        ),
        Err(AcceptError::Inclusion(InclusionError::Verify(_)))
    ));

    // The log grows; the device takes the newer checkpoint.
    for r in &records[100..] {
        world.log.append(r);
    }
    let served = world.publish(NOW + 3600);
    let second = world.device_check(&served, NOW + 3600).unwrap();
    let set = fetch(&world.log, &view.tiles_for_entry(second.checkpoint(), 250));
    let seen = accept_entry(
        &mut view,
        second.clone(),
        &records[250],
        250,
        &mut set.reader(300),
    )
    .unwrap();
    assert_eq!(seen, Seen::Newer);
    assert_eq!(view.newest(), &second);

    // A record proved against the older checkpoint still works, and the
    // view keeps the newer one.
    let set = fetch(&world.log, &view.tiles_for_entry(first.checkpoint(), 7));
    let seen = accept_entry(
        &mut view,
        first.clone(),
        &records[7],
        7,
        &mut set.reader(300),
    )
    .unwrap();
    assert_eq!(seen, Seen::Older);
    assert_eq!(view.newest(), &second);

    // Watching: read every bundle since the first checkpoint, checked
    // against the second.
    let mut read = Vec::new();
    for b in bundles_for_growth(100, 300) {
        let data = world.log.tile(&b).unwrap();
        let mut set = TileSet::new();
        let tiles: Vec<TileId> = (b.index() * 256..b.index() * 256 + u64::from(b.width()))
            .flat_map(|i| risala_keylog::client::inclusion_tiles(i, 300))
            .collect();
        set.fetch(&tiles, &mut &world.log).unwrap();
        read.extend(verify_bundle(&b, &data, second.checkpoint(), &mut set.reader(300)).unwrap());
    }
    assert_eq!(read, records[..300].to_vec());

    // A bundle with an entry swapped does not pass.
    let b = TileId::entries(1, 44).unwrap();
    let mut entries: Vec<Vec<u8>> = (256..300).map(|i| records[i].clone()).collect();
    entries[3] = b"forged".to_vec();
    let data = risala_keylog::tile::encode_bundle(&entries).unwrap();
    let set = fetch(
        &world.log,
        &risala_keylog::client::inclusion_tiles(259, 300),
    );
    assert!(verify_bundle(&b, &data, second.checkpoint(), &mut set.reader(300)).is_err());
    // Nor one with the wrong number of entries.
    let data = risala_keylog::tile::encode_bundle(&entries[..43]).unwrap();
    assert!(verify_bundle(&b, &data, second.checkpoint(), &mut set.reader(300)).is_err());
}

#[test]
fn daily_watch_needs_fresh_cosignatures() {
    let mut world = World::new();
    world.log.append(b"r");
    let served = world.publish(NOW);
    let key = world.log.key();
    assert!(
        world
            .policy
            .verify(&key, served.as_bytes(), Freshness::fresh(NOW + 3600))
            .is_ok()
    );
    assert!(matches!(
        world
            .policy
            .verify(&key, served.as_bytes(), Freshness::fresh(NOW + 25 * 3600)),
        Err(WitnessError::NotFresh { fresh: 0, need: 2 })
    ));
    // A new checkpoint, even with nothing added, is fresh again.
    let served = world.publish(NOW + 24 * 3600);
    assert!(
        world
            .policy
            .verify(&key, served.as_bytes(), Freshness::fresh(NOW + 25 * 3600))
            .is_ok()
    );
}

#[test]
fn witnesses_refuse_a_forked_log() {
    let mut world = World::new();
    for i in 0..10u8 {
        world.log.append(&[i]);
    }
    world.publish(NOW);
    // The same key, another history.
    let mut forked = MemoryLog::new(&origin(), &[1; 32]);
    for i in 0..12u8 {
        forked.append(&[i ^ 0x80]);
    }
    let mut cp = forked.checkpoint(NOW + 60);
    let results = forked.witness(&mut cp, &mut world.witnesses, NOW + 60);
    assert!(
        results
            .iter()
            .all(|r| r.as_ref().map_err(|e| e.status()) == Err(422)),
        "{results:?}"
    );
    assert!(matches!(
        world.device_check(&cp.to_text(), NOW),
        Err(WitnessError::NotEnoughWitnesses { have: 0, need: 2 })
    ));
}

/// A log and witnesses that sign whatever they are given: what a device
/// sees when a log forks and enough witnesses collude or are fooled.
struct Signers {
    log: Cosigner,
    witnesses: Vec<Cosigner>,
    key: LogKey,
    policy: WitnessPolicy,
}

impl Signers {
    fn new() -> Signers {
        let log = Cosigner::from_seed(&origin().to_string(), &[1; 32]).unwrap();
        let witnesses: Vec<Cosigner> = (0..3u8)
            .map(|i| Cosigner::from_seed(&format!("witness{i}.example/w"), &[10 + i; 32]).unwrap())
            .collect();
        let policy =
            WitnessPolicy::new(witnesses.iter().map(Cosigner::verifier).collect(), 2).unwrap();
        let key = LogKey::new(log.verifier()).unwrap();
        Signers {
            log,
            witnesses,
            key,
            policy,
        }
    }

    fn witnessed(&self, log: &MemoryLog, size: u64) -> WitnessedCheckpoint {
        let cp =
            risala_keylog::Checkpoint::new(&origin().to_string(), size, log.root_at(size).unwrap())
                .unwrap();
        let mut sc = SignedCheckpoint::unsigned(cp.clone());
        sc.push_signature(self.log.cosign(&cp, NOW, [0; 32]))
            .unwrap();
        for w in &self.witnesses[..2] {
            sc.push_signature(w.cosign(&cp, NOW, [0; 32])).unwrap();
        }
        self.policy
            .verify_signed(&self.key, sc, Freshness::at(NOW))
            .unwrap()
    }
}

fn two_histories(shared: u64, a_len: u64, b_len: u64) -> (MemoryLog, MemoryLog) {
    let mut a = MemoryLog::new(&origin(), &[1; 32]);
    let mut b = MemoryLog::new(&origin(), &[1; 32]);
    for i in 0..a_len.max(b_len) {
        let e = i.to_be_bytes();
        if i < a_len {
            a.append(&e);
        }
        if i < b_len {
            if i < shared {
                b.append(&e);
            } else {
                b.append(&[&e[..], b"fork"].concat());
            }
        }
    }
    (a, b)
}

#[test]
fn a_device_finds_forks() {
    let s = Signers::new();
    let (a, b) = two_histories(5, 20, 30);

    // Same size, different roots.
    let mut view = LogView::new(s.key.clone(), s.witnessed(&a, 20)).unwrap();
    let other = s.witnessed(&b, 20);
    let set = TileSet::new();
    let err = view.check(other, &mut set.reader(20)).unwrap_err();
    let ViewError::Fork(evidence) = err else {
        panic!("{err:?}")
    };
    assert!(matches!(*evidence, ForkEvidence::SameSize { .. }));
    evidence.verify(&s.key, &s.policy).unwrap();

    // A larger tree that does not extend the smaller one: the device
    // reads the larger tree's tiles, from the log that serves it.
    let other = s.witnessed(&b, 30);
    let set = fetch(&b, &view.tiles_for(other.checkpoint()));
    let err = view.check(other, &mut set.reader(30)).unwrap_err();
    let ViewError::Fork(evidence) = err else {
        panic!("{err:?}")
    };
    assert!(matches!(*evidence, ForkEvidence::Inconsistent { .. }));
    evidence.verify(&s.key, &s.policy).unwrap();
    // The view is unchanged.
    assert_eq!(view.newest().checkpoint().size(), 20);

    // Evidence with a changed path, or with the checkpoints the other way
    // round, proves nothing.
    if let ForkEvidence::Inconsistent { older, newer, path } = *evidence {
        let mut bad = path.clone();
        bad[0].0[0] ^= 1;
        let e = ForkEvidence::Inconsistent {
            older: older.clone(),
            newer: newer.clone(),
            path: bad,
        };
        assert!(e.verify(&s.key, &s.policy).is_err());
        let e = ForkEvidence::Inconsistent {
            older: newer,
            newer: older,
            path,
        };
        assert!(e.verify(&s.key, &s.policy).is_err());
    }

    // A fork from a log the device does not trust is not evidence.
    let stranger = Signers {
        policy: WitnessPolicy::new(
            vec![
                Cosigner::from_seed("x.example/w", &[50; 32])
                    .unwrap()
                    .verifier(),
            ],
            1,
        )
        .unwrap(),
        ..Signers::new()
    };
    let (x, y) = (s.witnessed(&a, 20), s.witnessed(&b, 20));
    let e = ForkEvidence::SameSize {
        a: x.signed().clone(),
        b: y.signed().clone(),
    };
    assert!(e.verify(&stranger.key, &stranger.policy).is_err());
}

#[test]
fn wrong_tiles_are_not_a_fork() {
    let s = Signers::new();
    let (a, _) = two_histories(0, 40, 0);
    let mut view = LogView::new(s.key.clone(), s.witnessed(&a, 10)).unwrap();
    let newer = s.witnessed(&a, 40);
    // Tiles of the right shape and the wrong content.
    let mut set = TileSet::new();
    for t in view.tiles_for(newer.checkpoint()) {
        set.insert(t, vec![7; usize::from(t.width()) * 32]).unwrap();
    }
    assert_eq!(
        view.check(newer.clone(), &mut set.reader(40)),
        Err(ViewError::Unproven)
    );
    // A missing tile.
    let empty = TileSet::new();
    assert!(matches!(
        view.check(newer.clone(), &mut empty.reader(40)),
        Err(ViewError::Proof(_))
    ));
    // The right tiles.
    let set = fetch(&a, &view.tiles_for(newer.checkpoint()));
    assert_eq!(view.check(newer, &mut set.reader(40)), Ok(Seen::Newer));
}

#[test]
fn other_logs_are_refused() {
    let s = Signers::new();
    let (a, _) = two_histories(0, 3, 0);
    let mut view = LogView::new(s.key.clone(), s.witnessed(&a, 3)).unwrap();
    let other_log = Cosigner::from_seed("chat.example.org/risala-log/2", &[1; 32]).unwrap();
    let other_key = LogKey::new(other_log.verifier()).unwrap();
    let cp =
        risala_keylog::Checkpoint::new("chat.example.org/risala-log/2", 1, Hash([0; 32])).unwrap();
    let mut sc = SignedCheckpoint::unsigned(cp.clone());
    sc.push_signature(other_log.cosign(&cp, NOW, [0; 32]))
        .unwrap();
    for w in &s.witnesses {
        sc.push_signature(w.cosign(&cp, NOW, [0; 32])).unwrap();
    }
    let w = s
        .policy
        .verify_signed(&other_key, sc, Freshness::at(NOW))
        .unwrap();
    assert_eq!(
        view.check(w.clone(), &mut TileSet::new().reader(3)),
        Err(ViewError::WrongLog)
    );
    assert!(LogView::new(s.key.clone(), w).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Two histories that share their first `shared` entries: checking a
    /// checkpoint of one against a checkpoint of the other finds a fork
    /// exactly when they differ within the smaller tree, and the evidence
    /// holds up.
    #[test]
    fn forks_are_found_exactly(shared in 0u64..300, a_size in 1u64..300, b_size in 1u64..300) {
        let s = Signers::new();
        let (a, b) = two_histories(shared, a_size, b_size);
        let mut view = LogView::new(s.key.clone(), s.witnessed(&a, a_size)).unwrap();
        let other = s.witnessed(&b, b_size);
        // The tiles of the larger tree, from the log that has it.
        let larger = if b_size >= a_size { &b } else { &a };
        let set = fetch(larger, &view.tiles_for(other.checkpoint()));
        let result = view.check(other, &mut set.reader(a_size.max(b_size)));
        let differ = shared < a_size.min(b_size);
        match result {
            Err(ViewError::Fork(e)) => {
                prop_assert!(differ);
                prop_assert!(e.verify(&s.key, &s.policy).is_ok());
            }
            Ok(seen) => {
                prop_assert!(!differ);
                let want = match b_size.cmp(&a_size) {
                    std::cmp::Ordering::Greater => Seen::Newer,
                    std::cmp::Ordering::Equal => Seen::Same,
                    std::cmp::Ordering::Less => Seen::Older,
                };
                prop_assert_eq!(seen, want);
            }
            Err(e) => prop_assert!(false, "{e:?}"),
        }
    }
}
