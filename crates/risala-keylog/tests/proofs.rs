//! Property tests of proofs computed from tiles (SPEC 4.5).

use proptest::prelude::*;
use risala_keylog::client::{consistency_tiles, inclusion_tiles};
use risala_keylog::merkle::{Hash, leaf_hash, root_from_leaf_hashes};
use risala_keylog::proof::{
    VerifyError, consistency_proof, inclusion_proof, tree_hash, verify_consistency,
    verify_inclusion,
};
use risala_keylog::tile::{HashTiles, TileId, TileSet, tiles_for_growth};

fn leaves(n: u64) -> Vec<Hash> {
    (0..n).map(|i| leaf_hash(&i.to_le_bytes())).collect()
}

/// A device's tile set for the tree of `size` leaves, holding only the
/// given tiles, fetched from the server's tiles at that size.
fn fetch(server: &HashTiles, tiles: &[TileId]) -> TileSet {
    let mut set = TileSet::new();
    for t in tiles {
        set.insert(*t, server.tile(t).expect("the server has the tile"))
            .unwrap();
    }
    set
}

fn tamper(proof: &mut [Hash], which: usize, bit: u8) {
    let i = which % proof.len();
    proof[i].0[usize::from(bit) % 32] ^= 1 << (bit % 8);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// An inclusion proof from just the tiles inclusion_tiles names
    /// verifies against the root, and fails once anything changes.
    #[test]
    fn inclusion_from_tiles(size in 1u64..1500, index_seed in any::<u64>(), which in any::<usize>(), bit in any::<u8>()) {
        let index = index_seed % size;
        let leaves = leaves(size);
        let server = HashTiles::from_leaf_hashes(leaves.iter().copied());
        let root = root_from_leaf_hashes(&leaves);
        prop_assert_eq!(server.root(), root);

        let set = fetch(&server, &inclusion_tiles(index, size));
        let proof = inclusion_proof(index, size, &mut set.reader(size)).unwrap();
        prop_assert_eq!(&proof, &inclusion_proof(index, size, &mut &server).unwrap());
        verify_inclusion(&leaves[index as usize], index, size, &proof, &root).unwrap();

        // Another leaf, another index, another size, a changed hash.
        let other = leaf_hash(b"not in the log");
        prop_assert!(verify_inclusion(&other, index, size, &proof, &root).is_err());
        if size > 1 {
            let wrong = (index + 1) % size;
            prop_assert!(verify_inclusion(&leaves[index as usize], wrong, size, &proof, &root).is_err());
            let mut bad = proof.clone();
            tamper(&mut bad, which, bit);
            prop_assert_eq!(verify_inclusion(&leaves[index as usize], index, size, &bad, &root), Err(VerifyError::RootMismatch));
            let mut short = proof.clone();
            short.pop();
            prop_assert!(verify_inclusion(&leaves[index as usize], index, size, &short, &root).is_err());
        }
        // No check that the proof fails for size + 1: the size only gives
        // the proof's shape, which is often the same for both. The signed
        // checkpoint is what ties a size to its root.
    }

    /// A consistency proof from the tiles consistency_tiles names verifies
    /// between the two roots, and fails once anything changes.
    #[test]
    fn consistency_from_tiles(new in 1u64..1500, old_seed in any::<u64>(), which in any::<usize>(), bit in any::<u8>()) {
        let old = old_seed % (new + 1);
        let leaves = leaves(new);
        let server = HashTiles::from_leaf_hashes(leaves.iter().copied());
        let old_root = root_from_leaf_hashes(&leaves[..old as usize]);
        let new_root = server.root();

        let set = fetch(&server, &consistency_tiles(old, new));
        let proof = consistency_proof(old, new, &mut set.reader(new)).unwrap();
        prop_assert_eq!(&proof, &consistency_proof(old, new, &mut &server).unwrap());
        verify_consistency(old, &old_root, new, &new_root, &proof).unwrap();
        if 0 < old && old < new {
            // The old root as the new tree has it, from the same tiles.
            prop_assert_eq!(tree_hash(old, &mut set.reader(new)).unwrap(), old_root);
        }

        if 0 < old && old < new {
            let mut bad = proof.clone();
            tamper(&mut bad, which, bit);
            prop_assert!(verify_consistency(old, &old_root, new, &new_root, &bad).is_err());
            prop_assert!(verify_consistency(old, &new_root, new, &new_root, &proof).is_err());
            prop_assert!(verify_consistency(old, &old_root, new, &old_root, &proof).is_err());
            let mut long = proof.clone();
            long.push(new_root);
            prop_assert!(verify_consistency(old, &old_root, new, &new_root, &long).is_err());
            if old + 1 < new {
                prop_assert!(verify_consistency(old + 1, &old_root, new, &new_root, &proof).is_err());
            }
        }
    }

    /// The tiles of a tree rebuild its root, at any size.
    #[test]
    fn roots_from_tiles(size in 0u64..2000) {
        let leaves = leaves(size);
        let server = HashTiles::from_leaf_hashes(leaves.iter().copied());
        let set = fetch(&server, &tiles_for_growth(0, size));
        prop_assert_eq!(tree_hash(size, &mut set.reader(size)).unwrap(), root_from_leaf_hashes(&leaves));
    }

    /// Tile paths survive a round trip.
    #[test]
    fn tile_paths(level in 0u8..=63, index in any::<u64>(), width in 1u16..=256, entries in any::<bool>()) {
        let t = if entries { TileId::entries(index, width) } else { TileId::hashes(level, index, width) }.unwrap();
        prop_assert_eq!(TileId::parse(&t.path()), Ok(t));
    }

    /// Tile path parsing never panics, and accepts only what it writes.
    #[test]
    fn tile_path_parsing(s in "tile/(entries|[0-9]{1,3})/(x[0-9]{1,4}/){0,7}[0-9]{1,4}(\\.p/[0-9]{1,4})?") {
        if let Ok(t) = TileId::parse(&s) {
            prop_assert_eq!(t.path(), s);
        }
    }
}

/// Proofs in a tree with three levels of tiles: [TLOG-TILES]'s example
/// size of 70,000 leaves, and a later size.
#[test]
fn three_levels_of_tiles() {
    let size = 70_000;
    let leaves = leaves(size);
    let mut server = HashTiles::from_leaf_hashes(leaves.iter().copied());
    let root = root_from_leaf_hashes(&leaves);
    assert_eq!(server.root(), root);

    for index in [0, 1, 255, 256, 65_535, 65_536, 69_887, 69_888, 69_999] {
        let set = fetch(&server, &inclusion_tiles(index, size));
        let proof = inclusion_proof(index, size, &mut set.reader(size)).unwrap();
        verify_inclusion(&leaves[index as usize], index, size, &proof, &root).unwrap();
    }

    let more: Vec<Hash> = (size..size + 70_000)
        .map(|i| leaf_hash(&i.to_le_bytes()))
        .collect();
    for h in &more {
        server.push(*h);
    }
    let new = server.size();
    let new_root = server.root();
    for old in [1, 256, 65_536, 65_537, 69_999, 70_000, 131_072, 139_999] {
        let set = fetch(&server, &consistency_tiles(old, new));
        let proof = consistency_proof(old, new, &mut set.reader(new)).unwrap();
        let old_root = server_root_at(&server, old);
        verify_consistency(old, &old_root, new, &new_root, &proof).unwrap();
    }
    verify_consistency(
        size,
        &root,
        new,
        &new_root,
        &consistency_proof(size, new, &mut &server).unwrap(),
    )
    .unwrap();
}

fn server_root_at(server: &HashTiles, size: u64) -> Hash {
    tree_hash(size, &mut &*server).unwrap()
}
