//! Inclusion and consistency proofs, RFC 9162 sections 2.1.3 and 2.1.4.
//!
//! Proofs are computed from any [`HashReader`]: the server's own hashes,
//! or the tiles a device fetched from the log ([`crate::tile::TileHashReader`]).
//! A device computes its proofs from tiles and verifies them against a
//! witnessed checkpoint (SPEC 4.5), so tiles need no checking of their
//! own: a wrong tile gives a proof that does not verify.

use thiserror::Error;

use crate::merkle::{Hash, NodeId, fold_range, largest_power_of_two_below, node_hash, range_nodes};

/// Where proofs get the hashes of complete subtrees.
pub trait HashReader {
    /// Why a hash could not be read.
    type Error;

    /// The hash of a complete subtree.
    fn node(&mut self, node: NodeId) -> Result<Hash, Self::Error>;
}

/// Why a proof could not be computed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofError<E> {
    /// The index or sizes are out of range: an index at or past the tree
    /// size, or an old size larger than the new one.
    #[error("index or tree size out of range")]
    OutOfRange,
    /// The hash reader failed.
    #[error("reading hashes: {0}")]
    Read(E),
}

/// Why a proof did not verify.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The index or sizes are out of range.
    #[error("index or tree size out of range")]
    OutOfRange,
    /// The proof has the wrong number of hashes.
    #[error("the proof has the wrong length")]
    WrongLength,
    /// The proof's hashes do not lead to the expected root (for a
    /// consistency proof, to either root).
    #[error("the proof does not match the root")]
    RootMismatch,
}

/// The ranges of leaves whose hashes make up the inclusion proof of leaf
/// `index` in a tree of `size` leaves, in proof order: RFC 9162's
/// `PATH(index, D[0:size])`.
pub fn inclusion_ranges(index: u64, size: u64) -> Option<Vec<(u64, u64)>> {
    if index >= size {
        return None;
    }
    let mut out = Vec::new();
    path(index, 0, size, &mut out);
    Some(out)
}

fn path(m: u64, lo: u64, hi: u64, out: &mut Vec<(u64, u64)>) {
    if hi - lo <= 1 {
        return;
    }
    let k = largest_power_of_two_below(hi - lo);
    if m < lo + k {
        path(m, lo, lo + k, out);
        out.push((lo + k, hi));
    } else {
        path(m, lo + k, hi, out);
        out.push((lo, lo + k));
    }
}

/// The ranges of leaves whose hashes make up the consistency proof from a
/// tree of `old` leaves to one of `new`, in proof order: RFC 9162's
/// `PROOF(old, D[0:new])`. Empty when `old` is 0 or equals `new`.
pub fn consistency_ranges(old: u64, new: u64) -> Option<Vec<(u64, u64)>> {
    if old > new {
        return None;
    }
    let mut out = Vec::new();
    if old > 0 && old < new {
        subproof(old, 0, new, true, &mut out);
    }
    Some(out)
}

fn subproof(m: u64, lo: u64, hi: u64, whole: bool, out: &mut Vec<(u64, u64)>) {
    if m == hi {
        if !whole {
            out.push((lo, hi));
        }
        return;
    }
    let k = largest_power_of_two_below(hi - lo);
    if m <= lo + k {
        subproof(m, lo, lo + k, whole, out);
        out.push((lo + k, hi));
    } else {
        subproof(m, lo + k, hi, false, out);
        out.push((lo, lo + k));
    }
}

/// The complete subtrees whose hashes a list of ranges needs.
pub fn nodes_for_ranges(ranges: &[(u64, u64)]) -> Vec<NodeId> {
    let mut nodes: Vec<NodeId> = ranges
        .iter()
        .flat_map(|&(lo, hi)| range_nodes(lo, hi).expect("proof ranges are aligned"))
        .collect();
    nodes.sort_unstable();
    nodes.dedup();
    nodes
}

/// The MTH of leaves `[lo, hi)`, read from `reader`.
pub fn range_hash<R: HashReader>(
    lo: u64,
    hi: u64,
    reader: &mut R,
) -> Result<Hash, ProofError<R::Error>> {
    let nodes = range_nodes(lo, hi).ok_or(ProofError::OutOfRange)?;
    let hashes = nodes
        .into_iter()
        .map(|n| reader.node(n))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ProofError::Read)?;
    Ok(fold_range(&hashes).expect("a non-empty range has nodes"))
}

/// The root of the tree of `size` leaves, read from `reader`.
pub fn tree_hash<R: HashReader>(size: u64, reader: &mut R) -> Result<Hash, ProofError<R::Error>> {
    if size == 0 {
        return Ok(crate::merkle::empty_root());
    }
    range_hash(0, size, reader)
}

/// The inclusion proof of leaf `index` in the tree of `size` leaves.
pub fn inclusion_proof<R: HashReader>(
    index: u64,
    size: u64,
    reader: &mut R,
) -> Result<Vec<Hash>, ProofError<R::Error>> {
    let ranges = inclusion_ranges(index, size).ok_or(ProofError::OutOfRange)?;
    ranges
        .into_iter()
        .map(|(lo, hi)| range_hash(lo, hi, reader))
        .collect()
}

/// The consistency proof from the tree of `old` leaves to the tree of
/// `new` leaves.
pub fn consistency_proof<R: HashReader>(
    old: u64,
    new: u64,
    reader: &mut R,
) -> Result<Vec<Hash>, ProofError<R::Error>> {
    let ranges = consistency_ranges(old, new).ok_or(ProofError::OutOfRange)?;
    ranges
        .into_iter()
        .map(|(lo, hi)| range_hash(lo, hi, reader))
        .collect()
}

/// Verifies that `leaf` is the hash of entry `index` in the tree of `size`
/// leaves whose root is `root` (RFC 9162, 2.1.3.2).
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    size: u64,
    proof: &[Hash],
    root: &Hash,
) -> Result<(), VerifyError> {
    if index >= size {
        return Err(VerifyError::OutOfRange);
    }
    let mut f = index;
    let mut s = size - 1;
    let mut r = *leaf;
    for p in proof {
        if s == 0 {
            return Err(VerifyError::WrongLength);
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 {
        return Err(VerifyError::WrongLength);
    }
    if r != *root {
        return Err(VerifyError::RootMismatch);
    }
    Ok(())
}

/// Verifies a consistency proof from the tree of `old` leaves with root
/// `old_root` to the tree of `new` leaves with root `new_root` (RFC 9162,
/// 2.1.4.2).
///
/// An old size of 0 is consistent with every tree, with an empty proof, as
/// [TLOG-WITNESS] has it. Equal sizes need an empty proof and equal roots.
pub fn verify_consistency(
    old: u64,
    old_root: &Hash,
    new: u64,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<(), VerifyError> {
    if old > new {
        return Err(VerifyError::OutOfRange);
    }
    if old == 0 || old == new {
        if !proof.is_empty() {
            return Err(VerifyError::WrongLength);
        }
        if old == new && old_root != new_root {
            return Err(VerifyError::RootMismatch);
        }
        return Ok(());
    }
    let mut path = Vec::with_capacity(proof.len() + 1);
    if old.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    let (fr, sr) = consistency_roots(old, new, &path)?;
    if fr != *old_root || sr != *new_root {
        return Err(VerifyError::RootMismatch);
    }
    Ok(())
}

/// The two roots that a consistency path leads to, for `0 < old < new`:
/// RFC 9162 2.1.4.2's `fr` and `sr`.
///
/// `path` is the proof with the hash of the old tree in front when `old`
/// is a power of two, as in step 2 of the RFC's algorithm.
pub(crate) fn consistency_roots(
    old: u64,
    new: u64,
    path: &[Hash],
) -> Result<(Hash, Hash), VerifyError> {
    debug_assert!(0 < old && old < new);
    let (first, rest) = path.split_first().ok_or(VerifyError::WrongLength)?;
    let mut f = old - 1;
    let mut s = new - 1;
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let mut fr = *first;
    let mut sr = *first;
    for c in rest {
        if s == 0 {
            return Err(VerifyError::WrongLength);
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 {
        return Err(VerifyError::WrongLength);
    }
    Ok((fr, sr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{leaf_hash, root_from_leaf_hashes};

    /// A reader over all the leaf hashes, computing every node directly.
    pub(crate) struct Leaves(pub Vec<Hash>);

    impl HashReader for Leaves {
        type Error = ();
        fn node(&mut self, node: NodeId) -> Result<Hash, ()> {
            let start = usize::try_from(node.start()).map_err(|_| ())?;
            let end = usize::try_from(node.end().ok_or(())?).map_err(|_| ())?;
            self.0.get(start..end).map(root_from_leaf_hashes).ok_or(())
        }
    }

    fn hex(s: &str) -> Hash {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Hash::from_slice(&bytes).unwrap()
    }

    fn b64(s: &str) -> Hash {
        Hash::from_base64(s).unwrap()
    }

    /// The eight leaves of transparency-dev/merkle's reference tree
    /// (testonly/constants.go).
    fn reference_leaves() -> Vec<Hash> {
        [
            "",
            "00",
            "10",
            "2021",
            "3031",
            "40414243",
            "5051525354555657",
            "606162636465666768696a6b6c6d6e6f",
        ]
        .iter()
        .map(|s| {
            let bytes: Vec<u8> = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect();
            leaf_hash(&bytes)
        })
        .collect()
    }

    #[test]
    fn reference_roots() {
        // RootHashes() from transparency-dev/merkle testonly/constants.go.
        let roots = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        let leaves = reference_leaves();
        let mut reader = Leaves(leaves.clone());
        for (n, root) in roots.iter().enumerate() {
            assert_eq!(root_from_leaf_hashes(&leaves[..n]), hex(root), "size {n}");
            assert_eq!(
                tree_hash(n as u64, &mut reader).unwrap(),
                hex(root),
                "size {n}"
            );
        }
    }

    /// transparency-dev/merkle testdata/inclusion/*/happy-path.json.
    #[test]
    fn reference_inclusion_proofs() {
        let cases: &[(u64, u64, &str, &str, &[&str])] = &[
            (
                0,
                1,
                "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
                "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
                &[],
            ),
            (
                0,
                8,
                "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
                "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
                &[
                    "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
                    "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
                    "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ=",
                ],
            ),
            (
                5,
                8,
                "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
                "QnGia+DYqE8L1UyMMC58s6O10fpngKQLzOKHNHfatlg=",
                &[
                    "vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms=",
                    "yoVOoSjtBQtBs1/8G4e46yveRh6eO1WW7Oa51ZdaCuA=",
                    "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc=",
                ],
            ),
            (
                2,
                3,
                "rra8/idLcKFPsGel5VeCZNsPqbUa9eC6FZFY8yngbnc=",
                "ApjRIpBtz8EIkstTpzmS/FufST6kybrbJ7eRtBJ6f+c=",
                &["+sVCA+fMaWzw38tCySodnbr3CtnmIfS9jZhmLwDjwSU="],
            ),
            (
                1,
                5,
                "Tju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=",
                "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
                &[
                    "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
                    "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
                    "vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms=",
                ],
            ),
        ];
        let mut reader = Leaves(reference_leaves());
        for &(index, size, root, leaf, proof) in cases {
            let proof: Vec<Hash> = proof.iter().map(|s| b64(s)).collect();
            assert_eq!(reader.0[index as usize], b64(leaf));
            verify_inclusion(&b64(leaf), index, size, &proof, &b64(root)).unwrap();
            assert_eq!(
                inclusion_proof(index, size, &mut reader).unwrap(),
                proof,
                "{index} in {size}"
            );
        }
    }

    /// transparency-dev/merkle testdata/consistency/*/happy-path.json.
    #[test]
    fn reference_consistency_proofs() {
        let cases: &[(u64, u64, &str, &str, &[&str])] = &[
            (
                1,
                1,
                "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
                "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
                &[],
            ),
            (
                1,
                8,
                "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
                "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
                &[
                    "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
                    "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
                    "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ=",
                ],
            ),
            (
                6,
                8,
                "duZ9rbzfHhDht03cYIq9L5jfsW+851J3tSMqEn8gh+8=",
                "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
                &[
                    "DrxdNDf74tsVi58Sah0RjjCBgQMdCpSfje3t68VY72o=",
                    "yoVOoSjtBQtBs1/8G4e46yveRh6eO1WW7Oa51ZdaCuA=",
                    "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc=",
                ],
            ),
            (
                2,
                5,
                "+sVCA+fMaWzw38tCySodnbr3CtnmIfS9jZhmLwDjwSU=",
                "Tju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=",
                &[
                    "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
                    "vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms=",
                ],
            ),
            (
                6,
                7,
                "duZ9rbzfHhDht03cYIq9L5jfsW+851J3tSMqEn8gh+8=",
                "3bib5AOAnjJXUNPSY814kpwpQreUKjS3fhIslZSnTIw=",
                &[
                    "DrxdNDf74tsVi58Sah0RjjCBgQMdCpSfje3t68VY72o=",
                    "sIaT7C5yFZcTBkHoIR5+7cy0wmQTlj7ubB4u0W/7Gl8=",
                    "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc=",
                ],
            ),
        ];
        let mut reader = Leaves(reference_leaves());
        for &(old, new, old_root, new_root, proof) in cases {
            let proof: Vec<Hash> = proof.iter().map(|s| b64(s)).collect();
            verify_consistency(old, &b64(old_root), new, &b64(new_root), &proof).unwrap();
            assert_eq!(
                consistency_proof(old, new, &mut reader).unwrap(),
                proof,
                "{old} to {new}"
            );
        }
    }

    #[test]
    fn rejects_bad_inputs() {
        let leaves = reference_leaves();
        let mut reader = Leaves(leaves.clone());
        let root = tree_hash(8, &mut reader).unwrap();
        let proof = inclusion_proof(3, 8, &mut reader).unwrap();
        assert_eq!(
            verify_inclusion(&leaves[3], 8, 8, &proof, &root),
            Err(VerifyError::OutOfRange)
        );
        assert_eq!(
            verify_inclusion(&leaves[3], 3, 8, &proof[..2], &root),
            Err(VerifyError::WrongLength)
        );
        assert_eq!(
            verify_inclusion(&leaves[4], 3, 8, &proof, &root),
            Err(VerifyError::RootMismatch)
        );
        let mut long = proof.clone();
        long.push(root);
        assert_eq!(
            verify_inclusion(&leaves[3], 3, 8, &long, &root),
            Err(VerifyError::WrongLength)
        );
        assert_eq!(
            inclusion_proof(8, 8, &mut reader),
            Err(ProofError::OutOfRange)
        );
        assert_eq!(
            consistency_proof(5, 4, &mut reader),
            Err(ProofError::OutOfRange)
        );

        let old = tree_hash(3, &mut reader).unwrap();
        let cproof = consistency_proof(3, 8, &mut reader).unwrap();
        verify_consistency(3, &old, 8, &root, &cproof).unwrap();
        assert_eq!(
            verify_consistency(3, &root, 8, &root, &cproof),
            Err(VerifyError::RootMismatch)
        );
        assert_eq!(
            verify_consistency(3, &old, 8, &root, &[]),
            Err(VerifyError::WrongLength)
        );
        assert_eq!(
            verify_consistency(0, &old, 8, &root, &cproof),
            Err(VerifyError::WrongLength)
        );
        verify_consistency(0, &old, 8, &root, &[]).unwrap();
        assert_eq!(
            verify_consistency(8, &old, 8, &root, &[]),
            Err(VerifyError::RootMismatch)
        );
        assert_eq!(
            verify_consistency(8, &root, 3, &old, &[]),
            Err(VerifyError::OutOfRange)
        );
    }
}
