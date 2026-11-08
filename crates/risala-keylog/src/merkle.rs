//! The Merkle tree of RFC 6962 and RFC 9162, with SHA-256, as
//! [TLOG-TILES] uses it (SPEC 4.5).
//!
//! The tree over entries `D[0:n]` is RFC 9162's MTH:
//!
//! - `MTH({}) = SHA-256()`
//! - `MTH({d}) = SHA-256(0x00 || d)`
//! - `MTH(D[0:n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`, where
//!   `k` is the largest power of two smaller than `n`.
//!
//! A [`NodeId`] names a complete subtree: the `2^height` leaves starting at
//! `index << height`. Every hash a proof needs is either such a node or,
//! along the right edge of the tree, a range that folds from them
//! ([`range_nodes`]).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};

/// The length of a hash, in bytes.
pub const HASH_LEN: usize = 32;

/// A SHA-256 hash in the tree: a leaf hash, a node hash or a root.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; HASH_LEN]);

impl Hash {
    /// The hash's bytes.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// The hash in standard base64 with padding, as checkpoints and
    /// tlog-witness requests write it.
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }

    /// Reads a hash from canonical base64 with padding. Anything else,
    /// including non-zero trailing bits, is refused.
    pub fn from_base64(s: &str) -> Option<Hash> {
        // 32 bytes are always 44 characters; checking first keeps the
        // decoder from writing past `out`.
        if s.len() != 44 {
            return None;
        }
        let mut out = [0u8; HASH_LEN];
        match BASE64.decode_slice(s, &mut out) {
            Ok(HASH_LEN) => Some(Hash(out)),
            _ => None,
        }
    }

    /// Reads a hash from a 32-byte slice.
    pub fn from_slice(bytes: &[u8]) -> Option<Hash> {
        bytes.try_into().ok().map(Hash)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

/// The hash of an entry: `SHA-256(0x00 || entry)`.
pub fn leaf_hash(entry: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(entry);
    Hash(h.finalize().into())
}

/// The hash of an interior node: `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left.0);
    h.update(right.0);
    Hash(h.finalize().into())
}

/// The root of the empty tree, `SHA-256()`.
pub fn empty_root() -> Hash {
    Hash(Sha256::digest([]).into())
}

/// The root of the tree over these leaf hashes, computed directly from
/// RFC 9162's definition. Slow for big trees; for tests and small sets.
pub fn root_from_leaf_hashes(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_below(n as u64) as usize;
            node_hash(
                &root_from_leaf_hashes(&leaves[..k]),
                &root_from_leaf_hashes(&leaves[k..]),
            )
        }
    }
}

/// The hash of a complete binary tree whose leaves are `hashes`, whose
/// number must be a power of two. This is how a tile's hashes fold into
/// the nodes above them.
pub(crate) fn fold_complete(hashes: &[Hash]) -> Hash {
    debug_assert!(hashes.len().is_power_of_two());
    let mut level: Vec<Hash> = hashes.to_vec();
    while level.len() > 1 {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[l, r]| node_hash(l, r))
            .collect();
    }
    level[0]
}

/// The largest power of two strictly smaller than `n`, for `n >= 2`.
pub(crate) fn largest_power_of_two_below(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1 << (63 - (n - 1).leading_zeros())
}

/// A complete subtree: the `2^height` leaves from `index << height`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId {
    /// The subtree's height; 0 for a leaf.
    pub height: u8,
    /// The subtree's position among those of its height, from the left.
    pub index: u64,
}

impl NodeId {
    /// The first leaf the node covers.
    pub fn start(&self) -> u64 {
        self.index << self.height
    }

    /// One past the last leaf the node covers, or `None` if that does not
    /// fit in a `u64`.
    pub fn end(&self) -> Option<u64> {
        self.index
            .checked_add(1)
            .and_then(|i| i.checked_mul(1u64.checked_shl(u32::from(self.height))?))
    }

    /// Whether the node is complete in a tree of `size` leaves.
    pub fn is_in_tree(&self, size: u64) -> bool {
        self.height < 64 && self.end().is_some_and(|e| e <= size)
    }
}

/// Splits the range of leaves `[lo, hi)` into the complete subtrees whose
/// hashes fold, right to left, into the range's MTH ([`fold_range`]).
///
/// The range must be one that RFC 9162's proofs use: `lo` a multiple of a
/// power of two at least `hi - lo`. Returns `None` for any other range.
pub fn range_nodes(lo: u64, hi: u64) -> Option<Vec<NodeId>> {
    if lo >= hi {
        return None;
    }
    let mut nodes = Vec::new();
    let mut lo = lo;
    while lo < hi {
        let len = hi - lo;
        // The largest power of two no bigger than len.
        let height = 63 - len.leading_zeros();
        let k = 1u64 << height;
        if !lo.is_multiple_of(k) {
            return None;
        }
        nodes.push(NodeId {
            height: height as u8,
            index: lo >> height,
        });
        lo += k;
    }
    Some(nodes)
}

/// Folds the hashes of [`range_nodes`] into the range's MTH.
pub fn fold_range(hashes: &[Hash]) -> Option<Hash> {
    let (last, rest) = hashes.split_last()?;
    Some(rest.iter().rev().fold(*last, |acc, h| node_hash(h, &acc)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_match_rfc_6962() {
        // The root of the empty tree and the hash of the empty leaf, from
        // transparency-dev/merkle's testonly constants.
        assert_eq!(
            format!("{:?}", empty_root()),
            "Hash(e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)"
        );
        assert_eq!(
            format!("{:?}", leaf_hash(b"")),
            "Hash(6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d)"
        );
    }

    #[test]
    fn base64_is_strict() {
        let h = leaf_hash(b"x");
        assert_eq!(Hash::from_base64(&h.to_base64()), Some(h));
        // 32 zero bytes are 43 'A's and a pad; the 43rd character carries
        // two unused bits, which must be zero.
        let zeros = format!("{}=", "A".repeat(43));
        assert_eq!(Hash::from_base64(&zeros), Some(Hash([0; 32])));
        let trailing = format!("{}B=", "A".repeat(42));
        assert_eq!(Hash::from_base64(&trailing), None);
        assert_eq!(Hash::from_base64(&"A".repeat(44)), None);
        assert_eq!(Hash::from_base64(&h.to_base64()[..43]), None);
        assert_eq!(Hash::from_base64(" "), None);
    }

    #[test]
    fn ranges_split_into_aligned_nodes() {
        assert_eq!(
            range_nodes(4, 7).unwrap(),
            vec![
                NodeId {
                    height: 1,
                    index: 2
                },
                NodeId {
                    height: 0,
                    index: 6
                }
            ]
        );
        assert_eq!(
            range_nodes(0, 8).unwrap(),
            vec![NodeId {
                height: 3,
                index: 0
            }]
        );
        assert_eq!(range_nodes(1, 3), None);
        assert_eq!(range_nodes(3, 3), None);
    }

    #[test]
    fn node_ends_do_not_overflow() {
        let top = NodeId {
            height: 63,
            index: 1,
        };
        assert_eq!(top.end(), None);
        assert!(!top.is_in_tree(u64::MAX));
        assert!(
            NodeId {
                height: 63,
                index: 0
            }
            .is_in_tree(u64::MAX)
        );
    }
}
