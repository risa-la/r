//! The puzzle built on HashWX.

use core::num::NonZeroU64;

use sha2::{Digest as _, Sha256};

use crate::hash::{HashWx, SEED_LEN, Scratchpad};

/// Length of a puzzle challenge in bytes.
pub const CHALLENGE_LEN: usize = 32;

/// A HashWX puzzle: a challenge c, nonces per function n and a
/// difficulty d.
///
/// A nonce N solves it when `HashWX(seed(floor(N / n)), N) <= T`, with
/// `T = floor((2^64 - 1) / d)`. The puzzle does not stop a
/// solution being used twice and does not expire; the protocol around it
/// must do both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Puzzle {
    challenge: [u8; CHALLENGE_LEN],
    nonces_per_function: NonZeroU64,
    difficulty: NonZeroU64,
}

impl Puzzle {
    /// A puzzle with challenge c, n nonces per function and difficulty d.
    /// The challenge should be random and must not repeat.
    pub const fn new(
        challenge: [u8; CHALLENGE_LEN],
        nonces_per_function: NonZeroU64,
        difficulty: NonZeroU64,
    ) -> Self {
        Puzzle {
            challenge,
            nonces_per_function,
            difficulty,
        }
    }

    /// The challenge c.
    pub const fn challenge(&self) -> &[u8; CHALLENGE_LEN] {
        &self.challenge
    }

    /// Nonces per function, n.
    pub const fn nonces_per_function(&self) -> NonZeroU64 {
        self.nonces_per_function
    }

    /// The difficulty d.
    pub const fn difficulty(&self) -> NonZeroU64 {
        self.difficulty
    }

    /// The target `T = floor((2^64 - 1) / d)`.
    pub const fn target(&self) -> u64 {
        u64::MAX / self.difficulty.get()
    }

    /// The block of a nonce, `floor(N / n)`.
    pub const fn block(&self, nonce: u64) -> u64 {
        nonce / self.nonces_per_function.get()
    }

    /// The seed of block b, `SHA-256(c || le64bytes(b))`.
    pub fn seed(&self, block: u64) -> [u8; SEED_LEN] {
        let mut h = Sha256::new();
        h.update(self.challenge);
        h.update(block.to_le_bytes());
        h.finalize().into()
    }

    /// The hash function of block b.
    pub fn function(&self, block: u64) -> HashWx {
        HashWx::new(&self.seed(block))
    }

    /// The hash of a nonce under this puzzle: it makes the function for
    /// the nonce's own block and hashes the nonce once.
    pub fn hash(&self, nonce: u64) -> u64 {
        self.function(self.block(nonce)).hash_one(nonce)
    }

    /// Checks a solution. The block comes from the nonce
    /// alone, never from the solver. This costs one make and one hash,
    /// whatever the difficulty.
    pub fn verify(&self, nonce: u64) -> bool {
        self.hash(nonce) <= self.target()
    }

    /// Searches for a solution: tries nonces `start`,
    /// `start + 1`, ... in order, at most `max_tries` of them, and returns
    /// the first that solves the puzzle. It makes each block's function
    /// once and hashes that block's nonces with it. It stops without a
    /// solution after `max_tries` nonces or after nonce 2^64 - 1.
    pub fn solve(&self, start: u64, max_tries: u64) -> Option<u64> {
        let n = self.nonces_per_function.get();
        let target = self.target();
        let mut scratchpad = Scratchpad::new();
        let mut nonce = start;
        let mut left = max_tries;
        while left > 0 {
            let block = self.block(nonce);
            let last_in_block = last_nonce_of_block(block, n);
            let function = self.function(block);
            loop {
                if function.hash(&mut scratchpad, nonce) <= target {
                    return Some(nonce);
                }
                left -= 1;
                if left == 0 || nonce == u64::MAX {
                    return None;
                }
                let next_block = nonce == last_in_block;
                nonce += 1;
                if next_block {
                    break;
                }
            }
        }
        None
    }
}

/// The last nonce of block `block`, with `n` nonces per block: the nonce
/// before the next block starts, or 2^64 - 1 for the last block.
/// `block * n` is at most a nonce of the block, so only the addition can
/// overflow, and it saturates.
pub(crate) fn last_nonce_of_block(block: u64, n: u64) -> u64 {
    (block * n).saturating_add(n - 1)
}
