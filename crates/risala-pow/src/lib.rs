//! HashWX, a proof-of-work hash, and the puzzle built on it.
//!
//! A clean-room implementation of HashWX, under the Apache License 2.0.
//! It interprets the generated programs and does not compile them to
//! machine code, so it runs where executable memory is not allowed, such
//! as iOS.
//!
//! It is `no_std`: it needs only `core` and `alloc`, for the boxed
//! scratchpad.
//!
//! The parts:
//!
//! - [`HashWx`] is a hash function made from a 32-byte seed: 32 small
//!   programs and a hashing key. It maps a 64-bit nonce to a
//!   64-bit result. Make it once per seed and reuse it.
//! - [`Scratchpad`] is the 16 KiB memory of one hash in flight. Reuse one
//!   per thread to hash without allocating.
//! - [`Puzzle`] is a puzzle built on it: find a nonce whose hash, under
//!   a function picked by the nonce's block, is at most a target.
//!
//! ```
//! use risala_pow::{HashWx, Scratchpad};
//!
//! let seed = *b"risala proof of work test seed 1";
//! let hashwx = HashWx::new(&seed);
//! let mut scratchpad = Scratchpad::new();
//! assert_eq!(hashwx.hash(&mut scratchpad, 0), 0xe40faca40ffc1aa6);
//! ```

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod hash;
mod program;
mod puzzle;
mod stream;
mod tables;

#[cfg(kani)]
mod proofs;
#[cfg(test)]
mod tests;

pub use hash::{HashWx, SCRATCHPAD_LEN, SEED_LEN, Scratchpad};
pub use program::{PROGRAM_COUNT, Program};
pub use puzzle::{CHALLENGE_LEN, Puzzle};
