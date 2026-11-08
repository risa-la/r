//! HashWX, a proof-of-work hash, and the puzzle built on it.
//!
//! A clean-room implementation of HashWX, under the Apache License 2.0.
//!
//! It has two backends (see [`Backend`]). The JIT compiles each
//! function's programs to machine code, on x86-64 Linux and macOS with the
//! `jit` feature (on by default). The interpreter runs everywhere,
//! including where executable memory is not allowed, such as iOS, and
//! wherever the JIT cannot run: the JIT falls back to it by itself.
//! [`HashWx::with_backend`] and [`Puzzle::with_backend`] can force it.
//!
//! The JIT keeps strict W^X: a code buffer is writable or executable,
//! never both, with guard pages around it. The compiled code reaches only
//! its register file and the scratchpad, every scratchpad access masked
//! into range, and jumps only to targets fixed at compile time. The
//! crate's only unsafe code is the small module that maps the buffers
//! and calls the code.
//!
//! Without the JIT the crate is `no_std`: it needs only `core` and
//! `alloc`, for the boxed scratchpad. The JIT needs `std`.
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
#[cfg(any(
    test,
    all(
        feature = "jit",
        target_arch = "x86_64",
        any(target_os = "linux", target_os = "macos")
    )
))]
extern crate std;

mod hash;
mod jit;
mod program;
mod puzzle;
mod stream;
mod tables;

#[cfg(kani)]
mod proofs;
#[cfg(test)]
mod tests;

pub use hash::{Backend, HashWx, SCRATCHPAD_LEN, SEED_LEN, Scratchpad};
pub use program::{PROGRAM_COUNT, Program};
pub use puzzle::{CHALLENGE_LEN, Puzzle};
