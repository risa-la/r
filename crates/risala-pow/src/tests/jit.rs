//! The JIT against the interpreter: same hash, same registers and same
//! scratchpad, for every test vector and many random seeds and nonces.
//!
//! Where this build has no JIT, the JIT functions fall back to the
//! interpreter and these tests still pass; [`jit_runs_where_supported`]
//! checks that the JIT really runs on the platforms it is built for.

use std::thread;
use std::vec::Vec;

use sha2::{Digest as _, Sha256};

use super::{HASH_VECTORS, PUZZLE_VECTORS, nz, unhex};
use crate::hash::{Backend, HashWx, Scratchpad};
use crate::puzzle::Puzzle;

/// Whether this build compiles functions on this platform.
const JIT_BUILT: bool = cfg!(all(
    feature = "jit",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
));

fn jit(seed: &[u8; 32]) -> HashWx {
    let f = HashWx::with_backend(seed, Backend::Jit);
    if JIT_BUILT {
        assert_eq!(f.backend(), Backend::Jit);
    }
    f
}

fn interpreter(seed: &[u8; 32]) -> HashWx {
    let f = HashWx::with_backend(seed, Backend::Interpreter);
    assert_eq!(f.backend(), Backend::Interpreter);
    f
}

/// The JIT and the interpreter agree on the hash, the registers after the
/// read phase and the whole scratchpad, starting from a dirty scratchpad.
fn assert_same(seed: &[u8; 32], jit: &HashWx, interp: &HashWx, nonce: u64) -> u64 {
    let mut a = Scratchpad::new();
    let mut b = Scratchpad::new();
    a.bytes_mut().fill(0x5a);
    b.bytes_mut().fill(0xa5);
    let want = interp.hash(&mut b, nonce);
    assert_eq!(
        jit.hash(&mut a, nonce),
        want,
        "seed {seed:02x?} nonce {nonce}"
    );
    assert_eq!(
        a.bytes(),
        b.bytes(),
        "scratchpad, seed {seed:02x?} nonce {nonce}"
    );
    if let Some(regs) = jit.jit_registers(&mut a, nonce) {
        let t = interp.trace(&mut Scratchpad::new(), nonce);
        assert_eq!(
            regs[..8],
            t.after_read[..8],
            "seed {seed:02x?} nonce {nonce}"
        );
    }
    want
}

/// A deterministic run of seeds.
fn seeds(count: usize, salt: u8) -> impl Iterator<Item = [u8; 32]> {
    let mut seed = [salt; 32];
    (0..count).map(move |_| {
        seed = Sha256::digest(seed).into();
        seed
    })
}

/// Nonces from small to large, including the edges.
fn nonces(seed: &[u8; 32], count: usize) -> impl Iterator<Item = u64> {
    let mut x = u64::from_le_bytes(seed[..8].try_into().expect("8 bytes"));
    let fixed = [0, 1, u64::MAX, 1 << 63];
    fixed.into_iter().chain((0..count).map(move |i| {
        x = x.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(i as u64);
        x >> (i % 64)
    }))
}

/// A function can still be shared between threads with the JIT.
const _: () = {
    const fn send_and_sync<T: Send + Sync>() {}
    send_and_sync::<HashWx>();
    send_and_sync::<Puzzle>();
};

#[test]
fn jit_runs_where_supported() {
    if JIT_BUILT {
        assert_eq!(Backend::best_available(), Backend::Jit);
        assert_eq!(HashWx::new(&[0; 32]).backend(), Backend::Jit);
    } else {
        assert_eq!(Backend::best_available(), Backend::Interpreter);
        assert_eq!(HashWx::new(&[0; 32]).backend(), Backend::Interpreter);
    }
}

#[test]
fn jit_hash_vectors() {
    let mut scratchpad = Scratchpad::new();
    for v in &HASH_VECTORS {
        let seed = unhex(v.seed);
        let f = jit(&seed);
        assert_eq!(f.hash(&mut scratchpad, v.nonce), v.hash, "{}", v.name);
        assert_eq!(f.hash_one(v.nonce), v.hash, "{} (fresh)", v.name);
        assert_same(&seed, &f, &interpreter(&seed), v.nonce);
    }
}

#[test]
fn jit_puzzle_vectors() {
    for v in &PUZZLE_VECTORS {
        for backend in [Backend::Jit, Backend::Interpreter] {
            let p = Puzzle::new(unhex(v.challenge), nz(v.n), nz(v.d)).with_backend(backend);
            assert_eq!(p.backend(), backend);
            assert_eq!(p.hash(v.nonce), v.hash, "{} {backend:?}", v.name);
            assert!(p.verify(v.nonce), "{} {backend:?}", v.name);
            assert_eq!(
                p.solve(0, u64::MAX),
                Some(v.nonce),
                "{} {backend:?}",
                v.name
            );
        }
    }
    // The backend is not part of the puzzle.
    let p = Puzzle::new([1; 32], nz(2), nz(3));
    assert_eq!(p.clone().with_backend(Backend::Interpreter), p);
}

/// Many seeds and nonces, fast enough for every run.
#[test]
fn jit_matches_interpreter() {
    for seed in seeds(40, 1) {
        let (f, g) = (jit(&seed), interpreter(&seed));
        for nonce in nonces(&seed, 4) {
            assert_same(&seed, &f, &g, nonce);
        }
    }
}

/// Many more. Run with `cargo test --release -p risala-pow -- --ignored`.
#[test]
#[ignore = "slow; run in release"]
fn jit_matches_interpreter_long() {
    let mut count = 0u64;
    for seed in seeds(20_000, 2) {
        let (f, g) = (jit(&seed), interpreter(&seed));
        for nonce in nonces(&seed, 12) {
            assert_same(&seed, &f, &g, nonce);
            count += 1;
        }
    }
    assert_eq!(count, 20_000 * 16);
}

/// Functions made one after another reuse code buffers; clones share
/// code; several threads hash with one function, and make and drop
/// functions at once.
#[test]
fn jit_buffers_reuse_and_threads() {
    let seeds: Vec<[u8; 32]> = seeds(24, 3).collect();
    let want: Vec<u64> = seeds.iter().map(|s| interpreter(s).hash_one(77)).collect();
    for _ in 0..3 {
        for (seed, want) in seeds.iter().zip(&want) {
            // The clone outlives the original.
            let g = jit(seed).clone();
            assert_eq!(g.hash_one(77), *want);
        }
    }
    let shared = jit(&seeds[0]);
    thread::scope(|s| {
        for t in 0..4u64 {
            let (shared, seeds, want) = (&shared, &seeds, &want);
            s.spawn(move || {
                let mut scratchpad = Scratchpad::new();
                for (seed, w) in seeds.iter().zip(want) {
                    assert_eq!(shared.hash(&mut scratchpad, 77), want[0]);
                    let f = jit(seed);
                    assert_eq!(f.hash(&mut scratchpad, 77), *w, "thread {t}");
                }
            });
        }
    });
}
