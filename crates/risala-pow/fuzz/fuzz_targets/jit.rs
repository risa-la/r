//! The JIT against the interpreter, on any seed and nonces.
//!
//! The first 32 bytes are the seed; each further 8 bytes are a nonce, at
//! most 16 of them, and a short tail is a nonce too. Every nonce must hash
//! the same under both backends, on a fresh scratchpad and on one reused
//! across nonces, and through a clone of the compiled function. Making
//! and dropping functions input after input also exercises the reuse of
//! code buffers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use risala_pow::{Backend, HashWx, Scratchpad};

/// Whether this build compiles functions on this platform: x86-64 or
/// little-endian aarch64, on Linux, Android or macOS.
const JIT_BUILT: bool = cfg!(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "android", target_os = "macos")
));

fuzz_target!(|data: &[u8]| {
    let Some((seed, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let jit = HashWx::with_backend(seed, Backend::Jit);
    let interp = HashWx::with_backend(seed, Backend::Interpreter);
    if JIT_BUILT {
        assert_eq!(jit.backend(), Backend::Jit);
    }
    assert_eq!(interp.backend(), Backend::Interpreter);
    assert_eq!(jit.programs(), interp.programs());

    let nonces = rest.chunks(8).take(16).map(|c| {
        let mut b = [0u8; 8];
        b[..c.len()].copy_from_slice(c);
        u64::from_le_bytes(b)
    });
    let clone = jit.clone();
    let mut a = Scratchpad::new();
    let mut b = Scratchpad::new();
    for nonce in nonces {
        let want = interp.hash(&mut b, nonce);
        assert_eq!(jit.hash(&mut a, nonce), want, "seed {seed:02x?} nonce {nonce}");
        assert_eq!(clone.hash_one(nonce), want, "seed {seed:02x?} nonce {nonce}");
    }
});
