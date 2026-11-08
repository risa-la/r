//! The JIT: compiles a function's 32 programs to machine code.
//!
//! It is built with the `jit` feature on x86-64 and little-endian aarch64,
//! on Linux, Android and macOS. Elsewhere, including iOS, tvOS, watchOS
//! and visionOS, where Apple forbids executable memory, [`compile`] never
//! compiles anything, and the interpreter runs.
//!
//! The parts:
//!
//! - `x86_64` and `aarch64` (safe code) emit the machine code into a byte
//!   slice (of bytes, or of instruction words on aarch64). Each has the
//!   same interface, `emit`, `CODE_CAPACITY`, `Entry` and `Unit`, and the
//!   one for the target is picked as `arch` below.
//! - `exec` (the crate's only unsafe code) maps code buffers, flips them
//!   between writable and executable, keeps the instruction cache
//!   coherent, and calls the code.
//! - `native` decides whether to compile, keeps spare code buffers for
//!   reuse, and remembers when the system refuses executable memory.
//!
//! Both compilers are built for tests and proofs on every host, so the
//! aarch64 encoder's tests, static verifier and Kani proofs run on
//! x86-64 too, and the other way round.

/// Whether this build compiles functions on this platform: the `jit`
/// feature, an architecture with a compiler, and a system that may give
/// executable memory.
#[cfg(test)]
pub(crate) const BUILT: bool = cfg!(all(
    feature = "jit",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos"
    )
));

#[cfg(all(
    feature = "jit",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "android", target_os = "macos")
))]
#[allow(unsafe_code)]
mod exec;
#[cfg(all(
    feature = "jit",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "android", target_os = "macos")
))]
mod native;
#[cfg(all(
    feature = "jit",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "android", target_os = "macos")
))]
pub(crate) use native::{Jit, available, compile};

#[cfg(all(
    feature = "jit",
    target_arch = "aarch64",
    target_endian = "little",
    any(target_os = "linux", target_os = "android", target_os = "macos")
))]
use aarch64 as arch;
#[cfg(all(
    feature = "jit",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "android", target_os = "macos")
))]
use x86_64 as arch;

// The compilers are safe code. Each is built where it is the JIT, and
// for tests and proofs on every host; elsewhere (iOS among them) neither
// is built at all.
#[cfg(any(
    test,
    kani,
    all(
        feature = "jit",
        target_arch = "x86_64",
        any(target_os = "linux", target_os = "android", target_os = "macos")
    )
))]
#[cfg_attr(
    not(all(
        feature = "jit",
        target_arch = "x86_64",
        any(target_os = "linux", target_os = "android", target_os = "macos")
    )),
    allow(dead_code)
)]
pub(crate) mod x86_64;

#[cfg(any(
    test,
    kani,
    all(
        feature = "jit",
        target_arch = "aarch64",
        target_endian = "little",
        any(target_os = "linux", target_os = "android", target_os = "macos")
    )
))]
#[cfg_attr(
    not(all(
        feature = "jit",
        target_arch = "aarch64",
        target_endian = "little",
        any(target_os = "linux", target_os = "android", target_os = "macos")
    )),
    allow(dead_code)
)]
pub(crate) mod aarch64;

#[cfg(not(all(
    feature = "jit",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "android", target_os = "macos")
)))]
pub(crate) use stub::{Jit, available, compile};

/// No JIT on this platform or build.
#[cfg(not(all(
    feature = "jit",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "android", target_os = "macos")
)))]
mod stub {
    use crate::hash::SCRATCHPAD_LEN;
    use crate::program::{PROGRAM_COUNT, Program};

    /// There is never a value of this type.
    #[derive(Clone, Debug)]
    pub(crate) enum Jit {}

    impl Jit {
        pub(crate) fn run(&self, _: &mut [u64; 9], _: &mut [u8; SCRATCHPAD_LEN]) {
            match *self {}
        }
    }

    pub(crate) fn available() -> bool {
        false
    }

    pub(crate) fn compile(_: &[Program; PROGRAM_COUNT]) -> Option<Jit> {
        None
    }
}
