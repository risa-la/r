//! The JIT: compiles a function's 32 programs to machine code.
//!
//! It is built with the `jit` feature on x86-64 Linux and macOS. Elsewhere
//! [`compile`] never compiles anything, and the interpreter runs.
//!
//! The parts:
//!
//! - `x86_64` (safe code) emits the machine code into a byte slice. A
//!   later `aarch64` module will sit beside it with the same interface:
//!   `emit`, `CODE_CAPACITY` and `Entry`, picked as `arch` below.
//! - `exec` (the crate's only unsafe code) maps code buffers, flips them
//!   between writable and executable, and calls the code.
//! - `native` decides whether to compile, keeps spare code buffers for
//!   reuse, and remembers when the system refuses executable memory.

#[cfg(all(
    feature = "jit",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
#[allow(unsafe_code)]
mod exec;
#[cfg(all(
    feature = "jit",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
mod native;
#[cfg(all(
    feature = "jit",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) use native::{Jit, available, compile};
#[cfg(all(
    feature = "jit",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
use x86_64 as arch;

// The compiler is safe code. It is built on every x86-64 target, so its
// tests and proofs run on any x86-64 host.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(
    not(all(feature = "jit", any(target_os = "linux", target_os = "macos"))),
    allow(dead_code)
)]
pub(crate) mod x86_64;

#[cfg(not(all(
    feature = "jit",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
)))]
pub(crate) use stub::{Jit, available, compile};

/// No JIT on this platform or build.
#[cfg(not(all(
    feature = "jit",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
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
