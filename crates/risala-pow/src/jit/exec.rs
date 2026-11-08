//! Executable memory: the only module of the crate with unsafe code.
//!
//! It maps a code buffer, has the compiler fill it, flips it from
//! writable to executable, and calls it. Strict W^X holds by type: a
//! buffer is either a [`Writable`] (read-write, never executable) or an
//! [`Executable`] (read-execute, never writable), and changing one into
//! the other consumes it. There is one mapping per buffer and no alias
//! of it, writable or otherwise. Each buffer has a guard page on either
//! side, mapped with no access.
//!
//! An [`Executable`] can only be made by [`Writable::compile`], which
//! fills the buffer with the output of the compiler and nothing else. So
//! the code [`Executable::run`] calls is always the compiler's, and the
//! soundness of `run` rests on the compiler's guarantees (see
//! `x86_64/mod.rs`): it touches only the register file and the
//! scratchpad it is given, follows the calling convention, and returns.

use core::ptr::NonNull;
use std::io;
use std::sync::OnceLock;

use super::arch;
use crate::hash::SCRATCHPAD_LEN;
use crate::program::{PROGRAM_COUNT, Program};

/// The system's page size.
fn page_size() -> usize {
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(|| {
        // SAFETY: sysconf only reads a system value.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(page)
            .ok()
            .filter(|p| p.is_power_of_two())
            .unwrap_or(4096)
    })
}

/// One mapping: a guard page, the code pages, a guard page.
struct Mapping {
    /// The start of the whole mapping, the first guard page.
    start: NonNull<u8>,
    /// The page size it was made with.
    page: usize,
    /// The bytes of code pages, a multiple of the page size.
    code_len: usize,
}

impl Mapping {
    /// Maps the guard pages and code pages with no access, then makes
    /// the code pages read-write.
    fn new() -> io::Result<Mapping> {
        let page = page_size();
        let code_len = arch::CODE_CAPACITY.next_multiple_of(page);
        let total = code_len + 2 * page;
        // SAFETY: a new private anonymous mapping, placed by the kernel,
        // with no access: it cannot overlap or change any memory in use.
        let p = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let Some(start) = NonNull::new(p.cast::<u8>()) else {
            return Err(io::Error::other("mmap returned null"));
        };
        let mapping = Mapping {
            start,
            page,
            code_len,
        };
        // On failure, dropping the mapping unmaps it.
        mapping.protect(libc::PROT_READ | libc::PROT_WRITE)?;
        Ok(mapping)
    }

    /// The first byte of code, after the first guard page.
    fn code(&self) -> *mut u8 {
        // The mapping is `code_len + 2 * page` bytes from `start`, so
        // this stays inside it.
        self.start.as_ptr().wrapping_add(self.page)
    }

    /// Sets the protection of the code pages. The guard pages keep none.
    fn protect(&self, prot: libc::c_int) -> io::Result<()> {
        // SAFETY: the code pages lie inside this mapping, which this
        // value owns alone; no other memory changes. Every caller holds
        // the mapping by value (a `Mapping` being made, or a `Writable` or
        // `Executable` being consumed), so no reference into the code
        // pages, and no running call of the code, is alive while their
        // access changes.
        let r = unsafe { libc::mprotect(self.code().cast(), self.code_len, prot) };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly the mapping made in `Mapping::new`, which
        // nothing refers to any more: the owner is being dropped, and
        // `Executable::run` borrows the owner while code runs.
        let r = unsafe { libc::munmap(self.start.as_ptr().cast(), self.code_len + 2 * self.page) };
        debug_assert_eq!(r, 0, "munmap failed");
    }
}

/// A code buffer that is read-write and not executable.
pub(crate) struct Writable(Mapping);

/// A code buffer that is read-execute and not writable, holding a
/// compiled function.
pub(crate) struct Executable(Mapping);

// SAFETY: the mapping is owned by this value alone, and moving it to
// another thread moves that ownership; nothing about it is tied to the
// thread that made it.
unsafe impl Send for Executable {}

// SAFETY: through `&Executable`, the code pages can only be run, never
// written. Running reads the code, which is read-only while this value
// exists, and writes only the buffers the caller lends `run` by `&mut`.
// So several threads can run it at once.
unsafe impl Sync for Executable {}

impl Writable {
    /// Maps a new code buffer.
    pub(crate) fn new() -> io::Result<Writable> {
        Mapping::new().map(Writable)
    }

    /// Compiles the programs into the buffer and makes it executable. On
    /// failure the buffer is unmapped.
    pub(crate) fn compile(self, programs: &[Program; PROGRAM_COUNT]) -> io::Result<Executable> {
        let m = self.0;
        {
            // SAFETY: the code pages are read-write (a `Writable` is only
            // made so, and only by `new` and `Executable::make_writable`),
            // `code_len` bytes long, and owned by `m`. This slice is the
            // only reference to them, and it ends before the protection
            // changes below.
            let code = unsafe { core::slice::from_raw_parts_mut(m.code(), m.code_len) };
            if arch::emit(programs, code).is_none() {
                return Err(io::Error::other("the JIT could not compile a program"));
            }
        }
        m.protect(libc::PROT_READ | libc::PROT_EXEC)?;
        Ok(Executable(m))
    }

    /// Makes the empty buffer executable without running it, to learn
    /// whether the system allows executable memory.
    pub(crate) fn probe(self) -> io::Result<()> {
        self.0.protect(libc::PROT_READ | libc::PROT_EXEC)
    }
}

impl Executable {
    /// Makes the buffer writable again, for reuse. It takes the value, so
    /// no one can be running the code.
    pub(crate) fn make_writable(self) -> io::Result<Writable> {
        self.0.protect(libc::PROT_READ | libc::PROT_WRITE)?;
        Ok(Writable(self.0))
    }

    /// Runs both phases of a hash: R0 to R8 in `regs`, the scratchpad in
    /// `scratchpad` with its R8 slot written. R0 to R7 come back in `regs`.
    pub(crate) fn run(&self, regs: &mut [u64; 9], scratchpad: &mut [u8; SCRATCHPAD_LEN]) {
        // SAFETY: the code pages hold a function the compiler emitted
        // (only `Writable::compile` makes an `Executable`), starting at
        // the first byte, and they are executable and stay mapped and
        // unchanged while `self` is borrowed. The function's type is
        // `arch::Entry`.
        let entry = unsafe { core::mem::transmute::<*mut u8, arch::Entry>(self.0.code()) };
        // SAFETY: the function follows the calling convention of
        // `arch::Entry`: it saves and restores the callee-saved registers
        // it uses and the stack pointer, and uses no stack beyond its own
        // pushes. It reads and writes only `regs[0..9]` and
        // `scratchpad[0..SCRATCHPAD_LEN]`, through the two pointers, which
        // are valid and exclusive for the call. Every scratchpad access is
        // masked into range by the instruction before it, and the
        // function always returns. See `x86_64/mod.rs` and the tests and
        // proofs of the compiler.
        unsafe { entry(regs.as_mut_ptr(), scratchpad.as_mut_ptr()) }
    }
}
