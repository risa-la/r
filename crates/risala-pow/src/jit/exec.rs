//! Executable memory: the only module of the crate with unsafe code.
//!
//! It maps a code buffer, has the compiler fill it, makes it executable,
//! keeps the instruction cache coherent, and calls it. W^X holds by type:
//! a buffer is either a [`Writable`] or an [`Executable`], and changing
//! one into the other consumes it. There is one mapping per buffer and no
//! alias of it, writable or otherwise. Each buffer has a guard page with
//! no access on either side.
//!
//! How a buffer changes between the two depends on the system:
//!
//! - Linux, Android, and macOS on x86-64: the code pages are read-write
//!   (never executable) while a [`Writable`], and read-execute (never
//!   writable) while an [`Executable`], set with `mprotect`. This is
//!   strict W^X: no thread can write the code while any thread can run
//!   it. On macOS the buffer is mapped with `MAP_JIT`, which the hardened
//!   runtime requires (with the `com.apple.security.cs.allow-jit`
//!   entitlement) before it lets memory become executable.
//! - macOS on Apple Silicon: the hardened runtime refuses `mprotect` to
//!   executable. Instead the buffer, guard pages included, is mapped once
//!   with `MAP_JIT` wherever the system puts it, and the guard pages then
//!   lose all access. The code pages never change protection: the system
//!   keeps a per-thread switch (`pthread_jit_write_protect_np`): a thread
//!   sees every `MAP_JIT` page either writable and not executable, or
//!   executable and not writable. Threads start on the second. Only
//!   [`Writable::compile`] turns the first on, for its own thread, while
//!   the compiler fills the buffer, and turns it off before returning,
//!   even on a panic. That is W^X per thread rather than per page: while
//!   one thread compiles, others may run JIT code, and the compiling
//!   thread could write any `MAP_JIT` page. The types still keep this
//!   crate from writing a buffer that any thread may be running.
//!
//! On aarch64 the instruction cache does not see data writes by itself.
//! After the code is written, [`Writable::compile`] cleans the data cache
//! and invalidates the instruction cache over it, and
//! [`Executable::run`] runs an `isb` before every call, so that whichever
//! core runs the code fetches the new instructions. See `sync_icache`.
//!
//! An [`Executable`] can only be made by [`Writable::compile`], which
//! fills the buffer with the output of the compiler and nothing else. So
//! the code [`Executable::run`] calls is always the compiler's, and the
//! soundness of `run` rests on the compiler's guarantees (see
//! `x86_64/mod.rs` and `aarch64/mod.rs`): it touches only the register
//! file and the scratchpad it is given, follows the calling convention,
//! and returns.

use core::ptr::NonNull;
use std::io;
use std::sync::OnceLock;

use super::arch;
use crate::hash::SCRATCHPAD_LEN;
use crate::program::{PROGRAM_COUNT, Program};

/// Why mapping JIT memory last failed, kept in test builds only, so a
/// test that expects the JIT can say why it fell back.
#[cfg(test)]
static LAST_FAILURE: std::sync::Mutex<Option<std::string::String>> = std::sync::Mutex::new(None);

/// Why mapping JIT memory last failed, if it has. Always `None` outside
/// macOS on Apple Silicon, which is the only system that records it.
#[cfg(test)]
pub(crate) fn last_failure() -> Option<std::string::String> {
    LAST_FAILURE.lock().ok()?.clone()
}

/// Whether this Mac has the per-thread write switch for `MAP_JIT` memory.
/// Apple Silicon hardware has it; virtual machines may not (GitHub's
/// macOS runners do not), and there the JIT is not used.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn write_switch_supported() -> bool {
    // SAFETY: only reads whether this system has the per-thread switch.
    unsafe { libc::pthread_jit_write_protect_supported_np() != 0 }
}

/// Records why mapping failed, in test builds.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn note(what: &str) {
    #[cfg(test)]
    if let Ok(mut last) = LAST_FAILURE.lock() {
        *last = Some(what.into());
    }
    let _ = what;
}

/// Records why mapping failed, with the system's error, in test builds.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn note_error(what: &str, e: &io::Error) {
    #[cfg(test)]
    note(&std::format!("{what}: {e}"));
    let _ = (what, e);
}

/// The system's page size, asked once: 4 KiB on x86-64, and 4, 16 or
/// 64 KiB on aarch64, depending on the kernel (16 KiB on Apple Silicon).
fn page_size() -> usize {
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(|| {
        // SAFETY: sysconf only reads a system value.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(page)
            .ok()
            .filter(|p| p.is_power_of_two() && *p >= 4096)
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

/// Maps `len` bytes of new private anonymous memory, placed by the
/// system, with `prot` and the extra `flags`. `hint` is where the system
/// should try to put it; it never replaces an existing mapping.
fn map(
    hint: *mut u8,
    len: usize,
    prot: libc::c_int,
    flags: libc::c_int,
) -> io::Result<NonNull<u8>> {
    // SAFETY: a new private anonymous mapping without MAP_FIXED, so the
    // system picks a free range (at `hint` only if it is free): it cannot
    // overlap or change any memory in use.
    let p = unsafe {
        libc::mmap(
            hint.cast(),
            len,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANON | flags,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    NonNull::new(p.cast::<u8>()).ok_or_else(|| io::Error::other("mmap returned null"))
}

/// The extra mmap flags of a code buffer on systems that use `mprotect`:
/// `MAP_JIT` on macOS, which its hardened runtime requires of memory that
/// is to become executable, and nothing elsewhere.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
const CODE_FLAGS: &[libc::c_int] = if cfg!(target_os = "macos") {
    // If the system does not take MAP_JIT, a plain mapping is tried: an
    // app without the hardened runtime can still make it executable.
    &[MAP_JIT, 0]
} else {
    &[0]
};

#[cfg(target_os = "macos")]
const MAP_JIT: libc::c_int = libc::MAP_JIT;
#[cfg(not(target_os = "macos"))]
const MAP_JIT: libc::c_int = 0;

impl Mapping {
    /// Maps the guard pages and code pages with no access, then makes
    /// the code pages read-write.
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn new() -> io::Result<Mapping> {
        let page = page_size();
        let code_len = arch::CODE_CAPACITY.next_multiple_of(page);
        let total = code_len + 2 * page;
        let mut result = Err(io::Error::other("no mapping tried"));
        for &flags in CODE_FLAGS {
            result = map(core::ptr::null_mut(), total, libc::PROT_NONE, flags);
            if result.is_ok() {
                break;
            }
        }
        let mapping = Mapping {
            start: result?,
            page,
            code_len,
        };
        // On failure, dropping the mapping unmaps it.
        mapping.protect(libc::PROT_READ | libc::PROT_WRITE)?;
        Ok(mapping)
    }

    /// Maps the guard pages and the code pages as one `MAP_JIT` mapping,
    /// read-write-execute, then takes all access away from its first and
    /// last page, the guard pages. Each thread sees the code pages as its
    /// write switch says.
    ///
    /// The system places `MAP_JIT` memory itself, at a random address on
    /// Apple Silicon, so the guard pages cannot be separate mappings
    /// placed around it: they are part of it.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn new() -> io::Result<Mapping> {
        if !write_switch_supported() {
            note("pthread_jit_write_protect_supported_np() is 0");
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        let page = page_size();
        let code_len = arch::CODE_CAPACITY.next_multiple_of(page);
        let total = code_len + 2 * page;
        let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let start = match map(core::ptr::null_mut(), total, prot, MAP_JIT) {
            Ok(start) => start,
            Err(e) => {
                note_error("mmap MAP_JIT", &e);
                // Only running out of memory is worth trying again; any
                // other error means this process gets no JIT memory (no
                // allow-jit entitlement under the hardened runtime).
                return Err(if e.raw_os_error() == Some(libc::ENOMEM) {
                    e
                } else {
                    io::Error::from_raw_os_error(libc::EPERM)
                });
            }
        };
        // From here, dropping the `Mapping` unmaps all of it.
        let mapping = Mapping {
            start,
            page,
            code_len,
        };
        for guard in [
            mapping.start.as_ptr(),
            mapping.code().wrapping_add(code_len),
        ] {
            // SAFETY: changes only a page of the mapping just made, which
            // nothing else knows of: its first page or its last.
            if unsafe { libc::mprotect(guard.cast(), page, libc::PROT_NONE) } != 0 {
                note_error(
                    "mprotect of a MAP_JIT guard page",
                    &io::Error::last_os_error(),
                );
                // Without guard pages the JIT is not used.
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
        }
        Ok(mapping)
    }

    /// The first byte of code, after the first guard page.
    fn code(&self) -> *mut u8 {
        // The mapping is `code_len + 2 * page` bytes from `start`, so
        // this stays inside it.
        self.start.as_ptr().wrapping_add(self.page)
    }

    /// The code pages as the compiler's units: bytes on x86-64,
    /// instruction words on aarch64.
    fn code_units(&self) -> *mut arch::Unit {
        self.code().cast()
    }

    /// How many units the code pages hold. Pages are a whole number of
    /// units.
    fn code_units_len(&self) -> usize {
        self.code_len / core::mem::size_of::<arch::Unit>()
    }

    /// Sets the protection of the code pages. The guard pages keep none.
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
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
        // SAFETY: unmaps exactly the range made in `Mapping::new`, which
        // nothing refers to any more: the owner is being dropped, and
        // `Executable::run` borrows the owner while code runs.
        let r = unsafe { libc::munmap(self.start.as_ptr().cast(), self.code_len + 2 * self.page) };
        debug_assert_eq!(r, 0, "munmap failed");
    }
}

/// While alive, the `MAP_JIT` pages are writable and not executable for
/// this thread. Dropping it, even in a panic, makes them executable and
/// not writable again.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct WriteWindow;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl WriteWindow {
    fn open() -> WriteWindow {
        // SAFETY: changes only this thread's view of `MAP_JIT` pages. It
        // runs no JIT code until the window is dropped: the window lives
        // only in `Writable::compile`, around the compiler, which is safe
        // Rust and calls no JIT code.
        unsafe { libc::pthread_jit_write_protect_np(0) };
        WriteWindow
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for WriteWindow {
    fn drop(&mut self) {
        // SAFETY: makes this thread's view of `MAP_JIT` pages executable
        // and not writable again, as a thread starts; nothing here holds
        // a reference into them.
        unsafe { libc::pthread_jit_write_protect_np(1) };
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe extern "C" {
    /// Makes the instruction cache coherent with data written at
    /// `start..start + len` (libkern/OSCacheControl.h).
    fn sys_icache_invalidate(start: *mut libc::c_void, len: libc::size_t);
}

/// Makes the instruction stream coherent with the code just written at
/// `start..start + len`, on Linux and Android on aarch64.
///
/// The sequence is the architecture's for code written as data: clean
/// each data cache line to the point of unification (`dc cvau`), wait
/// for that (`dsb ish`), invalidate each instruction cache line
/// (`ic ivau`), wait for that too (`dsb ish`), then `isb`. The
/// invalidations are broadcast to every core in the inner shareable
/// domain, so after the second `dsb` no core holds a stale line; each
/// core that runs the code also needs a context synchronization event
/// to drop instructions it fetched before, which is the `isb` that
/// [`Executable::run`] executes before every call (moving the thread to
/// another core is one too).
///
/// The line sizes come from CTR_EL0, read on every call, not cached. A
/// big.LITTLE system can have cores with different line sizes. Linux
/// gives user space the system-wide safe value, the smallest line sizes
/// of any core, trapping the read when the cores differ. On
/// a kernel that does not, a thread could read a big core's 128-byte
/// line and step past half the lines of a little core with 64-byte
/// lines, so the step is also capped at 64 bytes, the smallest line of
/// any 64-bit Arm core we know of. A smaller step than a line costs only
/// repeated maintenance of the same line. Kernels also trap and fix
/// these instructions on cores with errata that need it.
///
/// `__clear_cache` does the same, but where it lives (libgcc,
/// compiler-rt) differs between Linux and Android toolchains; this keeps
/// the sequence, and the reasoning, in one place.
#[cfg(all(target_arch = "aarch64", not(target_os = "macos")))]
fn sync_icache(start: *const u8, len: usize) {
    /// The most bytes to step by.
    const MAX_STEP: usize = 64;
    let ctr: u64;
    // SAFETY: reads CTR_EL0, the cache type register, which Linux lets
    // user space read (directly, or by trapping and emulating it); it
    // touches no memory.
    unsafe {
        core::arch::asm!(
            "mrs {ctr}, ctr_el0",
            ctr = out(reg) ctr,
            options(nomem, nostack, preserves_flags),
        );
    }
    // IminLine (bits 3:0) and DminLine (bits 19:16): log2 of the
    // smallest line, in 4-byte words.
    let i_line = 4usize << (ctr & 15);
    let d_line = 4usize << ((ctr >> 16) & 15);
    let step = i_line.min(d_line).min(MAX_STEP);
    let first = start as usize & !(step - 1);
    let end = start as usize + len;
    // SAFETY: cache maintenance by address over `first..end`, which lies
    // within the code pages (rounded down to a line, within the same
    // page), mapped and readable. It changes no memory and no register
    // but the scratch one and the flags.
    unsafe {
        core::arch::asm!(
            "mov {a}, {first}",
            "2:",
            "dc cvau, {a}",
            "add {a}, {a}, {step}",
            "cmp {a}, {end}",
            "b.lo 2b",
            "dsb ish",
            "mov {a}, {first}",
            "3:",
            "ic ivau, {a}",
            "add {a}, {a}, {step}",
            "cmp {a}, {end}",
            "b.lo 3b",
            "dsb ish",
            "isb",
            first = in(reg) first,
            end = in(reg) end,
            step = in(reg) step,
            a = out(reg) _,
            options(nostack),
        );
    }
}

/// A code buffer that is writable and not executable.
pub(crate) struct Writable(Mapping);

/// A code buffer that is executable and not writable, holding a compiled
/// function.
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
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn compile(self, programs: &[Program; PROGRAM_COUNT]) -> io::Result<Executable> {
        let m = self.0;
        let len = {
            // SAFETY: the code pages are read-write (a `Writable` is only
            // made so, and only by `new` and `Executable::make_writable`),
            // `code_len` bytes long, start on a page boundary (so aligned
            // for any unit) and are owned by `m`. Any bytes are valid
            // units. This slice is the only reference to them, and it ends
            // before the protection changes below.
            let code =
                unsafe { core::slice::from_raw_parts_mut(m.code_units(), m.code_units_len()) };
            arch::emit(programs, code)
                .ok_or_else(|| io::Error::other("the JIT could not compile a program"))?
        };
        m.protect(libc::PROT_READ | libc::PROT_EXEC)?;
        #[cfg(target_arch = "aarch64")]
        sync_icache(m.code(), len);
        #[cfg(not(target_arch = "aarch64"))]
        let _ = len;
        Ok(Executable(m))
    }

    /// Compiles the programs into the buffer, in a write window of this
    /// thread, and makes the instruction cache see them. On failure the
    /// buffer is unmapped.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn compile(self, programs: &[Program; PROGRAM_COUNT]) -> io::Result<Executable> {
        let m = self.0;
        let len = {
            let _window = WriteWindow::open();
            // SAFETY: the code pages are mapped `MAP_JIT`, so writable by
            // this thread while the window is open, which it is until the
            // end of this block, after the slice's last use. They are
            // `code_len` bytes long, start on a page boundary (so aligned
            // for any unit) and are owned by `m`, and no thread runs them:
            // an `Executable` of this buffer was consumed to make this
            // `Writable`, or none was ever made. Any bytes are valid units.
            // This slice is the only reference to them.
            let code =
                unsafe { core::slice::from_raw_parts_mut(m.code_units(), m.code_units_len()) };
            arch::emit(programs, code)
                .ok_or_else(|| io::Error::other("the JIT could not compile a program"))?
        };
        // SAFETY: the range lies within the code pages, written above
        // with the window now closed.
        unsafe { sys_icache_invalidate(m.code().cast(), len) };
        Ok(Executable(m))
    }

    /// Makes the empty buffer executable without running it, to learn
    /// whether the system allows executable memory.
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn probe(self) -> io::Result<()> {
        self.0.protect(libc::PROT_READ | libc::PROT_EXEC)
    }

    /// With `MAP_JIT`, a buffer that could be mapped is already
    /// executable: the system said yes when it mapped it.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn probe(self) -> io::Result<()> {
        Ok(())
    }
}

impl Executable {
    /// Makes the buffer writable again, for reuse. It takes the value, so
    /// no one can be running the code.
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn make_writable(self) -> io::Result<Writable> {
        self.0.protect(libc::PROT_READ | libc::PROT_WRITE)?;
        Ok(Writable(self.0))
    }

    /// Makes the buffer a [`Writable`] again, for reuse. It takes the
    /// value, so no one can be running the code. Nothing changes in the
    /// system: [`Writable::compile`] opens the write window.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn make_writable(self) -> io::Result<Writable> {
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
        // The code was written, and the caches made coherent, before this
        // value reached this thread. On aarch64 this core may still hold
        // instructions it fetched from these addresses before (for code
        // an earlier function left in a reused buffer): an `isb` drops
        // them.
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: an instruction barrier: it changes no register or
            // memory.
            unsafe { core::arch::asm!("isb", options(nostack, preserves_flags)) };
        }
        // SAFETY: the function follows the calling convention of
        // `arch::Entry`: it saves and restores the callee-saved registers
        // it uses and the stack pointer, and uses no stack beyond its own
        // pushes (on aarch64 it touches neither). It reads and writes only
        // `regs[0..9]` and `scratchpad[0..SCRATCHPAD_LEN]`, through the
        // two pointers, which are valid and exclusive for the call. Every
        // scratchpad access is masked into range by the instructions just
        // before it, and the function always returns. See `x86_64/mod.rs`
        // and `aarch64/mod.rs`, and the tests and proofs of the
        // compilers.
        unsafe { entry(regs.as_mut_ptr(), scratchpad.as_mut_ptr()) }
    }
}
