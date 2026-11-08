//! Deciding whether to compile, and reusing code buffers.

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};
use std::cell::RefCell;
use std::io;
use std::sync::Arc;
use std::vec::Vec;

use super::exec::{Executable, Writable};
use crate::hash::SCRATCHPAD_LEN;
use crate::program::{PROGRAM_COUNT, Program};

/// Spare code buffers a thread keeps for reuse. Reusing one costs two
/// `mprotect` calls; a new one also costs `mmap`, `munmap` and the page
/// faults of first use.
const SPARES_PER_THREAD: usize = 4;

std::thread_local! {
    /// Code buffers of dropped functions, executable, waiting to be made
    /// writable for the next function this thread makes.
    static SPARES: RefCell<Vec<Executable>> = const { RefCell::new(Vec::new()) };
}

/// Whether executable memory works here: not yet known, yes, or no.
static STATE: AtomicU8 = AtomicU8::new(UNKNOWN);
const UNKNOWN: u8 = 0;
const AVAILABLE: u8 = 1;
const REFUSED: u8 = 2;

/// The compiled code of one function, shared by its clones.
#[derive(Clone)]
pub(crate) struct Jit(Arc<Code>);

/// Owns a code buffer, and gives it to the thread's spares when the last
/// clone is dropped.
struct Code(Option<Executable>);

impl Drop for Code {
    fn drop(&mut self) {
        let Some(code) = self.0.take() else {
            return;
        };
        // During thread exit the spares may be gone; the buffer is then
        // unmapped, as it is when there are enough spares.
        let _ = SPARES.try_with(|spares| {
            if let Ok(mut spares) = spares.try_borrow_mut()
                && spares.len() < SPARES_PER_THREAD
            {
                spares.push(code);
            }
        });
    }
}

impl fmt::Debug for Jit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Jit")
    }
}

impl Jit {
    /// Runs both phases of a hash. See [`Executable::run`].
    #[inline]
    pub(crate) fn run(&self, regs: &mut [u64; 9], scratchpad: &mut [u8; SCRATCHPAD_LEN]) {
        if let Some(code) = &self.0.0 {
            code.run(regs, scratchpad);
        }
    }
}

/// Records a failure to map or protect memory. A refusal by policy
/// (SELinux, a hardened kernel, a sandbox, macOS's hardened runtime) turns
/// the JIT off for the rest of the process, so the system is not asked,
/// and does not log a denial, for every function.
fn note_failure(e: &io::Error) {
    if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
        STATE.store(REFUSED, Ordering::Relaxed);
    }
}

/// Whether the system allows executable memory, asking it once.
pub(crate) fn available() -> bool {
    match STATE.load(Ordering::Relaxed) {
        AVAILABLE => true,
        REFUSED => false,
        _ => match Writable::new().and_then(Writable::probe) {
            Ok(()) => {
                // A refusal noted meanwhile wins.
                let _ = STATE.compare_exchange(
                    UNKNOWN,
                    AVAILABLE,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
                STATE.load(Ordering::Relaxed) == AVAILABLE
            }
            Err(e) => {
                note_failure(&e);
                false
            }
        },
    }
}

/// Compiles the programs, or returns `None` if executable memory cannot be
/// had.
pub(crate) fn compile(programs: &[Program; PROGRAM_COUNT]) -> Option<Jit> {
    if STATE.load(Ordering::Relaxed) == REFUSED {
        return None;
    }
    let spare = SPARES
        .try_with(|spares| spares.try_borrow_mut().ok()?.pop())
        .ok()
        .flatten();
    let buffer = match spare {
        Some(code) => code.make_writable(),
        None => Writable::new(),
    };
    match buffer.and_then(|b| b.compile(programs)) {
        Ok(code) => Some(Jit(Arc::new(Code(Some(code))))),
        Err(e) => {
            note_failure(&e);
            None
        }
    }
}
