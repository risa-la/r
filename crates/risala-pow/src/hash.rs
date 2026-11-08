//! Making a hash function from a seed and hashing nonces.

use alloc::boxed::Box;

use crate::jit::Jit;
use crate::program::{PROGRAM_COUNT, Program, build_programs};
use crate::stream::{WordStream, key_words, sip_round};

/// Length of a HashWX seed in bytes.
pub const SEED_LEN: usize = 32;

/// Size of the scratchpad M in bytes: 16384 bytes written by `SAVE` and an
/// 8-byte slot holding R8.
pub const SCRATCHPAD_LEN: usize = 16392;

/// Where the R8 slot starts, and the first value of the save pointer P.
pub(crate) const R8_SLOT: usize = 16384;

/// Read addresses are the low 14 bits of a register.
const ADDRESS_MASK: u64 = 16383;

/// Rounds in each of the write and read phases.
pub(crate) const ROUNDS: usize = 4;

/// The loop budget C at the start of each round.
pub(crate) const LOOP_BUDGET: u32 = 32;

/// What runs a function's programs.
///
/// Both give the same hash for every seed and nonce. The JIT is about ten
/// times faster, and runs only on x86-64 Linux and macOS, with the `jit`
/// feature (on by default), where the system allows executable memory.
/// Elsewhere the interpreter runs, whatever is asked for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Backend {
    /// The portable interpreter, which needs no executable memory.
    Interpreter,
    /// Machine code compiled for the function, where available; else the
    /// interpreter. The default.
    #[default]
    Jit,
}

impl Backend {
    /// The backend [`HashWx::new`] uses here: [`Backend::Jit`] if this
    /// build has a JIT for this platform and the system allows executable
    /// memory, else [`Backend::Interpreter`]. The first call may map and
    /// unmap a page to find out; later calls only read a flag.
    pub fn best_available() -> Backend {
        if crate::jit::available() {
            Backend::Jit
        } else {
            Backend::Interpreter
        }
    }
}

/// A hash function made from a 32-byte seed: the 32 programs and the
/// hashing key, and the programs compiled to machine code if the JIT is
/// used.
///
/// Make it once per seed and hash many nonces with it. It
/// never changes after it is
/// made, so it can be shared between threads; each thread brings its own
/// [`Scratchpad`]. Clones share the compiled code.
#[derive(Clone, Debug)]
pub struct HashWx {
    programs: [Program; PROGRAM_COUNT],
    /// The hashing key `seed[16..32]`, as two words.
    key: [u64; 2],
    /// The compiled programs, if the JIT is used.
    jit: Option<Jit>,
}

/// The 16392-byte scratchpad M of one hash in flight.
///
/// It holds no state between hashes: every hash writes all of it before
/// reading it. It exists so that one buffer can be reused
/// for many hashes, with no allocation per hash.
#[derive(Clone)]
pub struct Scratchpad {
    mem: Box<[u8; SCRATCHPAD_LEN]>,
}

impl Scratchpad {
    /// Allocates a scratchpad.
    pub fn new() -> Self {
        let mem = alloc::vec![0u8; SCRATCHPAD_LEN]
            .into_boxed_slice()
            .try_into()
            .expect("the vector has SCRATCHPAD_LEN bytes");
        Scratchpad { mem }
    }

    /// All 16392 bytes, as left by the last hash.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8; SCRATCHPAD_LEN] {
        &self.mem
    }

    #[cfg(test)]
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; SCRATCHPAD_LEN] {
        &mut self.mem
    }
}

impl Default for Scratchpad {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Scratchpad {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scratchpad").finish_non_exhaustive()
    }
}

impl HashWx {
    /// Makes the hash function for a seed, compiled by the JIT where
    /// available. Every seed works.
    pub fn new(seed: &[u8; SEED_LEN]) -> Self {
        Self::with_backend(seed, Backend::Jit)
    }

    /// Makes the hash function for a seed with the given backend.
    /// [`Backend::Interpreter`] never compiles; [`Backend::Jit`] compiles
    /// where it can and falls back to the interpreter where it cannot,
    /// such as where the system refuses executable memory.
    /// [`HashWx::backend`] tells which runs.
    pub fn with_backend(seed: &[u8; SEED_LEN], backend: Backend) -> Self {
        let (program_key, hash_key) = seed.split_at(16);
        let program_key: &[u8; 16] = program_key.try_into().expect("16 bytes");
        let hash_key: &[u8; 16] = hash_key.try_into().expect("16 bytes");
        let programs = build_programs(key_words(program_key));
        let jit = match backend {
            Backend::Jit => crate::jit::compile(&programs),
            Backend::Interpreter => None,
        };
        HashWx {
            programs,
            key: key_words(hash_key),
            jit,
        }
    }

    /// The backend that runs this function.
    pub fn backend(&self) -> Backend {
        if self.jit.is_some() {
            Backend::Jit
        } else {
            Backend::Interpreter
        }
    }

    /// The 32 programs, in order. Their
    /// [`Display`](core::fmt::Display) form is a one-line listing.
    pub fn programs(&self) -> &[Program; PROGRAM_COUNT] {
        &self.programs
    }

    /// Hashes a nonce, using `scratchpad` as the memory M.
    ///
    /// This takes `&self` and a separate `&mut Scratchpad` so that one
    /// function can be shared by several threads, each with its own
    /// scratchpad, and so that hashing does not allocate.
    pub fn hash(&self, scratchpad: &mut Scratchpad, nonce: u64) -> u64 {
        if let Some(jit) = &self.jit {
            let mut regs = start_registers(self.key, nonce, &mut scratchpad.mem);
            jit.run(&mut regs, &mut scratchpad.mem);
            return finish(&regs);
        }
        let mut m = Machine::start(self.key, nonce, &mut scratchpad.mem);
        m.write_phase(&self.programs);
        m.read_phase(&self.programs);
        m.finish()
    }

    /// R0 to R8 after the read phase, from the compiled code, or `None`
    /// if this function is interpreted.
    #[cfg(test)]
    pub(crate) fn jit_registers(
        &self,
        scratchpad: &mut Scratchpad,
        nonce: u64,
    ) -> Option<[u64; 9]> {
        let jit = self.jit.as_ref()?;
        let mut regs = start_registers(self.key, nonce, &mut scratchpad.mem);
        jit.run(&mut regs, &mut scratchpad.mem);
        Some(regs)
    }

    /// Hashes one nonce with a fresh scratchpad. This allocates 16 KiB;
    /// use [`HashWx::hash`] to hash many nonces.
    pub fn hash_one(&self, nonce: u64) -> u64 {
        self.hash(&mut Scratchpad::new(), nonce)
    }

    /// Runs a hash step by step, recording the registers between phases.
    #[cfg(test)]
    pub(crate) fn trace(&self, scratchpad: &mut Scratchpad, nonce: u64) -> Trace {
        let mut m = Machine::start(self.key, nonce, &mut scratchpad.mem);
        let start = m.registers();
        m.write_phase(&self.programs);
        let after_write = m.registers();
        let save_pointer_after_write = m.p;
        let scratchpad_after_write = m.mem.to_vec();
        m.read_phase(&self.programs);
        let after_read = m.registers();
        let (r8_slot_reads, stops) = (m.r8_slot_reads, m.stops);
        let hash = m.finish();
        Trace {
            start,
            after_write,
            save_pointer_after_write,
            scratchpad_after_write,
            after_read,
            hash,
            r8_slot_reads,
            stops,
        }
    }
}

/// What [`HashWx::trace`] records.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct Trace {
    /// R0 to R8 after the registers are set up.
    pub(crate) start: [u64; 9],
    /// R0 to R8 after the write phase.
    pub(crate) after_write: [u64; 9],
    /// The save pointer P after the write phase.
    pub(crate) save_pointer_after_write: usize,
    /// All of M after the write phase.
    pub(crate) scratchpad_after_write: alloc::vec::Vec<u8>,
    /// R0 to R8 after the read phase.
    pub(crate) after_read: [u64; 9],
    pub(crate) hash: u64,
    /// Scratchpad reads at addresses 16377 to 16383.
    pub(crate) r8_slot_reads: u32,
    /// Times `LOOP_IF` did not loop because C was 0 while F was 0.
    pub(crate) stops: u32,
}

/// The state of one hash in flight. The loop flag F lives in
/// a local of [`Machine::run_program`], since every pass sets it before
/// reading it.
struct Machine<'a> {
    /// R0 to R7.
    r: [u64; 8],
    /// R8, set once.
    r8: u64,
    mem: &'a mut [u8; SCRATCHPAD_LEN],
    /// The save pointer P.
    p: usize,
    /// The loop budget C.
    c: u32,
    #[cfg(test)]
    r8_slot_reads: u32,
    #[cfg(test)]
    stops: u32,
}

impl<'a> Machine<'a> {
    /// Sets up the registers from the stream with the
    /// hashing key and the nonce as tweak, then the R8 slot.
    fn start(key: [u64; 2], nonce: u64, mem: &'a mut [u8; SCRATCHPAD_LEN]) -> Self {
        let [r0, r1, r2, r3, r4, r5, r6, r7, r8] = start_registers(key, nonce, mem);
        Machine {
            r: [r0, r1, r2, r3, r4, r5, r6, r7],
            r8,
            mem,
            p: R8_SLOT,
            c: 0,
            #[cfg(test)]
            r8_slot_reads: 0,
            #[cfg(test)]
            stops: 0,
        }
    }

    #[cfg(test)]
    fn registers(&self) -> [u64; 9] {
        let r = self.r;
        [r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], self.r8]
    }

    /// The write phase. It saves exactly 256 blocks of 64 bytes, so P
    /// ends at 0.
    fn write_phase(&mut self, programs: &[Program; PROGRAM_COUNT]) {
        for _ in 0..ROUNDS {
            self.round::<true>(programs);
        }
    }

    /// The read phase.
    fn read_phase(&mut self, programs: &[Program; PROGRAM_COUNT]) {
        for _ in 0..ROUNDS {
            self.round::<false>(programs);
        }
    }

    /// The finish: two SipRounds, then the hash.
    fn finish(self) -> u64 {
        let [r0, r1, r2, r3, r4, r5, r6, r7] = self.r;
        finish(&[r0, r1, r2, r3, r4, r5, r6, r7, self.r8])
    }

    /// One round: reset C, then run programs 0 to 31 in order.
    /// `WRITE` picks the mode.
    fn round<const WRITE: bool>(&mut self, programs: &[Program; PROGRAM_COUNT]) {
        self.c = LOOP_BUDGET;
        for program in programs {
            self.run_program::<WRITE>(program);
        }
    }

    /// Runs one program until `END`.
    #[inline(always)]
    fn run_program<const WRITE: bool>(&mut self, program: &Program) {
        loop {
            // Slot 0, SAVE: R7 first, R0 last, in write mode only.
            if WRITE {
                self.p -= 64;
                let block = &mut self.mem[self.p..self.p + 64];
                for (bytes, reg) in block
                    .as_chunks_mut::<8>()
                    .0
                    .iter_mut()
                    .zip(self.r.iter().rev())
                {
                    *bytes = reg.to_le_bytes();
                }
            }

            // Slot 1, STEP: always multiplies by R8, in both modes. F is
            // bit 5 of the value after the rotation.
            let d = usize::from(program.step_dst & 7);
            let stepped = self.r[d].wrapping_mul(self.r8).rotate_right(program.step_k);
            self.r[d] = stepped;
            let flag = (stepped >> 5) & 1 == 1;

            // Slots 2 to 8. The operand is read before the destination is
            // written.
            for ins in &program.ops {
                let src = self.r[usize::from(ins.src & 7)];
                let v = if WRITE { src } else { self.load(src) };
                let dst = &mut self.r[usize::from(ins.dst & 7)];
                *dst = ins.apply(*dst, v);
            }

            // Slot 9, LOOP or LOOP_IF.
            if loops_again(&mut self.c, program.always_loop, flag) {
                continue;
            }
            #[cfg(test)]
            if !program.always_loop && !flag {
                self.stops += 1;
            }
            // Slot 10, END.
            return;
        }
    }

    /// The read-mode operand: 8 little-endian bytes of M at the low 14 bits
    /// of the source register. Addresses 16377 to 16383 reach
    /// into the R8 slot, which holds R8 of this nonce.
    #[inline(always)]
    fn load(&mut self, src: u64) -> u64 {
        let a = load_address(src);
        #[cfg(test)]
        if a > R8_SLOT - 8 {
            self.r8_slot_reads += 1;
        }
        let bytes: &[u8; 8] = self.mem[a..]
            .first_chunk()
            .expect("a + 8 <= SCRATCHPAD_LEN");
        u64::from_le_bytes(*bytes)
    }
}

/// Sets up R0 to R8 from the stream with the hashing key and the nonce as
/// tweak, and writes the R8 slot.
#[inline(always)]
fn start_registers(key: [u64; 2], nonce: u64, mem: &mut [u8; SCRATCHPAD_LEN]) -> [u64; 9] {
    let mut stream = WordStream::new(key, nonce);
    let [r0, r1, r2, r3] = stream.next_four();
    let [r4, r5, r6, r7] = stream.next_four();
    let r8 = ((r0 ^ r4) & !7) | 3;
    // The R8 slot MUST be written for every nonce.
    mem[R8_SLOT..].copy_from_slice(&r8.to_le_bytes());
    [r0, r1, r2, r3, r4, r5, r6, r7, r8]
}

/// The finish from R0 to R8: two SipRounds, then the hash.
#[inline(always)]
fn finish(r: &[u64; 9]) -> u64 {
    let mut lo = [r[0], r[1], r[2], r[3]];
    let mut hi = [r[4], r[5], r[6], r[7]];
    sip_round(&mut lo);
    sip_round(&mut hi);
    lo[3] ^ hi[3] ^ r[8]
}

/// Slot 9: whether the program goes back to slot 0. `LOOP` loops while
/// the budget C lasts, and `LOOP_IF` also needs the flag F clear. Each
/// loop spends one unit of C.
#[inline(always)]
pub(crate) fn loops_again(c: &mut u32, always_loop: bool, flag: bool) -> bool {
    if *c > 0 && (always_loop || !flag) {
        *c -= 1;
        true
    } else {
        false
    }
}

/// The scratchpad address of a read-mode operand: the low 14 bits of the
/// source register.
#[inline(always)]
pub(crate) fn load_address(src: u64) -> usize {
    (src & ADDRESS_MASK) as usize
}
