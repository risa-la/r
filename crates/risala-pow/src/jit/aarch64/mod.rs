//! The aarch64 compiler: turns the 32 programs of a function into one
//! machine-code function that runs both phases of a hash.
//!
//! The function is called as `f(regs, scratchpad)` with the AAPCS64
//! calling convention (the same on Linux, Android and Apple platforms
//! for this signature). `regs` points to R0 to R8, nine words, as set up
//! for a nonce; `scratchpad` points to the 16392 bytes of M, with the R8
//! slot already written. It runs the four write rounds and the four read
//! rounds, then writes R0 to R7 back to `regs`. The caller does the
//! finish.
//!
//! # Layout
//!
//! ```text
//! prologue    load R0..R8 from the register file, P = 16384
//! write phase rounds = 4
//!   round:    C = 32
//!             program 0 .. program 31 (write mode)
//!             rounds -= 1, back to round if not 0
//! read phase  the same, in read mode
//! epilogue    store R0..R7 to the register file, ret
//! ```
//!
//! Each program is a straight run of code ending in its slot 9 branch
//! back to its own start:
//!
//! ```text
//! top:  SAVE (write mode): P -= 64, P &= 0x3fc0, x14 = M + P,
//!                          store R7..R0 at x14 (four stp)
//!       STEP: Rd = Rd * R8, Rd = Rd ror k
//!       slots 2 to 8
//!       LOOP_IF: tbnz Rd, #5, next            (F set: no loop)
//!       LOOP:    subs w12, w12, #1; b.hs top  (C was > 0: C -= 1, loop)
//!                add w12, w12, #1             (C was 0: put it back)
//! next:
//! ```
//!
//! F is bit 5 of Rd after the STEP, and Rd is still that value at slot 9
//! because slots 2 to 8 never write the STEP's register (each register is
//! written once per program). [`supported`] checks that, and the other
//! facts the code relies on, before each program is emitted; if one
//! fails, the whole function is refused and the interpreter runs.
//!
//! The operations of slots 2 to 8 are listed in [`asm::op_words`] and
//! emitted from templates, [`asm::Operation`], one per operation, so that
//! compiling is fast and has no branches on the program.
//!
//! # Registers
//!
//! X0 holds the register file's address and X1 the scratchpad's; neither
//! is ever written. R0 to R7 live in X2 to X9 and R8 in X10. X11 is P as
//! an offset from X1, W12 is C and W13 counts rounds. X14 is the masked
//! read index or the address of a `SAVE` block, X15 the operand read from
//! the scratchpad, and X16 the constant of `OR_MUL` and `XOR_MUL`.
//!
//! These are all argument, result or temporary registers, which the
//! caller does not expect kept. X18, the platform register (reserved on
//! Apple platforms and Android), the callee-saved X19 to X29, the link
//! register X30 and SP are never touched: the function uses no stack and
//! returns with `ret` to X30.
//!
//! # Safety by construction
//!
//! - Every scratchpad read is `ldr x15, [x1, x14]` with X14 the low 14 bits
//!   of a register, masked by the instruction just before: at most byte
//!   16391 of 16392.
//! - Every scratchpad write is `stp _, _, [x14, #16i]`, i < 4, with X14 =
//!   X1 + X11 just before and X11 masked to a multiple of 64 below 16384
//!   just before that: within the first 16384 bytes. The Kani proofs show
//!   that P runs from 16384 to 0 in steps of 64 on the interpreter's path,
//!   where the mask changes nothing.
//! - The register file is reached only by `ldp`, `ldr` and `stp` at fixed
//!   offsets from X0, within its nine words.
//! - There are no calls and no indirect or unconditional jumps. Every
//!   branch is a `tbnz` or `b.cond` to a label fixed at compile time
//!   inside the function. The only way out is the final `ret`.
//! - It always ends: each program loops at most C times, C only goes
//!   down within a round, and the round counts are fixed.
//! - The code has a static size bound, [`MAX_CODE_LEN`], proven by Kani,
//!   and the encoder never writes past its buffer.

pub(crate) mod asm;
#[cfg(kani)]
mod proofs;
#[cfg(test)]
mod tests;

use crate::hash::{LOOP_BUDGET, R8_SLOT, ROUNDS};
use crate::program::{Instr, Op, PROGRAM_COUNT, Program};
use asm::{Asm, Cond, Operation, Reg};

/// The compiled function's type: `f(regs, scratchpad)`.
pub(crate) type Entry = unsafe extern "C" fn(regs: *mut u64, scratchpad: *mut u8);

/// What a code buffer is a slice of: instruction words. The buffer
/// starts on a page boundary, so it is aligned for them.
pub(crate) type Unit = u32;

/// The machine registers of R0 to R7.
const R: [Reg; 8] = [
    Reg::X2,
    Reg::X3,
    Reg::X4,
    Reg::X5,
    Reg::X6,
    Reg::X7,
    Reg::X8,
    Reg::X9,
];
/// The machine register of Ri, `R[i]`, for i from 0 to 7.
#[inline(always)]
pub(crate) fn r(i: u8) -> Reg {
    Reg::file(i)
}

/// R7 to R0, in the order `SAVE` writes them.
const SAVE_ORDER: [Reg; 8] = [
    Reg::X9,
    Reg::X8,
    Reg::X7,
    Reg::X6,
    Reg::X5,
    Reg::X4,
    Reg::X3,
    Reg::X2,
];
/// The machine register of R8.
const R8_REG: Reg = Reg::X10;
/// The loop budget C, used as W12.
const BUDGET: Reg = Reg::X12;
/// Rounds left in the phase, used as W13.
const ROUNDS_LEFT: Reg = Reg::X13;

/// The most bytes the prologue takes: four `ldp`, an `ldr` and a `movz`.
pub(crate) const PROLOGUE_MAX: usize = 6 * 4;
/// The most bytes the epilogue takes: four `stp` and `ret`.
pub(crate) const EPILOGUE_MAX: usize = 5 * 4;
/// The most bytes a phase takes besides its programs: the round count,
/// the budget, and the round's `subs` and branch.
pub(crate) const PHASE_OVERHEAD_MAX: usize = 4 * 4;
/// The most bytes of slots 1 and 9: `mul` and `ror`, and `tbnz`, `subs`,
/// `b.hs` and `add`.
const STEP_AND_LOOP_MAX: usize = 6 * 4;
/// The most bytes of a write-mode program: `SAVE`, slots 1 and 9, and
/// seven operations of at most three words.
pub(crate) const WRITE_PROGRAM_MAX: usize =
    asm::SAVE_WORDS * 4 + STEP_AND_LOOP_MAX + 7 * asm::WRITE_OP_WORDS * 4;
/// The most bytes of a read-mode program: slots 1 and 9, and seven
/// operations of at most five words (the read and three for the
/// operation).
pub(crate) const READ_PROGRAM_MAX: usize = STEP_AND_LOOP_MAX + 7 * asm::READ_OP_WORDS * 4;
/// The most bytes a compiled function takes.
pub(crate) const MAX_CODE_LEN: usize = PROLOGUE_MAX
    + 2 * PHASE_OVERHEAD_MAX
    + PROGRAM_COUNT * (WRITE_PROGRAM_MAX + READ_PROGRAM_MAX)
    + EPILOGUE_MAX;
/// The size of a code buffer: three 4 KiB pages, or one page of 16 or
/// 64 KiB.
pub(crate) const CODE_CAPACITY: usize = 3 * 4096;

const _: () = assert!(MAX_CODE_LEN + 4 * asm::SLACK <= CODE_CAPACITY);
const _: () = assert!(CODE_CAPACITY.is_multiple_of(4));
// The masks in the encoder are the interpreter's.
const _: () = assert!(asm::READ_MASK as usize == SCRATCHPAD_ADDRESSES - 1);
const _: () = assert!(asm::SAVE_MASK as usize == R8_SLOT - asm::SAVE_BLOCK as usize);
// P starts at the R8 slot, set by one `movz`.
const _: () = assert!(R8_SLOT <= u16::MAX as usize);

/// The number of read addresses, 2^14.
const SCRATCHPAD_ADDRESSES: usize = 16384;

/// Whether the compiled code computes what the interpreter does for this
/// program. Every program [`Program::from_words`] makes is supported (the
/// Kani proofs show the facts checked here), but the compiler checks
/// rather than trusts them, and refuses a program it would get wrong.
pub(crate) fn supported(program: &Program) -> bool {
    // Non-short-circuit `&`, so that there is no branch on the operation,
    // which changes from slot to slot and would often be mispredicted.
    let mut ok = (program.step_dst < 8) & (1..=63).contains(&program.step_k);
    for ins in &program.ops {
        let (min, max) = constant_range(ins.op);
        // The STEP's register must hold F until slot 9. In write mode the
        // operand register is read after the destination is first
        // written, so it must be another register.
        ok &= (ins.dst < 8)
            & (ins.src < 8)
            & (ins.src != ins.dst)
            & (ins.dst != program.step_dst)
            & (ins.k >= min)
            & (ins.k <= max);
    }
    ok
}

/// The constants the compiled code gets right for an operation: those
/// that fit the 12-bit immediate of `add` (and the 16 bits of `movz`) in
/// the multiply group; counts must be 1 to 63.
const fn constant_range(op: Op) -> (u64, u64) {
    match op {
        Op::OrMul | Op::XorMul | Op::AddMul => (0, asm::MAX_CONSTANT as u64),
        _ => (1, 63),
    }
}

/// Compiles the 32 programs into `buf`, which should hold
/// [`CODE_CAPACITY`] bytes (at least [`MAX_CODE_LEN`] and the encoder's
/// slack), and returns the length of the code in bytes. The rest of
/// `buf` is filled with `brk #0`. Returns `None` if a program is not
/// [`supported`] or the code does not fit, which the Kani proofs show
/// cannot happen.
pub(crate) fn emit(programs: &[Program; PROGRAM_COUNT], buf: &mut [Unit]) -> Option<usize> {
    let mut a = Asm::new(buf);
    prologue(&mut a);
    phase::<true>(&mut a, programs);
    phase::<false>(&mut a, programs);
    epilogue(&mut a);
    a.fill_rest_with_traps();
    a.finish()
}

pub(crate) fn prologue(a: &mut Asm<'_>) {
    for (slot, pair) in (0u8..).step_by(2).zip(R.as_chunks::<2>().0) {
        a.load_pair_from_regs(pair[0], pair[1], slot);
    }
    a.load_from_regs(R8_REG, 8);
    a.movz64(asm::SAVE_OFFSET, R8_SLOT as u16);
}

pub(crate) fn epilogue(a: &mut Asm<'_>) {
    for (slot, pair) in (0u8..).step_by(2).zip(R.as_chunks::<2>().0) {
        a.store_pair_to_regs(pair[0], pair[1], slot);
    }
    a.ret();
}

/// The four rounds of one phase.
fn phase<const WRITE: bool>(a: &mut Asm<'_>, programs: &[Program; PROGRAM_COUNT]) {
    a.movz32(ROUNDS_LEFT, ROUNDS as u16);
    let round = a.label();
    a.movz32(BUDGET, LOOP_BUDGET as u16);
    for program in programs {
        emit_program::<WRITE>(a, program);
    }
    a.subs32(ROUNDS_LEFT, 1);
    a.branch_back(Cond::Ne, round);
}

/// One program, slots 0 to 9. Emits nothing and fails the code if the
/// program is not [`supported`].
pub(crate) fn emit_program<const WRITE: bool>(a: &mut Asm<'_>, program: &Program) {
    if !supported(program) {
        a.fail();
        return;
    }
    let top = a.label();

    // Slot 0, SAVE.
    if WRITE {
        a.save_block(&SAVE_ORDER);
    }

    // Slot 1, STEP.
    let step = r(program.step_dst);
    a.mul(step, step, R8_REG);
    a.ror(step, step, program.step_k);

    // Slots 2 to 8.
    for ins in &program.ops {
        emit_instruction::<WRITE>(a, ins);
    }

    // Slot 9.
    let no_loop = if program.always_loop {
        None
    } else {
        Some(a.tbnz_forward(step, 5))
    };
    a.subs32(BUDGET, 1);
    a.branch_back(Cond::Hs, top);
    a.add32(BUDGET, 1);
    if let Some(branch) = no_loop {
        a.bind(branch);
    }
}

/// One instruction of slots 2 to 8.
#[inline(always)]
fn emit_instruction<const WRITE: bool>(a: &mut Asm<'_>, ins: &Instr) {
    let op = &OPERATIONS[ins.op as usize];
    // Constants are checked by `supported`: at most 4095 for the multiply
    // group, and 1 to 63 for counts, so each fits its field.
    let k = ins.k as u32;
    if WRITE {
        a.operation(op, ins.dst, ins.src, k);
    } else {
        a.operation_scratch(op, ins.dst, ins.src, k);
    }
}

/// Every operation, in the order of its discriminant.
pub(crate) const ALL_OPS: [Op; 12] = [
    Op::OrMul,
    Op::XorMul,
    Op::AddMul,
    Op::RorXor,
    Op::RorAdd,
    Op::RorSub,
    Op::SarXor,
    Op::SarAdd,
    Op::SarSub,
    Op::ShrXor,
    Op::ShrAdd,
    Op::ShrSub,
];

/// The templates of each operation, by its discriminant.
pub(crate) const OPERATIONS: [Operation; 12] = {
    let mut out = [Operation::new(Op::OrMul); 12];
    let mut i = 0;
    while i < ALL_OPS.len() {
        assert!(ALL_OPS[i] as usize == i);
        out[i] = Operation::new(ALL_OPS[i]);
        i += 1;
    }
    out
};
