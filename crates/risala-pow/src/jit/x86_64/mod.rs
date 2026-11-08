//! The x86-64 compiler: turns the 32 programs of a function into one
//! machine-code function that runs both phases of a hash.
//!
//! The function is called as `f(regs, scratchpad)` with the System V
//! calling convention. `regs` points to R0 to R8, nine words, as set up
//! for a nonce; `scratchpad` points to the 16392 bytes of M, with the R8
//! slot already written. It runs the four write rounds and the four read
//! rounds, then writes R0 to R7 back to `regs`. The caller does the
//! finish.
//!
//! # Layout
//!
//! ```text
//! prologue    push the callee-saved registers it uses, load R0..R8,
//!             push the register file's address, P = 16384
//! write phase rounds = 4
//!   round:    C = 32
//!             program 0 .. program 31 (write mode)
//!             rounds -= 1, back to round if not 0
//! read phase  the same, in read mode
//! epilogue    pop the register file's address, store R0..R7,
//!             pop the callee-saved registers, ret
//! ```
//!
//! Each program is a straight run of code ending in its slot 9 branch
//! back to its own start:
//!
//! ```text
//! top:  SAVE (write mode): P -= 64, P &= 0x3fc0, store R7..R0 at M[P]
//!       STEP: Rd = Rd * R8, Rd = Rd ror k
//!       slots 2 to 8
//!       LOOP_IF: test Rd, 32; jnz next      (F set: no loop)
//!       LOOP:    sub ecx, 1; jae top        (C was > 0: C -= 1, loop)
//!                inc ecx                    (C was 0: put it back)
//! next:
//! ```
//!
//! F is bit 5 of Rd after the STEP, and Rd is still that value at slot 9
//! because slots 2 to 8 never write the STEP's register (each register is
//! written once per program). [`supported`] checks that, and the other
//! facts the code relies on, before each program is emitted; if one
//! fails, the whole function is refused and the interpreter runs.
//!
//! The operations of slots 2 to 8 are encoded from a table,
//! [`asm::Operation`], one per operation, so that compiling is fast and
//! has no branches on the program.
//!
//! # Registers
//!
//! R0 to R7 live in R8 to R15, and R8 in RBP. RSI holds the scratchpad's
//! address and is never written. RAX is the masked read index, RDI is P
//! as an offset from RSI (and the register file's address in the
//! prologue and epilogue), ECX is C and EDX counts rounds. The function
//! saves RBP and R12 to R15, and leaves the stack as it found it.
//!
//! # Safety by construction
//!
//! - Every scratchpad read is `[rsi + rax]` with RAX the low 14 bits of a
//!   register, masked by the instruction just before: at most byte 16391
//!   of 16392.
//! - Every scratchpad write is `[rsi + rdi + 8i]`, i < 8, with RDI masked
//!   to a multiple of 64 below 16384 just before: within the first 16384
//!   bytes. The Kani proofs show that P runs from 16384 to 0 in steps of
//!   64 on the interpreter's path, where the mask changes nothing.
//! - There are no calls and no indirect jumps. Every branch goes to a
//!   label fixed at compile time inside the function. The only way out
//!   is the final `ret`.
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
use asm::{Alu, Asm, Cond, Operation, Reg, Unary};

/// The compiled function's type: `f(regs, scratchpad)`.
pub(crate) type Entry = unsafe extern "sysv64" fn(regs: *mut u64, scratchpad: *mut u8);

/// The machine registers of R0 to R7.
const R: [Reg; 8] = [
    Reg::R8,
    Reg::R9,
    Reg::R10,
    Reg::R11,
    Reg::R12,
    Reg::R13,
    Reg::R14,
    Reg::R15,
];
/// The machine register of Ri, `R[i]`, for i from 0 to 7. Computed rather
/// than looked up, so that the compiler knows it is one of R8 to R15 and
/// folds the encoding's REX bits.
#[inline(always)]
pub(crate) fn r(i: u8) -> Reg {
    Reg::extended(i)
}

/// R7 to R0, in the order `SAVE` writes them.
const SAVE_ORDER: [Reg; 8] = [
    Reg::R15,
    Reg::R14,
    Reg::R13,
    Reg::R12,
    Reg::R11,
    Reg::R10,
    Reg::R9,
    Reg::R8,
];
/// The machine register of R8.
const R8_REG: Reg = Reg::RBP;
/// The loop budget C.
const BUDGET: Reg = Reg::RCX;
/// Rounds left in the phase.
const ROUNDS_LEFT: Reg = Reg::RDX;
/// The callee-saved registers the function uses, in the order it pushes
/// them.
const SAVED: [Reg; 5] = [Reg::RBP, Reg::R12, Reg::R13, Reg::R14, Reg::R15];

/// The most bytes the prologue takes: five pushes of 1 or 2 bytes, nine
/// 4-byte loads, `push rdi` and a 5-byte `mov`.
pub(crate) const PROLOGUE_MAX: usize = 9 + 9 * 4 + 1 + 5;
/// The most bytes the epilogue takes.
pub(crate) const EPILOGUE_MAX: usize = 1 + 8 * 4 + 9 + 1;
/// The most bytes a phase takes besides its programs: the round count,
/// the budget, and the round's `dec` and 6-byte branch.
pub(crate) const PHASE_OVERHEAD_MAX: usize = 5 + 5 + 2 + 6;
/// The most bytes of slots 1 and 9: the STEP, and the longest loop test,
/// whose branch back is always the 6-byte form.
const STEP_AND_LOOP_MAX: usize = 4 + 4 + (4 + 2 + 3 + 6 + 2);
/// The most bytes of a write-mode program: `SAVE` (3 + 6 + 8 * 5), slots
/// 1 and 9, and seven operations of at most 8 bytes.
pub(crate) const WRITE_PROGRAM_MAX: usize = asm::SAVE_CODE_LEN + STEP_AND_LOOP_MAX + 7 * 8;
/// The most bytes of a read-mode program: slots 1 and 9, and seven
/// operations of at most 4 + 3 + 5 + 5 bytes (`ror`; `mov eax`, always
/// with a REX prefix; the mask; `imul` from memory).
pub(crate) const READ_PROGRAM_MAX: usize = STEP_AND_LOOP_MAX + 7 * 17;
/// The most bytes a compiled function takes.
pub(crate) const MAX_CODE_LEN: usize = PROLOGUE_MAX
    + 2 * PHASE_OVERHEAD_MAX
    + PROGRAM_COUNT * (WRITE_PROGRAM_MAX + READ_PROGRAM_MAX)
    + EPILOGUE_MAX;
/// The size of a code buffer: three 4 KiB pages.
pub(crate) const CODE_CAPACITY: usize = 3 * 4096;

const _: () = assert!(MAX_CODE_LEN + asm::SLACK <= CODE_CAPACITY);
// The masks in the encoder are the interpreter's.
const _: () = assert!(asm::READ_MASK as usize == SCRATCHPAD_ADDRESSES - 1);
const _: () = assert!(asm::SAVE_MASK as usize == R8_SLOT - asm::SAVE_BLOCK as usize);
const _: () = assert!(R8_SLOT <= u32::MAX as usize);

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
        // operand is read after the operation on the destination starts,
        // so it must be another register.
        ok &= (ins.dst < 8)
            & (ins.src < 8)
            & (ins.src != ins.dst)
            & (ins.dst != program.step_dst)
            & (ins.k >= min)
            & (ins.k <= max);
    }
    ok
}

/// The constants the compiled code gets right for an operation: an 8-bit
/// immediate, sign-extended, must equal k in the multiply group; counts
/// must be 1 to 63.
const fn constant_range(op: Op) -> (u64, u64) {
    match op {
        Op::OrMul | Op::XorMul | Op::AddMul => (0, 127),
        _ => (1, 63),
    }
}

/// Compiles the 32 programs into `buf`, which should hold
/// [`CODE_CAPACITY`] bytes (at least [`MAX_CODE_LEN`] and the encoder's
/// slack), and returns the length of the code. The rest
/// of `buf` is filled with `int3`. Returns `None` if a program is not
/// [`supported`] or the code does not fit, which the Kani proofs show
/// cannot happen.
pub(crate) fn emit(programs: &[Program; PROGRAM_COUNT], buf: &mut [u8]) -> Option<usize> {
    let mut a = Asm::new(buf);
    prologue(&mut a);
    phase::<true>(&mut a, programs);
    phase::<false>(&mut a, programs);
    epilogue(&mut a);
    a.fill_rest_with_traps();
    a.finish()
}

pub(crate) fn prologue(a: &mut Asm<'_>) {
    for r in SAVED {
        a.push(r);
    }
    for (slot, r) in (0u8..).zip(R) {
        a.load_from_regs(r, slot);
    }
    a.load_from_regs(R8_REG, 8);
    // The register file's address goes on the stack until the epilogue,
    // and RDI becomes P.
    a.push(asm::REGS_PTR);
    a.mov_imm32(asm::SAVE_OFFSET, R8_SLOT as u32);
}

pub(crate) fn epilogue(a: &mut Asm<'_>) {
    a.pop(asm::REGS_PTR);
    for (slot, r) in (0u8..).zip(R) {
        a.store_to_regs(r, slot);
    }
    for r in SAVED.iter().rev() {
        a.pop(*r);
    }
    a.ret();
}

/// The four rounds of one phase.
fn phase<const WRITE: bool>(a: &mut Asm<'_>, programs: &[Program; PROGRAM_COUNT]) {
    a.mov_imm32(ROUNDS_LEFT, ROUNDS as u32);
    let round = a.label();
    a.mov_imm32(BUDGET, LOOP_BUDGET);
    for program in programs {
        emit_program::<WRITE>(a, program);
    }
    a.dec32(ROUNDS_LEFT);
    a.branch_back(Cond::NotZero, round);
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
    a.alu(Alu::Imul, step, R8_REG);
    a.unary(Unary::Ror, step, program.step_k as u8);

    // Slots 2 to 8.
    for ins in &program.ops {
        emit_instruction::<WRITE>(a, ins);
    }

    // Slot 9.
    let no_loop = if program.always_loop {
        None
    } else {
        a.test_low_byte(step, 1 << 5);
        Some(a.branch_forward(Cond::NotZero))
    };
    a.sub_imm8_32(BUDGET, 1);
    a.branch_back(Cond::NoCarry, top);
    a.inc32(BUDGET);
    if let Some(branch) = no_loop {
        a.bind(branch);
    }
}

/// One instruction of slots 2 to 8.
#[inline(always)]
fn emit_instruction<const WRITE: bool>(a: &mut Asm<'_>, ins: &Instr) {
    let op = &OPERATIONS[ins.op as usize];
    // Constants are checked by `supported`: at most 127 for the multiply
    // group, so the sign-extended byte is k, and 1 to 63 for counts. Ri is
    // R8 + i.
    let k = ins.k as u8;
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

/// The encoding of each operation, by its discriminant.
const OPERATIONS: [Operation; 12] = {
    let mut out = [Operation::new(Unary::Add, Alu::Add); 12];
    let mut i = 0;
    while i < ALL_OPS.len() {
        assert!(ALL_OPS[i] as usize == i);
        let (first, combine) = form(ALL_OPS[i]);
        out[i] = Operation::new(first, combine);
        i += 1;
    }
    out
};

/// An operation as two machine instructions: its first step on the
/// destination, with k as the immediate, and how the result combines
/// with the operand.
pub(crate) const fn form(op: Op) -> (Unary, Alu) {
    match op {
        Op::OrMul => (Unary::Or, Alu::Imul),
        Op::XorMul => (Unary::Xor, Alu::Imul),
        Op::AddMul => (Unary::Add, Alu::Imul),
        Op::RorXor => (Unary::Ror, Alu::Xor),
        Op::RorAdd => (Unary::Ror, Alu::Add),
        Op::RorSub => (Unary::Ror, Alu::Sub),
        Op::SarXor => (Unary::Sar, Alu::Xor),
        Op::SarAdd => (Unary::Sar, Alu::Add),
        Op::SarSub => (Unary::Sar, Alu::Sub),
        Op::ShrXor => (Unary::Shr, Alu::Xor),
        Op::ShrAdd => (Unary::Shr, Alu::Add),
        Op::ShrSub => (Unary::Shr, Alu::Sub),
    }
}
