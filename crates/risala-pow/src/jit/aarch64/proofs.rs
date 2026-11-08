//! Kani proofs of the aarch64 compiler.
//!
//! They check, for every program (every operation, register and constant,
//! not only those a seed can make):
//!
//! - the code of one program fits its size bound, so a whole function
//!   fits [`MAX_CODE_LEN`] and the encoder never fails or writes past its
//!   buffer;
//! - the program's branches go to its own start and its own end;
//! - filling an operation's template gives exactly the words of encoding
//!   it directly, which the unit tests check against a decoder; in read
//!   mode those start with the mask and the read, and nothing else in
//!   them reads or writes memory;
//! - `SAVE` masks the save pointer and stores only through the masked
//!   address, and the masks keep every access in range.

use super::asm::{
    Asm, Cond, READ_OP_WORDS, Reg, SAVE_BLOCK, SAVE_MASK, SAVE_MASK_IMM, SLACK, and_imm, ldr_reg,
    read_words, write_words,
};
use super::*;
use crate::hash::{SCRATCHPAD_LEN, loops_again};

fn any_instr() -> Instr {
    let which: usize = kani::any();
    kani::assume(which < ALL_OPS.len());
    Instr {
        op: ALL_OPS[which],
        dst: kani::any(),
        src: kani::any(),
        k: kani::any(),
    }
}

/// Any program at all: the compiler must cope with each, compiling it
/// or refusing it.
fn any_program() -> Program {
    Program {
        step_dst: kani::any(),
        step_k: kani::any(),
        ops: [
            any_instr(),
            any_instr(),
            any_instr(),
            any_instr(),
            any_instr(),
            any_instr(),
            any_instr(),
        ],
        always_loop: kani::any(),
    }
}

/// The target, in words, of the `b.cond` at word `at`, from its 19-bit
/// word offset.
fn b_cond_target(w: u32, at: usize) -> isize {
    let words = (((w >> 5) & 0x7_ffff) << 13) as i32 >> 13;
    at as isize + words as isize
}

/// The target, in words, of the `tbnz` at word `at`, from its 14-bit
/// word offset.
fn tbnz_target(w: u32, at: usize) -> isize {
    let words = (((w >> 5) & 0x3fff) << 18) as i32 >> 18;
    at as isize + words as isize
}

/// Checks one program's code: given `MAX` bytes and the encoder's slack,
/// it fits in `MAX` if the program is supported, and its slot 9 branches
/// go to its start (word 0) and its end. `WORDS` is `MAX / 4 + SLACK`.
fn check_program<const WRITE: bool, const MAX: usize, const WORDS: usize>() {
    assert_eq!(WORDS, MAX / 4 + SLACK);
    let program = any_program();
    let mut buf = [0u32; WORDS];
    let mut a = Asm::new(&mut buf);
    emit_program::<WRITE>(&mut a, &program);
    let len = a.finish();
    if !supported(&program) {
        assert!(len.is_none());
        return;
    }
    let len = len.expect("a supported program fits its bound");
    assert!(len <= MAX && len.is_multiple_of(4));
    let end = len / 4;

    // The program ends `subs w12, w12, #1; b.hs top; add w12, w12, #1`.
    assert_eq!(buf[end - 1], 0x1100_058c);
    let b = buf[end - 2];
    assert_eq!(b & 0xff00_001f, 0x5400_0002);
    assert_eq!(b_cond_target(b, end - 2), 0);
    assert_eq!(buf[end - 3], 0x7100_058c);
    if !program.always_loop {
        // Before that, `tbnz Rd, #5, next`, which goes to the end.
        let t = buf[end - 4];
        assert_eq!(
            t & 0xfff8_001f,
            0x3728_0000 | (2 + u32::from(program.step_dst))
        );
        assert_eq!(tbnz_target(t, end - 4), end as isize);
    }
}

#[kani::proof]
#[kani::unwind(10)]
fn write_program_fits_and_branches_home() {
    check_program::<true, WRITE_PROGRAM_MAX, { WRITE_PROGRAM_MAX / 4 + SLACK }>();
}

#[kani::proof]
#[kani::unwind(10)]
fn read_program_fits_and_branches_home() {
    check_program::<false, READ_PROGRAM_MAX, { READ_PROGRAM_MAX / 4 + SLACK }>();
}

/// The prologue and epilogue fit their bounds. With the two proofs above,
/// a function, which is the prologue, two phases of `PHASE_OVERHEAD_MAX`
/// bytes and 32 programs, and the epilogue, fits `MAX_CODE_LEN`, which a
/// constant assertion keeps within `CODE_CAPACITY`.
#[kani::proof]
#[kani::unwind(10)]
fn prologue_and_epilogue_fit() {
    let mut buf = [0u32; PROLOGUE_MAX / 4 + SLACK];
    let mut a = Asm::new(&mut buf);
    prologue(&mut a);
    assert!(a.finish().is_some_and(|len| len <= PROLOGUE_MAX));
    let mut buf = [0u32; EPILOGUE_MAX / 4 + SLACK];
    let mut a = Asm::new(&mut buf);
    epilogue(&mut a);
    assert!(a.finish().is_some_and(|len| len <= EPILOGUE_MAX));
}

/// A backward branch lands exactly on its label, for every position and
/// distance.
#[kani::proof]
fn backward_branches_land_on_their_label() {
    let mut buf = [0u32; 512];
    let mut a = Asm::new(&mut buf);
    let before: usize = kani::any();
    let gap: usize = kani::any();
    kani::assume(before <= 256 && gap <= 250);
    a.skip_words(before);
    let label = a.label();
    a.skip_words(gap);
    let at = a.len() / 4;
    let cond = if kani::any() { Cond::Ne } else { Cond::Hs };
    a.branch_back(cond, label);
    let end = a.finish().expect("fits");
    assert_eq!(end, 4 * (at + 1));
    assert_eq!(b_cond_target(buf[at], at), before as isize);
}

/// A forward branch lands exactly where it is bound, or the code fails.
#[kani::proof]
fn forward_branches_land_where_bound() {
    let mut buf = [0u32; 256];
    let mut a = Asm::new(&mut buf);
    let r: usize = kani::any();
    kani::assume(r < 31);
    let branch = a.tbnz_forward(Reg::ALL[r], 5);
    let gap: usize = kani::any();
    kani::assume(gap <= 250);
    a.skip_words(gap);
    a.bind(branch);
    let end = a.finish().expect("fits");
    assert_eq!(end, 4 * (gap + 1));
    assert_eq!(tbnz_target(buf[0], 0), (gap + 1) as isize);
}

/// Every operation, in both modes, for every pair of R0 to R7 and every
/// constant the compiler accepts: the emitted words are the direct
/// encoding. In read mode, they begin with `and x14, xs, #0x3fff;
/// ldr x15, [x1, x14]`, and the rest are the write-mode operation on X15,
/// which reads and writes no memory.
#[kani::proof]
#[kani::unwind(21)]
fn operations_are_their_direct_encodings() {
    let dst: u8 = kani::any();
    let src: u8 = kani::any();
    let k: u32 = kani::any();
    let (d, s) = (r(dst).number(), r(src).number());
    for (i, op) in ALL_OPS.iter().enumerate() {
        let (min, max) = constant_range(*op);
        if u64::from(k) < min || u64::from(k) > max {
            continue;
        }
        let t = &OPERATIONS[i];

        let mut buf = [0u32; READ_OP_WORDS];
        let mut a = Asm::new(&mut buf);
        a.operation(t, dst, src, k);
        let len = a.finish().expect("fits") / 4;
        let (w, n) = write_words(*op, d, s, k);
        assert_eq!(len, n as usize);
        assert_eq!(buf[..len], w[..len]);

        let mut buf = [0u32; READ_OP_WORDS];
        let mut a = Asm::new(&mut buf);
        a.operation_scratch(t, dst, src, k);
        let len = a.finish().expect("fits") / 4;
        let (w, n) = read_words(*op, d, s, k);
        assert_eq!(len, n as usize);
        assert_eq!(buf[..len], w[..len]);
        assert_eq!(buf[0], and_imm(14, s, asm::READ_MASK_IMM));
        assert_eq!(buf[1], ldr_reg(15, 1, 14));

        // No memory access among the operation's words: none is in the
        // loads and stores class (op0 bits x1x0 in 28..25).
        let (w, n) = write_words(*op, d, 15, k);
        assert_eq!(buf[2..len], w[..n as usize]);
        for word in &w[..n as usize] {
            assert!((word >> 25) & 0b0101 != 0b0100);
        }
    }
}

/// `SAVE`: `sub x11, x11, #64; and x11, x11, #0x3fc0; add x14, x1, x11`,
/// then four `stp` through X14 at offsets 0 to 48, whatever registers
/// are stored.
#[kani::proof]
#[kani::unwind(10)]
fn saves_are_masked() {
    let any_reg = || {
        let r: usize = kani::any();
        kani::assume(r < 31);
        Reg::ALL[r]
    };
    let regs = [
        any_reg(),
        any_reg(),
        any_reg(),
        any_reg(),
        any_reg(),
        any_reg(),
        any_reg(),
        any_reg(),
    ];
    let mut buf = [0u32; 8];
    let mut a = Asm::new(&mut buf);
    a.save_block(&regs);
    assert_eq!(a.finish(), Some(4 * asm::SAVE_WORDS));
    assert_eq!(buf[0], 0xd101_016b);
    assert_eq!(buf[1], and_imm(11, 11, SAVE_MASK_IMM));
    assert_eq!(buf[1], 0x927a_1d6b);
    assert_eq!(buf[2], 0x8b0b_002e);
    for i in 0..4 {
        let w = buf[3 + i];
        // STP (signed offset, 64-bit), base X14, imm7 = 2i.
        assert_eq!(w & 0xffc0_0000, 0xa900_0000);
        assert_eq!((w >> 5) & 31, 14);
        assert_eq!((w >> 15) & 0x7f, 2 * i as u32);
    }
}

/// The read mask keeps an 8-byte read inside the scratchpad, for every
/// register value, and selects the interpreter's address.
#[kani::proof]
fn read_mask_stays_in_range() {
    let x: u64 = kani::any();
    let index = (x & asm::READ_MASK) as usize;
    assert!(index + 8 <= SCRATCHPAD_LEN);
    assert_eq!(index, crate::hash::load_address(x));
}

/// The save mask keeps the 64-byte block below the R8 slot for every
/// value of X11, and on the interpreter's path, P = 16384 - 64 n for n
/// below 256, it gives the interpreter's P.
#[kani::proof]
fn save_mask_stays_in_range() {
    let x11: u64 = kani::any();
    let p = (x11.wrapping_sub(u64::from(SAVE_BLOCK)) & SAVE_MASK) as usize;
    assert!(p + SAVE_BLOCK as usize <= R8_SLOT);
    assert_eq!(p % 64, 0);

    let n: u64 = kani::any();
    kani::assume(n < 256);
    let before = R8_SLOT as u64 - 64 * n;
    let after = before.wrapping_sub(u64::from(SAVE_BLOCK)) & SAVE_MASK;
    assert_eq!(after, before - 64);
}

/// The slot 9 code, `tbnz Rd, #5, next; subs w12, w12, #1; b.hs top;
/// add w12, w12, #1`, decides as the interpreter's `loops_again` does
/// and leaves C the same, for every budget and flag.
#[kani::proof]
fn loop_code_matches_the_interpreter() {
    let c: u32 = kani::any();
    let always: bool = kani::any();
    let flag: bool = kani::any();

    let (jit_loops, jit_c) = if !always && flag {
        (false, c)
    } else {
        // subs: C (carry) is set when there is no borrow, c >= 1.
        let after = c.wrapping_sub(1);
        let carry = c >= 1;
        if carry {
            (true, after)
        } else {
            (false, after.wrapping_add(1))
        }
    };

    let mut interp_c = c;
    let interp_loops = loops_again(&mut interp_c, always, flag);
    assert_eq!(jit_loops, interp_loops);
    assert_eq!(jit_c, interp_c);
}
