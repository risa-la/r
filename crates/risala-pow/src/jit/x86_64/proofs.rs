//! Kani proofs of the x86-64 compiler.
//!
//! They check, for every program (every operation, register and constant,
//! not only those a seed can make):
//!
//! - the code of one program fits its size bound, so a whole function
//!   fits [`MAX_CODE_LEN`] and the encoder never fails or writes past its
//!   buffer;
//! - the program's branches go to its own start and its own end;
//! - every scratchpad access the encoder emits is masked just before, and
//!   the masks keep it in range.

use super::asm::{Alu, Asm, Cond, Operation, READ_MASK, Reg, SAVE_BLOCK, SAVE_MASK, SLACK, Unary};
use super::*;
use crate::hash::{SCRATCHPAD_LEN, loops_again};
use crate::program::Instr;

const ALL_OPS: [Op; 12] = [
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

const ALL_ALU: [Alu; 4] = [Alu::Add, Alu::Sub, Alu::Xor, Alu::Imul];

const ALL_UNARY: [Unary; 6] = [
    Unary::Add,
    Unary::Or,
    Unary::Xor,
    Unary::Ror,
    Unary::Shr,
    Unary::Sar,
];

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

fn any_reg() -> Reg {
    let r: usize = kani::any();
    kani::assume(r < 16);
    Reg::ALL[r]
}

/// The target of the branch whose first byte is at `at` and which ends
/// at `end`, from its bytes: a short `jcc rel8` or a near `0F jcc rel32`.
fn branch_target(code: &[u8], at: usize, end: usize) -> isize {
    match end - at {
        2 => end as isize + isize::from(code[at + 1] as i8),
        6 => {
            let rel = i32::from_le_bytes([code[at + 2], code[at + 3], code[at + 4], code[at + 5]]);
            end as isize + rel as isize
        }
        _ => panic!("not a branch"),
    }
}

/// Checks one program's code: given `MAX` bytes and the encoder's slack,
/// it fits in `MAX` if the program is supported, and its slot 9 branches
/// go to its start (offset 0) and its end. `BUF` is `MAX + SLACK`.
fn check_program<const WRITE: bool, const MAX: usize, const BUF: usize>() {
    assert_eq!(BUF, MAX + SLACK);
    let program = any_program();
    let mut buf = [0u8; BUF];
    let mut a = Asm::new(&mut buf);
    emit_program::<WRITE>(&mut a, &program);
    let len = a.finish();
    if !supported(&program) {
        assert!(len.is_none());
        return;
    }
    let len = len.expect("a supported program fits its bound");
    assert!(len <= MAX);

    // The program ends `sub ecx, 1; jae top; inc ecx`, the branch in its
    // six-byte form.
    assert_eq!(buf[len - 2..len], [0xff, 0xc1]);
    let jae_end = len - 2;
    let jae_at = jae_end - 6;
    assert_eq!(buf[jae_at..jae_at + 2], [0x0f, 0x83]);
    assert_eq!(branch_target(&buf, jae_at, jae_end), 0);
    assert_eq!(buf[jae_at - 3..jae_at], [0x83, 0xe9, 0x01]);
    if !program.always_loop {
        // Before that, `jnz next`, which goes to the end.
        let jnz_at = jae_at - 3 - 2;
        assert_eq!(buf[jnz_at], 0x75);
        assert_eq!(branch_target(&buf, jnz_at, jnz_at + 2), len as isize);
    }
}

#[kani::proof]
#[kani::unwind(10)]
fn write_program_fits_and_branches_home() {
    check_program::<true, WRITE_PROGRAM_MAX, { WRITE_PROGRAM_MAX + SLACK }>();
}

#[kani::proof]
#[kani::unwind(10)]
fn read_program_fits_and_branches_home() {
    check_program::<false, READ_PROGRAM_MAX, { READ_PROGRAM_MAX + SLACK }>();
}

/// The prologue and epilogue fit their bounds. With the two proofs above,
/// a function, which is the prologue, two phases of `PHASE_OVERHEAD_MAX`
/// bytes and 32 programs, and the epilogue, fits `MAX_CODE_LEN`, which a
/// constant assertion keeps within `CODE_CAPACITY`.
#[kani::proof]
#[kani::unwind(10)]
fn prologue_and_epilogue_fit() {
    let mut buf = [0u8; PROLOGUE_MAX + SLACK];
    let mut a = Asm::new(&mut buf);
    prologue(&mut a);
    assert!(a.finish().is_some_and(|len| len <= PROLOGUE_MAX));
    let mut buf = [0u8; EPILOGUE_MAX + SLACK];
    let mut a = Asm::new(&mut buf);
    epilogue(&mut a);
    assert!(a.finish().is_some_and(|len| len <= EPILOGUE_MAX));
}

/// A backward branch lands exactly on its label, for every position and
/// distance.
#[kani::proof]
fn backward_branches_land_on_their_label() {
    let mut buf = [0u8; 512];
    let mut a = Asm::new(&mut buf);
    let before: usize = kani::any();
    let gap: usize = kani::any();
    kani::assume(before <= 256 && gap <= 250);
    a.skip(before);
    let label = a.label();
    a.skip(gap);
    let at = a.len();
    let cond = if kani::any() {
        Cond::NotZero
    } else {
        Cond::NoCarry
    };
    a.branch_back(cond, label);
    let end = a.finish().expect("fits");
    assert_eq!(branch_target(&buf, at, end), before as isize);
}

/// A forward branch lands exactly where it is bound, or the code fails.
#[kani::proof]
fn forward_branches_land_where_bound() {
    let mut buf = [0u8; 256];
    let mut a = Asm::new(&mut buf);
    let branch = a.branch_forward(Cond::NotZero);
    let gap: usize = kani::any();
    kani::assume(gap <= 250);
    a.skip(gap);
    a.bind(branch);
    match a.finish() {
        Some(end) => {
            assert!(gap <= 127);
            assert_eq!(branch_target(&buf, 0, 2), end as isize);
        }
        None => assert!(gap > 127),
    }
}

/// A read-mode operation, for every pair of steps, register pair and
/// immediate: the bytes are `first dst, imm; mov eax, src32;
/// and eax, 0x3fff; combine dst, [rsi + rax]`, the read with no
/// displacement and no other base or index.
#[kani::proof]
fn scratchpad_reads_are_masked() {
    let which: usize = kani::any();
    kani::assume(which < ALL_ALU.len());
    let first: usize = kani::any();
    kani::assume(first < ALL_UNARY.len());
    let op = Operation::new(ALL_UNARY[first], ALL_ALU[which]);
    let mut buf = [0u8; 32];
    let mut a = Asm::new(&mut buf);
    a.operation_scratch(&op, kani::any(), kani::any(), kani::any());
    let len = a.finish().expect("fits");
    assert!(len == 16 || len == 17);
    // first dst, imm: REX.W and B (R8 to R15), 83 or C1, ModRM mod 11.
    assert_eq!(buf[0], 0x49);
    assert!(buf[1] == 0x83 || buf[1] == 0xc1);
    assert_eq!(buf[2] & 0xc0, 0xc0);
    // mov eax, src32: REX.B (R8 to R15), 8B, ModRM mod 11 reg 000.
    assert_eq!(buf[4], 0x41);
    assert_eq!(buf[5], 0x8b);
    assert_eq!(buf[6] & 0xf8, 0xc0);
    // and eax, 0x3fff.
    assert_eq!(buf[7..12], [0x25, 0xff, 0x3f, 0x00, 0x00]);
    // REX.W and R (R8 to R15) with X = B = 0 (index RAX, base RSI), the
    // opcode, then ModRM mod 00 rm 100 and SIB scale 1, index RAX, base
    // RSI.
    assert_eq!(buf[12], 0x4c);
    assert_eq!(buf[len - 1], 0x06);
    assert_eq!(buf[len - 2] & 0xc7, 0x04);
}

/// `SAVE`: `sub edi, 64; and edi, 0x3fc0`, then eight stores to
/// `[rsi + rdi + 8i]`.
#[kani::proof]
#[kani::unwind(10)]
fn saves_are_masked() {
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
    let mut buf = [0u8; 64];
    let mut a = Asm::new(&mut buf);
    a.save_block(&regs);
    assert_eq!(a.finish(), Some(49));
    assert_eq!(
        buf[..9],
        [0x83, 0xef, 0x40, 0x81, 0xe7, 0xc0, 0x3f, 0x00, 0x00]
    );
    for i in 0..8 {
        let s = &buf[9 + 5 * i..14 + 5 * i];
        // REX.W, X = B = 0; 89; ModRM mod 01 rm 100; SIB index RDI base
        // RSI; disp8 = 8i.
        assert_eq!(s[0] & 0xfb, 0x48);
        assert_eq!(s[1], 0x89);
        assert_eq!(s[2] & 0xc7, 0x44);
        assert_eq!(s[3], 0x3e);
        assert_eq!(usize::from(s[4]), 8 * i);
    }
}

/// The read mask keeps an 8-byte read inside the scratchpad, for every
/// register value, and selects the interpreter's address.
#[kani::proof]
fn read_mask_stays_in_range() {
    let x: u64 = kani::any();
    let index = (x as u32 & READ_MASK) as usize;
    assert!(index + 8 <= SCRATCHPAD_LEN);
    assert_eq!(index, crate::hash::load_address(x));
}

/// The save mask keeps the 64-byte block below the R8 slot for every
/// value of RDI, and on the interpreter's path, P = 16384 - 64 n for n
/// below 256, it gives the interpreter's P.
#[kani::proof]
fn save_mask_stays_in_range() {
    let edi: u32 = kani::any();
    let p = (edi.wrapping_sub(u32::from(SAVE_BLOCK)) & SAVE_MASK) as usize;
    assert!(p + usize::from(SAVE_BLOCK) <= R8_SLOT);
    assert_eq!(p % 64, 0);

    let n: u32 = kani::any();
    kani::assume(n < 256);
    let before = R8_SLOT as u32 - 64 * n;
    let after = before.wrapping_sub(u32::from(SAVE_BLOCK)) & SAVE_MASK;
    assert_eq!(after, before - 64);
}

/// The slot 9 code, `test; jnz next; sub ecx, 1; jae top; inc ecx`,
/// decides as the interpreter's `loops_again` does and leaves C the same,
/// for every budget and flag.
#[kani::proof]
fn loop_code_matches_the_interpreter() {
    let c: u32 = kani::any();
    let always: bool = kani::any();
    let flag: bool = kani::any();

    let (jit_loops, jit_c) = if !always && flag {
        (false, c)
    } else {
        let (after, borrow) = c.overflowing_sub(1);
        if !borrow {
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
