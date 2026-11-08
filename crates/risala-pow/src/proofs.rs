//! Kani proofs. Run them with `cargo kani -p risala-pow`.
//!
//! Each harness states a property and lets Kani check it for every input:
//! every set of words a program is made from, every register value, every
//! run of loop flags. The tests check that the hashes come out right for
//! some seeds; these check that nothing can go wrong for any seed.

use crate::hash::{LOOP_BUDGET, R8_SLOT, ROUNDS, SCRATCHPAD_LEN, load_address, loops_again};
use crate::program::{Instr, Layout, Op, PROGRAM_COUNT, Program, WORDS_PER_PROGRAM, sar};
use crate::puzzle::last_nonce_of_block;

/// Every operation.
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

fn any_program_index() -> usize {
    let index: usize = kani::any();
    kani::assume(index < PROGRAM_COUNT);
    index
}

/// Whether `k` is a constant that operation `op` can hold.
fn constant_in_range(op: Op, k: u64) -> bool {
    match op {
        Op::OrMul | Op::XorMul | Op::AddMul => matches!(k, 1 | 9 | 33),
        Op::RorXor | Op::RorAdd | Op::RorSub => (1..=63).contains(&k),
        _ => (1..=3).contains(&k),
    }
}

/// The destination list is a permutation of R0 to R7, for every word and
/// every program.
#[kani::proof]
fn destinations_are_a_permutation() {
    let w: [u64; WORDS_PER_PROGRAM] = kani::any();
    let layout = Layout::new(&w, any_program_index());
    let mut seen = 0u8;
    for d in layout.dst {
        assert!(d < 8);
        seen |= 1 << d;
    }
    assert_eq!(seen, 0xff);
}

/// Every program is well formed, for every 16 words and every program
/// number: slots 1 to 8 write each of R0 to R7 exactly once, no slot
/// reads the register it writes, every constant is in range, and only
/// the last program loops unconditionally. So every seed works.
#[kani::proof]
fn programs_are_well_formed() {
    let w: [u64; WORDS_PER_PROGRAM] = kani::any();
    let index = any_program_index();
    let p = Program::from_words(&w, index);

    assert!(p.step_dst < 8);
    assert!((1..=63).contains(&p.step_k));
    let mut written = 1u8 << p.step_dst;
    for ins in p.ops {
        assert!(ins.dst < 8);
        assert!(ins.src < 8);
        assert_ne!(ins.src, ins.dst);
        assert!(constant_in_range(ins.op, ins.k));
        written |= 1 << ins.dst;
    }
    assert_eq!(written, 0xff);
    assert_eq!(p.always_loop, index == PROGRAM_COUNT - 1);
}

/// Applying an instruction never panics, for every operation, every
/// constant it can hold and every pair of operands.
#[kani::proof]
fn instructions_never_panic() {
    let which: usize = kani::any();
    kani::assume(which < ALL_OPS.len());
    let op = ALL_OPS[which];
    let k: u64 = kani::any();
    kani::assume(constant_in_range(op, k));
    let ins = Instr {
        op,
        dst: 0,
        src: 1,
        k,
    };
    let _ = ins.apply(kani::any(), kani::any());
}

/// The arithmetic right shift fills the top with copies of bit 63, for
/// every value and every count from 1 to 63.
#[kani::proof]
fn sar_fills_with_the_sign_bit() {
    let x: u64 = kani::any();
    let n: u32 = kani::any();
    kani::assume((1..=63).contains(&n));
    let fill = if x >> 63 == 1 { !(u64::MAX >> n) } else { 0 };
    assert_eq!(sar(x, n), (x >> n) | fill);
}

/// A read-mode operand lies inside the scratchpad, for every register
/// value.
#[kani::proof]
fn loads_stay_in_the_scratchpad() {
    let a = load_address(kani::any());
    assert!(a + 8 <= SCRATCHPAD_LEN);
}

/// Runs the slot 9 decision of one program from budget `start`, with a
/// free loop flag on every pass. Returns the passes and the budget left.
fn run_one_program(start: u32, always_loop: bool) -> (u32, u32) {
    let mut c = start;
    let mut passes = 0;
    loop {
        passes += 1;
        if !loops_again(&mut c, always_loop, kani::any()) {
            return (passes, c);
        }
    }
}

/// A program other than the last runs one pass, plus one more for each
/// unit of budget it spends, and never spends more than is left,
/// whatever the loop flags.
#[kani::proof]
#[kani::unwind(34)]
fn a_program_spends_one_unit_per_loop() {
    let start: u32 = kani::any();
    kani::assume(start <= LOOP_BUDGET);
    let (passes, left) = run_one_program(start, false);
    assert!(left <= start);
    assert_eq!(passes, 1 + (start - left));
}

/// The last program loops until the budget is spent, whatever the loop
/// flags.
///
/// With the proof above, a round therefore runs exactly 64 passes: each
/// of the 32 programs runs one pass plus the budget it spends, and
/// together they spend all 32. Each pass of the write phase saves 64
/// bytes, so the four rounds save exactly 16384 bytes: the save pointer
/// goes from the R8 slot down to 0 and never below.
#[kani::proof]
#[kani::unwind(34)]
fn the_last_program_spends_the_rest() {
    let start: u32 = kani::any();
    kani::assume(start <= LOOP_BUDGET);
    let (passes, left) = run_one_program(start, true);
    assert_eq!(left, 0);
    assert_eq!(passes, 1 + start);
    assert_eq!(
        ROUNDS * (PROGRAM_COUNT + LOOP_BUDGET as usize) * 64,
        R8_SLOT
    );
}

/// The block arithmetic of `solve` never overflows, and the last nonce of
/// a nonce's block is at or after it and still in the same block. The
/// next nonce, if there is one, starts the next block.
///
/// Every nonce is `block * n + offset` for exactly one block and one
/// offset below n, which is how [`Puzzle::block`](crate::Puzzle::block)
/// splits it. The proof picks the block and offset rather than the
/// nonce, so it needs no division, which the solver finds very slow.
#[kani::proof]
#[kani::solver(kissat)]
fn block_ends_stay_in_the_block() {
    let n: u64 = kani::any();
    let block: u64 = kani::any();
    let offset: u64 = kani::any();
    kani::assume(n > 0 && offset < n);
    let first = block.checked_mul(n);
    kani::assume(first.is_some());
    let first = first.unwrap();
    let nonce = first.checked_add(offset);
    kani::assume(nonce.is_some());
    let nonce = nonce.unwrap();

    let last = last_nonce_of_block(block, n);
    assert!(nonce <= last);
    // Still in the block: fewer than n nonces from its first.
    assert!(last - first < n);
    // The next nonce is the first of the next block.
    if last < u64::MAX {
        assert_eq!(last + 1, first + n);
    }
}
