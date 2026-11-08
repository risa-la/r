//! Making the 32 programs from the first half of a seed.

use core::fmt;

use crate::stream::WordStream;
use crate::tables::{GROUP_PATTERNS, LARGE_SOURCES, SMALL_SOURCES};

/// Number of programs made from one seed.
pub const PROGRAM_COUNT: usize = 32;

/// Number of stream words each program takes.
pub(crate) const WORDS_PER_PROGRAM: usize = 16;

/// An arithmetic operation of slots 2 to 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    OrMul,
    XorMul,
    AddMul,
    RorXor,
    RorAdd,
    RorSub,
    SarXor,
    SarAdd,
    SarSub,
    ShrXor,
    ShrAdd,
    ShrSub,
}

/// The multiply group, by `lo(w) mod 3`.
const MULTIPLY_OPS: [Op; 3] = [Op::OrMul, Op::XorMul, Op::AddMul];

/// The mix group, by `lo(w) mod 9`.
const MIX_OPS: [Op; 9] = [
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

/// The constants of the multiply group, by `u mod 3`.
const MULTIPLY_CONSTANTS: [u64; 3] = [1, 9, 33];

impl Op {
    /// The name of the operation, as program listings show it.
    fn name(self) -> &'static str {
        match self {
            Op::OrMul => "OR_MUL",
            Op::XorMul => "XOR_MUL",
            Op::AddMul => "ADD_MUL",
            Op::RorXor => "ROR_XOR",
            Op::RorAdd => "ROR_ADD",
            Op::RorSub => "ROR_SUB",
            Op::SarXor => "SAR_XOR",
            Op::SarAdd => "SAR_ADD",
            Op::SarSub => "SAR_SUB",
            Op::ShrXor => "SHR_XOR",
            Op::ShrAdd => "SHR_ADD",
            Op::ShrSub => "SHR_SUB",
        }
    }

    /// The constant k for this operation, from the word u.
    fn constant(self, u: u64) -> u64 {
        match self {
            Op::OrMul | Op::XorMul | Op::AddMul => MULTIPLY_CONSTANTS[(u % 3) as usize],
            Op::RorXor | Op::RorAdd | Op::RorSub => 1 + u % 63,
            Op::SarXor | Op::SarAdd | Op::SarSub | Op::ShrXor | Op::ShrAdd | Op::ShrSub => {
                1 + u % 3
            }
        }
    }
}

/// One arithmetic instruction, in slots 2 to 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Instr {
    pub(crate) op: Op,
    /// Destination register, 0 to 7.
    pub(crate) dst: u8,
    /// Source register, 0 to 7, never equal to `dst`.
    pub(crate) src: u8,
    /// The constant k: 1, 9 or 33 for the multiply group, a
    /// rotate count of 1 to 63, or a shift count of 1 to 3.
    pub(crate) k: u64,
}

impl Instr {
    /// The new value of the destination, from its old value x and the
    /// operand v. All arithmetic wraps.
    #[inline(always)]
    pub(crate) fn apply(self, x: u64, v: u64) -> u64 {
        // Counts are 1 to 63, so the casts and shifts are exact.
        let n = self.k as u32;
        match self.op {
            Op::OrMul => (x | self.k).wrapping_mul(v),
            Op::XorMul => (x ^ self.k).wrapping_mul(v),
            Op::AddMul => x.wrapping_add(self.k).wrapping_mul(v),
            Op::RorXor => x.rotate_right(n) ^ v,
            Op::RorAdd => x.rotate_right(n).wrapping_add(v),
            Op::RorSub => x.rotate_right(n).wrapping_sub(v),
            Op::SarXor => sar(x, n) ^ v,
            Op::SarAdd => sar(x, n).wrapping_add(v),
            Op::SarSub => sar(x, n).wrapping_sub(v),
            Op::ShrXor => (x >> n) ^ v,
            Op::ShrAdd => (x >> n).wrapping_add(v),
            Op::ShrSub => (x >> n).wrapping_sub(v),
        }
    }
}

/// Arithmetic shift right: fills with copies of bit 63.
#[inline(always)]
pub(crate) fn sar(x: u64, n: u32) -> u64 {
    ((x as i64) >> n) as u64
}

/// One of the 32 generated programs.
///
/// Slot 0 (`SAVE`) and slot 10 (`END`) are the same in every program, so
/// only slots 1 to 9 are stored. The [`Display`](fmt::Display) form is
/// a one-line listing, for example
/// `STEP r1 13 | ROR_XOR r4 r0 26 | ... | LOOP_IF`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    /// Slot 1, `STEP`: its destination register.
    pub(crate) step_dst: u8,
    /// Slot 1, `STEP`: its rotate count, 1 to 63.
    pub(crate) step_k: u32,
    /// Slots 2 to 8.
    pub(crate) ops: [Instr; 7],
    /// Slot 9: `LOOP` if true (program 31), `LOOP_IF` if false.
    pub(crate) always_loop: bool,
}

impl Program {
    /// Makes program number `index` from the next 16 words of the program
    /// stream.
    pub(crate) fn build(stream: &mut WordStream, index: usize) -> Program {
        let mut w = [0u64; WORDS_PER_PROGRAM];
        for word in &mut w {
            *word = stream.next_word();
        }
        Program::from_words(&w, index)
    }

    /// Makes program number `index` from its 16 words w0 to w15.
    pub(crate) fn from_words(w: &[u64; WORDS_PER_PROGRAM], index: usize) -> Program {
        let layout = Layout::new(w, index);
        let pattern = GROUP_PATTERNS[layout.pattern].as_bytes();
        let sources = layout.sources.as_bytes();
        let dst = layout.dst;

        let ops = core::array::from_fn(|i| {
            let slot = i + 2;
            // Operation: the group from the pattern, then lo(w_i).
            let lo = w[i] as u32;
            let op = match pattern[i] {
                b'*' => MULTIPLY_OPS[(lo % 3) as usize],
                _ => MIX_OPS[(lo % 9) as usize],
            };
            // Digit T_{s-1} of the entry picks the source D[T_{s-1}].
            let t = sources[slot - 2] - b'0';
            Instr {
                op,
                dst: dst[slot - 1],
                src: dst[usize::from(t)],
                k: op.constant(w[slot + 7]),
            }
        });

        Program {
            step_dst: dst[0],
            // The constant of slot 1 is 1 + (w8 mod 63), at most 63.
            step_k: (1 + w[8] % 63) as u32,
            ops,
            always_loop: index == PROGRAM_COUNT - 1,
        }
    }
}

/// The choices a program's words make before its instructions are put
/// together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    /// Index of the group pattern, `w7 mod 35`.
    pub(crate) pattern: usize,
    /// The destination list D.
    pub(crate) dst: [u8; 8],
    /// Whether the program takes its sources from the small table.
    pub(crate) small_table: bool,
    /// Index into the small or large table.
    pub(crate) source_index: usize,
    /// That table entry, the digits T1 to T7.
    pub(crate) sources: &'static str,
}

impl Layout {
    pub(crate) fn new(w: &[u64; WORDS_PER_PROGRAM], index: usize) -> Layout {
        // Destinations: the inside-out shuffle on hi(w0) to hi(w6).
        let mut dst = [0u8; 8];
        for n in 1..8 {
            let j = hi(w[n - 1]) % (n as u32 + 1);
            dst[n] = n as u8;
            dst.swap(n, j as usize);
        }

        // Programs 0, 6, 12, 18, 24 and 30 use the small table.
        let small_table = index.is_multiple_of(6);
        let table: &[&'static str] = if small_table {
            &SMALL_SOURCES
        } else {
            &LARGE_SOURCES
        };
        let source_index = (w[7] % table.len() as u64) as usize;

        Layout {
            pattern: (w[7] % GROUP_PATTERNS.len() as u64) as usize,
            dst,
            small_table,
            source_index,
            sources: table[source_index],
        }
    }
}

/// The high 32 bits of a word.
fn hi(x: u64) -> u32 {
    (x >> 32) as u32
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "STEP r{} {}", self.step_dst, self.step_k)?;
        for ins in &self.ops {
            write!(
                f,
                " | {} r{} r{} {}",
                ins.op.name(),
                ins.dst,
                ins.src,
                ins.k
            )?;
        }
        f.write_str(if self.always_loop {
            " | LOOP"
        } else {
            " | LOOP_IF"
        })
    }
}

/// Makes all 32 programs from the first half of a seed. The
/// stream has key `seed[0..16]` and tweak 2^64 - 1, and each program takes
/// exactly 16 words of it, so every seed works.
pub(crate) fn build_programs(program_key: [u64; 2]) -> [Program; PROGRAM_COUNT] {
    let mut stream = WordStream::new(program_key, u64::MAX);
    // `from_fn` calls the closure in index order, so program 0 is built first.
    core::array::from_fn(|index| Program::build(&mut stream, index))
}
