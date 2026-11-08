//! An encoder for the few A64 instruction forms the JIT emits.
//!
//! It is safe code that writes 32-bit instruction words into a slice of
//! words. It never writes past the slice: an instruction that does not
//! fit is not written, and [`Asm::finish`] then reports failure. The JIT
//! runs only on little-endian aarch64, where the words in memory are the
//! little-endian instructions A64 has whatever the data endianness.
//!
//! The scratchpad is reached only through two methods,
//! [`Asm::operation_scratch`] and [`Asm::save_block`]. Each emits the mask
//! of its address register immediately before the accesses, with no jump
//! target in between, and the base and address registers are fixed here,
//! not chosen by the caller. So no sequence of calls can emit an unmasked
//! scratchpad access. The register file is reached only through
//! [`Asm::load_pair_from_regs`], [`Asm::load_from_regs`] and
//! [`Asm::store_pair_to_regs`], at fixed offsets from X0.
//!
//! The operations of slots 2 to 8 are emitted from [`Template`]s: each
//! operation's words with its register and constant fields empty, and
//! where those fields are. Filling one in is a few multiplications and
//! one store, with no branches on the operation, which changes from slot
//! to slot and would often be mispredicted.
//!
//! Every form here is checked against an independent decoder
//! (yaxpeax-arm) for every register and many immediates, in `tests.rs`,
//! and the Kani proofs show that filling a template gives the same words
//! as encoding the operation directly, for every operation, register and
//! constant.

use crate::program::Op;

/// A general-purpose register, X0 to X30, by its number in the
/// encoding. Number 31, which is XZR or SP depending on the instruction,
/// is never a `Reg`: the encoders below spell XZR out where they use it,
/// and nothing here uses SP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reg(u8);

impl Reg {
    pub(crate) const X0: Reg = Reg(0);
    pub(crate) const X1: Reg = Reg(1);
    pub(crate) const X2: Reg = Reg(2);
    pub(crate) const X3: Reg = Reg(3);
    pub(crate) const X4: Reg = Reg(4);
    pub(crate) const X5: Reg = Reg(5);
    pub(crate) const X6: Reg = Reg(6);
    pub(crate) const X7: Reg = Reg(7);
    pub(crate) const X8: Reg = Reg(8);
    pub(crate) const X9: Reg = Reg(9);
    pub(crate) const X10: Reg = Reg(10);
    pub(crate) const X11: Reg = Reg(11);
    pub(crate) const X12: Reg = Reg(12);
    pub(crate) const X13: Reg = Reg(13);
    pub(crate) const X14: Reg = Reg(14);
    pub(crate) const X15: Reg = Reg(15);
    pub(crate) const X16: Reg = Reg(16);

    /// Every register, X0 to X30, for the tests and proofs.
    #[cfg(any(test, kani))]
    pub(crate) const ALL: [Reg; 31] = {
        let mut all = [Reg(0); 31];
        let mut i = 0;
        while i < 31 {
            all[i] = Reg(i as u8);
            i += 1;
        }
        all
    };

    /// X2 to X9, for `i` from 0 to 7 (the low three bits of `i`): the
    /// machine registers of R0 to R7.
    #[inline(always)]
    pub(crate) const fn file(i: u8) -> Reg {
        Reg(2 + (i & 7))
    }

    /// The register's number, 0 to 30.
    #[inline(always)]
    pub(crate) const fn number(self) -> u32 {
        self.0 as u32
    }
}

/// The register file's address: the first argument. Nothing the JIT
/// emits writes it.
pub(crate) const REGS_PTR: Reg = Reg::X0;
/// The scratchpad's address: the second argument. Nothing the JIT emits
/// writes it.
pub(crate) const SCRATCH_BASE: Reg = Reg::X1;
/// The save pointer P, as an offset from the scratchpad's address.
pub(crate) const SAVE_OFFSET: Reg = Reg::X11;
/// The address register: the masked index of a read-mode operand, or
/// the address of a `SAVE` block. Masked before every use.
pub(crate) const ADDRESS: Reg = Reg::X14;
/// The read-mode operand, loaded from the scratchpad.
pub(crate) const OPERAND: Reg = Reg::X15;
/// The constant of `OR_MUL` and `XOR_MUL`, which no logical immediate
/// can hold.
pub(crate) const CONSTANT: Reg = Reg::X16;

/// The mask of read addresses: the low 14 bits, so the index is at most
/// 16383 and an 8-byte read ends at most at byte 16391 of the 16392.
pub(crate) const READ_MASK: u64 = 0x3fff;
/// The mask of the save pointer: a multiple of 64 below 16384, so a
/// 64-byte block lies within the 16384 bytes before the R8 slot.
pub(crate) const SAVE_MASK: u64 = 0x3fc0;
/// The bytes `SAVE` writes, and what the save pointer drops by.
pub(crate) const SAVE_BLOCK: u32 = 64;

/// A logical immediate as its N, immr and imms fields: a run of
/// `imms + 1` ones, rotated right by `immr`, in a 64-bit element (N = 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BitMask {
    pub(crate) n: u32,
    pub(crate) immr: u32,
    pub(crate) imms: u32,
}

impl BitMask {
    /// The value it stands for, for N = 1 and `imms` below 63, the only
    /// kind used here.
    pub(crate) const fn value(self) -> u64 {
        assert!(self.n == 1 && self.imms < 63 && self.immr < 64);
        ((1u64 << (self.imms + 1)) - 1).rotate_right(self.immr)
    }
}

/// [`READ_MASK`]: 14 ones, not rotated.
pub(crate) const READ_MASK_IMM: BitMask = BitMask {
    n: 1,
    immr: 0,
    imms: 13,
};
/// [`SAVE_MASK`]: 8 ones, rotated right by 58, that is left by 6.
pub(crate) const SAVE_MASK_IMM: BitMask = BitMask {
    n: 1,
    immr: 58,
    imms: 7,
};
const _: () = assert!(READ_MASK_IMM.value() == READ_MASK);
const _: () = assert!(SAVE_MASK_IMM.value() == SAVE_MASK);

/// The largest constant an operation may have: the 12 bits of `add`'s
/// immediate. Counts are at most 63, and `movz` takes 16 bits.
pub(crate) const MAX_CONSTANT: u32 = 0xfff;

/// The most words an operation of slots 2 to 8 takes in write mode.
pub(crate) const WRITE_OP_WORDS: usize = 3;
/// The most words an operation takes in read mode: two for the read of
/// its operand and three for the operation.
pub(crate) const READ_OP_WORDS: usize = 5;
/// The words [`Asm::save_block`] emits.
pub(crate) const SAVE_WORDS: usize = 7;
/// The most words a write stores beyond the end of the code: an
/// operation stores all its template's words and keeps at least one in
/// write mode, three in read mode. A buffer must have this much room
/// past the code it is to hold.
pub(crate) const SLACK: usize = 2;

/// `brk #0`, which fills the buffer past the code.
pub(crate) const TRAP: u32 = 0xd420_0000;
/// `ret`, to the address in X30.
const RET: u32 = 0xd65f_03c0;
/// Register number 31 where it means the zero register.
const XZR: u32 = 31;

// Shifts of a register operand.
const LSL: u32 = 0;
const LSR: u32 = 1;
const ASR: u32 = 2;
const ROR: u32 = 3;

// The logical operations, by their opc field.
const ORR: u32 = 1;
const EOR: u32 = 2;

// The arithmetic operations, by their op field.
const ADD: u32 = 0;
const SUB: u32 = 1;

// The encoders. Registers are numbers 0 to 31; each field is cut to its
// width, so no value spills into another field.

/// `LDP Xt, Xt2, [Xn, #8 * words]`, signed offset.
const fn ldp(rt: u32, rt2: u32, rn: u32, words: u32) -> u32 {
    0xa940_0000 | (words & 0x7f) << 15 | (rt2 & 31) << 10 | (rn & 31) << 5 | (rt & 31)
}

/// `STP Xt, Xt2, [Xn, #8 * words]`, signed offset.
const fn stp(rt: u32, rt2: u32, rn: u32, words: u32) -> u32 {
    0xa900_0000 | (words & 0x7f) << 15 | (rt2 & 31) << 10 | (rn & 31) << 5 | (rt & 31)
}

/// `LDR Xt, [Xn, #8 * words]`, unsigned offset.
const fn ldr_imm(rt: u32, rn: u32, words: u32) -> u32 {
    0xf940_0000 | (words & 0xfff) << 10 | (rn & 31) << 5 | (rt & 31)
}

/// `LDR Xt, [Xn, Xm]`: register offset, LSL #0.
pub(crate) const fn ldr_reg(rt: u32, rn: u32, rm: u32) -> u32 {
    0xf860_6800 | (rm & 31) << 16 | (rn & 31) << 5 | (rt & 31)
}

/// `MOVZ Xd, #imm16` (`sf` = 1) or `MOVZ Wd, #imm16` (`sf` = 0).
const fn movz(sf: u32, rd: u32, imm16: u32) -> u32 {
    0x5280_0000 | (sf & 1) << 31 | (imm16 & 0xffff) << 5 | (rd & 31)
}

/// `MUL Xd, Xn, Xm`, that is `MADD Xd, Xn, Xm, XZR`: the low 64 bits of
/// the product.
const fn mul(rd: u32, rn: u32, rm: u32) -> u32 {
    0x9b00_0000 | (rm & 31) << 16 | XZR << 10 | (rn & 31) << 5 | (rd & 31)
}

/// `EXTR Xd, Xn, Xm, #lsb`. With Xn = Xm it is `ROR Xd, Xn, #lsb`.
const fn extr(rd: u32, rn: u32, rm: u32, lsb: u32) -> u32 {
    0x93c0_0000 | (rm & 31) << 16 | (lsb & 63) << 10 | (rn & 31) << 5 | (rd & 31)
}

/// `ORR`, `EOR` (by `opc`) `Xd, Xn, Xm, <shift> #amount`.
const fn logical_reg(opc: u32, shift: u32, rd: u32, rn: u32, rm: u32, amount: u32) -> u32 {
    0x8a00_0000
        | (opc & 3) << 29
        | (shift & 3) << 22
        | (rm & 31) << 16
        | (amount & 63) << 10
        | (rn & 31) << 5
        | (rd & 31)
}

/// `ADD`, `SUB` (by `op`) `Xd, Xn, Xm, <shift> #amount`. The shift is
/// LSL, LSR or ASR.
const fn arith_reg(op: u32, shift: u32, rd: u32, rn: u32, rm: u32, amount: u32) -> u32 {
    0x8b00_0000
        | (op & 1) << 30
        | (shift & 3) << 22
        | (rm & 31) << 16
        | (amount & 63) << 10
        | (rn & 31) << 5
        | (rd & 31)
}

/// `ADD`, `SUB` (by `op`), setting the flags if `s`, `Xd, Xn, #imm12`
/// (`sf` = 1) or `Wd, Wn, #imm12` (`sf` = 0).
const fn arith_imm(sf: u32, op: u32, s: u32, rd: u32, rn: u32, imm12: u32) -> u32 {
    0x1100_0000
        | (sf & 1) << 31
        | (op & 1) << 30
        | (s & 1) << 29
        | (imm12 & 0xfff) << 10
        | (rn & 31) << 5
        | (rd & 31)
}

/// `AND Xd, Xn, #mask`.
pub(crate) const fn and_imm(rd: u32, rn: u32, mask: BitMask) -> u32 {
    0x9200_0000
        | (mask.n & 1) << 22
        | (mask.immr & 63) << 16
        | (mask.imms & 63) << 10
        | (rn & 31) << 5
        | (rd & 31)
}

/// `SBFM` (if `signed`) or `UBFM Xd, Xn, #immr, #imms`. With
/// `imms` = 63 they are `ASR` and `LSR Xd, Xn, #immr`.
const fn bitfield(signed: bool, rd: u32, rn: u32, immr: u32, imms: u32) -> u32 {
    let base = if signed { 0x9340_0000 } else { 0xd340_0000 };
    base | (immr & 63) << 16 | (imms & 63) << 10 | (rn & 31) << 5 | (rd & 31)
}

/// `TBNZ Rt, #bit, #4 * words`, for bits 0 to 31.
const fn tbnz(rt: u32, bit: u32, words: u32) -> u32 {
    0x3700_0000 | (bit & 31) << 19 | (words & 0x3fff) << 5 | (rt & 31)
}

/// `B.cond #4 * words`.
const fn b_cond(cond: u32, words: u32) -> u32 {
    0x5400_0000 | (words & 0x7_ffff) << 5 | (cond & 15)
}

/// An operation of slots 2 to 8 on Xd, with operand Xv and constant k:
/// its words and how many there are. Each operation is the
/// interpreter's, in at most three instructions:
///
/// - `OR_MUL`, `XOR_MUL`: `movz x16, #k; orr/eor xd, xd, x16;
///   mul xd, xd, xv`, since 9 and 33 are not logical immediates;
/// - `ADD_MUL`: `add xd, xd, #k; mul xd, xd, xv`;
/// - `ROR_XOR`, `SAR_XOR`, `SHR_XOR`, `SAR_ADD`, `SHR_ADD`: one
///   instruction, `eor/add xd, xv, xd, ror/asr/lsr #k`, the shifted
///   register being the destination;
/// - `ROR_ADD`, `ROR_SUB`, `SAR_SUB`, `SHR_SUB`: `ror/asr/lsr xd, xd, #k;
///   add/sub xd, xd, xv` (an added register cannot be rotated, and the
///   shifted register would be the subtrahend).
///
/// Xd must not be Xv, nor X16 for the first two.
pub(crate) const fn op_words(op: Op, d: u32, v: u32, k: u32) -> ([u32; 3], u32) {
    let c = CONSTANT.number();
    match op {
        Op::OrMul => (
            [
                movz(1, c, k),
                logical_reg(ORR, LSL, d, d, c, 0),
                mul(d, d, v),
            ],
            3,
        ),
        Op::XorMul => (
            [
                movz(1, c, k),
                logical_reg(EOR, LSL, d, d, c, 0),
                mul(d, d, v),
            ],
            3,
        ),
        Op::AddMul => ([arith_imm(1, ADD, 0, d, d, k), mul(d, d, v), 0], 2),
        Op::RorXor => ([logical_reg(EOR, ROR, d, v, d, k), 0, 0], 1),
        Op::RorAdd => ([extr(d, d, d, k), arith_reg(ADD, LSL, d, d, v, 0), 0], 2),
        Op::RorSub => ([extr(d, d, d, k), arith_reg(SUB, LSL, d, d, v, 0), 0], 2),
        Op::SarXor => ([logical_reg(EOR, ASR, d, v, d, k), 0, 0], 1),
        Op::SarAdd => ([arith_reg(ADD, ASR, d, v, d, k), 0, 0], 1),
        Op::SarSub => (
            [
                bitfield(true, d, d, k, 63),
                arith_reg(SUB, LSL, d, d, v, 0),
                0,
            ],
            2,
        ),
        Op::ShrXor => ([logical_reg(EOR, LSR, d, v, d, k), 0, 0], 1),
        Op::ShrAdd => ([arith_reg(ADD, LSR, d, v, d, k), 0, 0], 1),
        Op::ShrSub => (
            [
                bitfield(false, d, d, k, 63),
                arith_reg(SUB, LSL, d, d, v, 0),
                0,
            ],
            2,
        ),
    }
}

/// A write-mode operation on Xd with operand Xs: the operation itself.
pub(crate) const fn write_words(op: Op, d: u32, s: u32, k: u32) -> ([u32; WRITE_OP_WORDS], u32) {
    op_words(op, d, s, k)
}

/// A read-mode operation on Xd with operand the scratchpad at the low 14
/// bits of Xs: `and x14, xs, #0x3fff; ldr x15, [x1, x14]`, then the
/// operation with X15 as its operand. [`Asm::operation_scratch`] emits
/// this; the tests and proofs check it against this.
#[cfg(any(test, kani))]
pub(crate) const fn read_words(op: Op, d: u32, s: u32, k: u32) -> ([u32; READ_OP_WORDS], u32) {
    let (w, n) = op_words(op, d, OPERAND.number(), k);
    (
        [
            and_imm(ADDRESS.number(), s, READ_MASK_IMM),
            ldr_reg(OPERAND.number(), SCRATCH_BASE.number(), ADDRESS.number()),
            w[0],
            w[1],
            w[2],
        ],
        n + 2,
    )
}

/// An operation's N words with the destination register, source register
/// and constant fields empty, and for each word the value of a 1 in each
/// of those fields (zero where the word has no such field; two or three
/// bits where the register fills several fields).
///
/// The fields of a word do not overlap, and every encoder above is an OR
/// of its fields, so the word for registers d and s and constant k is
/// `base | d * dst | s * src | k * k_unit` as long as each value fits its
/// field: registers below 32, and constants checked by the compiler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Template<const N: usize> {
    base: [u32; N],
    dst: [u32; N],
    src: [u32; N],
    k_unit: [u32; N],
    /// The words it takes, 1 to N.
    len: u32,
}

impl<const N: usize> Template<N> {
    /// The template of an encoder, from its words for all fields zero,
    /// and for a 1 in the destination, the source and the constant.
    const fn new(
        zero: ([u32; N], u32),
        dst: ([u32; N], u32),
        src: ([u32; N], u32),
        k: ([u32; N], u32),
    ) -> Template<N> {
        let mut t = Template {
            base: zero.0,
            dst: [0; N],
            src: [0; N],
            k_unit: [0; N],
            len: zero.1,
        };
        let mut i = 0;
        while i < N {
            t.dst[i] = dst.0[i] ^ zero.0[i];
            t.src[i] = src.0[i] ^ zero.0[i];
            t.k_unit[i] = k.0[i] ^ zero.0[i];
            i += 1;
        }
        t
    }

    /// The words for registers Xd and Xs and constant k, and how many
    /// there are. Each value is first cut to its field: five bits for a
    /// register and twelve for a constant (the most the compiler
    /// accepts), so no value spills into another field.
    #[inline(always)]
    pub(crate) fn fill(&self, d: u32, s: u32, k: u32) -> ([u32; N], u32) {
        let (d, s, k) = (d & 31, s & 31, k & MAX_CONSTANT);
        let mut words = [0u32; N];
        for (i, word) in words.iter_mut().enumerate() {
            *word = self.base[i]
                | d.wrapping_mul(self.dst[i])
                | s.wrapping_mul(self.src[i])
                | k.wrapping_mul(self.k_unit[i]);
        }
        (words, self.len)
    }
}

/// The templates of one operation, in write and in read mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Operation {
    pub(crate) write: Template<WRITE_OP_WORDS>,
    /// The operation on X15, after the read that [`Asm::operation_scratch`]
    /// emits itself.
    pub(crate) read: Template<WRITE_OP_WORDS>,
}

impl Operation {
    pub(crate) const fn new(op: Op) -> Operation {
        Operation {
            write: Template::new(
                write_words(op, 0, 0, 0),
                write_words(op, 1, 0, 0),
                write_words(op, 0, 1, 0),
                write_words(op, 0, 0, 1),
            ),
            read: Template::new(
                op_words(op, 0, OPERAND.number(), 0),
                op_words(op, 1, OPERAND.number(), 0),
                op_words(op, 0, OPERAND.number(), 0),
                op_words(op, 0, OPERAND.number(), 1),
            ),
        }
    }
}

/// A branch condition, by its number in the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cond {
    /// Not equal: Z clear.
    Ne = 1,
    /// Unsigned higher or same: C set, which after a subtraction means
    /// there was no borrow.
    Hs = 2,
}

/// A position in the code that a later backward branch can target. Only
/// [`Asm::label`] makes one, between two instructions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Label(usize);

/// A `tbnz` waiting for its target, from [`Asm::tbnz_forward`].
#[must_use]
#[derive(Debug)]
pub(crate) struct Forward {
    /// Where the branch's word is.
    at: usize,
}

/// The assembler: a slice of words and how many are written.
pub(crate) struct Asm<'a> {
    buf: &'a mut [u32],
    /// Words written.
    pos: usize,
    /// Set when something did not fit or could not be encoded. Nothing
    /// more is written after that.
    failed: bool,
}

impl<'a> Asm<'a> {
    pub(crate) fn new(buf: &'a mut [u32]) -> Self {
        Asm {
            buf,
            pos: 0,
            failed: false,
        }
    }

    /// How many bytes are written.
    #[cfg(any(test, kani))]
    pub(crate) fn len(&self) -> usize {
        4 * self.pos
    }

    /// Skips `n` words, leaving them as they are, to place code at a given
    /// position. Fails if they are not there.
    #[cfg(any(test, kani))]
    pub(crate) fn skip_words(&mut self, n: usize) {
        match self.pos.checked_add(n) {
            Some(end) if end <= self.buf.len() => self.pos = end,
            _ => self.failed = true,
        }
    }

    /// The length of the code in bytes, or `None` if anything failed.
    pub(crate) fn finish(self) -> Option<usize> {
        (!self.failed).then_some(4 * self.pos)
    }

    /// Marks the code as failed: [`Asm::finish`] will return `None`.
    pub(crate) fn fail(&mut self) {
        self.failed = true;
    }

    /// Writes one instruction word, or fails if it does not fit.
    #[inline(always)]
    fn put(&mut self, word: u32) {
        if let Some(slot) = self.buf.get_mut(self.pos) {
            *slot = word;
            self.pos += 1;
        } else {
            self.failed = true;
        }
    }

    /// Writes the first `len` of N words, or fails if they do not fit.
    /// Where all N fit, it writes all N, as one fixed-size store, and the
    /// words past `len` are overwritten by the next instruction, or by
    /// [`Asm::fill_rest_with_traps`] at the end.
    ///
    /// All N words must fit, even when `len` is less, so the buffer needs
    /// [`SLACK`] words beyond the code. After a failure, later writes may
    /// still go into the buffer, but [`Asm::finish`] returns `None`, so the
    /// code is never used.
    #[inline(always)]
    fn put_words<const N: usize>(&mut self, words: [u32; N], len: u32) {
        if let Some(dst) = self
            .buf
            .get_mut(self.pos..)
            .and_then(|rest| rest.first_chunk_mut::<N>())
        {
            *dst = words;
            self.pos += (len as usize).min(N);
        } else {
            self.failed = true;
        }
    }

    /// `ldp r1, r2, [x0, #8 * slot]`: reads slots `slot` and `slot + 1` of
    /// the register file, in the prologue. The file has nine slots.
    pub(crate) fn load_pair_from_regs(&mut self, r1: Reg, r2: Reg, slot: u8) {
        if slot >= 8 {
            self.failed = true;
            return;
        }
        self.put(ldp(
            r1.number(),
            r2.number(),
            REGS_PTR.number(),
            u32::from(slot),
        ));
    }

    /// `ldr r, [x0, #8 * slot]`: reads slot `slot` of the register file,
    /// in the prologue.
    pub(crate) fn load_from_regs(&mut self, r: Reg, slot: u8) {
        if slot >= 9 {
            self.failed = true;
            return;
        }
        self.put(ldr_imm(r.number(), REGS_PTR.number(), u32::from(slot)));
    }

    /// `stp r1, r2, [x0, #8 * slot]`: writes slots `slot` and `slot + 1`
    /// of the register file, in the epilogue.
    pub(crate) fn store_pair_to_regs(&mut self, r1: Reg, r2: Reg, slot: u8) {
        if slot >= 8 {
            self.failed = true;
            return;
        }
        self.put(stp(
            r1.number(),
            r2.number(),
            REGS_PTR.number(),
            u32::from(slot),
        ));
    }

    /// `movz xd, #imm`, which clears the rest of the register.
    pub(crate) fn movz64(&mut self, rd: Reg, imm: u16) {
        self.put(movz(1, rd.number(), u32::from(imm)));
    }

    /// `movz wd, #imm`, which clears the rest of the register.
    pub(crate) fn movz32(&mut self, rd: Reg, imm: u16) {
        self.put(movz(0, rd.number(), u32::from(imm)));
    }

    /// `mul xd, xn, xm`.
    pub(crate) fn mul(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.put(mul(rd.number(), rn.number(), rm.number()));
    }

    /// `ror xd, xn, #k`, for k from 0 to 63.
    pub(crate) fn ror(&mut self, rd: Reg, rn: Reg, k: u32) {
        if k >= 64 {
            self.failed = true;
            return;
        }
        self.put(extr(rd.number(), rn.number(), rn.number(), k));
    }

    /// A write-mode operation of slots 2 to 8 on R`dst` and R`src` (X2 +
    /// `dst` and X2 + `src`), in one store. The compiler checks the
    /// constant fits.
    #[inline(always)]
    pub(crate) fn operation(&mut self, op: &Operation, dst: u8, src: u8, k: u32) {
        let (words, len) = op
            .write
            .fill(Reg::file(dst).number(), Reg::file(src).number(), k);
        self.put_words(words, len);
    }

    /// A read-mode operation of slots 2 to 8 on R`dst`, with the operand
    /// read from the scratchpad at the low 14 bits of R`src`, in one store:
    /// `and x14, xs, #0x3fff; ldr x15, [x1, x14]`, then the operation with
    /// X15 as its operand.
    ///
    /// Only this method emits a scratchpad read, and the mask always comes
    /// just before it.
    #[inline(always)]
    pub(crate) fn operation_scratch(&mut self, op: &Operation, dst: u8, src: u8, k: u32) {
        let (w, n) = op.read.fill(Reg::file(dst).number(), 0, k);
        self.put_words(
            [
                and_imm(ADDRESS.number(), Reg::file(src).number(), READ_MASK_IMM),
                ldr_reg(OPERAND.number(), SCRATCH_BASE.number(), ADDRESS.number()),
                w[0],
                w[1],
                w[2],
            ],
            n + 2,
        );
    }

    /// `SAVE`: `sub x11, x11, #64; and x11, x11, #0x3fc0;
    /// add x14, x1, x11`, then `stp regs[2i], regs[2i + 1], [x14, #16i]`
    /// for i = 0 to 3.
    ///
    /// The save pointer is lowered and masked before the stores, so they
    /// write only within the 16384 bytes before the R8 slot, whatever
    /// X11 held. On the interpreter's path the mask changes nothing: P
    /// goes from 16384 down to 0 in steps of 64. Only this method emits a
    /// scratchpad write.
    pub(crate) fn save_block(&mut self, regs: &[Reg; 8]) {
        let p = SAVE_OFFSET.number();
        let a = ADDRESS.number();
        self.put(arith_imm(1, SUB, 0, p, p, SAVE_BLOCK));
        self.put(and_imm(p, p, SAVE_MASK_IMM));
        self.put(arith_reg(ADD, LSL, a, SCRATCH_BASE.number(), p, 0));
        for (i, pair) in (0u32..).zip(regs.as_chunks::<2>().0) {
            self.put(stp(pair[0].number(), pair[1].number(), a, 2 * i));
        }
    }

    /// `subs wd, wd, #imm`, which sets C when there is no borrow.
    pub(crate) fn subs32(&mut self, rd: Reg, imm: u16) {
        if imm >= 4096 {
            self.failed = true;
            return;
        }
        self.put(arith_imm(
            0,
            SUB,
            1,
            rd.number(),
            rd.number(),
            u32::from(imm),
        ));
    }

    /// `add wd, wd, #imm`.
    pub(crate) fn add32(&mut self, rd: Reg, imm: u16) {
        if imm >= 4096 {
            self.failed = true;
            return;
        }
        self.put(arith_imm(
            0,
            ADD,
            0,
            rd.number(),
            rd.number(),
            u32::from(imm),
        ));
    }

    /// `ret`.
    pub(crate) fn ret(&mut self) {
        self.put(RET);
    }

    /// The current position, as a target for later backward branches.
    pub(crate) fn label(&self) -> Label {
        Label(self.pos)
    }

    /// A conditional branch back to `target`.
    ///
    /// The target is a label taken earlier, so it lies between two
    /// instructions already written, at or before this branch.
    pub(crate) fn branch_back(&mut self, cond: Cond, target: Label) {
        let Label(target) = target;
        // The offset counts from the branch, in words, and must fit in 19
        // signed bits.
        let back = (target <= self.pos)
            .then(|| self.pos - target)
            .filter(|&w| w < 1 << 18);
        match back {
            Some(back) => self.put(b_cond(cond as u32, (back as u32).wrapping_neg())),
            None => self.failed = true,
        }
    }

    /// `tbnz r, #bit` forward, to the position later passed to
    /// [`Asm::bind`]. `bit` is 0 to 31.
    pub(crate) fn tbnz_forward(&mut self, r: Reg, bit: u32) -> Forward {
        if bit >= 32 {
            self.failed = true;
        }
        let at = self.pos;
        self.put(tbnz(r.number(), bit, 0));
        Forward { at }
    }

    /// Points a forward branch at the current position. Fails if it is
    /// out of the branch's reach.
    pub(crate) fn bind(&mut self, branch: Forward) {
        if self.failed {
            return;
        }
        let words = self.pos - branch.at;
        match (u32::try_from(words), self.buf.get_mut(branch.at)) {
            (Ok(words @ 0..0x2000), Some(word)) => *word |= words << 5,
            _ => self.failed = true,
        }
    }

    /// Fills the rest of the buffer with `brk #0`, so that a stray jump or
    /// fall-through would trap.
    pub(crate) fn fill_rest_with_traps(&mut self) {
        if let Some(rest) = self.buf.get_mut(self.pos..) {
            rest.fill(TRAP);
        }
    }
}
