//! An encoder for the few x86-64 instruction forms the JIT emits.
//!
//! It is safe code that writes bytes into a slice. It never writes past
//! the slice: an instruction that does not fit is not written, and
//! [`Asm::finish`] then reports failure.
//!
//! The scratchpad is reached only through two methods,
//! [`Asm::operation_scratch`] and [`Asm::save_block`]. Each emits the mask of
//! its index register immediately before the accesses, with no jump
//! target in between, and the base and index registers are fixed here,
//! not chosen by the caller. So no sequence of calls can emit an unmasked
//! scratchpad access. The register file is reached only through
//! [`Asm::load_from_regs`] and [`Asm::store_to_regs`], at fixed offsets.
//!
//! The forms the programs use are encoded without branches on the
//! operation or registers: each fills a fixed-size array from small
//! tables and writes it whole, then counts only the bytes the instruction
//! takes. Branches on data that changes from program to program are
//! mispredicted often, and they made compiling twice as slow.
//!
//! Every form here is checked against an independent decoder (iced-x86)
//! for every register and every immediate, in `tests.rs`.

/// A general-purpose register, by its number in the encoding: 0 is RAX,
/// 7 is RDI, 8 to 15 are R8 to R15.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reg(u8);

impl Reg {
    pub(crate) const RAX: Reg = Reg(0);
    pub(crate) const RCX: Reg = Reg(1);
    pub(crate) const RDX: Reg = Reg(2);
    pub(crate) const RBP: Reg = Reg(5);
    pub(crate) const RSI: Reg = Reg(6);
    pub(crate) const RDI: Reg = Reg(7);
    pub(crate) const R8: Reg = Reg(8);
    pub(crate) const R9: Reg = Reg(9);
    pub(crate) const R10: Reg = Reg(10);
    pub(crate) const R11: Reg = Reg(11);
    pub(crate) const R12: Reg = Reg(12);
    pub(crate) const R13: Reg = Reg(13);
    pub(crate) const R14: Reg = Reg(14);
    pub(crate) const R15: Reg = Reg(15);

    /// Every register, for the tests and proofs.
    #[cfg(any(test, kani))]
    pub(crate) const ALL: [Reg; 16] = [
        Reg(0),
        Reg(1),
        Reg(2),
        Reg(3),
        Reg(4),
        Reg(5),
        Reg(6),
        Reg(7),
        Reg(8),
        Reg(9),
        Reg(10),
        Reg(11),
        Reg(12),
        Reg(13),
        Reg(14),
        Reg(15),
    ];

    /// The register's number, 0 to 15.
    #[cfg(test)]
    pub(crate) fn number(self) -> usize {
        usize::from(self.0)
    }

    /// R8 to R15, for `i` from 0 to 7 (the low three bits of `i`).
    #[inline(always)]
    pub(crate) const fn extended(i: u8) -> Reg {
        Reg(8 | (i & 7))
    }

    /// The low three bits, for ModRM and opcode fields.
    const fn low(self) -> u8 {
        self.0 & 7
    }

    /// The fourth bit, for a REX prefix.
    const fn high(self) -> u8 {
        (self.0 >> 3) & 1
    }
}

/// The scratchpad's base register. Nothing the JIT emits writes it.
pub(crate) const SCRATCH_BASE: Reg = Reg::RSI;
/// The index register of read-mode operands, masked before every use.
pub(crate) const SCRATCH_INDEX: Reg = Reg::RAX;
/// The register holding the save pointer P, as an offset from the base,
/// in the write phase. In the prologue and epilogue, the same register
/// holds the address of the register file.
pub(crate) const SAVE_OFFSET: Reg = Reg::RDI;
/// The register file's address, during the prologue and epilogue.
pub(crate) const REGS_PTR: Reg = Reg::RDI;

/// The mask of read addresses: the low 14 bits. A 32-bit `and` clears
/// the upper half of the register too, so the index is at most 16383 and
/// an 8-byte read ends at most at byte 16391 of the 16392.
pub(crate) const READ_MASK: u32 = 0x3fff;
/// The mask of the save pointer: a multiple of 64 below 16384, so a
/// 64-byte block lies within the 16384 bytes before the R8 slot.
pub(crate) const SAVE_MASK: u32 = 0x3fc0;
/// The bytes `SAVE` writes, and what the save pointer drops by.
pub(crate) const SAVE_BLOCK: u8 = 64;
/// The bytes [`Asm::save_block`] emits.
pub(crate) const SAVE_CODE_LEN: usize = 3 + 6 + 8 * 5;
/// The most bytes a write stores beyond the end of the code: each stores
/// a whole word (8 bytes, or 24 for a read-mode operation of at least 16)
/// and keeps only the instruction's bytes. A buffer must have this much
/// room past the code it is to hold.
pub(crate) const SLACK: usize = 8;

/// `dst = dst op src`, on 64-bit registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Alu {
    Add,
    Sub,
    Xor,
    /// The low 64 bits of the product.
    Imul,
}

/// For each [`Alu`], the opcode of the `r64, r/m64` form as a
/// little-endian word, and its length: one byte, or two for `imul`
/// (`0F AF`).
const ALU_OPCODE: [(u64, u32); 4] = [(0x03, 1), (0x2b, 1), (0x33, 1), (0xaf0f, 2)];

/// `dst = dst op imm8` on a 64-bit register: the first step of each
/// operation of slots 2 to 8, and the STEP's rotation. The immediate of
/// `Add`, `Or` and `Xor` is sign-extended; that of the shifts is a count,
/// of which the processor uses the low six bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unary {
    Add,
    Or,
    Xor,
    Ror,
    Shr,
    Sar,
}

/// For each [`Unary`], the opcode (`83 /n ib` or `C1 /n ib`) and the
/// ModRM reg field n.
const UNARY_OPCODE: [(u8, u8); 6] = [
    (0x83, 0),
    (0x83, 1),
    (0x83, 6),
    (0xc1, 1),
    (0xc1, 5),
    (0xc1, 7),
];

/// A branch condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cond {
    /// Not zero (`jnz`).
    NotZero,
    /// No borrow (`jae`, `jnc`).
    NoCarry,
}

impl Cond {
    const fn code(self) -> u8 {
        match self {
            Cond::NotZero => 5,
            Cond::NoCarry => 3,
        }
    }
}

/// A position in the code that a later backward branch can target. Only
/// [`Asm::label`] makes one, between two instructions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Label(usize);

/// A short forward branch waiting for its target, from
/// [`Asm::branch_forward`].
#[must_use]
#[derive(Debug)]
pub(crate) struct Forward {
    /// Where its 8-bit displacement byte is.
    at: usize,
    /// The end of the branch, which the displacement counts from.
    end: usize,
}

/// The assembler: a slice and how much of it is written.
pub(crate) struct Asm<'a> {
    buf: &'a mut [u8],
    pos: usize,
    /// Set when something did not fit or could not be encoded. Nothing
    /// more is written after that.
    failed: bool,
}

const fn rex(w: u8, r: u8, x: u8, b: u8) -> u8 {
    0x40 | (w << 3) | (r << 2) | (x << 1) | b
}

const fn modrm(md: u8, reg: u8, rm: u8) -> u8 {
    (md << 6) | ((reg & 7) << 3) | (rm & 7)
}

/// `[rsi + rax*1]` as ModRM (mod 00, rm 100, the reg field to be added)
/// and SIB bytes.
const SCRATCH_MODRM: u8 = modrm(0b00, 0, 0b100);
const SCRATCH_SIB: u8 = modrm(0b00, SCRATCH_INDEX.low(), SCRATCH_BASE.low());

/// `op dst, src` on 64-bit registers (`r64, r/m64` form): the bytes, as
/// a little-endian word, and their number.
const fn alu_code(op: Alu, dst: Reg, src: Reg) -> (u64, u32) {
    let (opcode, n) = ALU_OPCODE[op as usize];
    let m = modrm(0b11, dst.low(), src.low());
    (
        rex(1, dst.high(), 0, src.high()) as u64 | opcode << 8 | (m as u64) << (8 + 8 * n),
        2 + n,
    )
}

/// `op dst, imm8` on a 64-bit register: four bytes.
const fn unary_code(op: Unary, dst: Reg, imm: u8) -> u64 {
    let (opcode, extension) = UNARY_OPCODE[op as usize];
    rex(1, 0, 0, dst.high()) as u64
        | (opcode as u64) << 8
        | (modrm(0b11, extension, dst.low()) as u64) << 16
        | (imm as u64) << 24
}

/// `mov eax, src32; and eax, READ_MASK`: eight bytes. The `mov` (8B /r,
/// reg = eax) always has a REX prefix, so its length does not depend on
/// `src`; `and eax, imm32` is 25 id.
const fn mask_code(src: Reg) -> u64 {
    rex(0, 0, 0, src.high()) as u64
        | 0x8b << 8
        | (modrm(0b11, SCRATCH_INDEX.low(), src.low()) as u64) << 16
        | 0x25 << 24
        | (READ_MASK as u64) << 32
}

/// `op dst, [rsi + rax*1]`: the bytes and their number, four or five.
const fn scratch_code(op: Alu, dst: Reg) -> (u64, u32) {
    let (opcode, n) = ALU_OPCODE[op as usize];
    let m = SCRATCH_MODRM | (dst.low() << 3);
    (
        rex(1, dst.high(), SCRATCH_INDEX.high(), SCRATCH_BASE.high()) as u64
            | opcode << 8
            | (m as u64) << (8 + 8 * n)
            | (SCRATCH_SIB as u64) << (16 + 8 * n),
        3 + n,
    )
}

/// The bytes of `SAVE`: `sub edi, 64` (83 /5 ib), `and edi, imm32`
/// (81 /4 id), then `mov [rsi + rdi*1 + 8i], regs[i]` (89 /r, mod 01,
/// rm 100) for i = 0 to 7.
const fn save_code(regs: &[Reg; 8]) -> [u8; SAVE_CODE_LEN] {
    let mut code = [0u8; SAVE_CODE_LEN];
    let m = SAVE_MASK.to_le_bytes();
    let head = [
        0x83,
        modrm(0b11, 5, SAVE_OFFSET.low()),
        SAVE_BLOCK,
        0x81,
        modrm(0b11, 4, SAVE_OFFSET.low()),
        m[0],
        m[1],
        m[2],
        m[3],
    ];
    let mut i = 0;
    while i < head.len() {
        code[i] = head[i];
        i += 1;
    }
    let mut r = 0;
    while r < 8 {
        let reg = regs[r];
        let at = head.len() + 5 * r;
        code[at] = rex(1, reg.high(), SAVE_OFFSET.high(), SCRATCH_BASE.high());
        code[at + 1] = 0x89;
        code[at + 2] = modrm(0b01, reg.low(), 0b100);
        code[at + 3] = modrm(0b00, SAVE_OFFSET.low(), SCRATCH_BASE.low());
        code[at + 4] = 8 * r as u8;
        r += 1;
    }
    code
}

/// An operation of slots 2 to 8, `first dst, imm; combine dst, operand`,
/// encoded once for R8 as both registers and 0 as the immediate, with
/// where its fields are. [`Asm::operation`] and
/// [`Asm::operation_scratch`] put in the registers (R8 to R15) and the
/// immediate, so each operation costs one lookup and one store.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Operation {
    /// Write mode: the bytes, their number, and the bit at which the
    /// combine's ModRM byte starts.
    reg_code: u64,
    reg_len: u32,
    reg_modrm: u32,
    /// Read mode: the first 16 bytes, the rest, their number, and the bit
    /// at which the read's ModRM byte starts.
    mem_low: u128,
    mem_high: u64,
    mem_len: u32,
    mem_modrm: u32,
}

impl Operation {
    pub(crate) const fn new(first: Unary, combine: Alu) -> Operation {
        let base = Reg::R8;
        let unary = unary_code(first, base, 0);
        let (alu, alu_len) = alu_code(combine, base, base);
        let (read, read_len) = scratch_code(combine, base);
        // The opcode's bytes: one, or two for imul.
        let n = ALU_OPCODE[combine as usize].1;
        Operation {
            // Bytes 0 to 3, then the combine from byte 4.
            reg_code: unary | alu << 32,
            reg_len: 4 + alu_len,
            reg_modrm: 32 + 8 + 8 * n,
            // Bytes 0 to 3, the mask at 4 to 11, then the read from byte
            // 12: 16 or 17 bytes, the 17th in the second word.
            mem_low: unary as u128 | (mask_code(base) as u128) << 32 | (read as u128) << 96,
            mem_high: read >> 32,
            mem_len: 12 + read_len,
            mem_modrm: 96 + 8 + 8 * n,
        }
    }
}

impl<'a> Asm<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Asm {
            buf,
            pos: 0,
            failed: false,
        }
    }

    /// How many bytes are written.
    #[cfg(any(test, kani))]
    pub(crate) fn len(&self) -> usize {
        self.pos
    }

    /// Skips `n` bytes, leaving them as they are, to place code at a given
    /// position. Fails if they are not there.
    #[cfg(any(test, kani))]
    pub(crate) fn skip(&mut self, n: usize) {
        match self.pos.checked_add(n) {
            Some(end) if end <= self.buf.len() => self.pos = end,
            _ => self.failed = true,
        }
    }

    /// The length of the code, or `None` if anything failed.
    pub(crate) fn finish(self) -> Option<usize> {
        (!self.failed).then_some(self.pos)
    }

    /// Marks the code as failed: [`Asm::finish`] will return `None`.
    pub(crate) fn fail(&mut self) {
        self.failed = true;
    }

    /// Writes bytes, or fails if they do not fit. The length is a
    /// constant, so each write compiles to a few stores.
    #[inline(always)]
    fn put<const N: usize>(&mut self, bytes: [u8; N]) {
        self.put_first(bytes, N);
    }

    /// Writes the first `len` bytes of `bytes`, or fails if they do not
    /// fit. Where all N fit, it writes all N, as one fixed-size store, and
    /// the bytes past `len` are overwritten by the next instruction, or by
    /// [`Asm::fill_rest_with_traps`] at the end.
    ///
    /// All N bytes must fit, even when `len` is less, so the buffer needs
    /// [`SLACK`] bytes beyond the code. After a failure, later writes may
    /// still go into the buffer, but [`Asm::finish`] returns `None`, so the
    /// code is never used.
    #[inline(always)]
    fn put_first<const N: usize>(&mut self, bytes: [u8; N], len: usize) {
        if let Some(dst) = self
            .buf
            .get_mut(self.pos..)
            .and_then(|rest| rest.first_chunk_mut::<N>())
        {
            *dst = bytes;
            self.pos += len.min(N);
        } else {
            self.failed = true;
        }
    }

    /// Writes the low `len` bytes of `word`, little-endian. Building an
    /// instruction in a register and storing it whole is much faster than
    /// storing it byte by byte and copying it.
    #[inline(always)]
    fn put_word(&mut self, word: u64, len: u32) {
        self.put_first(word.to_le_bytes(), len as usize);
    }

    /// `push r64`.
    pub(crate) fn push(&mut self, r: Reg) {
        if r.high() == 1 {
            self.put([0x41, 0x50 + r.low()]);
        } else {
            self.put([0x50 + r.low()]);
        }
    }

    /// `pop r64`.
    pub(crate) fn pop(&mut self, r: Reg) {
        if r.high() == 1 {
            self.put([0x41, 0x58 + r.low()]);
        } else {
            self.put([0x58 + r.low()]);
        }
    }

    /// `mov r32, imm32`, which clears the upper half of the register.
    pub(crate) fn mov_imm32(&mut self, dst: Reg, imm: u32) {
        let [a, b, c, d] = imm.to_le_bytes();
        if dst.high() == 1 {
            self.put([0x41, 0xb8 + dst.low(), a, b, c, d]);
        } else {
            self.put([0xb8 + dst.low(), a, b, c, d]);
        }
    }

    /// `mov dst, [rdi + 8 * slot]`: reads slot `slot` of the register
    /// file, in the prologue.
    pub(crate) fn load_from_regs(&mut self, dst: Reg, slot: u8) {
        self.regs_access(0x8b, dst, slot);
    }

    /// `mov [rdi + 8 * slot], src`: writes slot `slot` of the register
    /// file, in the epilogue.
    pub(crate) fn store_to_regs(&mut self, src: Reg, slot: u8) {
        self.regs_access(0x89, src, slot);
    }

    fn regs_access(&mut self, opcode: u8, reg: Reg, slot: u8) {
        // Slots 0 to 15 keep the displacement within a signed byte.
        if slot >= 16 {
            self.failed = true;
            return;
        }
        self.put([
            rex(1, reg.high(), 0, REGS_PTR.high()),
            opcode,
            modrm(0b01, reg.low(), REGS_PTR.low()),
            slot * 8,
        ]);
    }

    /// `op dst, src` on 64-bit registers.
    #[inline(always)]
    pub(crate) fn alu(&mut self, op: Alu, dst: Reg, src: Reg) {
        let (code, len) = alu_code(op, dst, src);
        self.put_word(code, len);
    }

    /// `op dst, imm8` on a 64-bit register.
    #[inline(always)]
    pub(crate) fn unary(&mut self, op: Unary, dst: Reg, imm: u8) {
        self.put_word(unary_code(op, dst, imm), 4);
    }

    /// A write-mode operation of slots 2 to 8 on R8 + `dst` and R8 +
    /// `src`: `first dst, imm; combine dst, src`, in one store.
    #[inline(always)]
    pub(crate) fn operation(&mut self, op: &Operation, dst: u8, src: u8, imm: u8) {
        let (d, s) = (u64::from(dst & 7), u64::from(src & 7));
        self.put_word(
            op.reg_code | d << 16 | u64::from(imm) << 24 | (d << 3 | s) << op.reg_modrm,
            op.reg_len,
        );
    }

    /// A read-mode operation of slots 2 to 8 on R8 + `dst` and R8 +
    /// `src`, in one store: `first dst, imm; mov eax, src32;
    /// and eax, 0x3fff; combine dst, [rsi + rax]`.
    ///
    /// The 32-bit `mov` and `and` clear the upper half of RAX, so the
    /// index is the low 14 bits of `src`, as in the interpreter. Only
    /// this method emits a scratchpad read, and the mask always comes
    /// just before it.
    #[inline(always)]
    pub(crate) fn operation_scratch(&mut self, op: &Operation, dst: u8, src: u8, imm: u8) {
        let (d, s) = (u128::from(dst & 7), u128::from(src & 7));
        let low = op.mem_low | d << 16 | u128::from(imm) << 24 | s << 48 | (d << 3) << op.mem_modrm;
        let mut bytes = [0u8; 24];
        bytes[..16].copy_from_slice(&low.to_le_bytes());
        bytes[16..].copy_from_slice(&op.mem_high.to_le_bytes());
        self.put_first(bytes, op.mem_len as usize);
    }

    /// `SAVE`: `sub edi, 64; and edi, 0x3fc0`, then
    /// `mov [rsi + rdi + 8 * i], regs[i]` for i = 0 to 7.
    ///
    /// The save pointer is lowered and masked before the stores, so they
    /// write only within the 16384 bytes before the R8 slot, whatever
    /// RDI held. On the interpreter's path the mask changes nothing: P
    /// goes from 16384 down to 0 in steps of 64. Only this method emits a
    /// scratchpad write.
    #[inline(always)]
    pub(crate) fn save_block(&mut self, regs: &[Reg; 8]) {
        self.put(save_code(regs));
    }

    /// `test r8, imm8` on the low byte of a register. The REX prefix is
    /// always there, so the low bytes of RSP to RDI are SPL to DIL.
    pub(crate) fn test_low_byte(&mut self, r: Reg, imm: u8) {
        self.put([rex(0, 0, 0, r.high()), 0xf6, modrm(0b11, 0, r.low()), imm]);
    }

    /// `sub r32, imm8`, which sets the carry flag on a borrow.
    pub(crate) fn sub_imm8_32(&mut self, r: Reg, imm: u8) {
        if r.high() == 1 {
            self.put([0x41, 0x83, modrm(0b11, 5, r.low()), imm]);
        } else {
            self.put([0x83, modrm(0b11, 5, r.low()), imm]);
        }
    }

    /// `inc r32`.
    pub(crate) fn inc32(&mut self, r: Reg) {
        self.inc_dec(0, r);
    }

    /// `dec r32`.
    pub(crate) fn dec32(&mut self, r: Reg) {
        self.inc_dec(1, r);
    }

    fn inc_dec(&mut self, extension: u8, r: Reg) {
        if r.high() == 1 {
            self.put([0x41, 0xff, modrm(0b11, extension, r.low())]);
        } else {
            self.put([0xff, modrm(0b11, extension, r.low())]);
        }
    }

    /// `ret`.
    pub(crate) fn ret(&mut self) {
        self.put([0xc3]);
    }

    /// The current position, as a target for later backward branches.
    pub(crate) fn label(&self) -> Label {
        Label(self.pos)
    }

    /// A conditional branch back to `target`, always the six-byte form
    /// with a 32-bit displacement, so its length is fixed.
    ///
    /// The target is a label taken earlier, so it lies between two
    /// instructions already written, at or before this branch.
    pub(crate) fn branch_back(&mut self, cond: Cond, target: Label) {
        let Label(target) = target;
        // The displacement counts from the end of the branch. The distance
        // back must fit in an i32.
        let end = self.pos + 6;
        let back = (target <= self.pos)
            .then(|| i32::try_from(end - target).ok())
            .flatten();
        match back {
            Some(back) => {
                let [a, b, c, d] = (-back).to_le_bytes();
                self.put([0x0f, 0x80 | cond.code(), a, b, c, d]);
            }
            None => self.failed = true,
        }
    }

    /// A two-byte conditional branch forward, to the position later
    /// passed to [`Asm::bind`].
    pub(crate) fn branch_forward(&mut self, cond: Cond) -> Forward {
        self.put([0x70 | cond.code(), 0]);
        Forward {
            at: self.pos.wrapping_sub(1),
            end: self.pos,
        }
    }

    /// Points a forward branch at the current position. Fails if it is
    /// more than 127 bytes on.
    pub(crate) fn bind(&mut self, branch: Forward) {
        if self.failed {
            return;
        }
        let rel = self.pos - branch.end;
        match (u8::try_from(rel), self.buf.get_mut(branch.at)) {
            (Ok(rel @ 0..=127), Some(byte)) => *byte = rel,
            _ => self.failed = true,
        }
    }

    /// Fills the rest of the buffer with `int3`, so that a stray jump or
    /// fall-through would trap.
    pub(crate) fn fill_rest_with_traps(&mut self) {
        if let Some(rest) = self.buf.get_mut(self.pos..) {
            rest.fill(0xcc);
        }
    }
}
