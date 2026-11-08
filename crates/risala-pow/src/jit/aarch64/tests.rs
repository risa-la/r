//! Tests of the aarch64 encoder and compiler, against an independent
//! decoder, yaxpeax-arm. They run on every host.
//!
//! - Every instruction form the encoder has is decoded for every register
//!   and many immediates, and must be exactly the instruction meant.
//! - Filling an operation's template gives the words of encoding it
//!   directly, for every operation, register pair and constant.
//! - A small evaluator of decoded A64 instructions runs each operation,
//!   and whole compiled functions, against the interpreter.
//! - Whole compiled functions, for many seeds, go through a static
//!   verifier built on the decoder: it checks every memory access, every
//!   branch, and every register the safety argument rests on.

use std::collections::BTreeSet;
use std::vec;
use std::vec::Vec;

use sha2::{Digest as _, Sha256};
use yaxpeax_arch::{Arch, Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{ARMv8, Instruction, Opcode, Operand, ShiftStyle, SizeCode};

use super::asm::{
    self, Asm, Cond, OPERAND, Reg, SAVE_MASK, SLACK, TRAP, op_words, read_words, write_words,
};
use super::*;
use crate::hash::{Backend, HashWx, SCRATCHPAD_LEN, Scratchpad};

// Decoding.

fn decode(word: u32) -> Instruction {
    let bytes = word.to_le_bytes();
    <ARMv8 as Arch>::Decoder::default()
        .decode(&mut U8Reader::new(&bytes))
        .unwrap_or_else(|e| panic!("{word:08x} does not decode: {e:?}"))
}

/// Emits with `f` and checks the words decode to exactly `want`.
fn check(f: impl FnOnce(&mut Asm<'_>), want: &[Instruction]) {
    let mut buf = [0u32; 16];
    let mut a = Asm::new(&mut buf);
    f(&mut a);
    let len = a.finish().expect("fits");
    let words = &buf[..len / 4];
    let got: Vec<Instruction> = words.iter().map(|&w| decode(w)).collect();
    assert_eq!(got, want, "words {words:08x?}");
}

fn ins(opcode: Opcode, ops: &[Operand]) -> Instruction {
    let mut operands = [Operand::Nothing; 4];
    operands[..ops.len()].copy_from_slice(ops);
    Instruction { opcode, operands }
}

fn x(n: u32) -> Operand {
    Operand::Register(SizeCode::X, n as u16)
}

fn w(n: u32) -> Operand {
    Operand::Register(SizeCode::W, n as u16)
}

fn x_sp(n: u32) -> Operand {
    Operand::RegisterOrSP(SizeCode::X, n as u16)
}

fn w_sp(n: u32) -> Operand {
    Operand::RegisterOrSP(SizeCode::W, n as u16)
}

fn shifted(style: ShiftStyle, amount: u32, n: u32) -> Operand {
    Operand::RegShift(style, amount as u8, SizeCode::X, n as u16)
}

fn at(base: u32, offset: i32) -> Operand {
    Operand::RegPreIndex(base as u16, offset, false)
}

// Encodings, every register and many immediates.

#[test]
fn encode_register_file_access() {
    for r1 in Reg::ALL {
        for r2 in Reg::ALL {
            for slot in 0..8u8 {
                let mem = at(0, 8 * i32::from(slot));
                let (n1, n2) = (r1.number(), r2.number());
                check(
                    |a| a.load_pair_from_regs(r1, r2, slot),
                    &[ins(Opcode::LDP, &[x(n1), x(n2), mem])],
                );
                check(
                    |a| a.store_pair_to_regs(r1, r2, slot),
                    &[ins(Opcode::STP, &[x(n1), x(n2), mem])],
                );
            }
        }
        for slot in 0..9u8 {
            check(
                |a| a.load_from_regs(r1, slot),
                &[ins(
                    Opcode::LDR,
                    &[x(r1.number()), at(0, 8 * i32::from(slot))],
                )],
            );
        }
    }
    // Slots past the file are refused, not mis-encoded.
    let mut buf = [0u32; 4];
    for f in [
        |a: &mut Asm<'_>| a.load_pair_from_regs(Reg::X2, Reg::X3, 8),
        |a: &mut Asm<'_>| a.store_pair_to_regs(Reg::X2, Reg::X3, 8),
        |a: &mut Asm<'_>| a.load_from_regs(Reg::X2, 9),
    ] {
        let mut a = Asm::new(&mut buf);
        f(&mut a);
        assert_eq!(a.finish(), None);
    }
}

#[test]
fn encode_moves_and_counters() {
    for r in Reg::ALL {
        let n = r.number();
        for imm in [0u16, 1, 4, 32, 4095, 16384, 0xffff] {
            let shift = Operand::ImmShift(imm, 0);
            check(|a| a.movz64(r, imm), &[ins(Opcode::MOVZ, &[x(n), shift])]);
            check(|a| a.movz32(r, imm), &[ins(Opcode::MOVZ, &[w(n), shift])]);
        }
        for imm in 0..4096u16 {
            let i = Operand::Immediate(u32::from(imm));
            check(
                |a| a.subs32(r, imm),
                &[ins(Opcode::SUBS, &[w(n), w_sp(n), i])],
            );
            check(
                |a| a.add32(r, imm),
                &[ins(Opcode::ADD, &[w_sp(n), w_sp(n), i])],
            );
        }
        let mut buf = [0u32; 2];
        let mut a = Asm::new(&mut buf);
        a.subs32(r, 4096);
        assert_eq!(a.finish(), None);
        let mut a = Asm::new(&mut buf);
        a.add32(r, 4096);
        assert_eq!(a.finish(), None);
    }
    check(|a| a.ret(), &[ins(Opcode::RET, &[x(30)])]);
    assert_eq!(decode(TRAP), ins(Opcode::BRK, &[Operand::Imm16(0)]));
}

#[test]
fn encode_mul_and_ror() {
    for d in Reg::ALL {
        for n in Reg::ALL {
            for m in Reg::ALL {
                check(
                    |a| a.mul(d, n, m),
                    &[ins(
                        Opcode::MADD,
                        &[x(d.number()), x(n.number()), x(m.number()), x(31)],
                    )],
                );
            }
            for k in 0..64 {
                check(
                    |a| a.ror(d, n, k),
                    &[ins(
                        Opcode::EXTR,
                        &[
                            x(d.number()),
                            x(n.number()),
                            x(n.number()),
                            Operand::Immediate(k),
                        ],
                    )],
                );
            }
            let mut buf = [0u32; 2];
            let mut a = Asm::new(&mut buf);
            a.ror(d, n, 64);
            assert_eq!(a.finish(), None);
        }
    }
}

/// The instructions an operation on Xd with operand Xv and constant k
/// should be, written out from the meaning of each operation.
fn operation_meant(op: Op, d: u32, v: u32, k: u32) -> Vec<Instruction> {
    use ShiftStyle::{ASR, LSL, LSR, ROR};
    let c = asm::CONSTANT.number();
    let mul = ins(Opcode::MADD, &[x(d), x(d), x(v), x(31)]);
    let movz = ins(Opcode::MOVZ, &[x(c), Operand::ImmShift(k as u16, 0)]);
    // `op xd, xv, xd, <shift> #k`: the destination is the shifted one.
    let one = |opcode, style| vec![ins(opcode, &[x(d), x(v), shifted(style, k, d)])];
    // A shift of the destination, then `add/sub xd, xd, xv`.
    let then =
        |first: Instruction, opcode| vec![first, ins(opcode, &[x(d), x(d), shifted(LSL, 0, v)])];
    let ror = ins(Opcode::EXTR, &[x(d), x(d), x(d), Operand::Immediate(k)]);
    let shift_right = |opcode| {
        ins(
            opcode,
            &[x(d), x(d), Operand::Immediate(k), Operand::Immediate(63)],
        )
    };
    let logic_mul = |opcode| vec![movz, ins(opcode, &[x(d), x(d), shifted(LSL, 0, c)]), mul];
    match op {
        Op::OrMul => logic_mul(Opcode::ORR),
        Op::XorMul => logic_mul(Opcode::EOR),
        Op::AddMul => vec![
            ins(Opcode::ADD, &[x_sp(d), x_sp(d), Operand::Immediate(k)]),
            mul,
        ],
        Op::RorXor => one(Opcode::EOR, ROR),
        Op::RorAdd => then(ror, Opcode::ADD),
        Op::RorSub => then(ror, Opcode::SUB),
        Op::SarXor => one(Opcode::EOR, ASR),
        Op::SarAdd => one(Opcode::ADD, ASR),
        Op::SarSub => then(shift_right(Opcode::SBFM), Opcode::SUB),
        Op::ShrXor => one(Opcode::EOR, LSR),
        Op::ShrAdd => one(Opcode::ADD, LSR),
        Op::ShrSub => then(shift_right(Opcode::UBFM), Opcode::SUB),
    }
}

/// The constants to try for an operation: the edges of its range and
/// the ones programs use.
fn constants(op: Op) -> Vec<u32> {
    match constant_range(op) {
        (0, 4095) => vec![0, 1, 9, 33, 63, 64, 2048, 4095],
        (1, 63) => (1..=63).collect(),
        other => panic!("{other:?}"),
    }
}

/// Every operation, every register pair (X0 to X30) and many constants:
/// the direct encoding is the instruction meant.
#[test]
fn encode_operations() {
    for op in ALL_OPS {
        for d in Reg::ALL {
            for v in Reg::ALL {
                let (d, v) = (d.number(), v.number());
                if d == v || d == asm::CONSTANT.number() {
                    continue;
                }
                for k in constants(op) {
                    let (words, n) = op_words(op, d, v, k);
                    let got: Vec<Instruction> =
                        words[..n as usize].iter().map(|&w| decode(w)).collect();
                    assert_eq!(got, operation_meant(op, d, v, k), "{op:?} {d} {v} {k}");
                    assert!(words[n as usize..].iter().all(|&w| w == 0));
                }
            }
        }
    }
}

/// The read of a read-mode operand: `and x14, xs, #0x3fff;
/// ldr x15, [x1, x14]`, then the operation on X15.
#[test]
fn encode_read_operations() {
    for op in ALL_OPS {
        for s in Reg::ALL {
            let s = s.number();
            let k = constants(op)[1];
            let (words, n) = read_words(op, 2, s, k);
            let got: Vec<Instruction> = words[..n as usize].iter().map(|&w| decode(w)).collect();
            let mut want = vec![
                ins(Opcode::AND, &[x_sp(14), x(s), Operand::Imm64(0x3fff)]),
                ins(
                    Opcode::LDR,
                    &[
                        x(15),
                        Operand::RegRegOffset(1, 14, SizeCode::X, ShiftStyle::LSL, 0),
                    ],
                ),
            ];
            want.extend(operation_meant(op, 2, OPERAND.number(), k));
            assert_eq!(got, want, "{op:?} {s}");
        }
    }
}

/// The words the encoder emits for an operation, in write or read mode.
fn emit_operation(op: &asm::Operation, write: bool, dst: u8, src: u8, k: u32) -> Vec<u32> {
    let mut buf = [0u32; 5];
    let mut a = Asm::new(&mut buf);
    if write {
        a.operation(op, dst, src, k);
    } else {
        a.operation_scratch(op, dst, src, k);
    }
    let len = a.finish().expect("fits");
    buf[..len / 4].to_vec()
}

/// Filling a template gives the direct encoding, for every operation,
/// both modes, every pair of R0 to R7 and every constant in range. The
/// Kani proofs show the same.
#[test]
fn templates_match_direct_encodings() {
    for (i, op) in ALL_OPS.iter().enumerate() {
        assert_eq!(*op as usize, i);
        let t = &OPERATIONS[i];
        let (min, max) = constant_range(*op);
        for dst in 0..8u8 {
            for src in 0..8u8 {
                let (d, s) = (r(dst).number(), r(src).number());
                for k in min as u32..=max as u32 {
                    let (w, n) = write_words(*op, d, s, k);
                    assert_eq!(emit_operation(t, true, dst, src, k), w[..n as usize]);
                    let (w, n) = read_words(*op, d, s, k);
                    assert_eq!(emit_operation(t, false, dst, src, k), w[..n as usize]);
                }
            }
        }
    }
    for (i, reg) in R.iter().enumerate() {
        assert_eq!(r(i as u8), *reg);
        assert_eq!(SAVE_ORDER[7 - i], *reg);
    }
}

#[test]
fn encode_save_block() {
    let p = 11;
    let mut want = vec![
        ins(Opcode::SUB, &[x_sp(p), x_sp(p), Operand::Immediate(64)]),
        ins(Opcode::AND, &[x_sp(p), x(p), Operand::Imm64(SAVE_MASK)]),
        ins(Opcode::ADD, &[x(14), x(1), shifted(ShiftStyle::LSL, 0, p)]),
    ];
    for i in 0..4 {
        let (a, b) = (SAVE_ORDER[2 * i], SAVE_ORDER[2 * i + 1]);
        want.push(ins(
            Opcode::STP,
            &[x(a.number()), x(b.number()), at(14, 16 * i as i32)],
        ));
    }
    check(|a| a.save_block(&SAVE_ORDER), &want);
    // Any registers in any position.
    for r1 in Reg::ALL {
        let mut regs = SAVE_ORDER;
        regs[5] = r1;
        let mut want = want.clone();
        want[5] = ins(
            Opcode::STP,
            &[x(regs[4].number()), x(r1.number()), at(14, 32)],
        );
        check(|a| a.save_block(&regs), &want);
    }
}

/// Backward branches, at many positions and distances: the decoded
/// target is the label.
#[test]
fn encode_backward_branches() {
    for (cond, code) in [(Cond::Ne, 1), (Cond::Hs, 2)] {
        for before in [0usize, 1, 7, 300] {
            for gap in (0..400usize).chain([4095, 9000, (1 << 18) - 1]) {
                let mut buf = vec![0u32; before + gap + 1];
                let mut a = Asm::new(&mut buf);
                a.skip_words(before);
                let label = a.label();
                a.skip_words(gap);
                let at = a.len();
                a.branch_back(cond, label);
                assert_eq!(a.finish(), Some(at + 4));
                assert_eq!(
                    decode(buf[at / 4]),
                    ins(Opcode::Bcc(code), &[Operand::PCOffset(-4 * gap as i64)]),
                    "gap {gap}"
                );
            }
        }
        // One word too far.
        let mut buf = vec![0u32; (1 << 18) + 1];
        let mut a = Asm::new(&mut buf);
        let label = a.label();
        a.skip_words(1 << 18);
        a.branch_back(cond, label);
        assert_eq!(a.finish(), None);
    }
}

/// Forward branches, at every distance that fits, and the refusal of one
/// that does not.
#[test]
fn encode_forward_branches() {
    for r in Reg::ALL {
        for bit in [0, 5, 31] {
            // The offset counts from the branch: at most 0x1fff words.
            for gap in (0..64usize).chain([0x1ffd, 0x1ffe]) {
                let mut buf = vec![0u32; gap + 1];
                let mut a = Asm::new(&mut buf);
                let branch = a.tbnz_forward(r, bit);
                a.skip_words(gap);
                a.bind(branch);
                assert!(a.finish().is_some());
                assert_eq!(
                    decode(buf[0]),
                    ins(
                        Opcode::TBNZ,
                        &[
                            w(r.number()),
                            Operand::Imm16(bit as u16),
                            Operand::PCOffset(4 * (gap as i64 + 1))
                        ]
                    )
                );
            }
        }
    }
    let mut buf = vec![0u32; 0x2001];
    let mut a = Asm::new(&mut buf);
    let branch = a.tbnz_forward(Reg::X2, 5);
    a.skip_words(0x1fff);
    a.bind(branch);
    assert_eq!(a.finish(), None);
    let mut a = Asm::new(&mut buf);
    let _ = a.tbnz_forward(Reg::X2, 32);
    assert_eq!(a.finish(), None);
}

/// The encoder never writes past its buffer: it fails instead, at every
/// size.
#[test]
fn encoder_stops_at_the_end_of_its_buffer() {
    let programs = HashWx::new(&[3; 32]).programs().clone();
    let mut full = vec![0u32; CODE_CAPACITY / 4];
    let len = emit(&programs, &mut full).expect("fits") / 4;
    for size in (0..len).step_by(23).chain([len - 1]) {
        let mut buf = vec![0xabab_abab; size + 8];
        assert_eq!(emit(&programs, &mut buf[..size]), None, "size {size}");
        assert!(
            buf[size..].iter().all(|&w| w == 0xabab_abab),
            "wrote past {size}"
        );
    }
    let mut buf = vec![0u32; len + SLACK];
    assert_eq!(emit(&programs, &mut buf), Some(4 * len));
    assert_eq!(buf[..len], full[..len]);
}

// An evaluator of the decoded instructions the compiler uses.

/// Where the evaluator places the register file and the scratchpad.
const REGS_AT: u64 = 0x10_0000;
const SCRATCH_AT: u64 = 0x20_0000;

/// A tiny A64 machine: X0 to X30, the flags, and the two buffers. It
/// knows only the instructions the compiler emits, and panics on any
/// access outside the two buffers.
struct Cpu<'a> {
    x: [u64; 31],
    n: bool,
    z: bool,
    c: bool,
    regs: &'a mut [u64; 9],
    mem: &'a mut [u8; SCRATCHPAD_LEN],
    /// Instructions run.
    steps: u64,
}

impl Cpu<'_> {
    fn reg(&self, size: SizeCode, n: u16, zero: bool) -> u64 {
        let v = match n {
            0..31 => self.x[usize::from(n)],
            31 if zero => 0,
            _ => panic!("SP is never used"),
        };
        match size {
            SizeCode::X => v,
            SizeCode::W => v & 0xffff_ffff,
        }
    }

    fn read(&self, op: Operand) -> u64 {
        match op {
            Operand::Register(size, n) => self.reg(size, n, true),
            Operand::RegisterOrSP(size, n) => self.reg(size, n, false),
            Operand::RegShift(style, amount, SizeCode::X, n) => {
                let v = self.reg(SizeCode::X, n, true);
                let a = u32::from(amount);
                match style {
                    ShiftStyle::LSL => v << a,
                    ShiftStyle::LSR => v >> a,
                    ShiftStyle::ASR => ((v as i64) >> a) as u64,
                    ShiftStyle::ROR => v.rotate_right(a),
                    other => panic!("{other:?}"),
                }
            }
            Operand::Immediate(i) => u64::from(i),
            Operand::Imm64(i) => i,
            Operand::ImmShift(i, s) => u64::from(i) << s,
            other => panic!("operand {other:?}"),
        }
    }

    fn write(&mut self, op: Operand, value: u64) {
        let (size, n, zero) = match op {
            Operand::Register(size, n) => (size, n, true),
            Operand::RegisterOrSP(size, n) => (size, n, false),
            other => panic!("destination {other:?}"),
        };
        match n {
            0..31 => {
                self.x[usize::from(n)] = match size {
                    SizeCode::X => value,
                    SizeCode::W => value & 0xffff_ffff,
                }
            }
            31 if zero => {}
            _ => panic!("SP is never used"),
        }
    }

    fn address(&self, op: Operand) -> u64 {
        match op {
            Operand::RegPreIndex(base, offset, false) => self
                .reg(SizeCode::X, base, false)
                .wrapping_add(offset as i64 as u64),
            Operand::RegRegOffset(base, index, SizeCode::X, ShiftStyle::LSL, 0) => self
                .reg(SizeCode::X, base, false)
                .wrapping_add(self.reg(SizeCode::X, index, true)),
            other => panic!("address {other:?}"),
        }
    }

    fn load(&self, a: u64) -> u64 {
        if (REGS_AT..REGS_AT + 72).contains(&a) {
            assert_eq!(a % 8, 0);
            self.regs[((a - REGS_AT) / 8) as usize]
        } else if (SCRATCH_AT..=SCRATCH_AT + SCRATCHPAD_LEN as u64 - 8).contains(&a) {
            let i = (a - SCRATCH_AT) as usize;
            u64::from_le_bytes(self.mem[i..i + 8].try_into().unwrap())
        } else {
            panic!("load from {a:#x}")
        }
    }

    fn store(&mut self, a: u64, v: u64) {
        if (REGS_AT..REGS_AT + 72).contains(&a) {
            assert_eq!(a % 8, 0);
            self.regs[((a - REGS_AT) / 8) as usize] = v;
        } else if (SCRATCH_AT..=SCRATCH_AT + SCRATCHPAD_LEN as u64 - 8).contains(&a) {
            let i = (a - SCRATCH_AT) as usize;
            self.mem[i..i + 8].copy_from_slice(&v.to_le_bytes());
        } else {
            panic!("store to {a:#x}")
        }
    }

    /// Runs `code` from its first instruction to a `ret`.
    fn run(&mut self, code: &[Instruction]) {
        let mut pc = 0usize;
        loop {
            self.steps += 1;
            assert!(self.steps < 100_000_000, "runs on");
            let i = code[pc];
            let o = i.operands;
            let mut next = pc + 1;
            let mut jump = |offset: i64| next = (pc as i64 + offset / 4) as usize;
            match i.opcode {
                Opcode::LDP => {
                    let a = self.address(o[2]);
                    let (v1, v2) = (self.load(a), self.load(a + 8));
                    self.write(o[0], v1);
                    self.write(o[1], v2);
                }
                Opcode::STP => {
                    let a = self.address(o[2]);
                    self.store(a, self.read(o[0]));
                    self.store(a + 8, self.read(o[1]));
                }
                Opcode::LDR => {
                    let v = self.load(self.address(o[1]));
                    self.write(o[0], v);
                }
                Opcode::MOVZ => self.write(o[0], self.read(o[1])),
                Opcode::MADD => {
                    let v = self
                        .read(o[1])
                        .wrapping_mul(self.read(o[2]))
                        .wrapping_add(self.read(o[3]));
                    self.write(o[0], v);
                }
                Opcode::EXTR => {
                    let (hi, lo, lsb) = (self.read(o[1]), self.read(o[2]), self.read(o[3]));
                    let v = if lsb == 0 {
                        lo
                    } else {
                        (lo >> lsb) | (hi << (64 - lsb))
                    };
                    self.write(o[0], v);
                }
                Opcode::ORR => self.write(o[0], self.read(o[1]) | self.read(o[2])),
                Opcode::EOR => self.write(o[0], self.read(o[1]) ^ self.read(o[2])),
                Opcode::AND => self.write(o[0], self.read(o[1]) & self.read(o[2])),
                Opcode::ADD => self.write(o[0], self.read(o[1]).wrapping_add(self.read(o[2]))),
                Opcode::SUB => self.write(o[0], self.read(o[1]).wrapping_sub(self.read(o[2]))),
                Opcode::SUBS => {
                    assert!(matches!(o[0], Operand::Register(SizeCode::W, _)));
                    let (a, b) = (self.read(o[1]) as u32, self.read(o[2]) as u32);
                    let v = a.wrapping_sub(b);
                    (self.n, self.z, self.c) = (v >> 31 == 1, v == 0, a >= b);
                    self.write(o[0], u64::from(v));
                }
                Opcode::UBFM | Opcode::SBFM => {
                    assert_eq!(self.read(o[3]), 63, "only shifts right");
                    let (v, shift) = (self.read(o[1]), self.read(o[2]));
                    let v = if i.opcode == Opcode::SBFM {
                        ((v as i64) >> shift) as u64
                    } else {
                        v >> shift
                    };
                    self.write(o[0], v);
                }
                Opcode::TBNZ => {
                    let Operand::Register(_, n) = o[0] else {
                        panic!()
                    };
                    let (Operand::Imm16(bit), Operand::PCOffset(offset)) = (o[1], o[2]) else {
                        panic!()
                    };
                    if (self.reg(SizeCode::X, n, true) >> bit) & 1 == 1 {
                        jump(offset);
                    }
                }
                Opcode::Bcc(cond) => {
                    let Operand::PCOffset(offset) = o[0] else {
                        panic!()
                    };
                    let taken = match cond {
                        0 => self.z,
                        1 => !self.z,
                        2 => self.c,
                        3 => !self.c,
                        4 => self.n,
                        _ => panic!("condition {cond}"),
                    };
                    if taken {
                        jump(offset);
                    }
                }
                Opcode::RET => return,
                other => panic!("{other:?} at {pc}"),
            }
            pc = next;
        }
    }
}

/// Runs decoded code on `regs` and `mem` with the calling convention's
/// arguments, X0 and X1, set.
fn evaluate(code: &[Instruction], regs: &mut [u64; 9], mem: &mut [u8; SCRATCHPAD_LEN]) -> u64 {
    let mut cpu = Cpu {
        x: [0x5a5a_5a5a_5a5a_5a5a; 31],
        n: false,
        z: false,
        c: false,
        regs,
        mem,
        steps: 0,
    };
    cpu.x[0] = REGS_AT;
    cpu.x[1] = SCRATCH_AT;
    cpu.run(code);
    cpu.steps
}

/// A deterministic run of words.
fn randoms(seed: u64) -> impl Iterator<Item = u64> {
    let mut s = seed;
    core::iter::repeat_with(move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let x = s ^ (s >> 29);
        x.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ (x >> 31)
    })
}

/// Each operation, as decoded and evaluated, computes the interpreter's
/// arithmetic, in both modes, for every constant in range.
#[test]
fn operations_compute_the_interpreters_arithmetic() {
    let mut values = randoms(7);
    for op in ALL_OPS {
        let (min, max) = constant_range(op);
        for k in min..=max.min(127) {
            let ins = Instr {
                op,
                dst: 0,
                src: 1,
                k,
            };
            for _ in 0..4 {
                let (xv, v) = (values.next().unwrap(), values.next().unwrap());
                let mut mem = [0u8; SCRATCHPAD_LEN];
                for (i, b) in mem.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(31) ^ (v as u8);
                }
                for write in [true, false] {
                    let words = if write {
                        let (w, n) = write_words(op, 2, 3, k as u32);
                        w[..n as usize].to_vec()
                    } else {
                        let (w, n) = read_words(op, 2, 3, k as u32);
                        w[..n as usize].to_vec()
                    };
                    let mut code: Vec<Instruction> = words.iter().map(|&w| decode(w)).collect();
                    code.push(decode(0xd65f_03c0));
                    let mut cpu = Cpu {
                        x: [0; 31],
                        n: false,
                        z: false,
                        c: false,
                        regs: &mut [0; 9],
                        mem: &mut mem.clone(),
                        steps: 0,
                    };
                    cpu.x[1] = SCRATCH_AT;
                    cpu.x[2] = xv;
                    cpu.x[3] = v;
                    cpu.run(&code);
                    let operand = if write {
                        v
                    } else {
                        let a = crate::hash::load_address(v);
                        u64::from_le_bytes(mem[a..a + 8].try_into().unwrap())
                    };
                    assert_eq!(cpu.x[2], ins.apply(xv, operand), "{op:?} {k} {write}");
                    assert_eq!(cpu.x[3], v);
                }
            }
        }
    }
}

// Whole functions.

fn seeds(count: usize) -> impl Iterator<Item = [u8; 32]> {
    let mut seed = [0u8; 32];
    (0..count).map(move |i| {
        let out = seed;
        seed = Sha256::digest([&seed[..], &(i as u64).to_le_bytes()].concat()).into();
        out
    })
}

/// The words of a seed's compiled function.
fn compile(seed: &[u8; 32]) -> Vec<u32> {
    let mut buf = vec![0u32; CODE_CAPACITY / 4];
    let len = emit(HashWx::new(seed).programs(), &mut buf).expect("compiles");
    assert!(len <= MAX_CODE_LEN && len.is_multiple_of(4));
    assert!(buf[len / 4..].iter().all(|&w| w == TRAP), "the rest is brk");
    buf.truncate(len / 4);
    buf
}

/// Whole compiled functions, evaluated, give the interpreter's registers
/// and scratchpad, from a dirty scratchpad.
#[test]
fn compiled_functions_compute_the_interpreters_hash() {
    for seed in seeds(24) {
        let f = HashWx::with_backend(&seed, Backend::Interpreter);
        let code: Vec<Instruction> = compile(&seed).into_iter().map(decode).collect();
        for nonce in [
            0,
            1,
            u64::MAX,
            u64::from_le_bytes(seed[..8].try_into().unwrap()),
        ] {
            let mut want_mem = Scratchpad::new();
            let t = f.trace(&mut want_mem, nonce);
            let mut regs = t.start;
            let mut mem = [0xa5u8; SCRATCHPAD_LEN];
            mem[crate::hash::R8_SLOT..].copy_from_slice(&regs[8].to_le_bytes());
            evaluate(&code, &mut regs, &mut mem);
            assert_eq!(
                regs[..8],
                t.after_read[..8],
                "seed {seed:02x?} nonce {nonce}"
            );
            assert_eq!(regs[8], t.start[8], "R8 is not written back");
            let mut b = Scratchpad::new();
            f.hash(&mut b, nonce);
            assert_eq!(mem[..], b.bytes()[..], "seed {seed:02x?} nonce {nonce}");
        }
    }
}

/// What X14 or X11 holds, for the verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// X14: the low 14 bits of a register, masked by the instruction just
    /// before.
    ReadIndex,
    /// X14: X1 plus X11 masked.
    SaveAddress,
    /// X11: masked to a multiple of 64 below 16384.
    SaveMasked,
    Other,
}

/// The register numbers an operand names, and whether 31 there is SP.
fn registers(op: Operand) -> Vec<(u16, bool)> {
    match op {
        Operand::Register(_, n) | Operand::RegShift(_, _, _, n) => vec![(n, false)],
        Operand::RegisterOrSP(_, n) => vec![(n, true)],
        Operand::RegPreIndex(n, _, _) => vec![(n, true)],
        Operand::RegRegOffset(n, m, _, _, _) => vec![(n, true), (m, false)],
        _ => vec![],
    }
}

/// The static verifier. Checks, on the decoded words of a whole function:
///
/// - every word decodes, to one of the few instructions the compiler
///   uses;
/// - control flow: only `tbnz` and `b.ne`/`b.hs` to an instruction inside
///   the function, and one `ret`, to X30, at the end; no calls, no
///   indirect or unconditional jumps;
/// - every memory operand is one of: `ldr x15, [x1, x14]` with the
///   instruction just before `and x14, xN, #0x3fff`; `stp _, _,
///   [x14, #16i]`, i < 4, with X14 set by `add x14, x1, x11` from X11
///   masked by `and x11, x11, #0x3fc0`, with no jump target since; `ldp`,
///   `ldr` or `stp` at `[x0, #8i]` within the nine words of the register
///   file, the loads before the first jump target and the stores after
///   the last branch; no writeback;
/// - only X2 to X16 are written, and only X0 to X16 read (and XZR, and
///   X30 by `ret`): never SP, X18 or a callee-saved register.
fn verify_function(code: &[u32]) {
    let instrs: Vec<Instruction> = code.iter().map(|&w| decode(w)).collect();
    let n = instrs.len();
    assert_eq!(instrs.last().map(|i| i.opcode), Some(Opcode::RET));

    let mut targets = BTreeSet::new();
    let mut last_branch = 0;
    for (pc, i) in instrs.iter().enumerate() {
        let offset = match (i.opcode, i.operands) {
            (Opcode::TBNZ, [_, Operand::Imm16(5), Operand::PCOffset(o), _]) => Some(o),
            (Opcode::Bcc(1 | 2), [Operand::PCOffset(o), ..]) => Some(o),
            (Opcode::TBNZ | Opcode::Bcc(_), _) => panic!("branch at {pc}: {i}"),
            (Opcode::RET, [Operand::Register(SizeCode::X, 30), ..]) => {
                assert_eq!(pc, n - 1, "ret at {pc}");
                None
            }
            (
                Opcode::LDP
                | Opcode::STP
                | Opcode::LDR
                | Opcode::MOVZ
                | Opcode::MADD
                | Opcode::EXTR
                | Opcode::ORR
                | Opcode::EOR
                | Opcode::AND
                | Opcode::ADD
                | Opcode::SUB
                | Opcode::SUBS
                | Opcode::UBFM
                | Opcode::SBFM,
                _,
            ) => None,
            _ => panic!("{i} at {pc}"),
        };
        if let Some(o) = offset {
            assert_eq!(o % 4, 0);
            let t = pc as i64 + o / 4;
            assert!((0..n as i64).contains(&t), "branch to {t} at {pc}");
            targets.insert(t as usize);
            last_branch = pc;
        }
    }
    let first_target = *targets.first().expect("there are loops");

    let mut x14 = Held::Other;
    let mut x11 = Held::Other;
    for (pc, i) in instrs.iter().enumerate() {
        if targets.contains(&pc) {
            // Control merges here: assume nothing.
            x14 = Held::Other;
            x11 = Held::Other;
        }
        let o = i.operands;

        // Registers named.
        for (k, op) in o.iter().enumerate() {
            for (r, sp) in registers(*op) {
                let zr = r == 31 && !sp;
                let ok = r <= 16
                    || (zr && i.opcode == Opcode::MADD && k == 3)
                    || (r == 30 && i.opcode == Opcode::RET);
                assert!(ok, "register {r} in {i} at {pc}");
            }
        }

        // Memory operands.
        let mem = match i.opcode {
            Opcode::LDP | Opcode::STP => Some((o[2], 16)),
            Opcode::LDR => Some((o[1], 8)),
            _ => None,
        };
        if let Some((m, width)) = mem {
            match m {
                Operand::RegRegOffset(1, 14, SizeCode::X, ShiftStyle::LSL, 0) => {
                    assert_eq!(i.opcode, Opcode::LDR);
                    assert_eq!(o[0], x(15), "{i} at {pc}");
                    assert_eq!(x14, Held::ReadIndex, "unmasked read at {pc}: {i}");
                }
                Operand::RegPreIndex(14, offset, false) => {
                    assert_eq!(i.opcode, Opcode::STP, "{i} at {pc}");
                    assert_eq!(x14, Held::SaveAddress, "unmasked save at {pc}: {i}");
                    assert!(offset % 16 == 0 && (0..64).contains(&offset), "{i}");
                }
                Operand::RegPreIndex(0, offset, false) => {
                    assert!(
                        offset % 8 == 0 && offset >= 0 && offset + width <= 72,
                        "{i}"
                    );
                    if i.opcode == Opcode::STP {
                        assert!(pc > last_branch, "register file store in a loop at {pc}");
                    } else {
                        assert!(pc < first_target, "register file load in a loop at {pc}");
                    }
                }
                other => panic!("memory operand {other:?} at {pc}: {i}"),
            }
        }

        // Registers written.
        let written: &[Operand] = match i.opcode {
            Opcode::STP | Opcode::TBNZ | Opcode::Bcc(_) | Opcode::RET => &[],
            Opcode::LDP => &o[..2],
            _ => &o[..1],
        };
        let mut wrote = [false; 32];
        for op in written {
            let (Operand::Register(_, r) | Operand::RegisterOrSP(_, r)) = *op else {
                panic!("destination {op:?} at {pc}");
            };
            assert!((2..=16).contains(&r), "writes register {r} at {pc}: {i}");
            wrote[usize::from(r)] = true;
        }

        // What X14 and X11 hold after this instruction.
        let read_mask = matches!(
            (i.opcode, o),
            (
                Opcode::AND,
                [
                    Operand::RegisterOrSP(SizeCode::X, 14),
                    Operand::Register(SizeCode::X, _),
                    Operand::Imm64(0x3fff),
                    _
                ]
            )
        );
        let save_mask = (i.opcode, o)
            == (
                Opcode::AND,
                [x_sp(11), x(11), Operand::Imm64(SAVE_MASK), Operand::Nothing],
            );
        let save_address = (i.opcode, o)
            == (
                Opcode::ADD,
                [
                    x(14),
                    x(1),
                    shifted(ShiftStyle::LSL, 0, 11),
                    Operand::Nothing,
                ],
            );
        if wrote[14] {
            x14 = if read_mask {
                Held::ReadIndex
            } else if save_address && x11 == Held::SaveMasked {
                Held::SaveAddress
            } else {
                Held::Other
            };
        } else if x14 == Held::ReadIndex {
            // A read index is good for the next instruction only.
            x14 = Held::Other;
        }
        if wrote[11] {
            x11 = if save_mask {
                Held::SaveMasked
            } else {
                Held::Other
            };
        }
    }
}

#[test]
fn compiled_functions_pass_the_verifier() {
    for seed in seeds(48) {
        verify_function(&compile(&seed));
    }
}

/// The verifier itself catches the faults it looks for.
#[test]
fn the_verifier_catches_faults() {
    let good = compile(&[1; 32]);
    let fails = |code: &[u32]| std::panic::catch_unwind(|| verify_function(code)).is_err();
    assert!(!fails(&good));
    let find = |f: &dyn Fn(&Instruction) -> bool| {
        good.iter()
            .position(|&w| f(&decode(w)))
            .expect("there is one")
    };
    let read_mask = find(&|i| i.opcode == Opcode::AND && i.operands[2] == Operand::Imm64(0x3fff));
    let save_mask =
        find(&|i| i.opcode == Opcode::AND && i.operands[2] == Operand::Imm64(SAVE_MASK));
    let save_address = save_mask + 1;
    let mut faults: Vec<Vec<u32>> = Vec::new();
    // The read mask keeps 15 bits.
    let mut bad = good.clone();
    bad[read_mask] += 1 << 10;
    faults.push(bad);
    // The read mask goes to another register.
    let mut bad = good.clone();
    bad[read_mask] ^= 1;
    faults.push(bad);
    // An instruction between the mask and the read.
    let mut bad = good.clone();
    bad.insert(read_mask + 1, 0xd280_0010);
    faults.push(bad);
    // The save mask keeps 9 bits.
    let mut bad = good.clone();
    bad[save_mask] += 1 << 10;
    faults.push(bad);
    // The save address adds X12 instead of X11.
    let mut bad = good.clone();
    bad[save_address] ^= 7 << 16;
    faults.push(bad);
    // A store at offset 64 from X14.
    let mut bad = good.clone();
    bad[save_address + 4] += 2 << 15;
    faults.push(bad);
    // A ret in the middle.
    let mut bad = good.clone();
    bad[save_mask] = 0xd65f_03c0;
    faults.push(bad);
    // An indirect jump, `br x14`.
    let mut bad = good.clone();
    bad[save_mask] = 0xd61f_01c0;
    faults.push(bad);
    // A write to X1, `movz x1, #0`.
    let mut bad = good.clone();
    bad[save_mask] = 0xd280_0001;
    faults.push(bad);
    // A write to X19, `movz x19, #0`.
    let mut bad = good.clone();
    bad[save_mask] = 0xd280_0013;
    faults.push(bad);
    // A store through SP, `stp x2, x3, [sp]`.
    let mut bad = good.clone();
    bad[save_address + 1] = 0xa900_0fe2;
    faults.push(bad);
    for (i, bad) in faults.iter().enumerate() {
        assert!(fails(bad), "fault {i} not caught");
    }
}

/// The prologue and epilogue take exactly their bound, and every program
/// of many seeds fits its bound. The bounds are proven by Kani; this
/// checks they are not loose by much.
#[test]
fn code_sizes_are_within_their_bounds() {
    let mut buf = vec![0u32; CODE_CAPACITY / 4];
    let mut a = Asm::new(&mut buf);
    prologue(&mut a);
    assert_eq!(a.finish(), Some(PROLOGUE_MAX));
    let mut a = Asm::new(&mut buf);
    epilogue(&mut a);
    assert_eq!(a.finish(), Some(EPILOGUE_MAX));

    let (mut write_max, mut read_max, mut total_max) = (0, 0, 0);
    for seed in seeds(64) {
        let hashwx = HashWx::new(&seed);
        for p in hashwx.programs() {
            let mut a = Asm::new(&mut buf);
            emit_program::<true>(&mut a, p);
            write_max = write_max.max(a.finish().expect("fits"));
            let mut a = Asm::new(&mut buf);
            emit_program::<false>(&mut a, p);
            read_max = read_max.max(a.finish().expect("fits"));
        }
        total_max = total_max.max(compile(&seed).len());
    }
    assert!(write_max <= WRITE_PROGRAM_MAX && write_max + 24 >= WRITE_PROGRAM_MAX);
    assert!(read_max <= READ_PROGRAM_MAX && read_max + 24 >= READ_PROGRAM_MAX);
    assert!(total_max <= MAX_CODE_LEN, "{total_max}");
}

/// A program the compiler would get wrong is refused, not compiled.
#[test]
fn unsupported_programs_are_refused() {
    let programs = HashWx::new(&[5; 32]).programs().clone();
    let mut buf = vec![0u32; CODE_CAPACITY / 4];
    let mut changes: Vec<fn(&mut Program)> = vec![
        |p| p.ops[0].src = p.ops[0].dst,
        |p| p.ops[3].dst = p.step_dst,
        |p| p.ops[1].src = 8,
        |p| p.step_dst = 9,
        |p| p.step_k = 0,
        |p| p.step_k = 64,
    ];
    changes.push(|p| {
        p.ops[2].op = Op::RorXor;
        p.ops[2].k = 64;
    });
    changes.push(|p| {
        p.ops[2].op = Op::ShrSub;
        p.ops[2].k = 0;
    });
    changes.push(|p| {
        p.ops[2].op = Op::OrMul;
        p.ops[2].k = 4096;
    });
    for change in changes {
        let mut bad = programs.clone();
        change(&mut bad[7]);
        assert!(!supported(&bad[7]));
        assert_eq!(emit(&bad, &mut buf), None);
    }
}
