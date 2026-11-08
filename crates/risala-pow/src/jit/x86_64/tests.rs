//! Tests of the x86-64 encoder and compiler, against an independent
//! decoder, iced-x86.
//!
//! - Every instruction form the encoder has is decoded for every register
//!   and every immediate, and must be exactly the instruction meant, with
//!   no bytes left over.
//! - Whole compiled functions, for many seeds, go through a static
//!   verifier built on the decoder: it checks every memory access, every
//!   branch, and every register the safety argument rests on.

use std::collections::BTreeSet;
use std::format;
use std::vec;
use std::vec::Vec;

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, MemorySize,
    Mnemonic, OpAccess, OpKind, Register,
};
use sha2::{Digest as _, Sha256};

use super::asm::{Alu, Asm, Cond, Operation, Reg, Unary};
use super::*;
use crate::hash::HashWx;

const R64: [Register; 16] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSP,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

const R32: [Register; 16] = [
    Register::EAX,
    Register::ECX,
    Register::EDX,
    Register::EBX,
    Register::ESP,
    Register::EBP,
    Register::ESI,
    Register::EDI,
    Register::R8D,
    Register::R9D,
    Register::R10D,
    Register::R11D,
    Register::R12D,
    Register::R13D,
    Register::R14D,
    Register::R15D,
];

const R8L: [Register; 16] = [
    Register::AL,
    Register::CL,
    Register::DL,
    Register::BL,
    Register::SPL,
    Register::BPL,
    Register::SIL,
    Register::DIL,
    Register::R8L,
    Register::R9L,
    Register::R10L,
    Register::R11L,
    Register::R12L,
    Register::R13L,
    Register::R14L,
    Register::R15L,
];

fn q(r: Reg) -> Register {
    R64[r.number()]
}

fn d(r: Reg) -> Register {
    R32[r.number()]
}

/// An operand, as the decoder sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Opnd {
    Reg(Register),
    Imm(u64),
    Mem {
        base: Register,
        index: Register,
        scale: u32,
        displ: u64,
        size: MemorySize,
    },
    Branch(u64),
}

/// An instruction, as the decoder sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Desc {
    code: Code,
    ops: Vec<Opnd>,
}

fn desc(code: Code, ops: &[Opnd]) -> Desc {
    Desc {
        code,
        ops: ops.to_vec(),
    }
}

fn describe(ins: &Instruction) -> Desc {
    let ops = (0..ins.op_count())
        .map(|i| match ins.op_kind(i) {
            OpKind::Register => Opnd::Reg(ins.op_register(i)),
            OpKind::Memory => Opnd::Mem {
                base: ins.memory_base(),
                index: ins.memory_index(),
                scale: ins.memory_index_scale(),
                displ: ins.memory_displacement64(),
                size: ins.memory_size(),
            },
            OpKind::NearBranch64 => Opnd::Branch(ins.near_branch_target()),
            OpKind::Immediate8
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32
            | OpKind::Immediate32to64 => Opnd::Imm(ins.immediate(i)),
            other => panic!("unexpected operand kind {other:?} in {ins}"),
        })
        .collect();
    Desc {
        code: ins.code(),
        ops,
    }
}

/// Decodes all of `bytes` as 64-bit code at address `ip`. Every byte must
/// belong to a valid instruction.
fn decode_at(bytes: &[u8], ip: u64) -> Vec<Instruction> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut out = Vec::new();
    while decoder.can_decode() {
        let ins = decoder.decode();
        assert!(
            !ins.is_invalid(),
            "invalid code at {:#x} in {bytes:02x?}",
            ins.ip()
        );
        out.push(ins);
    }
    out
}

/// Emits with `f` and checks the bytes decode to exactly `want`.
fn check(f: impl FnOnce(&mut Asm<'_>), want: &[Desc]) {
    let mut buf = [0u8; 64];
    let mut a = Asm::new(&mut buf);
    f(&mut a);
    let len = a.finish().expect("fits");
    let got: Vec<Desc> = decode_at(&buf[..len], 0).iter().map(describe).collect();
    assert_eq!(got, want, "bytes {:02x?}", &buf[..len]);
}

/// `[rsi + rax]`, eight bytes, signed for `imul`.
fn scratch_operand(op: Alu) -> Opnd {
    Opnd::Mem {
        base: Register::RSI,
        index: Register::RAX,
        scale: 1,
        displ: 0,
        size: if op == Alu::Imul {
            MemorySize::Int64
        } else {
            MemorySize::UInt64
        },
    }
}

const ALU: [(Alu, Code); 4] = [
    (Alu::Add, Code::Add_r64_rm64),
    (Alu::Sub, Code::Sub_r64_rm64),
    (Alu::Xor, Code::Xor_r64_rm64),
    (Alu::Imul, Code::Imul_r64_rm64),
];

// Encodings, every register and immediate.

#[test]
fn encode_push_pop() {
    for r in Reg::ALL {
        check(|a| a.push(r), &[desc(Code::Push_r64, &[Opnd::Reg(q(r))])]);
        check(|a| a.pop(r), &[desc(Code::Pop_r64, &[Opnd::Reg(q(r))])]);
    }
}

#[test]
fn encode_mov_imm32() {
    for r in Reg::ALL {
        for imm in [0, 1, 4, 32, 16384, 0x7fff_ffff, 0xffff_ffff] {
            check(
                |a| a.mov_imm32(r, imm),
                &[desc(
                    Code::Mov_r32_imm32,
                    &[Opnd::Reg(d(r)), Opnd::Imm(u64::from(imm))],
                )],
            );
        }
    }
}

#[test]
fn encode_register_file_access() {
    for r in Reg::ALL {
        for slot in 0..16u8 {
            let mem = Opnd::Mem {
                base: Register::RDI,
                index: Register::None,
                scale: 1,
                displ: u64::from(slot) * 8,
                size: MemorySize::UInt64,
            };
            check(
                |a| a.load_from_regs(r, slot),
                &[desc(Code::Mov_r64_rm64, &[Opnd::Reg(q(r)), mem])],
            );
            check(
                |a| a.store_to_regs(r, slot),
                &[desc(Code::Mov_rm64_r64, &[mem, Opnd::Reg(q(r))])],
            );
        }
    }
    // Slots past 15 are refused, not mis-encoded.
    let mut buf = [0u8; 16];
    let mut a = Asm::new(&mut buf);
    a.load_from_regs(Reg::R8, 16);
    assert_eq!(a.finish(), None);
}

#[test]
fn encode_alu_registers() {
    for (op, code) in ALU {
        for dst in Reg::ALL {
            for src in Reg::ALL {
                check(
                    |a| a.alu(op, dst, src),
                    &[desc(code, &[Opnd::Reg(q(dst)), Opnd::Reg(q(src))])],
                );
            }
        }
    }
}

const UNARY: [(Unary, Code, bool); 6] = [
    (Unary::Add, Code::Add_rm64_imm8, true),
    (Unary::Or, Code::Or_rm64_imm8, true),
    (Unary::Xor, Code::Xor_rm64_imm8, true),
    (Unary::Ror, Code::Ror_rm64_imm8, false),
    (Unary::Shr, Code::Shr_rm64_imm8, false),
    (Unary::Sar, Code::Sar_rm64_imm8, false),
];

/// The decoded form of `unary dst, imm`.
fn unary_desc(code: Code, signed: bool, dst: Reg, imm: u8) -> Desc {
    // The immediate of add, or and xor is sign-extended.
    let value = if signed {
        imm as i8 as i64 as u64
    } else {
        u64::from(imm)
    };
    desc(code, &[Opnd::Reg(q(dst)), Opnd::Imm(value)])
}

/// Both kinds of operation of slots 2 to 8, for every pair of steps (a
/// superset of the twelve operations), every pair of R8 to R15, and the
/// immediates the programs use and the edges of a byte.
#[test]
fn encode_operations() {
    for (first, first_code, signed) in UNARY {
        for (combine, code) in ALU {
            let op = Operation::new(first, combine);
            for dst in 0..8u8 {
                for src in 0..8u8 {
                    let (rd, rs) = (Reg::extended(dst), Reg::extended(src));
                    for imm in [0, 1, 2, 3, 9, 33, 63, 64, 127, 128, 255] {
                        check(
                            |a| a.operation(&op, dst, src, imm),
                            &[
                                unary_desc(first_code, signed, rd, imm),
                                desc(code, &[Opnd::Reg(q(rd)), Opnd::Reg(q(rs))]),
                            ],
                        );
                        check(
                            |a| a.operation_scratch(&op, dst, src, imm),
                            &[
                                unary_desc(first_code, signed, rd, imm),
                                desc(
                                    Code::Mov_r32_rm32,
                                    &[Opnd::Reg(Register::EAX), Opnd::Reg(d(rs))],
                                ),
                                desc(
                                    Code::And_EAX_imm32,
                                    &[Opnd::Reg(Register::EAX), Opnd::Imm(0x3fff)],
                                ),
                                desc(code, &[Opnd::Reg(q(rd)), scratch_operand(combine)]),
                            ],
                        );
                    }
                }
            }
        }
    }
}

/// The table of operations is each operation's own form, and Ri is R8 + i.
#[test]
fn operation_table_and_registers() {
    for (i, op) in ALL_OPS.iter().enumerate() {
        assert_eq!(*op as usize, i);
        let (first, combine) = form(*op);
        let want = Operation::new(first, combine);
        assert_eq!(format!("{:?}", OPERATIONS[i]), format!("{want:?}"));
    }
    for (i, reg) in R.iter().enumerate() {
        assert_eq!(r(i as u8), *reg);
        assert_eq!(SAVE_ORDER[7 - i], *reg);
    }
}

#[test]
fn encode_unary() {
    for (op, code, signed) in UNARY {
        for dst in Reg::ALL {
            for imm in 0..=255u8 {
                check(
                    |a| a.unary(op, dst, imm),
                    &[unary_desc(code, signed, dst, imm)],
                );
            }
        }
    }
}

#[test]
fn encode_save_block() {
    // Each of the eight positions, with every register in it.
    for pos in 0..8 {
        for r in Reg::ALL {
            let mut regs = SAVE_ORDER;
            regs[pos] = r;
            let mut want = vec![
                desc(
                    Code::Sub_rm32_imm8,
                    &[Opnd::Reg(Register::EDI), Opnd::Imm(64)],
                ),
                desc(
                    Code::And_rm32_imm32,
                    &[Opnd::Reg(Register::EDI), Opnd::Imm(0x3fc0)],
                ),
            ];
            for (i, reg) in regs.iter().enumerate() {
                want.push(desc(
                    Code::Mov_rm64_r64,
                    &[
                        Opnd::Mem {
                            base: Register::RSI,
                            index: Register::RDI,
                            scale: 1,
                            displ: 8 * i as u64,
                            size: MemorySize::UInt64,
                        },
                        Opnd::Reg(q(*reg)),
                    ],
                ));
            }
            check(|a| a.save_block(&regs), &want);
        }
    }
}

#[test]
fn encode_test_low_byte() {
    for r in Reg::ALL {
        for imm in 0..=255u8 {
            check(
                |a| a.test_low_byte(r, imm),
                &[desc(
                    Code::Test_rm8_imm8,
                    &[Opnd::Reg(R8L[r.number()]), Opnd::Imm(u64::from(imm))],
                )],
            );
        }
    }
}

#[test]
fn encode_counters() {
    for r in Reg::ALL {
        for imm in 0..=255u8 {
            check(
                |a| a.sub_imm8_32(r, imm),
                &[desc(
                    Code::Sub_rm32_imm8,
                    // The immediate is sign-extended.
                    &[Opnd::Reg(d(r)), Opnd::Imm(imm as i8 as i64 as u64)],
                )],
            );
        }
        check(|a| a.inc32(r), &[desc(Code::Inc_rm32, &[Opnd::Reg(d(r))])]);
        check(|a| a.dec32(r), &[desc(Code::Dec_rm32, &[Opnd::Reg(d(r))])]);
    }
    check(|a| a.ret(), &[desc(Code::Retnq, &[])]);
}

/// Backward branches, at many positions and distances: the decoded
/// target is the label.
#[test]
fn encode_backward_branches() {
    for (cond, code) in [
        (Cond::NotZero, Code::Jne_rel32_64),
        (Cond::NoCarry, Code::Jae_rel32_64),
    ] {
        for before in [0usize, 1, 7, 300] {
            for gap in (0..400usize).chain([4095, 9000]) {
                let mut buf = vec![0u8; before + gap + 6];
                let mut a = Asm::new(&mut buf);
                a.skip(before);
                let label = a.label();
                a.skip(gap);
                let at = a.len();
                a.branch_back(cond, label);
                let len = a.finish().expect("fits");
                let got = decode_at(&buf[at..len], at as u64);
                assert_eq!(got.len(), 1);
                assert_eq!(
                    describe(&got[0]),
                    desc(code, &[Opnd::Branch(before as u64)]),
                    "gap {gap}"
                );
            }
        }
    }
}

/// Forward branches, at every distance that fits, and the refusal of one
/// that does not.
#[test]
fn encode_forward_branches() {
    for (cond, code) in [
        (Cond::NotZero, Code::Jne_rel8_64),
        (Cond::NoCarry, Code::Jae_rel8_64),
    ] {
        for gap in 0..=128usize {
            let mut buf = vec![0u8; gap + 2];
            let mut a = Asm::new(&mut buf);
            let branch = a.branch_forward(cond);
            a.skip(gap);
            a.bind(branch);
            match a.finish() {
                Some(_) => {
                    assert!(gap <= 127);
                    let got = decode_at(&buf[..2], 0);
                    assert_eq!(
                        describe(&got[0]),
                        desc(code, &[Opnd::Branch(2 + gap as u64)])
                    );
                }
                None => assert_eq!(gap, 128),
            }
        }
    }
}

/// The encoder never writes past its buffer: it fails instead, at every
/// size.
#[test]
fn encoder_stops_at_the_end_of_its_buffer() {
    let programs = HashWx::new(&[3; 32]).programs().clone();
    let mut full = vec![0u8; CODE_CAPACITY];
    let len = emit(&programs, &mut full).expect("fits");
    for size in (0..len).step_by(97).chain([len - 1]) {
        let mut buf = vec![0xabu8; size + 16];
        assert_eq!(emit(&programs, &mut buf[..size]), None, "size {size}");
        assert!(buf[size..].iter().all(|&b| b == 0xab), "wrote past {size}");
    }
    let mut buf = vec![0u8; len + super::asm::SLACK];
    assert_eq!(emit(&programs, &mut buf), Some(len));
    assert_eq!(buf[..len], full[..len]);
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

fn compile(seed: &[u8; 32]) -> Vec<u8> {
    let mut buf = vec![0u8; CODE_CAPACITY];
    let len = emit(HashWx::new(seed).programs(), &mut buf).expect("compiles");
    assert!(len <= MAX_CODE_LEN);
    assert!(buf[len..].iter().all(|&b| b == 0xcc), "the rest is int3");
    buf.truncate(len);
    buf
}

/// What a register holds, for the verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rdi {
    /// The register file's address, as at entry.
    RegsPtr,
    /// P, just masked to a multiple of 64 below 16384.
    SaveMasked,
    Other,
}

fn writes(info_regs: &[iced_x86::UsedRegister], reg: Register) -> bool {
    info_regs.iter().any(|u| {
        u.register().full_register() == reg
            && matches!(
                u.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            )
    })
}

/// The static verifier. Checks, on the decoded bytes of a whole function:
///
/// - every byte decodes, to one of the few instructions the compiler uses;
/// - control flow: only conditional branches to the start of an
///   instruction inside the function, and one `ret`, at the end; no
///   calls, no indirect or unconditional jumps;
/// - every explicit memory operand is one of: `[rsi + rax]` with the
///   instruction just before `and eax, 0x3fff`; `[rsi + rdi + 8i]`, i < 8,
///   with RDI masked by `and edi, 0x3fc0` since the last jump target and
///   not written since; `[rdi + 8i]`, i <= 8, while RDI still holds the
///   register file's address (from entry, or after `pop rdi`, with no
///   jump target in between); all 8 bytes wide;
/// - the only other memory accesses are the stack's, by push, pop and
///   the final ret;
/// - RSI is never written, RSP only by push and pop; the pushes all come
///   before the first jump target and the pops after the last branch,
///   and they match.
fn verify_function(code: &[u8]) {
    let instrs = decode_at(code, 0);
    let starts: BTreeSet<u64> = instrs.iter().map(|i| i.ip()).collect();
    let last = instrs.last().expect("not empty");
    assert_eq!(last.next_ip(), code.len() as u64);

    let mut targets = BTreeSet::new();
    let mut last_branch = 0;
    for (n, ins) in instrs.iter().enumerate() {
        match ins.flow_control() {
            FlowControl::Next => {}
            FlowControl::ConditionalBranch => {
                assert_eq!(ins.op_kind(0), OpKind::NearBranch64, "{ins}");
                let t = ins.near_branch_target();
                assert!(starts.contains(&t), "branch to {t:#x} at {:#x}", ins.ip());
                targets.insert(t);
                last_branch = ins.ip();
            }
            FlowControl::Return => assert_eq!(n, instrs.len() - 1, "ret at {:#x}", ins.ip()),
            other => panic!("{other:?} at {:#x}: {ins}", ins.ip()),
        }
        assert!(
            matches!(
                ins.mnemonic(),
                Mnemonic::Push
                    | Mnemonic::Pop
                    | Mnemonic::Mov
                    | Mnemonic::And
                    | Mnemonic::Sub
                    | Mnemonic::Imul
                    | Mnemonic::Xor
                    | Mnemonic::Add
                    | Mnemonic::Or
                    | Mnemonic::Ror
                    | Mnemonic::Sar
                    | Mnemonic::Shr
                    | Mnemonic::Test
                    | Mnemonic::Jne
                    | Mnemonic::Jae
                    | Mnemonic::Inc
                    | Mnemonic::Dec
                    | Mnemonic::Ret
            ),
            "{ins}"
        );
    }
    let first_target = *targets.first().expect("there are loops");

    let mut factory = InstructionInfoFactory::new();
    let mut rax_masked = false;
    let mut rdi = Rdi::RegsPtr;
    let mut pushed = Vec::new();
    let mut popped = Vec::new();
    for ins in &instrs {
        if targets.contains(&ins.ip()) {
            // Control merges here: assume nothing about RAX and RDI.
            rax_masked = false;
            rdi = Rdi::Other;
        }
        let info = factory.info(ins).clone();
        let at = ins.ip();

        // Explicit memory operands.
        let mut explicit = None;
        for i in 0..ins.op_count() {
            if ins.op_kind(i) != OpKind::Memory {
                continue;
            }
            assert!(
                matches!(ins.memory_size(), MemorySize::UInt64 | MemorySize::Int64),
                "{ins} at {at:#x}"
            );
            let (base, index, scale, displ) = (
                ins.memory_base(),
                ins.memory_index(),
                ins.memory_index_scale(),
                ins.memory_displacement64(),
            );
            match (base, index) {
                (Register::RSI, Register::RAX) => {
                    assert!(rax_masked, "unmasked read at {at:#x}: {ins}");
                    assert_eq!((scale, displ), (1, 0), "{ins}");
                }
                (Register::RSI, Register::RDI) => {
                    assert_eq!(rdi, Rdi::SaveMasked, "unmasked save at {at:#x}: {ins}");
                    assert_eq!(scale, 1, "{ins}");
                    assert!(displ % 8 == 0 && displ < 64, "{ins}");
                    assert_eq!(info.used_memory()[0].access(), OpAccess::Write);
                }
                (Register::RDI, Register::None) => {
                    assert_eq!(rdi, Rdi::RegsPtr, "register file access at {at:#x}: {ins}");
                    assert!(displ % 8 == 0 && displ <= 64, "{ins}");
                }
                _ => panic!("memory operand at {at:#x}: {ins}"),
            }
            explicit = Some((base, index, displ));
        }

        // Every memory access, explicit or not.
        for m in info.used_memory() {
            if matches!(
                ins.mnemonic(),
                Mnemonic::Push | Mnemonic::Pop | Mnemonic::Ret
            ) {
                assert_eq!(m.base(), Register::RSP, "{ins}");
            } else {
                assert_eq!(
                    Some((m.base(), m.index(), m.displacement())),
                    explicit,
                    "{ins} at {at:#x}"
                );
            }
        }

        // The stack.
        match ins.mnemonic() {
            Mnemonic::Push => {
                assert!(at < first_target, "push in a loop at {at:#x}");
                pushed.push(ins.op_register(0));
            }
            Mnemonic::Pop => {
                assert!(at > last_branch, "pop in a loop at {at:#x}");
                popped.push(ins.op_register(0));
            }
            // The final ret, checked above, pops the return address.
            Mnemonic::Ret => {}
            _ => assert!(!writes(info.used_registers(), Register::RSP), "{ins}"),
        }
        assert!(
            !writes(info.used_registers(), Register::RSI),
            "{ins} at {at:#x}"
        );

        // What RAX and RDI hold after this instruction.
        let is_and_imm = |reg, imm| {
            matches!(ins.code(), Code::And_EAX_imm32 | Code::And_rm32_imm32)
                && ins.op_register(0) == reg
                && ins.immediate(1) == imm
        };
        if writes(info.used_registers(), Register::RAX) {
            rax_masked = is_and_imm(Register::EAX, 0x3fff);
        }
        if writes(info.used_registers(), Register::RDI) {
            rdi = if is_and_imm(Register::EDI, 0x3fc0) {
                Rdi::SaveMasked
            } else if ins.code() == Code::Pop_r64 {
                Rdi::RegsPtr
            } else {
                Rdi::Other
            };
        }
    }
    // The epilogue pops the register file's address first.
    assert_eq!(popped.first(), Some(&Register::RDI));
    popped.reverse();
    assert_eq!(pushed, popped, "pushes and pops match");
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
    let fails = |code: &[u8]| std::panic::catch_unwind(|| verify_function(code)).is_err();
    assert!(!fails(&good));
    // Find the first `and eax, 0x3fff` and make it `and eax, 0x7fff`.
    let at = good
        .windows(5)
        .position(|w| w == [0x25, 0xff, 0x3f, 0, 0])
        .expect("a read mask");
    let mut bad = good.clone();
    bad[at + 2] = 0x7f;
    assert!(fails(&bad));
    // The first `and edi, 0x3fc0` loses a bit.
    let at = good
        .windows(6)
        .position(|w| w == [0x81, 0xe7, 0xc0, 0x3f, 0, 0])
        .expect("a save mask");
    let mut bad = good.clone();
    bad[at + 3] = 0x7f;
    assert!(fails(&bad));
    // A ret in the middle.
    let mut bad = good.clone();
    bad[at] = 0xc3;
    assert!(fails(&bad));
}

/// The prologue and epilogue take exactly their bound, and every program
/// of many seeds fits its bound. The bounds are proven by Kani; this
/// checks they are not loose by much.
#[test]
fn code_sizes_are_within_their_bounds() {
    let mut buf = vec![0u8; CODE_CAPACITY];
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
    assert!(write_max <= WRITE_PROGRAM_MAX && write_max + 8 >= WRITE_PROGRAM_MAX);
    assert!(read_max <= READ_PROGRAM_MAX && read_max + 12 >= READ_PROGRAM_MAX);
    assert!(total_max <= MAX_CODE_LEN, "{total_max}");
}

/// A program the compiler would get wrong is refused, not compiled.
#[test]
fn unsupported_programs_are_refused() {
    let programs = HashWx::new(&[5; 32]).programs().clone();
    let mut buf = vec![0u8; CODE_CAPACITY];
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
        p.ops[2].op = Op::OrMul;
        p.ops[2].k = 128;
    });
    for change in changes {
        let mut bad = programs.clone();
        change(&mut bad[7]);
        assert!(!supported(&bad[7]));
        assert_eq!(emit(&bad, &mut buf), None);
    }
}
