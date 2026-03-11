// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ARM64 (AArch64) syscall rewriting support.
//!
//! On ARM64, `SVC #0` is exactly 4 bytes, and `B imm26` (direct branch) is also
//! 4 bytes with ±128MB range. This allows a direct 1:1 replacement in the common
//! case — no instruction borrowing needed (unlike x86).

use crate::{Error, Result, TextSectionInfo};

/// ARM64 instruction: `SVC #0` (supervisor call)
const SVC_0: u32 = 0xD4000001;

/// NR_rt_sigreturn on aarch64 (used for sigreturn trampoline)
const NR_RT_SIGRETURN: u16 = 139;

/// ARM64 instruction mask for `MSR TPIDR_EL0, Xt`.
///
/// Encoding: `0xD51BD05t` where `t` is the source register (0-30 for X0-X30, 31 for XZR).
/// We match the top 27 bits and extract the bottom 5 as the register number.
const MSR_TPIDR_EL0_MASK: u32 = 0xFFFF_FFE0;
const MSR_TPIDR_EL0_BITS: u32 = 0xD51B_D040;

// ============================================================
// Shared trampoline layout constants
// ============================================================

/// Number of instructions in the shared SVC handler (18 insns, 72 bytes).
///
/// Uses linear scan to find TLS entry matching guest TPIDR.
/// On macOS, TPIDR_EL0 may be clobbered by the kernel on signal delivery,
/// causing the scan to hit the sentinel without finding a match. The fallback
/// path loads entry\[0\]'s host_tls and guest_tpidr as a best-effort recovery.
///
/// ```text
///  [0]  MRS  X18, TPIDR_EL0       ; get guest TPIDR (may be clobbered)
///  [1]  STR  X18, [SP, #24]       ; save guest TPIDR
///  [2]  LDR  X17, [PC, #off]      ; X17 = TLS table base
///  [3]  LDR  X16, [X17, #0]       ; .Lloop: X16 = entry.guest_tpidr
///  [4]  CMN  X16, #1              ; sentinel?
///  [5]  B.EQ .Lfallback           ; -> [12]
///  [6]  CMP  X16, X18             ; match guest TPIDR?
///  [7]  B.EQ .Lfound              ; -> [10]
///  [8]  ADD  X17, X17, #16        ; next entry
///  [9]  B    .Lloop               ; -> [3]
/// [10]  LDR  X18, [X17, #8]       ; .Lfound: X18 = host TLS
/// [11]  B    .Ldone               ; -> [16]
/// [12]  LDR  X17, [PC, #off]      ; .Lfallback: reload TLS table base
/// [13]  LDR  X16, [X17, #0]       ; X16 = entry[0].guest_tpidr
/// [14]  STR  X16, [SP, #24]       ; fix guest_tpidr on stack
/// [15]  LDR  X18, [X17, #8]       ; X18 = entry[0].host_tls (fallback)
/// [16]  LDR  X16, [PC, #off]      ; .Ldone: callback addr
/// [17]  BR   X16                  ; jump to callback
/// ```
const SHARED_SVC_HANDLER_INSN_COUNT: usize = 18;

/// Size in bytes of the shared SVC handler.
const SHARED_SVC_HANDLER_SIZE: usize = SHARED_SVC_HANDLER_INSN_COUNT * 4; // 72

/// Number of instructions in each per-site SVC gate (6 insns, 24 bytes).
///
/// ```text
/// [0] SUB  SP, SP, #32
/// [1] STP  X16, X17, [SP]        ; save X16, X17
/// [2] STR  X30, [SP, #16]        ; save guest LR
/// [3] ADRP X30, <return_page>    ; return addr = site.vaddr + 4 (high bits)
/// [4] ADD  X30, X30, #<pageoff>  ; return addr (low 12 bits)
/// [5] B    <shared_svc_handler>  ; branch to shared handler
/// ```
const SVC_GATE_INSN_COUNT: usize = 6;

/// Size in bytes of each per-site SVC gate.
const SVC_GATE_SIZE: usize = SVC_GATE_INSN_COUNT * 4; // 24

/// Number of instructions in the shared MSR handler (16 insns, 64 bytes).
///
/// Uses linear scan to find and update TLS entry for old guest TPIDR.
///
/// ```text
///  [0]  STR  X30, [SP, #32]       ; save BL return addr
///  [1]  MRS  X16, TPIDR_EL0       ; old guest TPIDR
///  [2]  LDR  X17, [PC, #off]      ; X17 = TLS table base
///  [3]  LDR  X30, [X17, #0]       ; .Lloop: X30 = entry.guest_tpidr (scratch)
///  [4]  CMN  X30, #1              ; sentinel?
///  [5]  B.EQ .Lsentinel           ; -> [12] (skip STR to avoid phantom entries)
///  [6]  CMP  X30, X16             ; match old TPIDR?
///  [7]  B.EQ .Lfound              ; -> [10]
///  [8]  ADD  X17, X17, #16        ; next entry
///  [9]  B    .Lloop               ; -> [3]
/// [10]  LDR  X16, [SP, #24]       ; .Lfound: X16 = new TPIDR
/// [11]  STR  X16, [X17, #0]       ; update entry.guest_tpidr (only from .Lfound)
/// [12]  LDR  X16, [SP, #24]       ; .Lsentinel: new TPIDR
/// [13]  MSR  TPIDR_EL0, X16       ; execute actual MSR
/// [14]  LDR  X30, [SP, #32]       ; restore BL return
/// [15]  RET
/// ```
const SHARED_MSR_HANDLER_INSN_COUNT: usize = 16;

/// Size in bytes of the shared MSR handler.
const SHARED_MSR_HANDLER_SIZE: usize = SHARED_MSR_HANDLER_INSN_COUNT * 4; // 64

/// Number of instructions in each per-site MSR gate (general case: 9 insns, 36 bytes).
///
/// ```text
/// [0] SUB  SP, SP, #48           ; 48-byte frame
/// [1] STP  X16, X17, [SP]        ; save X16, X17
/// [2] STR  X30, [SP, #16]        ; save guest LR
/// [3] STR  Xt,  [SP, #24]        ; store new TPIDR value (varies by Xt)
/// [4] BL   shared_msr_handler    ; call shared handler
/// [5] LDP  X16, X17, [SP]        ; restore X16, X17
/// [6] LDR  X30, [SP, #16]        ; restore guest LR
/// [7] ADD  SP, SP, #48           ; deallocate frame
/// [8] B    <return_addr>          ; branch back to site.vaddr + 4
/// ```
///
/// Special register cases (X16, X17, X30) use 10 instructions (40 bytes).
const MSR_GATE_INSN_COUNT: usize = 9;

/// Size in bytes of each per-site MSR gate (general case).
const MSR_GATE_SIZE: usize = MSR_GATE_INSN_COUNT * 4; // 36

/// Size in bytes of each per-site MSR gate for special registers (X16, X17, X30).
const MSR_GATE_SPECIAL_SIZE: usize = (MSR_GATE_INSN_COUNT + 1) * 4; // 40

/// ARM64 NOP instruction.
#[allow(dead_code)] // May be used for padding in future
const NOP: u32 = 0xD503201F;

/// Offset of the header region: callback address (8 bytes).
const HEADER_CALLBACK_OFFSET: usize = 0;

/// Offset of the TLS lookup table pointer (8 bytes, filled at load time).
const HEADER_TLS_TABLE_OFFSET: usize = 8;

/// Offset of the sigreturn preamble (8 bytes = 2 instructions: MOV X8, #139; B <sigreturn_snippet>).
#[allow(dead_code)] // Documenting the layout; used by tests
const HEADER_SIGRETURN_OFFSET: usize = 16;

/// Offset where the sigreturn SVC gate begins (24 bytes).
/// Called from the sigreturn preamble at offset 16 via `B .+8`.
const SIGRETURN_GATE_OFFSET: usize = 24;

/// Offset where the shared SVC handler begins.
const SHARED_SVC_HANDLER_OFFSET: usize = SIGRETURN_GATE_OFFSET + SVC_GATE_SIZE; // 48

/// Offset where the shared MSR handler begins.
const SHARED_MSR_HANDLER_OFFSET: usize = SHARED_SVC_HANDLER_OFFSET + SHARED_SVC_HANDLER_SIZE; // 120

/// Offset where per-site gates begin (after shared MSR handler).
const GATES_START_OFFSET: usize = SHARED_MSR_HANDLER_OFFSET + SHARED_MSR_HANDLER_SIZE; // 184

// ============================================================
// Instruction encoders
// ============================================================

/// Encode a `B` (unconditional branch) instruction to a PC-relative offset.
///
/// The offset must be a multiple of 4 and within ±128MB (signed 26-bit instruction count).
/// Encoding: `[31:26] = 0b000101`, `[25:0] = signed offset / 4`
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn encode_b(offset: i64) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm26 = offset >> 2;
    if !(-(1 << 25)..(1 << 25)).contains(&imm26) {
        return None;
    }
    Some(0x14000000 | ((imm26 as u32) & 0x03FF_FFFF))
}

/// Encode an `ADR Xd, #imm` instruction.
///
/// The immediate is a signed 21-bit byte offset (NOT instruction-aligned).
/// The encoding splits the immediate: `immlo` in bits [30:29], `immhi` in bits [23:5].
#[allow(dead_code)]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn encode_adr(rd: u8, offset: i64) -> Option<u32> {
    if !(-(1 << 20)..(1 << 20)).contains(&offset) {
        return None;
    }
    let imm = offset as u32;
    let immlo = (imm & 0x3) << 29;
    let immhi = ((imm >> 2) & 0x7_FFFF) << 5;
    Some(0x10000000 | immlo | immhi | u32::from(rd))
}

/// Encode an `ADRP Xd, #imm` instruction.
///
/// The immediate is a signed 21-bit page offset (each unit = 4KB page).
/// The PC is rounded down to a 4KB boundary, then the page offset is added.
/// Range: ±4GB.
/// The encoding splits the immediate: `immlo` in bits [30:29], `immhi` in bits [23:5].
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn encode_adrp(rd: u8, page_offset: i64) -> Option<u32> {
    if !(-(1 << 20)..(1 << 20)).contains(&page_offset) {
        return None;
    }
    let imm = page_offset as u32;
    let immlo = (imm & 0x3) << 29;
    let immhi = ((imm >> 2) & 0x7_FFFF) << 5;
    // ADRP: op=1 (bit 31), immlo, 10000 (bits 28:24), immhi, Rd
    Some(0x90000000 | immlo | immhi | u32::from(rd))
}

/// Encode `LDR Xt, <literal>` (PC-relative literal load, 64-bit).
///
/// Loads 8 bytes from a PC-relative address. The offset must be 4-byte aligned
/// and within ±1MB (signed 19-bit instruction count).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn encode_ldr_literal(rt: u8, offset: i64) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm19 = offset >> 2;
    if !(-(1 << 18)..(1 << 18)).contains(&imm19) {
        return None;
    }
    // opc=01 (64-bit), V=0, imm19, Rt
    Some(0x5800_0000 | (((imm19 as u32) & 0x7_FFFF) << 5) | u32::from(rt))
}

/// Encode `MOVZ Xd, #imm16` (move wide with zero, 64-bit).
fn encode_movz_x(rd: u8, imm16: u16) -> u32 {
    0xD280_0000 | (u32::from(imm16) << 5) | u32::from(rd)
}

/// Encode `BR Xn` (branch to register).
fn encode_br(rn: u8) -> u32 {
    0xD61F_0000 | (u32::from(rn) << 5)
}

/// Encode `SUB SP, SP, #imm12` (64-bit, immediate).
///
/// Subtracts an unsigned 12-bit immediate from SP and writes back to SP.
/// Encoding: sf=1, op=1 (SUB), S=0, shift=00, imm12, Rn=SP(31), Rd=SP(31)
fn encode_sub_sp_imm(imm12: u16) -> Option<u32> {
    if imm12 >= (1 << 12) {
        return None;
    }
    // 1_1_0_10001_00_imm12_Rn_Rd
    // sf=1, op=1, S=0 -> 110
    // 10001 (fixed)
    // sh=00 (no shift)
    // = 0xD1000000 | (imm12 << 10) | (Rn << 5) | Rd
    Some(0xD100_0000 | (u32::from(imm12) << 10) | (31 << 5) | 31)
}

/// Encode `STR Xt, [Xn, #imm]` (64-bit, unsigned offset).
///
/// Store a 64-bit register to memory at base + unsigned immediate offset.
/// The immediate must be a non-negative multiple of 8 and fit in 12 bits after
/// scaling (i.e., `imm_bytes` must be in `[0, 32760]` and divisible by 8).
///
/// Encoding: size=11, V=0, opc=00 (STR), imm12=imm_bytes/8, Rn, Rt
fn encode_str_imm_unsigned(rt: u8, rn: u8, imm_bytes: u16) -> Option<u32> {
    if !imm_bytes.is_multiple_of(8) {
        return None;
    }
    let imm12 = imm_bytes / 8;
    if imm12 >= (1 << 12) {
        return None;
    }
    // 11_111_0_01_00_imm12_Rn_Rt
    // = 0xF9000000 | (imm12 << 10) | (Rn << 5) | Rt
    Some(0xF900_0000 | (u32::from(imm12) << 10) | (u32::from(rn) << 5) | u32::from(rt))
}

/// Encode `LDR Xt, [Xn, #imm]` (64-bit, unsigned offset).
///
/// Load a 64-bit value from memory at base + unsigned immediate offset.
/// The immediate must be a non-negative multiple of 8 and fit in 12 bits after
/// scaling (i.e., `imm_bytes` must be in `[0, 32760]` and divisible by 8).
///
/// Encoding: size=11, V=0, opc=01 (LDR), imm12=imm_bytes/8, Rn, Rt
fn encode_ldr_imm_unsigned(rt: u8, rn: u8, imm_bytes: u16) -> Option<u32> {
    if !imm_bytes.is_multiple_of(8) {
        return None;
    }
    let imm12 = imm_bytes / 8;
    if imm12 >= (1 << 12) {
        return None;
    }
    // 11_111_0_01_01_imm12_Rn_Rt
    // = 0xF9400000 | (imm12 << 10) | (Rn << 5) | Rt
    Some(0xF940_0000 | (u32::from(imm12) << 10) | (u32::from(rn) << 5) | u32::from(rt))
}

/// Encode `ADD Xd, Xn, #imm12` (64-bit, immediate).
///
/// Adds an unsigned 12-bit immediate to a 64-bit source register.
/// Encoding: sf=1, op=0 (ADD), S=0, shift=00, imm12, Rn, Rd
fn encode_add_imm(rd: u8, rn: u8, imm12: u16) -> Option<u32> {
    if imm12 >= (1 << 12) {
        return None;
    }
    // 1_0_0_10001_00_imm12_Rn_Rd
    // = 0x91000000 | (imm12 << 10) | (Rn << 5) | Rd
    Some(0x9100_0000 | (u32::from(imm12) << 10) | (u32::from(rn) << 5) | u32::from(rd))
}

/// Encode `CMP Xn, Xm` (64-bit register compare).
///
/// This is an alias for `SUBS XZR, Xn, Xm` (shifted register, no shift).
/// Encoding: sf=1, op=1, S=1, shift=00, Rm, imm6=0, Rn, Rd=XZR(31)
fn encode_cmp_reg(rn: u8, rm: u8) -> u32 {
    // 1_1_1_01011_00_0_Rm_000000_Rn_11111
    // = 0xEB00001F | (Rm << 16) | (Rn << 5)
    0xEB00_001F | (u32::from(rm) << 16) | (u32::from(rn) << 5)
}

/// Encode `CMN Xn, #imm12` (64-bit immediate compare negative).
///
/// This is an alias for `ADDS XZR, Xn, #imm12`.
/// Encoding: sf=1, op=0, S=1, shift=00, imm12, Rn, Rd=XZR(31)
fn encode_cmn_imm(rn: u8, imm12: u16) -> Option<u32> {
    if imm12 >= (1 << 12) {
        return None;
    }
    // 1_0_1_10001_00_imm12_Rn_11111
    // = 0xB100001F | (imm12 << 10) | (Rn << 5)
    Some(0xB100_001F | (u32::from(imm12) << 10) | (u32::from(rn) << 5))
}

/// Encode `B.cond` (conditional branch, ±1MB range).
///
/// The offset must be a multiple of 4 and within ±1MB (signed 19-bit instruction count).
/// Condition codes: EQ=0x0, NE=0x1, etc.
///
/// Encoding: `[31:25]=0101010_0`, `[23:5]=imm19`, `[4]=0`, `[3:0]=cond`
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn encode_b_cond(cond: u8, offset: i64) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm19 = offset >> 2;
    if !(-(1 << 18)..(1 << 18)).contains(&imm19) {
        return None;
    }
    // 0101010_0_imm19_0_cond
    // = 0x54000000 | (imm19 << 5) | cond
    Some(0x5400_0000 | (((imm19 as u32) & 0x7_FFFF) << 5) | u32::from(cond))
}

/// Condition code for B.EQ (equal, Z==1).
const COND_EQ: u8 = 0x0;

/// Encode `MRS Xt, TPIDR_EL0` (read thread pointer register).
///
/// TPIDR_EL0 system register: op0=3, op1=3, CRn=13, CRm=0, op2=2
/// Encoding: `MRS Xt, <sysreg>` = `0xD53BD040 | Rt`
fn encode_mrs_tpidr_el0(rt: u8) -> u32 {
    // MRS: 1101_0101_0011_1_op0[1]_op1[2:0]_CRn[3:0]_CRm[3:0]_op2[2:0]_Rt[4:0]
    // TPIDR_EL0: op0=3(11), op1=3(011), CRn=13(1101), CRm=0(0000), op2=2(010)
    // = 0xD53BD040 | Rt
    0xD53B_D040 | u32::from(rt)
}

/// Encode `MSR TPIDR_EL0, Xt` (write thread pointer register).
///
/// Encoding: `0xD51BD040 | Rt`
fn encode_msr_tpidr_el0(rt: u8) -> u32 {
    0xD51B_D040 | u32::from(rt)
}

/// Encode `LSR Xd, Xn, #shift` (logical shift right, 64-bit, immediate).
///
/// This is an alias for `UBFM Xd, Xn, #shift, #63`.
/// Encoding: sf=1, opc=10, N=1, immr=shift, imms=63
#[allow(dead_code)] // Will be used for hash-based TLS lookup
fn encode_lsr_imm(rd: u8, rn: u8, shift: u8) -> Option<u32> {
    if shift >= 64 {
        return None;
    }
    // UBFM: 1_10_100110_1_immr_imms_Rn_Rd
    // For LSR: imms = 63 (0x3F)
    // = 0xD340FC00 | (shift << 16) | (Rn << 5) | Rd
    Some(0xD340_FC00 | (u32::from(shift) << 16) | (u32::from(rn) << 5) | u32::from(rd))
}

/// Encode `LSL Xd, Xn, #shift` (logical shift left, 64-bit, immediate).
///
/// This is an alias for `UBFM Xd, Xn, #(-shift MOD 64), #(63-shift)`.
/// Encoding: sf=1, opc=10, N=1, immr=(64-shift), imms=(63-shift)
#[allow(dead_code)] // Will be used for hash-based TLS lookup
fn encode_lsl_imm(rd: u8, rn: u8, shift: u8) -> Option<u32> {
    if shift == 0 || shift >= 64 {
        return None;
    }
    let rotation = (64 - shift) & 0x3F;
    let width = 63 - shift;
    // UBFM: 1_10_100110_1_immr_imms_Rn_Rd
    Some(
        0xD340_0000
            | (u32::from(rotation) << 16)
            | (u32::from(width) << 10)
            | (u32::from(rn) << 5)
            | u32::from(rd),
    )
}

/// Encode `AND Xd, Xn, #bitmask` (logical AND with bitmask immediate, 64-bit).
///
/// Only supports specific bitmask patterns that can be encoded as ARM64
/// bitmask immediates. This function supports common masks: 0xFF (8 bits)
/// and 0xFFF (12 bits).
///
/// Encoding: sf=1, opc=00, N=1, immr=0, imms=(width-1)
#[allow(dead_code)] // Will be used for hash-based TLS lookup
fn encode_and_bitmask(rd: u8, rn: u8, mask: u64) -> Option<u32> {
    // ARM64 bitmask immediate encoding for contiguous 1s starting at bit 0:
    // N=1 (64-bit), immr=0 (no rotation), imms=(number of 1s - 1)
    let imms: u32 = match mask {
        0xFF => 7,         // 8 ones
        0xFFF => 11,       // 12 ones
        0xFFFF => 15,      // 16 ones
        0xFFFF_FFFF => 31, // 32 ones
        _ => return None,  // Unsupported mask
    };
    // AND (immediate): 1_00_100100_N_immr_imms_Rn_Rd
    // For 64-bit: sf=1, opc=00, 100100, N=1, immr=0, imms, Rn, Rd
    // Encoding: 0x92400000 | (imms << 10) | (Rn << 5) | Rd
    Some(0x9240_0000 | (imms << 10) | (u32::from(rn) << 5) | u32::from(rd))
}

/// Encode `ADD Xd, Xn, Xm` (64-bit register add, no shift).
///
/// Encoding: sf=1, op=0, S=0, 01011, shift=00, Rm, imm6=0, Rn, Rd
#[allow(dead_code)] // Will be used for hash-based TLS lookup
fn encode_add_reg(rd: u8, rn: u8, rm: u8) -> u32 {
    // 1_0_0_01011_00_0_Rm_000000_Rn_Rd
    // = 0x8B000000 | (Rm << 16) | (Rn << 5) | Rd
    0x8B00_0000 | (u32::from(rm) << 16) | (u32::from(rn) << 5) | u32::from(rd)
}

/// Encode `ADD SP, SP, #imm12` (64-bit, immediate).
///
/// Adds an unsigned 12-bit immediate to SP and writes back to SP.
/// Encoding: sf=1, op=0 (ADD), S=0, shift=00, imm12, Rn=SP(31), Rd=SP(31)
fn encode_add_sp_imm(imm12: u16) -> Option<u32> {
    if imm12 >= (1 << 12) {
        return None;
    }
    // 1_0_0_10001_00_imm12_Rn_Rd with Rn=Rd=SP(31)
    // = 0x91000000 | (imm12 << 10) | (31 << 5) | 31
    Some(0x9100_0000 | (u32::from(imm12) << 10) | (31 << 5) | 31)
}

/// Encode `MOV Xd, Xm` (register move, 64-bit).
///
/// This is an alias for `ORR Xd, XZR, Xm`.
/// Encoding: sf=1, opc=01, N=0, Rm, imm6=0, Rn=XZR(31), Rd
#[allow(dead_code)] // General-purpose encoder, available for future use
fn encode_mov_reg(rd: u8, rm: u8) -> u32 {
    // 1_01_01010_00_0_Rm_000000_11111_Rd
    // = 0xAA0003E0 | (Rm << 16) | Rd
    0xAA00_03E0 | (u32::from(rm) << 16) | u32::from(rd)
}

/// Encode `STP Xt1, Xt2, [Xn, #imm]` (store pair, 64-bit, signed offset).
///
/// Stores two 64-bit registers to memory at base + signed immediate offset.
/// The offset must be a multiple of 8 and within [-512, 504].
///
/// Encoding: opc=10, V=0, L=0 (store), imm7=offset/8, Rt2, Rn, Rt
fn encode_stp_offset(rt: u8, rt2: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
    if imm_bytes % 8 != 0 {
        return None;
    }
    let imm7 = imm_bytes / 8;
    if !(-64..=63).contains(&imm7) {
        return None;
    }
    #[allow(clippy::cast_sign_loss)] // Masked to 7 bits; sign bit is intentionally truncated
    let imm7_u = (imm7 as u32) & 0x7F;
    // 10_101_0_010_0_imm7_Rt2_Rn_Rt
    // = 0xA9000000 | (imm7 << 15) | (Rt2 << 10) | (Rn << 5) | Rt
    Some(
        0xA900_0000
            | (imm7_u << 15)
            | (u32::from(rt2) << 10)
            | (u32::from(rn) << 5)
            | u32::from(rt),
    )
}

/// Encode `LDP Xt1, Xt2, [Xn, #imm]` (load pair, 64-bit, signed offset).
///
/// Loads two 64-bit values from memory at base + signed immediate offset.
/// The offset must be a multiple of 8 and within [-512, 504].
///
/// Encoding: opc=10, V=0, L=1 (load), imm7=offset/8, Rt2, Rn, Rt
fn encode_ldp_offset(rt: u8, rt2: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
    if imm_bytes % 8 != 0 {
        return None;
    }
    let imm7 = imm_bytes / 8;
    if !(-64..=63).contains(&imm7) {
        return None;
    }
    #[allow(clippy::cast_sign_loss)] // Masked to 7 bits; sign bit is intentionally truncated
    let imm7_u = (imm7 as u32) & 0x7F;
    // 10_101_0_010_1_imm7_Rt2_Rn_Rt
    // = 0xA9400000 | (imm7 << 15) | (Rt2 << 10) | (Rn << 5) | Rt
    Some(
        0xA940_0000
            | (imm7_u << 15)
            | (u32::from(rt2) << 10)
            | (u32::from(rn) << 5)
            | u32::from(rt),
    )
}

/// Encode `BL` (branch with link) instruction to a PC-relative offset.
///
/// The offset must be a multiple of 4 and within ±128MB (signed 26-bit instruction count).
/// Encoding: `[31:26] = 0b100101`, `[25:0] = signed offset / 4`
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn encode_bl(offset: i64) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm26 = offset >> 2;
    if !(-(1 << 25)..(1 << 25)).contains(&imm26) {
        return None;
    }
    Some(0x94000000 | ((imm26 as u32) & 0x03FF_FFFF))
}

/// Encode `RET {Xn}` (return from subroutine).
///
/// Branches to the address in the specified register (default X30).
/// Encoding: `0xD65F0000 | (Rn << 5)`
fn encode_ret(rn: u8) -> u32 {
    0xD65F_0000 | (u32::from(rn) << 5)
}

// ============================================================
// SVC site scanning
// ============================================================

/// Information about a found instruction to patch.
struct PatchSite {
    /// File offset of the instruction
    file_offset: usize,
    /// Virtual address of the instruction
    vaddr: u64,
    /// Kind of patch site
    kind: PatchKind,
}

/// The kind of instruction being patched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchKind {
    /// `SVC #0` — syscall instruction
    Svc,
    /// `MSR TPIDR_EL0, Xt` — thread pointer write.
    /// The `u8` is the source register number (0-30 for X0-X30, 31 for XZR).
    MsrTpidr(u8),
}

/// Scan executable sections for `SVC #0` and `MSR TPIDR_EL0, Xt` instructions.
///
/// ARM64 instructions are always 4-byte aligned, so we scan in 4-byte steps.
/// Returns patch sites sorted by file offset.
#[allow(clippy::cast_possible_truncation)]
fn find_patch_sites(sections: &[TextSectionInfo], buf: &[u8]) -> Result<Vec<PatchSite>> {
    let mut sites = Vec::new();

    for section in sections {
        let start = section.file_offset as usize;
        let end = start + section.size as usize;
        let section_data = buf
            .get(start..end)
            .ok_or_else(|| Error::ParseError("section extends beyond file".into()))?;

        for i in (0..section_data.len()).step_by(4) {
            if i + 4 > section_data.len() {
                break;
            }
            let insn = u32::from_le_bytes(section_data[i..i + 4].try_into().unwrap());
            if insn == SVC_0 {
                sites.push(PatchSite {
                    file_offset: start + i,
                    vaddr: section.vaddr + i as u64,
                    kind: PatchKind::Svc,
                });
            } else if (insn & MSR_TPIDR_EL0_MASK) == MSR_TPIDR_EL0_BITS {
                let rt = (insn & 0x1F) as u8;
                sites.push(PatchSite {
                    file_offset: start + i,
                    vaddr: section.vaddr + i as u64,
                    kind: PatchKind::MsrTpidr(rt),
                });
            }
        }
    }

    Ok(sites)
}

// ============================================================
// Main hooking function
// ============================================================

/// Hook all `SVC #0` instructions in an AArch64 ELF binary.
///
/// This function:
/// 1. Scans for SVC #0 and MSR TPIDR_EL0 instructions in executable sections
/// 2. Builds a shared trampoline with header, shared handlers, and per-site gates
/// 3. Patches each instruction with a `B` (branch) to its per-site gate
///
/// Returns `(trampoline_data, found_any_syscalls)`.
///
/// # Trampoline layout
///
/// ```text
/// Offset 0:     [8 bytes]   syscall_callback address
/// Offset 8:     [8 bytes]   TLS lookup table pointer
/// Offset 16:    [8 bytes]   Sigreturn preamble (MOV X8, #139 + B .+4)
/// Offset 24:    [24 bytes]  Sigreturn SVC gate
/// Offset 48:    [72 bytes]  Shared SVC handler (with sentinel fallback)
/// Offset 120:   [64 bytes]  Shared MSR handler
/// Offset 184:   Per-site SVC gates (24 bytes each)
///               Per-site MSR gates (36-40 bytes each)
/// ```
pub(crate) fn hook_syscalls_aarch64(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    trampoline: u64,
) -> Result<(Vec<u8>, bool)> {
    // Find all SVC #0 and MSR TPIDR_EL0 sites
    let sites = find_patch_sites(text_sections, buf)?;

    // Check if there are any SVC instructions to patch
    let has_svc = sites.iter().any(|s| s.kind == PatchKind::Svc);
    if !has_svc {
        // No SVC instructions found. Produce a minimal trampoline containing
        // the full shared layout (header + sigreturn gate + shared handlers).
        // This is needed for dynamically linked binaries where all syscalls are in
        // shared libraries — the rtld_audit library reads the callback address from
        // the main binary's trampoline region (via parse_object), so we must provide
        // a valid trampoline even when there are no instructions to patch.
        let mut trampoline_data: Vec<u8> = Vec::new();
        // Offset 0: syscall_callback address (8 bytes)
        trampoline_data.extend_from_slice(&trampoline.to_le_bytes());
        // Offset 8: TLS lookup table pointer (8 bytes, initially 0)
        trampoline_data.extend_from_slice(&0u64.to_le_bytes());
        // Offset 16: sigreturn preamble — MOV X8, #139; B .+4
        trampoline_data.extend_from_slice(&encode_movz_x(8, NR_RT_SIGRETURN).to_le_bytes());
        let b_to_gate = encode_b(4).expect("offset +4 always valid");
        trampoline_data.extend_from_slice(&b_to_gate.to_le_bytes());

        debug_assert_eq!(trampoline_data.len(), SIGRETURN_GATE_OFFSET);

        // Offset 24: sigreturn SVC gate (24 bytes)
        // rt_sigreturn never returns, so the return address doesn't matter —
        // we use the gate's own address as a dummy.
        let sigret_gate_vaddr = trampoline_base_addr + SIGRETURN_GATE_OFFSET as u64;
        let sigret_dummy_site = PatchSite {
            file_offset: 0,
            vaddr: sigret_gate_vaddr,
            kind: PatchKind::Svc,
        };
        emit_svc_gate(
            &mut trampoline_data,
            SIGRETURN_GATE_OFFSET,
            trampoline_base_addr,
            &sigret_dummy_site,
        )?;

        debug_assert_eq!(trampoline_data.len(), SHARED_SVC_HANDLER_OFFSET);

        // Offset 48: shared SVC handler (72 bytes)
        emit_shared_svc_handler(
            &mut trampoline_data,
            SHARED_SVC_HANDLER_OFFSET,
            trampoline_base_addr,
        )?;

        debug_assert_eq!(trampoline_data.len(), SHARED_MSR_HANDLER_OFFSET);

        // Offset 120: shared MSR handler (64 bytes)
        emit_shared_msr_handler(
            &mut trampoline_data,
            SHARED_MSR_HANDLER_OFFSET,
            trampoline_base_addr,
        )?;

        debug_assert_eq!(trampoline_data.len(), GATES_START_OFFSET);

        return Ok((trampoline_data, false));
    }

    // Build trampoline data
    let mut trampoline_data: Vec<u8> = Vec::new();

    // Offset 0: syscall_callback address (8 bytes)
    trampoline_data.extend_from_slice(&trampoline.to_le_bytes());

    // Offset 8: TLS lookup table pointer (8 bytes, initially 0)
    trampoline_data.extend_from_slice(&0u64.to_le_bytes());

    // Offset 16: sigreturn preamble
    // MOV X8, #NR_RT_SIGRETURN (= 139)
    trampoline_data.extend_from_slice(&encode_movz_x(8, NR_RT_SIGRETURN).to_le_bytes());
    // B .+4 — branch forward to the sigreturn SVC gate at offset 24
    let b_to_gate = encode_b(4).expect("offset +4 always valid");
    trampoline_data.extend_from_slice(&b_to_gate.to_le_bytes());

    debug_assert_eq!(trampoline_data.len(), SIGRETURN_GATE_OFFSET);

    // Offset 24: sigreturn SVC gate (24 bytes)
    let sigret_gate_vaddr = trampoline_base_addr + SIGRETURN_GATE_OFFSET as u64;
    let sigret_dummy_site = PatchSite {
        file_offset: 0,
        vaddr: sigret_gate_vaddr,
        kind: PatchKind::Svc,
    };
    emit_svc_gate(
        &mut trampoline_data,
        SIGRETURN_GATE_OFFSET,
        trampoline_base_addr,
        &sigret_dummy_site,
    )?;

    debug_assert_eq!(trampoline_data.len(), SHARED_SVC_HANDLER_OFFSET);

    // Offset 48: shared SVC handler (72 bytes)
    emit_shared_svc_handler(
        &mut trampoline_data,
        SHARED_SVC_HANDLER_OFFSET,
        trampoline_base_addr,
    )?;

    debug_assert_eq!(trampoline_data.len(), SHARED_MSR_HANDLER_OFFSET);

    // Offset 120: shared MSR handler (64 bytes)
    emit_shared_msr_handler(
        &mut trampoline_data,
        SHARED_MSR_HANDLER_OFFSET,
        trampoline_base_addr,
    )?;

    debug_assert_eq!(trampoline_data.len(), GATES_START_OFFSET);

    // Generate per-site gates and patch original code
    for site in &sites {
        let gate_offset = trampoline_data.len();
        let gate_vaddr = trampoline_base_addr + gate_offset as u64;

        match site.kind {
            PatchKind::Svc => {
                emit_svc_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                )?;
            }
            PatchKind::MsrTpidr(rt) => {
                emit_msr_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    rt,
                )?;
            }
        }

        // Patch original instruction with B <gate>
        let b_offset = gate_vaddr.cast_signed() - site.vaddr.cast_signed();
        let b_insn = encode_b(b_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "Branch offset {b_offset:#x} out of ±128MB range for site at {:#x}. \
                 Binary too large for direct branch patching.",
                site.vaddr
            ))
        })?;

        buf[site.file_offset..site.file_offset + 4].copy_from_slice(&b_insn.to_le_bytes());
    }

    Ok((trampoline_data, true))
}

/// Emit the shared SVC handler (20 instructions, 80 bytes).
///
/// This handler is shared by all SVC gates. It uses hash-based lookup to find
/// the host TLS from the TLS table, saves the guest TPIDR, and jumps to the
/// syscall callback.
///
/// Hash function: `(guest_tpidr >> 4) & 0xFF` gives initial probe index.
/// Linear probing with wrap-around (offset `& 0xFFF`) handles collisions.
///
/// At entry (from per-site SVC gate):
/// - SP decremented by 32, with `[0]=X16, [8]=X17, [16]=guest_LR` already saved
/// - X30 = guest return address (set by gate via ADRP+ADD)
/// - All other registers = live guest values
///
/// This handler fills `[SP, #24]` with guest TPIDR, loads host TLS into X18,
/// and branches to the callback via the address at trampoline offset 0.
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_svc_handler(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
) -> Result<()> {
    let handler_vaddr = trampoline_base_addr + handler_offset as u64;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { handler_vaddr + (idx as u64) * 4 };
    let tls_table_vaddr = trampoline_base_addr + HEADER_TLS_TABLE_OFFSET as u64;

    // [0] MRS X18, TPIDR_EL0
    trampoline_data.extend_from_slice(&encode_mrs_tpidr_el0(18).to_le_bytes());
    insn_idx += 1;

    // [1] STR X18, [SP, #24] — save guest TPIDR
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(18, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [2] LDR X17, [PC, #offset] — X17 = TLS table base
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let ldr_tls_offset = tls_table_vaddr.cast_signed() - ldr_tls_vaddr.cast_signed();
    let ldr_tls_insn = encode_ldr_literal(17, ldr_tls_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_tls_offset:#x} out of range for shared SVC handler TLS load"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_tls_insn.to_le_bytes());
    insn_idx += 1;

    // [3] .Lloop: LDR X16, [X17, #0] — X16 = entry.guest_tpidr
    let loop_idx = insn_idx;
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 17, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [4] CMN X16, #1 — sentinel?
    trampoline_data.extend_from_slice(&encode_cmn_imm(16, 1).expect("imm12=1 fits").to_le_bytes());
    insn_idx += 1;

    // [5] B.EQ .Lfallback -> [12]
    let fallback_idx = 12usize;
    let beq_fallback_offset = (fallback_idx as i64 - insn_idx as i64) * 4;
    let beq_fallback = encode_b_cond(COND_EQ, beq_fallback_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_fallback_offset:#x} out of range in shared SVC handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_fallback.to_le_bytes());
    insn_idx += 1;

    // [6] CMP X16, X18 — match guest TPIDR?
    trampoline_data.extend_from_slice(&encode_cmp_reg(16, 18).to_le_bytes());
    insn_idx += 1;

    // [7] B.EQ .Lfound -> [10]
    let found_idx = 10usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_found_offset:#x} out of range in shared SVC handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_found.to_le_bytes());
    insn_idx += 1;

    // [8] ADD X17, X17, #16 — next entry
    trampoline_data.extend_from_slice(
        &encode_add_imm(17, 17, 16)
            .expect("imm12=16 fits")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [9] B .Lloop -> [3]
    let b_loop_offset = (loop_idx as i64 - insn_idx as i64) * 4;
    let b_loop = encode_b(b_loop_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_loop_offset:#x} out of range in shared SVC handler loop"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [10] .Lfound: LDR X18, [X17, #8] — X18 = host TLS
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(18, 17, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [11] B .Ldone -> [16]
    let done_idx = 16usize;
    let b_done_offset = (done_idx as i64 - insn_idx as i64) * 4;
    let b_done = encode_b(b_done_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_done_offset:#x} out of range in shared SVC handler done"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_done.to_le_bytes());
    insn_idx += 1;

    // [12] .Lfallback: LDR X17, [PC, #offset] — reload TLS table base
    //
    // On macOS, TPIDR_EL0 is clobbered by every kernel transition (signal
    // delivery, sigreturn, etc.), so the MRS at [0] may return a stale pthread
    // value instead of the guest TPIDR. When no table entry matches, we fall
    // back to entry[0] — correct for single-thread, best-effort for multi.
    debug_assert_eq!(insn_idx, fallback_idx);
    let fallback_ldr_vaddr = insn_vaddr(insn_idx);
    let fallback_ldr_offset = tls_table_vaddr.cast_signed() - fallback_ldr_vaddr.cast_signed();
    let fallback_ldr_insn =
        encode_ldr_literal(17, fallback_ldr_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "LDR literal offset {fallback_ldr_offset:#x} out of range for SVC handler fallback TLS load"
            ))
        })?;
    trampoline_data.extend_from_slice(&fallback_ldr_insn.to_le_bytes());
    insn_idx += 1;

    // [13] LDR X16, [X17, #0] — X16 = entry[0].guest_tpidr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 17, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [14] STR X16, [SP, #24] — fix guest_tpidr on stack (replace clobbered value)
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [15] LDR X18, [X17, #8] — X18 = entry[0].host_tls (fallback)
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(18, 17, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [16] .Ldone: LDR X16, [PC, #offset_to_callback]
    debug_assert_eq!(insn_idx, done_idx);
    let ldr_cb_vaddr = insn_vaddr(insn_idx);
    let callback_vaddr = trampoline_base_addr + HEADER_CALLBACK_OFFSET as u64;
    let ldr_cb_offset = callback_vaddr.cast_signed() - ldr_cb_vaddr.cast_signed();
    let ldr_cb_insn = encode_ldr_literal(16, ldr_cb_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_cb_offset:#x} out of range for shared SVC handler callback"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_cb_insn.to_le_bytes());
    insn_idx += 1;

    // [17] BR X16
    trampoline_data.extend_from_slice(&encode_br(16).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, SHARED_SVC_HANDLER_INSN_COUNT);
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        SHARED_SVC_HANDLER_SIZE,
        "Shared SVC handler size mismatch"
    );

    Ok(())
}

/// Emit a per-site SVC gate (6 instructions, 24 bytes).
///
/// This gate saves registers, sets the return address, and branches to
/// the shared SVC handler.
#[allow(clippy::cast_possible_wrap)]
fn emit_svc_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
) -> Result<()> {
    let gate_vaddr = trampoline_base_addr + gate_offset as u64;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { gate_vaddr + (idx as u64) * 4 };

    // [0] SUB SP, SP, #32
    trampoline_data.extend_from_slice(&encode_sub_sp_imm(32).expect("imm12=32 fits").to_le_bytes());
    insn_idx += 1;

    // [1] STP X16, X17, [SP]
    trampoline_data.extend_from_slice(
        &encode_stp_offset(16, 17, 31, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [2] STR X30, [SP, #16]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 31, 16)
            .expect("offset 16 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [3] ADRP X30, <return_page>
    let return_addr = site.vaddr + 4;
    let adrp_vaddr = insn_vaddr(insn_idx);
    let adrp_base = adrp_vaddr & !0xFFF;
    let return_page = return_addr & !0xFFF;
    let page_offset = (return_page as i64 - adrp_base as i64) >> 12;
    let adrp_insn = encode_adrp(30, page_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "ADRP page offset {page_offset:#x} out of ±4GB range for SVC gate at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&adrp_insn.to_le_bytes());
    insn_idx += 1;

    // [4] ADD X30, X30, #<pageoff>
    let pageoff = (return_addr & 0xFFF) as u16;
    trampoline_data.extend_from_slice(
        &encode_add_imm(30, 30, pageoff)
            .expect("page offset fits in imm12")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [5] B <shared_svc_handler>
    let b_vaddr = insn_vaddr(insn_idx);
    let handler_vaddr = trampoline_base_addr + SHARED_SVC_HANDLER_OFFSET as u64;
    let b_offset = handler_vaddr.cast_signed() - b_vaddr.cast_signed();
    let b_insn = encode_b(b_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_offset:#x} out of range for SVC gate -> shared handler at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&b_insn.to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, SVC_GATE_INSN_COUNT);
    debug_assert_eq!(
        trampoline_data.len() - gate_offset,
        SVC_GATE_SIZE,
        "SVC gate size mismatch"
    );

    Ok(())
}

/// Emit the shared MSR handler (23 instructions, 92 bytes).
///
/// This handler is shared by all MSR gates. It uses linear scan to find
/// the old TLS entry and updates it with the new guest TPIDR value, then
/// executes the actual MSR instruction.
///
/// At entry (from per-site MSR gate via BL):
/// - SP decremented by 48, with frame:
///   `[0]=X16, [8]=X17, [16]=guest_LR, [24]=new_TPIDR`
/// - X30 = return-to-gate address (from BL)
/// - [SP, #32] available for saving BL return address
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_msr_handler(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
) -> Result<()> {
    let handler_vaddr = trampoline_base_addr + handler_offset as u64;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { handler_vaddr + (idx as u64) * 4 };
    let tls_table_vaddr = trampoline_base_addr + HEADER_TLS_TABLE_OFFSET as u64;

    // [0] STR X30, [SP, #32] — save BL return addr
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [1] MRS X16, TPIDR_EL0 — old guest TPIDR
    trampoline_data.extend_from_slice(&encode_mrs_tpidr_el0(16).to_le_bytes());
    insn_idx += 1;

    // [2] LDR X17, [PC, #offset] — X17 = TLS table base
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let ldr_tls_offset = tls_table_vaddr.cast_signed() - ldr_tls_vaddr.cast_signed();
    let ldr_tls_insn = encode_ldr_literal(17, ldr_tls_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_tls_offset:#x} out of range for shared MSR handler TLS load"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_tls_insn.to_le_bytes());
    insn_idx += 1;

    // [3] .Lloop: LDR X30, [X17, #0] — X30 = entry.guest_tpidr (scratch)
    let loop_idx = insn_idx;
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 17, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [4] CMN X30, #1 — sentinel?
    trampoline_data.extend_from_slice(&encode_cmn_imm(30, 1).expect("imm12=1 fits").to_le_bytes());
    insn_idx += 1;

    // [5] B.EQ .Lsentinel -> [12]
    //
    // On the sentinel path (no existing entry matches the old TPIDR), skip
    // the table update at [11]. This prevents writing a phantom entry with
    // host_tls=0 when TPIDR_EL0 has been clobbered (e.g., by macOS signal
    // delivery). The actual MSR TPIDR_EL0 at [13] still executes correctly
    // since it loads the new TPIDR from [SP, #24].
    let sentinel_idx = 12usize;
    let beq_sentinel_offset = (sentinel_idx as i64 - insn_idx as i64) * 4;
    let beq_sentinel = encode_b_cond(COND_EQ, beq_sentinel_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_sentinel_offset:#x} out of range in shared MSR handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_sentinel.to_le_bytes());
    insn_idx += 1;

    // [6] CMP X30, X16 — match old TPIDR?
    trampoline_data.extend_from_slice(&encode_cmp_reg(30, 16).to_le_bytes());
    insn_idx += 1;

    // [7] B.EQ .Lfound -> [10]
    let found_idx = 10usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_found_offset:#x} out of range in shared MSR handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_found.to_le_bytes());
    insn_idx += 1;

    // [8] ADD X17, X17, #16 — next entry
    trampoline_data.extend_from_slice(
        &encode_add_imm(17, 17, 16)
            .expect("imm12=16 fits")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [9] B .Lloop -> [3]
    let b_loop_offset = (loop_idx as i64 - insn_idx as i64) * 4;
    let b_loop = encode_b(b_loop_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_loop_offset:#x} out of range in shared MSR handler loop"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [10] .Lfound: LDR X16, [SP, #24] — X16 = new TPIDR
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [11] STR X16, [X17, #0] — update entry.guest_tpidr (only reached from .Lfound)
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 17, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [12] .Lsentinel: LDR X16, [SP, #24] — new TPIDR
    debug_assert_eq!(insn_idx, sentinel_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [13] MSR TPIDR_EL0, X16
    trampoline_data.extend_from_slice(&encode_msr_tpidr_el0(16).to_le_bytes());
    insn_idx += 1;

    // [14] LDR X30, [SP, #32] — restore BL return addr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [15] RET
    trampoline_data.extend_from_slice(&encode_ret(30).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, SHARED_MSR_HANDLER_INSN_COUNT);
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        SHARED_MSR_HANDLER_SIZE,
        "Shared MSR handler size mismatch"
    );

    Ok(())
}

/// Compute the size of a per-site MSR gate for the given source register.
///
/// Special registers (X16, X17, X30) need an extra instruction to reload
/// the saved value before storing to `[SP, #24]`, resulting in 40 bytes.
/// All other registers (including XZR) use 36 bytes.
fn msr_gate_size(rt: u8) -> usize {
    match rt {
        16 | 17 | 30 => MSR_GATE_SPECIAL_SIZE,
        _ => MSR_GATE_SIZE,
    }
}

/// Emit a per-site MSR gate (9-10 instructions, 36-40 bytes).
///
/// This gate saves registers, stores the new TPIDR value, calls the shared
/// MSR handler via BL, restores registers, and branches back to guest code.
#[allow(clippy::cast_possible_wrap)]
fn emit_msr_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rt: u8,
) -> Result<()> {
    let gate_vaddr = trampoline_base_addr + gate_offset as u64;
    let gate_size = msr_gate_size(rt);
    let gate_insn_count = gate_size / 4;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { gate_vaddr + (idx as u64) * 4 };

    // [0] SUB SP, SP, #48
    trampoline_data.extend_from_slice(&encode_sub_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
    insn_idx += 1;

    // [1] STP X16, X17, [SP]
    trampoline_data.extend_from_slice(
        &encode_stp_offset(16, 17, 31, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [2] STR X30, [SP, #16]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 31, 16)
            .expect("offset 16 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [3] (or [3]-[4] for special regs) Store the new TPIDR value to [SP, #24]
    match rt {
        16 => {
            // X16 already saved at [SP, #0]: reload into scratch, store to [SP, #24]
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(30, 31, 0)
                    .expect("valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            trampoline_data.extend_from_slice(
                &encode_str_imm_unsigned(30, 31, 24)
                    .expect("valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
        }
        17 => {
            // X17 already saved at [SP, #8]
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(30, 31, 8)
                    .expect("valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            trampoline_data.extend_from_slice(
                &encode_str_imm_unsigned(30, 31, 24)
                    .expect("valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
        }
        30 => {
            // X30 already saved at [SP, #16]: use X16 as scratch (already saved)
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(16, 31, 16)
                    .expect("valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            trampoline_data.extend_from_slice(
                &encode_str_imm_unsigned(16, 31, 24)
                    .expect("valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
        }
        _ => {
            // General case: STR Xt, [SP, #24] (reg 31 = XZR in STR context)
            trampoline_data.extend_from_slice(
                &encode_str_imm_unsigned(rt, 31, 24)
                    .expect("valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
        }
    }

    // [next] BL shared_msr_handler
    let bl_vaddr = insn_vaddr(insn_idx);
    let handler_vaddr = trampoline_base_addr + SHARED_MSR_HANDLER_OFFSET as u64;
    let bl_offset = handler_vaddr.cast_signed() - bl_vaddr.cast_signed();
    let bl_insn = encode_bl(bl_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "BL offset {bl_offset:#x} out of range for MSR gate -> shared handler at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&bl_insn.to_le_bytes());
    insn_idx += 1;

    // [next] LDP X16, X17, [SP]
    trampoline_data.extend_from_slice(
        &encode_ldp_offset(16, 17, 31, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [next] LDR X30, [SP, #16]
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 16)
            .expect("offset 16 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [next] ADD SP, SP, #48
    trampoline_data.extend_from_slice(&encode_add_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
    insn_idx += 1;

    // [next] B <return_addr>
    let ret_vaddr = insn_vaddr(insn_idx);
    let ret_offset = (site.vaddr + 4).cast_signed() - ret_vaddr.cast_signed();
    let ret_insn = encode_b(ret_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {ret_offset:#x} out of ±128MB range for return from MSR gate at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&ret_insn.to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, gate_insn_count);
    debug_assert_eq!(
        trampoline_data.len() - gate_offset,
        gate_size,
        "MSR gate size mismatch"
    );

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::manual_range_contains
)]
mod tests {
    use super::*;

    // ============================================================
    // Encoding unit tests — existing encoders
    // ============================================================

    #[test]
    fn test_encode_b_forward() {
        // B +8 (skip 2 instructions)
        let insn = encode_b(8).unwrap();
        assert_eq!(insn, 0x14000002); // imm26 = 8/4 = 2
    }

    #[test]
    fn test_encode_b_backward() {
        // B -4 (jump back 1 instruction)
        let insn = encode_b(-4).unwrap();
        // imm26 = -4/4 = -1 = 0x03FFFFFF in 26-bit unsigned
        assert_eq!(insn, 0x17FFFFFF);
    }

    #[test]
    fn test_encode_b_zero() {
        // B +0 (branch to self)
        let insn = encode_b(0).unwrap();
        assert_eq!(insn, 0x14000000);
    }

    #[test]
    fn test_encode_b_max_forward() {
        // Max forward: (2^25 - 1) * 4 = 128MB - 4
        let max_offset = ((1i64 << 25) - 1) * 4;
        let insn = encode_b(max_offset).unwrap();
        assert_eq!(insn & 0xFC000000, 0x14000000); // opcode bits
        assert_eq!(insn & 0x03FFFFFF, 0x01FFFFFF); // max positive imm26
    }

    #[test]
    fn test_encode_b_max_backward() {
        // Max backward: -(2^25) * 4 = -128MB
        let min_offset = -(1i64 << 25) * 4;
        let insn = encode_b(min_offset).unwrap();
        assert_eq!(insn & 0xFC000000, 0x14000000); // opcode bits
        assert_eq!(insn & 0x03FFFFFF, 0x02000000); // min negative imm26
    }

    #[test]
    fn test_encode_b_out_of_range() {
        // Just beyond max forward
        let too_far = (1i64 << 25) * 4;
        assert!(encode_b(too_far).is_none());

        // Just beyond max backward
        let too_far_back = (-(1i64 << 25) - 1) * 4;
        assert!(encode_b(too_far_back).is_none());
    }

    #[test]
    fn test_encode_b_unaligned() {
        assert!(encode_b(1).is_none());
        assert!(encode_b(3).is_none());
        assert!(encode_b(5).is_none());
    }

    #[test]
    fn test_encode_adr_zero() {
        // ADR x30, #0
        let insn = encode_adr(30, 0).unwrap();
        assert_eq!(insn, 0x1000001E); // base | rd=30
    }

    #[test]
    fn test_encode_adr_small_positive() {
        // ADR x0, #4
        // imm = 4, immlo = 4 & 3 = 0, immhi = (4 >> 2) & 0x7FFFF = 1
        let insn = encode_adr(0, 4).unwrap();
        let immlo = (insn >> 29) & 0x3;
        let immhi = (insn >> 5) & 0x7_FFFF;
        let decoded = ((immhi << 2) | immlo) as i64;
        assert_eq!(decoded, 4);
    }

    #[test]
    fn test_encode_adr_small_negative() {
        // ADR x30, #-4
        let insn = encode_adr(30, -4).unwrap();
        // Verify round-trip: extract immlo and immhi, reconstruct offset
        let immlo = (insn >> 29) & 0x3;
        let immhi = (insn >> 5) & 0x7_FFFF;
        let raw = (immhi << 2) | immlo;
        // Sign-extend from 21 bits
        let decoded = if raw & (1 << 20) != 0 {
            (raw | 0xFFE0_0000) as i32 as i64
        } else {
            raw as i64
        };
        assert_eq!(decoded, -4);
    }

    #[test]
    fn test_encode_adr_out_of_range() {
        assert!(encode_adr(0, 1 << 20).is_none());
        assert!(encode_adr(0, -(1 << 20) - 1).is_none());
    }

    #[test]
    fn test_encode_adr_various_offsets() {
        // Test several offsets to verify the split encoding
        for offset in [1i64, 2, 3, 7, 100, -1, -2, -3, -100, 0x7FFFF, -0x80000] {
            if offset < -(1 << 20) || offset >= (1 << 20) {
                assert!(encode_adr(0, offset).is_none());
                continue;
            }
            let insn = encode_adr(0, offset).unwrap();
            let immlo = (insn >> 29) & 0x3;
            let immhi = (insn >> 5) & 0x7_FFFF;
            let raw = (immhi << 2) | immlo;
            // Sign-extend from 21 bits
            let decoded = if raw & (1 << 20) != 0 {
                (raw | 0xFFE0_0000) as i32 as i64
            } else {
                raw as i64
            };
            assert_eq!(decoded, offset, "round-trip failed for offset {offset}");
        }
    }

    #[test]
    fn test_encode_ldr_literal_zero() {
        // LDR x16, [PC+0] — load from current PC
        let insn = encode_ldr_literal(16, 0).unwrap();
        assert_eq!(insn, 0x58000010); // base | rt=16
    }

    #[test]
    fn test_encode_ldr_literal_positive() {
        // LDR x16, [PC+8]
        let insn = encode_ldr_literal(16, 8).unwrap();
        let imm19 = (insn >> 5) & 0x7_FFFF;
        assert_eq!(imm19, 2); // 8/4 = 2
        assert_eq!(insn & 0x1F, 16); // Rt = x16
    }

    #[test]
    fn test_encode_ldr_literal_negative() {
        // LDR x16, [PC-4]
        let insn = encode_ldr_literal(16, -4).unwrap();
        let imm19 = (insn >> 5) & 0x7_FFFF;
        // -4/4 = -1, as 19-bit unsigned = 0x7FFFF
        assert_eq!(imm19, 0x7_FFFF);
    }

    #[test]
    fn test_encode_ldr_literal_out_of_range() {
        let too_far = (1i64 << 18) * 4;
        assert!(encode_ldr_literal(16, too_far).is_none());
    }

    #[test]
    fn test_encode_ldr_literal_unaligned() {
        assert!(encode_ldr_literal(16, 1).is_none());
        assert!(encode_ldr_literal(16, 2).is_none());
    }

    #[test]
    fn test_encode_movz_x() {
        // MOVZ X8, #139
        let insn = encode_movz_x(8, 139);
        assert_eq!(insn, 0xD2800000 | (139 << 5) | 8);
        // Verify register
        assert_eq!(insn & 0x1F, 8);
        // Verify immediate
        assert_eq!((insn >> 5) & 0xFFFF, 139);
    }

    #[test]
    fn test_encode_br() {
        // BR x16
        let insn = encode_br(16);
        assert_eq!(insn, 0xD61F0200);
        // BR x30
        let insn = encode_br(30);
        assert_eq!(insn, 0xD61F03C0);
    }

    // ============================================================
    // Encoding unit tests — new encoders
    // ============================================================

    #[test]
    fn test_encode_sub_sp_imm() {
        // SUB SP, SP, #32
        let insn = encode_sub_sp_imm(32).unwrap();
        // 0xD1000000 | (32 << 10) | (31 << 5) | 31
        let expected = 0xD100_0000 | (32u32 << 10) | (31u32 << 5) | 31u32;
        assert_eq!(insn, expected);
        // Verify Rd=SP and Rn=SP
        assert_eq!(insn & 0x1F, 31); // Rd
        assert_eq!((insn >> 5) & 0x1F, 31); // Rn
        // Verify imm12
        assert_eq!((insn >> 10) & 0xFFF, 32);
    }

    #[test]
    fn test_encode_sub_sp_imm_zero() {
        let insn = encode_sub_sp_imm(0).unwrap();
        assert_eq!((insn >> 10) & 0xFFF, 0);
    }

    #[test]
    fn test_encode_sub_sp_imm_max() {
        // Max valid: 4095
        let insn = encode_sub_sp_imm(4095).unwrap();
        assert_eq!((insn >> 10) & 0xFFF, 4095);
    }

    #[test]
    fn test_encode_sub_sp_imm_out_of_range() {
        assert!(encode_sub_sp_imm(4096).is_none());
    }

    #[test]
    fn test_encode_str_imm_unsigned() {
        // STR X16, [SP, #0]
        let insn = encode_str_imm_unsigned(16, 31, 0).unwrap();
        assert_eq!(insn & 0x1F, 16); // Rt
        assert_eq!((insn >> 5) & 0x1F, 31); // Rn = SP
        assert_eq!((insn >> 10) & 0xFFF, 0); // imm12 = 0/8 = 0
        assert_eq!(insn & 0xFFC0_0000, 0xF900_0000); // opcode

        // STR X17, [SP, #8]
        let insn = encode_str_imm_unsigned(17, 31, 8).unwrap();
        assert_eq!(insn & 0x1F, 17); // Rt
        assert_eq!((insn >> 10) & 0xFFF, 1); // imm12 = 8/8 = 1

        // STR X30, [SP, #16]
        let insn = encode_str_imm_unsigned(30, 31, 16).unwrap();
        assert_eq!(insn & 0x1F, 30);
        assert_eq!((insn >> 10) & 0xFFF, 2); // imm12 = 16/8 = 2
    }

    #[test]
    fn test_encode_str_imm_unsigned_unaligned() {
        assert!(encode_str_imm_unsigned(16, 31, 1).is_none());
        assert!(encode_str_imm_unsigned(16, 31, 4).is_none());
        assert!(encode_str_imm_unsigned(16, 31, 7).is_none());
    }

    #[test]
    fn test_encode_ldr_imm_unsigned() {
        // LDR X16, [X17, #0]
        let insn = encode_ldr_imm_unsigned(16, 17, 0).unwrap();
        assert_eq!(insn & 0x1F, 16); // Rt
        assert_eq!((insn >> 5) & 0x1F, 17); // Rn
        assert_eq!((insn >> 10) & 0xFFF, 0); // imm12 = 0
        assert_eq!(insn & 0xFFC0_0000, 0xF940_0000); // opcode

        // LDR X18, [X17, #8]
        let insn = encode_ldr_imm_unsigned(18, 17, 8).unwrap();
        assert_eq!(insn & 0x1F, 18);
        assert_eq!((insn >> 10) & 0xFFF, 1); // imm12 = 8/8 = 1
    }

    #[test]
    fn test_encode_ldr_imm_unsigned_unaligned() {
        assert!(encode_ldr_imm_unsigned(16, 17, 1).is_none());
        assert!(encode_ldr_imm_unsigned(16, 17, 4).is_none());
    }

    #[test]
    fn test_encode_add_imm() {
        // ADD X17, X17, #16
        let insn = encode_add_imm(17, 17, 16).unwrap();
        assert_eq!(insn & 0x1F, 17); // Rd
        assert_eq!((insn >> 5) & 0x1F, 17); // Rn
        assert_eq!((insn >> 10) & 0xFFF, 16); // imm12
        assert_eq!(insn & 0xFF00_0000, 0x9100_0000); // opcode bits
    }

    #[test]
    fn test_encode_add_imm_out_of_range() {
        assert!(encode_add_imm(0, 0, 4096).is_none());
    }

    #[test]
    fn test_encode_cmp_reg() {
        // CMP X16, X18 (= SUBS XZR, X16, X18)
        let insn = encode_cmp_reg(16, 18);
        assert_eq!(insn & 0x1F, 31); // Rd = XZR
        assert_eq!((insn >> 5) & 0x1F, 16); // Rn
        assert_eq!((insn >> 16) & 0x1F, 18); // Rm
        // Verify top bits: 111_01011_00_0
        assert_eq!(insn & 0xFFE0_FC00, 0xEB00_0000);
    }

    #[test]
    fn test_encode_cmn_imm() {
        // CMN X16, #1 (= ADDS XZR, X16, #1)
        let insn = encode_cmn_imm(16, 1).unwrap();
        assert_eq!(insn & 0x1F, 31); // Rd = XZR
        assert_eq!((insn >> 5) & 0x1F, 16); // Rn
        assert_eq!((insn >> 10) & 0xFFF, 1); // imm12
        // Verify opcode: 1_0_1_10001_00 = 0xB1000000
        assert_eq!(insn & 0xFF00_0000, 0xB100_0000);
    }

    #[test]
    fn test_encode_cmn_imm_out_of_range() {
        assert!(encode_cmn_imm(16, 4096).is_none());
    }

    #[test]
    fn test_encode_b_cond_eq_forward() {
        // B.EQ +24 (6 instructions forward)
        let insn = encode_b_cond(COND_EQ, 24).unwrap();
        let imm19 = (insn >> 5) & 0x7_FFFF;
        assert_eq!(imm19, 6); // 24/4 = 6
        assert_eq!(insn & 0xF, 0); // cond = EQ = 0
        assert_eq!(insn & 0xFF00_0010, 0x5400_0000); // opcode
    }

    #[test]
    fn test_encode_b_cond_eq_backward() {
        // B.EQ -8 (2 instructions backward)
        let insn = encode_b_cond(COND_EQ, -8).unwrap();
        let imm19 = (insn >> 5) & 0x7_FFFF;
        // -8/4 = -2, as 19-bit unsigned = 0x7FFFE
        assert_eq!(imm19, 0x7_FFFE);
    }

    #[test]
    fn test_encode_b_cond_unaligned() {
        assert!(encode_b_cond(COND_EQ, 1).is_none());
        assert!(encode_b_cond(COND_EQ, 2).is_none());
    }

    #[test]
    fn test_encode_b_cond_out_of_range() {
        let too_far = (1i64 << 18) * 4;
        assert!(encode_b_cond(COND_EQ, too_far).is_none());
    }

    #[test]
    fn test_encode_mrs_tpidr_el0() {
        // MRS X18, TPIDR_EL0
        let insn = encode_mrs_tpidr_el0(18);
        assert_eq!(insn, 0xD53BD052);
        // Verify register
        assert_eq!(insn & 0x1F, 18);
        // Verify sysreg bits
        assert_eq!(insn & 0xFFFF_FFE0, 0xD53BD040);
    }

    // ============================================================
    // SVC scanning tests (unchanged)
    // ============================================================

    #[test]
    fn test_find_patch_sites_single_svc() {
        // Build a minimal buffer with one SVC #0
        let mut buf = vec![0u8; 16];
        // Put SVC #0 at offset 4
        buf[4..8].copy_from_slice(&SVC_0.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        let sites = find_patch_sites(&sections, &buf).unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].file_offset, 4);
        assert_eq!(sites[0].vaddr, 0x1004);
        assert_eq!(sites[0].kind, PatchKind::Svc);
    }

    #[test]
    fn test_find_patch_sites_multiple_svc() {
        let mut buf = vec![0u8; 32];
        // SVC #0 at offsets 0, 12, 24
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes());
        buf[12..16].copy_from_slice(&SVC_0.to_le_bytes());
        buf[24..28].copy_from_slice(&SVC_0.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x2000,
            file_offset: 0,
            size: 32,
        }];

        let sites = find_patch_sites(&sections, &buf).unwrap();
        assert_eq!(sites.len(), 3);
        assert_eq!(sites[0].vaddr, 0x2000);
        assert_eq!(sites[1].vaddr, 0x200C);
        assert_eq!(sites[2].vaddr, 0x2018);
    }

    #[test]
    fn test_find_patch_sites_none() {
        let buf = vec![0u8; 16];
        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        let sites = find_patch_sites(&sections, &buf).unwrap();
        assert!(sites.is_empty());
    }

    #[test]
    fn test_find_patch_sites_not_svc0() {
        // SVC #1 (not SVC #0) should not be found
        let mut buf = vec![0u8; 16];
        let svc_1: u32 = 0xD4000021; // SVC #1
        buf[0..4].copy_from_slice(&svc_1.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        let sites = find_patch_sites(&sections, &buf).unwrap();
        assert!(sites.is_empty());
    }

    #[test]
    fn test_find_patch_sites_msr_tpidr() {
        // MSR TPIDR_EL0, X19 = 0xD51BD053
        let msr_x19: u32 = encode_msr_tpidr_el0(19);
        let mut buf = vec![0u8; 16];
        buf[4..8].copy_from_slice(&msr_x19.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        let sites = find_patch_sites(&sections, &buf).unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].file_offset, 4);
        assert_eq!(sites[0].vaddr, 0x1004);
        assert_eq!(sites[0].kind, PatchKind::MsrTpidr(19));
    }

    #[test]
    fn test_find_patch_sites_mixed_svc_and_msr() {
        let msr_x0: u32 = encode_msr_tpidr_el0(0);
        let msr_xzr: u32 = encode_msr_tpidr_el0(31);
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes()); // SVC at offset 0
        buf[8..12].copy_from_slice(&msr_x0.to_le_bytes()); // MSR at offset 8
        buf[16..20].copy_from_slice(&msr_xzr.to_le_bytes()); // MSR XZR at offset 16

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 24,
        }];

        let sites = find_patch_sites(&sections, &buf).unwrap();
        assert_eq!(sites.len(), 3);
        assert_eq!(sites[0].kind, PatchKind::Svc);
        assert_eq!(sites[1].kind, PatchKind::MsrTpidr(0));
        assert_eq!(sites[2].kind, PatchKind::MsrTpidr(31));
    }

    // ============================================================
    // Snippet layout tests
    // ============================================================

    #[test]
    fn test_snippet_size_constant() {
        // Shared SVC handler: 18 instructions, 72 bytes (linear scan + fallback)
        assert_eq!(SHARED_SVC_HANDLER_SIZE, 72);
        assert_eq!(SHARED_SVC_HANDLER_INSN_COUNT, 18);
        // Per-site SVC gate: 6 instructions, 24 bytes
        assert_eq!(SVC_GATE_SIZE, 24);
        assert_eq!(SVC_GATE_INSN_COUNT, 6);
        // Shared MSR handler: 16 instructions, 64 bytes (linear scan)
        assert_eq!(SHARED_MSR_HANDLER_SIZE, 64);
        assert_eq!(SHARED_MSR_HANDLER_INSN_COUNT, 16);
        // Per-site MSR gate: 9 instructions (general), 36 bytes
        assert_eq!(MSR_GATE_SIZE, 36);
        assert_eq!(MSR_GATE_INSN_COUNT, 9);
        // Per-site MSR gate (special regs): 10 instructions, 40 bytes
        assert_eq!(MSR_GATE_SPECIAL_SIZE, 40);
    }

    #[test]
    fn test_snippet_instruction_layout() {
        // Generate a trampoline with one SVC and verify every instruction
        // in the per-site SVC gate and shared SVC handler.
        let nop: u32 = 0xD503201F;
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&nop.to_le_bytes());
        buf[4..8].copy_from_slice(&SVC_0.to_le_bytes()); // SVC at vaddr 0x1004
        buf[8..12].copy_from_slice(&nop.to_le_bytes());
        buf[12..16].copy_from_slice(&nop.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        let trampoline_base = 0x2000u64;
        let callback_addr = 0xDEAD_BEEF_CAFE_BABEu64;

        let (td, _) =
            hook_syscalls_aarch64(&mut buf, &sections, trampoline_base, callback_addr).unwrap();

        // === Per-site SVC gate at GATES_START_OFFSET (6 instructions) ===
        let gate_start = GATES_START_OFFSET;
        let gate_vaddr = trampoline_base + gate_start as u64;

        let gate_insn_at = |idx: usize| -> u32 {
            let off = gate_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [0] SUB SP, SP, #32
        assert_eq!(gate_insn_at(0), encode_sub_sp_imm(32).unwrap());

        // [1] STP X16, X17, [SP]
        assert_eq!(gate_insn_at(1), encode_stp_offset(16, 17, 31, 0).unwrap());

        // [2] STR X30, [SP, #16]
        assert_eq!(
            gate_insn_at(2),
            encode_str_imm_unsigned(30, 31, 16).unwrap()
        );

        // [3] ADRP X30, <return_page>
        // return_addr = 0x1004 + 4 = 0x1008
        let adrp_vaddr = gate_vaddr + 3 * 4;
        let adrp_base = adrp_vaddr & !0xFFF;
        let return_addr = 0x1008u64;
        let return_page = return_addr & !0xFFF;
        let page_offset = (return_page.cast_signed() - adrp_base.cast_signed()) >> 12;
        assert_eq!(gate_insn_at(3), encode_adrp(30, page_offset).unwrap());

        // [4] ADD X30, X30, #<pageoff>
        let pageoff = (return_addr & 0xFFF) as u16;
        assert_eq!(gate_insn_at(4), encode_add_imm(30, 30, pageoff).unwrap());

        // [5] B <shared_svc_handler>
        let b_vaddr = gate_vaddr + 5 * 4;
        let handler_vaddr = trampoline_base + SHARED_SVC_HANDLER_OFFSET as u64;
        let b_offset = handler_vaddr as i64 - b_vaddr as i64;
        assert_eq!(gate_insn_at(5), encode_b(b_offset).unwrap());

        // === Shared SVC handler at SHARED_SVC_HANDLER_OFFSET (18 instructions) ===
        // Linear scan TLS lookup with sentinel fallback
        let handler_start = SHARED_SVC_HANDLER_OFFSET;
        let handler_vaddr = trampoline_base + handler_start as u64;

        let handler_insn_at = |idx: usize| -> u32 {
            let off = handler_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [0] MRS X18, TPIDR_EL0
        assert_eq!(handler_insn_at(0), encode_mrs_tpidr_el0(18));

        // [1] STR X18, [SP, #24]
        assert_eq!(
            handler_insn_at(1),
            encode_str_imm_unsigned(18, 31, 24).unwrap()
        );

        // [2] LDR X17, [PC, #offset] -- X17 = TLS table base
        let ldr_tls_vaddr = handler_vaddr + 2 * 4;
        let tls_offset = (trampoline_base + 8) as i64 - ldr_tls_vaddr as i64;
        assert_eq!(
            handler_insn_at(2),
            encode_ldr_literal(17, tls_offset).unwrap()
        );

        // [3] .Lloop: LDR X16, [X17, #0] -- X16 = entry.guest_tpidr
        assert_eq!(
            handler_insn_at(3),
            encode_ldr_imm_unsigned(16, 17, 0).unwrap()
        );

        // [4] CMN X16, #1 -- sentinel?
        assert_eq!(handler_insn_at(4), encode_cmn_imm(16, 1).unwrap());

        // [5] B.EQ .Lfallback -> [12]: offset = (12-5)*4 = 28
        assert_eq!(handler_insn_at(5), encode_b_cond(COND_EQ, 28).unwrap());

        // [6] CMP X16, X18 -- match?
        assert_eq!(handler_insn_at(6), encode_cmp_reg(16, 18));

        // [7] B.EQ .Lfound -> [10]: offset = (10-7)*4 = 12
        assert_eq!(handler_insn_at(7), encode_b_cond(COND_EQ, 12).unwrap());

        // [8] ADD X17, X17, #16 -- next entry
        assert_eq!(handler_insn_at(8), encode_add_imm(17, 17, 16).unwrap());

        // [9] B .Lloop -> [3]: offset = (3-9)*4 = -24
        assert_eq!(handler_insn_at(9), encode_b(-24).unwrap());

        // [10] .Lfound: LDR X18, [X17, #8] -- X18 = host TLS
        assert_eq!(
            handler_insn_at(10),
            encode_ldr_imm_unsigned(18, 17, 8).unwrap()
        );

        // [11] B .Ldone -> [16]: offset = (16-11)*4 = 20
        assert_eq!(handler_insn_at(11), encode_b(20).unwrap());

        // [12] .Lfallback: LDR X17, [PC, #offset] -- reload TLS table base
        let fallback_ldr_vaddr = handler_vaddr + 12 * 4;
        let fallback_offset = (trampoline_base + 8) as i64 - fallback_ldr_vaddr as i64;
        assert_eq!(
            handler_insn_at(12),
            encode_ldr_literal(17, fallback_offset).unwrap()
        );

        // [13] LDR X16, [X17, #0] -- entry[0].guest_tpidr
        assert_eq!(
            handler_insn_at(13),
            encode_ldr_imm_unsigned(16, 17, 0).unwrap()
        );

        // [14] STR X16, [SP, #24] -- fix guest_tpidr on stack
        assert_eq!(
            handler_insn_at(14),
            encode_str_imm_unsigned(16, 31, 24).unwrap()
        );

        // [15] LDR X18, [X17, #8] -- entry[0].host_tls (fallback)
        assert_eq!(
            handler_insn_at(15),
            encode_ldr_imm_unsigned(18, 17, 8).unwrap()
        );

        // [16] .Ldone: LDR X16, [PC, #offset_to_callback]
        let ldr_cb_vaddr = handler_vaddr + 16 * 4;
        let cb_offset = trampoline_base as i64 - ldr_cb_vaddr as i64;
        assert_eq!(
            handler_insn_at(16),
            encode_ldr_literal(16, cb_offset).unwrap()
        );

        // [17] BR X16
        assert_eq!(handler_insn_at(17), encode_br(16));
    }

    // ============================================================
    // Integration / hooking tests
    // ============================================================

    #[test]
    fn test_hook_single_svc() {
        let nop: u32 = 0xD503201F;
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&nop.to_le_bytes());
        buf[4..8].copy_from_slice(&SVC_0.to_le_bytes());
        buf[8..12].copy_from_slice(&nop.to_le_bytes());
        buf[12..16].copy_from_slice(&nop.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        let trampoline_base = 0x2000u64;
        let callback_addr = 0xDEAD_BEEF_CAFE_BABEu64;

        let (trampoline_data, found) =
            hook_syscalls_aarch64(&mut buf, &sections, trampoline_base, callback_addr).unwrap();

        assert!(found);

        // Verify callback address at offset 0
        assert_eq!(
            u64::from_le_bytes(trampoline_data[0..8].try_into().unwrap()),
            callback_addr
        );

        // Verify TLS table pointer at offset 8 (initially 0)
        assert_eq!(
            u64::from_le_bytes(trampoline_data[8..16].try_into().unwrap()),
            0
        );

        // Verify sigreturn preamble at offset 16
        let sigreturn_mov = u32::from_le_bytes(trampoline_data[16..20].try_into().unwrap());
        assert_eq!(sigreturn_mov, encode_movz_x(8, NR_RT_SIGRETURN));
        // Offset 20: B .+4 (branch forward to sigreturn SVC gate at offset 24)
        let sigreturn_b = u32::from_le_bytes(trampoline_data[20..24].try_into().unwrap());
        assert_eq!(sigreturn_b, encode_b(4).unwrap());

        // Total: GATES_START_OFFSET (184) + 1 SVC gate (24) = 208
        assert_eq!(trampoline_data.len(), GATES_START_OFFSET + SVC_GATE_SIZE);

        // Verify the original SVC was patched with a B instruction
        let patched = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        // B to per-site gate at 0x2000 + GATES_START_OFFSET
        let gate_vaddr = trampoline_base + GATES_START_OFFSET as u64;
        let expected_b = encode_b(gate_vaddr as i64 - 0x1004i64).unwrap();
        assert_eq!(patched, expected_b);

        // Verify surrounding instructions are untouched
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), nop);
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), nop);
    }

    #[test]
    fn test_hook_no_svc_returns_minimal_trampoline() {
        let nop: u32 = 0xD503201F;
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&nop.to_le_bytes());
        buf[4..8].copy_from_slice(&nop.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let result = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0);
        let (trampoline_data, has_svc) = result.expect("should succeed with minimal trampoline");
        assert!(!has_svc, "should report no SVC found");
        // Minimal trampoline: header(16) + sigret preamble(8) + sigret gate(24) + shared SVC(72) + shared MSR(64) = 184
        assert_eq!(
            trampoline_data.len(),
            GATES_START_OFFSET,
            "minimal trampoline should be exactly GATES_START_OFFSET bytes"
        );
    }

    #[test]
    fn test_hook_multiple_svcs() {
        let nop: u32 = 0xD503201F;
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&nop.to_le_bytes());
        buf[4..8].copy_from_slice(&SVC_0.to_le_bytes()); // SVC #0 at offset 4
        buf[8..12].copy_from_slice(&nop.to_le_bytes());
        buf[12..16].copy_from_slice(&nop.to_le_bytes());
        buf[16..20].copy_from_slice(&SVC_0.to_le_bytes()); // SVC #0 at offset 16
        buf[20..24].copy_from_slice(&nop.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 24,
        }];

        let trampoline_base = 0x2000u64;
        let (trampoline_data, found) =
            hook_syscalls_aarch64(&mut buf, &sections, trampoline_base, 0).unwrap();

        assert!(found);

        // GATES_START_OFFSET (184) + 2 * SVC_GATE_SIZE (24) = 232
        assert_eq!(
            trampoline_data.len(),
            GATES_START_OFFSET + 2 * SVC_GATE_SIZE
        );

        // Both SVCs should be patched
        let patched1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let patched2 = u32::from_le_bytes(buf[16..20].try_into().unwrap());

        // Verify both are B instructions (opcode in bits [31:26])
        assert_eq!(patched1 & 0xFC00_0000, 0x1400_0000);
        assert_eq!(patched2 & 0xFC00_0000, 0x1400_0000);

        // Verify they branch to different targets (different gates)
        assert_ne!(patched1, patched2);

        // Verify gate 1 at GATES_START_OFFSET and gate 2 at GATES_START_OFFSET + SVC_GATE_SIZE
        let gate1_vaddr = trampoline_base + GATES_START_OFFSET as u64;
        let gate2_vaddr = trampoline_base + GATES_START_OFFSET as u64 + SVC_GATE_SIZE as u64;

        let expected_b1 = encode_b(gate1_vaddr as i64 - 0x1004i64).unwrap();
        let expected_b2 = encode_b(gate2_vaddr as i64 - 0x1010i64).unwrap();
        assert_eq!(patched1, expected_b1);
        assert_eq!(patched2, expected_b2);
    }

    #[test]
    fn test_sigreturn_preamble_branches_to_gate() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let (trampoline_data, _) = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0).unwrap();

        // Offset 16: MOV X8, #139
        let sigreturn_mov = u32::from_le_bytes(trampoline_data[16..20].try_into().unwrap());
        assert_eq!(
            sigreturn_mov,
            encode_movz_x(8, NR_RT_SIGRETURN),
            "sigreturn preamble should set X8 = 139"
        );

        // Offset 20: B .+4 (branch to sigreturn SVC gate at offset 24)
        let sigreturn_b = u32::from_le_bytes(trampoline_data[20..24].try_into().unwrap());
        assert_eq!(
            sigreturn_b,
            encode_b(4).unwrap(),
            "sigreturn preamble should branch forward to SVC gate"
        );

        // Verify the sigreturn SVC gate starts at offset 24 (SIGRETURN_GATE_OFFSET)
        // It should begin with SUB SP, SP, #32 (the standard SVC gate prologue)
        let sigret_prologue = u32::from_le_bytes(trampoline_data[24..28].try_into().unwrap());
        assert_eq!(
            sigret_prologue,
            encode_sub_sp_imm(32).unwrap(),
            "sigreturn SVC gate should start with SUB SP, SP, #32"
        );
    }

    #[test]
    fn test_trampoline_callback_zero_when_not_specified() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let (trampoline_data, _) = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0).unwrap();

        let callback = u64::from_le_bytes(trampoline_data[0..8].try_into().unwrap());
        assert_eq!(callback, 0);
    }

    #[test]
    fn test_tls_table_ptr_initially_zero() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let (trampoline_data, _) = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0).unwrap();

        let tls_ptr = u64::from_le_bytes(trampoline_data[8..16].try_into().unwrap());
        assert_eq!(tls_ptr, 0, "TLS table pointer should be 0 initially");
    }

    #[test]
    fn test_trampoline_header_layout() {
        // Verify the exact offsets of the header fields
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let callback_addr = 0x1234_5678_9ABC_DEF0u64;
        let (td, _) = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, callback_addr).unwrap();

        // Offset 0-7: callback address
        assert_eq!(
            u64::from_le_bytes(
                td[HEADER_CALLBACK_OFFSET..HEADER_CALLBACK_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            callback_addr
        );

        // Offset 8-15: TLS table pointer (0)
        assert_eq!(
            u64::from_le_bytes(
                td[HEADER_TLS_TABLE_OFFSET..HEADER_TLS_TABLE_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            0
        );

        // Offset 16-19: MOV X8, #139
        assert_eq!(
            u32::from_le_bytes(
                td[HEADER_SIGRETURN_OFFSET..HEADER_SIGRETURN_OFFSET + 4]
                    .try_into()
                    .unwrap()
            ),
            encode_movz_x(8, NR_RT_SIGRETURN)
        );

        // Offset 20-23: B .+4 (branch to sigreturn SVC gate)
        assert_eq!(
            u32::from_le_bytes(
                td[HEADER_SIGRETURN_OFFSET + 4..HEADER_SIGRETURN_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            encode_b(4).unwrap()
        );

        // Offset 24: sigreturn SVC gate (24 bytes)
        // Offset 48: shared SVC handler (72 bytes)
        // Offset 120: shared MSR handler (64 bytes)
        // Offset 184: per-site gates start
        // Total: GATES_START_OFFSET + SVC_GATE_SIZE = 208
        assert_eq!(td.len(), GATES_START_OFFSET + SVC_GATE_SIZE);
    }

    #[test]
    fn test_tls_loop_branch_offsets() {
        // Verify that the TLS lookup loop branches have correct offsets
        // in the shared SVC handler.
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let (td, _) = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0).unwrap();

        // Read instructions from the shared SVC handler at SHARED_SVC_HANDLER_OFFSET
        // Linear scan: loop at [3], found at [10], fallback at [12], done at [16]
        let insn_at = |idx: usize| -> u32 {
            let off = SHARED_SVC_HANDLER_OFFSET + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [5] B.EQ .Lfallback -> [12]: offset = (12-5)*4 = 28
        let beq_fallback = insn_at(5);
        let imm19 = (beq_fallback >> 5) & 0x7_FFFF;
        assert_eq!(imm19, 7); // 28/4 = 7
        assert_eq!(beq_fallback & 0xF, 0); // cond = EQ

        // [7] B.EQ .Lfound -> [10]: offset = (10-7)*4 = 12
        let beq_found = insn_at(7);
        let imm19 = (beq_found >> 5) & 0x7_FFFF;
        assert_eq!(imm19, 3); // 12/4 = 3

        // [9] B .Lloop -> [3]: offset = (3-9)*4 = -24
        let b_loop = insn_at(9);
        let imm26 = b_loop & 0x03FF_FFFF;
        // -24/4 = -6, as 26-bit unsigned: 0x03FFFFFA
        assert_eq!(imm26, 0x03FF_FFFA);
    }

    // ============================================================
    // MSR TPIDR_EL0 snippet tests
    // ============================================================

    /// Helper to build a buffer with one SVC and one MSR TPIDR_EL0 instruction,
    /// then hook it and return the trampoline data.
    fn hook_with_svc_and_msr(msr_rt: u8) -> (Vec<u8>, Vec<u8>, u64) {
        let nop: u32 = 0xD503201F;
        let msr_insn = encode_msr_tpidr_el0(msr_rt);
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes()); // SVC at offset 0
        buf[4..8].copy_from_slice(&nop.to_le_bytes());
        buf[8..12].copy_from_slice(&msr_insn.to_le_bytes()); // MSR at offset 8
        buf[12..16].copy_from_slice(&nop.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        let trampoline_base = 0x2000u64;
        let (td, found) =
            hook_syscalls_aarch64(&mut buf, &sections, trampoline_base, 0xCAFE).unwrap();
        assert!(found);
        (td, buf, trampoline_base)
    }

    #[test]
    fn test_hook_svc_and_msr_trampoline_sizes() {
        let (td, _, _) = hook_with_svc_and_msr(19);
        // GATES_START_OFFSET (184) + SVC gate (24) + MSR gate for X19 (36) = 244
        assert_eq!(td.len(), GATES_START_OFFSET + SVC_GATE_SIZE + MSR_GATE_SIZE);
    }

    #[test]
    fn test_hook_msr_patches_original_instruction() {
        let (_, buf, _) = hook_with_svc_and_msr(19);
        // The MSR at offset 8 should be patched to a B instruction
        let patched = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        assert_eq!(
            patched & 0xFC00_0000,
            0x1400_0000,
            "MSR should be patched to B"
        );
    }

    #[test]
    fn test_msr_gate_prologue() {
        let (td, _, _) = hook_with_svc_and_msr(19);
        // MSR gate starts after the SVC gate
        let msr_start = GATES_START_OFFSET + SVC_GATE_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [0] SUB SP, SP, #48
        assert_eq!(insn_at(0), encode_sub_sp_imm(48).unwrap());
        // [1] STP X16, X17, [SP]
        assert_eq!(insn_at(1), encode_stp_offset(16, 17, 31, 0).unwrap());
        // [2] STR X30, [SP, #16]
        assert_eq!(insn_at(2), encode_str_imm_unsigned(30, 31, 16).unwrap());
    }

    #[test]
    fn test_msr_gate_store_new_tpidr_generic_reg() {
        // MSR TPIDR_EL0, X19 — generic register, should be STR X19, [SP, #24]
        let (td, _, _) = hook_with_svc_and_msr(19);
        let msr_start = GATES_START_OFFSET + SVC_GATE_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [3] STR X19, [SP, #24]
        assert_eq!(insn_at(3), encode_str_imm_unsigned(19, 31, 24).unwrap());
    }

    #[test]
    fn test_msr_gate_store_new_tpidr_x16() {
        // MSR TPIDR_EL0, X16 — saved reg, must reload from [SP, #0]
        let (td, _, _) = hook_with_svc_and_msr(16);
        // X16 is a special register, so MSR gate is 40 bytes
        let msr_start = GATES_START_OFFSET + SVC_GATE_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [3] LDR X30, [SP, #0] (reload X16's original value into X30)
        assert_eq!(insn_at(3), encode_ldr_imm_unsigned(30, 31, 0).unwrap());
        // [4] STR X30, [SP, #24]
        assert_eq!(insn_at(4), encode_str_imm_unsigned(30, 31, 24).unwrap());
    }

    #[test]
    fn test_msr_gate_store_new_tpidr_x17() {
        // MSR TPIDR_EL0, X17 — saved reg, must reload from [SP, #8]
        let (td, _, _) = hook_with_svc_and_msr(17);
        // X17 is a special register, so MSR gate is 40 bytes
        let msr_start = GATES_START_OFFSET + SVC_GATE_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [3] LDR X30, [SP, #8] (reload X17's original value into X30)
        assert_eq!(insn_at(3), encode_ldr_imm_unsigned(30, 31, 8).unwrap());
        // [4] STR X30, [SP, #24]
        assert_eq!(insn_at(4), encode_str_imm_unsigned(30, 31, 24).unwrap());
    }

    #[test]
    fn test_msr_gate_store_new_tpidr_x30() {
        // MSR TPIDR_EL0, X30 — saved reg, must reload from [SP, #16]
        let (td, _, _) = hook_with_svc_and_msr(30);
        // X30 is a special register, so MSR gate is 40 bytes
        let msr_start = GATES_START_OFFSET + SVC_GATE_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [3] LDR X16, [SP, #16] (reload X30's original value into X16)
        assert_eq!(insn_at(3), encode_ldr_imm_unsigned(16, 31, 16).unwrap());
        // [4] STR X16, [SP, #24]
        assert_eq!(insn_at(4), encode_str_imm_unsigned(16, 31, 24).unwrap());
    }

    #[test]
    fn test_msr_gate_store_new_tpidr_xzr() {
        // MSR TPIDR_EL0, XZR (reg 31) — store zero
        let (td, _, _) = hook_with_svc_and_msr(31);
        let msr_start = GATES_START_OFFSET + SVC_GATE_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [3] STR XZR, [SP, #24] (reg 31 = XZR in STR context)
        assert_eq!(insn_at(3), encode_str_imm_unsigned(31, 31, 24).unwrap());
    }

    #[test]
    fn test_msr_gate_bl_and_epilogue() {
        // Verify the full MSR gate instruction layout: BL to shared handler + epilogue
        let (td, _, trampoline_base) = hook_with_svc_and_msr(19);
        let msr_start = GATES_START_OFFSET + SVC_GATE_SIZE;
        let gate_vaddr = trampoline_base + msr_start as u64;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [0] SUB SP, SP, #48  (already tested in prologue test)
        // [1] STP X16, X17, [SP]
        // [2] STR X30, [SP, #16]
        // [3] STR X19, [SP, #24]

        // [4] BL shared_msr_handler
        let bl_vaddr = gate_vaddr + 4 * 4;
        let handler_vaddr = trampoline_base + SHARED_MSR_HANDLER_OFFSET as u64;
        let bl_offset = handler_vaddr as i64 - bl_vaddr as i64;
        assert_eq!(insn_at(4), encode_bl(bl_offset).unwrap());

        // [5] LDP X16, X17, [SP]
        assert_eq!(insn_at(5), encode_ldp_offset(16, 17, 31, 0).unwrap());

        // [6] LDR X30, [SP, #16]
        assert_eq!(insn_at(6), encode_ldr_imm_unsigned(30, 31, 16).unwrap());

        // [7] ADD SP, SP, #48
        assert_eq!(insn_at(7), encode_add_sp_imm(48).unwrap());

        // [8] B <return_addr>
        // MSR was at vaddr 0x1008, return to 0x100C
        let b_ret_vaddr = gate_vaddr + 8 * 4;
        let expected_offset = 0x100Ci64 - b_ret_vaddr as i64;
        assert_eq!(insn_at(8), encode_b(expected_offset).unwrap());
    }

    #[test]
    fn test_shared_msr_handler_layout() {
        // Verify the full shared MSR handler instruction layout
        // Linear scan TLS lookup
        let (td, _, trampoline_base) = hook_with_svc_and_msr(19);
        let handler_start = SHARED_MSR_HANDLER_OFFSET;
        let handler_vaddr = trampoline_base + handler_start as u64;
        let insn_at = |idx: usize| -> u32 {
            let off = handler_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [0] STR X30, [SP, #32]
        assert_eq!(insn_at(0), encode_str_imm_unsigned(30, 31, 32).unwrap());

        // [1] MRS X16, TPIDR_EL0 -- old guest TPIDR
        assert_eq!(insn_at(1), encode_mrs_tpidr_el0(16));

        // [2] LDR X17, [PC, #offset] -- X17 = TLS table base
        let ldr_tls_vaddr = handler_vaddr + 2 * 4;
        let tls_offset = (trampoline_base + 8) as i64 - ldr_tls_vaddr as i64;
        assert_eq!(insn_at(2), encode_ldr_literal(17, tls_offset).unwrap());

        // [3] .Lloop: LDR X30, [X17, #0] -- X30 = entry.guest_tpidr
        assert_eq!(insn_at(3), encode_ldr_imm_unsigned(30, 17, 0).unwrap());

        // [4] CMN X30, #1 -- sentinel?
        assert_eq!(insn_at(4), encode_cmn_imm(30, 1).unwrap());

        // [5] B.EQ .Lsentinel -> [12]: offset = (12-5)*4 = 28
        assert_eq!(insn_at(5), encode_b_cond(COND_EQ, 28).unwrap());

        // [6] CMP X30, X16 -- match?
        assert_eq!(insn_at(6), encode_cmp_reg(30, 16));

        // [7] B.EQ .Lfound -> [10]: offset = (10-7)*4 = 12
        assert_eq!(insn_at(7), encode_b_cond(COND_EQ, 12).unwrap());

        // [8] ADD X17, X17, #16 -- next entry
        assert_eq!(insn_at(8), encode_add_imm(17, 17, 16).unwrap());

        // [9] B .Lloop -> [3]: offset = (3-9)*4 = -24
        assert_eq!(insn_at(9), encode_b(-24).unwrap());

        // [10] .Lfound: LDR X16, [SP, #24] -- new TPIDR
        assert_eq!(insn_at(10), encode_ldr_imm_unsigned(16, 31, 24).unwrap());

        // [11] STR X16, [X17, #0] -- update entry (only from .Lfound)
        assert_eq!(insn_at(11), encode_str_imm_unsigned(16, 17, 0).unwrap());

        // [12] .Lsentinel: LDR X16, [SP, #24] -- new TPIDR
        assert_eq!(insn_at(12), encode_ldr_imm_unsigned(16, 31, 24).unwrap());

        // [13] MSR TPIDR_EL0, X16
        assert_eq!(insn_at(13), encode_msr_tpidr_el0(16));

        // [14] LDR X30, [SP, #32] -- restore
        assert_eq!(insn_at(14), encode_ldr_imm_unsigned(30, 31, 32).unwrap());

        // [15] RET
        assert_eq!(insn_at(15), encode_ret(30));
    }

    #[test]
    fn test_hook_msr_only_produces_minimal_trampoline() {
        // A binary with only MSR TPIDR_EL0 and no SVC should produce a minimal
        // trampoline (no MSR sites are patched without at least one SVC, since the
        // TLS table requires the callback mechanism).
        let msr_insn = encode_msr_tpidr_el0(19);
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&msr_insn.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let result = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0);
        let (trampoline_data, has_svc) = result.expect("should succeed with minimal trampoline");
        assert!(!has_svc, "should report no SVC found");
        // MSR instruction should NOT be patched (no SVC means no callback mechanism)
        assert_eq!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            msr_insn,
            "MSR instruction should be left unpatched"
        );
        assert_eq!(
            trampoline_data.len(),
            GATES_START_OFFSET,
            "minimal trampoline should be exactly GATES_START_OFFSET bytes"
        );
    }
}
