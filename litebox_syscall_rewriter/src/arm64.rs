// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ARM64 (AArch64) syscall rewriting support.
//!
//! On ARM64, `SVC #0` is exactly 4 bytes, and `B imm26` (direct branch) is also
//! 4 bytes with ±128MB range. This allows a direct 1:1 replacement in the common
//! case — no instruction borrowing needed (unlike x86).

use crate::{Error, Result, TextSectionInfo};

/// Target operating system for the rewritten binary.
///
/// On x86, all targets produce identical output.
/// On ARM64, each OS has distinct rewriting behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TargetOs {
    Linux,
    #[value(name = "macos")]
    MacOs,
    Windows,
}

impl TargetOs {
    pub const fn is_macos(self) -> bool {
        matches!(self, Self::MacOs)
    }

    pub const fn is_windows(self) -> bool {
        matches!(self, Self::Windows)
    }

    /// Whether the target OS requires X18 virtualization.
    ///
    /// On macOS, the kernel zeros X18 on every exception entry.
    /// On Windows, X18 is reserved as the TEB pointer and must not be clobbered.
    /// On Linux, X18 is a free GPR and needs no rewriting.
    pub const fn needs_x18_rewriting(self) -> bool {
        matches!(self, Self::MacOs | Self::Windows)
    }

    // Shared SVC handler
    pub const fn shared_svc_handler_insn_count(self) -> usize {
        match self {
            Self::Linux | Self::MacOs => 18,
            // Windows: 2 extra instructions to store host_tls to stack frame
            // (avoids X16 clobber by linker veneers on BR to callback).
            Self::Windows => 20,
        }
    }
    pub const fn shared_svc_handler_size(self) -> usize {
        self.shared_svc_handler_insn_count() * 4
    }

    // SVC gate
    pub const fn svc_gate_insn_count(self) -> usize {
        match self {
            Self::Linux | Self::Windows => 7,
            Self::MacOs => 7,
        }
    }
    pub const fn svc_gate_size(self) -> usize {
        self.svc_gate_insn_count() * 4
    }

    // Shared MSR handler
    pub const fn shared_msr_handler_insn_count(self) -> usize {
        match self {
            Self::Linux | Self::Windows => 19,
            Self::MacOs => 17,
        }
    }
    pub const fn shared_msr_handler_size(self) -> usize {
        self.shared_msr_handler_insn_count() * 4
    }

    // MSR gate
    pub const fn msr_gate_insn_count(self) -> usize {
        match self {
            Self::Linux | Self::Windows => 9,
            Self::MacOs => 13,
        }
    }
    pub const fn msr_gate_size(self) -> usize {
        self.msr_gate_insn_count() * 4
    }
    pub const fn msr_gate_special_size(self) -> usize {
        (self.msr_gate_insn_count() + 1) * 4
    }

    // MRS gate
    pub const fn mrs_gate_insn_count(self) -> usize {
        match self {
            Self::Linux => 5,
            Self::Windows => 11,
            Self::MacOs => 13,
        }
    }
    pub const fn mrs_gate_size(self) -> usize {
        self.mrs_gate_insn_count() * 4
    }

    // macOS-only shared handlers (values only meaningful when self == MacOs)
    pub const fn shared_mrs_handler_insn_count(self) -> usize {
        16
    }
    pub const fn shared_mrs_handler_size(self) -> usize {
        self.shared_mrs_handler_insn_count() * 4
    }
    pub const fn shared_x18_load_handler_insn_count(self) -> usize {
        16
    }
    pub const fn shared_x18_load_handler_size(self) -> usize {
        self.shared_x18_load_handler_insn_count() * 4
    }
    pub const fn shared_x18_save_handler_insn_count(self) -> usize {
        16
    }
    pub const fn shared_x18_save_handler_size(self) -> usize {
        self.shared_x18_save_handler_insn_count() * 4
    }

    // x18 gate constants (only meaningful when self == MacOs)
    pub const fn x18_gate_read_insn_count(self) -> usize {
        14
    }
    #[allow(dead_code)]
    pub const fn x18_gate_write_insn_count(self) -> usize {
        14
    }
    pub const fn x18_gate_readwrite_insn_count(self) -> usize {
        16
    }

    // Layout offsets
    pub const fn shared_svc_handler_offset(self) -> usize {
        SIGRETURN_GATE_OFFSET + self.svc_gate_size()
    }

    pub const fn shared_msr_handler_offset(self) -> usize {
        self.shared_svc_handler_offset() + self.shared_svc_handler_size()
    }

    pub const fn shared_mrs_handler_offset(self) -> usize {
        self.shared_msr_handler_offset() + self.shared_msr_handler_size()
    }

    pub const fn shared_x18_load_handler_offset(self) -> usize {
        self.shared_mrs_handler_offset() + self.shared_mrs_handler_size()
    }

    pub const fn shared_x18_save_handler_offset(self) -> usize {
        self.shared_x18_load_handler_offset() + self.shared_x18_load_handler_size()
    }

    pub const fn gates_start_offset(self) -> usize {
        match self {
            Self::Linux => self.shared_msr_handler_offset() + self.shared_msr_handler_size(),
            Self::Windows | Self::MacOs => {
                self.shared_x18_save_handler_offset() + self.shared_x18_save_handler_size()
            }
        }
    }

    pub const fn msr_gate_size_for_rt(self, rt: u8) -> usize {
        match rt {
            16 | 17 | 30 => self.msr_gate_special_size(),
            _ => self.msr_gate_size(),
        }
    }
}

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

/// ARM64 instruction mask for `MRS Xd, TPIDR_EL0` (read thread pointer).
///
/// Encoding: `0xD53BD04d` where `d` is the destination register (0-30 for X0-X30, 31 for XZR).
/// We match the top 27 bits and extract the bottom 5 as the register number.
///
/// MRS TPIDR_EL0 is rewritten to read from the TLS table's entry[0].guest_tpidr
/// instead of the hardware register. On macOS, the kernel can clobber TPIDR_EL0
/// on context switches (not just signals), making native reads unreliable.
/// Each MRS site gets a self-contained 5-instruction gate that loads directly
/// from entry[0] — no shared handler needed.
const MRS_TPIDR_EL0_MASK: u32 = 0xFFFF_FFE0;
const MRS_TPIDR_EL0_BITS: u32 = 0xD53B_D040;

/// ARM64 NOP instruction.
const NOP: u32 = 0xD503201F;

/// Offset of the header region: callback address (8 bytes).
const HEADER_CALLBACK_OFFSET: usize = 0;

/// Offset of the TLS lookup table pointer (8 bytes, filled at load time).
const HEADER_TLS_TABLE_OFFSET: usize = 8;

/// Offset of the sigreturn preamble (8 bytes = 2 instructions: MOV X8, #139; B <sigreturn_snippet>).
/// On Windows ARM64 this offset is repurposed for the TEB TLS slot offset
/// (see `HEADER_TEB_TLS_OFFSET`).
#[allow(dead_code)] // Documenting the layout; used by tests
const HEADER_SIGRETURN_OFFSET: usize = 16;

/// Offset of the precomputed TEB TLS slot offset (8 bytes, Windows ARM64 only).
///
/// Stores `TEB_TLS_SLOTS_OFFSET + TLS_INDEX * 8`, allowing the MRS gate to
/// reach the TlsState pointer via `LDR Xn, [X18, <this value>]`.
/// Reuses the same header offset as `HEADER_SIGRETURN_OFFSET` since sigreturn
/// is not used on Windows.
#[allow(dead_code)]
const HEADER_TEB_TLS_OFFSET: usize = 16;

/// Offset where the sigreturn SVC gate begins.
/// Called from the sigreturn preamble at offset 16 via `B .+8`.
const SIGRETURN_GATE_OFFSET: usize = 24;

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
#[allow(dead_code)]
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

/// Encode `MRS Xt, TPIDRRO_EL0` (read read-only thread pointer register).
///
/// TPIDRRO_EL0 system register: op0=3, op1=3, CRn=13, CRm=0, op2=3
/// Encoding: `MRS Xt, <sysreg>` = `0xD53BD060 | Rt`
///
/// On macOS, TPIDRRO_EL0 is set to the pthread TSD base. It is stable,
/// per-thread, read-only to userspace, and never clobbered — making it
/// a reliable lookup key for TLS table entries.
fn encode_mrs_tpidrro_el0(rt: u8) -> u32 {
    // TPIDRRO_EL0: op0=3(11), op1=3(011), CRn=13(1101), CRm=0(0000), op2=3(011)
    // Same as TPIDR_EL0 except op2=3 instead of 2
    // = 0xD53BD060 | Rt
    0xD53B_D060 | u32::from(rt)
}

/// Encode `MRS Xt, NZCV` (read condition flags register).
///
/// NZCV: op0=3, op1=3, CRn=4, CRm=2, op2=0
/// Encoding: `0xD53B4200 | Rt`
fn encode_mrs_nzcv(rt: u8) -> u32 {
    0xD53B_4200 | u32::from(rt)
}

/// Encode `MSR NZCV, Xt` (write condition flags register).
///
/// Encoding: `0xD51B4200 | Rt`
fn encode_msr_nzcv(rt: u8) -> u32 {
    0xD51B_4200 | u32::from(rt)
}

/// Encode `BRK #imm16` (breakpoint exception).
///
/// Used as a trap instruction in unreachable code paths (e.g., unknown thread
/// in TLS table lookup). Generates a synchronous debug exception.
/// Encoding: `0xD4200000 | (imm16 << 5)`
fn encode_brk(imm16: u16) -> u32 {
    0xD420_0000 | (u32::from(imm16) << 5)
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

/// Encode `STP Xt1, Xt2, [Xn, #imm]!` (store pair, 64-bit, pre-index).
///
/// Stores two 64-bit registers and updates the base register with base + offset.
/// The offset must be a multiple of 8 and within [-512, 504].
///
/// Encoding: opc=10, V=0, type=011 (pre-index), L=0 (store), imm7=offset/8, Rt2, Rn, Rt
#[allow(dead_code)]
fn encode_stp_pre_index(rt: u8, rt2: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
    if imm_bytes % 8 != 0 {
        return None;
    }
    let imm7 = imm_bytes / 8;
    if !(-64..=63).contains(&imm7) {
        return None;
    }
    #[allow(clippy::cast_sign_loss)]
    let imm7_u = (imm7 as u32) & 0x7F;
    // 10_101_0_011_0_imm7_Rt2_Rn_Rt
    // = 0xA9800000 | (imm7 << 15) | (Rt2 << 10) | (Rn << 5) | Rt
    Some(
        0xA980_0000
            | (imm7_u << 15)
            | (u32::from(rt2) << 10)
            | (u32::from(rn) << 5)
            | u32::from(rt),
    )
}

/// Encode `LDP Xt1, Xt2, [Xn], #imm` (load pair, 64-bit, post-index).
///
/// Loads two 64-bit values then updates the base register with base + offset.
/// The offset must be a multiple of 8 and within [-512, 504].
///
/// Encoding: opc=10, V=0, type=001 (post-index), L=1 (load), imm7=offset/8, Rt2, Rn, Rt
#[allow(dead_code)]
fn encode_ldp_post_index(rt: u8, rt2: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
    if imm_bytes % 8 != 0 {
        return None;
    }
    let imm7 = imm_bytes / 8;
    if !(-64..=63).contains(&imm7) {
        return None;
    }
    #[allow(clippy::cast_sign_loss)]
    let imm7_u = (imm7 as u32) & 0x7F;
    // 10_101_0_001_1_imm7_Rt2_Rn_Rt
    // = 0xA8C00000 | (imm7 << 15) | (Rt2 << 10) | (Rn << 5) | Rt
    Some(
        0xA8C0_0000
            | (imm7_u << 15)
            | (u32::from(rt2) << 10)
            | (u32::from(rn) << 5)
            | u32::from(rt),
    )
}

/// Encode `STR Xt, [Xn, #simm]!` (store register, 64-bit, pre-index).
///
/// The offset must be within [-256, 255].
///
/// Encoding: size=11, V=0, opc=00 (store), imm9, pre-index=11, Rn, Rt
#[allow(dead_code)]
fn encode_str_pre_index(rt: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
    if !(-256..=255).contains(&imm_bytes) {
        return None;
    }
    #[allow(clippy::cast_sign_loss)]
    let imm9 = (imm_bytes as u32) & 0x1FF;
    // 11_111_000_00_0_imm9_11_Rn_Rt
    Some(0xF800_0C00 | (imm9 << 12) | (u32::from(rn) << 5) | u32::from(rt))
}

/// Encode `LDR Xt, [Xn], #simm` (load register, 64-bit, post-index).
///
/// The offset must be within [-256, 255].
///
/// Encoding: size=11, V=0, opc=01 (load), imm9, post-index=01, Rn, Rt
#[allow(dead_code)]
fn encode_ldr_post_index(rt: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
    if !(-256..=255).contains(&imm_bytes) {
        return None;
    }
    #[allow(clippy::cast_sign_loss)]
    let imm9 = (imm_bytes as u32) & 0x1FF;
    // 11_111_000_01_0_imm9_01_Rn_Rt
    Some(0xF840_0400 | (imm9 << 12) | (u32::from(rn) << 5) | u32::from(rt))
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

/// Encode `CBZ Xt, #offset` (compare and branch on zero, 64-bit).
///
/// The offset must be a multiple of 4 and within ±1MB (signed 19-bit instruction count).
/// Encoding: `[31] = 1 (sf=64-bit)`, `[30:25] = 011010`, `[24] = 0 (not-zero=0 → CBZ)`,
/// `[23:5] = imm19`, `[4:0] = Rt`
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn encode_cbz(rt: u8, offset: i64) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm19 = offset / 4;
    if !(-0x40000..0x40000).contains(&imm19) {
        return None;
    }
    Some(0xB400_0000 | ((imm19 as u32 & 0x7FFFF) << 5) | u32::from(rt))
}

/// Encode `LDR Xt, [Xn, Xm]` (64-bit register offset load, no shift).
///
/// Loads from address `Xn + Xm` into `Xt`.
/// Encoding: size=11, V=0, opc=01, Rm, option=011, S=0.
fn encode_ldr_reg_offset(rt: u8, rn: u8, rm: u8) -> u32 {
    0xF860_6800 | (u32::from(rm) << 16) | (u32::from(rn) << 5) | u32::from(rt)
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
    /// `MRS Xd, TPIDR_EL0` — thread pointer read.
    /// The `u8` is the destination register number (0-30 for X0-X30, 31 for XZR).
    /// Rewritten to read from TLS table entry[0] instead of the hardware register.
    MrsTpidr(u8),
    /// An instruction that references X18 (macOS and Windows only).
    ///
    /// On macOS, x18 is zeroed by the kernel on every return to userspace, so every
    /// instruction that reads or writes x18 must be rewritten to load/store from the
    /// per-thread `guest_x18` cell in the TCB.
    /// On Windows, x18 is reserved as the TEB pointer and must not be clobbered by
    /// guest code. Instructions referencing x18 are rewritten to use a scratch register
    /// that loads/stores from a TLS-backed virtual x18 slot.
    X18Use {
        /// The original 32-bit instruction word.
        insn: u32,
        /// The rewritten instruction with x18 replaced by the scratch register.
        rewritten: u32,
        /// Which scratch register replaces x18 (typically 17, or 16 if insn uses X17).
        scratch: u8,
        /// Whether x18 is read by this instruction.
        is_read: bool,
        /// Whether x18 is written by this instruction.
        is_write: bool,
        /// Whether the instruction is SP-relative memory access whose immediate offset
        /// would overflow when adjusted by +48 (the gate's frame size). When true, the
        /// gate uses ADD SP, SP, #48 / <original insn> / SUB SP, SP, #48 instead of
        /// modifying the instruction's immediate field. This adds 2 instructions to the gate.
        needs_sp_fixup: bool,
    },
}

// ============================================================
// macOS x18 detection and rewriting (cfg-gated for test too)
// ============================================================

/// Check if an ARM64 instruction references register x18.
///
/// Uses yaxpeax-arm to decode the instruction and inspect operands. If the decoder
/// fails (rare), falls back to a conservative bit-field check.
///
/// Returns `true` if any operand is a general-purpose register with number 18,
/// including inside memory addressing modes (base register, index register, etc.).
fn references_x18(insn: u32) -> bool {
    use yaxpeax_arch::Decoder;
    use yaxpeax_arm::armv8::a64::{InstDecoder, Operand};

    // Helper: check if a register number is 18
    fn has_x18_in_operand(op: &Operand) -> bool {
        match op {
            Operand::Register(_, reg) if *reg == 18 => true,
            Operand::RegisterPair(_, reg) if *reg == 18 || *reg + 1 == 18 => true,
            Operand::RegisterOrSP(_, reg) if *reg == 18 => true,
            Operand::RegShift(_, _, _, reg) if *reg == 18 => true,
            Operand::RegRegOffset(base, idx, _, _, _) if *base == 18 || *idx == 18 => true,
            Operand::RegPreIndex(reg, _, _) if *reg == 18 => true,
            Operand::RegPostIndex(reg, _) if *reg == 18 => true,
            Operand::RegPostIndexReg(reg, reg2) if *reg == 18 || *reg2 == 18 => true,
            _ => false,
        }
    }

    // Fast path: if no standard register bit field contains 18, skip
    let rd = insn & 0x1F;
    let rn = (insn >> 5) & 0x1F;
    let rm = (insn >> 16) & 0x1F;
    let rt2 = (insn >> 10) & 0x1F;
    if rd != 18 && rn != 18 && rm != 18 && rt2 != 18 {
        return false;
    }

    // Decode with yaxpeax-arm to confirm the bit field is actually a register operand
    let decoder = InstDecoder::default();
    let word = insn.to_le_bytes();
    let mut reader = yaxpeax_arch::U8Reader::new(&word);
    let Ok(instruction) = decoder.decode(&mut reader) else {
        // Decoder failed — use conservative bit-field check
        return true;
    };

    instruction.operands.iter().any(has_x18_in_operand)
}

/// Check if an ARM64 instruction is a store (writes to memory).
///
/// Uses the top byte of the instruction encoding to classify common store patterns.
/// This is conservative — instructions not recognized as stores are treated as
/// non-stores (loads or arithmetic), which is the safe default for read/write analysis.
fn is_store_instruction(insn: u32) -> bool {
    use yaxpeax_arch::Decoder;
    use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode};

    let decoder = InstDecoder::default();
    let word = insn.to_le_bytes();
    let mut reader = yaxpeax_arch::U8Reader::new(&word);
    let Ok(instruction) = decoder.decode(&mut reader) else {
        return false;
    };

    matches!(
        instruction.opcode,
        Opcode::STP
            | Opcode::STR
            | Opcode::STUR
            | Opcode::STRB
            | Opcode::STURB
            | Opcode::STRH
            | Opcode::STURH
            | Opcode::STLR
            | Opcode::STLRB
            | Opcode::STLRH
            | Opcode::STXR
            | Opcode::STXRB
            | Opcode::STXRH
            | Opcode::STLXR
            | Opcode::STLXRB
            | Opcode::STLXRH
            | Opcode::STNP
            | Opcode::STXP
            | Opcode::STLXP
    )
}

/// Rewrite an instruction that references x18, replacing x18 with a scratch register.
///
/// Returns `(rewritten_insn, scratch_reg, is_read, is_write)`.
///
/// Scratch register is X17 by default, or X16 if the instruction already uses X17
/// in a non-x18 role.
fn rewrite_x18(insn: u32) -> (u32, u8, bool, bool) {
    // Determine if instruction uses X17 in a non-x18 field — if so, use X16 as scratch
    let rd = insn & 0x1F;
    let rn = (insn >> 5) & 0x1F;
    let rm = (insn >> 16) & 0x1F;
    let rt2 = (insn >> 10) & 0x1F;

    let uses_x17 = (rd == 17 && rd != 18)
        || (rn == 17 && rn != 18)
        || (rm == 17 && rm != 18)
        || (rt2 == 17 && rt2 != 18);
    let scratch = if uses_x17 { 16u8 } else { 17u8 };

    let mut result = insn;
    let mut is_read = false;
    let mut is_write = false;

    let is_store = is_store_instruction(insn);

    // Rd (bits 4:0) — destination for most insns, but Rt (source) for stores
    if (result & 0x1F) == 18 {
        result = (result & !0x1F) | u32::from(scratch);
        if is_store {
            is_read = true;
        } else {
            is_write = true;
        }
    }

    // Rn (bits 9:5) — first source/base register (read)
    if ((result >> 5) & 0x1F) == 18 {
        result = (result & !(0x1F << 5)) | (u32::from(scratch) << 5);
        is_read = true;
    }

    // Rm (bits 20:16) — second source register (read)
    if ((result >> 16) & 0x1F) == 18 {
        result = (result & !(0x1F << 16)) | (u32::from(scratch) << 16);
        is_read = true;
    }

    // Rt2 (bits 14:10) — second transfer register in LDP/STP
    if ((result >> 10) & 0x1F) == 18 {
        result = (result & !(0x1F << 10)) | (u32::from(scratch) << 10);
        if is_store {
            is_read = true;
        } else {
            is_write = true;
        }
    }

    (result, scratch, is_read, is_write)
}

/// Adjust the immediate offset of an SP-relative instruction to compensate for the
/// x18 gate's stack frame.
///
/// When the x18 gate pushes its frame (`SUB SP, SP, #frame_size`), any guest instruction
/// that uses SP-relative addressing will access the wrong memory location because SP has
/// shifted. This function adds `frame_size` to the instruction's immediate offset to
/// compensate.
///
/// Returns `Some(adjusted_insn)` if adjustment was needed and successful,
/// `None` if the instruction is not SP-relative or the adjusted offset doesn't fit.
///
/// Supported formats:
/// - STP/LDP signed offset (imm7, scaled by access size)
/// - STR/LDR unsigned offset (imm12, scaled by access size)
/// - STUR/LDUR unscaled offset (imm9, signed)
fn adjust_sp_relative_offset(insn: u32, frame_size: u16) -> Option<u32> {
    use yaxpeax_arch::Decoder;
    use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode};

    // Check if Rn (bits 9:5) is SP (register 31)
    let rn = (insn >> 5) & 0x1F;
    if rn != 31 {
        return None; // Not SP-relative, no adjustment needed
    }

    // Decode to identify instruction format
    let decoder = InstDecoder::default();
    let word = insn.to_le_bytes();
    let mut reader = yaxpeax_arch::U8Reader::new(&word);
    let Ok(instruction) = decoder.decode(&mut reader) else {
        return None;
    };

    match instruction.opcode {
        // STP/LDP/STNP/LDNP with signed offset: imm7 at bits 21:15, scaled by access size
        Opcode::STP | Opcode::LDP | Opcode::STNP | Opcode::LDNP => {
            // Determine scale from the opc field (bits 31:30)
            // opc=00 → 32-bit (scale 4), opc=10 → 64-bit (scale 8), opc=01 → SIMD varies
            let opc = (insn >> 30) & 0x3;
            let scale: i16 = match opc {
                0b00 => 4,        // 32-bit (W registers)
                0b10 => 8,        // 64-bit (X registers)
                _ => return None, // SIMD/FP or other — bail
            };

            // Check this is the signed-offset variant (not pre-index or post-index)
            // Bits 25:23 encode the addressing mode for load/store pair:
            //   010 = signed offset, 011 = pre-index, 001 = post-index
            let addr_mode = (insn >> 23) & 0x7;
            if addr_mode != 0b010 {
                // Pre-index or post-index — these modify SP, can't just adjust offset
                return None;
            }

            // Extract signed imm7 (bits 21:15)
            let imm7_raw = ((insn >> 15) & 0x7F) as i16;
            let imm7_signed = if imm7_raw >= 64 {
                imm7_raw - 128
            } else {
                imm7_raw
            };
            let current_offset = imm7_signed * scale;
            let new_offset = current_offset + frame_size.cast_signed();
            let new_imm7 = new_offset / scale;

            // Validate: new offset must be aligned and fit in imm7 range [-64, 63]
            if new_offset % scale != 0 || !(-64..=63).contains(&new_imm7) {
                return None;
            }

            #[allow(clippy::cast_sign_loss)]
            let new_imm7_u = (new_imm7 as u32) & 0x7F;
            let adjusted = (insn & !(0x7F << 15)) | (new_imm7_u << 15);
            Some(adjusted)
        }

        // STR/LDR with unsigned offset: imm12 at bits 21:10, scaled by access size
        Opcode::STR | Opcode::LDR => {
            // Determine scale from size field (bits 31:30)
            let size = (insn >> 30) & 0x3;
            let scale: u16 = 1 << size; // 0→1, 1→2, 2→4, 3→8

            // Check this is the unsigned offset variant (bits 29:24 = 0b111001 for STR
            // or 0b111001 for LDR, with bit 24=0 for unsigned offset form)
            // The key distinguisher: bits 29:21 pattern. For unsigned offset:
            // STR: 1x_111_0_01_00 (bits 31:22), LDR: 1x_111_0_01_01
            // For unscaled (STUR/LDUR): 1x_111_0_00_0x
            // Check bit 24 (part of the opc/type field): 1 = unsigned offset, 0 = other
            let is_unsigned_offset = ((insn >> 24) & 0x1) == 1;
            if !is_unsigned_offset {
                // This is STUR/LDUR (unscaled) or other variant — handle separately
                return None;
            }

            // Extract unsigned imm12 (bits 21:10)
            let imm12 = ((insn >> 10) & 0xFFF) as u16;
            let current_offset = imm12 * scale;
            let new_offset = current_offset + frame_size;
            let new_imm12 = new_offset / scale;

            // Validate: new offset must be aligned and fit in 12 bits
            if !new_offset.is_multiple_of(scale) || new_imm12 >= (1 << 12) {
                return None;
            }

            let adjusted = (insn & !(0xFFF << 10)) | (u32::from(new_imm12) << 10);
            Some(adjusted)
        }

        // STUR/LDUR with unscaled signed offset: imm9 at bits 20:12
        Opcode::STUR
        | Opcode::LDUR
        | Opcode::STURB
        | Opcode::LDURB
        | Opcode::STURH
        | Opcode::LDURH => {
            let imm9_raw = ((insn >> 12) & 0x1FF) as i16;
            let imm9_signed = if imm9_raw >= 256 {
                imm9_raw - 512
            } else {
                imm9_raw
            };
            let new_offset = imm9_signed + frame_size.cast_signed();

            // Validate: fits in signed 9-bit range [-256, 255]
            if !(-256..=255).contains(&new_offset) {
                return None;
            }

            #[allow(clippy::cast_sign_loss)]
            let new_imm9_u = (new_offset as u32) & 0x1FF;
            let adjusted = (insn & !(0x1FF << 12)) | (new_imm9_u << 12);
            Some(adjusted)
        }

        // STRB/LDRB/STRH/LDRH unsigned offset — same pattern as STR/LDR but different scale
        Opcode::STRB | Opcode::LDRB => {
            let is_unsigned_offset = ((insn >> 24) & 0x1) == 1;
            if !is_unsigned_offset {
                return None;
            }
            // Scale = 1 byte
            let imm12 = ((insn >> 10) & 0xFFF) as u16;
            let new_offset = imm12 + frame_size;
            if new_offset >= (1 << 12) {
                return None;
            }
            let adjusted = (insn & !(0xFFF << 10)) | (u32::from(new_offset) << 10);
            Some(adjusted)
        }

        Opcode::STRH | Opcode::LDRH => {
            let is_unsigned_offset = ((insn >> 24) & 0x1) == 1;
            if !is_unsigned_offset {
                return None;
            }
            // Scale = 2 bytes
            let imm12 = ((insn >> 10) & 0xFFF) as u16;
            let current_offset = imm12 * 2;
            let new_offset = current_offset + frame_size;
            let new_imm12 = new_offset / 2;
            if !new_offset.is_multiple_of(2) || new_imm12 >= (1 << 12) {
                return None;
            }
            let adjusted = (insn & !(0xFFF << 10)) | (u32::from(new_imm12) << 10);
            Some(adjusted)
        }

        // Any other instruction with SP as base that we don't know how to adjust
        _ => None,
    }
}

/// Check if a rewritten instruction is an SP-relative memory access whose immediate
/// offset would overflow when adjusted by the gate's frame size.
///
/// Returns `true` if the instruction uses SP as base (Rn=31), is a recognized
/// memory opcode, and `adjust_sp_relative_offset` returns `None` (overflow or
/// unsupported format). In this case, the gate must use the SP restore strategy
/// (ADD SP, SP, #frame / <insn> / SUB SP, SP, #frame) instead of immediate adjustment.
fn needs_sp_fixup(rewritten: u32, frame_size: u16) -> bool {
    use yaxpeax_arch::Decoder;
    use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode};

    let rn = (rewritten >> 5) & 0x1F;
    if rn != 31 {
        return false; // Not SP-relative
    }

    // If adjust succeeds, no fixup needed
    if adjust_sp_relative_offset(rewritten, frame_size).is_some() {
        return false;
    }

    // Check if this is a memory operation (vs. ADD/SUB/CMP with SP)
    let decoder = InstDecoder::default();
    let word = rewritten.to_le_bytes();
    let mut reader = yaxpeax_arch::U8Reader::new(&word);
    decoder.decode(&mut reader).is_ok_and(|decoded| {
        matches!(
            decoded.opcode,
            Opcode::STP
                | Opcode::LDP
                | Opcode::STNP
                | Opcode::LDNP
                | Opcode::STR
                | Opcode::LDR
                | Opcode::STUR
                | Opcode::LDUR
                | Opcode::STRB
                | Opcode::LDRB
                | Opcode::STURB
                | Opcode::LDURB
                | Opcode::STRH
                | Opcode::LDRH
                | Opcode::STURH
                | Opcode::LDURH
                | Opcode::STLR
                | Opcode::STLRB
                | Opcode::STLRH
                | Opcode::LDAR
                | Opcode::LDARB
                | Opcode::LDARH
                | Opcode::STXR
                | Opcode::STXRB
                | Opcode::STXRH
                | Opcode::LDXR
                | Opcode::LDXRB
                | Opcode::LDXRH
        )
    })
}

/// Compute the gate size for an x18-referencing instruction.
///
/// When `sp_fixup` is true, the gate emits 2 extra instructions (ADD SP / SUB SP)
/// around the rewritten instruction to restore the original SP for memory access.
fn x18_gate_size(target_os: TargetOs, is_read: bool, is_write: bool, sp_fixup: bool) -> usize {
    let extra = if sp_fixup { 2 } else { 0 };
    if is_read && is_write {
        (target_os.x18_gate_readwrite_insn_count() + extra) * 4
    } else {
        // Both read-only and write-only are 14 insns (with NZCV save/restore)
        (target_os.x18_gate_read_insn_count() + extra) * 4
    }
}

/// Scan executable sections for `SVC #0`, `MSR TPIDR_EL0, Xt`, and
/// `MRS Xd, TPIDR_EL0` instructions.
///
/// ARM64 instructions are always 4-byte aligned, so we scan in 4-byte steps.
/// Returns patch sites sorted by file offset.
#[allow(clippy::cast_possible_truncation)]
fn find_patch_sites(
    sections: &[TextSectionInfo],
    buf: &[u8],
    target_os: TargetOs,
) -> Result<Vec<PatchSite>> {
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
            } else if (insn & MRS_TPIDR_EL0_MASK) == MRS_TPIDR_EL0_BITS {
                let rd = (insn & 0x1F) as u8;
                sites.push(PatchSite {
                    file_offset: start + i,
                    vaddr: section.vaddr + i as u64,
                    kind: PatchKind::MrsTpidr(rd),
                });
            }
            // macOS/Windows: check for x18 references (after SVC/MSR/MRS checks to avoid double-patching)
            if target_os.needs_x18_rewriting()
                && insn != SVC_0
                && (insn & MSR_TPIDR_EL0_MASK) != MSR_TPIDR_EL0_BITS
                && (insn & MRS_TPIDR_EL0_MASK) != MRS_TPIDR_EL0_BITS
                && references_x18(insn)
            {
                let (rewritten, scratch, is_read, is_write) = rewrite_x18(insn);
                let sp_fixup = needs_sp_fixup(rewritten, 48);
                sites.push(PatchSite {
                    file_offset: start + i,
                    vaddr: section.vaddr + i as u64,
                    kind: PatchKind::X18Use {
                        insn,
                        rewritten,
                        scratch,
                        is_read,
                        is_write,
                        needs_sp_fixup: sp_fixup,
                    },
                });
            }
        }
    }

    Ok(sites)
}

// ============================================================
// Main hooking function
// ============================================================

/// Hook all `SVC #0`, `MSR TPIDR_EL0`, and `MRS Xd, TPIDR_EL0` instructions
/// in an AArch64 ELF binary.
///
/// This function:
/// 1. Scans for SVC #0, MSR TPIDR_EL0, and MRS TPIDR_EL0 instructions
/// 2. Builds a shared trampoline with header, shared handlers, and per-site gates
/// 3. Patches each instruction with a `B` (branch) to its per-site gate
///
/// On macOS, TPIDR_EL0 is clobbered by preemptive context switches, so both
/// MSR (writes) and MRS (reads) must be rewritten. MSR gates update the TLS
/// table via the shared MSR handler; MRS gates read `entry[0].guest_tpidr`
/// directly from the TLS table.
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
/// Offset 120:   [76 bytes]  Shared MSR handler (with sentinel entry[0] write)
/// Offset 196:   Per-site SVC gates (24 bytes each)
///               Per-site MSR gates (36-40 bytes each)
///               Per-site MRS gates (20 bytes each)
/// ```
pub(crate) fn hook_syscalls_aarch64(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    trampoline: u64,
    target_os: TargetOs,
) -> Result<(Vec<u8>, bool)> {
    // Find all SVC #0, MSR TPIDR_EL0, and MRS TPIDR_EL0 sites
    let sites = find_patch_sites(text_sections, buf, target_os)?;

    // Check if there are any SVC instructions to patch
    let has_svc = sites.iter().any(|s| s.kind == PatchKind::Svc);
    let has_tpidr_sites = sites
        .iter()
        .any(|s| matches!(s.kind, PatchKind::MsrTpidr(_) | PatchKind::MrsTpidr(_)));

    let has_x18_sites = if target_os.needs_x18_rewriting() {
        sites
            .iter()
            .any(|s| matches!(s.kind, PatchKind::X18Use { .. }))
    } else {
        false
    };

    if !has_svc && !has_tpidr_sites && !has_x18_sites {
        // No patch sites at all. Produce a minimal trampoline containing
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
            target_os,
        )?;

        debug_assert_eq!(trampoline_data.len(), target_os.shared_svc_handler_offset());

        // Offset 48: shared SVC handler (72 bytes)
        emit_shared_svc_handler(
            &mut trampoline_data,
            target_os.shared_svc_handler_offset(),
            trampoline_base_addr,
            target_os,
        )?;

        debug_assert_eq!(trampoline_data.len(), target_os.shared_msr_handler_offset());

        // Offset 120: shared MSR handler (76 bytes)
        emit_shared_msr_handler(
            &mut trampoline_data,
            target_os.shared_msr_handler_offset(),
            trampoline_base_addr,
            target_os,
        )?;

        // macOS/Windows: shared MRS handler, x18 load handler, x18 save handler
        if target_os.needs_x18_rewriting() {
            debug_assert_eq!(trampoline_data.len(), target_os.shared_mrs_handler_offset());
            emit_shared_mrs_handler(
                &mut trampoline_data,
                target_os.shared_mrs_handler_offset(),
                trampoline_base_addr,
                target_os,
            )?;

            debug_assert_eq!(
                trampoline_data.len(),
                target_os.shared_x18_load_handler_offset()
            );
            emit_shared_x18_load_handler(
                &mut trampoline_data,
                target_os.shared_x18_load_handler_offset(),
                trampoline_base_addr,
                target_os,
            )?;

            debug_assert_eq!(
                trampoline_data.len(),
                target_os.shared_x18_save_handler_offset()
            );
            emit_shared_x18_save_handler(
                &mut trampoline_data,
                target_os.shared_x18_save_handler_offset(),
                trampoline_base_addr,
                target_os,
            )?;
        }

        debug_assert_eq!(trampoline_data.len(), target_os.gates_start_offset());

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
        target_os,
    )?;

    debug_assert_eq!(trampoline_data.len(), target_os.shared_svc_handler_offset());

    // Offset 48: shared SVC handler (72 bytes)
    emit_shared_svc_handler(
        &mut trampoline_data,
        target_os.shared_svc_handler_offset(),
        trampoline_base_addr,
        target_os,
    )?;

    debug_assert_eq!(trampoline_data.len(), target_os.shared_msr_handler_offset());

    // Offset 120: shared MSR handler (76 bytes)
    emit_shared_msr_handler(
        &mut trampoline_data,
        target_os.shared_msr_handler_offset(),
        trampoline_base_addr,
        target_os,
    )?;

    // macOS/Windows: shared MRS handler, x18 load handler, x18 save handler
    if target_os.needs_x18_rewriting() {
        debug_assert_eq!(trampoline_data.len(), target_os.shared_mrs_handler_offset());
        emit_shared_mrs_handler(
            &mut trampoline_data,
            target_os.shared_mrs_handler_offset(),
            trampoline_base_addr,
            target_os,
        )?;

        debug_assert_eq!(
            trampoline_data.len(),
            target_os.shared_x18_load_handler_offset()
        );
        emit_shared_x18_load_handler(
            &mut trampoline_data,
            target_os.shared_x18_load_handler_offset(),
            trampoline_base_addr,
            target_os,
        )?;

        debug_assert_eq!(
            trampoline_data.len(),
            target_os.shared_x18_save_handler_offset()
        );
        emit_shared_x18_save_handler(
            &mut trampoline_data,
            target_os.shared_x18_save_handler_offset(),
            trampoline_base_addr,
            target_os,
        )?;
    }

    debug_assert_eq!(trampoline_data.len(), target_os.gates_start_offset());

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
                    target_os,
                )?;
            }
            PatchKind::MsrTpidr(rt) => {
                emit_msr_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    rt,
                    target_os,
                )?;
            }
            PatchKind::MrsTpidr(rd) => {
                emit_mrs_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    rd,
                    target_os,
                )?;
            }
            PatchKind::X18Use {
                rewritten,
                scratch,
                is_read,
                is_write,
                needs_sp_fixup: sp_fixup,
                ..
            } => {
                emit_x18_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    rewritten,
                    scratch,
                    is_read,
                    is_write,
                    sp_fixup,
                    target_os,
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

    Ok((trampoline_data, has_svc))
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
    target_os: TargetOs,
) -> Result<()> {
    match target_os {
        TargetOs::Linux => emit_shared_svc_handler_linux(
            trampoline_data,
            handler_offset,
            trampoline_base_addr,
            target_os,
        ),
        TargetOs::Windows => emit_shared_svc_handler_windows(
            trampoline_data,
            handler_offset,
            trampoline_base_addr,
            target_os,
        ),
        TargetOs::MacOs => emit_shared_svc_handler_macos(
            trampoline_data,
            handler_offset,
            trampoline_base_addr,
            target_os,
        ),
    }
}

/// Linux shared SVC handler: TPIDR_EL0-keyed lookup with fallback to entry[0].
/// See constant docs for instruction layout.
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_svc_handler_linux(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
    target_os: TargetOs,
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

    debug_assert_eq!(insn_idx, target_os.shared_svc_handler_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        target_os.shared_svc_handler_size(),
        "Shared SVC handler size mismatch"
    );

    Ok(())
}

/// Windows shared SVC handler: same logic as Linux but avoids clobbering X18 (TEB).
///
/// On Windows ARM64, X18 is the TEB pointer and must not be modified. This handler
/// uses X30 (saved in the SVC gate frame at [SP+16]) instead of X18 for the
/// TPIDR_EL0 lookup key. The host_tls result goes into X16, and the callback
/// address is loaded last via a PC-relative LDR.
///
/// Register allocation:
///   X30: TPIDR_EL0 value (lookup key) — already saved at [SP+16] by SVC gate
///   X17: TLS table pointer
///   X16: entry fields, host_tls, callback address
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_svc_handler_windows(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
    target_os: TargetOs,
) -> Result<()> {
    let handler_vaddr = trampoline_base_addr + handler_offset as u64;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { handler_vaddr + (idx as u64) * 4 };
    let tls_table_vaddr = trampoline_base_addr + HEADER_TLS_TABLE_OFFSET as u64;

    // [0] MRS X30, TPIDR_EL0 — use X30 (saved by SVC gate) instead of X18
    trampoline_data.extend_from_slice(&encode_mrs_tpidr_el0(30).to_le_bytes());
    insn_idx += 1;

    // [1] STR X30, [SP, #24] — save guest TPIDR
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [2] LDR X17, [PC, #offset] — X17 = TLS table base
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let ldr_tls_offset = tls_table_vaddr.cast_signed() - ldr_tls_vaddr.cast_signed();
    let ldr_tls_insn = encode_ldr_literal(17, ldr_tls_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_tls_offset:#x} out of range for Windows shared SVC handler"
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

    // [5] B.EQ .Lfallback -> [13]
    let fallback_idx = 13usize;
    let beq_fallback_offset = (fallback_idx as i64 - insn_idx as i64) * 4;
    let beq_fallback = encode_b_cond(COND_EQ, beq_fallback_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_fallback_offset:#x} out of range in Windows shared SVC handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_fallback.to_le_bytes());
    insn_idx += 1;

    // [6] CMP X16, X30 — match guest TPIDR? (X30 instead of X18)
    trampoline_data.extend_from_slice(&encode_cmp_reg(16, 30).to_le_bytes());
    insn_idx += 1;

    // [7] B.EQ .Lfound -> [10]
    let found_idx = 10usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_found_offset:#x} out of range in Windows shared SVC handler"
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
            "B offset {b_loop_offset:#x} out of range in Windows shared SVC handler loop"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [10] .Lfound: LDR X16, [X17, #8] — X16 = host_tls
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 17, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [11] STR X16, [SP, #24] — store host_tls to frame for syscall_callback
    // (Overwrites guest_tpidr at [SP+24] which was saved at instruction [1].
    // The callback reads host_tls from [SP+24] instead of X16, because the
    // BR X17 to callback may go through a linker veneer that clobbers X16.)
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [12] B .Ldone -> [18]
    let done_idx = 18usize;
    let b_done_offset = (done_idx as i64 - insn_idx as i64) * 4;
    let b_done = encode_b(b_done_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_done_offset:#x} out of range in Windows shared SVC handler done"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_done.to_le_bytes());
    insn_idx += 1;

    // [12] .Lfallback: LDR X17, [PC, #offset] — reload TLS table base
    debug_assert_eq!(insn_idx, fallback_idx);
    let fallback_ldr_vaddr = insn_vaddr(insn_idx);
    let fallback_ldr_offset = tls_table_vaddr.cast_signed() - fallback_ldr_vaddr.cast_signed();
    let fallback_ldr_insn = encode_ldr_literal(17, fallback_ldr_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {fallback_ldr_offset:#x} out of range for Windows SVC handler fallback"
        ))
    })?;
    trampoline_data.extend_from_slice(&fallback_ldr_insn.to_le_bytes());
    insn_idx += 1;

    // [13] LDR X30, [X17, #0] — X30 = entry[0].guest_tpidr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 17, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [14] STR X30, [SP, #24] — fix guest_tpidr on stack
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [16] LDR X16, [X17, #8] — X16 = entry[0].host_tls (fallback)
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 17, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [16b] STR X16, [SP, #24] — store host_tls to frame (fallback path)
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [17] .Ldone: LDR X17, [PC, #offset_to_callback]
    // Use X17 for callback since X16 holds host_tls
    debug_assert_eq!(insn_idx, done_idx);
    let ldr_cb_vaddr = insn_vaddr(insn_idx);
    let callback_vaddr = trampoline_base_addr + HEADER_CALLBACK_OFFSET as u64;
    let ldr_cb_offset = callback_vaddr.cast_signed() - ldr_cb_vaddr.cast_signed();
    let ldr_cb_insn = encode_ldr_literal(17, ldr_cb_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_cb_offset:#x} out of range for Windows shared SVC handler callback"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_cb_insn.to_le_bytes());
    insn_idx += 1;

    // [17] BR X17 — jump to callback with X16 = host_tls
    trampoline_data.extend_from_slice(&encode_br(17).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.shared_svc_handler_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        target_os.shared_svc_handler_size(),
        "Windows shared SVC handler size mismatch"
    );

    Ok(())
}
///
/// Uses TPIDRRO_EL0 (stable per-pthread, never clobbered) as the TLS table lookup key.
/// On match: loads host_tls (TCB ptr), saves guest x18 to TCB, loads guest_tpidr to frame.
/// On sentinel: BRK (unknown thread = bug, not recoverable).
///
/// ```text
///  [0]  MRS  X17, TPIDRRO_EL0     ; stable per-thread key
///  [1]  LDR  X16, [PC, #off]      ; X16 = TLS table base
///  [2]  LDR  X18, [X16, #0]       ; .Lloop: X18 = entry.tpidrro_el0
///  [3]  CMN  X18, #1              ; sentinel?
///  [4]  B.EQ .Ltrap               ; -> [17] (unknown thread = bug)
///  [5]  CMP  X18, X17             ; match tpidrro?
///  [6]  B.EQ .Lfound              ; -> [9]
///  [7]  ADD  X16, X16, #16        ; next entry
///  [8]  B    .Lloop               ; -> [2]
///  [9]  LDR  X16, [X16, #8]       ; .Lfound: X16 = host_tls (safe register!)
/// [10]  LDR  X17, [X16, #24]      ; X17 = TCB.guest_tpidr
/// [11]  STR  X17, [SP, #24]       ; frame.guest_tpidr = guest_tpidr
/// [12]  LDR  X17, [SP, #32]       ; X17 = guest x18 (saved by gate)
/// [13]  STR  X17, [X16, #40]      ; TCB.guest_x18 = guest x18
/// [14]  STR  X16, [SP, #40]       ; host_tls → frame slot for syscall_callback
/// [15]  LDR  X16, [PC, #off]      ; callback addr
/// [16]  BR   X16                  ; jump to callback
/// [17]  BRK  #1                   ; .Ltrap: unreachable (unknown thread)
/// ```
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_svc_handler_macos(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
    target_os: TargetOs,
) -> Result<()> {
    let handler_vaddr = trampoline_base_addr + handler_offset as u64;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { handler_vaddr + (idx as u64) * 4 };
    let tls_table_vaddr = trampoline_base_addr + HEADER_TLS_TABLE_OFFSET as u64;

    // [0] MRS X17, TPIDRRO_EL0 — stable per-thread key
    trampoline_data.extend_from_slice(&encode_mrs_tpidrro_el0(17).to_le_bytes());
    insn_idx += 1;

    // [1] LDR X16, [PC, #offset] — X16 = TLS table base
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let ldr_tls_offset = tls_table_vaddr.cast_signed() - ldr_tls_vaddr.cast_signed();
    let ldr_tls_insn = encode_ldr_literal(16, ldr_tls_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_tls_offset:#x} out of range for macOS shared SVC handler TLS load"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_tls_insn.to_le_bytes());
    insn_idx += 1;

    // [2] .Lloop: LDR X18, [X16, #0] — X18 = entry.tpidrro_el0
    let loop_idx = insn_idx;
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(18, 16, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [3] CMN X18, #1 — sentinel?
    trampoline_data.extend_from_slice(&encode_cmn_imm(18, 1).expect("imm12=1 fits").to_le_bytes());
    insn_idx += 1;

    // [4] B.EQ .Ltrap -> [17]
    let trap_idx = 17usize;
    let beq_trap_offset = (trap_idx as i64 - insn_idx as i64) * 4;
    let beq_trap = encode_b_cond(COND_EQ, beq_trap_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_trap_offset:#x} out of range in macOS shared SVC handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_trap.to_le_bytes());
    insn_idx += 1;

    // [5] CMP X18, X17 — match tpidrro?
    trampoline_data.extend_from_slice(&encode_cmp_reg(18, 17).to_le_bytes());
    insn_idx += 1;

    // [6] B.EQ .Lfound -> [9]
    let found_idx = 9usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_found_offset:#x} out of range in macOS shared SVC handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_found.to_le_bytes());
    insn_idx += 1;

    // [7] ADD X16, X16, #16 — next entry
    trampoline_data.extend_from_slice(
        &encode_add_imm(16, 16, 16)
            .expect("imm12=16 fits")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [8] B .Lloop -> [2]
    let b_loop_offset = (loop_idx as i64 - insn_idx as i64) * 4;
    let b_loop = encode_b(b_loop_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_loop_offset:#x} out of range in macOS shared SVC handler loop"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [9] .Lfound: LDR X16, [X16, #8] — X16 = host_tls (safe register, survives preemption)
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 16, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [10] LDR X17, [X16, #24] — X17 = TCB.guest_tpidr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 16, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [11] STR X17, [SP, #24] — frame.guest_tpidr = guest_tpidr
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(17, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [12] LDR X17, [SP, #32] — X17 = guest x18 (saved by gate at [SP+32])
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [13] STR X17, [X16, #40] — TCB.guest_x18 = guest x18
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(17, 16, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [14] STR X16, [SP, #40] — host_tls → frame slot for syscall_callback
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [15] LDR X16, [PC, #offset_to_callback]
    let ldr_cb_vaddr = insn_vaddr(insn_idx);
    let callback_vaddr = trampoline_base_addr + HEADER_CALLBACK_OFFSET as u64;
    let ldr_cb_offset = callback_vaddr.cast_signed() - ldr_cb_vaddr.cast_signed();
    let ldr_cb_insn = encode_ldr_literal(16, ldr_cb_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_cb_offset:#x} out of range for macOS shared SVC handler callback"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_cb_insn.to_le_bytes());
    insn_idx += 1;

    // [16] BR X16
    trampoline_data.extend_from_slice(&encode_br(16).to_le_bytes());
    insn_idx += 1;

    // [17] .Ltrap: BRK #1 — unreachable (unknown thread)
    debug_assert_eq!(insn_idx, trap_idx);
    trampoline_data.extend_from_slice(&encode_brk(1).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.shared_svc_handler_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        target_os.shared_svc_handler_size(),
        "macOS shared SVC handler size mismatch"
    );

    Ok(())
}

/// Emit a per-site SVC gate.
///
/// This gate saves registers, sets the return address, and branches to
/// the shared SVC handler.
/// Linux: 6 instructions, 24 bytes, 32-byte frame.
/// macOS: 7 instructions, 28 bytes, 48-byte frame (includes x18 save).
#[allow(clippy::cast_possible_wrap)]
fn emit_svc_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    target_os: TargetOs,
) -> Result<()> {
    match target_os {
        TargetOs::Linux | TargetOs::Windows => emit_svc_gate_linux(
            trampoline_data,
            gate_offset,
            trampoline_base_addr,
            site,
            target_os,
        ),
        TargetOs::MacOs => emit_svc_gate_macos(
            trampoline_data,
            gate_offset,
            trampoline_base_addr,
            site,
            target_os,
        ),
    }
}

/// Linux SVC gate: 6 instructions, 24 bytes, 32-byte frame.
#[allow(clippy::cast_possible_wrap)]
fn emit_svc_gate_linux(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    target_os: TargetOs,
) -> Result<()> {
    let gate_vaddr = trampoline_base_addr + gate_offset as u64;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { gate_vaddr + (idx as u64) * 4 };

    // [0] SUB SP, SP, #48  — 48-byte frame (was 32)
    //   [SP+0]  = saved X16
    //   [SP+8]  = saved X17
    //   [SP+16] = return address (PC after original SVC)
    //   [SP+24] = (used by shared SVC handler: first TPIDR, then host_tls)
    //   [SP+32] = guest's original X30 (LR)
    trampoline_data.extend_from_slice(&encode_sub_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
    insn_idx += 1;

    // [1] STP X16, X17, [SP]
    trampoline_data.extend_from_slice(
        &encode_stp_offset(16, 17, 31, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [2] STR X30, [SP, #32]  — save guest's original LR BEFORE we clobber X30
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [3] ADRP X30, <return_page>  — compute return address
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

    // [5] STR X30, [SP, #16]  — store return address
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 31, 16)
            .expect("offset 16 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [6] B <shared_svc_handler>
    let b_vaddr = insn_vaddr(insn_idx);
    let handler_vaddr = trampoline_base_addr + target_os.shared_svc_handler_offset() as u64;
    let b_offset = handler_vaddr.cast_signed() - b_vaddr.cast_signed();
    let b_insn = encode_b(b_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_offset:#x} out of range for SVC gate -> shared handler at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&b_insn.to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.svc_gate_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - gate_offset,
        target_os.svc_gate_size(),
        "SVC gate size mismatch"
    );

    Ok(())
}

/// macOS SVC gate: 7 instructions, 28 bytes, 48-byte frame (includes x18 save at [SP+32]).
///
/// ```text
/// [0] SUB  SP, SP, #48            ; 48-byte frame (was 32)
/// [1] STP  X16, X17, [SP]         ; save X16, X17
/// [2] STR  X30, [SP, #16]         ; save guest LR
/// [3] STR  X18, [SP, #32]         ; save guest x18 (NEW)
/// [4] ADRP X30, <return_page>     ; return addr high bits
/// [5] ADD  X30, X30, #<pageoff>   ; return addr low 12 bits
/// [6] B    <shared_svc_handler>   ; branch to shared handler
/// ```
#[allow(clippy::cast_possible_wrap)]
fn emit_svc_gate_macos(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    target_os: TargetOs,
) -> Result<()> {
    let gate_vaddr = trampoline_base_addr + gate_offset as u64;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { gate_vaddr + (idx as u64) * 4 };

    // [0] SUB SP, SP, #48 — 48-byte frame (includes x18 save slot)
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

    // [3] STR X18, [SP, #32] — save guest x18
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(18, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [4] ADRP X30, <return_page>
    let return_addr = site.vaddr + 4;
    let adrp_vaddr = insn_vaddr(insn_idx);
    let adrp_base = adrp_vaddr & !0xFFF;
    let return_page = return_addr & !0xFFF;
    let page_offset = (return_page as i64 - adrp_base as i64) >> 12;
    let adrp_insn = encode_adrp(30, page_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "ADRP page offset {page_offset:#x} out of ±4GB range for macOS SVC gate at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&adrp_insn.to_le_bytes());
    insn_idx += 1;

    // [5] ADD X30, X30, #<pageoff>
    let pageoff = (return_addr & 0xFFF) as u16;
    trampoline_data.extend_from_slice(
        &encode_add_imm(30, 30, pageoff)
            .expect("page offset fits in imm12")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [6] B <shared_svc_handler>
    let b_vaddr = insn_vaddr(insn_idx);
    let handler_vaddr = trampoline_base_addr + target_os.shared_svc_handler_offset() as u64;
    let b_offset = handler_vaddr.cast_signed() - b_vaddr.cast_signed();
    let b_insn = encode_b(b_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_offset:#x} out of range for macOS SVC gate -> shared handler at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&b_insn.to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.svc_gate_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - gate_offset,
        target_os.svc_gate_size(),
        "macOS SVC gate size mismatch"
    );

    Ok(())
}

/// Emit the shared MSR handler (19 instructions, 76 bytes).
///
/// This handler is shared by all MSR gates. It uses linear scan to find
/// the old TLS entry and updates it with the new guest TPIDR value, then
/// executes the actual MSR instruction.
///
/// On the sentinel path (no match found — e.g. macOS clobbered TPIDR_EL0),
/// the new guest_tpidr is written to entry\[0\] so that the SVC handler's
/// fallback path and the signal handler's fault-and-reinstall logic can
/// find the correct value.
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
    target_os: TargetOs,
) -> Result<()> {
    match target_os {
        TargetOs::Linux | TargetOs::Windows => emit_shared_msr_handler_linux(
            trampoline_data,
            handler_offset,
            trampoline_base_addr,
            target_os,
        ),
        TargetOs::MacOs => emit_shared_msr_handler_macos(
            trampoline_data,
            handler_offset,
            trampoline_base_addr,
            target_os,
        ),
    }
}

/// Linux shared MSR handler: TPIDR_EL0-keyed lookup, updates entry in-place.
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_msr_handler_linux(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
    target_os: TargetOs,
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

    // [5] B.EQ .Lsentinel -> [13]
    //
    // On the sentinel path (no existing entry matches the old TPIDR — e.g.,
    // macOS clobbered TPIDR_EL0 on signal delivery), we still write the new
    // guest_tpidr to entry[0] so that subsequent SVC handler fallback reads
    // and fault-and-reinstall logic can find the correct value.
    let sentinel_idx = 13usize;
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

    // [12] B .Lmsr -> [16] — skip sentinel path, go to MSR
    let msr_idx = 16usize;
    let b_msr_offset = (msr_idx as i64 - insn_idx as i64) * 4;
    let b_msr = encode_b(b_msr_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_msr_offset:#x} out of range in shared MSR handler found->msr"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_msr.to_le_bytes());
    insn_idx += 1;

    // [13] .Lsentinel: LDR X17, [PC, #offset] — reload TLS table base
    debug_assert_eq!(insn_idx, sentinel_idx);
    let sentinel_ldr_vaddr = insn_vaddr(insn_idx);
    let sentinel_ldr_offset = tls_table_vaddr.cast_signed() - sentinel_ldr_vaddr.cast_signed();
    let sentinel_ldr_insn =
        encode_ldr_literal(17, sentinel_ldr_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "LDR literal offset {sentinel_ldr_offset:#x} out of range for MSR handler sentinel TLS reload"
            ))
        })?;
    trampoline_data.extend_from_slice(&sentinel_ldr_insn.to_le_bytes());
    insn_idx += 1;

    // [14] LDR X16, [SP, #24] — new TPIDR
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [15] STR X16, [X17, #0] — write entry[0].guest_tpidr
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 17, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [16] .Lmsr: MSR TPIDR_EL0, X16
    debug_assert_eq!(insn_idx, msr_idx);
    trampoline_data.extend_from_slice(&encode_msr_tpidr_el0(16).to_le_bytes());
    insn_idx += 1;

    // [17] LDR X30, [SP, #32] — restore BL return addr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [18] RET
    trampoline_data.extend_from_slice(&encode_ret(30).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.shared_msr_handler_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        target_os.shared_msr_handler_size(),
        "Shared MSR handler size mismatch"
    );

    Ok(())
}

/// macOS shared MSR handler: TPIDRRO_EL0-keyed lookup, writes guest_tpidr to TCB.
///
/// Uses TPIDRRO_EL0 (stable per-pthread, never clobbered) as the TLS table lookup key.
/// On match: loads host_tls (TCB ptr), reads new guest_tpidr from [SP+24], writes to
/// TCB.guest_tpidr (offset 24), and also executes MSR TPIDR_EL0 for belt-and-suspenders.
/// On sentinel: BRK (unknown thread = bug).
///
/// ```text
///  [0]  STR  X30, [SP, #32]       ; save BL return addr
///  [1]  MRS  X16, TPIDRRO_EL0     ; stable lookup key
///  [2]  LDR  X17, [PC, #off]      ; X17 = TLS table base
///  [3]  LDR  X30, [X17, #0]       ; .Lloop: X30 = entry.tpidrro_el0
///  [4]  CMN  X30, #1              ; sentinel?
///  [5]  B.EQ .Ltrap               ; -> [16] (unknown thread = bug)
///  [6]  CMP  X30, X16             ; match tpidrro?
///  [7]  B.EQ .Lfound              ; -> [10]
///  [8]  ADD  X17, X17, #16        ; next entry
///  [9]  B    .Lloop               ; -> [3]
/// [10]  LDR  X17, [X17, #8]       ; .Lfound: X17 = host_tls (TCB ptr)
/// [11]  LDR  X16, [SP, #24]       ; X16 = new guest_tpidr (from gate)
/// [12]  STR  X16, [X17, #24]      ; TCB.guest_tpidr = new value
/// [13]  MSR  TPIDR_EL0, X16       ; set hardware register (best-effort)
/// [14]  LDR  X30, [SP, #32]       ; restore BL return addr
/// [15]  RET
/// [16]  BRK  #1                   ; .Ltrap: unreachable
/// ```
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_msr_handler_macos(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
    target_os: TargetOs,
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

    // [1] MRS X16, TPIDRRO_EL0 — stable lookup key
    trampoline_data.extend_from_slice(&encode_mrs_tpidrro_el0(16).to_le_bytes());
    insn_idx += 1;

    // [2] LDR X17, [PC, #offset] — X17 = TLS table base
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let ldr_tls_offset = tls_table_vaddr.cast_signed() - ldr_tls_vaddr.cast_signed();
    let ldr_tls_insn = encode_ldr_literal(17, ldr_tls_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_tls_offset:#x} out of range for macOS shared MSR handler TLS load"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_tls_insn.to_le_bytes());
    insn_idx += 1;

    // [3] .Lloop: LDR X30, [X17, #0] — X30 = entry.tpidrro_el0
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

    // [5] B.EQ .Ltrap -> [16]
    let trap_idx = 16usize;
    let beq_trap_offset = (trap_idx as i64 - insn_idx as i64) * 4;
    let beq_trap = encode_b_cond(COND_EQ, beq_trap_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_trap_offset:#x} out of range in macOS shared MSR handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_trap.to_le_bytes());
    insn_idx += 1;

    // [6] CMP X30, X16 — match tpidrro?
    trampoline_data.extend_from_slice(&encode_cmp_reg(30, 16).to_le_bytes());
    insn_idx += 1;

    // [7] B.EQ .Lfound -> [10]
    let found_idx = 10usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_found_offset:#x} out of range in macOS shared MSR handler"
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
            "B offset {b_loop_offset:#x} out of range in macOS shared MSR handler loop"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [10] .Lfound: LDR X17, [X17, #8] — X17 = host_tls (TCB ptr)
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 17, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [11] LDR X16, [SP, #24] — X16 = new guest_tpidr (from gate)
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [12] STR X16, [X17, #24] — TCB.guest_tpidr = new value
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 17, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [13] MSR TPIDR_EL0, X16 — set hardware register (best-effort)
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

    // [16] .Ltrap: BRK #1 — unreachable (unknown thread)
    debug_assert_eq!(insn_idx, trap_idx);
    trampoline_data.extend_from_slice(&encode_brk(1).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.shared_msr_handler_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        target_os.shared_msr_handler_size(),
        "macOS shared MSR handler size mismatch"
    );

    Ok(())
}

/// Emit the shared MRS handler (macOS only).
///
/// On Linux there is no shared MRS handler — the MRS gate reads entry[0].guest_tpidr
/// inline. On macOS/Windows the handler does a TLS table lookup (keyed by TPIDRRO_EL0
/// on macOS, TPIDR_EL0 on Windows) to find the correct TCB and loads guest_tpidr from
/// it into [SP+24] for the gate.
fn emit_shared_mrs_handler(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
    target_os: TargetOs,
) -> Result<()> {
    emit_shared_mrs_handler_tls_lookup(
        trampoline_data,
        handler_offset,
        trampoline_base_addr,
        target_os,
    )
}

/// Shared MRS handler with TLS table lookup.
///
/// Uses TPIDRRO_EL0 (macOS) or TPIDR_EL0 (Windows) as the TLS table lookup key.
/// On match: loads host_tls (TCB ptr), reads TCB.guest_tpidr (offset 24), stores to
/// [SP+24] for the gate to pick up. On sentinel: BRK (unknown thread = bug).
///
/// Called via BL from the per-site MRS gate. Gate uses a 48-byte frame with:
///   [SP+0..15] = saved X16, X17
///   [SP+16]    = saved X30 (guest LR)
///   [SP+24]    = output slot (guest_tpidr)
///   [SP+32]    = BL return address (saved by this handler)
///
/// ```text
///  [0]  STR  X30, [SP, #32]       ; save BL return addr
///  [1]  MRS  X16, TPIDRRO_EL0     ; stable lookup key
///  [2]  LDR  X17, [PC, #off]      ; X17 = TLS table base
///  [3]  LDR  X30, [X17, #0]       ; .Lloop: X30 = entry.tpidrro_el0
///  [4]  CMN  X30, #1              ; sentinel?
///  [5]  B.EQ .Ltrap               ; -> [15] (unknown thread = bug)
///  [6]  CMP  X30, X16             ; match tpidrro?
///  [7]  B.EQ .Lfound              ; -> [10]
///  [8]  ADD  X17, X17, #16        ; next entry
///  [9]  B    .Lloop               ; -> [3]
/// [10]  LDR  X17, [X17, #8]       ; .Lfound: X17 = host_tls (TCB ptr)
/// [11]  LDR  X16, [X17, #24]      ; X16 = TCB.guest_tpidr (offset 24)
/// [12]  STR  X16, [SP, #24]       ; frame[24] = guest_tpidr for gate
/// [13]  LDR  X30, [SP, #32]       ; restore BL return addr
/// [14]  RET
/// [15]  BRK  #1                   ; .Ltrap: unreachable
/// ```
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_mrs_handler_tls_lookup(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
    target_os: TargetOs,
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

    // [1] MRS X16, TPIDRRO_EL0 (macOS) or MRS X16, TPIDR_EL0 (Windows) — lookup key
    if target_os.is_macos() {
        trampoline_data.extend_from_slice(&encode_mrs_tpidrro_el0(16).to_le_bytes());
    } else {
        trampoline_data.extend_from_slice(&encode_mrs_tpidr_el0(16).to_le_bytes());
    }
    insn_idx += 1;

    // [2] LDR X17, [PC, #offset] — X17 = TLS table base
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let ldr_tls_offset = tls_table_vaddr.cast_signed() - ldr_tls_vaddr.cast_signed();
    let ldr_tls_insn = encode_ldr_literal(17, ldr_tls_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_tls_offset:#x} out of range for shared MRS handler TLS load"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_tls_insn.to_le_bytes());
    insn_idx += 1;

    // [3] .Lloop: LDR X30, [X17, #0] — X30 = entry.tpidrro_el0
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

    // [5] B.EQ .Ltrap -> [15]
    let trap_idx = 15usize;
    let beq_trap_offset = (trap_idx as i64 - insn_idx as i64) * 4;
    let beq_trap = encode_b_cond(COND_EQ, beq_trap_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_trap_offset:#x} out of range in macOS shared MRS handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_trap.to_le_bytes());
    insn_idx += 1;

    // [6] CMP X30, X16 — match tpidrro?
    trampoline_data.extend_from_slice(&encode_cmp_reg(30, 16).to_le_bytes());
    insn_idx += 1;

    // [7] B.EQ .Lfound -> [10]
    let found_idx = 10usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_found_offset:#x} out of range in macOS shared MRS handler"
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
            "B offset {b_loop_offset:#x} out of range in macOS shared MRS handler loop"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [10] .Lfound: LDR X17, [X17, #8] — X17 = host_tls (TCB ptr)
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 17, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [11] LDR X16, [X17, #24] — X16 = TCB.guest_tpidr (offset 24)
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 17, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [12] STR X16, [SP, #24] — frame[24] = guest_tpidr for gate to pick up
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [13] LDR X30, [SP, #32] — restore BL return addr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [14] RET
    trampoline_data.extend_from_slice(&encode_ret(30).to_le_bytes());
    insn_idx += 1;

    // [15] .Ltrap: BRK #1 — unreachable (unknown thread)
    debug_assert_eq!(insn_idx, trap_idx);
    trampoline_data.extend_from_slice(&encode_brk(1).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.shared_mrs_handler_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        target_os.shared_mrs_handler_size(),
        "macOS shared MRS handler size mismatch"
    );

    Ok(())
}

/// macOS shared x18 load handler: TPIDRRO_EL0-keyed lookup, reads guest_x18 from TCB.
///
/// Same TPIDRRO_EL0 scan pattern as the MRS handler, but reads TCB offset 40 (guest_x18)
/// instead of offset 24 (guest_tpidr). Stores the loaded value to [SP+24] for the gate.
///
/// Called via BL from the per-site x18 gate (read case). Gate uses a 48-byte frame with:
///   [SP+0]  = X16, [SP+8] = X17, [SP+16] = X30 (guest LR), [SP+24] = transfer slot,
///   [SP+32] = BL return addr (saved/restored by this handler).
///
/// ```text
///  [0]  STR  X30, [SP, #32]         ; save BL return addr
///  [1]  MRS  X16, TPIDRRO_EL0       ; stable key
///  [2]  LDR  X17, [PC, #off]        ; X17 = TLS table base
///  [3]  LDR  X30, [X17, #0]         ; .Lloop: X30 = entry.tpidrro
///  [4]  CMN  X30, #1                ; sentinel?
///  [5]  B.EQ .Ltrap                 ; -> [15]
///  [6]  CMP  X30, X16               ; match?
///  [7]  B.EQ .Lfound                ; -> [10]
///  [8]  ADD  X17, X17, #16          ; next entry
///  [9]  B    .Lloop                 ; -> [3]
/// [10]  LDR  X17, [X17, #8]         ; .Lfound: X17 = host_tls (TCB ptr)
/// [11]  LDR  X16, [X17, #40]        ; X16 = TCB.guest_x18 (offset 40)
/// [12]  STR  X16, [SP, #24]         ; frame[24] = guest_x18 for gate to pick up
/// [13]  LDR  X30, [SP, #32]         ; restore BL return addr
/// [14]  RET
/// [15]  BRK  #1                     ; trap
/// ```
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_x18_load_handler(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
    target_os: TargetOs,
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

    // [1] MRS X16, TPIDRRO_EL0 (macOS) or MRS X16, TPIDR_EL0 (Windows) — lookup key
    if target_os.is_macos() {
        trampoline_data.extend_from_slice(&encode_mrs_tpidrro_el0(16).to_le_bytes());
    } else {
        trampoline_data.extend_from_slice(&encode_mrs_tpidr_el0(16).to_le_bytes());
    }
    insn_idx += 1;

    // [2] LDR X17, [PC, #offset] — X17 = TLS table base
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let ldr_tls_offset = tls_table_vaddr.cast_signed() - ldr_tls_vaddr.cast_signed();
    let ldr_tls_insn = encode_ldr_literal(17, ldr_tls_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_tls_offset:#x} out of range for shared x18 load handler TLS load"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_tls_insn.to_le_bytes());
    insn_idx += 1;

    // [3] .Lloop: LDR X30, [X17, #0] — X30 = entry.tpidrro_el0
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

    // [5] B.EQ .Ltrap -> [15]
    let trap_idx = 15usize;
    let beq_trap_offset = (trap_idx as i64 - insn_idx as i64) * 4;
    let beq_trap = encode_b_cond(COND_EQ, beq_trap_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_trap_offset:#x} out of range in macOS shared x18 load handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_trap.to_le_bytes());
    insn_idx += 1;

    // [6] CMP X30, X16 — match tpidrro?
    trampoline_data.extend_from_slice(&encode_cmp_reg(30, 16).to_le_bytes());
    insn_idx += 1;

    // [7] B.EQ .Lfound -> [10]
    let found_idx = 10usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_found_offset:#x} out of range in macOS shared x18 load handler"
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
            "B offset {b_loop_offset:#x} out of range in macOS shared x18 load handler loop"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [10] .Lfound: LDR X17, [X17, #8] — X17 = host_tls (TCB ptr)
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 17, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [11] LDR X16, [X17, #40] — X16 = TCB.guest_x18 (offset 40)
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 17, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [12] STR X16, [SP, #24] — frame[24] = guest_x18 for gate to pick up
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [13] LDR X30, [SP, #32] — restore BL return addr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [14] RET
    trampoline_data.extend_from_slice(&encode_ret(30).to_le_bytes());
    insn_idx += 1;

    // [15] .Ltrap: BRK #1 — unreachable (unknown thread)
    debug_assert_eq!(insn_idx, trap_idx);
    trampoline_data.extend_from_slice(&encode_brk(1).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.shared_x18_load_handler_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        target_os.shared_x18_load_handler_size(),
        "macOS shared x18 load handler size mismatch"
    );

    Ok(())
}

/// macOS shared x18 save handler: reads [SP+24] and stores to TCB.guest_x18.
///
/// Same TPIDRRO_EL0 scan pattern as the load handler, but reads the new x18 value
/// from [SP+24] and writes it to TCB offset 40 (guest_x18).
///
/// Called via BL from the per-site x18 gate (write case). Gate uses the same 48-byte frame.
///
/// ```text
///  [0]  STR  X30, [SP, #32]         ; save BL return addr
///  [1]  MRS  X16, TPIDRRO_EL0       ; stable key
///  [2]  LDR  X17, [PC, #off]        ; X17 = TLS table base
///  [3]  LDR  X30, [X17, #0]         ; .Lloop: X30 = entry.tpidrro
///  [4]  CMN  X30, #1                ; sentinel?
///  [5]  B.EQ .Ltrap                 ; -> [15]
///  [6]  CMP  X30, X16               ; match?
///  [7]  B.EQ .Lfound                ; -> [10]
///  [8]  ADD  X17, X17, #16          ; next entry
///  [9]  B    .Lloop                 ; -> [3]
/// [10]  LDR  X17, [X17, #8]         ; .Lfound: X17 = host_tls (TCB ptr)
/// [11]  LDR  X16, [SP, #24]         ; X16 = new guest_x18 value (from gate)
/// [12]  STR  X16, [X17, #40]        ; TCB.guest_x18 = new value (offset 40)
/// [13]  LDR  X30, [SP, #32]         ; restore BL return addr
/// [14]  RET
/// [15]  BRK  #1                     ; trap
/// ```
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_x18_save_handler(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
    target_os: TargetOs,
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

    // [1] MRS X16, TPIDRRO_EL0 (macOS) or MRS X16, TPIDR_EL0 (Windows) — lookup key
    if target_os.is_macos() {
        trampoline_data.extend_from_slice(&encode_mrs_tpidrro_el0(16).to_le_bytes());
    } else {
        trampoline_data.extend_from_slice(&encode_mrs_tpidr_el0(16).to_le_bytes());
    }
    insn_idx += 1;

    // [2] LDR X17, [PC, #offset] — X17 = TLS table base
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let ldr_tls_offset = tls_table_vaddr.cast_signed() - ldr_tls_vaddr.cast_signed();
    let ldr_tls_insn = encode_ldr_literal(17, ldr_tls_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_tls_offset:#x} out of range for shared x18 save handler TLS load"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_tls_insn.to_le_bytes());
    insn_idx += 1;

    // [3] .Lloop: LDR X30, [X17, #0] — X30 = entry.tpidrro_el0
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

    // [5] B.EQ .Ltrap -> [15]
    let trap_idx = 15usize;
    let beq_trap_offset = (trap_idx as i64 - insn_idx as i64) * 4;
    let beq_trap = encode_b_cond(COND_EQ, beq_trap_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_trap_offset:#x} out of range in macOS shared x18 save handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_trap.to_le_bytes());
    insn_idx += 1;

    // [6] CMP X30, X16 — match tpidrro?
    trampoline_data.extend_from_slice(&encode_cmp_reg(30, 16).to_le_bytes());
    insn_idx += 1;

    // [7] B.EQ .Lfound -> [10]
    let found_idx = 10usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_found_offset:#x} out of range in macOS shared x18 save handler"
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
            "B offset {b_loop_offset:#x} out of range in macOS shared x18 save handler loop"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [10] .Lfound: LDR X17, [X17, #8] — X17 = host_tls (TCB ptr)
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 17, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [11] LDR X16, [SP, #24] — X16 = new guest_x18 value (from gate)
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [12] STR X16, [X17, #40] — TCB.guest_x18 = new value (offset 40)
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 17, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [13] LDR X30, [SP, #32] — restore BL return addr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [14] RET
    trampoline_data.extend_from_slice(&encode_ret(30).to_le_bytes());
    insn_idx += 1;

    // [15] .Ltrap: BRK #1 — unreachable (unknown thread)
    debug_assert_eq!(insn_idx, trap_idx);
    trampoline_data.extend_from_slice(&encode_brk(1).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.shared_x18_save_handler_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        target_os.shared_x18_save_handler_size(),
        "macOS shared x18 save handler size mismatch"
    );

    Ok(())
}

/// Emit a per-site x18 gate for instructions that reference x18 (macOS only).
///
/// Saves/restores NZCV condition flags so that the shared handler's CMP/CMN
/// instructions don't clobber guest condition flags (critical for correct
/// conditional branch behavior after x18-referencing instructions).
///
/// Depending on whether x18 is read, written, or both, the gate layout varies:
///
/// **x18-read-only** (14 insns / 56 bytes):
/// ```text
///  [0] SUB  SP, SP, #48
///  [1] STP  X16, X17, [SP]
///  [2] STR  X30, [SP, #16]
///  [3] MRS  X16, NZCV              ; save condition flags
///  [4] STR  X16, [SP, #40]         ; store NZCV to frame
///  [5] BL   <shared_x18_load>      ; writes guest_x18 to [SP+24], clobbers NZCV
///  [6] LDR  X16, [SP, #40]         ; reload saved NZCV
///  [7] MSR  NZCV, X16              ; restore flags BEFORE guest instruction
///  [8] LDR  Xscratch, [SP, #24]   ; scratch = guest_x18
///  [9] <rewritten instruction>      ; flag output survives to caller
/// [10] LDP  X16, X17, [SP]
/// [11] LDR  X30, [SP, #16]
/// [12] ADD  SP, SP, #48
/// [13] B    <return_addr>
/// ```
///
/// **x18-write-only** (14 insns / 56 bytes):
/// ```text
///  [0] SUB  SP, SP, #48
///  [1] STP  X16, X17, [SP]
///  [2] STR  X30, [SP, #16]
///  [3] MRS  X16, NZCV              ; save condition flags
///  [4] STR  X16, [SP, #40]         ; store NZCV to frame
///  [5] LDR  X16, [SP, #40]         ; reload saved NZCV
///  [6] MSR  NZCV, X16              ; restore flags BEFORE guest instruction
///  [7] <rewritten instruction>      ; flag output survives
///  [8] STR  Xscratch, [SP, #24]
///  [9] BL   <shared_x18_save>
/// [10] LDP  X16, X17, [SP]
/// [11] LDR  X30, [SP, #16]
/// [12] ADD  SP, SP, #48
/// [13] B    <return_addr>
/// ```
///
/// **x18-read-write** (16 insns / 64 bytes):
/// ```text
///  [0]  SUB  SP, SP, #48
///  [1]  STP  X16, X17, [SP]
///  [2]  STR  X30, [SP, #16]
///  [3]  MRS  X16, NZCV             ; save condition flags
///  [4]  STR  X16, [SP, #40]        ; store NZCV to frame
///  [5]  BL   <shared_x18_load>     ; clobbers NZCV
///  [6]  LDR  X16, [SP, #40]        ; reload saved NZCV
///  [7]  MSR  NZCV, X16             ; restore flags BEFORE guest instruction
///  [8]  LDR  Xscratch, [SP, #24]
///  [9]  <rewritten instruction>     ; flag output survives
/// [10]  STR  Xscratch, [SP, #24]
/// [11]  BL   <shared_x18_save>
/// [12]  LDP  X16, X17, [SP]
/// [13]  LDR  X30, [SP, #16]
/// [14]  ADD  SP, SP, #48
/// [15]  B    <return_addr>
/// ```
#[allow(clippy::cast_possible_wrap, clippy::too_many_arguments)]
fn emit_x18_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rewritten: u32,
    scratch: u8,
    is_read: bool,
    is_write: bool,
    sp_fixup: bool,
    target_os: TargetOs,
) -> Result<()> {
    let gate_vaddr = trampoline_base_addr + gate_offset as u64;
    let gate_size = x18_gate_size(target_os, is_read, is_write, sp_fixup);
    let gate_insn_count = gate_size / 4;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { gate_vaddr + (idx as u64) * 4 };

    // Adjust SP-relative offset: the gate pushes a 48-byte frame, so any instruction
    // that uses SP as a base register for memory access needs its immediate offset
    // increased by 48 to access the original (caller's) stack location.
    //
    // There are two strategies:
    // 1. Immediate adjustment: modify the instruction's offset field (+48). Used when
    //    the adjusted value fits in the instruction's immediate encoding.
    // 2. SP restore: when the adjusted offset overflows (sp_fixup=true), we instead
    //    restore SP before the instruction and re-push after:
    //      ADD SP, SP, #48   ; restore caller's SP
    //      <original insn>   ; accesses correct stack location
    //      SUB SP, SP, #48   ; re-push gate frame
    //    This adds 2 instructions to the gate.
    //
    // `adjust_sp_relative_offset` returns `None` for non-memory instructions (ADD, SUB,
    // CMP, etc.) even if they have Rn=SP, since it only matches load/store opcodes.
    let rn = (rewritten >> 5) & 0x1F;
    let rewritten = if rn == 31 && !sp_fixup {
        // Try immediate adjustment (non-sp_fixup path)
        match adjust_sp_relative_offset(rewritten, 48) {
            Some(adjusted) => adjusted,
            None => {
                // Not a memory op (ADD, CMP, etc. with Rn=SP) — use as-is
                rewritten
            }
        }
    } else {
        // Either not SP-relative, or sp_fixup mode (instruction used unchanged,
        // SP is restored around it)
        rewritten
    };

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

    // [3] MRS X16, NZCV — save condition flags before BL to shared handler
    trampoline_data.extend_from_slice(&encode_mrs_nzcv(16).to_le_bytes());
    insn_idx += 1;

    // [4] STR X16, [SP, #40] — store NZCV value to unused frame slot
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    if is_read && is_write {
        // Read-write path: load, restore NZCV, execute, save

        // [5] BL <shared_x18_load>
        let bl_vaddr = insn_vaddr(insn_idx);
        let load_handler_vaddr =
            trampoline_base_addr + target_os.shared_x18_load_handler_offset() as u64;
        let bl_offset = load_handler_vaddr.cast_signed() - bl_vaddr.cast_signed();
        let bl_insn = encode_bl(bl_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "BL offset {bl_offset:#x} out of range for x18 gate -> shared x18 load handler at {:#x}",
                site.vaddr
            ))
        })?;
        trampoline_data.extend_from_slice(&bl_insn.to_le_bytes());
        insn_idx += 1;

        // [6] LDR X16, [SP, #40] — reload saved NZCV (before guest instruction)
        trampoline_data.extend_from_slice(
            &encode_ldr_imm_unsigned(16, 31, 40)
                .expect("offset 40 valid")
                .to_le_bytes(),
        );
        insn_idx += 1;

        // [7] MSR NZCV, X16 — restore condition flags (before guest instruction)
        trampoline_data.extend_from_slice(&encode_msr_nzcv(16).to_le_bytes());
        insn_idx += 1;

        // [8] LDR Xscratch, [SP, #24]
        trampoline_data.extend_from_slice(
            &encode_ldr_imm_unsigned(scratch, 31, 24)
                .expect("offset 24 valid")
                .to_le_bytes(),
        );
        insn_idx += 1;

        // [9] <rewritten instruction> (possibly wrapped with SP restore/re-push)
        if sp_fixup {
            // ADD SP, SP, #48 — restore caller's SP
            trampoline_data
                .extend_from_slice(&encode_add_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
            insn_idx += 1;
        }
        trampoline_data.extend_from_slice(&rewritten.to_le_bytes());
        insn_idx += 1;
        if sp_fixup {
            // SUB SP, SP, #48 — re-push gate frame
            trampoline_data
                .extend_from_slice(&encode_sub_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
            insn_idx += 1;
        }

        // [10/12] STR Xscratch, [SP, #24]
        trampoline_data.extend_from_slice(
            &encode_str_imm_unsigned(scratch, 31, 24)
                .expect("offset 24 valid")
                .to_le_bytes(),
        );
        insn_idx += 1;

        // [11/13] BL <shared_x18_save>
        let bl_vaddr = insn_vaddr(insn_idx);
        let save_handler_vaddr =
            trampoline_base_addr + target_os.shared_x18_save_handler_offset() as u64;
        let bl_offset = save_handler_vaddr.cast_signed() - bl_vaddr.cast_signed();
        let bl_insn = encode_bl(bl_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "BL offset {bl_offset:#x} out of range for x18 gate -> shared x18 save handler at {:#x}",
                site.vaddr
            ))
        })?;
        trampoline_data.extend_from_slice(&bl_insn.to_le_bytes());
        insn_idx += 1;
    } else if is_read {
        // Read-only path: load, restore NZCV, execute

        // [5] BL <shared_x18_load>
        let bl_vaddr = insn_vaddr(insn_idx);
        let load_handler_vaddr =
            trampoline_base_addr + target_os.shared_x18_load_handler_offset() as u64;
        let bl_offset = load_handler_vaddr.cast_signed() - bl_vaddr.cast_signed();
        let bl_insn = encode_bl(bl_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "BL offset {bl_offset:#x} out of range for x18 gate -> shared x18 load handler at {:#x}",
                site.vaddr
            ))
        })?;
        trampoline_data.extend_from_slice(&bl_insn.to_le_bytes());
        insn_idx += 1;

        // [6] LDR X16, [SP, #40] — reload saved NZCV (before guest instruction)
        trampoline_data.extend_from_slice(
            &encode_ldr_imm_unsigned(16, 31, 40)
                .expect("offset 40 valid")
                .to_le_bytes(),
        );
        insn_idx += 1;

        // [7] MSR NZCV, X16 — restore condition flags (before guest instruction)
        trampoline_data.extend_from_slice(&encode_msr_nzcv(16).to_le_bytes());
        insn_idx += 1;

        // [8] LDR Xscratch, [SP, #24]
        trampoline_data.extend_from_slice(
            &encode_ldr_imm_unsigned(scratch, 31, 24)
                .expect("offset 24 valid")
                .to_le_bytes(),
        );
        insn_idx += 1;

        // [9] <rewritten instruction> (possibly wrapped with SP restore/re-push)
        if sp_fixup {
            trampoline_data
                .extend_from_slice(&encode_add_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
            insn_idx += 1;
        }
        trampoline_data.extend_from_slice(&rewritten.to_le_bytes());
        insn_idx += 1;
        if sp_fixup {
            trampoline_data
                .extend_from_slice(&encode_sub_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
            insn_idx += 1;
        }
    } else {
        // Write-only path: restore NZCV, execute, save

        // [5] LDR X16, [SP, #40] — reload saved NZCV (before guest instruction)
        trampoline_data.extend_from_slice(
            &encode_ldr_imm_unsigned(16, 31, 40)
                .expect("offset 40 valid")
                .to_le_bytes(),
        );
        insn_idx += 1;

        // [6] MSR NZCV, X16 — restore condition flags (before guest instruction)
        trampoline_data.extend_from_slice(&encode_msr_nzcv(16).to_le_bytes());
        insn_idx += 1;

        // [7] <rewritten instruction> (possibly wrapped with SP restore/re-push)
        if sp_fixup {
            trampoline_data
                .extend_from_slice(&encode_add_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
            insn_idx += 1;
        }
        trampoline_data.extend_from_slice(&rewritten.to_le_bytes());
        insn_idx += 1;
        if sp_fixup {
            trampoline_data
                .extend_from_slice(&encode_sub_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
            insn_idx += 1;
        }

        // [8/10] STR Xscratch, [SP, #24]
        trampoline_data.extend_from_slice(
            &encode_str_imm_unsigned(scratch, 31, 24)
                .expect("offset 24 valid")
                .to_le_bytes(),
        );
        insn_idx += 1;

        // [9/11] BL <shared_x18_save>
        let bl_vaddr = insn_vaddr(insn_idx);
        let save_handler_vaddr =
            trampoline_base_addr + target_os.shared_x18_save_handler_offset() as u64;
        let bl_offset = save_handler_vaddr.cast_signed() - bl_vaddr.cast_signed();
        let bl_insn = encode_bl(bl_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "BL offset {bl_offset:#x} out of range for x18 gate -> shared x18 save handler at {:#x}",
                site.vaddr
            ))
        })?;
        trampoline_data.extend_from_slice(&bl_insn.to_le_bytes());
        insn_idx += 1;
    }

    // Epilogue (common to all paths) — NZCV already restored before guest instruction

    // LDP X16, X17, [SP]
    trampoline_data.extend_from_slice(
        &encode_ldp_offset(16, 17, 31, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // LDR X30, [SP, #16]
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 16)
            .expect("offset 16 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // ADD SP, SP, #48
    trampoline_data.extend_from_slice(&encode_add_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
    insn_idx += 1;

    // B <return_addr>
    let ret_vaddr = insn_vaddr(insn_idx);
    let ret_offset = (site.vaddr + 4).cast_signed() - ret_vaddr.cast_signed();
    let ret_insn = encode_b(ret_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {ret_offset:#x} out of ±128MB range for return from x18 gate at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&ret_insn.to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, gate_insn_count);
    debug_assert_eq!(
        trampoline_data.len() - gate_offset,
        gate_size,
        "x18 gate size mismatch"
    );

    Ok(())
}

///
/// Special registers (X16, X17, X30) need an extra instruction to reload
/// the saved value before storing to `[SP, #24]`.
/// Linux: general 36 bytes, special 40 bytes.
/// macOS: general 52 bytes, special 56 bytes.
fn msr_gate_size(target_os: TargetOs, rt: u8) -> usize {
    target_os.msr_gate_size_for_rt(rt)
}

/// Emit a per-site MSR gate.
///
/// On Linux: 9-10 instructions (36-40 bytes), no NZCV save/restore.
/// On macOS: 13-14 instructions (52-56 bytes), with NZCV save/restore.
///
/// This gate saves registers, stores the new TPIDR value, calls the shared
/// MSR handler via BL, restores registers, and branches back to guest code.
fn emit_msr_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rt: u8,
    target_os: TargetOs,
) -> Result<()> {
    match target_os {
        TargetOs::Linux | TargetOs::Windows => emit_msr_gate_linux(
            trampoline_data,
            gate_offset,
            trampoline_base_addr,
            site,
            rt,
            target_os,
        ),
        TargetOs::MacOs => emit_msr_gate_macos(
            trampoline_data,
            gate_offset,
            trampoline_base_addr,
            site,
            rt,
            target_os,
        ),
    }
}

/// Linux MSR gate: 9-10 instructions, 36-40 bytes, no NZCV save/restore.
#[allow(clippy::cast_possible_wrap)]
fn emit_msr_gate_linux(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rt: u8,
    target_os: TargetOs,
) -> Result<()> {
    let gate_vaddr = trampoline_base_addr + gate_offset as u64;
    let gate_size = msr_gate_size(target_os, rt);
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
    let handler_vaddr = trampoline_base_addr + target_os.shared_msr_handler_offset() as u64;
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

/// macOS MSR gate: 13-14 instructions (52-56 bytes), with NZCV save/restore.
///
/// Same structure as Linux MSR gate but with NZCV condition flags saved/restored
/// around the BL to the shared handler, preventing flag clobbering from the
/// handler's CMP/CMN instructions during TLS table lookup.
///
/// **General case (Xt ∉ {X16, X17, X30}):**
/// ```text
///  [0]  SUB  SP, SP, #48           ; 48-byte frame
///  [1]  STP  X16, X17, [SP]        ; save X16, X17
///  [2]  STR  X30, [SP, #16]        ; save guest LR
///  [3]  MRS  X16, NZCV             ; save condition flags
///  [4]  STR  X16, [SP, #40]        ; store NZCV to frame
///  [5]  STR  Xt,  [SP, #24]        ; store new TPIDR value
///  [6]  BL   shared_msr_handler    ; call shared handler
///  [7]  LDR  X16, [SP, #40]        ; reload NZCV
///  [8]  MSR  NZCV, X16             ; restore condition flags
///  [9]  LDP  X16, X17, [SP]        ; restore X16, X17
/// [10]  LDR  X30, [SP, #16]        ; restore guest LR
/// [11]  ADD  SP, SP, #48           ; deallocate frame
/// [12]  B    <return_addr>          ; branch back
/// ```
///
/// Special register cases (X16, X17, X30) use 14 instructions (56 bytes).
#[allow(clippy::cast_possible_wrap)]
fn emit_msr_gate_macos(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rt: u8,
    target_os: TargetOs,
) -> Result<()> {
    let gate_vaddr = trampoline_base_addr + gate_offset as u64;
    let gate_size = msr_gate_size(target_os, rt);
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

    // [3] MRS X16, NZCV — save condition flags
    trampoline_data.extend_from_slice(&encode_mrs_nzcv(16).to_le_bytes());
    insn_idx += 1;

    // [4] STR X16, [SP, #40] — store NZCV value to frame
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [5] (or [5]-[6] for special regs) Store the new TPIDR value to [SP, #24]
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
    let handler_vaddr = trampoline_base_addr + target_os.shared_msr_handler_offset() as u64;
    let bl_offset = handler_vaddr.cast_signed() - bl_vaddr.cast_signed();
    let bl_insn = encode_bl(bl_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "BL offset {bl_offset:#x} out of range for MSR gate -> shared handler at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&bl_insn.to_le_bytes());
    insn_idx += 1;

    // [next] LDR X16, [SP, #40] — reload saved NZCV value
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 31, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [next] MSR NZCV, X16 — restore condition flags
    trampoline_data.extend_from_slice(&encode_msr_nzcv(16).to_le_bytes());
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

/// Emit a per-site MRS gate for `MRS Xd, TPIDR_EL0`.
///
/// On Linux: inline TLS table read (5 instructions, 20 bytes).
/// On macOS: BL to shared MRS handler (9 instructions, 36 bytes, 48-byte frame).
fn emit_mrs_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rd: u8,
    target_os: TargetOs,
) -> Result<()> {
    match target_os {
        TargetOs::Linux => emit_mrs_gate_linux(
            trampoline_data,
            gate_offset,
            trampoline_base_addr,
            site,
            rd,
            target_os,
        ),
        TargetOs::Windows => emit_mrs_gate_windows(
            trampoline_data,
            gate_offset,
            trampoline_base_addr,
            site,
            rd,
            target_os,
        ),
        TargetOs::MacOs => emit_mrs_gate_macos(
            trampoline_data,
            gate_offset,
            trampoline_base_addr,
            site,
            rd,
            target_os,
        ),
    }
}

/// Windows MRS gate: TEB-based TlsState lookup, 11 instructions / 44 bytes.
///
/// On Windows ARM64, the kernel does NOT preserve `TPIDR_EL0` across context
/// switches, so reading the hardware register directly returns stale values.
/// Instead, the gate reads `TlsState.guest_tpidr` via the TEB (X18), which
/// Windows guarantees is always valid.
///
/// Access path: `X18 (TEB) → [X18 + TEB_TLS_SLOT_OFFSET] → TlsState* → guest_tpidr`
///
/// The precomputed `TEB_TLS_SLOT_OFFSET` (= `TEB_TLS_SLOTS_OFFSET + TLS_INDEX*8`)
/// is stored in the trampoline header at offset 16 (`HEADER_TEB_TLS_OFFSET`).
///
/// A NULL fallback reads `entry[0].guest_tpidr` from the TLS table (header+8)
/// for early execution before TlsState is registered in the TEB slot (e.g.,
/// during rtld_audit's `do_syscall` before `run_thread` runs).
///
/// **General case (Xd ∉ {X16, X17}):**
/// ```text
/// [0]  STP  X16, X17, [SP, #-16]!    ; save scratch
/// [1]  LDR  X16, [PC, #off_teb]      ; X16 = TEB_TLS_SLOT_OFFSET (from header+16)
/// [2]  LDR  X16, [X18, X16]          ; X16 = TlsState* (from TEB TLS slot)
/// [3]  CBZ  X16, .Lfallback          ; NULL → fallback to entry[0]
/// [4]  LDR  Xd,  [X16, #64]          ; Xd = TlsState.guest_tpidr
/// [5]  LDP  X16, X17, [SP], #16      ; restore scratch
/// [6]  B    <return_addr>
/// .Lfallback:
/// [7]  LDR  X16, [PC, #off_tls]      ; X16 = TLS table address (from header+8)
/// [8]  LDR  Xd,  [X16, #0]           ; Xd = entry[0].guest_tpidr
/// [9]  LDP  X16, X17, [SP], #16      ; restore scratch
/// [10] B    <return_addr>
/// ```
///
/// The `guest_tpidr` field offset (64) must match
/// `core::mem::offset_of!(TlsState, guest_tpidr)` in the platform crate.
const TLSSTATE_GUEST_TPIDR_OFFSET: u16 = 64;

#[allow(clippy::cast_possible_wrap)]
fn emit_mrs_gate_windows(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rd: u8,
    target_os: TargetOs,
) -> Result<()> {
    let gate_vaddr = trampoline_base_addr + gate_offset as u64;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { gate_vaddr + (idx as u64) * 4 };

    let teb_offset_vaddr = trampoline_base_addr + HEADER_TEB_TLS_OFFSET as u64;
    let tls_table_vaddr = trampoline_base_addr + HEADER_TLS_TABLE_OFFSET as u64;

    // Determine scratch register usage based on destination register.
    // When Xd is X16 or X17, we use the other as the sole scratch.
    let (save_scratch, restore_scratch, scratch) = match rd {
        16 => (
            // [0] STR X17, [SP, #-16]!
            encode_str_pre_index(17, 31, -16).unwrap(),
            // restore: LDR X17, [SP], #16
            encode_ldr_post_index(17, 31, 16).unwrap(),
            17u8,
        ),
        17 => (
            // [0] STR X16, [SP, #-16]!
            encode_str_pre_index(16, 31, -16).unwrap(),
            // restore: LDR X16, [SP], #16
            encode_ldr_post_index(16, 31, 16).unwrap(),
            16u8,
        ),
        _ => (
            // [0] STP X16, X17, [SP, #-16]!
            encode_stp_pre_index(16, 17, 31, -16).unwrap(),
            // restore: LDP X16, X17, [SP], #16
            encode_ldp_post_index(16, 17, 31, 16).unwrap(),
            16u8,
        ),
    };

    // [0] Save scratch register(s)
    trampoline_data.extend_from_slice(&save_scratch.to_le_bytes());
    insn_idx += 1;

    // [1] LDR Xscratch, [PC, #off_teb] — load TEB TLS slot offset from header+16
    let ldr_vaddr = insn_vaddr(insn_idx);
    let ldr_offset = teb_offset_vaddr.cast_signed() - ldr_vaddr.cast_signed();
    let ldr_insn = encode_ldr_literal(scratch, ldr_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_offset:#x} out of range for Windows MRS gate TEB load at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_insn.to_le_bytes());
    insn_idx += 1;

    // [2] LDR Xscratch, [X18, Xscratch] — load TlsState* from TEB TLS slot
    trampoline_data.extend_from_slice(&encode_ldr_reg_offset(scratch, 18, scratch).to_le_bytes());
    insn_idx += 1;

    // [3] CBZ Xscratch, .Lfallback — NULL check (fallback is at instruction [7])
    let cbz_offset: i64 = (7 - insn_idx as i64) * 4; // jump forward to [7]
    let cbz_insn = encode_cbz(scratch, cbz_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "CBZ offset {cbz_offset:#x} out of range for Windows MRS gate at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&cbz_insn.to_le_bytes());
    insn_idx += 1;

    // [4] LDR Xd, [Xscratch, #TLSSTATE_GUEST_TPIDR_OFFSET] — read guest_tpidr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(rd, scratch, TLSSTATE_GUEST_TPIDR_OFFSET)
            .expect("offset 64 valid for LDR imm")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [5] Restore scratch register(s)
    trampoline_data.extend_from_slice(&restore_scratch.to_le_bytes());
    insn_idx += 1;

    // [6] B <return_addr>
    let return_vaddr = site.vaddr + 4;
    let b_vaddr = insn_vaddr(insn_idx);
    let b_offset = return_vaddr.cast_signed() - b_vaddr.cast_signed();
    let b_insn = encode_b(b_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_offset:#x} out of range for Windows MRS gate return at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&b_insn.to_le_bytes());
    insn_idx += 1;

    // --- Fallback path: TlsState is NULL (early execution before run_thread) ---

    // [7] LDR Xscratch, [PC, #off_tls] — load TLS table address from header+8
    let ldr_vaddr = insn_vaddr(insn_idx);
    let ldr_offset = tls_table_vaddr.cast_signed() - ldr_vaddr.cast_signed();
    let ldr_insn = encode_ldr_literal(scratch, ldr_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_offset:#x} out of range for Windows MRS gate TLS fallback at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_insn.to_le_bytes());
    insn_idx += 1;

    // [8] LDR Xd, [Xscratch, #0] — entry[0].guest_tpidr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(rd, scratch, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [9] Restore scratch register(s)
    trampoline_data.extend_from_slice(&restore_scratch.to_le_bytes());
    insn_idx += 1;

    // [10] B <return_addr>
    let b_vaddr = insn_vaddr(insn_idx);
    let b_offset = return_vaddr.cast_signed() - b_vaddr.cast_signed();
    let b_insn = encode_b(b_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_offset:#x} out of range for Windows MRS gate fallback return at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&b_insn.to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.mrs_gate_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - gate_offset,
        target_os.mrs_gate_size(),
        "Windows MRS gate size mismatch"
    );

    Ok(())
}

/// Linux MRS gate: inline TLS table read, 5 instructions / 20 bytes.
///
/// Reads `entry[0].guest_tpidr` directly from the TLS lookup table.
/// Self-contained (no shared handler needed).
///
/// **General case (Xd ∉ {X16, X17}):**
/// ```text
/// [0] STP  X16, X17, [SP, #-16]!  ; save scratch
/// [1] LDR  X16, [PC, #off]        ; X16 = TLS table address
/// [2] LDR  Xd,  [X16, #0]         ; Xd = entry[0].guest_tpidr
/// [3] LDP  X16, X17, [SP], #16    ; restore scratch
/// [4] B    <return_addr>
/// ```
///
/// **Xd = X16:** use X17 as sole scratch
/// **Xd = X17:** use X16 as sole scratch
#[allow(clippy::cast_possible_wrap)]
fn emit_mrs_gate_linux(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rd: u8,
    target_os: TargetOs,
) -> Result<()> {
    let gate_vaddr = trampoline_base_addr + gate_offset as u64;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { gate_vaddr + (idx as u64) * 4 };
    let tls_table_vaddr = trampoline_base_addr + HEADER_TLS_TABLE_OFFSET as u64;

    if rd == 16 {
        // Xd = X16: use X17 as sole scratch register
        // [0] STR X17, [SP, #-16]!
        trampoline_data
            .extend_from_slice(&encode_str_pre_index(17, 31, -16).unwrap().to_le_bytes());
        insn_idx += 1;

        // [1] LDR X17, [PC, #off] — TLS table address
        let ldr_vaddr = insn_vaddr(insn_idx);
        let ldr_offset = tls_table_vaddr.cast_signed() - ldr_vaddr.cast_signed();
        let ldr_insn = encode_ldr_literal(17, ldr_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "LDR literal offset {ldr_offset:#x} out of range for MRS gate TLS load at {:#x}",
                site.vaddr
            ))
        })?;
        trampoline_data.extend_from_slice(&ldr_insn.to_le_bytes());
        insn_idx += 1;

        // [2] LDR X16, [X17, #0] — entry[0].guest_tpidr
        trampoline_data.extend_from_slice(
            &encode_ldr_imm_unsigned(16, 17, 0)
                .expect("offset 0 valid")
                .to_le_bytes(),
        );
        insn_idx += 1;

        // [3] LDR X17, [SP], #16 — restore X17
        trampoline_data
            .extend_from_slice(&encode_ldr_post_index(17, 31, 16).unwrap().to_le_bytes());
        insn_idx += 1;
    } else if rd == 17 {
        // Xd = X17: use X16 as sole scratch register
        // [0] STR X16, [SP, #-16]!
        trampoline_data
            .extend_from_slice(&encode_str_pre_index(16, 31, -16).unwrap().to_le_bytes());
        insn_idx += 1;

        // [1] LDR X16, [PC, #off] — TLS table address
        let ldr_vaddr = insn_vaddr(insn_idx);
        let ldr_offset = tls_table_vaddr.cast_signed() - ldr_vaddr.cast_signed();
        let ldr_insn = encode_ldr_literal(16, ldr_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "LDR literal offset {ldr_offset:#x} out of range for MRS gate TLS load at {:#x}",
                site.vaddr
            ))
        })?;
        trampoline_data.extend_from_slice(&ldr_insn.to_le_bytes());
        insn_idx += 1;

        // [2] LDR X17, [X16, #0] — entry[0].guest_tpidr
        trampoline_data.extend_from_slice(
            &encode_ldr_imm_unsigned(17, 16, 0)
                .expect("offset 0 valid")
                .to_le_bytes(),
        );
        insn_idx += 1;

        // [3] LDR X16, [SP], #16 — restore X16
        trampoline_data
            .extend_from_slice(&encode_ldr_post_index(16, 31, 16).unwrap().to_le_bytes());
        insn_idx += 1;
    } else {
        // General case: Xd ∉ {X16, X17}
        // [0] STP X16, X17, [SP, #-16]!
        trampoline_data
            .extend_from_slice(&encode_stp_pre_index(16, 17, 31, -16).unwrap().to_le_bytes());
        insn_idx += 1;

        // [1] LDR X16, [PC, #off] — TLS table address
        let ldr_vaddr = insn_vaddr(insn_idx);
        let ldr_offset = tls_table_vaddr.cast_signed() - ldr_vaddr.cast_signed();
        let ldr_insn = encode_ldr_literal(16, ldr_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "LDR literal offset {ldr_offset:#x} out of range for MRS gate TLS load at {:#x}",
                site.vaddr
            ))
        })?;
        trampoline_data.extend_from_slice(&ldr_insn.to_le_bytes());
        insn_idx += 1;

        // [2] LDR Xd, [X16, #0] — entry[0].guest_tpidr
        trampoline_data.extend_from_slice(
            &encode_ldr_imm_unsigned(rd, 16, 0)
                .expect("offset 0 valid")
                .to_le_bytes(),
        );
        insn_idx += 1;

        // [3] LDP X16, X17, [SP], #16 — restore scratch
        trampoline_data
            .extend_from_slice(&encode_ldp_post_index(16, 17, 31, 16).unwrap().to_le_bytes());
        insn_idx += 1;
    }

    // [4] B <return_addr> — branch back to instruction after original MRS
    let return_vaddr = site.vaddr + 4; // instruction after the MRS
    let b_vaddr = insn_vaddr(insn_idx);
    let b_offset = return_vaddr.cast_signed() - b_vaddr.cast_signed();
    let b_insn = encode_b(b_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {b_offset:#x} out of range for MRS gate return at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&b_insn.to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.mrs_gate_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - gate_offset,
        target_os.mrs_gate_size(),
        "MRS gate size mismatch"
    );

    Ok(())
}

/// macOS MRS gate: BL to shared MRS handler, 13 instructions / 52 bytes, 48-byte frame.
///
/// Saves/restores NZCV condition flags so that the shared handler's CMP/CMN
/// instructions don't clobber guest condition flags.
///
/// The shared handler does TPIDRRO_EL0-keyed TLS table lookup, reads TCB.guest_tpidr,
/// and stores the result to [SP+24]. The gate then loads [SP+24] into the destination register.
///
/// **General case (Xd ∉ {X16, X17, X30}):**
/// ```text
///  [0] SUB  SP, SP, #48            ; 48-byte frame
///  [1] STP  X16, X17, [SP]         ; save scratch
///  [2] STR  X30, [SP, #16]         ; save LR
///  [3] MRS  X16, NZCV              ; save condition flags
///  [4] STR  X16, [SP, #40]         ; store NZCV to frame
///  [5] BL   <shared_mrs_handler>   ; writes guest_tpidr to [SP+24]
///  [6] LDR  X16, [SP, #40]         ; reload NZCV
///  [7] MSR  NZCV, X16              ; restore condition flags
///  [8] LDR  Xd,  [SP, #24]         ; Xd = guest_tpidr
///  [9] LDP  X16, X17, [SP]         ; restore scratch
/// [10] LDR  X30, [SP, #16]         ; restore LR
/// [11] ADD  SP, SP, #48            ; deallocate
/// [12] B    <return_addr>           ; back to guest
/// ```
///
/// **Xd = X16:** NZCV restore first, then restore X17/X30 individually, load X16 from [SP+24] last
/// **Xd = X17:** NZCV restore first, then restore X16/X30 individually, load X17 from [SP+24] last
/// **Xd = X30:** NZCV restore first, then restore X16/X17, load X30 from [SP+24], NOP pad to 13
#[allow(clippy::cast_possible_wrap)]
fn emit_mrs_gate_macos(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rd: u8,
    target_os: TargetOs,
) -> Result<()> {
    let gate_vaddr = trampoline_base_addr + gate_offset as u64;
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

    // [3] MRS X16, NZCV — save condition flags before BL to shared handler
    trampoline_data.extend_from_slice(&encode_mrs_nzcv(16).to_le_bytes());
    insn_idx += 1;

    // [4] STR X16, [SP, #40] — store NZCV value to frame
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [5] BL <shared_mrs_handler>
    let bl_vaddr = insn_vaddr(insn_idx);
    let handler_vaddr = trampoline_base_addr + target_os.shared_mrs_handler_offset() as u64;
    let bl_offset = handler_vaddr.cast_signed() - bl_vaddr.cast_signed();
    let bl_insn = encode_bl(bl_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "BL offset {bl_offset:#x} out of range for MRS gate -> shared MRS handler at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&bl_insn.to_le_bytes());
    insn_idx += 1;

    // [6] LDR X16, [SP, #40] — reload saved NZCV value
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 31, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [7] MSR NZCV, X16 — restore condition flags
    trampoline_data.extend_from_slice(&encode_msr_nzcv(16).to_le_bytes());
    insn_idx += 1;

    // [8]-[10] varies by destination register
    match rd {
        16 => {
            // Xd = X16: restore X17 and X30 individually, load X16 from [SP+24] last
            // [8] LDR X17, [SP, #8]
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(17, 31, 8)
                    .expect("offset 8 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            // [9] LDR X30, [SP, #16]
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(30, 31, 16)
                    .expect("offset 16 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            // [10] LDR X16, [SP, #24] — X16 = guest_tpidr
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(16, 31, 24)
                    .expect("offset 24 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
        }
        17 => {
            // Xd = X17: restore X16 and X30 individually, load X17 from [SP+24] last
            // [8] LDR X16, [SP, #0]
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(16, 31, 0)
                    .expect("offset 0 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            // [9] LDR X30, [SP, #16]
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(30, 31, 16)
                    .expect("offset 16 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            // [10] LDR X17, [SP, #24] — X17 = guest_tpidr
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(17, 31, 24)
                    .expect("offset 24 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
        }
        30 => {
            // Xd = X30: restore X16,X17, load X30 from [SP+24], NOP pad
            // [8] LDP X16, X17, [SP]
            trampoline_data.extend_from_slice(
                &encode_ldp_offset(16, 17, 31, 0)
                    .expect("offset 0 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            // [9] LDR X30, [SP, #24] — X30 = guest_tpidr
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(30, 31, 24)
                    .expect("offset 24 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            // [10] NOP — pad to 13 instructions for uniform gate size
            trampoline_data.extend_from_slice(&NOP.to_le_bytes());
            insn_idx += 1;
        }
        _ => {
            // General case: Xd ∉ {X16, X17, X30}
            // [8] LDR Xd, [SP, #24] — Xd = guest_tpidr
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(rd, 31, 24)
                    .expect("offset 24 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            // [9] LDP X16, X17, [SP]
            trampoline_data.extend_from_slice(
                &encode_ldp_offset(16, 17, 31, 0)
                    .expect("offset 0 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
            // [10] LDR X30, [SP, #16]
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(30, 31, 16)
                    .expect("offset 16 valid")
                    .to_le_bytes(),
            );
            insn_idx += 1;
        }
    }

    // [11] ADD SP, SP, #48
    trampoline_data.extend_from_slice(&encode_add_sp_imm(48).expect("imm12=48 fits").to_le_bytes());
    insn_idx += 1;

    // [12] B <return_addr>
    let ret_vaddr = insn_vaddr(insn_idx);
    let ret_offset = (site.vaddr + 4).cast_signed() - ret_vaddr.cast_signed();
    let ret_insn = encode_b(ret_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {ret_offset:#x} out of ±128MB range for return from MRS gate at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&ret_insn.to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, target_os.mrs_gate_insn_count());
    debug_assert_eq!(
        trampoline_data.len() - gate_offset,
        target_os.mrs_gate_size(),
        "macOS MRS gate size mismatch"
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

        let sites = find_patch_sites(&sections, &buf, TargetOs::Linux).unwrap();
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

        let sites = find_patch_sites(&sections, &buf, TargetOs::Linux).unwrap();
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

        let sites = find_patch_sites(&sections, &buf, TargetOs::Linux).unwrap();
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

        let sites = find_patch_sites(&sections, &buf, TargetOs::Linux).unwrap();
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

        let sites = find_patch_sites(&sections, &buf, TargetOs::Linux).unwrap();
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

        let sites = find_patch_sites(&sections, &buf, TargetOs::Linux).unwrap();
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
        assert_eq!(TargetOs::Linux.shared_svc_handler_size(), 72);
        assert_eq!(TargetOs::Linux.shared_svc_handler_insn_count(), 18);
        // Per-site SVC gate: 6 instructions, 24 bytes
        assert_eq!(TargetOs::Linux.svc_gate_size(), 24);
        assert_eq!(TargetOs::Linux.svc_gate_insn_count(), 6);
        // Shared MSR handler: 19 instructions, 76 bytes (linear scan + sentinel entry[0] write)
        assert_eq!(TargetOs::Linux.shared_msr_handler_size(), 76);
        assert_eq!(TargetOs::Linux.shared_msr_handler_insn_count(), 19);
        // Per-site MSR gate: 9 instructions (general), 36 bytes
        assert_eq!(TargetOs::Linux.msr_gate_size(), 36);
        assert_eq!(TargetOs::Linux.msr_gate_insn_count(), 9);
        // Per-site MSR gate (special regs): 10 instructions, 40 bytes
        assert_eq!(TargetOs::Linux.msr_gate_special_size(), 40);
        // Per-site MRS gate: 5 instructions, 20 bytes
        assert_eq!(TargetOs::Linux.mrs_gate_size(), 20);
        assert_eq!(TargetOs::Linux.mrs_gate_insn_count(), 5);
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

        let (td, _) = hook_syscalls_aarch64(
            &mut buf,
            &sections,
            trampoline_base,
            callback_addr,
            TargetOs::Linux,
        )
        .unwrap();

        // === Per-site SVC gate at TargetOs::Linux.gates_start_offset() (6 instructions) ===
        let gate_start = TargetOs::Linux.gates_start_offset();
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
        let handler_vaddr = trampoline_base + TargetOs::Linux.shared_svc_handler_offset() as u64;
        let b_offset = handler_vaddr as i64 - b_vaddr as i64;
        assert_eq!(gate_insn_at(5), encode_b(b_offset).unwrap());

        // === Shared SVC handler at TargetOs::Linux.shared_svc_handler_offset() (18 instructions) ===
        // Linear scan TLS lookup with sentinel fallback
        let handler_start = TargetOs::Linux.shared_svc_handler_offset();
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

        let (trampoline_data, found) = hook_syscalls_aarch64(
            &mut buf,
            &sections,
            trampoline_base,
            callback_addr,
            TargetOs::Linux,
        )
        .unwrap();

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

        // Total: TargetOs::Linux.gates_start_offset() (184) + 1 SVC gate (24) = 208
        assert_eq!(
            trampoline_data.len(),
            TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size()
        );

        // Verify the original SVC was patched with a B instruction
        let patched = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        // B to per-site gate at 0x2000 + TargetOs::Linux.gates_start_offset()
        let gate_vaddr = trampoline_base + TargetOs::Linux.gates_start_offset() as u64;
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

        let result = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0, TargetOs::Linux);
        let (trampoline_data, has_svc) = result.expect("should succeed with minimal trampoline");
        assert!(!has_svc, "should report no SVC found");
        // Minimal trampoline: header(16) + sigret preamble(8) + sigret gate(24) + shared SVC(72) + shared MSR(64) = 184
        assert_eq!(
            trampoline_data.len(),
            TargetOs::Linux.gates_start_offset(),
            "minimal trampoline should be exactly TargetOs::Linux.gates_start_offset() bytes"
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
            hook_syscalls_aarch64(&mut buf, &sections, trampoline_base, 0, TargetOs::Linux)
                .unwrap();

        assert!(found);

        // TargetOs::Linux.gates_start_offset() (184) + 2 * TargetOs::Linux.svc_gate_size() (24) = 232
        assert_eq!(
            trampoline_data.len(),
            TargetOs::Linux.gates_start_offset() + 2 * TargetOs::Linux.svc_gate_size()
        );

        // Both SVCs should be patched
        let patched1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let patched2 = u32::from_le_bytes(buf[16..20].try_into().unwrap());

        // Verify both are B instructions (opcode in bits [31:26])
        assert_eq!(patched1 & 0xFC00_0000, 0x1400_0000);
        assert_eq!(patched2 & 0xFC00_0000, 0x1400_0000);

        // Verify they branch to different targets (different gates)
        assert_ne!(patched1, patched2);

        // Verify gate 1 at TargetOs::Linux.gates_start_offset() and gate 2 at TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size()
        let gate1_vaddr = trampoline_base + TargetOs::Linux.gates_start_offset() as u64;
        let gate2_vaddr = trampoline_base
            + TargetOs::Linux.gates_start_offset() as u64
            + TargetOs::Linux.svc_gate_size() as u64;

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

        let (trampoline_data, _) =
            hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0, TargetOs::Linux).unwrap();

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

        let (trampoline_data, _) =
            hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0, TargetOs::Linux).unwrap();

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

        let (trampoline_data, _) =
            hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0, TargetOs::Linux).unwrap();

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
        let (td, _) =
            hook_syscalls_aarch64(&mut buf, &sections, 0x2000, callback_addr, TargetOs::Linux)
                .unwrap();

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
        // Total: TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size() = 208
        assert_eq!(
            td.len(),
            TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size()
        );
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

        let (td, _) =
            hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0, TargetOs::Linux).unwrap();

        // Read instructions from the shared SVC handler at TargetOs::Linux.shared_svc_handler_offset()
        // Linear scan: loop at [3], found at [10], fallback at [12], done at [16]
        let insn_at = |idx: usize| -> u32 {
            let off = TargetOs::Linux.shared_svc_handler_offset() + idx * 4;
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
        let (td, found) = hook_syscalls_aarch64(
            &mut buf,
            &sections,
            trampoline_base,
            0xCAFE,
            TargetOs::Linux,
        )
        .unwrap();
        assert!(found);
        (td, buf, trampoline_base)
    }

    #[test]
    fn test_hook_svc_and_msr_trampoline_sizes() {
        let (td, _, _) = hook_with_svc_and_msr(19);
        // TargetOs::Linux.gates_start_offset() (184) + SVC gate (24) + MSR gate for X19 (36) = 244
        assert_eq!(
            td.len(),
            TargetOs::Linux.gates_start_offset()
                + TargetOs::Linux.svc_gate_size()
                + TargetOs::Linux.msr_gate_size()
        );
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
        let msr_start = TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size();
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
        let msr_start = TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size();
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
        let msr_start = TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size();
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
        let msr_start = TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size();
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
        let msr_start = TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size();
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
        let msr_start = TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size();
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
        let msr_start = TargetOs::Linux.gates_start_offset() + TargetOs::Linux.svc_gate_size();
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
        let handler_vaddr = trampoline_base + TargetOs::Linux.shared_msr_handler_offset() as u64;
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
        // Verify the full shared MSR handler instruction layout (19 instructions)
        // Linear scan TLS lookup with sentinel entry[0] write
        let (td, _, trampoline_base) = hook_with_svc_and_msr(19);
        let handler_start = TargetOs::Linux.shared_msr_handler_offset();
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

        // [5] B.EQ .Lsentinel -> [13]: offset = (13-5)*4 = 32
        assert_eq!(insn_at(5), encode_b_cond(COND_EQ, 32).unwrap());

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

        // [12] B .Lmsr -> [16]: offset = (16-12)*4 = 16
        assert_eq!(insn_at(12), encode_b(16).unwrap());

        // [13] .Lsentinel: LDR X17, [PC, #offset] -- reload TLS table base
        let sentinel_ldr_vaddr = handler_vaddr + 13 * 4;
        let sentinel_tls_offset = (trampoline_base + 8) as i64 - sentinel_ldr_vaddr as i64;
        assert_eq!(
            insn_at(13),
            encode_ldr_literal(17, sentinel_tls_offset).unwrap()
        );

        // [14] LDR X16, [SP, #24] -- new TPIDR
        assert_eq!(insn_at(14), encode_ldr_imm_unsigned(16, 31, 24).unwrap());

        // [15] STR X16, [X17, #0] -- write entry[0].guest_tpidr
        assert_eq!(insn_at(15), encode_str_imm_unsigned(16, 17, 0).unwrap());

        // [16] .Lmsr: MSR TPIDR_EL0, X16
        assert_eq!(insn_at(16), encode_msr_tpidr_el0(16));

        // [17] LDR X30, [SP, #32] -- restore
        assert_eq!(insn_at(17), encode_ldr_imm_unsigned(30, 31, 32).unwrap());

        // [18] RET
        assert_eq!(insn_at(18), encode_ret(30));
    }

    #[test]
    fn test_hook_msr_only_produces_trampoline_with_gates() {
        // A binary with only MSR TPIDR_EL0 and no SVC should produce a
        // trampoline with shared layout + MSR gate. The MSR instruction
        // should be patched with a branch to the gate.
        let msr_insn = encode_msr_tpidr_el0(19);
        let nop: u32 = 0xD503201F;
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&msr_insn.to_le_bytes());
        buf[4..8].copy_from_slice(&nop.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let result = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0, TargetOs::Linux);
        let (trampoline_data, has_svc) = result.expect("should succeed");
        assert!(!has_svc, "should report no SVC found");
        // MSR instruction should be patched (replaced with a branch)
        assert_ne!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            msr_insn,
            "MSR instruction should be patched with a branch"
        );
        // Trampoline should be larger than TargetOs::Linux.gates_start_offset() (has an MSR gate)
        assert_eq!(
            trampoline_data.len(),
            TargetOs::Linux.gates_start_offset() + TargetOs::Linux.msr_gate_size(),
            "trampoline should contain shared layout + one MSR gate"
        );
    }

    // ============================================================
    // MRS TPIDR_EL0 — rewritten to read from TLS table
    // ============================================================
    // MRS TPIDR_EL0 is rewritten to read entry[0].guest_tpidr from the TLS
    // table. On macOS, TPIDR_EL0 can be clobbered by preemptive context
    // switches, so native reads are unreliable.

    #[test]
    fn test_find_patch_sites_mrs_tpidr_detected() {
        // MRS TPIDR_EL0 is detected as a patch site alongside SVC and MSR
        let nop: u32 = 0xD503201F;
        let msr_x5 = encode_msr_tpidr_el0(5);
        let mrs_x10 = encode_mrs_tpidr_el0(10);
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes());
        buf[4..8].copy_from_slice(&msr_x5.to_le_bytes());
        buf[8..12].copy_from_slice(&mrs_x10.to_le_bytes());
        buf[12..16].copy_from_slice(&nop.to_le_bytes());
        buf[16..20].copy_from_slice(&nop.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 20,
        }];

        let sites = find_patch_sites(&sections, &buf, TargetOs::Linux).unwrap();
        assert_eq!(sites.len(), 3, "should find SVC + MSR + MRS");
        assert_eq!(sites[0].kind, PatchKind::Svc);
        assert_eq!(sites[1].kind, PatchKind::MsrTpidr(5));
        assert_eq!(sites[2].kind, PatchKind::MrsTpidr(10));
    }

    #[test]
    fn test_mrs_only_produces_trampoline_with_gates() {
        // A binary with only MRS TPIDR_EL0 (no SVC, no MSR) should produce
        // a trampoline with shared layout + MRS gate, and the MRS instruction
        // should be patched with a branch to the gate.
        let mrs_insn = encode_mrs_tpidr_el0(0);
        let nop: u32 = 0xD503201F;
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&mrs_insn.to_le_bytes());
        buf[4..8].copy_from_slice(&nop.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let result = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0, TargetOs::Linux);
        let (trampoline_data, has_svc) = result.expect("should succeed");
        assert!(!has_svc, "should report no SVC found");
        // MRS instruction should be patched (replaced with a branch)
        assert_ne!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            mrs_insn,
            "MRS instruction should be patched with a branch"
        );
        // Trampoline should be larger than TargetOs::Linux.gates_start_offset() (has an MRS gate)
        assert_eq!(
            trampoline_data.len(),
            TargetOs::Linux.gates_start_offset() + TargetOs::Linux.mrs_gate_size(),
            "trampoline should contain shared layout + one MRS gate"
        );
    }

    // ============================================================
    // MRS gate instruction-level tests
    // ============================================================

    /// Helper: emit an MRS gate and return the trampoline bytes.
    fn emit_mrs_gate_helper(rd: u8) -> Vec<u8> {
        let mut td = Vec::new();
        let trampoline_base = 0x2000u64;
        // Emit header (16 bytes) so TLS table pointer is at offset 8
        td.extend_from_slice(&0u64.to_le_bytes()); // callback
        td.extend_from_slice(&0u64.to_le_bytes()); // TLS table ptr

        let gate_offset = td.len();
        let site = PatchSite {
            file_offset: 0,
            vaddr: 0x1000,
            kind: PatchKind::MrsTpidr(rd),
        };
        emit_mrs_gate(
            &mut td,
            gate_offset,
            trampoline_base,
            &site,
            rd,
            TargetOs::Linux,
        )
        .unwrap();
        td
    }

    #[test]
    fn test_mrs_gate_general_reg() {
        // General case: Xd = X0, uses STP/LDP for X16,X17
        let td = emit_mrs_gate_helper(0);
        let gate_start = 16; // after header
        let insn_at = |idx: usize| -> u32 {
            let off = gate_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [0] STP X16, X17, [SP, #-16]! (pre-index)
        let stp = insn_at(0);
        assert_eq!(stp, encode_stp_pre_index(16, 17, 31, -16).unwrap());

        // [1] LDR X16, [PC, #off] — loads TLS table address
        let ldr = insn_at(1);
        assert_eq!(ldr & 0xFF00_0000, 0x5800_0000, "should be LDR literal");
        assert_eq!(ldr & 0x1F, 16, "should load into X16");

        // [2] LDR X0, [X16, #0] — entry[0].guest_tpidr
        let ldr_tpidr = insn_at(2);
        assert_eq!(
            ldr_tpidr,
            encode_ldr_imm_unsigned(0, 16, 0).unwrap(),
            "should load entry[0] into X0"
        );

        // [3] LDP X16, X17, [SP], #16 (post-index)
        let ldp = insn_at(3);
        assert_eq!(ldp, encode_ldp_post_index(16, 17, 31, 16).unwrap());

        // [4] B <return> — branches to site.vaddr + 4
        let b_insn = insn_at(4);
        assert_eq!(b_insn & 0xFC00_0000, 0x14000000, "should be B instruction");

        // Total size = 5 instructions = 20 bytes
        assert_eq!(td.len() - gate_start, TargetOs::Linux.mrs_gate_size());
    }

    #[test]
    fn test_mrs_gate_x16() {
        // Xd = X16: uses X17 as sole scratch (STR/LDR pre/post-index)
        let td = emit_mrs_gate_helper(16);
        let gate_start = 16;
        let insn_at = |idx: usize| -> u32 {
            let off = gate_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [0] STR X17, [SP, #-16]!
        let str_insn = insn_at(0);
        assert_eq!(str_insn, encode_str_pre_index(17, 31, -16).unwrap());

        // [1] LDR X17, [PC, #off] — TLS table via X17 (scratch)
        let ldr = insn_at(1);
        assert_eq!(ldr & 0xFF00_0000, 0x5800_0000, "should be LDR literal");
        assert_eq!(ldr & 0x1F, 17, "should load into X17 (scratch)");

        // [2] LDR X16, [X17, #0] — entry[0].guest_tpidr into X16 (dest)
        let ldr_tpidr = insn_at(2);
        assert_eq!(
            ldr_tpidr,
            encode_ldr_imm_unsigned(16, 17, 0).unwrap(),
            "should load entry[0] into X16 via X17"
        );

        // [3] LDR X17, [SP], #16
        let ldr_restore = insn_at(3);
        assert_eq!(ldr_restore, encode_ldr_post_index(17, 31, 16).unwrap());

        // [4] B <return>
        let b_insn = insn_at(4);
        assert_eq!(b_insn & 0xFC00_0000, 0x14000000, "should be B instruction");

        assert_eq!(td.len() - gate_start, TargetOs::Linux.mrs_gate_size());
    }

    #[test]
    fn test_mrs_gate_x17() {
        // Xd = X17: uses X16 as sole scratch (STR/LDR pre/post-index)
        let td = emit_mrs_gate_helper(17);
        let gate_start = 16;
        let insn_at = |idx: usize| -> u32 {
            let off = gate_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [0] STR X16, [SP, #-16]!
        let str_insn = insn_at(0);
        assert_eq!(str_insn, encode_str_pre_index(16, 31, -16).unwrap());

        // [1] LDR X16, [PC, #off] — TLS table via X16 (scratch)
        let ldr = insn_at(1);
        assert_eq!(ldr & 0xFF00_0000, 0x5800_0000, "should be LDR literal");
        assert_eq!(ldr & 0x1F, 16, "should load into X16 (scratch)");

        // [2] LDR X17, [X16, #0] — entry[0].guest_tpidr into X17 (dest)
        let ldr_tpidr = insn_at(2);
        assert_eq!(
            ldr_tpidr,
            encode_ldr_imm_unsigned(17, 16, 0).unwrap(),
            "should load entry[0] into X17 via X16"
        );

        // [3] LDR X16, [SP], #16
        let ldr_restore = insn_at(3);
        assert_eq!(ldr_restore, encode_ldr_post_index(16, 31, 16).unwrap());

        // [4] B <return>
        let b_insn = insn_at(4);
        assert_eq!(b_insn & 0xFC00_0000, 0x14000000, "should be B instruction");

        assert_eq!(td.len() - gate_start, TargetOs::Linux.mrs_gate_size());
    }

    #[test]
    fn test_trampoline_size_with_svc_msr_mrs() {
        // A binary with SVC + MSR + MRS should produce a trampoline with all gates.
        let nop: u32 = 0xD503201F;
        let msr_x5 = encode_msr_tpidr_el0(5);
        let mrs_x10 = encode_mrs_tpidr_el0(10);
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes());
        buf[4..8].copy_from_slice(&msr_x5.to_le_bytes());
        buf[8..12].copy_from_slice(&mrs_x10.to_le_bytes());
        buf[12..16].copy_from_slice(&nop.to_le_bytes());
        buf[16..20].copy_from_slice(&nop.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 20,
        }];

        let (td, has_svc) =
            hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0, TargetOs::Linux).unwrap();
        assert!(has_svc);
        assert_eq!(
            td.len(),
            TargetOs::Linux.gates_start_offset()
                + TargetOs::Linux.svc_gate_size()
                + TargetOs::Linux.msr_gate_size()
                + TargetOs::Linux.mrs_gate_size(),
            "trampoline should have shared layout + SVC + MSR + MRS gates"
        );
    }

    // ============================================================
    // x18 detection, rewriting, and gate tests
    // ============================================================

    #[test]
    fn test_references_x18_mov_to_x18() {
        // MOV X18, X0 => ORR X18, XZR, X0 => 0xAA0003F2
        // Rd=18 (bits 4:0), Rn=31 (XZR), Rm=0
        let insn: u32 = 0xAA0003F2;
        assert!(references_x18(insn));
    }

    #[test]
    fn test_references_x18_mov_from_x18() {
        // MOV X0, X18 => ORR X0, XZR, X18 => 0xAA1203E0
        // Rd=0, Rn=31 (XZR), Rm=18 (bits 20:16)
        let insn: u32 = 0xAA1203E0;
        assert!(references_x18(insn));
    }

    #[test]
    fn test_references_x18_add_with_x18_base() {
        // ADD X5, X18, #0x10 => 0x91004245
        // Rd=5, Rn=18 (bits 9:5), imm12=0x10
        let insn: u32 = 0x91004245;
        assert!(references_x18(insn));
    }

    #[test]
    fn test_references_x18_ldr_with_x18_base() {
        // LDR X0, [X18] => 0xF9400240
        // Rt=0, Rn=18 (bits 9:5)
        let insn: u32 = 0xF9400240;
        assert!(references_x18(insn));
    }

    #[test]
    fn test_references_x18_str_x18_value() {
        // STR X18, [X0] => 0xF9000012
        // Rt=18 (bits 4:0), Rn=0
        let insn: u32 = 0xF9000012;
        assert!(references_x18(insn));
    }

    #[test]
    fn test_references_x18_nop_no_x18() {
        // NOP => 0xD503201F
        let insn: u32 = 0xD503201F;
        assert!(!references_x18(insn));
    }

    #[test]
    fn test_references_x18_add_no_x18() {
        // ADD X1, X2, X3 => 0x8B030041
        let insn: u32 = 0x8B030041;
        assert!(!references_x18(insn));
    }

    #[test]
    fn test_references_x18_stp_with_x18_in_rt2() {
        // STP X5, X18, [SP, #0] => Rt=5, Rt2=18, Rn=SP(31), offset=0
        // opc=10, mode=010, imm7=0, Rt2=18, Rn=31, Rt=5
        let insn: u32 = 0xA9004BE5;
        assert!(references_x18(insn));
    }

    #[test]
    fn test_is_store_instruction_str() {
        // STR X18, [X0] => 0xF9000012
        let insn: u32 = 0xF9000012;
        assert!(is_store_instruction(insn));
    }

    #[test]
    fn test_is_store_instruction_stp() {
        // STP X5, X18, [SP, #0] => 0xA90047E5
        let insn: u32 = 0xA90047E5;
        assert!(is_store_instruction(insn));
    }

    #[test]
    fn test_is_store_instruction_ldr_not_store() {
        // LDR X0, [X18] => 0xF9400240
        let insn: u32 = 0xF9400240;
        assert!(!is_store_instruction(insn));
    }

    #[test]
    fn test_is_store_instruction_add_not_store() {
        // ADD X5, X18, #0x10 => 0x91004245
        let insn: u32 = 0x91004245;
        assert!(!is_store_instruction(insn));
    }

    #[test]
    fn test_rewrite_x18_mov_to_x18() {
        // MOV X18, X0 => Rd=18, x18 is write destination
        let insn: u32 = 0xAA0003F2;
        let (rewritten, scratch, is_read, is_write) = rewrite_x18(insn);
        assert_eq!(scratch, 17, "scratch should be X17 (default)");
        assert!(!is_read, "MOV to X18 should not set is_read");
        assert!(is_write, "writing to X18 should set is_write");
        // Rd should be replaced: bits 4:0 should be scratch (17)
        assert_eq!(rewritten & 0x1F, 17);
        // Other fields unchanged
        assert_eq!(rewritten & !0x1F, insn & !0x1F);
    }

    #[test]
    fn test_rewrite_x18_mov_from_x18() {
        // MOV X0, X18 => Rm=18 (bits 20:16), x18 is read source
        let insn: u32 = 0xAA1203E0;
        let (rewritten, scratch, is_read, is_write) = rewrite_x18(insn);
        assert_eq!(scratch, 17);
        assert!(is_read, "reading from X18 should set is_read");
        assert!(!is_write);
        // Rm (bits 20:16) should be replaced with scratch
        assert_eq!((rewritten >> 16) & 0x1F, 17);
    }

    #[test]
    fn test_rewrite_x18_ldr_base_x18() {
        // LDR X0, [X18] => Rn=18 (base register, read)
        let insn: u32 = 0xF9400240;
        let (rewritten, scratch, is_read, is_write) = rewrite_x18(insn);
        assert_eq!(scratch, 17);
        assert!(is_read, "base register X18 in LDR is a read");
        assert!(!is_write);
        // Rn (bits 9:5) should be replaced with scratch
        assert_eq!((rewritten >> 5) & 0x1F, 17);
    }

    #[test]
    fn test_rewrite_x18_str_value_x18() {
        // STR X18, [X0] => Rt=18 (value being stored, read for stores)
        let insn: u32 = 0xF9000012;
        let (rewritten, scratch, is_read, is_write) = rewrite_x18(insn);
        assert_eq!(scratch, 17);
        assert!(is_read, "X18 as Rt in STR is a read (value being stored)");
        assert!(!is_write);
        // Rd/Rt (bits 4:0) should be replaced with scratch
        assert_eq!(rewritten & 0x1F, 17);
    }

    #[test]
    fn test_rewrite_x18_uses_x16_when_x17_in_use() {
        // ADD X17, X18, #0 => Rd=17, Rn=18
        // Since X17 appears in Rd (non-x18), scratch should be X16
        let insn: u32 = 0x91000251; // ADD X17, X18, #0
        let (rewritten, scratch, is_read, _is_write) = rewrite_x18(insn);
        assert_eq!(
            scratch, 16,
            "scratch should be X16 when X17 is used by insn"
        );
        assert!(is_read, "Rn=X18 is a read");
        // Rn (bits 9:5) should be replaced with scratch=16
        assert_eq!((rewritten >> 5) & 0x1F, 16);
    }

    #[test]
    fn test_rewrite_x18_add_base_x18_write_to_x18() {
        // ADD X18, X18, #8 => Rd=18 (write), Rn=18 (read)
        let insn: u32 = 0x91002252;
        let (rewritten, scratch, is_read, is_write) = rewrite_x18(insn);
        assert_eq!(scratch, 17);
        assert!(is_read, "Rn=X18 is a read");
        assert!(is_write, "Rd=X18 in non-store is a write");
        // Both Rd and Rn should be replaced with scratch
        assert_eq!(rewritten & 0x1F, 17, "Rd should be scratch");
        assert_eq!((rewritten >> 5) & 0x1F, 17, "Rn should be scratch");
    }

    #[test]
    fn test_x18_gate_size_read_only() {
        assert_eq!(
            x18_gate_size(TargetOs::MacOs, true, false, false),
            TargetOs::MacOs.x18_gate_read_insn_count() * 4
        );
    }

    #[test]
    fn test_x18_gate_size_write_only() {
        assert_eq!(
            x18_gate_size(TargetOs::MacOs, false, true, false),
            TargetOs::MacOs.x18_gate_write_insn_count() * 4
        );
    }

    #[test]
    fn test_x18_gate_size_readwrite() {
        assert_eq!(
            x18_gate_size(TargetOs::MacOs, true, true, false),
            TargetOs::MacOs.x18_gate_readwrite_insn_count() * 4
        );
    }

    #[test]
    fn test_x18_gate_sizes_consistent() {
        // Read-only and write-only should be the same size
        assert_eq!(
            TargetOs::MacOs.x18_gate_read_insn_count(),
            TargetOs::MacOs.x18_gate_write_insn_count()
        );
        // Read-write should be larger
        assert!(
            TargetOs::MacOs.x18_gate_readwrite_insn_count()
                > TargetOs::MacOs.x18_gate_read_insn_count()
        );
    }

    #[test]
    fn test_shared_x18_handler_constants() {
        assert_eq!(TargetOs::MacOs.shared_x18_load_handler_size(), 64);
        assert_eq!(TargetOs::MacOs.shared_x18_save_handler_size(), 64);
        assert_eq!(TargetOs::MacOs.shared_x18_load_handler_insn_count(), 16);
        assert_eq!(TargetOs::MacOs.shared_x18_save_handler_insn_count(), 16);
    }

    // ============================================================
    // Tests for adjust_sp_relative_offset
    // ============================================================

    #[test]
    fn test_adjust_sp_offset_stp_x4_x18_sp_0xb8() {
        // STP X4, X18, [SP, #0xb8] — the exact instruction from ld.so's do_lookup_x
        // After x18→x17 rewrite, encode properly:
        // STP X4, X17, [SP, #0xb8]: imm7 = 0xb8/8 = 23 = 0x17
        // 0xA900_0000 | (0x17 << 15) | (17 << 10) | (31 << 5) | 4
        let insn = 0xA900_0000 | (23u32 << 15) | (17u32 << 10) | (31u32 << 5) | 4;
        let adjusted = adjust_sp_relative_offset(insn, 48).unwrap();
        // New offset should be 0xb8 + 48 = 0xe8, imm7 = 0xe8/8 = 29 = 0x1D
        let new_imm7 = (adjusted >> 15) & 0x7F;
        assert_eq!(
            new_imm7, 29,
            "imm7 should be 29 (0xe8/8) after +48 adjustment"
        );
        // Other fields unchanged
        assert_eq!(adjusted & 0x1F, 4, "Rt should still be 4");
        assert_eq!((adjusted >> 5) & 0x1F, 31, "Rn should still be SP");
        assert_eq!((adjusted >> 10) & 0x1F, 17, "Rt2 should still be 17");
    }

    #[test]
    fn test_adjust_sp_offset_ldp_x4_x18_sp_0xb8() {
        // LDP X4, X17, [SP, #0xb8] (after x18→x17 rewrite)
        let insn = 0xA940_0000 | (23u32 << 15) | (17u32 << 10) | (31u32 << 5) | 4;
        let adjusted = adjust_sp_relative_offset(insn, 48).unwrap();
        let new_imm7 = (adjusted >> 15) & 0x7F;
        assert_eq!(new_imm7, 29, "imm7 should be 29 after +48 adjustment");
    }

    #[test]
    fn test_adjust_sp_offset_stp_sp_0xd0() {
        // STP X4, X17, [SP, #0xd0]: imm7 = 0xd0/8 = 26
        let insn = 0xA900_0000 | (26u32 << 15) | (17u32 << 10) | (31u32 << 5) | 4;
        let adjusted = adjust_sp_relative_offset(insn, 48).unwrap();
        // New offset = 0xd0 + 48 = 0x100, imm7 = 0x100/8 = 32
        let new_imm7 = (adjusted >> 15) & 0x7F;
        assert_eq!(
            new_imm7, 32,
            "imm7 should be 32 (0x100/8) after +48 adjustment"
        );
    }

    #[test]
    fn test_adjust_sp_offset_str_x18_sp_0xc8() {
        // STR X17, [SP, #0xc8] (after x18→x17 rewrite)
        // Encoding: 0xF900_0000 | (imm12 << 10) | (Rn << 5) | Rt
        // imm12 = 0xc8/8 = 25
        let insn = 0xF900_0000 | (25u32 << 10) | (31u32 << 5) | 17;
        let adjusted = adjust_sp_relative_offset(insn, 48).unwrap();
        // New offset = 0xc8 + 48 = 0xf8, imm12 = 0xf8/8 = 31
        let new_imm12 = (adjusted >> 10) & 0xFFF;
        assert_eq!(
            new_imm12, 31,
            "imm12 should be 31 (0xf8/8) after +48 adjustment"
        );
    }

    #[test]
    fn test_adjust_sp_offset_ldr_x18_sp_0xc8() {
        // LDR X17, [SP, #0xc8] (after x18→x17 rewrite)
        // imm12 = 0xc8/8 = 25
        let insn = 0xF940_0000 | (25u32 << 10) | (31u32 << 5) | 17;
        let adjusted = adjust_sp_relative_offset(insn, 48).unwrap();
        let new_imm12 = (adjusted >> 10) & 0xFFF;
        assert_eq!(new_imm12, 31, "imm12 should be 31 (0xf8/8)");
    }

    #[test]
    fn test_adjust_sp_offset_stp_sp_0x70() {
        // STP X17, X18→X16, [SP, #0x70]: imm7 = 0x70/8 = 14
        let insn = 0xA900_0000 | (14u32 << 15) | (16u32 << 10) | (31u32 << 5) | 17;
        let adjusted = adjust_sp_relative_offset(insn, 48).unwrap();
        // New offset = 0x70 + 48 = 0xa0, imm7 = 0xa0/8 = 20
        let new_imm7 = (adjusted >> 15) & 0x7F;
        assert_eq!(
            new_imm7, 20,
            "imm7 should be 20 (0xa0/8) after +48 adjustment"
        );
    }

    #[test]
    fn test_adjust_sp_offset_not_sp_returns_none() {
        // LDR X17, [X0, #8] — base is X0, not SP
        let insn = 0xF940_0000 | (1u32 << 10) | (0u32 << 5) | 17;
        assert!(
            adjust_sp_relative_offset(insn, 48).is_none(),
            "non-SP-relative should return None"
        );
    }

    #[test]
    fn test_adjust_sp_offset_add_sp_returns_none() {
        // ADD X17, SP, #8 — SP is base but this is not a memory access
        let insn: u32 = 0x910023F1; // ADD X17, SP, #8
        assert!(
            adjust_sp_relative_offset(insn, 48).is_none(),
            "ADD with SP should return None (not a memory op)"
        );
    }

    #[test]
    fn test_adjust_sp_offset_stp_offset_overflow() {
        // STP X4, X17, [SP, #0x1F0]: imm7 = 0x1F0/8 = 62
        // After +48: 0x1F0 + 48 = 0x220, imm7 = 0x220/8 = 68 > 63 (max imm7)
        let insn = 0xA900_0000 | (62u32 << 15) | (17u32 << 10) | (31u32 << 5) | 4;
        assert!(
            adjust_sp_relative_offset(insn, 48).is_none(),
            "adjusted STP offset overflowing imm7 should return None"
        );
    }

    #[test]
    fn test_adjust_sp_offset_stp_zero_offset() {
        // STP X4, X17, [SP, #0]: imm7 = 0
        let insn = 0xA900_0000 | (0u32 << 15) | (17u32 << 10) | (31u32 << 5) | 4;
        let adjusted = adjust_sp_relative_offset(insn, 48).unwrap();
        // New offset = 0 + 48, imm7 = 48/8 = 6
        let new_imm7 = (adjusted >> 15) & 0x7F;
        assert_eq!(new_imm7, 6, "imm7 should be 6 (48/8)");
    }

    #[test]
    fn test_adjust_sp_offset_roundtrip_all_ld_so_patterns() {
        // Test all SP-relative x18 instruction patterns from ld-linux-aarch64.so.1
        // Format: (original_offset, instruction_type, expected_new_offset)
        let frame_size: u16 = 48;

        // STP X4, X17, [SP, #0xb8] — offset 0xb8=184, new 0xe8=232
        let stp_b8 = 0xA900_0000 | (23u32 << 15) | (17u32 << 10) | (31u32 << 5) | 4;
        assert!(adjust_sp_relative_offset(stp_b8, frame_size).is_some());

        // STP X4, X17, [SP, #0xd0] — offset 0xd0=208, new 0x100=256
        let stp_d0 = 0xA900_0000 | (26u32 << 15) | (17u32 << 10) | (31u32 << 5) | 4;
        assert!(adjust_sp_relative_offset(stp_d0, frame_size).is_some());

        // STR X17, [SP, #0xc8] — offset 0xc8=200, new 0xf8=248
        let str_c8 = 0xF900_0000 | (25u32 << 10) | (31u32 << 5) | 17;
        assert!(adjust_sp_relative_offset(str_c8, frame_size).is_some());

        // LDR X17, [SP, #0xc8] — offset 0xc8=200, new 0xf8=248
        let ldr_c8 = 0xF940_0000 | (25u32 << 10) | (31u32 << 5) | 17;
        assert!(adjust_sp_relative_offset(ldr_c8, frame_size).is_some());

        // STP X17, X16, [SP, #0x70] — offset 0x70=112, new 0xa0=160
        let stp_70 = 0xA900_0000 | (14u32 << 15) | (16u32 << 10) | (31u32 << 5) | 17;
        assert!(adjust_sp_relative_offset(stp_70, frame_size).is_some());
    }

    // ============================================================
    // Tests for needs_sp_fixup
    // ============================================================

    #[test]
    fn test_needs_sp_fixup_ldp_w_overflow() {
        // LDP W17, W8, [SP, #240] — the exact instruction from libc.so.6 at 0xa9f00
        // opc=00 (32-bit), imm7=60 (240/4), Rt2=8, Rn=SP(31), Rt=17
        // After +48: 288/4 = 72 > 63 (imm7 max), so needs SP fixup
        let insn: u32 = 0x295e23f1; // LDP W17, W8, [SP, #240]
        // After x18→x17 rewrite, x18 is not present in this encoding (it's W17, W8)
        // but the instruction has Rn=SP and would overflow
        assert!(
            needs_sp_fixup(insn, 48),
            "LDP W17, W8, [SP, #240] should need SP fixup (imm7 overflow)"
        );
    }

    #[test]
    fn test_needs_sp_fixup_stp_x_no_overflow() {
        // STP X4, X17, [SP, #0xb8] — fits after +48 (imm7 goes from 23 to 29)
        let insn = 0xA900_0000 | (23u32 << 15) | (17u32 << 10) | (31u32 << 5) | 4;
        assert!(
            !needs_sp_fixup(insn, 48),
            "STP X4, X17, [SP, #0xb8] should NOT need SP fixup"
        );
    }

    #[test]
    fn test_needs_sp_fixup_stp_x_overflow() {
        // STP X4, X17, [SP, #0x1F0]: imm7=62, after +48: 68 > 63
        let insn = 0xA900_0000 | (62u32 << 15) | (17u32 << 10) | (31u32 << 5) | 4;
        assert!(
            needs_sp_fixup(insn, 48),
            "STP X4, X17, [SP, #0x1F0] should need SP fixup (imm7 overflow)"
        );
    }

    #[test]
    fn test_needs_sp_fixup_add_sp_returns_false() {
        // ADD X17, SP, #8 — not a memory op, doesn't need fixup
        let insn: u32 = 0x910023F1;
        assert!(
            !needs_sp_fixup(insn, 48),
            "ADD X17, SP should NOT need SP fixup (not memory op)"
        );
    }

    #[test]
    fn test_needs_sp_fixup_non_sp_returns_false() {
        // LDR X17, [X0, #8] — not SP-relative
        let insn = 0xF940_0000 | (1u32 << 10) | (0u32 << 5) | 17;
        assert!(
            !needs_sp_fixup(insn, 48),
            "LDR X17, [X0, #8] should NOT need SP fixup (not SP-relative)"
        );
    }

    #[test]
    fn test_x18_gate_size_with_sp_fixup() {
        // SP fixup adds 2 instructions (8 bytes) to each gate type
        assert_eq!(
            x18_gate_size(TargetOs::MacOs, true, false, true),
            (TargetOs::MacOs.x18_gate_read_insn_count() + 2) * 4,
            "read-only gate with SP fixup"
        );
        assert_eq!(
            x18_gate_size(TargetOs::MacOs, false, true, true),
            (TargetOs::MacOs.x18_gate_write_insn_count() + 2) * 4,
            "write-only gate with SP fixup"
        );
        assert_eq!(
            x18_gate_size(TargetOs::MacOs, true, true, true),
            (TargetOs::MacOs.x18_gate_readwrite_insn_count() + 2) * 4,
            "read-write gate with SP fixup"
        );
    }

    #[test]
    fn test_needs_sp_fixup_ldp_w_near_max() {
        // LDP W registers with imm7 = 63 (max), offset = 252
        // After +48: 300/4 = 75 > 63, needs fixup
        let insn: u32 = 0x2940_0000 | (63u32 << 15) | (8u32 << 10) | (31u32 << 5) | 17;
        assert!(
            needs_sp_fixup(insn, 48),
            "LDP W at max imm7 should need SP fixup"
        );
    }

    #[test]
    fn test_needs_sp_fixup_ldp_w_just_fits() {
        // LDP W registers with imm7 = 51, offset = 204
        // After +48: 252/4 = 63, exactly at max — should fit
        let insn: u32 = 0x2940_0000 | (51u32 << 15) | (8u32 << 10) | (31u32 << 5) | 17;
        assert!(
            !needs_sp_fixup(insn, 48),
            "LDP W with imm7=51 should NOT need SP fixup (63 fits)"
        );
    }

    // ============================================================
    // Tests for x18 gate NZCV ordering
    // ============================================================

    /// Helper: emit an x18 gate and return the instruction words.
    /// Creates a trampoline buffer with enough padding for the shared handler offsets,
    /// then emits the gate at the correct offset.
    fn emit_x18_gate_helper(
        rewritten: u32,
        scratch: u8,
        is_read: bool,
        is_write: bool,
        sp_fixup: bool,
    ) -> Vec<u32> {
        let trampoline_base: u64 = 0x10000;
        let gate_offset = TargetOs::MacOs.shared_x18_save_handler_offset()
            + TargetOs::MacOs.shared_x18_save_handler_size();

        let site = PatchSite {
            file_offset: 0,
            vaddr: 0x1000,
            kind: PatchKind::X18Use {
                insn: 0,
                rewritten,
                scratch,
                is_read,
                is_write,
                needs_sp_fixup: sp_fixup,
            },
        };

        // Pad the trampoline buffer to gate_offset
        let mut td = vec![0u8; gate_offset];
        emit_x18_gate(
            &mut td,
            gate_offset,
            trampoline_base,
            &site,
            rewritten,
            scratch,
            is_read,
            is_write,
            sp_fixup,
            TargetOs::MacOs,
        )
        .unwrap();

        // Extract instructions from the gate
        let gate_bytes = &td[gate_offset..];
        gate_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn test_x18_gate_nzcv_restore_before_instruction_read_only() {
        // CMP X16, X4 — a flag-setting instruction (after x18→X16 rewrite).
        // Encoding: SUBS XZR, X16, X4 → 0xEB04021F
        let cmp_x16_x4: u32 = 0xEB04_021F;
        let insns = emit_x18_gate_helper(cmp_x16_x4, 16, true, false, false);

        let msr_nzcv_x16 = encode_msr_nzcv(16); // MSR NZCV, X16
        let mrs_nzcv_x16 = encode_mrs_nzcv(16); // MRS X16, NZCV

        // Find the position of the rewritten instruction (CMP)
        let cmp_pos = insns
            .iter()
            .position(|&i| i == cmp_x16_x4)
            .expect("CMP instruction not found in gate");

        // Find the position of MSR NZCV, X16 (restore)
        let msr_pos = insns
            .iter()
            .position(|&i| i == msr_nzcv_x16)
            .expect("MSR NZCV, X16 not found in gate");

        // Find MRS NZCV, X16 (save) — should be in prologue
        let mrs_pos = insns
            .iter()
            .position(|&i| i == mrs_nzcv_x16)
            .expect("MRS X16, NZCV not found in gate");

        // The NZCV restore (MSR) must come BEFORE the rewritten instruction (CMP),
        // NOT after. This ensures the CMP's flag output survives to the caller.
        assert!(
            msr_pos < cmp_pos,
            "NZCV restore (MSR at idx {msr_pos}) must come BEFORE the rewritten \
             instruction (CMP at idx {cmp_pos}). The gate must not destroy flag-setting results."
        );

        // The NZCV save (MRS) must come before the restore
        assert!(mrs_pos < msr_pos, "NZCV save must come before restore");
    }

    #[test]
    fn test_x18_gate_nzcv_restore_before_instruction_write_only() {
        // LDR W16, [X5, #8] — a write-to-x18 instruction (after x18→X16 rewrite).
        // Encoding: LDR W16, [X5, #8] → 0xB94008B0
        let ldr_w16: u32 = 0xB940_08B0;
        let insns = emit_x18_gate_helper(ldr_w16, 16, false, true, false);

        let msr_nzcv_x16 = encode_msr_nzcv(16);

        let ldr_pos = insns
            .iter()
            .position(|&i| i == ldr_w16)
            .expect("LDR instruction not found in gate");

        let msr_pos = insns
            .iter()
            .position(|&i| i == msr_nzcv_x16)
            .expect("MSR NZCV, X16 not found in gate");

        assert!(
            msr_pos < ldr_pos,
            "NZCV restore (MSR at idx {msr_pos}) must come BEFORE the rewritten \
             instruction (LDR at idx {ldr_pos})."
        );
    }

    #[test]
    fn test_x18_gate_nzcv_restore_before_instruction_readwrite() {
        // ADD X16, X16, X4 — a read-write instruction (after x18→X16 rewrite).
        // Encoding: ADD X16, X16, X4 → 0x8B040210
        let add_x16: u32 = 0x8B04_0210;
        let insns = emit_x18_gate_helper(add_x16, 16, true, true, false);

        let msr_nzcv_x16 = encode_msr_nzcv(16);

        let add_pos = insns
            .iter()
            .position(|&i| i == add_x16)
            .expect("ADD instruction not found in gate");

        let msr_pos = insns
            .iter()
            .position(|&i| i == msr_nzcv_x16)
            .expect("MSR NZCV, X16 not found in gate");

        assert!(
            msr_pos < add_pos,
            "NZCV restore (MSR at idx {msr_pos}) must come BEFORE the rewritten \
             instruction (ADD at idx {add_pos})."
        );
    }

    #[test]
    fn test_x18_gate_no_nzcv_restore_after_instruction_read_only() {
        // Verify there is NO MSR NZCV after the rewritten instruction.
        // This ensures the guest instruction's flag output survives.
        let cmp_x16_x4: u32 = 0xEB04_021F;
        let insns = emit_x18_gate_helper(cmp_x16_x4, 16, true, false, false);

        let msr_nzcv_x16 = encode_msr_nzcv(16);

        let cmp_pos = insns
            .iter()
            .position(|&i| i == cmp_x16_x4)
            .expect("CMP instruction not found in gate");

        let nzcv_restores_after = insns[cmp_pos + 1..]
            .iter()
            .filter(|&&i| i == msr_nzcv_x16)
            .count();

        assert_eq!(
            nzcv_restores_after, 0,
            "There must be NO NZCV restore (MSR NZCV, X16) after the rewritten instruction. \
             Found {nzcv_restores_after} instance(s) that would destroy the instruction's flag output."
        );
    }
}
