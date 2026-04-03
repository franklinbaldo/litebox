// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 Mach-O syscall rewriting.

use crate::{Error, Result};

/// `SVC #0x80` encoding: 0xD4001001
pub const SVC_0X80: u32 = 0xD4001001;

/// Metadata for an executable section in the Mach-O.
#[derive(Debug)]
pub struct TextSectionInfo {
    /// Virtual address of the section.
    pub vaddr: u64,
    /// File offset of the section.
    pub file_offset: usize,
    /// Size of the section in bytes.
    pub size: usize,
}

/// A site in the binary that needs patching.
#[derive(Debug)]
pub struct PatchSite {
    /// File offset of the instruction.
    pub file_offset: usize,
    /// Virtual address of the instruction.
    pub vaddr: u64,
    /// Kind of patch (used for diagnostics / future expansion).
    #[allow(dead_code)]
    pub kind: PatchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchKind {
    /// `SVC #0x80` — BSD syscall.
    Svc,
}

/// Find all patch sites in the given executable sections.
pub fn find_patch_sites(text_sections: &[TextSectionInfo], buf: &[u8]) -> Result<Vec<PatchSite>> {
    let mut sites = Vec::new();
    for section in text_sections {
        let start = section.file_offset;
        let end = start + section.size;
        if end > buf.len() {
            return Err(Error::ParseError(format!(
                "section at offset {start:#x} extends past end of file"
            )));
        }
        // Walk 4 bytes at a time
        let mut offset = start;
        let mut vaddr = section.vaddr;
        while offset + 4 <= end {
            let insn = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
            if insn == SVC_0X80 {
                sites.push(PatchSite {
                    file_offset: offset,
                    vaddr,
                    kind: PatchKind::Svc,
                });
            }
            offset += 4;
            vaddr += 4;
        }
    }
    Ok(sites)
}

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
    Some(0x5800_0000 | (((imm19 as u32) & 0x7_FFFF) << 5) | u32::from(rt))
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
    Some(0x9100_0000 | (u32::from(imm12) << 10) | (u32::from(rn) << 5) | u32::from(rd))
}

/// Encode `CMP Xn, Xm` (64-bit register compare).
///
/// This is an alias for `SUBS XZR, Xn, Xm` (shifted register, no shift).
/// Encoding: sf=1, op=1, S=1, shift=00, Rm, imm6=0, Rn, Rd=XZR(31)
fn encode_cmp_reg(rn: u8, rm: u8) -> u32 {
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
    Some(0x5400_0000 | (((imm19 as u32) & 0x7_FFFF) << 5) | u32::from(cond))
}

/// Condition code for B.EQ (equal, Z==1).
const COND_EQ: u8 = 0x0;

/// Encode `MRS Xt, TPIDRRO_EL0` (read read-only thread pointer register).
fn encode_mrs_tpidrro_el0(rt: u8) -> u32 {
    0xD53B_D060 | u32::from(rt)
}

/// Encode `BRK #imm16` (breakpoint exception).
fn encode_brk(imm16: u16) -> u32 {
    0xD420_0000 | (u32::from(imm16) << 5)
}

/// Encode `STP Xt1, Xt2, [Xn, #imm]` (store pair, 64-bit, signed offset).
///
/// The offset must be a multiple of 8 and within [-512, 504].
fn encode_stp_offset(rt: u8, rt2: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
    if imm_bytes % 8 != 0 {
        return None;
    }
    let imm7 = imm_bytes / 8;
    if !(-64..=63).contains(&imm7) {
        return None;
    }
    #[allow(clippy::cast_sign_loss)]
    let imm7_u = (imm7 as u32) & 0x7F;
    Some(
        0xA900_0000
            | (imm7_u << 15)
            | (u32::from(rt2) << 10)
            | (u32::from(rn) << 5)
            | u32::from(rt),
    )
}

// ============================================================
// Trampoline layout constants
// ============================================================

/// Offset of the callback address in the trampoline header.
pub const HEADER_CALLBACK_OFFSET: usize = 0;

/// Offset of the TLS table pointer in the trampoline header.
pub const HEADER_TLS_TABLE_OFFSET: usize = 8;

/// Number of instructions in the shared SVC handler (macOS).
const SHARED_SVC_HANDLER_INSN_COUNT: usize = 18;

/// Size of the shared SVC handler in bytes.
const SHARED_SVC_HANDLER_SIZE: usize = SHARED_SVC_HANDLER_INSN_COUNT * 4;

/// Offset where the shared SVC handler begins in the trampoline.
const SHARED_SVC_HANDLER_OFFSET: usize = 16; // After 8-byte callback + 8-byte TLS ptr

/// Number of instructions in each SVC gate.
const SVC_GATE_INSN_COUNT: usize = 7;

/// Size of each SVC gate in bytes.
const SVC_GATE_SIZE: usize = SVC_GATE_INSN_COUNT * 4;

// ============================================================
// Trampoline emission
// ============================================================

/// Emit the shared SVC handler for macOS.
///
/// This handler performs TLS lookup via TPIDRRO_EL0, then jumps to the
/// syscall callback. It is shared by all SVC gates.
///
/// Layout (18 instructions, 72 bytes):
/// ```text
/// [0]  MRS  X17, TPIDRRO_EL0      ; per-thread key
/// [1]  LDR  X16, [PC, #off]       ; X16 = TLS table base
/// [2]  .Lloop: LDR X18, [X16, #0] ; entry.tpidrro
/// [3]  CMN  X18, #1               ; sentinel?
/// [4]  B.EQ .Ltrap                ; → [17]
/// [5]  CMP  X18, X17              ; match?
/// [6]  B.EQ .Lfound               ; → [9]
/// [7]  ADD  X16, X16, #16         ; next entry
/// [8]  B    .Lloop                ; → [2]
/// [9]  .Lfound: LDR X16, [X16, #8] ; host_tls
/// [10] LDR  X17, [X16, #24]       ; TCB.guest_tpidr
/// [11] STR  X17, [SP, #24]        ; frame.guest_tpidr
/// [12] LDR  X17, [SP, #32]        ; guest x18 (from gate)
/// [13] STR  X17, [X16, #40]       ; TCB.guest_x18
/// [14] STR  X16, [SP, #40]        ; host_tls → frame
/// [15] LDR  X16, [PC, #off]       ; callback addr
/// [16] BR   X16                   ; jump to callback
/// [17] .Ltrap: BRK #1             ; unreachable
/// ```
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_svc_handler_macos(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
) -> crate::Result<()> {
    let handler_vaddr = trampoline_base_addr + handler_offset as u64;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { handler_vaddr + (idx as u64) * 4 };
    let tls_table_vaddr = trampoline_base_addr + HEADER_TLS_TABLE_OFFSET as u64;

    // [0] MRS X17, TPIDRRO_EL0
    trampoline_data.extend_from_slice(&encode_mrs_tpidrro_el0(17).to_le_bytes());
    insn_idx += 1;

    // [1] LDR X16, [PC, #offset] — X16 = TLS table base
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let ldr_tls_offset = tls_table_vaddr as i64 - ldr_tls_vaddr as i64;
    let ldr_tls_insn = encode_ldr_literal(16, ldr_tls_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_tls_offset:#x} out of range for macOS shared SVC handler TLS load"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_tls_insn.to_le_bytes());
    insn_idx += 1;

    // [2] .Lloop: LDR X18, [X16, #0]
    let loop_idx = insn_idx;
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(18, 16, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [3] CMN X18, #1
    trampoline_data.extend_from_slice(&encode_cmn_imm(18, 1).expect("imm12=1 fits").to_le_bytes());
    insn_idx += 1;

    // [4] B.EQ .Ltrap -> [17]
    let trap_idx = 17usize;
    let beq_trap_offset = (trap_idx as i64 - insn_idx as i64) * 4;
    let beq_trap = encode_b_cond(COND_EQ, beq_trap_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_trap_offset:#x} out of range in macOS shared SVC handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_trap.to_le_bytes());
    insn_idx += 1;

    // [5] CMP X18, X17
    trampoline_data.extend_from_slice(&encode_cmp_reg(18, 17).to_le_bytes());
    insn_idx += 1;

    // [6] B.EQ .Lfound -> [9]
    let found_idx = 9usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_found_offset:#x} out of range in macOS shared SVC handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_found.to_le_bytes());
    insn_idx += 1;

    // [7] ADD X16, X16, #16
    trampoline_data.extend_from_slice(
        &encode_add_imm(16, 16, 16)
            .expect("imm12=16 fits")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [8] B .Lloop -> [2]
    let b_loop_offset = (loop_idx as i64 - insn_idx as i64) * 4;
    let b_loop = encode_b(b_loop_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(format!(
            "B offset {b_loop_offset:#x} out of range in macOS shared SVC handler loop"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [9] .Lfound: LDR X16, [X16, #8]
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 16, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [10] LDR X17, [X16, #24]
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 16, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [11] STR X17, [SP, #24]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(17, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [12] LDR X17, [SP, #32]
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [13] STR X17, [X16, #40]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(17, 16, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [14] STR X16, [SP, #40]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [15] LDR X16, [PC, #offset_to_callback]
    let ldr_cb_vaddr = insn_vaddr(insn_idx);
    let callback_vaddr = trampoline_base_addr + HEADER_CALLBACK_OFFSET as u64;
    let ldr_cb_offset = callback_vaddr as i64 - ldr_cb_vaddr as i64;
    let ldr_cb_insn = encode_ldr_literal(16, ldr_cb_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(format!(
            "LDR literal offset {ldr_cb_offset:#x} out of range for macOS shared SVC handler callback"
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_cb_insn.to_le_bytes());
    insn_idx += 1;

    // [16] BR X16
    trampoline_data.extend_from_slice(&encode_br(16).to_le_bytes());
    insn_idx += 1;

    // [17] .Ltrap: BRK #1
    debug_assert_eq!(insn_idx, trap_idx);
    trampoline_data.extend_from_slice(&encode_brk(1).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, SHARED_SVC_HANDLER_INSN_COUNT);
    debug_assert_eq!(
        trampoline_data.len() - handler_offset,
        SHARED_SVC_HANDLER_SIZE,
        "macOS shared SVC handler size mismatch"
    );

    Ok(())
}

/// Emit a per-site SVC gate for macOS.
///
/// 7 instructions, 28 bytes, 48-byte frame (includes x18 save at [SP+32]).
///
/// ```text
/// [0] SUB  SP, SP, #48            ; 48-byte frame
/// [1] STP  X16, X17, [SP]         ; save X16, X17
/// [2] STR  X30, [SP, #16]         ; save guest LR
/// [3] STR  X18, [SP, #32]         ; save guest x18
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
) -> crate::Result<()> {
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

    // [3] STR X18, [SP, #32]
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
        crate::Error::DisassemblyFailure(format!(
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
    let handler_vaddr = trampoline_base_addr + SHARED_SVC_HANDLER_OFFSET as u64;
    let b_offset = handler_vaddr as i64 - b_vaddr as i64;
    let b_insn = encode_b(b_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(format!(
            "B offset {b_offset:#x} out of range for macOS SVC gate -> shared handler at {:#x}",
            site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&b_insn.to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, SVC_GATE_INSN_COUNT);
    debug_assert_eq!(
        trampoline_data.len() - gate_offset,
        SVC_GATE_SIZE,
        "macOS SVC gate size mismatch"
    );

    Ok(())
}

// ============================================================
// Main rewriting entry point
// ============================================================

/// Rewrite a Mach-O binary's SVC sites and produce trampoline data.
///
/// This function:
/// 1. Finds all SVC #0x80 sites
/// 2. Generates the trampoline (header + shared handler + per-site gates)
/// 3. Patches original SVC instructions to branch to their gates
///
/// Returns the trampoline data that should be appended to the binary.
#[allow(clippy::cast_possible_wrap)]
pub fn hook_syscalls_aarch64(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
) -> crate::Result<Vec<u8>> {
    let sites = find_patch_sites(text_sections, buf)?;
    if sites.is_empty() {
        return Err(crate::Error::NoSvcInstructionsFound);
    }

    let mut trampoline_data = Vec::new();

    // Header: callback addr (0) + TLS table ptr (0) — filled at load time
    trampoline_data.extend_from_slice(&0u64.to_le_bytes()); // offset 0: callback
    trampoline_data.extend_from_slice(&0u64.to_le_bytes()); // offset 8: TLS table

    // Shared SVC handler at offset 16
    let handler_offset = trampoline_data.len();
    debug_assert_eq!(handler_offset, SHARED_SVC_HANDLER_OFFSET);
    emit_shared_svc_handler_macos(&mut trampoline_data, handler_offset, trampoline_base_addr)?;

    // Per-site SVC gates
    for site in &sites {
        let gate_offset = trampoline_data.len();
        emit_svc_gate_macos(
            &mut trampoline_data,
            gate_offset,
            trampoline_base_addr,
            site,
        )?;

        // Patch original SVC #0x80 → B <gate>
        let gate_vaddr = trampoline_base_addr + gate_offset as u64;
        let b_offset = gate_vaddr as i64 - site.vaddr as i64;
        let b_insn = encode_b(b_offset).ok_or_else(|| {
            crate::Error::DisassemblyFailure(format!(
                "B offset {b_offset:#x} out of ±128MB range for SVC at {:#x}",
                site.vaddr
            ))
        })?;
        buf[site.file_offset..site.file_offset + 4].copy_from_slice(&b_insn.to_le_bytes());
    }

    Ok(trampoline_data)
}
