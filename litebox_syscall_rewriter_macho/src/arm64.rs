// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 Mach-O syscall rewriting.

use crate::{Error, Result};

/// Write a `u32` in little-endian to `dst[0..4]` using volatile stores.
///
/// This avoids calling `memcpy` (which may live on non-executable shared
/// cache pages during copy-and-patch).
#[inline]
unsafe fn volatile_write_le_u32(dst: *mut u8, val: u32) {
    let bytes = val.to_le_bytes();
    unsafe {
        core::ptr::write_volatile(dst, bytes[0]);
        core::ptr::write_volatile(dst.add(1), bytes[1]);
        core::ptr::write_volatile(dst.add(2), bytes[2]);
        core::ptr::write_volatile(dst.add(3), bytes[3]);
    }
}

/// Write a `u64` in little-endian to `dst[0..8]` using volatile stores.
#[inline]
unsafe fn volatile_write_le_u64(dst: *mut u8, val: u64) {
    let bytes = val.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        unsafe {
            core::ptr::write_volatile(dst.add(i), bytes[i]);
        }
        i += 1;
    }
}

/// Copy `src[0..len]` to `dst[0..len]` using volatile byte stores.
#[inline]
unsafe fn volatile_copy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        unsafe {
            core::ptr::write_volatile(dst.add(i), core::ptr::read(src.add(i)));
        }
        i += 1;
    }
}

/// `SVC #0x80` encoding: 0xD4001001
pub const SVC_0X80: u32 = 0xD4001001;

/// `DMB ISH` (data memory barrier, inner shareable) encoding.
///
/// Ensures that all preceding data memory accesses from any core in the
/// inner shareable domain are visible before any subsequent data memory
/// accesses. Used in the shared SVC handler to guarantee that TLS table
/// stores from `update_host_tls_entry` (which uses atomic compare-exchange)
/// are visible to the handler's plain LDR loads on different cores.
const DMB_ISH: u32 = 0xD503_3BBF;

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
///
/// # Panics
///
/// Panics if a 4-byte slice cannot be converted to `[u8; 4]`, which cannot
/// happen because the loop only reads when at least 4 bytes remain.
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
pub fn encode_b(offset: i64) -> Option<u32> {
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
pub fn encode_adrp(rd: u8, page_offset: i64) -> Option<u32> {
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
pub fn encode_sub_sp_imm(imm12: u16) -> Option<u32> {
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
pub fn encode_str_imm_unsigned(rt: u8, rn: u8, imm_bytes: u16) -> Option<u32> {
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
pub fn encode_add_imm(rd: u8, rn: u8, imm12: u16) -> Option<u32> {
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
#[allow(dead_code)]
fn encode_brk(imm16: u16) -> u32 {
    0xD420_0000 | (u32::from(imm16) << 5)
}

/// Encode `STP Xt1, Xt2, [Xn, #imm]` (store pair, 64-bit, signed offset).
///
/// The offset must be a multiple of 8 and within [-512, 504].
pub fn encode_stp_offset(rt: u8, rt2: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
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

/// Encode `LDP Xt1, Xt2, [Xn, #imm]` (load pair, 64-bit, signed offset).
///
/// The offset must be a multiple of 8 and within [-512, 504].
fn encode_ldp_offset(rt: u8, rt2: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
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
        0xA940_0000
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
const SHARED_SVC_HANDLER_INSN_COUNT: usize = 28;

/// Size of the shared SVC handler in bytes.
pub const SHARED_SVC_HANDLER_SIZE: usize = SHARED_SVC_HANDLER_INSN_COUNT * 4;

/// Offset where the shared SVC handler begins in the trampoline.
pub const SHARED_SVC_HANDLER_OFFSET: usize = 16; // After 8-byte callback + 8-byte TLS ptr

/// Number of instructions in each SVC gate.
const SVC_GATE_INSN_COUNT: usize = 7;

/// Size of each SVC gate in bytes.
pub const SVC_GATE_SIZE: usize = SVC_GATE_INSN_COUNT * 4;

// ============================================================
// Trampoline emission
// ============================================================

/// Emit the shared SVC handler for macOS.
///
/// This handler performs TLS lookup via TPIDRRO_EL0, then jumps to the
/// syscall callback. It is shared by all SVC gates.
///
/// Layout (28 instructions, 112 bytes):
/// ```text
/// [0]  MRS  X17, TPIDRRO_EL0      ; per-thread key
/// [1]  LDR  X16, [PC, #off]       ; X16 = TLS table base
/// [2]  DMB  ISH                    ; ensure cross-core TLS stores visible
/// [3]  STR  X9,  [SP, #24]        ; save X9 (frame slot reused)
/// [4]  .Lloop: LDR X9, [X16, #0]  ; entry key
/// [5]  CMN  X9, #1                ; sentinel?
/// [6]  B.EQ .Lpassthrough [20]
/// [7]  CMP  X9, X17               ; match?
/// [8]  B.EQ .Lfound [11]
/// [9]  ADD  X16, X16, #16
/// [10] B    .Lloop [4]
/// [11] .Lfound: LDR X9, [SP, #24] ; restore X9
/// [12] LDR  X16, [X16, #8]        ; TCB pointer
/// [13] LDR  X17, [X16, #24]       ; guest_tpidr
/// [14] STR  X17, [SP, #24]        ; frame[24] = guest_tpidr
/// [15] LDR  X17, [SP, #32]        ; guest_x18
/// [16] STR  X17, [X16, #40]       ; TCB.guest_x18
/// [17] STR  X16, [SP, #40]        ; host_tls → frame
/// [18] LDR  X16, [PC, #off]       ; callback addr
/// [19] BR   X16                    ; jump to callback
/// -- PASSTHROUGH (TLS scan hit sentinel) --
/// [20] LDR  X9,  [SP, #24]        ; restore X9
/// [21] STR  X30, [SP, #24]        ; stash return addr
/// [22] LDP  X16, X17, [SP]        ; restore orig x16, x17
/// [23] LDR  X30, [SP, #16]        ; restore LR
/// [24] SVC  #0x80                 ; real syscall
/// [25] LDR  X16, [SP, #24]        ; load return addr
/// [26] ADD  SP, SP, #48           ; undo gate frame
/// [27] BR   X16                   ; return
/// ```
/// # Panics
///
/// Panics if encoding helpers (`encode_ldr_imm_unsigned`, `encode_cmn_imm`,
/// etc.) fail on hardcoded constants that are always valid.
#[allow(clippy::cast_possible_wrap)]
pub fn emit_shared_svc_handler_macos(
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

    // [2] DMB ISH — data memory barrier (inner shareable).
    // Ensures that TLS table stores from other cores (via
    // `update_host_tls_entry` using AtomicU64 compare_exchange) are
    // visible to the plain LDR loads in the TLS scan loop below.
    // Without this barrier, a spawned thread running on a different core
    // can see stale (sentinel) values in the TLS table even though Rust
    // has already written its entry.
    trampoline_data.extend_from_slice(&DMB_ISH.to_le_bytes());
    insn_idx += 1;

    // [3] STR X9, [SP, #24] — save X9 (frame[24] is unused during TLS scan)
    // Using X9 instead of X18 for TLS key scan: XNU zeros X18 on EVERY
    // kernel→userspace transition (preemptive context switches via FIQ timer),
    // not just signal delivery. Even though the scan loop is only ~4 instructions,
    // on Apple Silicon the FIQ preemption timer can fire at any instruction
    // boundary, leaving X18=0 mid-scan and causing the TLS lookup to fail.
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(9, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [4] .Lloop: LDR X9, [X16, #0]
    let loop_idx = insn_idx;
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(9, 16, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [5] CMN X9, #1
    trampoline_data.extend_from_slice(&encode_cmn_imm(9, 1).expect("imm12=1 fits").to_le_bytes());
    insn_idx += 1;

    // [6] B.EQ .Lpassthrough -> [20]
    let trap_idx = 20usize;
    let beq_trap_offset = (trap_idx as i64 - insn_idx as i64) * 4;
    let beq_trap = encode_b_cond(COND_EQ, beq_trap_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_trap_offset:#x} out of range in macOS shared SVC handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_trap.to_le_bytes());
    insn_idx += 1;

    // [7] CMP X9, X17
    trampoline_data.extend_from_slice(&encode_cmp_reg(9, 17).to_le_bytes());
    insn_idx += 1;

    // [8] B.EQ .Lfound -> [11]
    let found_idx = 11usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(format!(
            "B.EQ offset {beq_found_offset:#x} out of range in macOS shared SVC handler"
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_found.to_le_bytes());
    insn_idx += 1;

    // [9] ADD X16, X16, #16
    trampoline_data.extend_from_slice(
        &encode_add_imm(16, 16, 16)
            .expect("imm12=16 fits")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [10] B .Lloop -> [4]
    let b_loop_offset = (loop_idx as i64 - insn_idx as i64) * 4;
    let b_loop = encode_b(b_loop_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(format!(
            "B offset {b_loop_offset:#x} out of range in macOS shared SVC handler loop"
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [11] .Lfound: LDR X9, [SP, #24] — restore X9
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(9, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [12] LDR X16, [X16, #8] — X16 = TCB pointer
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 16, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [13] LDR X17, [X16, #24]
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 16, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [14] STR X17, [SP, #24]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(17, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [15] LDR X17, [SP, #32]
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 31, 32)
            .expect("offset 32 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [16] STR X17, [X16, #40]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(17, 16, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [17] STR X16, [SP, #40]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 40)
            .expect("offset 40 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [18] LDR X16, [PC, #offset_to_callback]
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

    // [19] BR X16
    trampoline_data.extend_from_slice(&encode_br(16).to_le_bytes());
    insn_idx += 1;

    // [20] .Lpassthrough: LDR X9, [SP, #24] — restore X9
    debug_assert_eq!(insn_idx, trap_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(9, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [21] STR X30, [SP, #24] — stash return addr
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [22] LDP X16, X17, [SP] — restore original x16 (syscall#), x17
    trampoline_data.extend_from_slice(
        &encode_ldp_offset(16, 17, 31, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [23] LDR X30, [SP, #16] — restore caller's LR
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 16)
            .expect("offset 16 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [24] SVC #0x80 — execute real syscall on host
    trampoline_data.extend_from_slice(&SVC_0X80.to_le_bytes());
    insn_idx += 1;

    // [25] LDR X16, [SP, #24] — load stashed return addr
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [26] ADD SP, SP, #48 — undo gate's SUB SP, SP, #48
    trampoline_data.extend_from_slice(
        &encode_add_imm(31, 31, 48)
            .expect("imm12=48 fits")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [27] BR X16 — return to instruction after original SVC
    trampoline_data.extend_from_slice(&encode_br(16).to_le_bytes());
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
/// # Panics
///
/// Panics if encoding helpers (`encode_sub_sp_imm`, `encode_stp_offset`)
/// fail on hardcoded constants that are always valid.
#[allow(clippy::cast_possible_wrap)]
pub fn emit_svc_gate_macos(
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

/// Scan a code buffer for `SVC #0x80` instructions and return their locations.
///
/// This function allocates a `Vec<PatchSite>`.  Call it **before** replacing
/// shared cache pages (while `malloc` still works), then pass the result to
/// [`patch_code_segment_prescan`] which is allocation-free.
///
/// # Panics
///
/// Panics if `code.len()` is not aligned to 4 bytes (each instruction is 4
/// bytes on AArch64).
pub fn scan_svc_sites(code: &[u8], code_vaddr: u64) -> Vec<PatchSite> {
    let estimated = code.len() / 64;
    let mut sites = Vec::with_capacity(estimated);
    let mut off = 0usize;
    while off + 4 <= code.len() {
        let insn = u32::from_le_bytes(code[off..off + 4].try_into().unwrap());
        if insn == SVC_0X80 {
            sites.push(PatchSite {
                file_offset: off,
                vaddr: code_vaddr + off as u64,
                kind: PatchKind::Svc,
            });
        }
        off += 4;
    }
    sites
}

/// Emit the shared SVC handler directly into a fixed-size `&mut [u8]` slice.
///
/// This is the allocation-free counterpart of [`emit_shared_svc_handler_macos`].
/// The caller must ensure `out.len() >= SHARED_SVC_HANDLER_SIZE`.
///
/// Returns `Ok(SHARED_SVC_HANDLER_SIZE)` on success.
#[allow(clippy::cast_possible_wrap)]
fn emit_shared_svc_handler_to_slice(
    out: &mut [u8],
    handler_vaddr: u64,
    trampoline_base_addr: u64,
) -> crate::Result<usize> {
    if out.len() < SHARED_SVC_HANDLER_SIZE {
        return Err(crate::Error::ParseError("handler slice too small".into()));
    }
    let mut pos = 0usize;
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { handler_vaddr + (idx as u64) * 4 };
    let tls_table_vaddr = trampoline_base_addr + HEADER_TLS_TABLE_OFFSET as u64;

    macro_rules! emit {
        ($insn:expr) => {{
            // Use volatile write to avoid calling memcpy (which may be on
            // non-executable shared cache pages during copy-and-patch).
            unsafe {
                volatile_write_le_u32(out.as_mut_ptr().add(pos), $insn);
            }
            pos += 4;
            insn_idx += 1;
        }};
    }

    // [0] MRS X17, TPIDRRO_EL0
    emit!(encode_mrs_tpidrro_el0(17));
    // [1] LDR X16, [PC, #offset] — X16 = TLS table base
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let ldr_tls_offset = tls_table_vaddr as i64 - ldr_tls_vaddr as i64;
    let ldr_tls_insn = encode_ldr_literal(16, ldr_tls_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(
            "LDR literal out of range for shared SVC handler TLS load".into(),
        )
    })?;
    emit!(ldr_tls_insn);
    // [2] DMB ISH — ensure cross-core TLS stores visible
    emit!(DMB_ISH);
    // [3] STR X9, [SP, #24] — save X9 (frame[24] is unused during TLS scan)
    // Using X9 instead of X18 for TLS key scan: XNU zeros X18 on EVERY
    // kernel→userspace transition (preemptive context switches via FIQ timer).
    emit!(encode_str_imm_unsigned(9, 31, 24).expect("offset 24 valid"));
    // [4] .Lloop: LDR X9, [X16, #0]
    let loop_idx = insn_idx;
    emit!(encode_ldr_imm_unsigned(9, 16, 0).expect("offset 0 valid"));
    // [5] CMN X9, #1
    emit!(encode_cmn_imm(9, 1).expect("imm12=1 fits"));
    // [6] B.EQ .Lpassthrough -> [20]
    let trap_idx = 20usize;
    let beq_trap_offset = (trap_idx as i64 - insn_idx as i64) * 4;
    let beq_trap = encode_b_cond(COND_EQ, beq_trap_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure("B.EQ offset out of range in shared SVC handler".into())
    })?;
    emit!(beq_trap);
    // [7] CMP X9, X17
    emit!(encode_cmp_reg(9, 17));
    // [8] B.EQ .Lfound -> [11]
    let found_idx = 11usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure("B.EQ offset out of range in shared SVC handler".into())
    })?;
    emit!(beq_found);
    // [9] ADD X16, X16, #16
    emit!(encode_add_imm(16, 16, 16).expect("imm12=16 fits"));
    // [10] B .Lloop -> [4]
    let b_loop_offset = (loop_idx as i64 - insn_idx as i64) * 4;
    let b_loop = encode_b(b_loop_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure("B offset out of range in shared SVC handler loop".into())
    })?;
    emit!(b_loop);
    // [11] .Lfound: LDR X9, [SP, #24] — restore X9
    debug_assert_eq!(insn_idx, found_idx);
    emit!(encode_ldr_imm_unsigned(9, 31, 24).expect("offset 24 valid"));
    // [12] LDR X16, [X16, #8] — X16 = TCB pointer
    emit!(encode_ldr_imm_unsigned(16, 16, 8).expect("offset 8 valid"));
    // [13] LDR X17, [X16, #24]
    emit!(encode_ldr_imm_unsigned(17, 16, 24).expect("offset 24 valid"));
    // [14] STR X17, [SP, #24]
    emit!(encode_str_imm_unsigned(17, 31, 24).expect("offset 24 valid"));
    // [15] LDR X17, [SP, #32]
    emit!(encode_ldr_imm_unsigned(17, 31, 32).expect("offset 32 valid"));
    // [16] STR X17, [X16, #40]
    emit!(encode_str_imm_unsigned(17, 16, 40).expect("offset 40 valid"));
    // [17] STR X16, [SP, #40]
    emit!(encode_str_imm_unsigned(16, 31, 40).expect("offset 40 valid"));
    // [18] LDR X16, [PC, #offset_to_callback]
    let ldr_cb_vaddr = insn_vaddr(insn_idx);
    let callback_vaddr = trampoline_base_addr + HEADER_CALLBACK_OFFSET as u64;
    let ldr_cb_offset = callback_vaddr as i64 - ldr_cb_vaddr as i64;
    let ldr_cb_insn = encode_ldr_literal(16, ldr_cb_offset).ok_or_else(|| {
        crate::Error::DisassemblyFailure(
            "LDR literal out of range for shared SVC handler callback".into(),
        )
    })?;
    emit!(ldr_cb_insn);
    // [19] BR X16
    emit!(encode_br(16));
    // [20] .Lpassthrough: LDR X9, [SP, #24] — restore X9
    debug_assert_eq!(insn_idx, trap_idx);
    emit!(encode_ldr_imm_unsigned(9, 31, 24).expect("offset 24 valid"));
    // [21] STR X30, [SP, #24] — stash return addr
    emit!(encode_str_imm_unsigned(30, 31, 24).expect("offset 24 valid"));
    // [22] LDP X16, X17, [SP] — restore original x16 (syscall#), x17
    emit!(encode_ldp_offset(16, 17, 31, 0).expect("offset 0 valid"));
    // [23] LDR X30, [SP, #16] — restore caller's LR
    emit!(encode_ldr_imm_unsigned(30, 31, 16).expect("offset 16 valid"));
    // [24] SVC #0x80 — execute real syscall on host
    emit!(SVC_0X80);
    // [25] LDR X16, [SP, #24] — load stashed return addr
    emit!(encode_ldr_imm_unsigned(16, 31, 24).expect("offset 24 valid"));
    // [26] ADD SP, SP, #48 — undo gate's SUB SP, SP, #48
    emit!(encode_add_imm(31, 31, 48).expect("imm12=48 fits"));
    // [27] BR X16 — return to instruction after original SVC
    emit!(encode_br(16));

    debug_assert_eq!(insn_idx, SHARED_SVC_HANDLER_INSN_COUNT);
    debug_assert_eq!(pos, SHARED_SVC_HANDLER_SIZE);

    Ok(pos)
}

/// Patch SVC sites using a pre-scanned site list.  **Allocation-free.**
///
/// This function must be called when `malloc` may not work (e.g. after
/// `mmap(MAP_FIXED)` has replaced shared cache code pages with RW pages).
/// All error returns use static strings (no `format!`).
///
/// `sites` — pre-scanned by [`scan_svc_sites`].
/// `code`  — the (now-RW) code region with original content restored.
/// `code_vaddr` — virtual address of the start of `code` (used only for
///   computing `offset_in_code` from `PatchSite::vaddr`; pass the same
///   value used when scanning).
///
/// # Panics
///
/// Panics if internal instruction encoding helpers fail on values that are
/// statically guaranteed to fit (e.g. `encode_sub_sp_imm(48)`).
///
/// Returns the updated trampoline cursor.
#[allow(clippy::cast_possible_wrap)]
pub fn patch_code_segment_prescan(
    code: &mut [u8],
    trampoline: &mut [u8],
    trampoline_vaddr: u64,
    mut cursor: usize,
    syscall_entry: u64,
    sites: &[PatchSite],
) -> crate::Result<usize> {
    if sites.is_empty() {
        return Ok(cursor);
    }

    // If header not yet written (cursor == 0), write header + shared handler.
    if cursor == 0 {
        if trampoline.len() < SHARED_SVC_HANDLER_OFFSET + SHARED_SVC_HANDLER_SIZE {
            return Err(crate::Error::ParseError(
                "trampoline too small for header + shared handler".into(),
            ));
        }
        // Write syscall entry callback address at offset 0
        unsafe {
            volatile_write_le_u64(trampoline.as_mut_ptr(), syscall_entry);
        }
        // TLS table ptr at offset 8 — left as zero, caller fills it in.

        // Emit shared handler directly into the trampoline slice.
        let handler_vaddr = trampoline_vaddr + SHARED_SVC_HANDLER_OFFSET as u64;
        emit_shared_svc_handler_to_slice(
            &mut trampoline
                [SHARED_SVC_HANDLER_OFFSET..SHARED_SVC_HANDLER_OFFSET + SHARED_SVC_HANDLER_SIZE],
            handler_vaddr,
            trampoline_vaddr,
        )?;
        cursor = SHARED_SVC_HANDLER_OFFSET + SHARED_SVC_HANDLER_SIZE;
    }

    // Emit per-site SVC gates — pure computation, no allocations.
    for site in sites {
        let gate_vaddr = trampoline_vaddr + cursor as u64;
        let return_addr = site.vaddr + 4;

        // Build the 7-instruction gate directly into a fixed buffer.
        // Use volatile writes to avoid memcpy calls (memcpy may be on
        // non-executable shared cache pages during copy-and-patch).
        let mut gate = [0u8; SVC_GATE_SIZE];
        let gp = gate.as_mut_ptr();

        // [0] SUB SP, SP, #48
        unsafe {
            volatile_write_le_u32(gp, encode_sub_sp_imm(48).expect("imm12=48 fits"));
        }
        // [1] STP X16, X17, [SP]
        unsafe {
            volatile_write_le_u32(
                gp.add(4),
                encode_stp_offset(16, 17, 31, 0).expect("offset 0 valid"),
            );
        }
        // [2] STR X30, [SP, #16]
        unsafe {
            volatile_write_le_u32(
                gp.add(8),
                encode_str_imm_unsigned(30, 31, 16).expect("offset 16 valid"),
            );
        }
        // [3] STR X18, [SP, #32]
        unsafe {
            volatile_write_le_u32(
                gp.add(12),
                encode_str_imm_unsigned(18, 31, 32).expect("offset 32 valid"),
            );
        }
        // [4] ADRP X30, <return_page>
        let adrp_vaddr_val = gate_vaddr + 4 * 4;
        let adrp_base = adrp_vaddr_val & !0xFFF;
        let return_page = return_addr & !0xFFF;
        let page_offset = (return_page as i64 - adrp_base as i64) >> 12;
        let adrp_insn = encode_adrp(30, page_offset).ok_or_else(|| {
            crate::Error::DisassemblyFailure("ADRP out of range for SVC gate".into())
        })?;
        unsafe {
            volatile_write_le_u32(gp.add(16), adrp_insn);
        }
        // [5] ADD X30, X30, #pageoff
        let pageoff = (return_addr & 0xFFF) as u16;
        unsafe {
            volatile_write_le_u32(
                gp.add(20),
                encode_add_imm(30, 30, pageoff).expect("page offset fits imm12"),
            );
        }
        // [6] B <shared_svc_handler>
        let handler_vaddr = trampoline_vaddr + SHARED_SVC_HANDLER_OFFSET as u64;
        let b_to_handler = handler_vaddr as i64 - (gate_vaddr + 6 * 4) as i64;
        let b_insn = encode_b(b_to_handler).ok_or_else(|| {
            crate::Error::DisassemblyFailure("B to handler out of range for SVC gate".into())
        })?;
        unsafe {
            volatile_write_le_u32(gp.add(24), b_insn);
        }

        // Copy gate into trampoline
        if cursor + SVC_GATE_SIZE > trampoline.len() {
            return Err(crate::Error::ParseError(
                "trampoline buffer too small for gate".into(),
            ));
        }
        unsafe {
            volatile_copy(
                trampoline.as_mut_ptr().add(cursor),
                gate.as_ptr(),
                SVC_GATE_SIZE,
            );
        }

        // Patch original SVC → B <gate>
        let b_offset = gate_vaddr as i64 - site.vaddr as i64;
        let b_to_gate = encode_b(b_offset).ok_or_else(|| {
            crate::Error::DisassemblyFailure("B offset out of ±128MB for SVC patch".into())
        })?;
        unsafe {
            volatile_write_le_u32(code.as_mut_ptr().add(site.file_offset), b_to_gate);
        }

        cursor += SVC_GATE_SIZE;
    }

    Ok(cursor)
}
