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

/// Number of instructions in each per-SVC trampoline snippet.
///
/// Layout (19 instructions, 76 bytes):
/// ```text
///  [0] SUB SP, SP, #32
///  [1] STR X16, [SP, #0]
///  [2] STR X17, [SP, #8]
///  [3] STR X30, [SP, #16]
///  [4] MRS X18, TPIDR_EL0
///  [5] STR X18, [SP, #24]       ; save guest TPIDR for syscall_callback
///  [6] LDR X17, [PC, #off]     ; TLS table ptr from trampoline offset 8
///  [7] LDR X16, [X17, #0]      ; .Lloop
///  [8] CMN X16, #1
///  [9] B.EQ .Ldone              ; -> [15]
/// [10] CMP X16, X18
/// [11] B.EQ .Lfound             ; -> [14]
/// [12] ADD X17, X17, #16
/// [13] B .Lloop                 ; -> [7]
/// [14] LDR X18, [X17, #8]      ; .Lfound
/// [15] ADRP X30, <return_page>  ; .Ldone
/// [16] ADD X30, X30, #<pageoff> ; return_addr = site.vaddr + 4
/// [17] LDR X16, [PC, #off]     ; callback from trampoline offset 0
/// [18] BR X16
/// ```
const SVC_SNIPPET_INSN_COUNT: usize = 19;

/// Size in bytes of each per-SVC trampoline snippet.
const SVC_SNIPPET_SIZE: usize = SVC_SNIPPET_INSN_COUNT * 4; // 76

/// Number of instructions in each per-MSR TPIDR_EL0 trampoline snippet.
///
/// Layout (24 instructions, 96 bytes):
/// ```text
///  [0] SUB SP, SP, #32
///  [1] STR X16, [SP, #0]
///  [2] STR X17, [SP, #8]
///  [3] STR X30, [SP, #16]
///  [4] <store new TPIDR to [SP, #24]>   ; varies by Xt (insn 1 of 2)
///  [5] <store new TPIDR to [SP, #24]>   ; varies by Xt (insn 2 of 2, may be NOP)
///  [6] MRS X16, TPIDR_EL0              ; X16 = old guest TPIDR
///  [7] LDR X17, [PC, #off]             ; X17 = TLS table ptr
///  [8] LDR X30, [X17, #0]              ; .Lloop: load guest_tpidr
///  [9] CMN X30, #1                     ; sentinel?
/// [10] B.EQ .Ldone                     ; -> [17]
/// [11] CMP X30, X16                    ; match old TPIDR?
/// [12] B.EQ .Lfound                    ; -> [15]
/// [13] ADD X17, X17, #16              ; next entry
/// [14] B .Lloop                        ; -> [8]
/// [15] LDR X30, [SP, #24]             ; .Lfound: new tpidr value
/// [16] STR X30, [X17, #0]             ; update table entry's guest_tpidr
/// [17] LDR X30, [SP, #24]             ; .Ldone: new tpidr value
/// [18] MSR TPIDR_EL0, X30             ; execute actual MSR
/// [19] LDR X30, [SP, #16]             ; restore X30
/// [20] LDR X17, [SP, #8]              ; restore X17
/// [21] LDR X16, [SP, #0]              ; restore X16
/// [22] ADD SP, SP, #32
/// [23] B <return_addr>                 ; branch back
/// ```
const MSR_SNIPPET_INSN_COUNT: usize = 24;

/// Size in bytes of each per-MSR TPIDR_EL0 trampoline snippet.
const MSR_SNIPPET_SIZE: usize = MSR_SNIPPET_INSN_COUNT * 4; // 96

/// ARM64 NOP instruction.
const NOP: u32 = 0xD503201F;

/// Offset of the header region: callback address (8 bytes).
const HEADER_CALLBACK_OFFSET: usize = 0;

/// Offset of the TLS lookup table pointer (8 bytes, filled at load time).
const HEADER_TLS_TABLE_OFFSET: usize = 8;

/// Offset of the sigreturn preamble (8 bytes = 2 instructions: MOV X8, #139; B <sigreturn_snippet>).
#[allow(dead_code)] // Documenting the layout; used by tests
const HEADER_SIGRETURN_OFFSET: usize = 16;

/// Offset where the sigreturn SVC snippet begins (full 76-byte SVC snippet).
/// Called from the sigreturn preamble at offset 16 via `B .+8`.
const SIGRETURN_SNIPPET_OFFSET: usize = 24;

/// Offset where per-site snippets begin (after sigreturn SVC snippet).
const SNIPPETS_START_OFFSET: usize = SIGRETURN_SNIPPET_OFFSET + SVC_SNIPPET_SIZE;

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
/// 1. Scans for SVC #0 instructions in executable sections
/// 2. Builds trampoline code with a sigreturn stub and per-SVC snippets
/// 3. Patches each SVC #0 with a `B` (branch) to its trampoline snippet
///
/// Returns `(trampoline_data, found_any_syscalls)`.
///
/// # Trampoline layout
///
/// ```text
/// Offset 0:     syscall_callback address (8 bytes, initially 0 or provided)
/// Offset 8:     TLS lookup table pointer (8 bytes, initially 0, filled at load time)
/// Offset 16:    Sigreturn trampoline (8 bytes = 2 instructions):
///                 MOV X8, #139     // __NR_rt_sigreturn
///                 SVC #0           // (NOT patched — it's in the trampoline)
/// Offset 24+:   Per-site trampoline snippets:
///                 - SVC sites: 68 bytes each (17 instructions)
///                 - MSR TPIDR_EL0 sites: 96 bytes each (24 instructions)
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
        // No SVC instructions found. Produce a minimal trampoline containing just
        // the callback address slot, TLS table pointer, and the sigreturn preamble.
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
        let b_to_snippet = encode_b(4).expect("offset +4 always valid");
        trampoline_data.extend_from_slice(&b_to_snippet.to_le_bytes());
        // Offset 24: sigreturn SVC snippet (76 bytes)
        let sigret_snippet_vaddr = trampoline_base_addr + SIGRETURN_SNIPPET_OFFSET as u64;
        let sigret_dummy_site = PatchSite {
            file_offset: 0,
            vaddr: sigret_snippet_vaddr,
            kind: PatchKind::Svc,
        };
        emit_svc_snippet(
            &mut trampoline_data,
            sigret_snippet_vaddr,
            SIGRETURN_SNIPPET_OFFSET,
            trampoline_base_addr,
            &sigret_dummy_site,
        )?;
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
    // B .+4 — branch forward to the sigreturn SVC snippet at offset 24
    // (We can't use a raw SVC #0 here because on aarch64 with the rewriter
    // backend there's no seccomp filter, so the SVC would go directly to the
    // host kernel which would fail. Instead we branch to a full SVC snippet
    // that goes through the litebox callback.)
    // The B instruction is at offset 20, snippet is at offset 24, delta = 4.
    let b_to_snippet = encode_b(4).expect("offset +4 always valid");
    trampoline_data.extend_from_slice(&b_to_snippet.to_le_bytes());

    debug_assert_eq!(trampoline_data.len(), SIGRETURN_SNIPPET_OFFSET);

    // Offset 24: sigreturn SVC snippet (76 bytes)
    // This is a full SVC snippet that routes through the syscall callback.
    // rt_sigreturn never returns, so the return address doesn't matter —
    // we use the snippet's own address as a dummy.
    let sigret_snippet_vaddr = trampoline_base_addr + SIGRETURN_SNIPPET_OFFSET as u64;
    let sigret_dummy_site = PatchSite {
        file_offset: 0, // unused — we don't patch any original instruction for this
        vaddr: sigret_snippet_vaddr, // return_addr = vaddr + 4, but rt_sigreturn never returns
        kind: PatchKind::Svc,
    };
    emit_svc_snippet(
        &mut trampoline_data,
        sigret_snippet_vaddr,
        SIGRETURN_SNIPPET_OFFSET,
        trampoline_base_addr,
        &sigret_dummy_site,
    )?;

    debug_assert_eq!(trampoline_data.len(), SNIPPETS_START_OFFSET);

    // Generate per-site trampoline snippets and patch original code
    for site in &sites {
        let snippet_offset = trampoline_data.len();
        let snippet_vaddr = trampoline_base_addr + snippet_offset as u64;

        match site.kind {
            PatchKind::Svc => {
                emit_svc_snippet(
                    &mut trampoline_data,
                    snippet_vaddr,
                    snippet_offset,
                    trampoline_base_addr,
                    site,
                )?;
            }
            PatchKind::MsrTpidr(rt) => {
                emit_msr_tpidr_snippet(
                    &mut trampoline_data,
                    snippet_vaddr,
                    snippet_offset,
                    trampoline_base_addr,
                    site,
                    rt,
                )?;
            }
        }

        // Patch original instruction with B <snippet>
        let b_offset = snippet_vaddr.cast_signed() - site.vaddr.cast_signed();
        let b_insn = encode_b(b_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "Branch offset {:#x} out of ±128MB range for site at {:#x}. \
                 Binary too large for direct branch patching.",
                b_offset, site.vaddr
            ))
        })?;

        buf[site.file_offset..site.file_offset + 4].copy_from_slice(&b_insn.to_le_bytes());
    }

    Ok((trampoline_data, true))
}

/// Emit a per-SVC trampoline snippet (17 instructions, 68 bytes).
///
/// This snippet saves registers, looks up the host TLS from the TLS table,
/// then jumps to the syscall callback.
#[allow(clippy::cast_possible_wrap)]
fn emit_svc_snippet(
    trampoline_data: &mut Vec<u8>,
    snippet_vaddr: u64,
    snippet_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
) -> Result<()> {
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { snippet_vaddr + (idx as u64) * 4 };

    // [0] SUB SP, SP, #32
    trampoline_data.extend_from_slice(&encode_sub_sp_imm(32).expect("imm12=32 fits").to_le_bytes());
    insn_idx += 1;

    // [1] STR X16, [SP, #0]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [2] STR X17, [SP, #8]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(17, 31, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [3] STR X30, [SP, #16]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 31, 16)
            .expect("offset 16 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [4] MRS X18, TPIDR_EL0
    trampoline_data.extend_from_slice(&encode_mrs_tpidr_el0(18).to_le_bytes());
    insn_idx += 1;

    // [5] STR X18, [SP, #24] — save guest TPIDR so syscall_callback can read it
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(18, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [6] LDR X17, [PC, #offset_to_tls_table_ptr]
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let tls_table_vaddr = trampoline_base_addr + HEADER_TLS_TABLE_OFFSET as u64;
    let ldr_tls_offset = tls_table_vaddr.cast_signed() - ldr_tls_vaddr.cast_signed();
    let ldr_tls_insn = encode_ldr_literal(17, ldr_tls_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {:#x} out of range for TLS table load at SVC {:#x}",
            ldr_tls_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_tls_insn.to_le_bytes());
    insn_idx += 1;

    // [7] .Lloop: LDR X16, [X17, #0]
    let loop_idx = insn_idx;
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 17, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [8] CMN X16, #1
    trampoline_data.extend_from_slice(&encode_cmn_imm(16, 1).expect("imm12=1 fits").to_le_bytes());
    insn_idx += 1;

    // [9] B.EQ .Ldone -> instruction [15]
    let done_idx = 15usize;
    let beq_done_offset = (done_idx as i64 - insn_idx as i64) * 4;
    let beq_done = encode_b_cond(COND_EQ, beq_done_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {:#x} out of range for SVC at {:#x}",
            beq_done_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_done.to_le_bytes());
    insn_idx += 1;

    // [10] CMP X16, X18
    trampoline_data.extend_from_slice(&encode_cmp_reg(16, 18).to_le_bytes());
    insn_idx += 1;

    // [11] B.EQ .Lfound -> instruction [14]
    let found_idx = 14usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {:#x} out of range for SVC at {:#x}",
            beq_found_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_found.to_le_bytes());
    insn_idx += 1;

    // [12] ADD X17, X17, #16
    trampoline_data.extend_from_slice(
        &encode_add_imm(17, 17, 16)
            .expect("imm12=16 fits")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [13] B .Lloop -> instruction [7]
    let b_loop_offset = (loop_idx as i64 - insn_idx as i64) * 4;
    let b_loop = encode_b(b_loop_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {:#x} out of range for loop at SVC {:#x}",
            b_loop_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [14] .Lfound: LDR X18, [X17, #8]
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(18, 17, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [15] .Ldone: ADRP X30, <return_page>
    //      return_addr = instruction after the original SVC = site.vaddr + 4
    debug_assert_eq!(insn_idx, done_idx);
    let return_addr = site.vaddr + 4;
    let adrp_vaddr = insn_vaddr(insn_idx);
    let adrp_base = adrp_vaddr & !0xFFF; // PC page-aligned
    let return_page = return_addr & !0xFFF;
    let page_offset = (return_page as i64 - adrp_base as i64) >> 12;
    let adrp_insn = encode_adrp(30, page_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "ADRP page offset {:#x} out of ±4GB range for SVC at {:#x}",
            page_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&adrp_insn.to_le_bytes());
    insn_idx += 1;

    // [16] ADD X30, X30, #<pageoff>
    let pageoff = (return_addr & 0xFFF) as u16;
    trampoline_data.extend_from_slice(
        &encode_add_imm(30, 30, pageoff)
            .expect("page offset fits in imm12")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [17] LDR X16, [PC, #offset_to_callback]
    let ldr_cb_vaddr = insn_vaddr(insn_idx);
    let callback_vaddr = trampoline_base_addr + HEADER_CALLBACK_OFFSET as u64;
    let ldr_cb_offset = callback_vaddr.cast_signed() - ldr_cb_vaddr.cast_signed();
    let ldr_cb_insn = encode_ldr_literal(16, ldr_cb_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {:#x} out of ±1MB range for SVC at {:#x}",
            ldr_cb_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_cb_insn.to_le_bytes());
    insn_idx += 1;

    // [17] BR X16
    trampoline_data.extend_from_slice(&encode_br(16).to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, SVC_SNIPPET_INSN_COUNT);
    debug_assert_eq!(
        trampoline_data.len() - snippet_offset,
        SVC_SNIPPET_SIZE,
        "SVC snippet size mismatch"
    );

    Ok(())
}

/// Emit a per-MSR TPIDR_EL0 trampoline snippet (24 instructions, 96 bytes).
///
/// This snippet intercepts `MSR TPIDR_EL0, Xt` instructions, updating the TLS
/// lookup table to reflect the new guest TPIDR value so subsequent SVC trampoline
/// lookups will find the correct host TLS.
///
/// Uses scratch registers X16, X17, X30 (all saved/restored on the stack).
/// The new TPIDR value is stored at `[SP, #24]` to avoid register conflicts.
#[allow(clippy::cast_possible_wrap)]
fn emit_msr_tpidr_snippet(
    trampoline_data: &mut Vec<u8>,
    snippet_vaddr: u64,
    snippet_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rt: u8,
) -> Result<()> {
    let mut insn_idx: usize = 0;
    let insn_vaddr = |idx: usize| -> u64 { snippet_vaddr + (idx as u64) * 4 };

    // [0] SUB SP, SP, #32
    trampoline_data.extend_from_slice(&encode_sub_sp_imm(32).expect("imm12=32 fits").to_le_bytes());
    insn_idx += 1;

    // [1] STR X16, [SP, #0]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(16, 31, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [2] STR X17, [SP, #8]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(17, 31, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [3] STR X30, [SP, #16]
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 31, 16)
            .expect("offset 16 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [4]-[5] Store the new TPIDR value (from Xt) to [SP, #24].
    // This is 2 instructions (fixed size) to keep snippets aligned.
    // For registers that were already saved to the stack, we reload from
    // their save slots. For XZR (reg 31), we store zero.
    match rt {
        16 => {
            // Xt = X16: reload from [SP, #0] into X30, then store to [SP, #24]
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(30, 31, 0)
                    .expect("valid")
                    .to_le_bytes(),
            );
            trampoline_data.extend_from_slice(
                &encode_str_imm_unsigned(30, 31, 24)
                    .expect("valid")
                    .to_le_bytes(),
            );
        }
        17 => {
            // Xt = X17: reload from [SP, #8] into X30, then store to [SP, #24]
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(30, 31, 8)
                    .expect("valid")
                    .to_le_bytes(),
            );
            trampoline_data.extend_from_slice(
                &encode_str_imm_unsigned(30, 31, 24)
                    .expect("valid")
                    .to_le_bytes(),
            );
        }
        30 => {
            // Xt = X30: reload from [SP, #16] into X16, then store to [SP, #24]
            // (X16 is already saved, so we can use it as scratch)
            trampoline_data.extend_from_slice(
                &encode_ldr_imm_unsigned(16, 31, 16)
                    .expect("valid")
                    .to_le_bytes(),
            );
            trampoline_data.extend_from_slice(
                &encode_str_imm_unsigned(16, 31, 24)
                    .expect("valid")
                    .to_le_bytes(),
            );
        }
        31 => {
            // Xt = XZR: store zero to [SP, #24]
            // STR XZR, [SP, #24] — register 31 in STR context is XZR
            trampoline_data.extend_from_slice(
                &encode_str_imm_unsigned(31, 31, 24)
                    .expect("valid")
                    .to_le_bytes(),
            );
            trampoline_data.extend_from_slice(&NOP.to_le_bytes());
        }
        _ => {
            // Xt = any other register (0-15 excluding 16, 18-29): STR Xt, [SP, #24] + NOP
            trampoline_data.extend_from_slice(
                &encode_str_imm_unsigned(rt, 31, 24)
                    .expect("valid")
                    .to_le_bytes(),
            );
            trampoline_data.extend_from_slice(&NOP.to_le_bytes());
        }
    }
    insn_idx += 2;

    // [6] MRS X16, TPIDR_EL0 — read old guest TPIDR
    trampoline_data.extend_from_slice(&encode_mrs_tpidr_el0(16).to_le_bytes());
    insn_idx += 1;

    // [7] LDR X17, [PC, #offset_to_tls_table_ptr]
    let ldr_tls_vaddr = insn_vaddr(insn_idx);
    let tls_table_vaddr = trampoline_base_addr + HEADER_TLS_TABLE_OFFSET as u64;
    let ldr_tls_offset = tls_table_vaddr.cast_signed() - ldr_tls_vaddr.cast_signed();
    let ldr_tls_insn = encode_ldr_literal(17, ldr_tls_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "LDR literal offset {:#x} out of range for TLS table load at MSR {:#x}",
            ldr_tls_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&ldr_tls_insn.to_le_bytes());
    insn_idx += 1;

    // [8] .Lloop: LDR X30, [X17, #0] — load guest_tpidr from table entry
    let loop_idx = insn_idx;
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 17, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [9] CMN X30, #1 — sentinel check
    trampoline_data.extend_from_slice(&encode_cmn_imm(30, 1).expect("imm12=1 fits").to_le_bytes());
    insn_idx += 1;

    // [10] B.EQ .Ldone -> instruction [17]
    let done_idx = 17usize;
    let beq_done_offset = (done_idx as i64 - insn_idx as i64) * 4;
    let beq_done = encode_b_cond(COND_EQ, beq_done_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {:#x} out of range for MSR at {:#x}",
            beq_done_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_done.to_le_bytes());
    insn_idx += 1;

    // [11] CMP X30, X16 — match old TPIDR?
    trampoline_data.extend_from_slice(&encode_cmp_reg(30, 16).to_le_bytes());
    insn_idx += 1;

    // [12] B.EQ .Lfound -> instruction [15]
    let found_idx = 15usize;
    let beq_found_offset = (found_idx as i64 - insn_idx as i64) * 4;
    let beq_found = encode_b_cond(COND_EQ, beq_found_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B.EQ offset {:#x} out of range for MSR at {:#x}",
            beq_found_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&beq_found.to_le_bytes());
    insn_idx += 1;

    // [13] ADD X17, X17, #16 — next entry
    trampoline_data.extend_from_slice(
        &encode_add_imm(17, 17, 16)
            .expect("imm12=16 fits")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [14] B .Lloop -> instruction [8]
    let b_loop_offset = (loop_idx as i64 - insn_idx as i64) * 4;
    let b_loop = encode_b(b_loop_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {:#x} out of range for loop at MSR {:#x}",
            b_loop_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&b_loop.to_le_bytes());
    insn_idx += 1;

    // [15] .Lfound: LDR X30, [SP, #24] — load new TPIDR value
    debug_assert_eq!(insn_idx, found_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [16] STR X30, [X17, #0] — update table entry's guest_tpidr to new value
    trampoline_data.extend_from_slice(
        &encode_str_imm_unsigned(30, 17, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [17] .Ldone: LDR X30, [SP, #24] — load new TPIDR value
    debug_assert_eq!(insn_idx, done_idx);
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 24)
            .expect("offset 24 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [18] MSR TPIDR_EL0, X30 — execute the actual MSR with new value
    trampoline_data.extend_from_slice(&encode_msr_tpidr_el0(30).to_le_bytes());
    insn_idx += 1;

    // [19] LDR X30, [SP, #16] — restore X30
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(30, 31, 16)
            .expect("offset 16 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [20] LDR X17, [SP, #8] — restore X17
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(17, 31, 8)
            .expect("offset 8 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [21] LDR X16, [SP, #0] — restore X16
    trampoline_data.extend_from_slice(
        &encode_ldr_imm_unsigned(16, 31, 0)
            .expect("offset 0 valid")
            .to_le_bytes(),
    );
    insn_idx += 1;

    // [22] ADD SP, SP, #32
    trampoline_data.extend_from_slice(&encode_add_sp_imm(32).expect("imm12=32 fits").to_le_bytes());
    insn_idx += 1;

    // [23] B <return_addr> — branch back to instruction after original MSR
    let b_ret_vaddr = insn_vaddr(insn_idx);
    let b_ret_offset = (site.vaddr + 4).cast_signed() - b_ret_vaddr.cast_signed();
    let b_ret = encode_b(b_ret_offset).ok_or_else(|| {
        Error::DisassemblyFailure(format!(
            "B offset {:#x} out of ±128MB range for return from MSR at {:#x}",
            b_ret_offset, site.vaddr
        ))
    })?;
    trampoline_data.extend_from_slice(&b_ret.to_le_bytes());
    insn_idx += 1;

    debug_assert_eq!(insn_idx, MSR_SNIPPET_INSN_COUNT);
    debug_assert_eq!(
        trampoline_data.len() - snippet_offset,
        MSR_SNIPPET_SIZE,
        "MSR snippet size mismatch"
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
        assert_eq!(SVC_SNIPPET_SIZE, 76);
        assert_eq!(SVC_SNIPPET_INSN_COUNT, 19);
        assert_eq!(MSR_SNIPPET_SIZE, 96);
        assert_eq!(MSR_SNIPPET_INSN_COUNT, 24);
    }

    #[test]
    fn test_snippet_instruction_layout() {
        // Generate a trampoline with one SVC and verify every instruction
        // in the snippet matches the expected encoding.
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

        // Snippet starts at offset 24
        let snippet_start = SNIPPETS_START_OFFSET;
        let snippet_vaddr = trampoline_base + snippet_start as u64;

        // Helper to read instruction at snippet-relative index
        let insn_at = |idx: usize| -> u32 {
            let off = snippet_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [0] SUB SP, SP, #32
        assert_eq!(insn_at(0), encode_sub_sp_imm(32).unwrap());

        // [1] STR X16, [SP, #0]
        assert_eq!(insn_at(1), encode_str_imm_unsigned(16, 31, 0).unwrap());

        // [2] STR X17, [SP, #8]
        assert_eq!(insn_at(2), encode_str_imm_unsigned(17, 31, 8).unwrap());

        // [3] STR X30, [SP, #16]
        assert_eq!(insn_at(3), encode_str_imm_unsigned(30, 31, 16).unwrap());

        // [4] MRS X18, TPIDR_EL0
        assert_eq!(insn_at(4), encode_mrs_tpidr_el0(18));

        // [5] STR X18, [SP, #24] — save guest TPIDR
        assert_eq!(insn_at(5), encode_str_imm_unsigned(18, 31, 24).unwrap());

        // [6] LDR X17, [PC, #offset_to_tls_table_ptr]
        // TLS table ptr at trampoline offset 8, LDR at snippet_vaddr + 24
        let ldr_tls_vaddr = snippet_vaddr + 24;
        let tls_offset = (trampoline_base + 8) as i64 - ldr_tls_vaddr as i64;
        assert_eq!(insn_at(6), encode_ldr_literal(17, tls_offset).unwrap());

        // [7] LDR X16, [X17, #0] (.Lloop)
        assert_eq!(insn_at(7), encode_ldr_imm_unsigned(16, 17, 0).unwrap());

        // [8] CMN X16, #1
        assert_eq!(insn_at(8), encode_cmn_imm(16, 1).unwrap());

        // [9] B.EQ .Ldone -> [15], offset = (15-9)*4 = +24
        assert_eq!(insn_at(9), encode_b_cond(COND_EQ, 24).unwrap());

        // [10] CMP X16, X18
        assert_eq!(insn_at(10), encode_cmp_reg(16, 18));

        // [11] B.EQ .Lfound -> [14], offset = (14-11)*4 = +12
        assert_eq!(insn_at(11), encode_b_cond(COND_EQ, 12).unwrap());

        // [12] ADD X17, X17, #16
        assert_eq!(insn_at(12), encode_add_imm(17, 17, 16).unwrap());

        // [13] B .Lloop -> [7], offset = (7-13)*4 = -24
        assert_eq!(insn_at(13), encode_b(-24).unwrap());

        // [14] LDR X18, [X17, #8] (.Lfound)
        assert_eq!(insn_at(14), encode_ldr_imm_unsigned(18, 17, 8).unwrap());

        // [15] ADRP X30, <return_page> (.Ldone)
        // return_addr = 0x1004 + 4 = 0x1008
        // ADRP at snippet_vaddr + 60
        let adrp_vaddr = snippet_vaddr + 60;
        let adrp_base = adrp_vaddr & !0xFFF;
        let return_addr = 0x1008u64;
        let return_page = return_addr & !0xFFF;
        let page_offset = (return_page.cast_signed() - adrp_base.cast_signed()) >> 12;
        assert_eq!(insn_at(15), encode_adrp(30, page_offset).unwrap());

        // [16] ADD X30, X30, #<pageoff>
        let pageoff = (return_addr & 0xFFF) as u16;
        assert_eq!(insn_at(16), encode_add_imm(30, 30, pageoff).unwrap());

        // [17] LDR X16, [PC, #offset_to_callback]
        // callback at trampoline offset 0, LDR at snippet_vaddr + 68
        let ldr_cb_vaddr = snippet_vaddr + 68;
        let cb_offset = trampoline_base as i64 - ldr_cb_vaddr as i64;
        assert_eq!(insn_at(17), encode_ldr_literal(16, cb_offset).unwrap());

        // [18] BR X16
        assert_eq!(insn_at(18), encode_br(16));
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
        // Offset 20: B .+8 (branch forward to sigreturn SVC snippet at offset 24)
        let sigreturn_b = u32::from_le_bytes(trampoline_data[20..24].try_into().unwrap());
        assert_eq!(sigreturn_b, encode_b(4).unwrap());

        // Sigreturn SVC snippet (76 bytes) at offset 24, then per-site snippets at offset 100
        // Total: 100 (header+sigreturn) + 76 (per-site snippet) = 176
        assert_eq!(
            trampoline_data.len(),
            SNIPPETS_START_OFFSET + SVC_SNIPPET_SIZE
        );

        // Verify the original SVC was patched with a B instruction
        let patched = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        // B to per-site snippet at 0x2000 + SNIPPETS_START_OFFSET = 0x2064
        // offset = 0x2064 - 0x1004 = 0x1060
        let snippet_vaddr = trampoline_base + SNIPPETS_START_OFFSET as u64;
        let expected_b = encode_b(snippet_vaddr as i64 - 0x1004i64).unwrap();
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
        // Minimal trampoline: callback(8) + TLS ptr(8) + sigret preamble(8) + sigret SVC snippet
        assert!(
            trampoline_data.len() >= SNIPPETS_START_OFFSET,
            "minimal trampoline should include sigreturn snippet"
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

        // 24 (header) + 76 (snippet1) + 76 (snippet2) = 176
        assert_eq!(
            trampoline_data.len(),
            SNIPPETS_START_OFFSET + 2 * SVC_SNIPPET_SIZE
        );

        // Both SVCs should be patched
        let patched1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let patched2 = u32::from_le_bytes(buf[16..20].try_into().unwrap());

        // Verify both are B instructions (opcode in bits [31:26])
        assert_eq!(patched1 & 0xFC00_0000, 0x1400_0000);
        assert_eq!(patched2 & 0xFC00_0000, 0x1400_0000);

        // Verify they branch to different targets (different snippets)
        assert_ne!(patched1, patched2);

        // Verify snippet 1 targets offset 24 and snippet 2 targets offset 24+76=100
        let snippet1_vaddr = trampoline_base + SNIPPETS_START_OFFSET as u64;
        let snippet2_vaddr =
            trampoline_base + SNIPPETS_START_OFFSET as u64 + SVC_SNIPPET_SIZE as u64;

        let expected_b1 = encode_b(snippet1_vaddr as i64 - 0x1004i64).unwrap();
        let expected_b2 = encode_b(snippet2_vaddr as i64 - 0x1010i64).unwrap();
        assert_eq!(patched1, expected_b1);
        assert_eq!(patched2, expected_b2);
    }

    #[test]
    fn test_sigreturn_preamble_branches_to_snippet() {
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

        // Offset 20: B .+4 (branch to sigreturn SVC snippet at offset 24)
        let sigreturn_b = u32::from_le_bytes(trampoline_data[20..24].try_into().unwrap());
        assert_eq!(
            sigreturn_b,
            encode_b(4).unwrap(),
            "sigreturn preamble should branch forward to SVC snippet"
        );

        // Verify the sigreturn SVC snippet starts at offset 24 (SIGRETURN_SNIPPET_OFFSET)
        // It should begin with SUB SP, SP, #32 (the standard SVC snippet prologue)
        let sigret_prologue = u32::from_le_bytes(trampoline_data[24..28].try_into().unwrap());
        assert_eq!(
            sigret_prologue,
            encode_sub_sp_imm(32).unwrap(),
            "sigreturn SVC snippet should start with SUB SP, SP, #32"
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

        // Offset 20-23: B .+8 (branch to sigreturn SVC snippet)
        assert_eq!(
            u32::from_le_bytes(
                td[HEADER_SIGRETURN_OFFSET + 4..HEADER_SIGRETURN_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            encode_b(4).unwrap()
        );

        // Offset 24: sigreturn SVC snippet (76 bytes)
        // Then per-site snippets start at offset 100
        assert_eq!(td.len(), SNIPPETS_START_OFFSET + SVC_SNIPPET_SIZE);
    }

    #[test]
    fn test_tls_loop_branch_offsets() {
        // Verify that the TLS lookup loop branches have correct offsets.
        // This test verifies the critical branch targets within the loop.
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let (td, _) = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0).unwrap();

        let insn_at = |idx: usize| -> u32 {
            let off = SNIPPETS_START_OFFSET + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [9] B.EQ .Ldone -> [15]: offset = (15-9)*4 = 24
        let beq_done = insn_at(9);
        let imm19 = (beq_done >> 5) & 0x7_FFFF;
        assert_eq!(imm19, 6); // 24/4 = 6
        assert_eq!(beq_done & 0xF, 0); // cond = EQ

        // [11] B.EQ .Lfound -> [14]: offset = (14-11)*4 = 12
        let beq_found = insn_at(11);
        let imm19 = (beq_found >> 5) & 0x7_FFFF;
        assert_eq!(imm19, 3); // 12/4 = 3

        // [13] B .Lloop -> [7]: offset = (7-13)*4 = -24
        let b_loop = insn_at(13);
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
        // Header (24) + SVC snippet (76) + MSR snippet (96) = 196
        assert_eq!(
            td.len(),
            SNIPPETS_START_OFFSET + SVC_SNIPPET_SIZE + MSR_SNIPPET_SIZE
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
    fn test_msr_snippet_prologue() {
        let (td, _, _) = hook_with_svc_and_msr(19);
        // MSR snippet starts after the SVC snippet
        let msr_start = SNIPPETS_START_OFFSET + SVC_SNIPPET_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [0] SUB SP, SP, #32
        assert_eq!(insn_at(0), encode_sub_sp_imm(32).unwrap());
        // [1] STR X16, [SP, #0]
        assert_eq!(insn_at(1), encode_str_imm_unsigned(16, 31, 0).unwrap());
        // [2] STR X17, [SP, #8]
        assert_eq!(insn_at(2), encode_str_imm_unsigned(17, 31, 8).unwrap());
        // [3] STR X30, [SP, #16]
        assert_eq!(insn_at(3), encode_str_imm_unsigned(30, 31, 16).unwrap());
    }

    #[test]
    fn test_msr_snippet_store_new_tpidr_generic_reg() {
        // MSR TPIDR_EL0, X19 — generic register, should be STR X19, [SP, #24] + NOP
        let (td, _, _) = hook_with_svc_and_msr(19);
        let msr_start = SNIPPETS_START_OFFSET + SVC_SNIPPET_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [4] STR X19, [SP, #24]
        assert_eq!(insn_at(4), encode_str_imm_unsigned(19, 31, 24).unwrap());
        // [5] NOP
        assert_eq!(insn_at(5), NOP);
    }

    #[test]
    fn test_msr_snippet_store_new_tpidr_x16() {
        // MSR TPIDR_EL0, X16 — saved reg, must reload from [SP, #0]
        let (td, _, _) = hook_with_svc_and_msr(16);
        let msr_start = SNIPPETS_START_OFFSET + SVC_SNIPPET_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [4] LDR X30, [SP, #0] (reload X16's original value into X30)
        assert_eq!(insn_at(4), encode_ldr_imm_unsigned(30, 31, 0).unwrap());
        // [5] STR X30, [SP, #24]
        assert_eq!(insn_at(5), encode_str_imm_unsigned(30, 31, 24).unwrap());
    }

    #[test]
    fn test_msr_snippet_store_new_tpidr_x17() {
        // MSR TPIDR_EL0, X17 — saved reg, must reload from [SP, #8]
        let (td, _, _) = hook_with_svc_and_msr(17);
        let msr_start = SNIPPETS_START_OFFSET + SVC_SNIPPET_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [4] LDR X30, [SP, #8] (reload X17's original value into X30)
        assert_eq!(insn_at(4), encode_ldr_imm_unsigned(30, 31, 8).unwrap());
        // [5] STR X30, [SP, #24]
        assert_eq!(insn_at(5), encode_str_imm_unsigned(30, 31, 24).unwrap());
    }

    #[test]
    fn test_msr_snippet_store_new_tpidr_x30() {
        // MSR TPIDR_EL0, X30 — saved reg, must reload from [SP, #16]
        let (td, _, _) = hook_with_svc_and_msr(30);
        let msr_start = SNIPPETS_START_OFFSET + SVC_SNIPPET_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [4] LDR X16, [SP, #16] (reload X30's original value into X16)
        assert_eq!(insn_at(4), encode_ldr_imm_unsigned(16, 31, 16).unwrap());
        // [5] STR X16, [SP, #24]
        assert_eq!(insn_at(5), encode_str_imm_unsigned(16, 31, 24).unwrap());
    }

    #[test]
    fn test_msr_snippet_store_new_tpidr_xzr() {
        // MSR TPIDR_EL0, XZR (reg 31) — store zero
        let (td, _, _) = hook_with_svc_and_msr(31);
        let msr_start = SNIPPETS_START_OFFSET + SVC_SNIPPET_SIZE;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [4] STR XZR, [SP, #24] (reg 31 = XZR in STR context)
        assert_eq!(insn_at(4), encode_str_imm_unsigned(31, 31, 24).unwrap());
        // [5] NOP
        assert_eq!(insn_at(5), NOP);
    }

    #[test]
    fn test_msr_snippet_loop_and_epilogue() {
        // Verify the full MSR snippet instruction layout for the loop and epilogue
        let (td, _, trampoline_base) = hook_with_svc_and_msr(19);
        let msr_start = SNIPPETS_START_OFFSET + SVC_SNIPPET_SIZE;
        let snippet_vaddr = trampoline_base + msr_start as u64;
        let insn_at = |idx: usize| -> u32 {
            let off = msr_start + idx * 4;
            u32::from_le_bytes(td[off..off + 4].try_into().unwrap())
        };

        // [6] MRS X16, TPIDR_EL0
        assert_eq!(insn_at(6), encode_mrs_tpidr_el0(16));

        // [7] LDR X17, [PC, #offset_to_tls_table]
        let ldr_tls_vaddr = snippet_vaddr + 7 * 4;
        let tls_offset = (trampoline_base + 8) as i64 - ldr_tls_vaddr as i64;
        assert_eq!(insn_at(7), encode_ldr_literal(17, tls_offset).unwrap());

        // [8] .Lloop: LDR X30, [X17, #0]
        assert_eq!(insn_at(8), encode_ldr_imm_unsigned(30, 17, 0).unwrap());

        // [9] CMN X30, #1
        assert_eq!(insn_at(9), encode_cmn_imm(30, 1).unwrap());

        // [10] B.EQ .Ldone -> [17]: offset = (17-10)*4 = 28
        assert_eq!(insn_at(10), encode_b_cond(COND_EQ, 28).unwrap());

        // [11] CMP X30, X16
        assert_eq!(insn_at(11), encode_cmp_reg(30, 16));

        // [12] B.EQ .Lfound -> [15]: offset = (15-12)*4 = 12
        assert_eq!(insn_at(12), encode_b_cond(COND_EQ, 12).unwrap());

        // [13] ADD X17, X17, #16
        assert_eq!(insn_at(13), encode_add_imm(17, 17, 16).unwrap());

        // [14] B .Lloop -> [8]: offset = (8-14)*4 = -24
        assert_eq!(insn_at(14), encode_b(-24).unwrap());

        // [15] .Lfound: LDR X30, [SP, #24]
        assert_eq!(insn_at(15), encode_ldr_imm_unsigned(30, 31, 24).unwrap());

        // [16] STR X30, [X17, #0]
        assert_eq!(insn_at(16), encode_str_imm_unsigned(30, 17, 0).unwrap());

        // [17] .Ldone: LDR X30, [SP, #24]
        assert_eq!(insn_at(17), encode_ldr_imm_unsigned(30, 31, 24).unwrap());

        // [18] MSR TPIDR_EL0, X30
        assert_eq!(insn_at(18), encode_msr_tpidr_el0(30));

        // [19] LDR X30, [SP, #16]
        assert_eq!(insn_at(19), encode_ldr_imm_unsigned(30, 31, 16).unwrap());

        // [20] LDR X17, [SP, #8]
        assert_eq!(insn_at(20), encode_ldr_imm_unsigned(17, 31, 8).unwrap());

        // [21] LDR X16, [SP, #0]
        assert_eq!(insn_at(21), encode_ldr_imm_unsigned(16, 31, 0).unwrap());

        // [22] ADD SP, SP, #32
        assert_eq!(insn_at(22), encode_add_sp_imm(32).unwrap());

        // [23] B <return_addr>
        // MSR was at vaddr 0x1008, return to 0x100C
        // B insn is at snippet_vaddr + 23*4
        let b_ret_vaddr = snippet_vaddr + 23 * 4;
        let expected_offset = 0x100Ci64 - b_ret_vaddr as i64;
        assert_eq!(insn_at(23), encode_b(expected_offset).unwrap());
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
        assert!(
            trampoline_data.len() >= SNIPPETS_START_OFFSET,
            "minimal trampoline should include sigreturn snippet"
        );
    }
}
