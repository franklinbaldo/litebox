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

/// Encode a `B` (unconditional branch) instruction to a PC-relative offset.
///
/// The offset must be a multiple of 4 and within ±128MB (signed 26-bit instruction count).
/// Encoding: `[31:26] = 0b000101`, `[25:0] = signed offset / 4`
fn encode_b(offset: i64) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm26 = offset >> 2;
    if imm26 < -(1 << 25) || imm26 >= (1 << 25) {
        return None;
    }
    Some(0x14000000 | ((imm26 as u32) & 0x03FF_FFFF))
}

/// Encode an `ADR Xd, #imm` instruction.
///
/// The immediate is a signed 21-bit byte offset (NOT instruction-aligned).
/// The encoding splits the immediate: `immlo` in bits [30:29], `immhi` in bits [23:5].
fn encode_adr(rd: u8, offset: i64) -> Option<u32> {
    if offset < -(1 << 20) || offset >= (1 << 20) {
        return None;
    }
    let imm = offset as u32;
    let immlo = (imm & 0x3) << 29;
    let immhi = ((imm >> 2) & 0x7_FFFF) << 5;
    Some(0x10000000 | immlo | immhi | u32::from(rd))
}

/// Encode `STP x16, x30, [SP, #-16]!` (pre-index store pair).
///
/// Saves x16 and LR (x30) to the stack, decrementing SP by 16.
const fn encode_stp_x16_x30_sp_pre() -> u32 {
    // STP Xt1, Xt2, [Xn, #imm7*8]! (64-bit, pre-index, store)
    // opc=10, V=0, L=0, imm7=-2 (=-16/8), Rt2=x30=30, Rn=SP=31, Rt=x16=16
    0xA9BF_7BF0
}

/// Encode `LDR Xt, <literal>` (PC-relative literal load, 64-bit).
///
/// Loads 8 bytes from a PC-relative address. The offset must be 4-byte aligned
/// and within ±1MB (signed 19-bit instruction count).
fn encode_ldr_literal(rt: u8, offset: i64) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm19 = offset >> 2;
    if imm19 < -(1 << 18) || imm19 >= (1 << 18) {
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

/// Information about a found instruction to patch.
struct PatchSite {
    /// File offset of the instruction
    file_offset: usize,
    /// Virtual address of the instruction
    vaddr: u64,
}

/// Scan executable sections for `SVC #0` instructions.
///
/// ARM64 instructions are always 4-byte aligned, so we scan in 4-byte steps.
/// Returns patch sites sorted by file offset.
fn find_svc_sites(sections: &[TextSectionInfo], buf: &[u8]) -> Result<Vec<PatchSite>> {
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
                });
            }
        }
    }

    Ok(sites)
}

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
/// Offset 8:     Sigreturn trampoline (8 bytes = 2 instructions):
///                 MOV X8, #139     // __NR_rt_sigreturn
///                 SVC #0           // (NOT patched — it's in the trampoline)
/// Offset 16+:   Per-SVC trampoline snippets (16 bytes each = 4 instructions)
/// ```
///
/// # Per-SVC trampoline snippet (4 instructions, 16 bytes)
///
/// ```asm
/// STP x16, x30, [SP, #-16]!      // save x16 and LR
/// ADR x30, <guest_return_addr>    // x30 = address after original SVC
/// LDR x16, <callback_addr>        // x16 = callback fn ptr from offset 0
/// BR  x16                          // jump to callback
/// ```
///
/// The callback receives x30 = guest return address, and is responsible for
/// saving/restoring all registers and eventually returning to the guest.
pub(crate) fn hook_syscalls_aarch64(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    trampoline: u64,
) -> Result<(Vec<u8>, bool)> {
    // Find all SVC #0 sites first (immutable borrow of buf)
    let sites = find_svc_sites(text_sections, buf)?;
    if sites.is_empty() {
        return Err(Error::NoSyscallInstructionsFound);
    }

    // Build trampoline data
    let mut trampoline_data: Vec<u8> = Vec::new();

    // Offset 0: syscall_callback address (8 bytes)
    trampoline_data.extend_from_slice(&trampoline.to_le_bytes());

    // Offset 8: sigreturn trampoline
    // MOV X8, #NR_RT_SIGRETURN (= 139)
    trampoline_data.extend_from_slice(&encode_movz_x(8, NR_RT_SIGRETURN).to_le_bytes());
    // SVC #0 (this one is NOT patched — it belongs to the trampoline)
    trampoline_data.extend_from_slice(&SVC_0.to_le_bytes());

    // Generate per-SVC trampoline snippets and patch original code
    for site in &sites {
        let snippet_vaddr = trampoline_base_addr + trampoline_data.len() as u64;
        let callback_addr_vaddr = trampoline_base_addr; // offset 0 of trampoline

        // Instruction 1: STP x16, x30, [SP, #-16]!
        trampoline_data.extend_from_slice(&encode_stp_x16_x30_sp_pre().to_le_bytes());

        // Instruction 2: ADR x30, <return_addr>
        // return_addr = instruction after the original SVC = site.vaddr + 4
        let adr_vaddr = trampoline_base_addr + trampoline_data.len() as u64;
        let adr_offset = (site.vaddr + 4) as i64 - adr_vaddr as i64;
        let adr_insn = encode_adr(30, adr_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "ADR offset {:#x} out of ±1MB range for SVC at {:#x}",
                adr_offset, site.vaddr
            ))
        })?;
        trampoline_data.extend_from_slice(&adr_insn.to_le_bytes());

        // Instruction 3: LDR x16, <callback_addr>
        // PC-relative literal load from offset 0 of trampoline
        let ldr_vaddr = trampoline_base_addr + trampoline_data.len() as u64;
        let ldr_offset = callback_addr_vaddr as i64 - ldr_vaddr as i64;
        let ldr_insn = encode_ldr_literal(16, ldr_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "LDR literal offset {:#x} out of ±1MB range for SVC at {:#x}",
                ldr_offset, site.vaddr
            ))
        })?;
        trampoline_data.extend_from_slice(&ldr_insn.to_le_bytes());

        // Instruction 4: BR x16
        trampoline_data.extend_from_slice(&encode_br(16).to_le_bytes());

        // Patch original SVC #0 with B <snippet>
        let b_offset = snippet_vaddr as i64 - site.vaddr as i64;
        let b_insn = encode_b(b_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "Branch offset {:#x} out of ±128MB range for SVC at {:#x}. \
                 Binary too large for direct branch patching.",
                b_offset, site.vaddr
            ))
        })?;

        buf[site.file_offset..site.file_offset + 4].copy_from_slice(&b_insn.to_le_bytes());
    }

    Ok((trampoline_data, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================
    // Encoding unit tests
    // ========================

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
    fn test_encode_stp_x16_x30_sp_pre() {
        assert_eq!(encode_stp_x16_x30_sp_pre(), 0xA9BF_7BF0);
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

    // ========================
    // SVC scanning tests
    // ========================

    #[test]
    fn test_find_svc_sites_single() {
        // Build a minimal buffer with one SVC #0
        let mut buf = vec![0u8; 16];
        // Put SVC #0 at offset 4
        buf[4..8].copy_from_slice(&SVC_0.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        let sites = find_svc_sites(&sections, &buf).unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].file_offset, 4);
        assert_eq!(sites[0].vaddr, 0x1004);
    }

    #[test]
    fn test_find_svc_sites_multiple() {
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

        let sites = find_svc_sites(&sections, &buf).unwrap();
        assert_eq!(sites.len(), 3);
        assert_eq!(sites[0].vaddr, 0x2000);
        assert_eq!(sites[1].vaddr, 0x200C);
        assert_eq!(sites[2].vaddr, 0x2018);
    }

    #[test]
    fn test_find_svc_sites_none() {
        let buf = vec![0u8; 16];
        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        let sites = find_svc_sites(&sections, &buf).unwrap();
        assert!(sites.is_empty());
    }

    #[test]
    fn test_find_svc_sites_not_svc0() {
        // SVC #1 (not SVC #0) should not be found
        let mut buf = vec![0u8; 16];
        let svc_1: u32 = 0xD4000021; // SVC #1
        buf[0..4].copy_from_slice(&svc_1.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        let sites = find_svc_sites(&sections, &buf).unwrap();
        assert!(sites.is_empty());
    }

    // ========================
    // Integration / hooking tests
    // ========================

    #[test]
    fn test_hook_single_svc() {
        // Create a buffer with some NOPs and one SVC #0
        let nop: u32 = 0xD503201F; // NOP on ARM64
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&nop.to_le_bytes()); // NOP
        buf[4..8].copy_from_slice(&SVC_0.to_le_bytes()); // SVC #0
        buf[8..12].copy_from_slice(&nop.to_le_bytes()); // NOP
        buf[12..16].copy_from_slice(&nop.to_le_bytes()); // NOP

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 16,
        }];

        // Place trampoline right after the section (page-aligned in real use,
        // but close enough for testing)
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

        // Verify sigreturn trampoline at offset 8
        let sigreturn_mov = u32::from_le_bytes(trampoline_data[8..12].try_into().unwrap());
        assert_eq!(sigreturn_mov, encode_movz_x(8, NR_RT_SIGRETURN));
        let sigreturn_svc = u32::from_le_bytes(trampoline_data[12..16].try_into().unwrap());
        assert_eq!(sigreturn_svc, SVC_0);

        // Verify per-SVC snippet starts at offset 16
        // Instruction 1: STP x16, x30, [SP, #-16]!
        let stp = u32::from_le_bytes(trampoline_data[16..20].try_into().unwrap());
        assert_eq!(stp, encode_stp_x16_x30_sp_pre());

        // Instruction 2: ADR x30, <return_addr>
        // return_addr = 0x1004 + 4 = 0x1008 (instruction after SVC)
        // ADR is at vaddr = 0x2000 + 20 = 0x2014
        // offset = 0x1008 - 0x2014 = -0x100C
        let adr = u32::from_le_bytes(trampoline_data[20..24].try_into().unwrap());
        let expected_adr = encode_adr(30, 0x1008i64 - 0x2014i64).unwrap();
        assert_eq!(adr, expected_adr);

        // Instruction 3: LDR x16, <callback_addr at offset 0>
        // LDR is at vaddr = 0x2000 + 24 = 0x2018
        // target = 0x2000 (offset 0)
        // offset = 0x2000 - 0x2018 = -0x18 = -24
        let ldr = u32::from_le_bytes(trampoline_data[24..28].try_into().unwrap());
        let expected_ldr = encode_ldr_literal(16, -24).unwrap();
        assert_eq!(ldr, expected_ldr);

        // Instruction 4: BR x16
        let br = u32::from_le_bytes(trampoline_data[28..32].try_into().unwrap());
        assert_eq!(br, encode_br(16));

        // Total trampoline size: 8 (callback) + 8 (sigreturn) + 16 (snippet) = 32
        assert_eq!(trampoline_data.len(), 32);

        // Verify the original SVC was patched with a B instruction
        let patched = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        // B to snippet at 0x2000 + 16 = 0x2010
        // offset = 0x2010 - 0x1004 = 0x100C
        let expected_b = encode_b(0x100C).unwrap();
        assert_eq!(patched, expected_b);

        // Verify surrounding instructions are untouched
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), nop);
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), nop);
    }

    #[test]
    fn test_hook_no_svc_returns_error() {
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
        assert!(matches!(result, Err(Error::NoSyscallInstructionsFound)));
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

        // 8 (callback) + 8 (sigreturn) + 16 (snippet1) + 16 (snippet2) = 48
        assert_eq!(trampoline_data.len(), 48);

        // Both SVCs should be patched
        let patched1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let patched2 = u32::from_le_bytes(buf[16..20].try_into().unwrap());

        // Verify both are B instructions (opcode in bits [31:26])
        assert_eq!(patched1 & 0xFC00_0000, 0x1400_0000);
        assert_eq!(patched2 & 0xFC00_0000, 0x1400_0000);

        // Verify they branch to different targets
        assert_ne!(patched1, patched2);
    }

    #[test]
    fn test_sigreturn_svc_not_patched() {
        // The SVC #0 inside the sigreturn trampoline must NOT be patched.
        // Our design avoids this because find_svc_sites only scans the
        // original executable sections, not the trampoline we're building.
        // This test verifies the sigreturn SVC remains intact.

        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&SVC_0.to_le_bytes());

        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 8,
        }];

        let (trampoline_data, _) = hook_syscalls_aarch64(&mut buf, &sections, 0x2000, 0).unwrap();

        // Sigreturn SVC at offset 12 (bytes 12..16 of trampoline_data)
        let sigreturn_svc = u32::from_le_bytes(trampoline_data[12..16].try_into().unwrap());
        assert_eq!(sigreturn_svc, SVC_0, "sigreturn SVC #0 should be preserved");
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
}
