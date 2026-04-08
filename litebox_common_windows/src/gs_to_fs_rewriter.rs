// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Rewrite GS segment prefixes to FS in x86-64 machine code.
//!
//! Windows guest code uses `gs:` to access the TEB (Thread Environment
//! Block). The Windows kernel clobbers user-mode GS base on every context
//! switch, restoring it to the host TEB — a silent corruption that is
//! impossible to intercept. FS base, by contrast, is clobbered to **zero**,
//! producing a catchable ACCESS_VIOLATION that the existing VEH handler can
//! repair.
//!
//! This module provides [`rewrite_gs_to_fs`], which uses the iced-x86
//! decoder to find every instruction that carries a GS segment prefix
//! (`0x65`) and patches it in-place to FS (`0x64`). The function operates
//! on a mutable byte slice and returns the number of instructions patched.
//!
//! # Safety / Correctness
//!
//! The GS prefix byte (`0x65`) and FS prefix byte (`0x64`) are the same
//! length (1 byte), so replacing one with the other never changes
//! instruction boundaries, lengths, or any relative offsets. The patch is
//! therefore safe for all instruction encodings.

/// Rewrite all `gs:` segment prefixes to `fs:` in the given x86-64 code.
///
/// `code` is the mutable machine-code bytes of an executable section.
/// `base_va` is the virtual address of the first byte (used to set the
/// decoder IP for correct instruction decoding, though it does not affect
/// the patching logic).
///
/// Returns the number of instructions that were patched.
pub fn rewrite_gs_to_fs(code: &mut [u8], base_va: u64) -> usize {
    // Two-pass approach: first decode (immutable borrow) to collect the
    // byte offsets of GS prefix bytes, then patch (mutable borrow).
    let mut gs_prefix_offsets = alloc::vec::Vec::new();
    let mut offset = 0usize;

    // Pass 1: Decode and collect offsets of the 0x65 (GS) prefix byte.
    while offset < code.len() {
        let remaining = &code[offset..];
        let chunk_ip = base_va.wrapping_add(offset as u64);

        // Cap to stay within a 4 GiB window from the data pointer.
        // If the slice pointer is near the top of a 4 GiB boundary,
        // `dist` could round to 0; in that case, skip the cap and let
        // the full remaining length be used (the decoder handles any
        // pointer value correctly — the cap is purely defensive).
        let boundary_cap = {
            let ptr_low = (remaining.as_ptr() as u64) & 0xFFFF_FFFF;
            let dist = (1u64 << 32) - ptr_low;
            let cap = remaining.len().min(dist as usize);
            if cap == 0 { remaining.len() } else { cap }
        };
        let advance_len = boundary_cap.min(8 * 1024 * 1024);
        let decode_len = remaining.len().min(advance_len + 32);

        let mut decoder =
            iced_x86::Decoder::new(64, &remaining[..decode_len], iced_x86::DecoderOptions::NONE);
        decoder.set_ip(chunk_ip);

        let chunk_end_ip = chunk_ip + advance_len as u64;

        for inst in &mut decoder {
            if inst.len() == 0 {
                break;
            }
            if inst.ip() >= chunk_end_ip {
                break;
            }
            if inst.segment_prefix() == iced_x86::Register::GS {
                // Find the 0x65 byte within the instruction's raw bytes.
                //
                // Safety of the linear scan: x86-64 legacy prefixes (including
                // segment overrides 0x64/0x65) always precede the opcode and
                // ModR/M bytes.  The GS prefix byte 0x65 cannot appear as an
                // opcode byte in an instruction that iced-x86 decoded *with*
                // a GS segment prefix, because the decoder has already consumed
                // it as a prefix.  Therefore the first 0x65 byte we encounter
                // in the raw encoding is always the GS prefix — never an
                // immediate, displacement, or opcode byte.
                let inst_start = (inst.ip() - base_va) as usize;
                let mut found = false;
                for i in 0..inst.len() {
                    if code[inst_start + i] == 0x65 {
                        gs_prefix_offsets.push(inst_start + i);
                        found = true;
                        break;
                    }
                }
                debug_assert!(
                    found,
                    "iced-x86 reported GS prefix but 0x65 not found in instruction bytes at offset {inst_start:#x}",
                );
            }
        }

        offset += advance_len;
    }

    // Pass 2: Patch all collected offsets.
    for &off in &gs_prefix_offsets {
        debug_assert_eq!(code[off], 0x65);
        code[off] = 0x64;
    }

    gs_prefix_offsets.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_rewrite_gs_mov_eax() {
        // mov eax, dword ptr gs:[0x68] => mov eax, dword ptr fs:[0x68]
        // 65 8B 04 25 68 00 00 00
        let mut code = vec![0x65, 0x8B, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00];
        let n = rewrite_gs_to_fs(&mut code, 0x1000);
        assert_eq!(n, 1);
        assert_eq!(code[0], 0x64); // FS prefix
        assert_eq!(code[1], 0x8B); // opcode unchanged
    }

    #[test]
    fn test_no_gs_prefix() {
        // mov eax, 0x42 (no segment prefix)
        let mut code = vec![0xB8, 0x42, 0x00, 0x00, 0x00];
        let n = rewrite_gs_to_fs(&mut code, 0x1000);
        assert_eq!(n, 0);
        assert_eq!(code[0], 0xB8); // unchanged
    }

    #[test]
    fn test_fs_prefix_unchanged() {
        // mov eax, dword ptr fs:[0x68] — should not be touched
        let mut code = vec![0x64, 0x8B, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00];
        let n = rewrite_gs_to_fs(&mut code, 0x1000);
        assert_eq!(n, 0);
        assert_eq!(code[0], 0x64);
    }

    #[test]
    fn test_multiple_gs_instructions() {
        // Two consecutive GS-prefixed instructions:
        // mov eax, dword ptr gs:[0x68] ; mov dword ptr gs:[0x68], ecx
        let mut code = vec![
            0x65, 0x8B, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00, // mov eax, gs:[0x68]
            0x65, 0x89, 0x0C, 0x25, 0x68, 0x00, 0x00, 0x00, // mov gs:[0x68], ecx
        ];
        let n = rewrite_gs_to_fs(&mut code, 0x1000);
        assert_eq!(n, 2);
        assert_eq!(code[0], 0x64);
        assert_eq!(code[8], 0x64);
    }

    #[test]
    fn test_empty_code() {
        let mut code = vec![];
        let n = rewrite_gs_to_fs(&mut code, 0x1000);
        assert_eq!(n, 0);
    }
}
