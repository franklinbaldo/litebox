// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest TLS slot management and context/FP state helpers used by NT syscall
//! handlers.

const TLS_INLINE_SLOT_COUNT: u32 = 64;
const TLS_MAX_SLOT_COUNT: u32 = 1088;
const TLS_EXPANSION_SLOT_COUNT: usize = (TLS_MAX_SLOT_COUNT - TLS_INLINE_SLOT_COUNT) as usize;

#[cfg(all(debug_assertions, feature = "trace_debug"))]
fn trace_inline_tls_divergence(op: &str, teb_va: usize, index: u32, inline_value: usize) {
    if teb_va == 0 || index >= 16 {
        return;
    }

    let inline_base = teb_va + crate::peb_teb::teb_offsets::TLS_SLOTS;
    let vector_ptr = unsafe {
        core::ptr::read((teb_va + crate::peb_teb::teb_offsets::TLS_POINTER) as *const usize)
    };
    if vector_ptr == 0 || vector_ptr == inline_base {
        return;
    }

    let vector_value =
        unsafe { core::ptr::read((vector_ptr + index as usize * 8) as *const usize) };
    if vector_value == inline_value {
        return;
    }

    use litebox::platform::DebugLogProvider as _;
    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
        "[K32-TLS-diverge] {op} idx={index} teb=0x{teb_va:X} inline=0x{inline_value:X} vector=0x{vector_value:X} teb_ptr=0x{vector_ptr:X}\n",
    ));
}

#[cfg(not(all(debug_assertions, feature = "trace_debug")))]
fn trace_inline_tls_divergence(_op: &str, _teb_va: usize, _index: u32, _inline_value: usize) {}

fn zero_explicit_tls_slot_for_teb(teb_va: usize, index: u32) {
    if teb_va == 0 || index >= TLS_MAX_SLOT_COUNT {
        return;
    }

    let Some(slot_offset) = (index as usize).checked_mul(core::mem::size_of::<usize>()) else {
        return;
    };

    if index < TLS_INLINE_SLOT_COUNT {
        let Some(slot_addr) = teb_va
            .checked_add(crate::peb_teb::teb_offsets::TLS_SLOTS)
            .and_then(|addr| addr.checked_add(slot_offset))
        else {
            return;
        };
        if !crate::is_addr_range_writable(slot_addr, core::mem::size_of::<usize>()) {
            return;
        }
        unsafe {
            core::ptr::write_unaligned(slot_addr as *mut usize, 0);
        }
        trace_inline_tls_divergence("ThreadZeroTlsCell", teb_va, index, 0);
        return;
    }

    let exp_ptr_addr = teb_va + crate::peb_teb::teb_offsets::TLS_EXPANSION_SLOTS;
    if !crate::is_addr_range_committed(exp_ptr_addr, core::mem::size_of::<usize>()) {
        return;
    }
    let exp_ptr = unsafe { core::ptr::read_unaligned(exp_ptr_addr as *const usize) };
    if exp_ptr == 0 {
        return;
    }

    let Some(expansion_slot_offset) =
        ((index - TLS_INLINE_SLOT_COUNT) as usize).checked_mul(core::mem::size_of::<usize>())
    else {
        return;
    };
    let Some(slot_addr) = exp_ptr.checked_add(expansion_slot_offset) else {
        return;
    };
    if !crate::is_addr_range_writable(slot_addr, core::mem::size_of::<usize>()) {
        return;
    }
    unsafe {
        core::ptr::write_unaligned(slot_addr as *mut usize, 0);
    }
}

pub(crate) fn zero_explicit_tls_slot_process_wide<FS: crate::NtShimFS>(
    shared: &crate::NtSharedState<FS>,
    index: u32,
) {
    if index >= TLS_MAX_SLOT_COUNT {
        return;
    }

    let threads = shared
        .threads_by_id
        .lock()
        .values()
        .cloned()
        .collect::<alloc::vec::Vec<_>>();
    for thread in threads {
        zero_explicit_tls_slot_for_teb(thread.teb_va(), index);
    }
}

pub(crate) const CONTEXT_AMD64_FULL_XSTATE: u32 = 0x10_004F;
const CONTEXT_XSTATE_FLAG_AMD64: u32 = 0x40;
const CONTEXT_XSTATE_AMD64: u32 = 0x10_0040;
pub(crate) const CONTEXT_AMD64_FULL: u32 = CONTEXT_AMD64_FULL_XSTATE & !CONTEXT_XSTATE_FLAG_AMD64;
pub(crate) const LEGACY_CONTEXT_SIZE_AMD64: usize = 0x4D0;
pub(crate) const LEGACY_EXCEPTION_RECORD_OFFSET_AMD64: usize = 0x4F0;
pub(crate) const XSTATE_CONTEXT_SIZE_AMD64: usize = 0x650;
pub(crate) const XSTATE_EXCEPTION_RECORD_OFFSET_AMD64: usize = 0x670;
const XSAVE_AREA_OFFSET_AMD64: usize = 0x300;
const XSAVE_AREA_SIZE_AMD64: usize = litebox_common_linux::FP_STATE_SIZE;

fn guest_context_flags(context_ptr: usize) -> u32 {
    crate::try_read_guest_value_unaligned::<u32>(context_ptr + 0x30).unwrap_or(0)
}

pub(crate) fn guest_context_size(context_ptr: usize) -> usize {
    let xstate_end =
        context_ptr.saturating_add(XSAVE_AREA_OFFSET_AMD64 + XSAVE_AREA_SIZE_AMD64 - 1);
    if context_ptr != 0
        && guest_context_flags(context_ptr) & CONTEXT_XSTATE_AMD64 != 0
        && crate::is_addr_committed(context_ptr + XSAVE_AREA_OFFSET_AMD64)
        && crate::is_addr_committed(xstate_end)
    {
        XSTATE_CONTEXT_SIZE_AMD64
    } else {
        LEGACY_CONTEXT_SIZE_AMD64
    }
}

/// Guest-visible xfeature mask: x87 | SSE | AVX.
///
/// Mirrors `GUEST_XSAVE_MASK` / `GUEST_XFEATURE_MASK` used in the platform
/// trampoline and the Linux shim's signal code.
const GUEST_XFEATURE_MASK: u64 = 0x7;
/// Offset of `xcomp_bv` within the XSAVE header (byte 520 in the save area).
const XCOMP_BV_OFFSET: usize = 520;
/// Offset past the 64-byte XSAVE header (byte 576), start of extended data.
const XSTATE_EXTENDED_OFFSET: usize = 576;
/// Default MXCSR: all exceptions masked, round-to-nearest.
const DEFAULT_MXCSR: u32 = 0x1F80;

/// Sanitizes the XSAVE image in `fp_regs` so that a subsequent `xrstor64`
/// will not #GP.
///
/// Modeled after the Linux shim's `sanitize_xsave_image`:
/// - Masks `xstate_bv` to only [`GUEST_XFEATURE_MASK`] bits.
/// - Forces FP + SSE bits on (like Linux's `force_fpsse`).
/// - Zeroes `xcomp_bv` and all reserved XSAVE header bytes (must be zero
///   for non-compacted `xrstor`; non-zero causes #GP).
/// - If AVX is not indicated, zeroes the extended payload.
/// - Validates MXCSR: if it has reserved bits set or is zero (all exceptions
///   unmasked), replaces it with the safe default.
fn sanitize_restored_fp_state(fp: &mut [u8; litebox_common_linux::FP_STATE_SIZE]) {
    let len = fp.len();
    if len <= 512 {
        return;
    }

    // --- XSAVE header (bytes 512..576) ---
    let mut xfeatures = u64::from_le_bytes(fp[512..520].try_into().unwrap()) & GUEST_XFEATURE_MASK;
    // Force x87 + SSE present so xrstor loads the FXSAVE region.
    xfeatures |= 0x3;
    fp[512..520].copy_from_slice(&xfeatures.to_le_bytes());
    // xcomp_bv and reserved must be zero for non-compacted xrstor.
    fp[XCOMP_BV_OFFSET..XSTATE_EXTENDED_OFFSET].fill(0);
    // Zero extended payload if AVX not indicated.
    if xfeatures & 0x4 == 0 && len > XSTATE_EXTENDED_OFFSET {
        fp[XSTATE_EXTENDED_OFFSET..].fill(0);
    }

    // --- MXCSR sanity (offset 24 in FXSAVE area) ---
    let mxcsr = u32::from_le_bytes(fp[24..28].try_into().unwrap());
    // Zero MXCSR means all exceptions unmasked which almost certainly causes
    // an immediate #P/#O/#U on any FP operation.  Reserved bits (16+) must
    // also be clear.
    if mxcsr == 0 || mxcsr & 0xFFFF_0000 != 0 {
        fp[24..28].copy_from_slice(&DEFAULT_MXCSR.to_le_bytes());
    }

    // --- FCW sanity (offset 0 in FXSAVE area) ---
    let fcw = u16::from_le_bytes(fp[0..2].try_into().unwrap());
    if fcw == 0 {
        // Zero FCW means all x87 exceptions unmasked. Use the standard
        // default (all masked, double precision, round-to-nearest).
        fp[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
    }
}

unsafe fn copy_guest_fp_state_from_context(
    ctx: &mut super::super::ExecutionContext,
    context_ptr: usize,
    preserve_xstate_tail: bool,
) {
    let flags = guest_context_flags(context_ptr);
    let p = context_ptr as *const u8;
    let xstate_end =
        context_ptr.saturating_add(XSAVE_AREA_OFFSET_AMD64 + XSAVE_AREA_SIZE_AMD64 - 1);
    if (flags & CONTEXT_XSTATE_AMD64) != 0
        && crate::is_addr_committed(context_ptr + XSAVE_AREA_OFFSET_AMD64)
        && crate::is_addr_committed(xstate_end)
    {
        let copy_len = XSAVE_AREA_SIZE_AMD64.min(ctx.fp_regs.data.len());
        let _ = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                ctx.fp_regs.data.as_mut_ptr(),
                p.add(XSAVE_AREA_OFFSET_AMD64),
                copy_len,
            )
        };
        sanitize_restored_fp_state(&mut ctx.fp_regs.data);
        return;
    }

    let fxsave_size = 512.min(ctx.fp_regs.data.len());
    let _ = unsafe {
        litebox::mm::exception_table::memcpy_fallible(
            ctx.fp_regs.data.as_mut_ptr(),
            p.add(0x100),
            fxsave_size,
        )
    };
    if ctx.fp_regs.data.len() > 512 {
        if !preserve_xstate_tail {
            ctx.fp_regs.data[512..].fill(0);
            ctx.fp_regs.data[512..520].copy_from_slice(&0x3u64.to_le_bytes());
        } else {
            // Preserve existing xstate_bv (may have AVX bit) and OR in x87+SSE.
            let mut xstate_bv = u64::from_le_bytes(ctx.fp_regs.data[512..520].try_into().unwrap());
            xstate_bv |= 0x3;
            ctx.fp_regs.data[512..520].copy_from_slice(&xstate_bv.to_le_bytes());
        }
    }
    sanitize_restored_fp_state(&mut ctx.fp_regs.data);
}

pub(crate) unsafe fn restore_guest_context_from_ptr(
    ctx: &mut super::super::ExecutionContext,
    context_ptr: usize,
    preserve_xstate_tail: bool,
) {
    let p = context_ptr as *const u8;
    let r64 = |off: usize| {
        u64::from_le_bytes(
            unsafe { core::slice::from_raw_parts(p.add(off), 8) }
                .try_into()
                .unwrap(),
        ) as usize
    };
    let r32 = |off: usize| {
        u32::from_le_bytes(
            unsafe { core::slice::from_raw_parts(p.add(off), 4) }
                .try_into()
                .unwrap(),
        )
    };

    ctx.regs.rip = r64(0xF8);
    ctx.regs.rsp = r64(0x98);
    ctx.regs.rax = r64(0x78);
    ctx.regs.rcx = r64(0x80);
    ctx.regs.rdx = r64(0x88);
    ctx.regs.rbx = r64(0x90);
    ctx.regs.rbp = r64(0xA0);
    ctx.regs.rsi = r64(0xA8);
    ctx.regs.rdi = r64(0xB0);
    ctx.regs.r8 = r64(0xB8);
    ctx.regs.r9 = r64(0xC0);
    ctx.regs.r10 = r64(0xC8);
    ctx.regs.r11 = r64(0xD0);
    ctx.regs.r12 = r64(0xD8);
    ctx.regs.r13 = r64(0xE0);
    ctx.regs.r14 = r64(0xE8);
    ctx.regs.r15 = r64(0xF0);
    ctx.eflags = r32(0x44) as usize;
    unsafe { copy_guest_fp_state_from_context(ctx, context_ptr, preserve_xstate_tail) };
}

#[cfg(test)]
mod tests {
    use super::{zero_explicit_tls_slot_for_teb, TLS_INLINE_SLOT_COUNT};

    #[test]
    fn zero_explicit_tls_slot_validates_expansion_slot_pointer() {
        let exp_ptr_offset = crate::peb_teb::teb_offsets::TLS_EXPANSION_SLOTS;
        let mut teb = alloc::vec![0u8; exp_ptr_offset + core::mem::size_of::<usize>()];
        let mut expansion_slots = alloc::vec![0usize; super::TLS_EXPANSION_SLOT_COUNT];
        let slot_index = TLS_INLINE_SLOT_COUNT + 5;
        expansion_slots[5] = 0xDEAD_BEEFusize;

        unsafe {
            core::ptr::write_unaligned(
                (teb.as_mut_ptr() as usize + exp_ptr_offset) as *mut usize,
                expansion_slots.as_mut_ptr() as usize,
            );
        }
        zero_explicit_tls_slot_for_teb(teb.as_ptr() as usize, slot_index);
        assert_eq!(expansion_slots[5], 0);

        unsafe {
            core::ptr::write_unaligned(
                (teb.as_mut_ptr() as usize + exp_ptr_offset) as *mut usize,
                1,
            );
        }
        zero_explicit_tls_slot_for_teb(teb.as_ptr() as usize, slot_index);
    }
}
