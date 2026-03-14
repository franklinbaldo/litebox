// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(feature = "platform_linux_userland")]
use crate::ConstPtr;
use crate::MutPtr;
use crate::syscalls::signal::{DeliverFault, SignalState};
use core::mem::offset_of;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    PtRegs,
    signal::{SaFlags, SigAction, Siginfo, Ucontext, x86_64::Sigcontext},
};
use zerocopy::{FromBytes, IntoBytes};

/// Size of the FXSAVE area in bytes.
const FXSAVE_SIZE: usize = 512;
/// FXSAVE area alignment (64-byte for future XSAVE compatibility).
const FXSAVE_ALIGN: usize = 64;
/// MXCSR bits that are valid (non-reserved). Bits 16-31 are reserved.
const MXCSR_VALID_MASK: u32 = 0x0000_FFFF;

#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct SignalFrame {
    return_address: usize,
    ucontext: Ucontext,
    siginfo: Siginfo,
}

/// Best-effort snapshot of the live x87/SSE state via `fxsave64`.
///
/// This is for debugging signal-corruption hypotheses on x86_64. It captures
/// the architectural FXSAVE area (512 bytes), which includes x87 state,
/// MXCSR, and XMM registers, but not AVX upper halves.
#[repr(C, align(16))]
pub(super) struct FpStateSnapshot {
    bytes: [u8; 512],
}

impl Default for FpStateSnapshot {
    fn default() -> Self {
        Self { bytes: [0; 512] }
    }
}

pub(super) fn capture_fp_state() -> FpStateSnapshot {
    let mut snapshot = FpStateSnapshot::default();
    // SAFETY: `snapshot` is 16-byte aligned and points to writable memory of
    // the required FXSAVE size.
    unsafe {
        core::arch::asm!(
            "fxsave64 [{ptr}]",
            ptr = in(reg) snapshot.bytes.as_mut_ptr(),
            options(preserves_flags),
        );
    }
    snapshot
}

pub(super) fn fpstate_hash(snapshot: &FpStateSnapshot) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in &snapshot.bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

pub(super) fn fpstate_mxcsr(snapshot: &FpStateSnapshot) -> u32 {
    u32::from_le_bytes(snapshot.bytes[24..28].try_into().unwrap())
}

pub(super) fn fpstate_diff_summary(
    before: &FpStateSnapshot,
    after: &FpStateSnapshot,
) -> (usize, [usize; 8], usize) {
    let mut changed_bytes = 0;
    let mut first_diffs = [0usize; 8];
    let mut first_diff_count = 0;

    for (idx, (&lhs, &rhs)) in before.bytes.iter().zip(after.bytes.iter()).enumerate() {
        if lhs == rhs {
            continue;
        }
        changed_bytes += 1;
        if first_diff_count < first_diffs.len() {
            first_diffs[first_diff_count] = idx;
            first_diff_count += 1;
        }
    }

    (changed_bytes, first_diffs, first_diff_count)
}

/// Returns a pointer to the `guest_fp_state` TLS variable defined in the
/// platform crate's `.tbss` section. This is only available on the
/// linux_userland platform where the guest FP state is saved/restored via
/// FXSAVE64/FXRSTOR64 in the platform asm.
#[cfg(feature = "platform_linux_userland")]
fn guest_fp_state_ptr() -> *mut u8 {
    let ptr: *mut u8;
    // SAFETY: `rdfsbase` reads the FS base which points to TLS. Adding
    // `guest_fp_state@tpoff` gives the address of the TLS variable.
    // The variable is 512 bytes, 64-byte aligned, defined in the
    // platform crate's global_asm.
    unsafe {
        core::arch::asm!(
            "rdfsbase {0}",
            "add {0}, OFFSET guest_fp_state@tpoff",
            out(reg) ptr,
            options(nostack, preserves_flags),
        );
    }
    ptr
}

/// Reads the guest FP state from TLS into a stack buffer.
#[cfg(feature = "platform_linux_userland")]
fn read_guest_fp_state() -> [u8; FXSAVE_SIZE] {
    let ptr = guest_fp_state_ptr();
    let mut buf = [0u8; FXSAVE_SIZE];
    // SAFETY: `guest_fp_state` is a 512-byte TLS variable that is always valid
    // when running on a shim thread.
    unsafe {
        core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), FXSAVE_SIZE);
    }
    buf
}

/// Writes guest FP state from a buffer back to TLS, where `switch_to_guest`
/// will restore it to the CPU via FXRSTOR64.
#[cfg(feature = "platform_linux_userland")]
fn write_guest_fp_state(buf: &[u8; FXSAVE_SIZE]) {
    let ptr = guest_fp_state_ptr();
    // SAFETY: Same as read_guest_fp_state.
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, FXSAVE_SIZE);
    }
}

pub(super) fn uctx_addr(ctx: &PtRegs) -> usize {
    ctx.rsp
}

pub(super) fn sp(ctx: &PtRegs) -> usize {
    ctx.rsp
}

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> usize {
    let mut frame_addr = sp;

    // Skip the redzone.
    frame_addr = frame_addr.wrapping_sub(128);

    // Reserve space for FpState (512 bytes, 64-byte aligned).
    // Align down first, then subtract the FpState size.
    frame_addr = (frame_addr.wrapping_sub(FXSAVE_SIZE)) & !(FXSAVE_ALIGN - 1);

    // Space for the signal frame.
    frame_addr = frame_addr.wrapping_sub(core::mem::size_of::<SignalFrame>());

    // Align the frame (offset by 8 bytes for return address)
    frame_addr &= !15;
    frame_addr = frame_addr.wrapping_sub(8);

    frame_addr
}

/// Computes the fpstate address on the guest stack given the signal frame
/// address. The FpState lives above the SignalFrame, 64-byte aligned.
fn fpstate_addr_from_frame(frame_addr: usize) -> usize {
    let above_frame = frame_addr.wrapping_add(core::mem::size_of::<SignalFrame>());
    // Align up to FXSAVE_ALIGN.
    (above_frame + (FXSAVE_ALIGN - 1)) & !(FXSAVE_ALIGN - 1)
}

impl SignalState {
    pub(super) fn write_signal_frame(
        &self,
        frame_addr: usize,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut PtRegs,
    ) -> Result<(), DeliverFault> {
        if !action.flags.contains(SaFlags::RESTORER) {
            return Err(DeliverFault);
        }

        // Compute fpstate address and write guest FP state to guest stack.
        #[cfg(feature = "platform_linux_userland")]
        let fpstate_guest_addr = {
            const SW_RESERVED_OFFSET: usize = 464;
            let addr = fpstate_addr_from_frame(frame_addr);
            let mut fp = read_guest_fp_state();
            // Zero sw_reserved (bytes 464-511). FXSAVE doesn't write these
            // bytes; they may contain stale data. magic1=0 tells the guest
            // this is legacy FXSAVE with no XSAVE extended state.
            fp[SW_RESERVED_OFFSET..].fill(0);
            let fp_ptr = MutPtr::<u8>::from_usize(addr);
            fp_ptr.write_slice_at_offset(0, &fp).ok_or(DeliverFault)?;
            addr as u64
        };
        #[cfg(not(feature = "platform_linux_userland"))]
        let fpstate_guest_addr: u64 = 0;

        let last_exception = self.last_exception.get();
        let frame = SignalFrame {
            return_address: action.restorer,
            ucontext: Ucontext {
                flags: 0,
                link: 0, // core::ptr::null_mut(),
                stack: self.altstack.get(),
                mcontext: Sigcontext {
                    r8: ctx.r8 as u64,
                    r9: ctx.r9 as u64,
                    r10: ctx.r10 as u64,
                    r11: ctx.r11 as u64,
                    r12: ctx.r12 as u64,
                    r13: ctx.r13 as u64,
                    r14: ctx.r14 as u64,
                    r15: ctx.r15 as u64,
                    rdi: ctx.rdi as u64,
                    rsi: ctx.rsi as u64,
                    rbp: ctx.rbp as u64,
                    rbx: ctx.rbx as u64,
                    rdx: ctx.rdx as u64,
                    rax: ctx.rax as u64,
                    rcx: ctx.rcx as u64,
                    rsp: ctx.rsp as u64,
                    rip: ctx.rip as u64,
                    rflags: ctx.eflags as u64,
                    cs: ctx.cs.truncate(),
                    gs: 0,
                    fs: 0,
                    ss: ctx.ss.truncate(),
                    err: last_exception.error_code.into(),
                    trapno: last_exception.exception.0.into(),
                    oldmask: self.blocked.get().as_u64(),
                    cr2: last_exception.cr2 as u64,
                    fpstate: fpstate_guest_addr,
                    reserved1: [0; 8],
                },
                sigmask: self.blocked.get(),
            },
            siginfo: siginfo.clone(),
        };

        let frame_ptr = MutPtr::from_usize(frame_addr);
        frame_ptr.write_at_offset(0, frame).ok_or(DeliverFault)?;

        ctx.rsp = frame_addr;
        ctx.rip = action.sigaction;
        ctx.rdi = siginfo.signo.reinterpret_as_unsigned() as usize;
        ctx.rsi = frame_addr.wrapping_add(offset_of!(SignalFrame, siginfo));
        ctx.rdx = frame_addr.wrapping_add(offset_of!(SignalFrame, ucontext));
        ctx.rax = 0;
        ctx.eflags &= !litebox_common_linux::EFLAGS_DF;
        Ok(())
    }
}

pub(super) fn restore_sigcontext(
    ctx: &mut PtRegs,
    sigctx: &litebox_common_linux::signal::x86_64::Sigcontext,
) -> Result<usize, ()> {
    let litebox_common_linux::signal::x86_64::Sigcontext {
        r8,
        r9,
        r10,
        r11,
        r12,
        r13,
        r14,
        r15,
        rdi,
        rsi,
        rbp,
        rbx,
        rdx,
        rax,
        rcx,
        rsp,
        rip,
        rflags,
        cs: _,
        gs: _,
        fs: _,
        ss: _,
        err: _,
        trapno: _,
        oldmask: _,
        cr2: _,
        fpstate,
        reserved1: _,
    } = *sigctx;

    ctx.r8 = r8.truncate();
    ctx.r9 = r9.truncate();
    ctx.r10 = r10.truncate();
    ctx.r11 = r11.truncate();
    ctx.r12 = r12.truncate();
    ctx.r13 = r13.truncate();
    ctx.r14 = r14.truncate();
    ctx.r15 = r15.truncate();
    ctx.rdi = rdi.truncate();
    ctx.rsi = rsi.truncate();
    ctx.rbp = rbp.truncate();
    ctx.rbx = rbx.truncate();
    ctx.rdx = rdx.truncate();
    ctx.rax = rax.truncate();
    ctx.rcx = rcx.truncate();
    ctx.rsp = rsp.truncate();
    ctx.rip = rip.truncate();
    ctx.eflags = rflags.truncate();

    // Restore FP state from the signal frame if present.
    #[cfg(feature = "platform_linux_userland")]
    if fpstate != 0 {
        // This is x86_64-only code; fpstate is a u64 guest pointer.
        #[allow(clippy::cast_possible_truncation)]
        let fp_ptr = ConstPtr::<u8>::from_usize(fpstate as usize);
        let Some(fp_bytes) = fp_ptr.to_owned_slice(FXSAVE_SIZE) else {
            return Err(());
        };

        let mut fp: [u8; FXSAVE_SIZE] = [0; FXSAVE_SIZE];
        fp.copy_from_slice(&fp_bytes);

        // Validate MXCSR from guest-controlled signal frame to prevent
        // fxrstor #GP fault. Reserved bits (16-31) must be clear.
        let mxcsr = u32::from_le_bytes(fp[24..28].try_into().unwrap());
        if mxcsr & !MXCSR_VALID_MASK != 0 {
            return Err(());
        }
        // Apply mxcsr_mask if non-zero (bits the CPU doesn't support must be 0).
        let mxcsr_mask = u32::from_le_bytes(fp[28..32].try_into().unwrap());
        if mxcsr_mask != 0 && mxcsr & !mxcsr_mask != 0 {
            return Err(());
        }

        write_guest_fp_state(&fp);
    }

    Ok(ctx.rax)
}
