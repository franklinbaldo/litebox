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

/// Validates an MXCSR value against the valid mask and an optional host CPU
/// feature mask. Returns `true` if the value is safe for FXRSTOR.
fn validate_mxcsr(mxcsr: u32, host_mxcsr_mask: u32) -> bool {
    // Reserved bits (16-31) must always be clear.
    if mxcsr & !MXCSR_VALID_MASK != 0 {
        return false;
    }
    // If the host reports a feature mask, unsupported bits must be clear.
    if host_mxcsr_mask != 0 && mxcsr & !host_mxcsr_mask != 0 {
        return false;
    }
    true
}

#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct SignalFrame {
    return_address: usize,
    ucontext: Ucontext,
    siginfo: Siginfo,
}

/// 512-byte FP state buffer matching the FXSAVE layout, used for writing
/// FP state to/from guest signal frames.
#[repr(C, align(64))]
#[derive(Clone, FromBytes, IntoBytes)]
struct FpStateBuf {
    bytes: [u8; FXSAVE_SIZE],
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

/// Reinitializes `guest_fp_state` in TLS by capturing the current (host) FP
/// state. Call this after `execve` so the new process starts with a clean FP
/// state (MXCSR=0x1F80) rather than the previous program's state.
#[cfg(feature = "platform_linux_userland")]
pub(crate) fn reinit_guest_fp_state() {
    let ptr = guest_fp_state_ptr();
    // SAFETY: `ptr` points to a valid 512-byte, 64-byte-aligned TLS area.
    // The current host FP state has a sane MXCSR (0x1F80) from the Rust runtime.
    unsafe {
        core::arch::asm!(
            "fxsave64 [{ptr}]",
            ptr = in(reg) ptr,
            options(preserves_flags),
        );
    }
}

/// Reads the `host_mxcsr_mask` TLS variable captured at thread startup from
/// the CPU's FXSAVE output. Returns the CPU's actual MXCSR feature mask.
/// If the CPU doesn't report a mask (older CPUs), returns 0.
#[cfg(feature = "platform_linux_userland")]
fn read_host_mxcsr_mask() -> u32 {
    let mask: u32;
    // SAFETY: `host_mxcsr_mask` is a u32 TLS variable populated at thread
    // startup in `run_thread_arch`.
    unsafe {
        core::arch::asm!(
            "rdfsbase {tmp}",
            "mov {out:e}, DWORD PTR [{tmp} + host_mxcsr_mask@tpoff]",
            tmp = out(reg) _,
            out = out(reg) mask,
            options(nostack, preserves_flags, readonly),
        );
    }
    mask
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
            let mut fp = FpStateBuf {
                bytes: read_guest_fp_state(),
            };
            // Zero sw_reserved (bytes 464-511). FXSAVE doesn't write these
            // bytes; they may contain stale data. magic1=0 tells the guest
            // this is legacy FXSAVE with no XSAVE extended state.
            fp.bytes[SW_RESERVED_OFFSET..].fill(0);
            let fp_ptr = MutPtr::<FpStateBuf>::from_usize(addr);
            fp_ptr.write_at_offset(0, fp).ok_or(DeliverFault)?;
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

        // Validate MXCSR from guest-controlled signal frame against the
        // trusted host CPU mask to prevent fxrstor #GP fault.
        let mxcsr = u32::from_le_bytes(fp[24..28].try_into().unwrap());
        let host_mask = read_host_mxcsr_mask();
        if !validate_mxcsr(mxcsr, host_mask) {
            return Err(());
        }

        write_guest_fp_state(&fp);
    }

    Ok(ctx.rax)
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::signal::SigSet;

    fn dummy_action() -> SigAction {
        SigAction {
            sigaction: 0x1000,
            restorer: 0x2000,
            flags: SaFlags::RESTORER,
            mask: SigSet::empty(),
            #[cfg(target_arch = "x86_64")]
            __pad: 0,
        }
    }

    // --- Signal frame layout tests ---

    #[test]
    fn signal_frame_is_return_address_aligned() {
        // The frame address should satisfy the x86_64 ABI: 16-byte aligned
        // minus 8 (so that after the call instruction pushes the return
        // address, RSP is 16-byte aligned).
        for &sp in &[
            0x7fff_ffff_f000usize,
            0x7fff_ffff_e008,
            0x7fff_ffff_d100,
            0x1000_0000_0000,
        ] {
            let frame_addr = get_signal_frame(sp, &dummy_action());
            assert_eq!(
                frame_addr % 16,
                8,
                "frame_addr {frame_addr:#x} for sp {sp:#x} should be 16-aligned minus 8"
            );
        }
    }

    #[test]
    fn signal_frame_below_redzone() {
        let sp = 0x7fff_ffff_f000usize;
        let frame_addr = get_signal_frame(sp, &dummy_action());
        // Frame must be at least 128 (redzone) + sizeof(SignalFrame) below sp.
        assert!(
            frame_addr + core::mem::size_of::<SignalFrame>() <= sp - 128,
            "frame overlaps redzone"
        );
    }

    #[test]
    fn fpstate_area_is_64_byte_aligned() {
        for &sp in &[
            0x7fff_ffff_f000usize,
            0x7fff_ffff_e008,
            0x7fff_ffff_d123,
            0x1000_0000_0000,
        ] {
            let frame_addr = get_signal_frame(sp, &dummy_action());
            let fp_addr = fpstate_addr_from_frame(frame_addr);
            assert_eq!(
                fp_addr % FXSAVE_ALIGN,
                0,
                "fpstate {fp_addr:#x} for sp {sp:#x} not 64-byte aligned"
            );
        }
    }

    #[test]
    fn fpstate_fits_between_frame_and_redzone() {
        let sp = 0x7fff_ffff_f000usize;
        let frame_addr = get_signal_frame(sp, &dummy_action());
        let fp_addr = fpstate_addr_from_frame(frame_addr);

        // fpstate must be above the signal frame.
        assert!(
            fp_addr >= frame_addr + core::mem::size_of::<SignalFrame>(),
            "fpstate overlaps signal frame"
        );
        // fpstate + 512 must not exceed sp - 128 (redzone boundary).
        assert!(
            fp_addr + FXSAVE_SIZE <= sp - 128,
            "fpstate extends into redzone"
        );
    }

    #[test]
    fn fpstate_layout_round_trip() {
        // Verify that for various SP values, fpstate_addr_from_frame produces
        // an address that is consistent with get_signal_frame's allocation.
        for sp in (0x1000_0000..0x1000_0100).step_by(8) {
            let frame_addr = get_signal_frame(sp, &dummy_action());
            let fp_addr = fpstate_addr_from_frame(frame_addr);
            assert_eq!(fp_addr % FXSAVE_ALIGN, 0);
            assert!(fp_addr >= frame_addr + core::mem::size_of::<SignalFrame>());
            assert!(fp_addr + FXSAVE_SIZE <= sp - 128);
        }
    }

    // --- MXCSR validation tests ---

    #[test]
    fn mxcsr_default_is_valid() {
        assert!(validate_mxcsr(0x1F80, 0));
        assert!(validate_mxcsr(0x1F80, 0xFFFF));
    }

    #[test]
    fn mxcsr_zero_is_valid() {
        // All exceptions unmasked — unusual but architecturally valid.
        assert!(validate_mxcsr(0x0000, 0));
        assert!(validate_mxcsr(0x0000, 0xFFFF));
    }

    #[test]
    fn mxcsr_reserved_bits_rejected() {
        // Bit 16 is reserved.
        assert!(!validate_mxcsr(0x0001_0000, 0));
        // Bit 31 is reserved.
        assert!(!validate_mxcsr(0x8000_0000, 0));
        // All reserved bits set.
        assert!(!validate_mxcsr(0xFFFF_0000, 0));
    }

    #[test]
    fn mxcsr_host_mask_rejects_unsupported_bits() {
        // Host mask says only bits 0-12 are valid (typical SSE-only CPU).
        let host_mask = 0x0000_FFBF;
        // Bit 6 (DAZ) is not in the mask — should fail.
        assert!(!validate_mxcsr(0x0040, host_mask));
        // Default 0x1F80 should pass (bits 7-12 = exception masks).
        assert!(validate_mxcsr(0x1F80, host_mask));
    }

    #[test]
    fn mxcsr_host_mask_zero_allows_all_low_bits() {
        // host_mask=0 means CPU didn't report a mask, allow all valid bits.
        assert!(validate_mxcsr(0xFFFF, 0));
    }

    #[test]
    fn mxcsr_combined_reserved_and_host_mask() {
        // Bit 16 is reserved AND unsupported — reserved check fires first.
        assert!(!validate_mxcsr(0x0001_0040, 0xFFBF));
    }

    // --- GPR restore round-trip tests ---

    #[test]
    fn restore_sigcontext_restores_gprs() {
        let sigctx = Sigcontext {
            r8: 0x0808,
            r9: 0x0909,
            r10: 0x1010,
            r11: 0x1111,
            r12: 0x1212,
            r13: 0x1313,
            r14: 0x1414,
            r15: 0x1515,
            rdi: 0xD1,
            rsi: 0x51,
            rbp: 0xB9,
            rbx: 0xBB,
            rdx: 0xDD,
            rax: 0xAA,
            rcx: 0xCC,
            rsp: 0x5959,
            rip: 0x1919,
            rflags: 0x0202,
            cs: 0x33,
            gs: 0,
            fs: 0,
            ss: 0x2B,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: 0, // no FP state pointer → skip FP restore
            reserved1: [0; 8],
        };

        let mut ctx = PtRegs::default();
        let result = restore_sigcontext(&mut ctx, &sigctx);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0xAA); // rax
        assert_eq!(ctx.r8, 0x0808);
        assert_eq!(ctx.r15, 0x1515);
        assert_eq!(ctx.rdi, 0xD1);
        assert_eq!(ctx.rsp, 0x5959);
        assert_eq!(ctx.rip, 0x1919);
        assert_eq!(ctx.eflags, 0x0202);
    }

    #[test]
    fn restore_sigcontext_with_zero_fpstate_succeeds() {
        // fpstate=0 means no FP state in the signal frame (legacy).
        // restore_sigcontext should succeed without touching TLS.
        let sigctx = Sigcontext {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 42,
            rcx: 0,
            rsp: 0x1000,
            rip: 0x2000,
            rflags: 0,
            cs: 0x33,
            gs: 0,
            fs: 0,
            ss: 0x2B,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: 0,
            reserved1: [0; 8],
        };

        let mut ctx = PtRegs::default();
        assert_eq!(restore_sigcontext(&mut ctx, &sigctx), Ok(42));
    }
}
