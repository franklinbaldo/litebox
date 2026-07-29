// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 signal frame construction and teardown.
//!
//! This mirrors `arch/arm64/kernel/signal.c`. The one place where the kernel's
//! behaviour cannot be reproduced is the signal return trampoline: the arm64
//! kernel ignores `sa_restorer` entirely and always points `x30` at the vDSO's
//! `__kernel_rt_sigreturn`. `litebox_platform_linux_userland` exposes no vDSO
//! (`get_vdso_address` returns `None`), so the only trampoline available here is
//! whatever the guest supplied via `SA_RESTORER` — which glibc, following the
//! kernel, does not set on aarch64. See [`SignalState::write_signal_frame`].

use crate::ShimPlatform;
use crate::UserPtrMut;
use crate::syscalls::signal::{DeliverFault, SignalState};
use core::mem::offset_of;
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    AARCH64_GENERAL_REGISTER_COUNT, PtRegs,
    signal::{SaFlags, SigAction, Siginfo, Ucontext, aarch64::Sigcontext},
};
use zerocopy::{FromBytes, IntoBytes};

/// The kernel's `struct rt_sigframe` followed by its `struct frame_record`,
/// i.e. `struct rt_sigframe_user_layout` without the dynamically sized extra
/// context (we emit none).
///
/// Note the field order is the opposite of x86-64's: on arm64 `siginfo` comes
/// first, and there is no return address on the stack because the trampoline is
/// reached through `x30` rather than a `ret`.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct SignalFrame {
    siginfo: Siginfo,
    ucontext: Ucontext,
    /// The kernel's `frame_record`: a terminating `{fp, lr}` pair that lets an
    /// unwinder walk out of the handler.
    next_frame_fp: usize,
    next_frame_lr: usize,
}

/// Widens a register slot. Infallible: the crate requires 64-bit pointers.
#[inline]
fn widen(value: usize) -> u64 {
    const {
        assert!(core::mem::size_of::<usize>() == core::mem::size_of::<u64>());
    }
    u64::from_ne_bytes(value.to_ne_bytes())
}

pub(super) fn uctx_addr(ctx: &PtRegs) -> usize {
    // `rt_sigreturn` recovers the `ucontext` from the stack pointer the handler
    // was entered with, which still points at the base of the frame.
    ctx.sp.wrapping_add(offset_of!(SignalFrame, ucontext))
}

pub(super) fn sp(ctx: &PtRegs) -> usize {
    ctx.sp
}

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> usize {
    // Unlike x86-64, the AArch64 procedure call standard has no red zone, so
    // the frame starts at the current stack pointer.
    let frame_addr = sp.wrapping_sub(core::mem::size_of::<SignalFrame>());
    // The AArch64 stack pointer must be 16-byte aligned at all times.
    frame_addr & !15
}

impl<Platform: ShimPlatform> SignalState<Platform> {
    pub(super) fn write_signal_frame(
        &self,
        frame_addr: usize,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut PtRegs,
    ) -> Result<(), DeliverFault> {
        if !action.flags.contains(SaFlags::RESTORER) {
            // Not a guest error: the arm64 kernel never requires SA_RESTORER,
            // because it supplies `__kernel_rt_sigreturn` in the vDSO. We have
            // no vDSO to point at, so there is no correct value for `x30` here.
            // Reporting `DeliverFault` would be indistinguishable from a genuine
            // stack fault, so fail loudly instead.
            unimplemented!(
                "aarch64: delivering a signal to the guest needs a `rt_sigreturn` \
                 trampoline. The guest set no SA_RESTORER (glibc does not, on \
                 aarch64) and this runtime provides no vDSO `__kernel_rt_sigreturn`."
            );
        }

        let last_exception = self.last_exception.get();
        let mut regs = [0u64; AARCH64_GENERAL_REGISTER_COUNT];
        for (dst, src) in regs.iter_mut().zip(ctx.regs.iter()) {
            *dst = widen(*src);
        }

        let frame = SignalFrame {
            siginfo: siginfo.clone(),
            ucontext: Ucontext {
                flags: 0,
                link: 0, // core::ptr::null_mut(),
                stack: self.altstack.get(),
                sigmask: self.blocked.get(),
                __unused: [0; _],
                __align_pad: [0; _],
                mcontext: Sigcontext {
                    fault_address: widen(last_exception.fault_address),
                    regs,
                    sp: widen(ctx.sp),
                    pc: widen(ctx.pc),
                    pstate: ctx.pstate,
                    __reserved_pad: [0; _],
                    // All-zero is the kernel's terminating `_aarch64_ctx`
                    // record (`magic == 0 && size == 0`), i.e. "no extra
                    // context". FP/SIMD state is not saved.
                    // TODO: save and restore the guest FP/SIMD context.
                    __reserved: [0; _],
                },
            },
            next_frame_fp: ctx.regs[29],
            next_frame_lr: ctx.regs[30],
        };

        let frame_ptr = UserPtrMut::from_usize(frame_addr);
        frame_ptr
            .write_at_offset::<Platform>(0, frame)
            .ok_or(DeliverFault)?;

        // `setup_return` in the kernel.
        ctx.sp = frame_addr;
        ctx.pc = action.sigaction;
        ctx.regs[0] = usize::try_from(siginfo.signo.reinterpret_as_unsigned())
            .expect("a u32 always fits in a 64-bit usize");
        ctx.regs[1] = frame_addr.wrapping_add(offset_of!(SignalFrame, siginfo));
        ctx.regs[2] = frame_addr.wrapping_add(offset_of!(SignalFrame, ucontext));
        // The frame record terminates the unwind chain.
        ctx.regs[29] = frame_addr.wrapping_add(offset_of!(SignalFrame, next_frame_fp));
        ctx.regs[30] = action.restorer;
        ctx.pstate &= litebox_common_linux::arch::SAFE_USER_PSTATE;
        ctx.syscallno = litebox_common_linux::arch::NO_SYSCALL;
        Ok(())
    }
}

pub(super) fn restore_sigcontext(ctx: &mut PtRegs, sigctx: &Sigcontext) -> usize {
    let Sigcontext {
        fault_address: _,
        regs,
        sp,
        pc,
        pstate,
        __reserved_pad: _,
        // TODO: restore the guest FP/SIMD context from the extra context
        // records the kernel would have placed here.
        __reserved: _,
    } = sigctx;

    for (dst, src) in ctx.regs.iter_mut().zip(regs.iter()) {
        *dst = src.trunc();
    }
    ctx.sp = sp.trunc();
    ctx.pc = pc.trunc();
    // The guest chose this value, so only the bits a guest may set survive.
    ctx.pstate = *pstate & litebox_common_linux::arch::SAFE_USER_PSTATE;
    ctx.syscallno = litebox_common_linux::arch::NO_SYSCALL;

    ctx.regs[0]
}
