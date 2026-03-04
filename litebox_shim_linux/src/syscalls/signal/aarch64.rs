// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::syscalls::signal::{DeliverFault, SignalState};
use crate::MutPtr;
use core::mem::offset_of;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::ReinterpretUnsignedExt as _;
use litebox_common_linux::{
    signal::{aarch64::Sigcontext, SaFlags, SigAction, Siginfo, Ucontext},
    PtRegs,
};
use zerocopy::{FromBytes, IntoBytes};

#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct SignalFrame {
    ucontext: Ucontext,
    siginfo: Siginfo,
}

/// Returns the address of the Ucontext on the guest stack.
///
/// On ARM64 signal delivery, x2 is set to point to the ucontext.
/// `sys_rt_sigreturn` reads the ucontext from this address.
pub(super) fn uctx_addr(ctx: &PtRegs) -> usize {
    ctx.regs[2]
}

pub(super) fn sp(ctx: &PtRegs) -> usize {
    ctx.sp
}

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> usize {
    let mut frame_addr = sp;

    // ARM64 has no redzone.

    // Space for the signal frame.
    frame_addr = frame_addr.wrapping_sub(core::mem::size_of::<SignalFrame>());

    // Align to 16 bytes (ARM64 requires 16-byte stack alignment).
    frame_addr &= !15;

    frame_addr
}

impl SignalState {
    pub(super) fn write_signal_frame(
        &self,
        frame_addr: usize,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut PtRegs,
    ) -> Result<(), DeliverFault> {
        // TODO(aarch64): use sigreturn trampoline from rewriter when SA_RESTORER is not set
        if !action.flags.contains(SaFlags::RESTORER) {
            return Err(DeliverFault);
        }

        let frame = SignalFrame {
            ucontext: Ucontext {
                flags: 0,
                link: 0,
                stack: self.altstack.get(),
                sigmask: self.blocked.get(),
                __unused: [0; 1024 / 8
                    - core::mem::size_of::<litebox_common_linux::signal::SigSet>()],
                mcontext: Sigcontext {
                    fault_address: 0,
                    regs: core::array::from_fn(|i| ctx.regs[i] as u64),
                    sp: ctx.sp as u64,
                    pc: ctx.pc as u64,
                    pstate: ctx.pstate as u64,
                    __reserved: [0; 4096],
                },
            },
            siginfo: siginfo.clone(),
        };

        let frame_ptr = MutPtr::from_usize(frame_addr);
        frame_ptr.write_at_offset(0, frame).ok_or(DeliverFault)?;

        // Set up the guest context for the signal handler.
        // ARM64 calling convention: x0 = first arg, x1 = second arg, x2 = third arg.
        ctx.pc = action.sigaction;
        ctx.sp = frame_addr;
        ctx.regs[0] = siginfo.signo.reinterpret_as_unsigned() as usize;
        ctx.regs[1] = frame_addr.wrapping_add(offset_of!(SignalFrame, siginfo));
        ctx.regs[2] = frame_addr.wrapping_add(offset_of!(SignalFrame, ucontext));
        // x30 (LR) = return address (restorer)
        ctx.regs[30] = action.restorer;

        // ARM64 has no direction flag equivalent to clear.

        Ok(())
    }
}

pub(super) fn restore_sigcontext(
    ctx: &mut PtRegs,
    sigctx: &litebox_common_linux::signal::aarch64::Sigcontext,
) -> usize {
    for i in 0..31 {
        ctx.regs[i] = sigctx.regs[i] as usize;
    }
    ctx.sp = sigctx.sp as usize;
    ctx.pc = sigctx.pc as usize;
    ctx.pstate = sigctx.pstate as usize;

    // TODO: restore FP/SIMD state from __reserved

    // Return x0 (the "return value" register), matching x86_64's convention
    // of returning rax.
    ctx.regs[0]
}
