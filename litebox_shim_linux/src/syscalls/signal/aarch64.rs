// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Partial implementation of the AArch64 Linux signal-frame ABI.
//!
//! LiteBox supplies a fallback restorer because it exposes no guest vDSO.

use crate::syscalls::signal::{DeliverFault, SignalState};
use crate::{ShimFS, ShimPlatform, Task, UserPtrMut};
use core::mem::offset_of;
use litebox::mm::linux::PAGE_SIZE;
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    AARCH64_GENERAL_REGISTER_COUNT, MapFlags, ProtFlags, PtRegs,
    signal::{SaFlags, SigAction, Siginfo, Ucontext, aarch64::Sigcontext},
};
use litebox_syscall_rewriter::aarch64::{
    SVC_FRAME_BYTES, SVC_FRAME_OFF_RETADDR, SVC_FRAME_OFF_STUB, SVC_FRAME_OFF_X16,
};
use zerocopy::{FromBytes, IntoBytes};

/// Linux `rt_sigframe` followed by an unwind-link frame record. Dynamic extra
/// context is omitted.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct SignalFrame {
    siginfo: Siginfo,
    ucontext: Ucontext,
    next_frame_fp: usize,
    next_frame_lr: usize,
}

pub(super) fn uctx_addr(ctx: &PtRegs) -> usize {
    ctx.sp.wrapping_add(offset_of!(SignalFrame, ucontext))
}

pub(super) fn sp(ctx: &PtRegs) -> usize {
    ctx.sp
}

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> usize {
    let frame_addr = sp.wrapping_sub(core::mem::size_of::<SignalFrame>());
    // Linux AArch64 signal entry requires a 16-byte-aligned stack pointer.
    frame_addr & !15
}

/// Synthetic `rt_sigreturn` trampoline for guest `x30`.
///
/// Raw `SVC` would bypass shim dispatch and reach the sandboxed host syscall.
/// Zero slots select async resume without clobbering restored `x16`; the stub
/// clobbers only `x8`, `x16`, and `sp`, which `rt_sigreturn` restores, and
/// preserves NZCV.
mod trampoline {
    use super::{SVC_FRAME_BYTES, SVC_FRAME_OFF_RETADDR, SVC_FRAME_OFF_STUB, SVC_FRAME_OFF_X16};

    const NR_RT_SIGRETURN: u32 = 139;

    const X16: u32 = 16;
    const X8: u32 = 8;
    /// `SP` and `XZR` share encoding 31; which one is meant is per-instruction.
    const SP: u32 = 31;
    const XZR: u32 = 31;

    const fn movz(rd: u32, imm16: u32) -> u32 {
        0xD280_0000 | (imm16 << 5) | rd
    }

    const fn sub_sp(imm12: u32) -> u32 {
        0xD100_0000 | (imm12 << 10) | (SP << 5) | SP
    }

    const fn str_sp(rt: u32, byte_offset: u32) -> u32 {
        assert!(byte_offset.is_multiple_of(8));
        0xF900_0000 | ((byte_offset / 8) << 10) | (SP << 5) | rt
    }

    const fn adr(rd: u32, byte_delta: u32) -> u32 {
        assert!(byte_delta < (1 << 20));
        let immlo = byte_delta & 0x3;
        let immhi = byte_delta >> 2;
        0x1000_0000 | (immlo << 29) | (immhi << 5) | rd
    }

    const fn ldr_literal(rt: u32, byte_delta: u32) -> u32 {
        assert!(byte_delta.is_multiple_of(4));
        0x5800_0000 | ((byte_delta / 4) << 5) | rt
    }

    const fn br(rn: u32) -> u32 {
        0xD61F_0000 | (rn << 5)
    }

    const NOP: u32 = 0xD503_201F;

    const ADR_OFFSET: u32 = 12;
    const CONTINUATION_OFFSET: u32 = 32;
    const LDR_OFFSET: u32 = 24;
    /// The page-aligned stub keeps this 64-bit literal aligned.
    const LITERAL_OFFSET: u32 = 40;

    const CODE: [u32; 10] = [
        movz(X8, NR_RT_SIGRETURN),
        sub_sp(SVC_FRAME_BYTES as u32),
        str_sp(X16, SVC_FRAME_OFF_X16 as u32),
        adr(X16, CONTINUATION_OFFSET - ADR_OFFSET),
        str_sp(X16, SVC_FRAME_OFF_RETADDR as u32),
        str_sp(XZR, SVC_FRAME_OFF_STUB as u32),
        ldr_literal(X16, LITERAL_OFFSET - LDR_OFFSET),
        br(X16),
        NOP,
        NOP,
    ];

    pub(super) const BYTES: usize = LITERAL_OFFSET as usize + 8;

    pub(super) fn assemble(callback: usize) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        for (i, insn) in CODE.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&insn.to_le_bytes());
        }
        out[LITERAL_OFFSET as usize..].copy_from_slice(&callback.to_ne_bytes());
        out
    }
}

fn requested_restorer(action: &SigAction) -> Option<usize> {
    action
        .flags
        .contains(SaFlags::RESTORER)
        .then_some(action.restorer)
}

fn handler_arguments(action: &SigAction, frame_addr: usize) -> Option<(usize, usize)> {
    action.flags.contains(SaFlags::SIGINFO).then(|| {
        (
            frame_addr.wrapping_add(offset_of!(SignalFrame, siginfo)),
            frame_addr.wrapping_add(offset_of!(SignalFrame, ucontext)),
        )
    })
}

/// Returns a cached synthetic `rt_sigreturn` guest mapping.
/// The cache is reset on `execve`; guest VM operations can invalidate it.
pub(super) fn sigreturn_trampoline<Platform: ShimPlatform, FS: ShimFS>(
    task: &Task<Platform, FS>,
    action: &SigAction,
) -> Result<usize, DeliverFault> {
    if let Some(restorer) = requested_restorer(action) {
        return Ok(restorer);
    }

    let mut cached = task.process().sigreturn_trampoline.lock();
    if let Some(addr) = *cached {
        return Ok(addr);
    }

    const { assert!(trampoline::BYTES <= PAGE_SIZE) };

    let page = task
        .do_mmap_anonymous(
            None,
            PAGE_SIZE,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .map_err(|_| DeliverFault)?;

    let callback = task.global.platform.get_syscall_entry_point();
    page.cast::<[u8; trampoline::BYTES]>()
        .write_at_offset::<Platform>(0, trampoline::assemble(callback))
        .ok_or(DeliverFault)?;

    // Drop write before execute; the guest never needs write access.
    task.sys_mprotect_raw(page, PAGE_SIZE, ProtFlags::PROT_READ | ProtFlags::PROT_EXEC)
        .map_err(|_| DeliverFault)?;

    let addr = page.as_usize();
    *cached = Some(addr);
    Ok(addr)
}

impl<Platform: ShimPlatform> SignalState<Platform> {
    pub(super) fn write_signal_frame(
        &self,
        frame_addr: usize,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut PtRegs,
        sigreturn_trampoline: usize,
    ) -> Result<(), DeliverFault> {
        let last_exception = self.last_exception.get();

        let mut regs = [0u64; AARCH64_GENERAL_REGISTER_COUNT];
        for (dst, src) in regs.iter_mut().zip(ctx.regs.iter()) {
            *dst = *src as u64;
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
                    fault_address: last_exception.fault_address as u64,
                    regs,
                    sp: ctx.sp as u64,
                    pc: ctx.pc as u64,
                    pstate: ctx.pstate,
                    __reserved_pad: [0; _],
                    // LiteBox writes only the terminating `_aarch64_ctx` and
                    // omits Linux's required FP/SIMD context.
                    // TODO: save and restore the guest FP/SIMD context. The
                    // transition path does not save V registers, so their values
                    // are unavailable when the frame is built. See
                    // `run_thread_arch` in `litebox_platform_linux_userland`.
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

        ctx.sp = frame_addr;
        ctx.pc = action.sigaction;
        ctx.regs[0] = usize::try_from(siginfo.signo.reinterpret_as_unsigned())
            .expect("a u32 always fits in a 64-bit usize");
        if let Some((siginfo, ucontext)) = handler_arguments(action, frame_addr) {
            ctx.regs[1] = siginfo;
            ctx.regs[2] = ucontext;
        }
        // Link the handler's frame chain to the interrupted frame.
        ctx.regs[29] = frame_addr.wrapping_add(offset_of!(SignalFrame, next_frame_fp));
        ctx.regs[30] = sigreturn_trampoline;
        // PSTATE carries over into the handler: `setup_return` adjusts only
        // TCO and BTYPE, neither of which LiteBox models. `copy_signal_context`
        // has already masked it to the bits a guest may own.
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
        // TODO: restore guest FP/SIMD state from extra context records. This
        // first requires the transition path to save V registers; see
        // `litebox_platform_linux_userland`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::signal::{SaFlags, SigSet};

    fn action(flags: SaFlags, restorer: usize) -> SigAction {
        SigAction {
            sigaction: 0x1000,
            flags,
            __pad: 0,
            restorer,
            mask: SigSet::empty(),
        }
    }

    #[test]
    fn sa_restorer_selects_the_guest_restorer() {
        let set = action(SaFlags::RESTORER, 0x1234_5678);
        assert_eq!(requested_restorer(&set), Some(0x1234_5678));

        let unset = action(SaFlags::empty(), 0x1234_5678);
        assert_eq!(requested_restorer(&unset), None);
    }

    #[test]
    fn handler_arguments_are_only_supplied_for_sa_siginfo() {
        let plain = action(SaFlags::empty(), 0);
        assert_eq!(handler_arguments(&plain, 0x8000), None);

        let siginfo = action(SaFlags::SIGINFO, 0);
        assert_eq!(
            handler_arguments(&siginfo, 0x8000),
            Some((
                0x8000 + offset_of!(SignalFrame, siginfo),
                0x8000 + offset_of!(SignalFrame, ucontext),
            ))
        );
    }
}
