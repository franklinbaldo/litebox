// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 signal frame construction and teardown.
//!
//! This mirrors `arch/arm64/kernel/signal.c`. The one place where the kernel's
//! behaviour cannot be reproduced verbatim is the signal return trampoline: the
//! arm64 kernel ignores `sa_restorer` entirely and always points `x30` at the
//! vDSO's `__kernel_rt_sigreturn`. `litebox_platform_linux_userland` exposes no
//! vDSO (`get_vdso_address` returns `None`), so this module synthesizes an
//! equivalent stub and maps it into guest address space; see
//! [`sigreturn_trampoline`].

use crate::syscalls::signal::{DeliverFault, SignalState};
use crate::{ShimFS, ShimPlatform, Task, UserPtrMut};
use core::mem::offset_of;
use litebox::mm::linux::PAGE_SIZE;
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    AARCH64_GENERAL_REGISTER_COUNT, MapFlags, ProtFlags, PtRegs,
    signal::{SigAction, Siginfo, Ucontext, aarch64::Sigcontext},
};
use litebox_syscall_rewriter::{
    AARCH64_SVC_FRAME_BYTES, AARCH64_SVC_FRAME_RETADDR_OFFSET, AARCH64_SVC_FRAME_STUB_OFFSET,
    AARCH64_SVC_FRAME_X16_OFFSET,
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

/// The `rt_sigreturn` trampoline the guest's `x30` points at while a signal
/// handler runs.
///
/// # Why the shim has to synthesize this at all
///
/// On x86-64 the restorer is the guest's problem: glibc sets `SA_RESTORER` and
/// the kernel just uses it. The arm64 kernel does the opposite — it *ignores*
/// `sa_restorer` and unconditionally points `x30` at `__kernel_rt_sigreturn` in
/// the vDSO — so glibc never sets `SA_RESTORER` on aarch64 and no guest-supplied
/// trampoline exists. LiteBox maps no vDSO, so the shim must provide one.
///
/// # Why it does not simply contain `SVC`
///
/// A raw `SVC` in runtime-generated code is not covered by the syscall
/// rewriter, so it would reach the *host* kernel, which would then try to
/// restore a signal frame it never created from a guest-controlled stack. That
/// is both incorrect (the guest's context lives in the shim, not the host) and
/// a sandbox-escape shape. So instead of an `SVC`, the stub reproduces by hand
/// exactly what a rewritten `SVC` site does: it builds the rewriter's gate frame
/// and branches straight to the runtime's syscall callback.
///
/// ```text
///   +0  movz x8, #139                 // __NR_rt_sigreturn
///   +4  sub  sp, sp, #SVC_FRAME_BYTES // carve out the gate frame
///   +8  str  x16, [sp, #X16_OFFSET]   // the gate's saved guest x16
///  +12  str  xzr, [sp, #RETADDR_OFF]  // resume PC: none
///  +16  str  xzr, [sp, #STUB_OFFSET]  // outbound stub: none
///  +20  ldr  x16, callback            // literal load, +12 bytes ahead
///  +24  br   x16
///  +28  nop                           // align the literal to 8 bytes
///  +32  .quad <syscall callback>
/// ```
///
/// # Why the two zeroed slots are correct
///
/// The runtime's `syscall_callback` copies the gate frame's stub and resume-PC
/// slots into TLS, and `switch_to_guest` uses the recorded stub to re-enter the
/// guest with `x16` restored. That fast path is only valid when resuming at the
/// original syscall site. `rt_sigreturn` resumes at an arbitrary PC restored
/// from the signal frame and never at a syscall site, so a stub would be flatly
/// wrong here. Storing zero in the stub slot is exactly how the ABI says "no
/// stub": `switch_to_guest` takes its direct-branch fallback, which materializes
/// `PtRegs::pc` into `x16` and branches. Clobbering `x16` on that path is
/// harmless — restoring an arbitrary PC together with full register state is
/// precisely what an `rt_sigreturn` frame is for, and `regs[16]` is restored
/// from the frame either way.
///
/// The resume-PC slot is zeroed for determinism only: the fallback is already
/// forced by the null stub, and `restore_sigcontext` overwrites `PtRegs::pc`
/// wholesale. Leaving it uninitialized would publish a stale guest stack word as
/// a PC.
///
/// # Register and flag discipline
///
/// The stub clobbers `x8` and `x16` and moves `sp`; every one of those is
/// restored from the saved `sigcontext` by `rt_sigreturn` itself, so nothing
/// needs preserving. `MOVZ`, `SUB` (not `SUBS`), `STR`, `LDR` and `BR` leave
/// NZCV alone, so the guest's flags reach the callback unchanged — the same
/// property the rewriter's own gate relies on.
mod trampoline {
    use super::{
        AARCH64_SVC_FRAME_BYTES, AARCH64_SVC_FRAME_RETADDR_OFFSET, AARCH64_SVC_FRAME_STUB_OFFSET,
        AARCH64_SVC_FRAME_X16_OFFSET,
    };

    /// `__NR_rt_sigreturn` on the AArch64 (generic) syscall table.
    const NR_RT_SIGRETURN: u32 = 139;

    const X16: u32 = 16;
    const X8: u32 = 8;
    /// `SP` and `XZR` share encoding 31; which one is meant is per-instruction.
    const SP: u32 = 31;
    const XZR: u32 = 31;

    /// `MOVZ Xd, #imm16`.
    const fn movz(rd: u32, imm16: u32) -> u32 {
        0xD280_0000 | (imm16 << 5) | rd
    }

    /// `SUB SP, SP, #imm12` (no flags).
    const fn sub_sp(imm12: u32) -> u32 {
        0xD100_0000 | (imm12 << 10) | (SP << 5) | SP
    }

    /// `STR Xt, [SP, #imm]`, unsigned scaled offset.
    const fn str_sp(rt: u32, byte_offset: u32) -> u32 {
        assert!(byte_offset.is_multiple_of(8));
        0xF900_0000 | ((byte_offset / 8) << 10) | (SP << 5) | rt
    }

    /// `LDR Xt, <label>`, PC-relative literal load.
    const fn ldr_literal(rt: u32, byte_delta: u32) -> u32 {
        assert!(byte_delta.is_multiple_of(4));
        0x5800_0000 | ((byte_delta / 4) << 5) | rt
    }

    /// `BR Xn`.
    const fn br(rn: u32) -> u32 {
        0xD61F_0000 | (rn << 5)
    }

    const NOP: u32 = 0xD503_201F;

    /// Byte offset of the `LDR` literal within the stub.
    const LDR_OFFSET: u32 = 20;
    /// Byte offset of the callback literal. 8-byte aligned (the stub itself is
    /// page-aligned), as a 64-bit literal load requires.
    const LITERAL_OFFSET: u32 = 32;

    const CODE: [u32; 8] = [
        movz(X8, NR_RT_SIGRETURN),
        sub_sp(AARCH64_SVC_FRAME_BYTES as u32),
        str_sp(X16, AARCH64_SVC_FRAME_X16_OFFSET as u32),
        str_sp(XZR, AARCH64_SVC_FRAME_RETADDR_OFFSET as u32),
        str_sp(XZR, AARCH64_SVC_FRAME_STUB_OFFSET as u32),
        ldr_literal(X16, LITERAL_OFFSET - LDR_OFFSET),
        br(X16),
        NOP,
    ];

    /// Total size of the emitted stub, code plus literal.
    pub(super) const BYTES: usize = LITERAL_OFFSET as usize + 8;

    /// Assembles the stub, with `callback` (the runtime's syscall entry point)
    /// baked into the literal pool.
    pub(super) fn assemble(callback: usize) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        for (i, insn) in CODE.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&insn.to_le_bytes());
        }
        out[LITERAL_OFFSET as usize..].copy_from_slice(&callback.to_ne_bytes());
        out
    }
}

/// Returns this process's `rt_sigreturn` trampoline, mapping it on first use.
///
/// The stub is one anonymous `PROT_READ | PROT_EXEC` guest page obtained through
/// the shim's ordinary `mmap` path, so it is a first-class, *reserved* mapping
/// in the process's memory manager: `mmap` will never hand the same range out
/// again, and it cannot silently overwrite another object. (Contrast the
/// rewriter's appended trampoline, whose placement is not covered by any
/// reservation — see the TODO on `trampoline_addr_for`. Deliberately not
/// repeating that here.)
///
/// It lives for the life of the address space. A guest *can* `munmap` it, just
/// as it can `munmap` the vDSO on a real kernel; the consequence is identical
/// (a fault on return from the next signal handler) and equally self-inflicted.
/// `execve` tears the address space down, and clears the cached address with it.
/// `action` is accepted for signature parity with x86-64 and deliberately
/// ignored: the arm64 kernel ignores `sa_restorer` too, so honouring a
/// guest-supplied one here would diverge from the kernel.
pub(super) fn sigreturn_trampoline<Platform: ShimPlatform, FS: ShimFS>(
    task: &Task<Platform, FS>,
    _action: &SigAction,
) -> Result<usize, DeliverFault> {
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

    // Drop write before granting execute: the guest never needs to write here,
    // and a W+X guest page would be a gratuitous weakening.
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
        // `sa_restorer` is deliberately ignored, exactly as `arch/arm64` does:
        // on arm64 the field is not part of the ABI, so a guest that sets it
        // (a port of x86-64 asm, say) has set something the kernel would never
        // have honoured. Always use our own trampoline.
        ctx.regs[30] = sigreturn_trampoline;
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
