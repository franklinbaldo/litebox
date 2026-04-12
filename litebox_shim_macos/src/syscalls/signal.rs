// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS signal handling: sigaction, sigprocmask, signal delivery, and sigreturn.

use core::sync::atomic::Ordering;
use litebox::platform::RawConstPointer as _;
use litebox::platform::RawMutPointer as _;
use litebox_common_macos::PtRegs;
use litebox_common_macos::errno::Errno;

use crate::{ConstPtr, MutPtr, ShimFS, Task};

// macOS signal constants.
const _SIG_DFL: u64 = 0;
const _SIG_IGN: u64 = 1;
const _SIGKILL: i32 = 9;
const _SIGSTOP: i32 = 17;

// SA_* flag constants.
const _SA_SIGINFO: u32 = 0x0040;
#[allow(dead_code)]
const SA_NODEFER: u32 = 0x0010;
/// SA_ONSTACK: deliver signal on alternate signal stack.
const SA_ONSTACK: u32 = 0x0001;

// sigprocmask `how` constants.
const SIG_BLOCK: i32 = 1;
const SIG_UNBLOCK: i32 = 2;
const SIG_SETMASK: i32 = 3;

// Signals that cannot be caught or blocked.
const UNCATCHABLE_MASK: u32 = (1 << (9 - 1)) | (1 << (17 - 1)); // SIGKILL | SIGSTOP

// UC_FLAVOR for aarch64 (used by _sigtramp and sigreturn).
#[allow(dead_code)]
const UC_FLAVOR: u64 = 30;

// Signal frame component sizes (bytes).
#[allow(dead_code)]
const SIGINFO_SIZE: usize = 104;
#[allow(dead_code)]
const UCONTEXT_SIZE: usize = 56;
#[allow(dead_code)]
const MCONTEXT_SIZE: usize = 816;
#[allow(dead_code)]
const REDZONE_SIZE: usize = 128;

// Offsets within ucontext_t (56 bytes).
const _UCTX_ONSTACK: usize = 0;
#[allow(dead_code)]
const UCTX_SIGMASK: usize = 4;
// uc_stack at offset 8, 24 bytes (ss_sp, ss_size, ss_flags, pad)
const _UCTX_LINK: usize = 32;
#[allow(dead_code)]
const UCTX_MCSIZE: usize = 40;
#[allow(dead_code)]
const UCTX_MCONTEXT: usize = 48;

// Offsets within __darwin_mcontext64 (816 bytes).
// __es: exception state at offset 0, 16 bytes.
#[allow(dead_code)]
const MCTX_ES_FAR: usize = 0;
const _MCTX_ES_ESR: usize = 8;
// __ss: thread state at offset 16, 272 bytes.
#[allow(dead_code)]
const MCTX_SS_BASE: usize = 16;
// Within __ss: x[0..29] at offset 0, fp at 232, lr at 240, sp at 248, pc at 256, cpsr at 264.
#[allow(dead_code)]
const SS_X_BASE: usize = 0; // x[0..29], 8 bytes each
#[allow(dead_code)]
const SS_FP: usize = 232; // x29
#[allow(dead_code)]
const SS_LR: usize = 240; // x30
#[allow(dead_code)]
const SS_SP: usize = 248;
#[allow(dead_code)]
const SS_PC: usize = 256;
#[allow(dead_code)]
const SS_CPSR: usize = 264;
// __ns: NEON state at offset 288, 528 bytes — zeroed (not saved).

// Offsets within siginfo_t (104 bytes).
#[allow(dead_code)]
const SI_SIGNO: usize = 0;
const _SI_ERRNO: usize = 4;
#[allow(dead_code)]
const SI_CODE: usize = 8;
#[allow(dead_code)]
const SI_ADDR: usize = 24;

// Signal codes.
#[allow(dead_code)]
const SEGV_MAPERR: i32 = 1;

/// Map a Linux signal number (from the platform's ExceptionInfo.esr) to a macOS signal number.
///
/// Most signals have the same number on both platforms. The notable
/// exception is SIGBUS (Linux 7 → macOS 10).
pub(crate) fn linux_to_macos_signal(linux_sig: i32) -> i32 {
    match linux_sig {
        7 => 10,        // Linux SIGBUS=7 → macOS SIGBUS=10
        _ => linux_sig, // SIGILL(4), SIGTRAP(5), SIGFPE(8), SIGSEGV(11) are the same
    }
}

/// Check if a stack pointer falls within the given alternate signal stack range.
fn is_on_stack(stack: &litebox_common_macos::SigAltStack, sp: usize) -> bool {
    if stack.ss_flags & litebox_common_macos::SS_DISABLE != 0 {
        return false;
    }
    let stack_start = stack.ss_sp;
    let stack_end = stack.ss_sp + stack.ss_size;
    sp >= stack_start && sp < stack_end
}

/// Result of delivering a software-originated signal (kill, pthread_kill).
///
/// This tells the caller whether the signal was delivered via a user
/// handler (and ctx was rewritten to the signal frame), so that
/// `set_syscall_return` can be skipped.
pub(crate) enum KillResult {
    /// Signal delivered or ignored; syscall returns 0.  If a user handler
    /// was invoked, ctx has already been rewritten to the signal frame and
    /// the caller must NOT call `set_syscall_return`.
    Delivered { frame_set: bool },
}

impl<FS: ShimFS> Task<FS> {
    /// Handle `sigaction()` (BSD syscall 46).
    ///
    /// Reads the kernel-facing `struct __sigaction` (24 bytes) from `new_act`
    /// and writes the user-facing `struct sigaction` (16 bytes) to `old_act`.
    pub(crate) fn sys_sigaction(
        &self,
        signum: i32,
        new_act: usize,
        old_act: usize,
    ) -> Result<usize, Errno> {
        if !(1..=31).contains(&signum) {
            return Err(Errno::EINVAL);
        }
        // SIGKILL and SIGSTOP cannot have their handlers changed.
        if signum == _SIGKILL || signum == _SIGSTOP {
            return Err(Errno::EINVAL);
        }

        let mut handlers = self.process.signal_handlers.lock();
        #[allow(clippy::cast_sign_loss)]
        let idx = signum as usize;

        // Write old handler to user space (struct sigaction, 16 bytes):
        //   [0..8]  sa_handler/sa_sigaction
        //   [8..12] sa_mask
        //   [12..16] sa_flags
        if old_act != 0 {
            let old = &handlers[idx];
            let ptr: MutPtr<u8> = MutPtr::from_usize(old_act);
            let handler_bytes = old.handler.to_le_bytes();
            ptr.copy_from_slice(0, &handler_bytes)
                .ok_or(Errno::EFAULT)?;
            let mask_bytes = old.mask.to_le_bytes();
            ptr.copy_from_slice(8, &mask_bytes).ok_or(Errno::EFAULT)?;
            let flags_bytes = old.flags.to_le_bytes();
            ptr.copy_from_slice(12, &flags_bytes).ok_or(Errno::EFAULT)?;
        }

        // Read new handler from user space (struct __sigaction, 24 bytes):
        //   [0..8]   sa_handler/sa_sigaction
        //   [8..16]  sa_tramp
        //   [16..20] sa_mask
        //   [20..24] sa_flags
        if new_act != 0 {
            let ptr: ConstPtr<u8> = ConstPtr::from_usize(new_act);
            let mut buf = [0u8; 24];
            #[allow(clippy::needless_range_loop)]
            for i in 0..24 {
                #[allow(clippy::cast_possible_wrap)]
                let val = ptr.read_at_offset(i as isize).ok_or(Errno::EFAULT)?;
                buf[i] = val;
            }
            handlers[idx] = crate::SignalHandler {
                handler: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
                tramp: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
                mask: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
                flags: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            };
        }

        Ok(0)
    }

    /// Handle `sigprocmask()` (BSD syscall 48).
    ///
    /// Reads/writes a 4-byte `sigset_t` (macOS 32-bit signal mask).
    pub(crate) fn sys_sigprocmask(
        &self,
        how: i32,
        set: usize,
        oldset: usize,
    ) -> Result<usize, Errno> {
        let current = self.blocked_signals.load(Ordering::Relaxed);

        // Write old mask to user space.
        if oldset != 0 {
            let ptr: MutPtr<u8> = MutPtr::from_usize(oldset);
            ptr.copy_from_slice(0, &current.to_le_bytes())
                .ok_or(Errno::EFAULT)?;
        }

        // Read and apply new mask.
        if set != 0 {
            let ptr: ConstPtr<u8> = ConstPtr::from_usize(set);
            let mut buf = [0u8; 4];
            #[allow(clippy::needless_range_loop)]
            for i in 0..4 {
                #[allow(clippy::cast_possible_wrap)]
                let val = ptr.read_at_offset(i as isize).ok_or(Errno::EFAULT)?;
                buf[i] = val;
            }
            let new_mask = u32::from_le_bytes(buf);

            let updated = match how {
                SIG_BLOCK => current | new_mask,
                SIG_UNBLOCK => current & !new_mask,
                SIG_SETMASK => new_mask,
                _ => return Err(Errno::EINVAL),
            };

            // Never allow blocking SIGKILL or SIGSTOP.
            self.blocked_signals
                .store(updated & !UNCATCHABLE_MASK, Ordering::Relaxed);
        }

        Ok(0)
    }

    /// Handle `kill()` (BSD syscall 37).
    ///
    /// Only supports sending signals to the calling process (pid == getpid,
    /// pid == 0, or pid == -1).  Other targets return ESRCH.
    #[allow(clippy::cast_sign_loss)]
    pub(crate) fn sys_kill(
        &self,
        pid: i32,
        sig: i32,
        ctx: &mut PtRegs,
    ) -> Result<KillResult, Errno> {
        // Only allow signals to self (pid 42 is our fixed getpid).
        let my_pid = 42i32;
        if pid != my_pid && pid != 0 && pid != -1 && pid != -(my_pid) {
            log_unsupported!("kill: target pid {} not supported (only self)", pid);
            return Err(Errno::ESRCH);
        }
        self.deliver_software_signal(sig, ctx)
    }

    /// Handle `__pthread_kill()` (BSD syscall 328).
    ///
    /// Only supports sending signals to the calling thread (matching mach
    /// port).  Other targets return ESRCH.
    #[allow(clippy::cast_sign_loss)]
    pub(crate) fn sys_pthread_kill(
        &self,
        port: u32,
        sig: i32,
        ctx: &mut PtRegs,
    ) -> Result<KillResult, Errno> {
        let my_port = self.real_mach_port.load(Ordering::Relaxed);
        if port != my_port && port != 0 {
            log_unsupported!(
                "__pthread_kill: target port {} != self port {} — not supported",
                port,
                my_port
            );
            return Err(Errno::ESRCH);
        }
        self.deliver_software_signal(sig, ctx)
    }

    /// Common signal delivery for kill / __pthread_kill.
    ///
    /// If `sig == 0` this is a permission check only (always succeeds).
    /// Otherwise looks up the handler and either terminates (SIG_DFL for
    /// fatal signals), ignores, or builds a signal frame.
    #[allow(clippy::cast_sign_loss)]
    fn deliver_software_signal(&self, sig: i32, ctx: &mut PtRegs) -> Result<KillResult, Errno> {
        // Signal 0 is a null signal: permission check only.
        if sig == 0 {
            return Ok(KillResult::Delivered { frame_set: false });
        }
        // Validate signal range.
        if !(1..=31).contains(&sig) {
            return Err(Errno::EINVAL);
        }

        let handler = {
            let handlers = self.process.signal_handlers.lock();
            handlers[sig as usize]
        };

        match handler.handler {
            0 => {
                // SIG_DFL.  For most signals this means terminate.
                // (SIGCHLD and SIGURG are ignored by default, others are fatal.)
                match sig {
                    // Signals ignored by default on macOS.
                    16 /* SIGURG */ |
                    19 /* SIGCONT — resume; no-op since we don't support stop */ |
                    20 /* SIGCHLD */ |
                    23 /* SIGIO */ |
                    28 /* SIGWINCH */ => {
                        Ok(KillResult::Delivered { frame_set: false })
                    }
                    _ => {
                        // Fatal: set exit code to 128+sig and terminate.
                        self.process
                            .exit_code
                            .store(128 + sig, Ordering::Release);
                        self.process.group_exit.store(true, Ordering::Release);
                        self.terminated.store(true, Ordering::Release);
                        Ok(KillResult::Delivered { frame_set: false })
                    }
                }
            }
            1 => {
                // SIG_IGN: silently ignore.
                Ok(KillResult::Delivered { frame_set: false })
            }
            _ => {
                // User handler: build a signal frame.
                // deliver_signal rewrites ctx to point at _sigtramp.
                self.deliver_signal(ctx, sig, 0, &handler);
                Ok(KillResult::Delivered { frame_set: true })
            }
        }
    }

    /// Handle `sigaltstack()` (BSD syscall 53).
    ///
    /// If `old_ss` is non-null, writes the current alternate signal stack.
    /// If `ss` is non-null, validates and installs a new alternate signal stack.
    /// Cannot change the stack while executing on it.
    pub(crate) fn sys_sigaltstack(
        &self,
        ss_addr: usize,
        old_ss_addr: usize,
        ctx: &PtRegs,
    ) -> Result<usize, Errno> {
        let mut altstack = self.altstack.lock();
        let sp = ctx.sp;

        // Check if we are currently on the alternate stack.
        let on_alt = is_on_stack(&altstack, sp);

        // Write old stack info to user space.
        if old_ss_addr != 0 {
            let mut out = *altstack;
            if on_alt {
                out.ss_flags |= litebox_common_macos::SS_ONSTACK;
            }
            let ptr: MutPtr<litebox_common_macos::SigAltStack> = MutPtr::from_usize(old_ss_addr);
            ptr.write_at_offset(0, out).ok_or(Errno::EFAULT)?;
        }

        // Read and install new stack.
        if ss_addr != 0 {
            // Cannot change the altstack while executing on it.
            if on_alt {
                return Err(Errno::EPERM);
            }
            let ptr: ConstPtr<litebox_common_macos::SigAltStack> = ConstPtr::from_usize(ss_addr);
            let ss = ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;

            if ss.ss_flags & litebox_common_macos::SS_DISABLE != 0 {
                // Disable the altstack.
                *altstack = litebox_common_macos::SigAltStack::DISABLED;
            } else {
                // Validate: size must be at least MINSIGSTKSZ, sp+size must not overflow.
                if ss.ss_size < litebox_common_macos::MINSIGSTKSZ {
                    return Err(Errno::ENOMEM);
                }
                if ss.ss_sp.checked_add(ss.ss_size).is_none() {
                    return Err(Errno::EINVAL);
                }
                // Only valid flag for new stack is 0 (no flags) — reject unknown bits.
                // (SS_ONSTACK is output-only, SS_DISABLE handled above.)
                let valid_input_flags = litebox_common_macos::SS_DISABLE;
                if ss.ss_flags & !valid_input_flags != 0 {
                    return Err(Errno::EINVAL);
                }
                *altstack = litebox_common_macos::SigAltStack {
                    ss_sp: ss.ss_sp,
                    ss_size: ss.ss_size,
                    ss_flags: 0,
                    pad: 0,
                };
            }
        }

        Ok(0)
    }

    /// Build an XNU signal frame on the guest stack and set registers for `_sigtramp`.
    ///
    /// The frame layout (high to low addresses):
    /// ```text
    /// [original SP]
    ///   128-byte red zone
    ///   mcontext64_t (816 bytes)   ← at new_sp + 160
    ///   ucontext_t   (56 bytes)    ← at new_sp + 104
    ///   siginfo_t    (104 bytes)   ← at new_sp + 0
    /// [new SP, 16-byte aligned]
    /// ```
    #[allow(clippy::cast_possible_wrap)]
    pub(crate) fn deliver_signal(
        &self,
        ctx: &mut PtRegs,
        signum: i32,
        fault_address: usize,
        handler: &crate::SignalHandler,
    ) {
        log_unsupported!(
            "deliver_signal: sig={} fault_addr={:#x} pc={:#x} lr={:#x} sp={:#x} x19={:#x} handler={:#x} tramp={:#x}",
            signum,
            fault_address,
            ctx.pc,
            ctx.regs[30],
            ctx.sp,
            ctx.regs[19],
            handler.handler,
            handler.tramp
        );
        // 1. Compute new stack pointer (with altstack support).
        let frame_size = SIGINFO_SIZE + UCONTEXT_SIZE + MCONTEXT_SIZE; // 976
        let altstack = self.altstack.lock();
        let on_alt = is_on_stack(&altstack, ctx.sp);
        let use_altstack = (handler.flags & SA_ONSTACK != 0)
            && !on_alt
            && (altstack.ss_flags & litebox_common_macos::SS_DISABLE == 0);
        let base_sp = if use_altstack {
            // Place frame at top of alternate signal stack.
            altstack.ss_sp + altstack.ss_size
        } else {
            ctx.sp
        };
        drop(altstack);
        let new_sp = (base_sp - REDZONE_SIZE - frame_size) & !0xF; // 16-byte aligned

        let siginfo_addr = new_sp;
        let ucontext_addr = new_sp + SIGINFO_SIZE; // new_sp + 104
        let mcontext_addr = new_sp + SIGINFO_SIZE + UCONTEXT_SIZE; // new_sp + 160

        // 2. Build mcontext64 (816 bytes) — zero-fill then populate.
        let mctx_zeros = [0u8; MCONTEXT_SIZE];
        let mctx_ptr: MutPtr<u8> = MutPtr::from_usize(mcontext_addr);
        mctx_ptr
            .copy_from_slice(0, &mctx_zeros)
            .expect("deliver_signal: write mcontext zeros");

        // __es: exception state (16 bytes)
        let mctx_u64: MutPtr<u64> = MutPtr::from_usize(mcontext_addr);
        mctx_u64
            .write_at_offset((MCTX_ES_FAR / 8) as isize, fault_address as u64)
            .expect("deliver_signal: write __far");
        // __esr and __exception left as 0.

        // __ss: thread state (272 bytes at offset 16)
        let ss_base = mcontext_addr + MCTX_SS_BASE;
        let ss_u64: MutPtr<u64> = MutPtr::from_usize(ss_base);

        // x0-x28 (29 registers, 8 bytes each)
        for i in 0..29 {
            ss_u64
                .write_at_offset(((SS_X_BASE / 8) + i) as isize, ctx.regs[i] as u64)
                .expect("deliver_signal: write x reg");
        }
        // fp (x29), lr (x30), sp, pc
        ss_u64
            .write_at_offset((SS_FP / 8) as isize, ctx.regs[29] as u64)
            .expect("deliver_signal: write fp");
        ss_u64
            .write_at_offset((SS_LR / 8) as isize, ctx.regs[30] as u64)
            .expect("deliver_signal: write lr");
        ss_u64
            .write_at_offset((SS_SP / 8) as isize, ctx.sp as u64)
            .expect("deliver_signal: write sp");
        ss_u64
            .write_at_offset((SS_PC / 8) as isize, ctx.pc as u64)
            .expect("deliver_signal: write pc");
        // cpsr (4 bytes at offset 264 within __ss)
        let cpsr_ptr: MutPtr<u32> = MutPtr::from_usize(ss_base + SS_CPSR);
        #[allow(clippy::cast_possible_truncation)]
        cpsr_ptr
            .write_at_offset(0, ctx.pstate as u32)
            .expect("deliver_signal: write cpsr");

        // __ns: NEON state (528 bytes at offset 288) — already zeroed.

        // 3. Build ucontext (56 bytes) — zero-fill then populate.
        let uctx_zeros = [0u8; UCONTEXT_SIZE];
        let uctx_ptr: MutPtr<u8> = MutPtr::from_usize(ucontext_addr);
        uctx_ptr
            .copy_from_slice(0, &uctx_zeros)
            .expect("deliver_signal: write ucontext zeros");

        // uc_onstack (4 bytes at offset 0): 1 if on altstack, else 0.
        if use_altstack || on_alt {
            let onstack_ptr: MutPtr<u32> = MutPtr::from_usize(ucontext_addr);
            onstack_ptr
                .write_at_offset(0, 1)
                .expect("deliver_signal: write uc_onstack");
        }
        // uc_sigmask (4 bytes at offset 4) = current blocked mask
        let uctx_mask_ptr: MutPtr<u32> = MutPtr::from_usize(ucontext_addr + UCTX_SIGMASK);
        uctx_mask_ptr
            .write_at_offset(0, self.blocked_signals.load(Ordering::Relaxed))
            .expect("deliver_signal: write uc_sigmask");
        // uc_stack (24 bytes at offset 8) = altstack info (ss_sp, ss_size, ss_flags, pad)
        // uc_link (8 bytes at offset 32) = 0
        // uc_mcsize (8 bytes at offset 40) = 816
        let uctx_u64: MutPtr<u64> = MutPtr::from_usize(ucontext_addr);
        uctx_u64
            .write_at_offset((UCTX_MCSIZE / 8) as isize, MCONTEXT_SIZE as u64)
            .expect("deliver_signal: write uc_mcsize");
        // uc_mcontext (8 bytes at offset 48) = pointer to mcontext on stack
        uctx_u64
            .write_at_offset((UCTX_MCONTEXT / 8) as isize, mcontext_addr as u64)
            .expect("deliver_signal: write uc_mcontext");

        // 4. Build siginfo (104 bytes) — zero-fill then populate.
        let si_zeros = [0u8; SIGINFO_SIZE];
        let si_ptr: MutPtr<u8> = MutPtr::from_usize(siginfo_addr);
        si_ptr
            .copy_from_slice(0, &si_zeros)
            .expect("deliver_signal: write siginfo zeros");

        let si_i32: MutPtr<i32> = MutPtr::from_usize(siginfo_addr);
        si_i32
            .write_at_offset((SI_SIGNO / 4) as isize, signum)
            .expect("deliver_signal: write si_signo");
        // si_errno = 0 (already zero)
        si_i32
            .write_at_offset((SI_CODE / 4) as isize, SEGV_MAPERR)
            .expect("deliver_signal: write si_code");
        #[allow(clippy::similar_names)]
        let siginfo_u64: MutPtr<u64> = MutPtr::from_usize(siginfo_addr);
        siginfo_u64
            .write_at_offset((SI_ADDR / 8) as isize, fault_address as u64)
            .expect("deliver_signal: write si_addr");

        // 5. Update blocked mask: add handler.mask | signal bit (unless SA_NODEFER).
        let mut block_add = handler.mask;
        if handler.flags & SA_NODEFER == 0 {
            #[allow(clippy::cast_sign_loss)]
            {
                block_add |= 1u32 << (signum as u32 - 1);
            }
        }
        let old_blocked = self.blocked_signals.load(Ordering::Relaxed);
        self.blocked_signals.store(
            (old_blocked | block_add) & !UNCATCHABLE_MASK,
            Ordering::Relaxed,
        );

        // 6. Set registers for _sigtramp entry.
        #[allow(clippy::cast_possible_truncation)]
        {
            ctx.regs[0] = handler.handler as usize; // x0 = catcher (user handler)
        }
        #[allow(clippy::cast_possible_truncation)]
        {
            ctx.regs[1] = UC_FLAVOR as usize; // x1 = infostyle = 30
        }
        #[allow(clippy::cast_sign_loss)]
        {
            ctx.regs[2] = signum as usize; // x2 = signal number
        }
        ctx.regs[3] = siginfo_addr; // x3 = &siginfo
        ctx.regs[4] = ucontext_addr; // x4 = &ucontext
        ctx.regs[5] = 0; // x5 = token (ignored)
        #[allow(clippy::cast_possible_truncation)]
        {
            ctx.pc = handler.tramp as usize; // pc = _sigtramp
        }
        ctx.sp = new_sp; // sp = bottom of frame
    }

    /// Handle `sigreturn()` (BSD syscall 184).
    ///
    /// Reads the saved `ucontext_t` and `mcontext64_t` from the guest stack,
    /// restores all general registers, pstate/cpsr, and the signal mask.
    ///
    /// This modifies `ctx` directly and must NOT be followed by `set_syscall_return`.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    pub(crate) fn sys_sigreturn(&self, ctx: &mut PtRegs, uctx_addr: usize) {
        // Log caller context BEFORE overwriting.
        log_unsupported!(
            "sigreturn: caller pc={:#x} lr={:#x} sp={:#x} uctx={:#x}",
            ctx.pc,
            ctx.regs[30],
            ctx.sp,
            uctx_addr
        );

        // 1. Read uc_sigmask (4 bytes at offset 4 in ucontext_t).
        let sigmask_ptr: ConstPtr<u32> = ConstPtr::from_usize(uctx_addr + UCTX_SIGMASK);
        let sigmask = sigmask_ptr
            .read_at_offset(0)
            .expect("sigreturn: read uc_sigmask");
        self.blocked_signals
            .store(sigmask & !UNCATCHABLE_MASK, Ordering::Relaxed);

        // 2. Read uc_mcontext pointer (8 bytes at offset 48 in ucontext_t).
        let mctx_ptr_ptr: ConstPtr<u64> = ConstPtr::from_usize(uctx_addr + UCTX_MCONTEXT);
        let mcontext_addr = mctx_ptr_ptr
            .read_at_offset(0)
            .expect("sigreturn: read uc_mcontext") as usize;

        log_unsupported!(
            "sigreturn: mcontext_addr={:#x} ss_addr={:#x}",
            mcontext_addr,
            mcontext_addr + MCTX_SS_BASE
        );

        // 3. Restore registers from mcontext.__ss (272 bytes at offset 16).
        let ss_addr = mcontext_addr + MCTX_SS_BASE;
        let ss_u64: ConstPtr<u64> = ConstPtr::from_usize(ss_addr);

        // x0-x28
        for i in 0..29 {
            ctx.regs[i] = ss_u64
                .read_at_offset(((SS_X_BASE / 8) + i) as isize)
                .expect("sigreturn: read x reg") as usize;
        }
        // fp (x29)
        ctx.regs[29] = ss_u64
            .read_at_offset((SS_FP / 8) as isize)
            .expect("sigreturn: read fp") as usize;
        // lr (x30)
        ctx.regs[30] = ss_u64
            .read_at_offset((SS_LR / 8) as isize)
            .expect("sigreturn: read lr") as usize;
        // sp
        ctx.sp = ss_u64
            .read_at_offset((SS_SP / 8) as isize)
            .expect("sigreturn: read sp") as usize;
        // pc
        ctx.pc = ss_u64
            .read_at_offset((SS_PC / 8) as isize)
            .expect("sigreturn: read pc") as usize;
        // cpsr → pstate
        let cpsr_ptr: ConstPtr<u32> = ConstPtr::from_usize(ss_addr + SS_CPSR);
        ctx.pstate = cpsr_ptr.read_at_offset(0).expect("sigreturn: read cpsr") as usize;

        log_unsupported!(
            "sigreturn: restored pc={:#x} sp={:#x} lr={:#x} x0={:#x} x16={:#x} fp={:#x}",
            ctx.pc,
            ctx.sp,
            ctx.regs[30],
            ctx.regs[0],
            ctx.regs[16],
            ctx.regs[29]
        );
    }
}
