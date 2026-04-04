// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS signal handling: sigaction, sigprocmask, signal delivery, and sigreturn.

use core::sync::atomic::Ordering;
use litebox::platform::RawConstPointer as _;
use litebox::platform::RawMutPointer as _;
use litebox_common_macos::errno::Errno;
#[allow(unused_imports)]
use litebox_common_macos::PtRegs;

use crate::{ConstPtr, MutPtr, ShimFS, Task};

// macOS signal constants.
const _SIG_DFL: u64 = 0;
const _SIG_IGN: u64 = 1;
const _SIGKILL: i32 = 9;
const _SIGSTOP: i32 = 17;

// SA_* flag constants.
const _SA_SIGINFO: u32 = 0x0040;
const _SA_NODEFER: u32 = 0x0010;

// sigprocmask `how` constants.
const SIG_BLOCK: i32 = 1;
const SIG_UNBLOCK: i32 = 2;
const SIG_SETMASK: i32 = 3;

// Signals that cannot be caught or blocked.
const UNCATCHABLE_MASK: u32 = (1 << (9 - 1)) | (1 << (17 - 1)); // SIGKILL | SIGSTOP

// UC_FLAVOR for aarch64 (used by _sigtramp and sigreturn).
const _UC_FLAVOR: u64 = 30;

// Signal frame component sizes (bytes).
const _SIGINFO_SIZE: usize = 104;
const _UCONTEXT_SIZE: usize = 56;
const _MCONTEXT_SIZE: usize = 816;
const _REDZONE_SIZE: usize = 128;

// Offsets within ucontext_t (56 bytes).
const _UCTX_ONSTACK: usize = 0;
const _UCTX_SIGMASK: usize = 4;
// uc_stack at offset 8, 24 bytes (ss_sp, ss_size, ss_flags, pad)
const _UCTX_LINK: usize = 32;
const _UCTX_MCSIZE: usize = 40;
const _UCTX_MCONTEXT: usize = 48;

// Offsets within __darwin_mcontext64 (816 bytes).
// __es: exception state at offset 0, 16 bytes.
const _MCTX_ES_FAR: usize = 0;
const _MCTX_ES_ESR: usize = 8;
// __ss: thread state at offset 16, 272 bytes.
const _MCTX_SS_BASE: usize = 16;
// Within __ss: x[0..29] at offset 0, fp at 232, lr at 240, sp at 248, pc at 256, cpsr at 264.
const _SS_X_BASE: usize = 0; // x[0..29], 8 bytes each
const _SS_FP: usize = 232; // x29
const _SS_LR: usize = 240; // x30
const _SS_SP: usize = 248;
const _SS_PC: usize = 256;
const _SS_CPSR: usize = 264;
// __ns: NEON state at offset 288, 528 bytes — zeroed (not saved).

// Offsets within siginfo_t (104 bytes).
const _SI_SIGNO: usize = 0;
const _SI_ERRNO: usize = 4;
const _SI_CODE: usize = 8;
const _SI_ADDR: usize = 24;

// Signal codes.
const _SEGV_MAPERR: i32 = 1;

/// Map a Linux signal number (from the platform's ExceptionInfo.esr) to a macOS signal number.
///
/// Most signals have the same number on both platforms. The notable
/// exception is SIGBUS (Linux 7 → macOS 10).
#[allow(dead_code)]
pub(crate) fn linux_to_macos_signal(linux_sig: i32) -> i32 {
    match linux_sig {
        7 => 10,        // Linux SIGBUS=7 → macOS SIGBUS=10
        _ => linux_sig, // SIGILL(4), SIGTRAP(5), SIGFPE(8), SIGSEGV(11) are the same
    }
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
        if signum < 1 || signum > 31 {
            return Err(Errno::EINVAL);
        }
        // SIGKILL and SIGSTOP cannot have their handlers changed.
        if signum == _SIGKILL || signum == _SIGSTOP {
            return Err(Errno::EINVAL);
        }

        let mut handlers = self.process.signal_handlers.lock();
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
            for i in 0..24 {
                buf[i] = ptr.read_at_offset(i as isize).ok_or(Errno::EFAULT)?;
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
            for i in 0..4 {
                buf[i] = ptr.read_at_offset(i as isize).ok_or(Errno::EFAULT)?;
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
}
