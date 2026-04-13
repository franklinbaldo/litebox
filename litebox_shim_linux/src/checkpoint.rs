// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Checkpoint support for OCI container checkpoint/restore.
//!
//! This module provides:
//! - A pre-opened checkpoint output fd (set by the runner before entering the
//!   sandbox execution loop, before seccomp Phase 2 locks down file opens).
//! - Raw file I/O using Linux syscalls (the shim is `no_std`).
//!
//! The checkpoint flow is:
//! 1. Runner pre-opens `<state_dir>/checkpoint.img` before seccomp Phase 2.
//! 2. Runner stores the fd via [`set_checkpoint_fd`].
//! 3. On SIGUSR1, the shim serializes a snapshot and writes it to the fd.
//! 4. After the sandbox exits, the OCI checkpoint command copies the image
//!    from `<state_dir>/checkpoint.img` to the user-specified `--image-path`.

use core::sync::atomic::{AtomicI32, Ordering};

/// Pre-opened fd for checkpoint output. -1 means not configured.
///
/// Opened by the runner at init time (before seccomp Phase 2), so the
/// checkpoint code only needs `write` and `close` — both allowed at runtime.
static CHECKPOINT_FD: AtomicI32 = AtomicI32::new(-1);

/// Store the pre-opened checkpoint output fd (called by the runner).
///
/// The fd must be open for writing (`O_WRONLY | O_CREAT | O_TRUNC`).
/// Must be called before the sandbox execution loop starts.
pub fn set_checkpoint_fd(fd: i32) {
    CHECKPOINT_FD.store(fd, Ordering::Release);
}

/// Returns `true` if a checkpoint fd has been configured.
pub fn is_configured() -> bool {
    CHECKPOINT_FD.load(Ordering::Acquire) >= 0
}

// ---------------------------------------------------------------------------
// Raw Linux syscall wrappers (no libc needed in no_std)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod raw {
    const SYS_CLOSE: usize = 3;
    const SYS_WRITE: usize = 1;

    #[inline]
    unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") nr,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                lateout("rax") ret,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    #[inline]
    unsafe fn syscall1(nr: usize, a1: usize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") nr,
                in("rdi") a1,
                lateout("rax") ret,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn write(fd: i32, buf: *const u8, count: usize) -> isize {
        unsafe { syscall3(SYS_WRITE, fd as usize, buf as usize, count) }
    }

    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn close(fd: i32) -> isize {
        unsafe { syscall1(SYS_CLOSE, fd as usize) }
    }
}

/// Write the checkpoint snapshot to the pre-opened fd.
///
/// Takes ownership of the fd (closes it after writing). Returns `true`
/// on success, `false` if no fd is configured or the write fails.
pub fn write_to_fd(data: &[u8]) -> bool {
    let fd = CHECKPOINT_FD.swap(-1, Ordering::AcqRel);
    if fd < 0 {
        return false;
    }

    let mut written = 0usize;
    while written < data.len() {
        let n = unsafe { raw::write(fd, data[written..].as_ptr(), data.len() - written) };
        if n <= 0 {
            unsafe { raw::close(fd) };
            return false;
        }
        #[allow(clippy::cast_sign_loss)]
        {
            written += n as usize;
        }
    }

    unsafe { raw::close(fd) };
    true
}
