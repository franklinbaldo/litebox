// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Checkpoint support for OCI container checkpoint/restore.
//!
//! This module provides:
//! - A global checkpoint request path (set by the runner before entering the
//!   sandbox execution loop).
//! - Raw file I/O using Linux syscalls (the shim is `no_std`).
//! - A helper to read the request file and return the checkpoint image path.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Global pointer to a heap-allocated checkpoint request file path.
/// Set by the runner via [`set_request_path`].
///
/// When SIGUSR1 is received, the shim reads this file to get the
/// checkpoint image output path.
static CHECKPOINT_REQUEST_PATH: AtomicPtr<String> = AtomicPtr::new(core::ptr::null_mut());

/// Set the checkpoint request path (called by the runner/OCI layer).
///
/// The request path is a file that the OCI `checkpoint` command writes
/// with the checkpoint image output path before sending SIGUSR1.
///
/// # Safety
///
/// Must be called before the sandbox execution loop starts, from a single
/// thread.
pub fn set_request_path(path: String) {
    let boxed = alloc::boxed::Box::new(path);
    let ptr = alloc::boxed::Box::into_raw(boxed);
    CHECKPOINT_REQUEST_PATH.store(ptr, Ordering::Release);
}

/// Get the checkpoint request path, if configured.
pub fn get_request_path() -> Option<String> {
    let ptr = CHECKPOINT_REQUEST_PATH.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: the pointer was allocated by `set_request_path` and is
        // never freed during the sandbox's lifetime.
        Some(unsafe { &*ptr }.clone())
    }
}

// ---------------------------------------------------------------------------
// Raw Linux syscall wrappers (no libc needed in no_std)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod raw {
    const SYS_OPEN: usize = 2;
    const SYS_CLOSE: usize = 3;
    const SYS_READ: usize = 0;
    const SYS_WRITE: usize = 1;

    const O_RDONLY: usize = 0;
    const O_WRONLY: usize = 1;
    const O_CREAT: usize = 0o100;
    const O_TRUNC: usize = 0o1000;

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

    pub unsafe fn open(path: *const u8, flags: usize, mode: usize) -> isize {
        unsafe { syscall3(SYS_OPEN, path as usize, flags, mode) }
    }

    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn read(fd: isize, buf: *mut u8, count: usize) -> isize {
        unsafe { syscall3(SYS_READ, fd as usize, buf as usize, count) }
    }

    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn write(fd: isize, buf: *const u8, count: usize) -> isize {
        unsafe { syscall3(SYS_WRITE, fd as usize, buf as usize, count) }
    }

    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn close(fd: isize) -> isize {
        unsafe { syscall1(SYS_CLOSE, fd as usize) }
    }

    pub const fn open_rdonly() -> usize {
        O_RDONLY
    }

    pub const fn open_wronly_creat_trunc() -> usize {
        O_WRONLY | O_CREAT | O_TRUNC
    }
}

/// Read the checkpoint request file using raw Linux syscalls.
///
/// Returns the trimmed contents (the checkpoint image path) on success,
/// or `None` if the file doesn't exist or can't be read.
pub fn read_request_file(path: &str) -> Option<String> {
    let mut c_path: Vec<u8> = Vec::with_capacity(path.len() + 1);
    c_path.extend_from_slice(path.as_bytes());
    c_path.push(0);

    let fd = unsafe { raw::open(c_path.as_ptr(), raw::open_rdonly(), 0) };
    if fd < 0 {
        return None;
    }

    let mut buf = [0u8; 4096];
    let n = unsafe { raw::read(fd, buf.as_mut_ptr(), buf.len()) };
    unsafe { raw::close(fd) };

    if n <= 0 {
        return None;
    }

    #[allow(clippy::cast_sign_loss)]
    let s = core::str::from_utf8(&buf[..n as usize]).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(String::from(trimmed))
}

/// Write bytes to a file using raw Linux syscalls.
///
/// Creates the file (or truncates if it exists) and writes all data.
/// Returns `true` on success.
pub fn write_file(path: &str, data: &[u8]) -> bool {
    let mut c_path: Vec<u8> = Vec::with_capacity(path.len() + 1);
    c_path.extend_from_slice(path.as_bytes());
    c_path.push(0);

    let fd = unsafe { raw::open(c_path.as_ptr(), raw::open_wronly_creat_trunc(), 0o644) };
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
