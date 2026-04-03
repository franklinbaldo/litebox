// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stub syscall handlers for macOS shim Phase 2.
//!
//! These handlers provide minimal implementations sufficient for dyld
//! bootstrap and hello.c execution.

use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::errno::Errno;
use litebox_common_macos::syscall::mach_trap;

use crate::{MutPtr, ShimFS, Task};

impl<FS: ShimFS> Task<FS> {
    /// Handle `sigaction()` — stub: record but don't deliver signals.
    pub(crate) fn sys_sigaction(
        &self,
        _signum: i32,
        _new_act: usize,
        _old_act: usize,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    /// Handle `sigprocmask()` — stub: return success.
    pub(crate) fn sys_sigprocmask(
        &self,
        _how: i32,
        _set: usize,
        _oldset: usize,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    /// Handle `madvise()` — stub: return success.
    pub(crate) fn sys_madvise(
        &self,
        _addr: usize,
        _length: usize,
        _advice: i32,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    /// Handle `csops()` — stub: return success (not code-signed).
    pub(crate) fn sys_csops(
        &self,
        _pid: i32,
        _ops: u32,
        _useraddr: usize,
        _usersize: usize,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    /// Handle `shared_region_check_np()` — return EINVAL to force dyld's fallback path.
    pub(crate) fn sys_shared_region_check_np(&self, _start_address: usize) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }

    /// Handle `getentropy()` — fill buffer with pseudo-random bytes.
    pub(crate) fn sys_getentropy(&self, buf_addr: usize, count: usize) -> Result<usize, Errno> {
        if count > 256 {
            return Err(Errno::EIO);
        }
        let data: alloc::vec::Vec<u8> = (0..count)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(13))
            .collect();
        let dest: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        dest.copy_from_slice(0, &data).ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    /// Handle `sysctl()` — return ENOENT for all queries.
    pub(crate) fn sys_sysctl(
        &self,
        _name: usize,
        _namelen: u32,
        _old: usize,
        _oldlenp: usize,
        _new_val: usize,
        _newlen: usize,
    ) -> Result<usize, Errno> {
        Err(Errno::ENOENT)
    }

    /// Handle `ioctl()` — return ENOTTY for all requests.
    pub(crate) fn sys_ioctl(&self, _fd: i32, _request: usize, _arg: usize) -> Result<usize, Errno> {
        Err(Errno::ENOTTY)
    }

    /// Dispatch a Mach trap by trap number.
    pub(crate) fn do_mach_trap(&self, number: usize) -> Result<usize, Errno> {
        match number {
            mach_trap::MACH_REPLY_PORT => Ok(0x0703),
            mach_trap::THREAD_SELF_TRAP => Ok(0x0303),
            mach_trap::TASK_SELF_TRAP => Ok(0x0103),
            mach_trap::HOST_SELF_TRAP => Ok(0x0503),
            mach_trap::MACH_MSG_TRAP => {
                // Return MACH_SEND_INVALID_DEST (0x10000003)
                Ok(0x1000_0003)
            }
            mach_trap::THREAD_GET_SPECIAL_REPLY_PORT => Ok(0x0903),
            _ => {
                log_unsupported!("Mach trap {number}");
                Ok(0)
            }
        }
    }

    // === Temporary stubs — proper implementations in Task 3 (file.rs) ===

    /// Handle `open()` — temporary stub.
    pub(crate) fn sys_open(
        &self,
        _path_addr: usize,
        _flags: i32,
        _mode: u32,
    ) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Handle `lseek()` — temporary stub.
    pub(crate) fn sys_lseek(&self, _fd: i32, _offset: i64, _whence: i32) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Handle `pread()` — temporary stub.
    pub(crate) fn sys_pread(
        &self,
        _fd: i32,
        _buf: usize,
        _count: usize,
        _offset: i64,
    ) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Handle `fstat64()` — temporary stub.
    pub(crate) fn sys_fstat64(&self, _fd: i32, _buf: usize) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Handle `fcntl()` — temporary stub.
    pub(crate) fn sys_fcntl(&self, _fd: i32, _cmd: i32, _arg: usize) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }
}
