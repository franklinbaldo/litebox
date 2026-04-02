// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Syscall handlers for the macOS shim.

pub(crate) mod file;
pub(crate) mod mm;
pub(crate) mod process;

use litebox_common_macos::{errno::Errno, syscall::MacosSyscallRequest, PtRegs};

use crate::{ShimFS, Task};

impl<FS: ShimFS> Task<FS> {
    /// Dispatch a decoded macOS syscall request to the appropriate handler.
    ///
    /// For `Exit`, the task is marked as terminated and the exit code is
    /// stored; the return value is unused in that case. All other syscalls
    /// return `Ok(value)` or `Err(errno)`.
    pub(crate) fn do_syscall(
        &self,
        request: MacosSyscallRequest,
        _ctx: &mut PtRegs,
    ) -> Result<usize, Errno> {
        match request {
            MacosSyscallRequest::Exit { status } => {
                self.sys_exit(status);
                Ok(0)
            }
            MacosSyscallRequest::Read { fd, buf, count } => self.sys_read(fd, buf, count),
            MacosSyscallRequest::Write { fd, buf, count } => self.sys_write(fd, buf, count),
            MacosSyscallRequest::Close { fd } => self.sys_close(fd).map(|()| 0),
            MacosSyscallRequest::Getpid => {
                #[allow(clippy::cast_sign_loss)] // getpid always returns positive
                Ok(self.sys_getpid() as usize)
            }
            MacosSyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            MacosSyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            MacosSyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            MacosSyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            MacosSyscallRequest::Issetugid => {
                #[allow(clippy::cast_sign_loss)] // issetugid returns 0 or 1
                Ok(self.sys_issetugid() as usize)
            }
            MacosSyscallRequest::Mmap {
                addr,
                length,
                prot,
                flags,
                fd,
                offset,
            } => self.sys_mmap(addr, length, prot, flags, fd, offset),
            MacosSyscallRequest::Munmap { addr, length } => {
                self.sys_munmap(addr, length).map(|()| 0)
            }
            MacosSyscallRequest::Mprotect { addr, length, prot } => {
                self.sys_mprotect(addr, length, prot).map(|()| 0)
            }
            MacosSyscallRequest::Unknown { number } => {
                log_unsupported!("unknown macOS syscall {number}");
                Err(Errno::ENOSYS)
            }
        }
    }
}
