// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Syscall handlers for the macOS shim.

pub(crate) mod file;
pub(crate) mod mm;
pub(crate) mod process;
pub(crate) mod stubs;

use litebox_common_macos::{PtRegs, errno::Errno, syscall::MacosSyscallRequest};

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
        ctx: &mut PtRegs,
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
            MacosSyscallRequest::Open { path, flags, mode } => self.sys_open(path, flags, mode),
            MacosSyscallRequest::Sigaction {
                signum,
                new_act,
                old_act,
            } => self.sys_sigaction(signum, new_act, old_act),
            MacosSyscallRequest::Sigprocmask { how, set, oldset } => {
                self.sys_sigprocmask(how, set, oldset)
            }
            MacosSyscallRequest::Ioctl { fd, request, arg } => self.sys_ioctl(fd, request, arg),
            MacosSyscallRequest::Madvise {
                addr,
                length,
                advice,
            } => self.sys_madvise(addr, length, advice),
            MacosSyscallRequest::Fcntl { fd, cmd, arg } => self.sys_fcntl(fd, cmd, arg),
            MacosSyscallRequest::Pread {
                fd,
                buf,
                count,
                offset,
            } => self.sys_pread(fd, buf, count, offset),
            MacosSyscallRequest::Csops {
                pid,
                ops,
                useraddr,
                usersize,
            } => self.sys_csops(pid, ops, useraddr, usersize),
            MacosSyscallRequest::Lseek { fd, offset, whence } => self.sys_lseek(fd, offset, whence),
            MacosSyscallRequest::Sysctl {
                name,
                namelen,
                old,
                oldlenp,
                new_val,
                newlen,
            } => self.sys_sysctl(name, namelen, old, oldlenp, new_val, newlen),
            MacosSyscallRequest::SharedRegionCheckNp { start_address } => {
                self.sys_shared_region_check_np(start_address)
            }
            MacosSyscallRequest::Fstat64 { fd, buf } => self.sys_fstat64(fd, buf),
            MacosSyscallRequest::Getentropy { buf, count } => self.sys_getentropy(buf, count),
            MacosSyscallRequest::ThreadSelfid => self.sys_thread_selfid(),
            MacosSyscallRequest::MachMsg2Trap { .. } => self.sys_mach_msg2_trap(),
            MacosSyscallRequest::MachTrap { number } => self.do_mach_trap(number, ctx),
            MacosSyscallRequest::CrossarchTrap | MacosSyscallRequest::KdebugTraceString => Ok(0),
            MacosSyscallRequest::Csrctl => Err(Errno::EPERM),
            MacosSyscallRequest::Dup2 { oldfd, newfd } => self.sys_dup2(oldfd, newfd),
            MacosSyscallRequest::MacSyscall => Err(Errno::ENOSYS),
            MacosSyscallRequest::Fsctl => Err(Errno::ENOTTY),
            MacosSyscallRequest::SharedRegionMapAndSlide2Np => {
                log_unsupported!("shared_region_map_and_slide_2_np: no-op (cache pre-mapped)");
                Ok(0)
            }
            MacosSyscallRequest::Statfs64 { path, buf } => self.sys_statfs64(path, buf),
            MacosSyscallRequest::Stat64 { path, buf } => self.sys_stat64(path, buf),
            MacosSyscallRequest::Openat {
                dirfd,
                path,
                flags,
                mode,
            } => self.sys_openat(dirfd, path, flags, mode),
            MacosSyscallRequest::Fstatat64 {
                dirfd,
                path,
                buf,
                flag,
            } => self.sys_fstatat64(dirfd, path, buf, flag),
            MacosSyscallRequest::TerminateWithPayload { namespace, code } => {
                log_unsupported!(
                    "terminate_with_payload(namespace={namespace:#x}, code={code:#x}) → exit(1)"
                );
                self.sys_exit(1);
                Ok(0)
            }
            MacosSyscallRequest::AbortWithPayload { namespace, code } => {
                log_unsupported!(
                    "abort_with_payload(namespace={namespace:#x}, code={code:#x}) → exit(1)"
                );
                self.sys_exit(1);
                Ok(0)
            }
            MacosSyscallRequest::Unknown { number } => {
                log_unsupported!("macOS syscall {number}");
                Err(Errno::ENOSYS)
            }
        }
    }
}
