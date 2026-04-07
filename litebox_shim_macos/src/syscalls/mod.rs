// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Syscall handlers for the macOS shim.

pub(crate) mod file;
pub(crate) mod mm;
pub(crate) mod process;
pub(crate) mod signal;
pub(crate) mod stubs;

pub(crate) mod kqueue;
pub(crate) mod net;
mod poll;
pub(crate) mod unix;

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
            MacosSyscallRequest::Gettimeofday { tv, tz } => self.sys_gettimeofday(tv, tz),
            MacosSyscallRequest::Readv { fd, iov, iovcnt } => self.sys_readv(fd, iov, iovcnt),
            MacosSyscallRequest::Writev { fd, iov, iovcnt } => self.sys_writev(fd, iov, iovcnt),
            MacosSyscallRequest::Getfsstat64 {
                buf,
                bufsize,
                flags,
            } => self.sys_getfsstat64(buf, bufsize, flags),
            MacosSyscallRequest::Fsgetpath {
                buf,
                bufsize,
                fsid,
                objid,
            } => self.sys_fsgetpath(buf, bufsize, fsid, objid),
            MacosSyscallRequest::Unknown { number } => {
                log_unsupported!("macOS syscall {number}");
                Err(Errno::ENOSYS)
            }
            MacosSyscallRequest::ProcRlimitControl { pid, flavor, arg } => {
                let _ = (pid, flavor, arg);
                log_unsupported!(
                    "proc_rlimit_control(pid={pid}, flavor={flavor}, arg={arg:#x}) → ENOSYS"
                );
                Err(Errno::ENOSYS)
            }
            MacosSyscallRequest::BsdthreadRegister {
                threadstart,
                wqthread,
                pthsize,
                pthread_init_data,
                pthread_init_data_size,
            } => self.sys_bsdthread_register(
                threadstart,
                wqthread,
                pthsize,
                pthread_init_data,
                pthread_init_data_size,
            ),
            MacosSyscallRequest::BsdthreadCreate {
                func,
                func_arg,
                stack,
                pthread,
                flags,
            } => self.sys_bsdthread_create(func, func_arg, stack, pthread, flags, ctx),
            MacosSyscallRequest::BsdthreadTerminate {
                stackaddr,
                freesize,
                port,
                sema_or_ulock,
            } => self.sys_bsdthread_terminate(stackaddr, freesize, port, sema_or_ulock),
            MacosSyscallRequest::BsdthreadCtl {
                cmd,
                arg1,
                arg2,
                arg3,
            } => self.sys_bsdthread_ctl(cmd, arg1, arg2, arg3),
            MacosSyscallRequest::Sigreturn { .. } => {
                unreachable!("Sigreturn is handled in handle_syscall_request before do_syscall")
            }
            MacosSyscallRequest::Pipe => {
                unreachable!("Pipe is handled in handle_syscall_request before do_syscall")
            }
            MacosSyscallRequest::Unlink { path } => self.sys_unlink(path),
            MacosSyscallRequest::Access { path, amode } => self.sys_access(path, amode),
            MacosSyscallRequest::Fchmod { fd, mode } => self.sys_fchmod(fd, mode),
            MacosSyscallRequest::Mkdir { path, mode } => self.sys_mkdir(path, mode),
            MacosSyscallRequest::Rmdir { path } => self.sys_rmdir(path),
            MacosSyscallRequest::Ftruncate { fd, length } => self.sys_ftruncate(fd, length),
            MacosSyscallRequest::Getdirentries64 {
                fd,
                buf,
                bufsize,
                basep,
            } => self.sys_getdirentries64(fd, buf, bufsize, basep),
            MacosSyscallRequest::SemwaitSignal {
                cond_sem,
                mutex_sem,
                timeout,
                relative,
                tv_sec,
                tv_nsec,
            } => self.sys_semwait_signal(cond_sem, mutex_sem, timeout, relative, tv_sec, tv_nsec),
            MacosSyscallRequest::Socket {
                domain,
                sock_type,
                protocol,
            } => self.sys_socket(domain, sock_type, protocol),
            MacosSyscallRequest::Bind { fd, addr, addrlen } => {
                self.sys_bind(fd, addr, addrlen).map(|()| 0)
            }
            MacosSyscallRequest::Listen { fd, backlog } => self.sys_listen(fd, backlog).map(|()| 0),
            MacosSyscallRequest::Accept { fd, addr, addrlen } => self.sys_accept(fd, addr, addrlen),
            MacosSyscallRequest::Connect { fd, addr, addrlen } => {
                self.sys_connect(fd, addr, addrlen).map(|()| 0)
            }
            MacosSyscallRequest::Sendto {
                fd,
                buf,
                len,
                flags,
                dest_addr,
                addrlen,
            } => self.sys_sendto(fd, buf, len, flags, dest_addr, addrlen),
            MacosSyscallRequest::Recvfrom {
                fd,
                buf,
                len,
                flags,
                src_addr,
                addrlen,
            } => self.sys_recvfrom(fd, buf, len, flags, src_addr, addrlen),
            MacosSyscallRequest::Sendmsg { fd, msg, flags } => self.sys_sendmsg(fd, msg, flags),
            MacosSyscallRequest::Recvmsg { fd, msg, flags } => self.sys_recvmsg(fd, msg, flags),
            MacosSyscallRequest::Shutdown { fd, how } => self.sys_shutdown(fd, how).map(|()| 0),
            MacosSyscallRequest::Socketpair {
                domain,
                sock_type,
                protocol,
                sv,
            } => self
                .sys_socketpair(domain, sock_type, protocol, sv)
                .map(|()| 0),
            MacosSyscallRequest::Setsockopt {
                fd,
                level,
                optname,
                optval,
                optlen,
            } => self
                .sys_setsockopt(fd, level, optname, optval, optlen)
                .map(|()| 0),
            MacosSyscallRequest::Getsockopt {
                fd,
                level,
                optname,
                optval,
                optlen,
            } => self
                .sys_getsockopt(fd, level, optname, optval, optlen)
                .map(|()| 0),
            MacosSyscallRequest::Getsockname { fd, addr, addrlen } => {
                self.sys_getsockname(fd, addr, addrlen).map(|()| 0)
            }
            MacosSyscallRequest::Getpeername { fd, addr, addrlen } => {
                self.sys_getpeername(fd, addr, addrlen).map(|()| 0)
            }
            MacosSyscallRequest::Select {
                nfds,
                readfds,
                writefds,
                errorfds,
                timeout,
            } => self.sys_select(nfds, readfds, writefds, errorfds, timeout),
            MacosSyscallRequest::Poll { fds, nfds, timeout } => self.sys_poll(fds, nfds, timeout),
            MacosSyscallRequest::Kqueue => kqueue::sys_kqueue(self),
            MacosSyscallRequest::Kevent {
                kq,
                changelist,
                nchanges,
                eventlist,
                nevents,
                timeout,
            } => kqueue::sys_kevent(self, kq, changelist, nchanges, eventlist, nevents, timeout),
            MacosSyscallRequest::Fstatfs64Fd { fd, buf } => {
                let _ = fd; // fd is validated but not used differently
                self.sys_statfs64(0, buf) // reuse statfs64 with fake values
            }
            MacosSyscallRequest::Fchdir { fd } => self.sys_fchdir(fd),
            MacosSyscallRequest::ChangeFdguardNp { fd } => {
                let _ = fd;
                Ok(0) // no-op: guards not enforced
            }
            MacosSyscallRequest::GetattrlistBulk {
                dirfd,
                alist,
                attr_buf,
                attr_buf_size,
                options,
            } => self.sys_getattrlistbulk(dirfd, alist, attr_buf, attr_buf_size, options),
            MacosSyscallRequest::GuardedCloseNp { fd } => self.sys_close(fd).map(|()| 0),
            MacosSyscallRequest::GuardedWriteNp { fd, buf, count } => {
                self.sys_write(fd, buf, count)
            }
            MacosSyscallRequest::GuardedOpenNp { path, flags, mode } => {
                self.sys_open(path, flags, mode)
            }
            MacosSyscallRequest::UlockWait {
                operation,
                addr,
                value,
                timeout_us,
            } => self.sys_ulock_wait(operation, addr, value, timeout_us),
            MacosSyscallRequest::UlockWait2 {
                operation,
                addr,
                value,
                timeout_ns,
            } => {
                // Convert nanoseconds to microseconds for the existing handler.
                // ulock_wait2 uses ns, ulock_wait uses us. 0 means infinite in both.
                #[allow(clippy::cast_possible_truncation)]
                let timeout_us = if timeout_ns == 0 {
                    0
                } else {
                    let us = timeout_ns.div_ceil(1000);
                    // Safe: clamped to u32::MAX before truncation.
                    us.min(u64::from(u32::MAX)) as u32
                };
                self.sys_ulock_wait(operation, addr, value, timeout_us)
            }
            MacosSyscallRequest::UlockWake {
                operation,
                addr,
                wake_value,
            } => self.sys_ulock_wake(operation, addr, wake_value),
        }
    }
}
