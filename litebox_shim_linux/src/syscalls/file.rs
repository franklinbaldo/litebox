// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of file related syscalls, e.g., `open`, `read`, `write`, etc.

use alloc::{
    ffi::CString,
    string::{String, ToString as _},
    vec,
};
use litebox::{
    event::{Events, wait::WaitError},
    fd::{FdEnabledSubsystem, MetadataError, TypedFd},
    fs::{Mode, OFlags, SeekWhence},
    path,
    platform::{RawConstPointer, RawMutPointer, StdioProvider as _},
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _},
};
use litebox_common_linux::{
    AtFlags, EfdFlags, EpollCreateFlags, FcntlArg, FileDescriptorFlags, FileStat, IoReadVec,
    IoWriteVec, IoctlArg, TimeParam, errno::Errno,
};
use litebox_platform_multiplex::Platform;

use crate::{ConstPtr, Descriptor, Descriptors, GlobalState, MutPtr, ShimFS, Task};
use core::sync::atomic::Ordering;

/// Classification of a file descriptor for terminal ioctl routing.
enum TerminalKind {
    /// Host stdio device (major=5) — forward ioctls to host kernel.
    HostStdio,
    /// PTY slave device (major=136) — handle locally.
    Pty,
    /// Not a terminal device.
    NotTerminal,
}

/// Task state shared by `CLONE_FS`.
pub(crate) struct FsState {
    umask: core::sync::atomic::AtomicU32,
    /// The current working directory
    ///
    /// Must end with a '/'.
    cwd: litebox::sync::RwLock<Platform, String>,
}

impl Clone for FsState {
    fn clone(&self) -> Self {
        Self {
            umask: self.umask.load(Ordering::Relaxed).into(),
            cwd: litebox::sync::RwLock::new(self.cwd.read().clone()),
        }
    }
}

impl FsState {
    pub fn new() -> Self {
        Self {
            umask: (Mode::WGRP | Mode::WOTH).bits().into(),
            cwd: litebox::sync::RwLock::new(String::from("/")),
        }
    }

    /// Create a new `FsState` with a custom initial working directory.
    ///
    /// The `cwd` must be an absolute path. A trailing '/' is appended if missing.
    pub fn with_cwd(mut cwd: String) -> Self {
        assert!(cwd.starts_with('/'), "initial CWD must be absolute");
        if !cwd.ends_with('/') {
            cwd.push('/');
        }
        Self {
            umask: (Mode::WGRP | Mode::WOTH).bits().into(),
            cwd: litebox::sync::RwLock::new(cwd),
        }
    }

    fn umask(&self) -> Mode {
        Mode::from_bits_retain(self.umask.load(Ordering::Relaxed))
    }
}

/// Task state shared by `CLONE_FILES`.
pub(crate) struct FilesState<FS: ShimFS> {
    /// The filesystem implementation, shared across tasks that share file system.
    pub(crate) fs: alloc::sync::Arc<FS>,
    pub file_descriptors: litebox::sync::RwLock<Platform, Descriptors<FS>>,
    pub raw_descriptor_store: litebox::sync::RwLock<Platform, litebox::fd::RawDescriptorStorage>,
}

impl<FS: ShimFS> FilesState<FS> {
    pub fn new(fs: alloc::sync::Arc<FS>) -> Self {
        Self {
            fs,
            file_descriptors: litebox::sync::RwLock::new(Descriptors::new()),
            raw_descriptor_store: litebox::sync::RwLock::new(
                litebox::fd::RawDescriptorStorage::new(),
            ),
        }
    }

    /// Clone the FD table for `fork()`.
    ///
    /// Creates an independent FD table that shares the underlying file objects
    /// (via `Arc`) with the parent. This matches POSIX fork semantics: the
    /// child gets its own FD number space but file descriptions (offsets,
    /// flags) are shared. Each raw fd is duplicated in the global descriptor
    /// table so the child's `OwnedFd` instances are independent from the
    /// parent's.
    pub fn clone_for_fork(
        &self,
        global_dt: &mut litebox::fd::Descriptors<litebox_platform_multiplex::Platform>,
    ) -> Self {
        Self {
            fs: self.fs.clone(),
            file_descriptors: litebox::sync::RwLock::new(self.file_descriptors.read().clone()),
            raw_descriptor_store: litebox::sync::RwLock::new(
                self.raw_descriptor_store.read().clone_for_fork(global_dt),
            ),
        }
    }
}

/// Path in the file system
#[derive(Debug)]
enum FsPath {
    /// Absolute path
    Absolute { path: CString },
    /// Current working directory
    Cwd,
    /// Path is relative to a file descriptor
    #[expect(dead_code, reason = "currently unused, might want to use later")]
    FdRelative { fd: u32, path: CString },
    /// Fd
    Fd(u32),
}

/// Maximum size of a file path
pub const PATH_MAX: usize = 4096;

impl FsPath {
    /// Create a new `FsPath` from a dirfd and path.
    ///
    /// CWD-relative paths are resolved immediately to absolute paths.
    fn new(
        dirfd: i32,
        path: impl path::Arg,
        get_cwd: impl FnOnce() -> String,
    ) -> Result<Self, Errno> {
        let path_str = path.as_rust_str()?;
        if path_str.len() > PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let fs_path = if path_str.starts_with('/') {
            let cpath = path.to_c_str()?.into_owned();
            FsPath::Absolute { path: cpath }
        } else if dirfd >= 0 {
            let dirfd = u32::try_from(dirfd).expect("dirfd >= 0");
            if path_str.is_empty() {
                FsPath::Fd(dirfd)
            } else {
                let cpath = path.to_c_str()?.into_owned();
                FsPath::FdRelative {
                    fd: dirfd,
                    path: cpath,
                }
            }
        } else if dirfd == litebox_common_linux::AT_FDCWD {
            if path_str.is_empty() {
                FsPath::Cwd
            } else {
                // Resolve CWD-relative path to absolute.
                let mut abs = get_cwd();
                abs.push_str(path_str);
                let cpath = CString::new(abs).map_err(|_| Errno::EINVAL)?;
                FsPath::Absolute { path: cpath }
            }
        } else {
            return Err(Errno::EBADF);
        };
        Ok(fs_path)
    }
}

impl<FS: ShimFS> Task<FS> {
    fn get_umask(&self) -> Mode {
        self.fs.borrow().umask()
    }

    fn pty_rdev_for_raw_fd(&self, files: &FilesState<FS>, raw_fd: usize) -> Option<usize> {
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    let status = files.fs.fd_file_status(fd).ok()?;
                    let rdev = status.node_info.rdev?.get();
                    ((rdev >> 8) == 136).then_some(rdev)
                },
                |_fd| None,
                |_fd| None,
            )
            .ok()
            .flatten()
    }

    fn pty_target_for_guest_fd(
        &self,
        files: &FilesState<FS>,
        guest_fd: u32,
    ) -> Option<(usize, usize)> {
        let desc = {
            let file_table = files.file_descriptors.read();
            file_table.get_fd(guest_fd).cloned()
        }?;
        let Descriptor::LiteBoxRawFd(raw_fd) = desc else {
            return None;
        };
        let rdev = self.pty_rdev_for_raw_fd(files, raw_fd)?;
        Some((raw_fd, rdev))
    }

    fn trace_pty_open(&self, path: &str, guest_fd: u32, raw_fd: usize, rdev: Option<usize>) {
        litebox::log_println!(
            self.global.platform,
            "[PTY-OPEN] pid={} guest_fd={} raw_fd={} path={:?} target={}",
            self.pid,
            guest_fd,
            raw_fd,
            path,
            rdev.map_or_else(
                || alloc::string::String::from("<non-pty>"),
                |rdev| alloc::format!("{}:{}", rdev >> 8, rdev & 0xff),
            ),
        );
    }

    fn maybe_trace_pty_dup(&self, oldfd: u32, newfd: u32) {
        let files = self.files.borrow();
        let Some((old_raw_fd, old_rdev)) = self.pty_target_for_guest_fd(&files, oldfd) else {
            return;
        };
        let Some((new_raw_fd, new_rdev)) = self.pty_target_for_guest_fd(&files, newfd) else {
            return;
        };
        litebox::log_println!(
            self.global.platform,
            "[PTY-DUP] pid={} oldfd={} old_raw_fd={} old_target={}:{} newfd={} new_raw_fd={} new_target={}:{}",
            self.pid,
            oldfd,
            old_raw_fd,
            old_rdev >> 8,
            old_rdev & 0xff,
            newfd,
            new_raw_fd,
            new_rdev >> 8,
            new_rdev & 0xff,
        );
    }

    /// Resolve a path against the current working directory.
    fn resolve_path(&self, path: impl path::Arg) -> Result<CString, Errno> {
        let path_str = path.as_rust_str().map_err(|_| Errno::EINVAL)?;
        if path_str.starts_with('/') {
            CString::new(path_str.to_string()).map_err(|_| Errno::EINVAL)
        } else {
            let mut cwd = self.fs.borrow().cwd.read().clone();
            cwd.push_str(path_str);
            CString::new(cwd).map_err(|_| Errno::EINVAL)
        }
    }

    /// Handle syscall `umask`
    pub(crate) fn sys_umask(&self, new_mask: u32) -> Mode {
        let new_mask = Mode::from_bits_truncate(new_mask) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
        let old_mask = self
            .fs
            .borrow()
            .umask
            .swap(new_mask.bits(), Ordering::Relaxed);
        Mode::from_bits_retain(old_mask)
    }

    /// Handle syscall `open`
    pub fn sys_open(&self, path: impl path::Arg, flags: OFlags, mode: Mode) -> Result<u32, Errno> {
        let path = self.resolve_path(path)?;
        let mode = mode & !self.get_umask();
        let file = self
            .files
            .borrow()
            .fs
            .open(&*path, flags - OFlags::CLOEXEC, mode)?;
        {
            let mut dt = self.global.litebox.descriptor_table_mut();
            if flags.contains(OFlags::CLOEXEC) {
                let None = dt.set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC) else {
                    unreachable!()
                };
            }
            // Store access mode + status flags so F_GETFL can return them.
            let status = flags & OFlags::STATUS_FLAGS_MASK;
            let None = dt.set_entry_metadata(&file, crate::StdioStatusFlags(status)) else {
                unreachable!()
            };
        }
        let files = self.files.borrow();
        let raw_fd = files.raw_descriptor_store.write().fd_into_raw_integer(file);
        let guest_fd = files
            .file_descriptors
            .write()
            .insert(self, Descriptor::LiteBoxRawFd(raw_fd))
            .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))?;

        // Record fd → path for ELF patch cache.
        if let Ok(s) = path.to_str() {
            self.process_state
                .borrow()
                .fd_paths
                .lock()
                .insert(guest_fd.cast_signed(), alloc::string::String::from(s));
            if s == "/dev/ptmx" || s.starts_with("/dev/pts/") {
                let rdev = self.pty_rdev_for_raw_fd(&files, raw_fd);
                self.trace_pty_open(s, guest_fd, raw_fd, rdev);
            }
        }

        Ok(guest_fd)
    }

    /// Handle syscall `openat`
    pub fn sys_openat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<u32, Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => self.sys_open(path, flags, mode),
            FsPath::Cwd => self.sys_open(get_cwd(), flags, mode),
            FsPath::Fd(_fd) => {
                log_unsupported!("openat with FsPath::Fd");
                Err(Errno::EINVAL)
            }
            FsPath::FdRelative { fd: _, path: _ } => {
                log_unsupported!("openat with FsPath::FdRelative");
                Err(Errno::EINVAL)
            }
        }
    }

    /// Handle syscall `ftruncate`
    pub(crate) fn sys_ftruncate(&self, fd: i32, length: usize) -> Result<(), Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let desc = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => files.run_on_raw_fd(
                *raw_fd,
                |fd| files.fs.truncate(fd, length, false).map_err(Errno::from),
                |_fd| todo!("net"),
                |_fd| todo!("pipes"),
            ),
            _ => Err(Errno::EINVAL),
        }
        .flatten()
    }

    /// Handle syscall `unlinkat`
    pub(crate) fn sys_unlinkat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        if flags.intersects(AtFlags::AT_REMOVEDIR.complement()) {
            return Err(Errno::EINVAL);
        }

        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => {
                if flags.contains(AtFlags::AT_REMOVEDIR) {
                    self.files.borrow().fs.rmdir(path).map_err(Errno::from)
                } else {
                    self.files.borrow().fs.unlink(path).map_err(Errno::from)
                }
            }
            FsPath::Cwd => Err(Errno::EINVAL),
            FsPath::Fd(_) | FsPath::FdRelative { .. } => unimplemented!(),
        }
    }

    pub(crate) fn sys_renameat2(
        &self,
        olddirfd: i32,
        oldpath: impl path::Arg,
        newdirfd: i32,
        newpath: impl path::Arg,
        flags: u32,
    ) -> Result<(), Errno> {
        if flags != 0 {
            // RENAME_NOREPLACE, RENAME_EXCHANGE, RENAME_WHITEOUT not yet supported
            return Err(Errno::EINVAL);
        }
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let old = FsPath::new(olddirfd, oldpath, get_cwd)?;
        let new = FsPath::new(newdirfd, newpath, get_cwd)?;
        let FsPath::Absolute { path: old_path } = old else {
            return Err(Errno::EINVAL);
        };
        let FsPath::Absolute { path: new_path } = new else {
            return Err(Errno::EINVAL);
        };
        self.files
            .borrow()
            .fs
            .rename(old_path, new_path)
            .map_err(Errno::from)
    }

    /// Handle syscall `read`
    ///
    /// `offset` is an optional offset to read from. If `None`, it will read from the current file position.
    /// If `Some`, it will read from the specified offset without changing the current file position.
    pub fn sys_read(&self, fd: i32, buf: &mut [u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let desc = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                let raw_fd = *raw_fd;
                drop(file_table);
                // We need to do this cell dance because otherwise Rust can't recognize that the two
                // closures are mutually exclusive.
                let buf: core::cell::RefCell<&mut [u8]> = core::cell::RefCell::new(buf);
                files
                    .run_on_raw_fd(
                        raw_fd,
                        |fd| {
                            // First attempt.
                            let result = files
                                .fs
                                .read(fd, &mut buf.borrow_mut(), offset)
                                .map_err(Errno::from);
                            // If the read returned EAGAIN (no data), check whether
                            // this fd is a pollable device that wants blocking reads
                            // (e.g. PTY slave). Non-blocking pollables (PTY master)
                            // return EAGAIN immediately for epoll-driven callers.
                            if let Err(Errno::EAGAIN) = result
                                && let Some(pollable) = files.fs.get_io_pollable(fd)
                                && pollable.should_block_read()
                            {
                                loop {
                                    // vfork parking needs blocked host-side loops
                                    // to break out so prepare_to_run_guest() can
                                    // park the thread.
                                    if self.is_exiting() || self.is_suspended() {
                                        return Err(Errno::EINTR);
                                    }
                                    let events = pollable.check_io_events();
                                    if events.contains(Events::HUP) {
                                        return Ok(0); // EOF — master closed
                                    }
                                    if events.contains(Events::IN) {
                                        match files.fs.read(fd, &mut buf.borrow_mut(), offset) {
                                            Ok(n) => return Ok(n),
                                            Err(litebox::fs::errors::ReadError::WouldBlock) => {
                                                core::hint::spin_loop();
                                                continue;
                                            }
                                            Err(e) => return Err(Errno::from(e)),
                                        }
                                    }
                                    core::hint::spin_loop();
                                }
                            }
                            result
                        },
                        |fd| {
                            self.global.receive(
                                &self.wait_cx(),
                                fd,
                                &mut buf.borrow_mut(),
                                litebox_common_linux::ReceiveFlags::empty(),
                                None,
                            )
                        },
                        |fd| {
                            let is_vfork_child = self.fork_context.borrow().is_some();
                            self.global
                                .pipes
                                .read_vfork_aware(
                                    &self.wait_cx(),
                                    fd,
                                    &mut buf.borrow_mut(),
                                    is_vfork_child,
                                )
                                .map_err(Errno::from)
                        },
                    )
                    .flatten()
            }
            Descriptor::Epoll { .. } => Err(Errno::EINVAL),
            Descriptor::Eventfd { file, .. } => {
                let file = file.clone();
                drop(file_table);
                if buf.len() < size_of::<u64>() {
                    return Err(Errno::EINVAL);
                }
                let value = file.read(&self.wait_cx())?;
                buf[..size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
                Ok(size_of::<u64>())
            }
            Descriptor::Unix { file, .. } => file.recvfrom(
                &self.wait_cx(),
                buf,
                litebox_common_linux::ReceiveFlags::empty(),
                None,
            ),
        }
    }

    /// Handle syscall `write`
    ///
    /// `offset` is an optional offset to write to. If `None`, it will write to the current file position.
    /// If `Some`, it will write to the specified offset without changing the current file position.
    pub fn sys_write(&self, fd: i32, buf: &[u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let desc = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        let res = match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                let raw_fd = *raw_fd;
                drop(file_table);
                files
                    .run_on_raw_fd(
                        raw_fd,
                        |fd| files.fs.write(fd, buf, offset).map_err(Errno::from),
                        |fd| {
                            self.global.sendto(
                                &self.wait_cx(),
                                fd,
                                buf,
                                litebox_common_linux::SendFlags::empty(),
                                None,
                            )
                        },
                        |fd| {
                            self.global
                                .pipes
                                .write(&self.wait_cx(), fd, buf)
                                .map_err(Errno::from)
                        },
                    )
                    .flatten()
            }
            Descriptor::Epoll { .. } => Err(Errno::EINVAL),
            Descriptor::Eventfd { file, .. } => {
                let file = file.clone();
                drop(file_table);
                let value: u64 = u64::from_le_bytes(
                    buf[..size_of::<u64>()]
                        .try_into()
                        .map_err(|_| Errno::EINVAL)?,
                );
                file.write(&self.wait_cx(), value)
            }
            Descriptor::Unix { file, .. } => {
                file.sendto(self, buf, litebox_common_linux::SendFlags::empty(), None)
            }
        };
        if let Err(Errno::EPIPE) = res {
            // TODO: send SIGPIPE to the current task.
            // For now, just return EPIPE — most programs check the return value.
        }
        res
    }

    /// Handle syscall `pread64`
    pub fn sys_pread64(&self, fd: i32, buf: &mut [u8], offset: i64) -> Result<usize, Errno> {
        let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.sys_read(fd, buf, Some(pos))
    }

    /// Handle syscall `pwrite64`
    pub fn sys_pwrite64(&self, fd: i32, buf: &[u8], offset: i64) -> Result<usize, Errno> {
        let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.sys_write(fd, buf, Some(pos))
    }
}

const SEEK_SET: i16 = 0;
const SEEK_CUR: i16 = 1;
const SEEK_END: i16 = 2;

pub(crate) fn try_into_whence(value: i16) -> Result<SeekWhence, i16> {
    match value {
        SEEK_SET => Ok(SeekWhence::RelativeToBeginning),
        SEEK_CUR => Ok(SeekWhence::RelativeToCurrentOffset),
        SEEK_END => Ok(SeekWhence::RelativeToEnd),
        _ => Err(value),
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `lseek`
    pub fn sys_lseek(&self, fd: i32, offset: isize, whence: SeekWhence) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let desc = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => files
                .run_on_raw_fd(
                    *raw_fd,
                    |fd| files.fs.seek(fd, offset, whence).map_err(Errno::from),
                    |_| Err(Errno::ESPIPE),
                    |_| Err(Errno::ESPIPE),
                )
                .flatten(),
            Descriptor::Epoll { .. } | Descriptor::Eventfd { .. } | Descriptor::Unix { .. } => {
                Err(Errno::ESPIPE)
            }
        }
    }

    /// Handle syscall `mkdir`
    pub fn sys_mkdir(&self, pathname: impl path::Arg, mode: u32) -> Result<(), Errno> {
        let pathname = self.resolve_path(pathname)?;
        let mode = Mode::from_bits_retain(mode) & !self.get_umask();
        self.files
            .borrow()
            .fs
            .mkdir(pathname, mode)
            .map_err(Errno::from)
    }

    pub(crate) fn do_close(&self, desc: Descriptor<FS>) -> Result<(), Errno> {
        let files = self.files.borrow();
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                let mut rds = files.raw_descriptor_store.write();
                match rds.fd_consume_raw_integer(raw_fd) {
                    Ok(fd) => {
                        drop(rds);
                        files.fs.close(&fd).map_err(Errno::from)
                    }
                    Err(litebox::fd::ErrRawIntFd::NotFound) => Err(Errno::EBADF),
                    Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                        match rds
                        .fd_consume_raw_integer::<litebox::net::Network<litebox_platform_multiplex::Platform>>(raw_fd)
                    {
                        Ok(fd) => {
                            drop(rds);
                            self.global.close_socket(&self.wait_cx(), fd)
                        },
                        Err(litebox::fd::ErrRawIntFd::NotFound) => Err(Errno::EBADF),
                        Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                            match rds.fd_consume_raw_integer::<litebox::pipes::Pipes<litebox_platform_multiplex::Platform>>(raw_fd) {
                                Ok(fd) => {
                                    drop(rds);
                                    self.global.pipes.close(&fd).map_err(Errno::from)
                                }
                                Err(litebox::fd::ErrRawIntFd::NotFound) => Err(Errno::EBADF),
                                Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                                    // We currently only have fs, net and pipes FDs at the moment,
                                    // if/when we add more, we need to expand this out too.
                                    unreachable!()
                                }
                            }
                        }
                    }
                    }
                }
            }
            Descriptor::Eventfd { .. } | Descriptor::Epoll { .. } | Descriptor::Unix { .. } => {
                Ok(())
            }
        }
    }

    /// Handle syscall `close`
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        // Finalize any in-progress ELF patching for this fd (mprotect
        // trampoline RW→RX) before closing the descriptor.
        self.finalize_elf_patch(fd);

        // Remove fd → path mapping.
        self.process_state.borrow().fd_paths.lock().remove(&fd);

        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let mut file_table = files.file_descriptors.write();
        match file_table.remove(fd) {
            Some(desc) => {
                drop(file_table); // drop before potentially blocking `close`
                self.do_close(desc)
            }
            None => Err(Errno::EBADF),
        }
    }

    /// Handle syscall `readv`
    pub fn sys_readv(
        &self,
        fd: i32,
        iovec: ConstPtr<IoReadVec<MutPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let iovs: &[IoReadVec<MutPtr<u8>>] = &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
        let mut total_read = 0;
        let mut kernel_buffer = vec![
            0u8;
            iovs.iter()
                .map(|i| i.iov_len)
                .max()
                .unwrap_or_default()
                .min(super::super::MAX_KERNEL_BUF_SIZE)
        ];
        for iov in iovs {
            if iov.iov_len == 0 {
                continue;
            }
            let Ok(_iov_len) = isize::try_from(iov.iov_len) else {
                return Err(Errno::EINVAL);
            };
            // TODO: The data transfers performed by readv() and writev() are atomic: the data
            // written by writev() is written as a single block that is not intermingled with
            // output from writes in other processes
            let size = match desc {
                Descriptor::LiteBoxRawFd(raw_fd) => files
                    .run_on_raw_fd(
                        *raw_fd,
                        |fd| {
                            files
                                .fs
                                .read(fd, &mut kernel_buffer, None)
                                .map_err(Errno::from)
                        },
                        |_fd| todo!("net"),
                        |_fd| todo!("pipes"),
                    )
                    .flatten()?,
                Descriptor::Epoll { .. } => return Err(Errno::EINVAL),
                Descriptor::Eventfd { .. } => todo!(),
                Descriptor::Unix { .. } => todo!(),
            };
            self.park_if_deferred();
            iov.iov_base
                .copy_from_slice(0, &kernel_buffer[..size])
                .ok_or(Errno::EFAULT)?;
            total_read += size;
            if size < iov.iov_len {
                // Okay to transfer fewer bytes than requested
                break;
            }
        }
        Ok(total_read)
    }
}

fn write_to_iovec<F>(iovs: &[IoWriteVec<ConstPtr<u8>>], write_fn: F) -> Result<usize, Errno>
where
    F: Fn(&[u8]) -> Result<usize, Errno>,
{
    let mut total_written = 0;
    for iov in iovs {
        if iov.iov_len == 0 {
            continue;
        }
        let slice = iov
            .iov_base
            .to_owned_slice(iov.iov_len)
            .ok_or(Errno::EFAULT)?;
        let size = write_fn(&slice)?;
        total_written += size;
        if size < iov.iov_len {
            // Okay to transfer fewer bytes than requested
            break;
        }
    }
    Ok(total_written)
}

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `writev`
    pub fn sys_writev(
        &self,
        fd: i32,
        iovec: ConstPtr<IoWriteVec<ConstPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let iovs: &[IoWriteVec<ConstPtr<u8>>] =
            &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        let res = match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                let raw_fd = *raw_fd;
                drop(locked_file_descriptors); // drop before potentially blocking write
                files
                    .run_on_raw_fd(
                        raw_fd,
                        |fd| {
                            write_to_iovec(iovs, |buf: &[u8]| {
                                files.fs.write(fd, buf, None).map_err(Errno::from)
                            })
                        },
                        |fd| {
                            write_to_iovec(iovs, |buf| {
                                self.global.sendto(
                                    &self.wait_cx(),
                                    fd,
                                    buf,
                                    litebox_common_linux::SendFlags::empty(),
                                    None,
                                )
                            })
                        },
                        |_fd| todo!("pipes"),
                    )
                    .flatten()
            }
            Descriptor::Epoll { .. } => Err(Errno::EINVAL),
            Descriptor::Eventfd { .. } => todo!(),
            Descriptor::Unix { .. } => todo!(),
        };
        if let Err(Errno::EPIPE) = res {
            // TODO: send SIGPIPE to the current task.
        }
        res
    }

    /// Handle syscall `access`
    pub fn sys_access(
        &self,
        pathname: impl path::Arg,
        mode: litebox_common_linux::AccessFlags,
    ) -> Result<(), Errno> {
        let pathname = self.resolve_path(pathname)?;
        let status = self.files.borrow().fs.file_status(pathname)?;
        if mode == litebox_common_linux::AccessFlags::F_OK {
            return Ok(());
        }
        // TODO: the check is done using the calling process's real UID and GID.
        // Here we assume the caller owns the file.
        if mode.contains(litebox_common_linux::AccessFlags::R_OK)
            && !status.mode.contains(litebox::fs::Mode::RUSR)
        {
            return Err(Errno::EACCES);
        }
        if mode.contains(litebox_common_linux::AccessFlags::W_OK)
            && !status.mode.contains(litebox::fs::Mode::WUSR)
        {
            return Err(Errno::EACCES);
        }
        if mode.contains(litebox_common_linux::AccessFlags::X_OK)
            && !status.mode.contains(litebox::fs::Mode::XUSR)
        {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// Read the target of a symbolic link
    ///
    /// The caller must pass an absolute path.
    ///
    /// Note that this function only handles the following cases that we hardcoded:
    /// - `/proc/self/fd/<fd>`
    fn do_readlink(&self, fullpath: &str) -> Result<String, Errno> {
        if let Some(stripped) = fullpath.strip_prefix("/proc/self/fd/") {
            let fd = stripped.parse::<u32>().map_err(|_| Errno::EINVAL)?;
            match fd {
                0 => return Ok("/dev/stdin".to_string()),
                1 => return Ok("/dev/stdout".to_string()),
                2 => return Ok("/dev/stderr".to_string()),
                _ => unimplemented!(),
            }
        }

        // Try the filesystem for symlink resolution
        match self.files.borrow().fs.read_link(fullpath) {
            Ok(target) => Ok(target),
            Err(_) => Err(Errno::ENOENT),
        }
    }

    /// Handle syscall `readlink`
    pub fn sys_readlink(&self, pathname: impl path::Arg, buf: &mut [u8]) -> Result<usize, Errno> {
        self.sys_readlinkat(litebox_common_linux::AT_FDCWD, pathname, buf)
    }

    /// Handle syscall `readlinkat`
    pub fn sys_readlinkat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fspath = FsPath::new(dirfd, pathname, get_cwd)?;
        let path = match fspath {
            FsPath::Absolute { path } => {
                self.do_readlink(path.to_str().map_err(|_| Errno::EINVAL)?)
            }
            FsPath::Cwd => {
                let cwd = self.fs.borrow().cwd.read().clone();
                self.do_readlink(&cwd)
            }
            FsPath::Fd(_) | FsPath::FdRelative { .. } => unimplemented!(),
        }?;
        let bytes = path.as_bytes();
        let min_len = core::cmp::min(buf.len(), bytes.len());
        buf[..min_len].copy_from_slice(&bytes[..min_len]);
        Ok(min_len)
    }
}

impl<FS: ShimFS> Descriptor<FS> {
    fn stat(&self, task: &Task<FS>) -> Result<FileStat, Errno> {
        let fstat = match self {
            Descriptor::LiteBoxRawFd(raw_fd) => task
                .files
                .borrow()
                .run_on_raw_fd(
                    *raw_fd,
                    |fd| {
                        task.files
                            .borrow()
                            .fs
                            .fd_file_status(fd)
                            .map(FileStat::from)
                            .map_err(Errno::from)
                    },
                    |_fd| {
                        Ok(FileStat {
                            // TODO: give correct values
                            st_dev: 0,
                            st_ino: 0,
                            st_nlink: 1,
                            st_mode: (litebox_common_linux::InodeType::Socket as u32
                                | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
                            .truncate(),
                            st_uid: 0,
                            st_gid: 0,
                            st_rdev: 0,
                            st_size: 0,
                            st_blksize: 4096,
                            st_blocks: 0,
                            ..Default::default()
                        })
                    },
                    |fd| {
                        let half_pipe_type = task.global.pipes.half_pipe_type(fd)?;
                        let read_write_mode = match half_pipe_type {
                            litebox::pipes::HalfPipeType::SenderHalf => Mode::WUSR,
                            litebox::pipes::HalfPipeType::ReceiverHalf => Mode::RUSR,
                        };
                        Ok(FileStat {
                            // TODO: give correct values
                            st_dev: 0,
                            st_ino: 0,
                            st_nlink: 1,
                            st_mode: (read_write_mode.bits()
                                | litebox_common_linux::InodeType::NamedPipe as u32)
                                .truncate(),
                            st_uid: 0,
                            st_gid: 0,
                            st_rdev: 0,
                            st_size: 0,
                            st_blksize: 4096,
                            st_blocks: 0,
                            ..Default::default()
                        })
                    },
                )
                .flatten()?,
            Descriptor::Eventfd { .. } => FileStat {
                // TODO: give correct values
                st_dev: 0,
                st_ino: 0,
                st_nlink: 1,
                st_mode: (Mode::RUSR | Mode::WUSR).bits().truncate(),
                st_uid: 0,
                st_gid: 0,
                st_rdev: 0,
                st_size: 0,
                st_blksize: 4096,
                st_blocks: 0,
                ..Default::default()
            },
            Descriptor::Epoll { .. } => FileStat {
                // TODO: give correct values
                st_dev: 0,
                st_ino: 0,
                st_nlink: 1,
                st_mode: (Mode::RUSR | Mode::WUSR).bits().truncate(),
                st_uid: 0,
                st_gid: 0,
                st_rdev: 0,
                st_size: 0,
                st_blksize: 0,
                st_blocks: 0,
                ..Default::default()
            },
            Descriptor::Unix { .. } => FileStat {
                // TODO: give correct values
                st_dev: 0,
                st_ino: 0,
                st_nlink: 1,
                st_mode: (litebox_common_linux::InodeType::Socket as u32
                    | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
                .truncate(),
                st_uid: 0,
                st_gid: 0,
                st_rdev: 0,
                st_size: 0,
                st_blksize: 4096,
                st_blocks: 0,
                ..Default::default()
            },
        };
        Ok(fstat)
    }

    pub(crate) fn get_file_descriptor_flags(
        &self,
        global: &GlobalState<FS>,
        files: &FilesState<FS>,
    ) -> Result<FileDescriptorFlags, Errno> {
        // Currently, only one such flag is defined: FD_CLOEXEC, the close-on-exec flag.
        // See https://www.man7.org/linux/man-pages/man2/F_GETFD.2const.html
        fn get_flags<FS: ShimFS, S: FdEnabledSubsystem>(
            global: &GlobalState<FS>,
            fd: &TypedFd<S>,
        ) -> FileDescriptorFlags {
            global
                .litebox
                .descriptor_table()
                .with_metadata(fd, |flags: &FileDescriptorFlags| *flags)
                .unwrap_or(FileDescriptorFlags::empty())
        }
        match self {
            Descriptor::LiteBoxRawFd(raw_fd) => files.run_on_raw_fd(
                *raw_fd,
                |fd| get_flags(global, fd),
                |fd| get_flags(global, fd),
                |fd| get_flags(global, fd),
            ),
            Descriptor::Eventfd { close_on_exec, .. }
            | Descriptor::Epoll { close_on_exec, .. }
            | Descriptor::Unix { close_on_exec, .. } => Ok(
                if close_on_exec.load(core::sync::atomic::Ordering::Relaxed) {
                    FileDescriptorFlags::FD_CLOEXEC
                } else {
                    FileDescriptorFlags::empty()
                },
            ),
        }
    }
    fn set_file_descriptor_flags(
        &self,
        global: &GlobalState<FS>,
        files: &FilesState<FS>,
        flags: FileDescriptorFlags,
    ) -> Result<(), Errno> {
        fn set_flags<FS: ShimFS, S: FdEnabledSubsystem>(
            global: &GlobalState<FS>,
            fd: &TypedFd<S>,
            flags: FileDescriptorFlags,
        ) {
            let _old = global
                .litebox
                .descriptor_table_mut()
                .set_fd_metadata(fd, flags);
        }

        match self {
            Descriptor::LiteBoxRawFd(raw_fd) => files.run_on_raw_fd(
                *raw_fd,
                |fd| set_flags(global, fd, flags),
                |fd| set_flags(global, fd, flags),
                |fd| set_flags(global, fd, flags),
            )?,
            Descriptor::Eventfd { close_on_exec, .. }
            | Descriptor::Epoll { close_on_exec, .. }
            | Descriptor::Unix { close_on_exec, .. } => {
                close_on_exec.store(
                    flags.contains(FileDescriptorFlags::FD_CLOEXEC),
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
        Ok(())
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Get the file status of `pathname`.
    ///
    /// The `pathname` must be absolute.
    fn do_stat(&self, pathname: impl path::Arg, follow_symlink: bool) -> Result<FileStat, Errno> {
        let normalized_path = pathname.normalized()?;
        let path = if follow_symlink {
            self.do_readlink(normalized_path.as_str())
                .unwrap_or(normalized_path)
        } else {
            normalized_path
        };
        let status = self.files.borrow().fs.file_status(path)?;
        Ok(FileStat::from(status))
    }

    /// Handle syscall `stat`
    pub fn sys_stat(&self, pathname: impl path::Arg) -> Result<FileStat, Errno> {
        let pathname = self.resolve_path(pathname)?;
        self.do_stat(pathname, true)
    }

    /// Handle syscall `lstat`
    ///
    /// `lstat` is identical to `stat`, except that if `pathname` is a symbolic link,
    /// then it returns information about the link itself, not the file that the link refers to.
    /// TODO: we do not support symbolic links yet.
    pub fn sys_lstat(&self, pathname: impl path::Arg) -> Result<FileStat, Errno> {
        let pathname = self.resolve_path(pathname)?;
        self.do_stat(pathname, false)
    }

    /// Handle syscall `fstat`
    pub fn sys_fstat(&self, fd: i32) -> Result<FileStat, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .file_descriptors
            .read()
            .get_fd(fd)
            .ok_or(Errno::EBADF)?
            .stat(self)
    }

    /// Handle syscall `newfstatat`
    pub fn sys_newfstatat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<FileStat, Errno> {
        let current_support_flags = AtFlags::AT_EMPTY_PATH;
        if flags.contains(current_support_flags.complement()) {
            todo!("unsupported flags");
        }

        let files = self.files.borrow();
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        let fstat: FileStat = match fs_path {
            FsPath::Absolute { path } => {
                self.do_stat(path, !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW))?
            }
            FsPath::Cwd => files.fs.file_status(get_cwd())?.into(),
            FsPath::Fd(fd) => files
                .file_descriptors
                .read()
                .get_fd(fd)
                .ok_or(Errno::EBADF)?
                .stat(self)?,
            FsPath::FdRelative { .. } => todo!(),
        };
        Ok(fstat)
    }

    pub(crate) fn sys_fcntl(
        &self,
        fd: i32,
        arg: FcntlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
        match arg {
            FcntlArg::GETFD => Ok(locked_file_descriptors
                .get_fd(fd)
                .ok_or(Errno::EBADF)?
                .get_file_descriptor_flags(&self.global, &files)?
                .bits()),
            FcntlArg::SETFD(flags) => locked_file_descriptors
                .get_fd(fd)
                .ok_or(Errno::EBADF)?
                .set_file_descriptor_flags(&self.global, &files, flags)
                .map(|()| 0),
            FcntlArg::GETFL => match desc {
                Descriptor::LiteBoxRawFd(raw_fd) => Ok(files
                    .run_on_raw_fd(
                        *raw_fd,
                        |fd| {
                            Ok(self
                                .global
                                .litebox
                                .descriptor_table()
                                .with_metadata(fd, |crate::StdioStatusFlags(flags)| {
                                    *flags & OFlags::STATUS_FLAGS_MASK
                                })
                                .unwrap_or(OFlags::empty()))
                        },
                        |fd| {
                            Ok(self
                                .global
                                .litebox
                                .descriptor_table()
                                .with_metadata(fd, |crate::syscalls::net::SocketOFlags(flags)| {
                                    *flags & OFlags::STATUS_FLAGS_MASK
                                })
                                .unwrap_or(OFlags::empty()))
                        },
                        |fd| {
                            let pipes = &self.global.pipes;
                            let flags = OFlags::from(pipes.get_flags(fd).map_err(Errno::from)?);
                            let dirn = match pipes.half_pipe_type(fd)? {
                                litebox::pipes::HalfPipeType::SenderHalf => OFlags::WRONLY,
                                litebox::pipes::HalfPipeType::ReceiverHalf => OFlags::RDONLY,
                            };
                            Ok(dirn | flags)
                        },
                    )
                    .flatten()?
                    .bits()),
                Descriptor::Eventfd { file, .. } => Ok(file.get_status().bits()),
                Descriptor::Epoll { file, .. } => Ok(file.get_status().bits()),
                Descriptor::Unix { file, .. } => Ok(file.get_status().bits()),
            },
            FcntlArg::SETFL(flags) => {
                let setfl_mask = OFlags::APPEND
                    | OFlags::NONBLOCK
                    | OFlags::NDELAY
                    | OFlags::DIRECT
                    | OFlags::NOATIME;
                macro_rules! toggle_flags {
                    ($t:ident) => {
                        let diff = $t.get_status() ^ flags;
                        if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                            todo!("unsupported flags");
                        }
                        $t.set_status(flags & setfl_mask, true);
                        $t.set_status(flags.complement() & setfl_mask, false);
                    };
                }
                match desc {
                    Descriptor::LiteBoxRawFd(raw_fd) => files.run_on_raw_fd(
                        *raw_fd,
                        |fd| {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .with_metadata_mut(fd, |crate::StdioStatusFlags(f)| {
                                    let diff = *f ^ flags;
                                    if diff.intersects(
                                        OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME,
                                    ) {
                                        todo!("unsupported flags");
                                    }
                                    f.toggle(diff);
                                })
                                .map_err(|err| match err {
                                    MetadataError::ClosedFd => Errno::EBADF,
                                    MetadataError::NoSuchMetadata => {
                                        unimplemented!("SETFL on non-stdio")
                                    }
                                })
                        },
                        |fd| {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .with_metadata_mut(fd, |crate::syscalls::net::SocketOFlags(f)| {
                                    let diff = *f ^ flags;
                                    if diff.intersects(
                                        OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME,
                                    ) {
                                        todo!("unsupported flags");
                                    }
                                    f.toggle(diff);
                                })
                                .map_err(|err| match err {
                                    MetadataError::ClosedFd => Errno::EBADF,
                                    MetadataError::NoSuchMetadata => {
                                        unreachable!("all sockets have SocketOFlags when created")
                                    }
                                })
                        },
                        |fd| {
                            if flags.intersects(OFlags::NONBLOCK.complement()) {
                                todo!("unsupported flags for pipes")
                            }
                            self.global
                                .pipes
                                .update_flags(
                                    fd,
                                    litebox::pipes::Flags::NON_BLOCKING,
                                    flags.intersects(OFlags::NONBLOCK),
                                )
                                .map_err(Errno::from)
                        },
                    )??,
                    Descriptor::Eventfd { file, .. } => {
                        toggle_flags!(file);
                    }
                    Descriptor::Epoll { .. } => todo!(),
                    Descriptor::Unix { file, .. } => {
                        toggle_flags!(file);
                    }
                }
                Ok(0)
            }
            FcntlArg::GETLK(lock) => {
                let Descriptor::LiteBoxRawFd(raw_fd) = desc else {
                    return Err(Errno::EBADF);
                };
                self.files
                    .borrow()
                    .run_on_raw_fd(
                        *raw_fd,
                        |_fd| {
                            let mut flock = lock.read_at_offset(0).ok_or(Errno::EFAULT)?;
                            let lock_type = litebox_common_linux::FlockType::try_from(flock.type_)
                                .map_err(|_| Errno::EINVAL)?;
                            if let litebox_common_linux::FlockType::Unlock = lock_type {
                                return Err(Errno::EINVAL);
                            }

                            // Note LiteBox does not support multiple processes yet, and one process
                            // can always acquire the lock it owns, so return `Unlock` unconditionally.
                            flock.type_ = litebox_common_linux::FlockType::Unlock as i16;
                            lock.write_at_offset(0, flock).ok_or(Errno::EFAULT)?;
                            Ok(0)
                        },
                        |_fd| todo!("net"),
                        |_fd| todo!("pipes"),
                    )
                    .flatten()
            }
            FcntlArg::SETLK(lock) | FcntlArg::SETLKW(lock) => {
                let Descriptor::LiteBoxRawFd(raw_fd) = desc else {
                    return Err(Errno::EBADF);
                };
                self.files
                    .borrow()
                    .run_on_raw_fd(
                        *raw_fd,
                        |_fd| {
                            let flock = lock.read_at_offset(0).ok_or(Errno::EFAULT)?;
                            let _ = litebox_common_linux::FlockType::try_from(flock.type_)
                                .map_err(|_| Errno::EINVAL)?;

                            // Note LiteBox does not support multiple processes yet, and one process
                            // can always acquire the lock it owns, so we don't need to maintain anything.
                            Ok(0)
                        },
                        |_fd| todo!("net"),
                        |_fd| todo!("pipes"),
                    )
                    .flatten()
            }
            FcntlArg::DUPFD { cloexec, min_fd } => {
                let new_file = self.do_dup(
                    desc,
                    if cloexec {
                        OFlags::CLOEXEC
                    } else {
                        OFlags::empty()
                    },
                )?;
                let max_fd = self
                    .process()
                    .limits
                    .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE);
                if min_fd as usize >= max_fd {
                    return Err(Errno::EINVAL);
                }
                drop(locked_file_descriptors); // drop before acquiring write lock
                files
                    .file_descriptors
                    .write()
                    .insert_in_range(new_file, min_fd as usize, max_fd)
                    .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))
            }
            _ => unimplemented!(),
        }
    }

    /// Handle syscall `getcwd`
    pub fn sys_getcwd(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let cwd = self.fs.borrow().cwd.read().clone();
        // need to account for the null terminator
        if cwd.len() >= buf.len() {
            return Err(Errno::ERANGE);
        }

        let Ok(name) = CString::new(cwd) else {
            return Err(Errno::EINVAL);
        };
        let bytes = name.as_bytes_with_nul();
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }

    /// Handle syscall `chdir`
    pub fn sys_chdir(&self, pathname: impl path::Arg) -> Result<(), Errno> {
        use litebox::fs::FileType;
        use litebox::fs::errors::{FileStatusError, PathError};
        use litebox::path::Arg as _;

        // Resolve relative paths against CWD, then normalize (handle `.` / `..`).
        let resolved = self.resolve_path(pathname)?;
        let abs_path = resolved.normalized().map_err(|_| Errno::EINVAL)?;

        // Verify the path exists and is a directory.
        match self.files.borrow().fs.file_status(abs_path.as_str()) {
            Ok(status) => {
                if status.file_type != FileType::Directory {
                    return Err(Errno::ENOTDIR);
                }
            }
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory)) => {
                return Err(Errno::ENOENT);
            }
            Err(FileStatusError::PathError(_)) => {
                return Err(Errno::EACCES);
            }
            Err(_) => {
                return Err(Errno::ENOENT);
            }
        }

        // Ensure the CWD ends with '/'.
        let mut new_cwd = abs_path;
        if !new_cwd.ends_with('/') {
            new_cwd.push('/');
        }

        *self.fs.borrow().cwd.write() = new_cwd;
        Ok(())
    }
}

const DEFAULT_PIPE_BUF_SIZE: usize = 1024 * 1024;

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `pipe2`
    pub fn sys_pipe2(&self, flags: OFlags) -> Result<(u32, u32), Errno> {
        let (pipe_flags, cloexec) = {
            use litebox::pipes::Flags;
            let mut f = Flags::empty();
            if flags.contains((OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::DIRECT).complement()) {
                return Err(Errno::EINVAL);
            }
            f.set(Flags::NON_BLOCKING, flags.contains(OFlags::NONBLOCK));
            if flags.contains(OFlags::DIRECT) {
                todo!("O_DIRECT not supported");
            }
            (f, flags.contains(OFlags::CLOEXEC))
        };

        let (writer, reader) = self.global.pipes.create_pipe(
            DEFAULT_PIPE_BUF_SIZE,
            pipe_flags,
            // See `man 7 pipe` for `PIPE_BUF`. On Linux, this is 4096.
            core::num::NonZero::new(4096),
        );

        if cloexec {
            let mut dt = self.global.litebox.descriptor_table_mut();
            let None = dt.set_fd_metadata(&writer, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
            let None = dt.set_fd_metadata(&reader, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
        }

        let files = self.files.borrow();
        let mut rds = files.raw_descriptor_store.write();
        let wr_raw_fd = rds.fd_into_raw_integer(writer);
        let rd_raw_fd = rds.fd_into_raw_integer(reader);
        let mut fds = files.file_descriptors.write();
        let w = fds
            .insert(self, Descriptor::LiteBoxRawFd(wr_raw_fd))
            .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))?;
        let r = fds
            .insert(self, Descriptor::LiteBoxRawFd(rd_raw_fd))
            .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))?;
        Ok((r, w))
    }

    pub fn sys_eventfd2(&self, initval: u32, flags: EfdFlags) -> Result<u32, Errno> {
        if flags
            .contains((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
        {
            return Err(Errno::EINVAL);
        }

        let eventfd = super::eventfd::EventFile::new(u64::from(initval), flags);
        let files = self.files.borrow();
        files
            .file_descriptors
            .write()
            .insert(
                self,
                Descriptor::Eventfd {
                    file: alloc::sync::Arc::new(eventfd),
                    close_on_exec: core::sync::atomic::AtomicBool::new(
                        flags.contains(EfdFlags::CLOEXEC),
                    ),
                },
            )
            .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))
    }

    /// Forward a terminal ioctl to the host kernel for a stdio fd.
    ///
    /// Maps the fd's device type to the corresponding host stdio stream and
    /// invokes the platform's `stdio_ioctl` punchthrough.
    fn host_stdio_ioctl(
        &self,
        fs: &FS,
        fd: &TypedFd<FS>,
        arg: &IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        use litebox::platform::{StdioIoctlError, StdioStream};

        // Determine which host stream this fd corresponds to.
        let status = fs.fd_file_status(fd).map_err(|_| Errno::EBADF)?;
        // Each stdio device has a distinct ino (stdin=9, stdout=10, stderr=11, tty=12).
        let preferred = match status.node_info.ino {
            9 | 12 => StdioStream::Stdin,
            10 => StdioStream::Stdout,
            _ => StdioStream::Stderr,
        };

        // Try the preferred stream first, then fall back to any stream that is
        // actually a terminal on the host. This handles the common case where
        // the runner's stderr (or stdout) is redirected to a log file but the
        // guest still expects all stdio fds to behave as terminal devices.
        let stream = if self.global.platform.is_a_tty(preferred) {
            preferred
        } else {
            [StdioStream::Stdin, StdioStream::Stdout, StdioStream::Stderr]
                .into_iter()
                .find(|s| self.global.platform.is_a_tty(*s))
                .ok_or(Errno::ENOTTY)?
        };

        match arg {
            IoctlArg::TCGETS(termios_ptr) => {
                let mut termios = litebox_common_linux::Termios {
                    c_iflag: 0,
                    c_oflag: 0,
                    c_cflag: 0,
                    c_lflag: 0,
                    c_line: 0,
                    c_cc: [0; 19],
                };
                let buf_ptr = core::ptr::from_mut(&mut termios).cast();
                self.global
                    .platform
                    .stdio_ioctl(stream, litebox_common_linux::TCGETS, buf_ptr)
                    .map_err(|_| Errno::ENOTTY)?;
                termios_ptr
                    .write_at_offset(0, termios)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TCSETS(termios_ptr) => {
                let termios = termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let buf_ptr = core::ptr::from_ref(&termios).cast_mut().cast();
                self.global
                    .platform
                    .stdio_ioctl(stream, litebox_common_linux::TCSETS, buf_ptr)
                    .map_err(|e| match e {
                        StdioIoctlError::NotATerminal => Errno::ENOTTY,
                        _ => Errno::EIO,
                    })?;
                Ok(0)
            }
            IoctlArg::TCSETSW(termios_ptr) => {
                let termios = termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let buf_ptr = core::ptr::from_ref(&termios).cast_mut().cast();
                self.global
                    .platform
                    .stdio_ioctl(stream, litebox_common_linux::TCSETSW, buf_ptr)
                    .map_err(|e| match e {
                        StdioIoctlError::NotATerminal => Errno::ENOTTY,
                        _ => Errno::EIO,
                    })?;
                Ok(0)
            }
            IoctlArg::TCSETSF(termios_ptr) => {
                let termios = termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let buf_ptr = core::ptr::from_ref(&termios).cast_mut().cast();
                self.global
                    .platform
                    .stdio_ioctl(stream, litebox_common_linux::TCSETSF, buf_ptr)
                    .map_err(|e| match e {
                        StdioIoctlError::NotATerminal => Errno::ENOTTY,
                        _ => Errno::EIO,
                    })?;
                Ok(0)
            }
            IoctlArg::TIOCGWINSZ(ws_ptr) => {
                let mut ws = litebox_common_linux::Winsize {
                    row: 0,
                    col: 0,
                    xpixel: 0,
                    ypixel: 0,
                };
                let buf_ptr = core::ptr::from_mut(&mut ws).cast();
                self.global
                    .platform
                    .stdio_ioctl(stream, litebox_common_linux::TIOCGWINSZ, buf_ptr)
                    .map_err(|_| Errno::ENOTTY)?;
                ws_ptr.write_at_offset(0, ws).ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCSWINSZ(ws_ptr) => {
                let ws = ws_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let buf_ptr = core::ptr::from_ref(&ws).cast_mut().cast();
                self.global
                    .platform
                    .stdio_ioctl(stream, litebox_common_linux::TIOCSWINSZ, buf_ptr)
                    .map_err(|e| match e {
                        StdioIoctlError::NotATerminal => Errno::ENOTTY,
                        _ => Errno::EIO,
                    })?;
                Ok(0)
            }
            IoctlArg::TIOCGPGRP(pgrp) => {
                // Return the calling process's PID as the foreground process group.
                pgrp.write_at_offset(0, self.sys_getpid())
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            // These are no-ops for stdio: TIOCSCTTY (already controlling terminal),
            // TIOCNOTTY (detach), TIOCSPGRP (set foreground pgrp), TIOCSPTLK (unlock PTY).
            IoctlArg::TIOCSCTTY
            | IoctlArg::TIOCNOTTY
            | IoctlArg::TIOCSPGRP(_)
            | IoctlArg::TIOCSPTLK(_) => Ok(0),
            _ => Err(Errno::ENOTTY),
        }
    }

    /// Handle terminal ioctls for PTY slave devices (major=136).
    fn pty_ioctl(
        &self,
        fs: &FS,
        fd: &TypedFd<FS>,
        arg: &IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        match arg {
            IoctlArg::TCGETS(termios) => {
                // Return stored terminal attributes for this PTY.
                let stored = fs.get_pty_termios(fd).ok_or(Errno::ENOTTY)?;
                termios
                    .write_at_offset(
                        0,
                        litebox_common_linux::Termios {
                            c_iflag: stored.c_iflag,
                            c_oflag: stored.c_oflag,
                            c_cflag: stored.c_cflag,
                            c_lflag: stored.c_lflag,
                            c_line: 0,
                            c_cc: stored.c_cc,
                        },
                    )
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TCSETS(termios_ptr)
            | IoctlArg::TCSETSW(termios_ptr)
            | IoctlArg::TCSETSF(termios_ptr) => {
                // Store the terminal attributes so future TCGETS and line
                // discipline behaviour reflect what the application configured.
                let t: litebox_common_linux::Termios =
                    termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let stored = litebox::fs::devices::PtyTermios {
                    c_iflag: t.c_iflag,
                    c_oflag: t.c_oflag,
                    c_cflag: t.c_cflag,
                    c_lflag: t.c_lflag,
                    c_cc: t.c_cc,
                };
                if !fs.set_pty_termios(fd, stored) {
                    return Err(Errno::ENOTTY);
                }
                Ok(0)
            }
            IoctlArg::TIOCSWINSZ(_)
            | IoctlArg::TIOCSPTLK(_)
            | IoctlArg::TIOCSCTTY
            | IoctlArg::TIOCNOTTY
            | IoctlArg::TIOCSPGRP(_) => Ok(0),
            IoctlArg::TIOCGWINSZ(ws) => {
                ws.write_at_offset(
                    0,
                    litebox_common_linux::Winsize {
                        row: 40,
                        col: 120,
                        xpixel: 0,
                        ypixel: 0,
                    },
                )
                .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCGPTN(ptn) => {
                let status = fs.fd_file_status(fd).map_err(|_| Errno::EBADF)?;
                let rdev = status.node_info.rdev.ok_or(Errno::ENOTTY)?;
                let major = rdev.get() >> 8;
                if major != 136 {
                    return Err(Errno::ENOTTY);
                }
                let minor = u32::try_from(rdev.get() & 0xFF).expect("minor fits in u32");
                ptn.write_at_offset(0, minor).ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCGPGRP(pgrp) => {
                pgrp.write_at_offset(0, self.sys_getpid())
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    /// Classify a file descriptor as a host stdio device, PTY device, or neither.
    fn classify_terminal(&self, fs: &FS, fd: &TypedFd<FS>) -> Result<TerminalKind, Errno> {
        match fs.fd_file_status(fd) {
            Ok(status) => {
                if status.file_type != litebox::fs::FileType::CharacterDevice {
                    return Ok(TerminalKind::NotTerminal);
                }
                let major = status.node_info.rdev.map_or(0, |v| v.get() >> 8);
                match major {
                    // major 5: /dev/tty, /dev/console, /dev/ptmx — host stdio
                    5 => Ok(TerminalKind::HostStdio),
                    // major 136-143: Unix98 PTY slaves (/dev/pts/*)
                    136..=143 => Ok(TerminalKind::Pty),
                    _ => Ok(TerminalKind::NotTerminal),
                }
            }
            Err(litebox::fs::errors::FileStatusError::ClosedFd) => Err(Errno::EBADF),
            Err(_) => unimplemented!(),
        }
    }

    /// Handle syscall `ioctl`
    pub fn sys_ioctl(
        &self,
        fd: i32,
        arg: IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
        match arg {
            IoctlArg::FIONREAD(out) => {
                // Return the number of bytes available to read.
                match desc {
                    Descriptor::LiteBoxRawFd(raw_fd) => {
                        files.run_on_raw_fd(
                            *raw_fd,
                            |_file_fd| {
                                // File/device fds: ENOTTY (not a supported operation).
                                Err(Errno::ENOTTY)
                            },
                            |socket_fd| {
                                let proxy = self.global.get_proxy(socket_fd)?;
                                let n = proxy.pending_rx_bytes();
                                let n = i32::try_from(n).unwrap_or(i32::MAX);
                                out.write_at_offset(0, n).ok_or(Errno::EFAULT)?;
                                Ok(0u32)
                            },
                            |pipe_fd| {
                                // Pipes: return actual buffered byte count.
                                let n = self
                                    .global
                                    .pipes
                                    .readable_bytes(pipe_fd)
                                    .map_err(|_| Errno::EBADF)?;
                                let n = i32::try_from(n).unwrap_or(i32::MAX);
                                out.write_at_offset(0, n).ok_or(Errno::EFAULT)?;
                                Ok(0u32)
                            },
                        )?
                    }
                    Descriptor::Eventfd { .. }
                    | Descriptor::Epoll { .. }
                    | Descriptor::Unix { .. } => Err(Errno::ENOTTY),
                }
            }
            IoctlArg::FIONBIO(arg) => {
                let val = arg.read_at_offset(0).ok_or(Errno::EFAULT)?;
                match desc {
                    Descriptor::LiteBoxRawFd(raw_fd) => {
                        self.files.borrow().run_on_raw_fd(
                            *raw_fd,
                            |_file_fd| {
                                // TODO: stdio NONBLOCK?
                                #[cfg(debug_assertions)]
                                litebox::log_println!(
                                    self.global.platform,
                                    "Attempted to set non-blocking on raw fd; currently unimplemented"
                                );
                                Ok(())
                            },
                            |socket_fd| {
                                if let Err(e) = self.global.litebox.descriptor_table_mut().with_metadata_mut(
                                    socket_fd,
                                    |crate::syscalls::net::SocketOFlags(flags)| {
                                        flags.set(OFlags::NONBLOCK, val != 0);
                                    },
                                ) {
                                    match e {
                                        MetadataError::ClosedFd => return Err(Errno::EBADF),
                                        MetadataError::NoSuchMetadata => unreachable!(),
                                    }
                                }
                                Ok(())
                            },
                            |fd| {
    self.global.pipes                                .update_flags(fd, litebox::pipes::Flags::NON_BLOCKING, val != 0)
                                    .map_err(Errno::from)
                            },
                        )
                        .flatten()?;
                    }
                    Descriptor::Eventfd { file, .. } => file.set_status(OFlags::NONBLOCK, val != 0),
                    Descriptor::Epoll { file, .. } => {
                        file.set_status(OFlags::NONBLOCK, val != 0);
                    }
                    Descriptor::Unix { file, .. } => {
                        file.set_status(OFlags::NONBLOCK, val != 0);
                    }
                }
                Ok(0)
            }
            IoctlArg::FIOCLEX => match desc {
                Descriptor::LiteBoxRawFd(raw_fd) => files.run_on_raw_fd(
                    *raw_fd,
                    |fd| {
                        let _old = self
                            .global
                            .litebox
                            .descriptor_table_mut()
                            .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                        Ok(0)
                    },
                    |_fd| todo!("net"),
                    |_fd| todo!("pipes"),
                )?,
                Descriptor::Eventfd { close_on_exec, .. }
                | Descriptor::Epoll { close_on_exec, .. }
                | Descriptor::Unix { close_on_exec, .. } => {
                    close_on_exec.store(true, core::sync::atomic::Ordering::Relaxed);
                    Ok(0)
                }
            },
            IoctlArg::FIONCLEX => match desc {
                Descriptor::LiteBoxRawFd(raw_fd) => files.run_on_raw_fd(
                    *raw_fd,
                    |fd| {
                        let _old = self
                            .global
                            .litebox
                            .descriptor_table_mut()
                            .set_fd_metadata(fd, FileDescriptorFlags::empty());
                        Ok(0)
                    },
                    |_fd| todo!("net"),
                    |_fd| todo!("pipes"),
                )?,
                Descriptor::Eventfd { close_on_exec, .. }
                | Descriptor::Epoll { close_on_exec, .. }
                | Descriptor::Unix { close_on_exec, .. } => {
                    close_on_exec.store(false, core::sync::atomic::Ordering::Relaxed);
                    Ok(0)
                }
            },
            IoctlArg::TIOCGPTPEER(open_flags) => {
                // TIOCGPTPEER: open the slave side of a PTY master, returning a new fd.
                // The argument contains O_RDWR|O_NOCTTY or similar open flags.
                match desc {
                    Descriptor::LiteBoxRawFd(raw_fd) => {
                        let source_raw_fd = *raw_fd;
                        let pty_idx = files.run_on_raw_fd(
                            source_raw_fd,
                            |file_fd| {
                                // Check the fd is a PTY master (major 136).
                                let status =
                                    files.fs.fd_file_status(file_fd).map_err(|_| Errno::EBADF)?;
                                let rdev = status.node_info.rdev.ok_or(Errno::ENOTTY)?;
                                let major = rdev.get() >> 8;
                                if major != 136 {
                                    return Err(Errno::ENOTTY);
                                }
                                Ok(rdev.get() & 0xFF)
                            },
                            |_| Err(Errno::ENOTTY),
                            |_| Err(Errno::ENOTTY),
                        )??;
                        // Drop the read lock before opening (which needs write access).
                        drop(locked_file_descriptors);
                        drop(files);
                        // Open the slave via the normal open path.
                        let slave_path = alloc::format!("/dev/pts/{pty_idx}");
                        let oflags =
                            OFlags::from_bits_truncate(u32::try_from(open_flags).unwrap_or(0));
                        let opened = self.sys_open(slave_path.as_str(), oflags, Mode::empty());
                        if let Ok(slave_fd) = opened {
                            litebox::log_println!(
                                self.global.platform,
                                "[PTY-PEER] pid={} src_fd={} src_raw_fd={} src_target=136:{} slave_fd={} slave_path={:?}",
                                self.pid,
                                fd,
                                source_raw_fd,
                                pty_idx,
                                slave_fd,
                                slave_path,
                            );
                        }
                        opened
                    }
                    _ => Err(Errno::ENOTTY),
                }
            }
            IoctlArg::TCGETS(..)
            | IoctlArg::TCSETS(..)
            | IoctlArg::TCSETSW(..)
            | IoctlArg::TCSETSF(..)
            | IoctlArg::TIOCGPTN(..)
            | IoctlArg::TIOCSPTLK(..)
            | IoctlArg::TIOCSCTTY
            | IoctlArg::TIOCNOTTY
            | IoctlArg::TIOCGPGRP(..)
            | IoctlArg::TIOCSPGRP(..)
            | IoctlArg::TIOCGWINSZ(..)
            | IoctlArg::TIOCSWINSZ(..) => match desc {
                Descriptor::LiteBoxRawFd(raw_fd) => files.run_on_raw_fd(
                    *raw_fd,
                    |term_fd| match self.classify_terminal(&files.fs, term_fd)? {
                        TerminalKind::HostStdio => self.host_stdio_ioctl(&files.fs, term_fd, &arg),
                        TerminalKind::Pty => self.pty_ioctl(&files.fs, term_fd, &arg),
                        TerminalKind::NotTerminal => Err(Errno::ENOTTY),
                    },
                    |_fd| Err(Errno::ENOTTY),
                    |_fd| Err(Errno::ENOTTY),
                )?,
                Descriptor::Eventfd { .. } | Descriptor::Epoll { .. } | Descriptor::Unix { .. } => {
                    Err(Errno::ENOTTY)
                }
            },
            _ => {
                // Return ENOTTY for unsupported ioctls rather than panicking.
                // Complex programs (e.g., bash) probe terminal capabilities and
                // handle ENOTTY gracefully.
                Err(Errno::ENOTTY)
            }
        }
    }

    /// Handle syscall `epoll_create` and `epoll_create1`
    pub fn sys_epoll_create(&self, flags: EpollCreateFlags) -> Result<u32, Errno> {
        if flags.contains(EpollCreateFlags::EPOLL_CLOEXEC.complement()) {
            return Err(Errno::EINVAL);
        }

        let epoll_file = super::epoll::EpollFile::new();
        let files = self.files.borrow();
        files
            .file_descriptors
            .write()
            .insert(
                self,
                Descriptor::Epoll {
                    file: alloc::sync::Arc::new(epoll_file),
                    close_on_exec: core::sync::atomic::AtomicBool::new(
                        flags.contains(EpollCreateFlags::EPOLL_CLOEXEC),
                    ),
                },
            )
            .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))
    }

    /// Handle syscall `epoll_ctl`
    pub(crate) fn sys_epoll_ctl(
        &self,
        epfd: i32,
        op: litebox_common_linux::EpollOp,
        fd: i32,
        event: ConstPtr<litebox_common_linux::EpollEvent>,
    ) -> Result<(), Errno> {
        let Ok(epfd) = u32::try_from(epfd) else {
            return Err(Errno::EBADF);
        };
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        if epfd == fd {
            return Err(Errno::EINVAL);
        }

        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let epoll_entry = locked_file_descriptors.get_fd(epfd).ok_or(Errno::EBADF)?;
        let Descriptor::Epoll { file: epoll, .. } = epoll_entry else {
            return Err(Errno::EBADF);
        };

        let file = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
        let file_descriptor = super::epoll::EpollDescriptor::try_from(&files, file)?;
        let event = if op == litebox_common_linux::EpollOp::EpollCtlDel {
            None
        } else {
            Some(event.read_at_offset(0).ok_or(Errno::EFAULT)?)
        };
        epoll.epoll_ctl(&self.global, &*files.fs, op, fd, &file_descriptor, event)?;
        Ok(())
    }

    /// Handle syscall `epoll_pwait`
    pub fn sys_epoll_pwait(
        &self,
        epfd: i32,
        events: MutPtr<litebox_common_linux::EpollEvent>,
        maxevents: u32,
        timeout: i32,
        sigmask: Option<ConstPtr<litebox_common_linux::signal::SigSet>>,
        _sigsetsize: usize,
    ) -> Result<usize, Errno> {
        // Save the current signal mask and apply the caller's mask for the
        // duration of the wait.  This is the core semantics of epoll_pwait:
        // atomically { set sigmask; wait; restore sigmask }.
        //
        // The mask restore is DEFERRED via `set_restore_mask` so that
        // `process_signals()` (called by `prepare_to_run_guest`) can deliver
        // newly-unblocked signals (e.g. SIGCHLD) before re-blocking them.
        let saved_mask = if let Some(mask_ptr) = sigmask {
            let new_mask = mask_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let old = self.signals.get_blocked();
            self.signals.set_blocked(new_mask);
            Some(old)
        } else {
            None
        };

        let Ok(epfd) = u32::try_from(epfd) else {
            if let Some(old) = saved_mask {
                self.signals.set_blocked(old);
            }
            return Err(Errno::EBADF);
        };
        let maxevents = maxevents as usize;
        if maxevents == 0
            || maxevents > i32::MAX as usize / size_of::<litebox_common_linux::EpollEvent>()
        {
            if let Some(old) = saved_mask {
                self.signals.set_blocked(old);
            }
            return Err(Errno::EINVAL);
        }
        let timeout = if timeout >= 0 {
            #[allow(clippy::cast_sign_loss, reason = "timeout is a positive integer")]
            Some(core::time::Duration::from_millis(timeout as u64))
        } else {
            None
        };
        let epoll_file = {
            let files = self.files.borrow();
            let locked_file_descriptors = files.file_descriptors.read();
            if let Some(Descriptor::Epoll { file, .. }) = locked_file_descriptors.get_fd(epfd) {
                file.clone()
            } else {
                if let Some(old) = saved_mask {
                    self.signals.set_blocked(old);
                }
                return Err(Errno::EBADF);
            }
        };
        let result = match epoll_file.wait(
            &self.global,
            &*self.files.borrow().fs,
            &self.wait_cx().with_timeout(timeout),
            maxevents,
        ) {
            Ok(epoll_events) => {
                if !epoll_events.is_empty() {
                    events
                        .copy_from_slice(0, &epoll_events)
                        .ok_or(Errno::EFAULT)?;
                }
                Ok(epoll_events.len())
            }
            Err(WaitError::TimedOut) => Ok(0),
            Err(WaitError::Interrupted) => Err(Errno::EINTR),
        };

        // Defer mask restore to process_signals() so that signals unblocked
        // by the caller's mask (like SIGCHLD) are delivered before the
        // original mask is reinstated.
        if let Some(old) = saved_mask {
            self.signals.set_restore_mask(old);
        }

        result
    }

    /// Handle syscall `ppoll`.
    pub fn sys_ppoll(
        &self,
        fds: MutPtr<litebox_common_linux::Pollfd>,
        nfds: usize,
        timeout: TimeParam<Platform>,
        sigmask: Option<ConstPtr<litebox_common_linux::signal::SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        // Save and apply the caller's signal mask for the duration of the wait,
        // matching ppoll(2) semantics.
        let saved_mask = if let Some(mask_ptr) = sigmask {
            if sigsetsize != core::mem::size_of::<litebox_common_linux::signal::SigSet>() {
                return Err(Errno::EINVAL);
            }
            let new_mask = mask_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let old = self.signals.get_blocked();
            self.signals.set_blocked(new_mask);
            Some(old)
        } else {
            None
        };
        let timeout = timeout.read()?;
        let nfds_signed = isize::try_from(nfds).map_err(|_| {
            if let Some(old) = saved_mask {
                self.signals.set_blocked(old);
            }
            Errno::EINVAL
        })?;

        let mut set = super::epoll::PollSet::with_capacity(nfds);
        for i in 0..nfds_signed {
            let fd = fds.read_at_offset(i).ok_or_else(|| {
                if let Some(old) = saved_mask {
                    self.signals.set_blocked(old);
                }
                Errno::EFAULT
            })?;

            let events = litebox::event::Events::from_bits_truncate(
                fd.events.reinterpret_as_unsigned().into(),
            );
            set.add_fd(fd.fd, events);
        }

        match set.wait(
            &self.global,
            &self.wait_cx().with_timeout(timeout),
            &self.files.borrow(),
        ) {
            Ok(()) => {}
            Err(WaitError::Interrupted) => {
                // Defer mask restore for process_signals.
                if let Some(old) = saved_mask {
                    self.signals.set_restore_mask(old);
                }
                // TODO: update the remaining time.
                return Err(Errno::EINTR);
            }
            Err(WaitError::TimedOut) => {
                // A timeout occurred. Scan one last time.
                set.scan(&self.global, &self.files.borrow());
            }
        }

        // Defer mask restore for process_signals.
        if let Some(old) = saved_mask {
            self.signals.set_restore_mask(old);
        }

        // Write just the revents back.
        let fds_base_addr = fds.as_usize();
        let mut ready_count = 0;
        for (i, revents) in set.revents().enumerate() {
            // TODO: This is not great from a provenance perspective. Consider
            // adding cast+add methods to ConstPtr/MutPtr.
            let fd_addr = fds_base_addr + i * core::mem::size_of::<litebox_common_linux::Pollfd>();
            let revents_ptr = crate::MutPtr::<i16>::from_usize(
                fd_addr + core::mem::offset_of!(litebox_common_linux::Pollfd, revents),
            );
            let revents: u16 = revents.bits().truncate();
            revents_ptr
                .write_at_offset(0, revents.reinterpret_as_signed())
                .ok_or(Errno::EFAULT)?;
            if revents != 0 {
                ready_count += 1;
            }
        }
        Ok(ready_count)
    }

    pub(crate) fn do_pselect(
        &self,
        nfds: u32,
        readfds: Option<&mut bitvec::vec::BitVec>,
        writefds: Option<&mut bitvec::vec::BitVec>,
        exceptfds: Option<&mut bitvec::vec::BitVec>,
        timeout: Option<core::time::Duration>,
    ) -> Result<usize, Errno> {
        let file_table_len = self.files.borrow().file_descriptors.read().len();
        let mut set = super::epoll::PollSet::with_capacity(nfds as usize);
        for i in 0..nfds {
            let mut events = litebox::event::Events::empty();
            if readfds.as_ref().is_some_and(|set| set[i as usize]) {
                events |= litebox::event::Events::IN;
            }
            if writefds.as_ref().is_some_and(|set| set[i as usize]) {
                events |= litebox::event::Events::OUT;
            }
            if exceptfds.as_ref().is_some_and(|set| set[i as usize]) {
                events |= litebox::event::Events::PRI;
            }
            if !events.is_empty() {
                if i as usize >= file_table_len {
                    return Err(Errno::EBADF);
                }
                set.add_fd(i.reinterpret_as_signed(), events);
            }
        }

        match set.wait(
            &self.global,
            &self.wait_cx().with_timeout(timeout),
            &self.files.borrow(),
        ) {
            Ok(()) => {}
            Err(WaitError::Interrupted) => {
                // TODO: update the remaining time.
                return Err(Errno::EINTR);
            }
            Err(WaitError::TimedOut) => {
                // A timeout occurred. Scan one last time.
                set.scan(&self.global, &self.files.borrow());
            }
        }

        let mut ready_count = 0;
        let mut process_fdset =
            |fds: Option<&mut bitvec::vec::BitVec>, target_events: Events| -> Result<(), Errno> {
                if let Some(fds) = fds {
                    fds.fill(false);
                    for (i, revents) in set.revents_with_fds() {
                        if revents.contains(Events::NVAL) {
                            return Err(Errno::EBADF);
                        }
                        if revents.intersects(target_events) {
                            // no negative fds added to the set
                            fds.set(i.reinterpret_as_unsigned() as usize, true);
                            ready_count += 1;
                        }
                    }
                }
                Ok(())
            };
        process_fdset(readfds, Events::IN | Events::ALWAYS_POLLED)?;
        process_fdset(writefds, Events::OUT | Events::ALWAYS_POLLED)?;
        process_fdset(exceptfds, Events::PRI)?;
        Ok(ready_count)
    }

    /// Handle syscall `pselect`.
    pub(crate) fn sys_pselect(
        &self,
        nfds: u32,
        readfds: Option<MutPtr<usize>>,
        writefds: Option<MutPtr<usize>>,
        exceptfds: Option<MutPtr<usize>>,
        timeout: TimeParam<Platform>,
        sigsetpack: Option<ConstPtr<litebox_common_linux::SigSetPack>>,
    ) -> Result<usize, Errno> {
        // Save the current signal mask and apply the caller's mask for the
        // duration of the wait (same semantics as epoll_pwait / ppoll).
        //
        // pselect6 passes a pointer to {sigset_t *ss, size_t ss_len} where
        // ss is itself a pointer to the actual signal mask.
        let saved_mask = if let Some(pack_ptr) = sigsetpack {
            let pack: litebox_common_linux::SigSetPack =
                pack_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            if pack.size != core::mem::size_of::<litebox_common_linux::signal::SigSet>() {
                return Err(Errno::EINVAL);
            }
            // pack.sigset is actually a pointer to the sigset (the u64 holds
            // the guest address). Dereference it to read the actual mask.
            let sigset_ptr = crate::ConstPtr::<litebox_common_linux::signal::SigSet>::from_usize(
                pack.sigset.as_u64().truncate(),
            );
            let new_mask = sigset_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let old = self.signals.get_blocked();
            self.signals.set_blocked(new_mask);
            Some(old)
        } else {
            None
        };

        let timeout = timeout.read()?;
        if nfds >= i32::MAX as u32
            || nfds as usize
                > self
                    .process()
                    .limits
                    .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE)
        {
            if let Some(old) = saved_mask {
                self.signals.set_blocked(old);
            }
            return Err(Errno::EINVAL);
        }
        let len = (nfds as usize).div_ceil(core::mem::size_of::<usize>() * 8);
        let mut kreadfds = readfds
            .map(|fds| fds.to_owned_slice(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));
        let mut kwritefds = writefds
            .map(|fds| fds.to_owned_slice(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));
        let mut kexceptfds = exceptfds
            .map(|fds| fds.to_owned_slice(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));

        let count = self.do_pselect(
            nfds,
            kreadfds.as_mut(),
            kwritefds.as_mut(),
            kexceptfds.as_mut(),
            timeout,
        );

        // Defer mask restore so signals unblocked by the caller's mask are
        // delivered before the original mask is reinstated.
        if let Some(old) = saved_mask {
            self.signals.set_restore_mask(old);
        }

        let count = count?;

        if let Some(fds) = kreadfds {
            readfds
                .unwrap()
                .write_slice_at_offset(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(fds) = kwritefds {
            writefds
                .unwrap()
                .write_slice_at_offset(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(fds) = kexceptfds {
            exceptfds
                .unwrap()
                .write_slice_at_offset(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }

        Ok(count)
    }

    fn do_dup(&self, file: &Descriptor<FS>, flags: OFlags) -> Result<Descriptor<FS>, Errno> {
        let close_on_exec = flags.contains(OFlags::CLOEXEC);
        let files = self.files.borrow();
        match file {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                fn dup<FS: ShimFS, S: FdEnabledSubsystem>(
                    global: &GlobalState<FS>,
                    files: &FilesState<FS>,
                    fd: &TypedFd<S>,
                    close_on_exec: bool,
                ) -> Result<Descriptor<FS>, Errno> {
                    let mut dt = global.litebox.descriptor_table_mut();
                    let fd: TypedFd<_> = dt.duplicate(fd).ok_or(Errno::EBADF)?;
                    if close_on_exec {
                        let old = dt.set_fd_metadata(&fd, FileDescriptorFlags::FD_CLOEXEC);
                        assert!(old.is_none());
                    }
                    Ok(Descriptor::LiteBoxRawFd(
                        files.raw_descriptor_store.write().fd_into_raw_integer(fd),
                    ))
                }
                files.run_on_raw_fd(
                    *raw_fd,
                    |fd| dup(&self.global, &files, fd, close_on_exec),
                    |fd| dup(&self.global, &files, fd, close_on_exec),
                    |fd| dup(&self.global, &files, fd, close_on_exec),
                )?
            }
            Descriptor::Eventfd { file, .. } => Ok(Descriptor::Eventfd {
                file: file.clone(),
                close_on_exec: core::sync::atomic::AtomicBool::new(close_on_exec),
            }),
            Descriptor::Epoll { file, .. } => Ok(Descriptor::Epoll {
                file: file.clone(),
                close_on_exec: core::sync::atomic::AtomicBool::new(close_on_exec),
            }),
            Descriptor::Unix { file, .. } => Ok(Descriptor::Unix {
                file: file.clone(),
                close_on_exec: core::sync::atomic::AtomicBool::new(close_on_exec),
            }),
        }
    }

    /// Handle syscall `dup/dup2/dup3`
    ///
    /// The dup() system call creates a copy of the file descriptor oldfd, using the lowest-numbered unused file descriptor for the new descriptor.
    /// The dup2() system call performs the same task as dup(), but instead of using the lowest-numbered unused file descriptor, it uses the file descriptor number specified in newfd.
    /// The dup3() system call is similar to dup2(), but it also takes an additional flags argument that can be used to set the close-on-exec flag for the new file descriptor.
    pub fn sys_dup(
        &self,
        oldfd: i32,
        newfd: Option<i32>,
        flags: Option<OFlags>,
    ) -> Result<u32, Errno> {
        let Ok(oldfd) = u32::try_from(oldfd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();

        if let Some(newfd_val) = newfd {
            let Ok(newfd) = u32::try_from(newfd_val) else {
                return Err(Errno::EBADF);
            };
            if oldfd == newfd {
                // dup3(fd, fd) always returns EINVAL per POSIX.
                if flags.is_some() {
                    return Err(Errno::EINVAL);
                }
                // dup2(fd, fd): verify fd is valid, then clear CLOEXEC.
                //
                // POSIX says dup2(fd, fd) "does nothing", but libuv relies on
                // inherited stdio fds surviving exec even though the parent
                // sets CLOEXEC. Clearing CLOEXEC here matches the intent of
                // the dup2 caller (set up this fd for the child) and prevents
                // close-on-exec from closing stdio fds after exec.
                let fds = files.file_descriptors.read();
                let desc = fds.get_fd(oldfd).ok_or(Errno::EBADF)?;
                desc.set_file_descriptor_flags(&self.global, &files, FileDescriptorFlags::empty())?;
                return Ok(oldfd);
            }
        }

        let new_file = files
            .file_descriptors
            .read()
            .get_fd(oldfd)
            .ok_or(Errno::EBADF)
            .map(|desc| self.do_dup(desc, flags.unwrap_or(OFlags::empty())))??;
        let result = if let Some(newfd_val) = newfd {
            let newfd = u32::try_from(newfd_val).unwrap(); // already validated above
            match files
                .file_descriptors
                .write()
                .insert_at(self, new_file, newfd as usize)
            {
                Ok(old_file) => {
                    // replace an existing file descriptor
                    if let Some(old_file) = old_file {
                        self.do_close(old_file)?;
                    }
                    Ok(newfd)
                }
                Err(new_file) => {
                    // failed to insert due to file limit
                    Err(self.do_close(new_file).err().unwrap_or(Errno::EMFILE))
                }
            }
        } else {
            // dup
            files
                .file_descriptors
                .write()
                .insert(self, new_file)
                .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))
        };

        if let Ok(newfd) = result {
            self.maybe_trace_pty_dup(oldfd, newfd);
        }

        result
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Diroff(usize);

const DIRENT_STRUCT_BYTES_WITHOUT_NAME: usize =
    core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `getdents64`
    pub(crate) fn sys_getdirent64(
        &self,
        fd: i32,
        dirp: MutPtr<u8>,
        count: usize,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let Descriptor::LiteBoxRawFd(raw_fd) =
            locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?
        else {
            return Err(Errno::EBADF);
        };
        files.run_on_raw_fd(
            *raw_fd,
            |file| {
                let dir_off: Diroff = self
                    .global
                    .litebox
                    .descriptor_table()
                    .with_metadata(file, |off: &Diroff| *off)
                    .unwrap_or_default();
                let mut dir_off = dir_off.0;
                let mut nbytes = 0;

                let mut entries = files.fs.read_dir(file)?;
                entries.sort_by(|a, b| a.name.cmp(&b.name));

                // Buffer all dirent64 entries into a kernel-side Vec<u8> before
                // writing to guest memory. This allows us to insert a single
                // park checkpoint (for deferred vfork parking) before the guest
                // write, rather than scattering them across every entry.
                let mut kernel_buf = alloc::vec::Vec::<u8>::with_capacity(count.min(4096));

                for entry in entries.iter().skip(dir_off) {
                    // include null terminator and make it aligned
                    let len = (DIRENT_STRUCT_BYTES_WITHOUT_NAME + entry.name.len() + 1)
                        .next_multiple_of(align_of::<litebox_common_linux::LinuxDirent64>());
                    if nbytes + len > count {
                        // not enough space
                        break;
                    }
                    let dirent64 = litebox_common_linux::LinuxDirent64 {
                        ino: entry.ino_info.as_ref().map_or(0, |node_info| node_info.ino) as u64,
                        off: dir_off as u64,
                        len: len.truncate(),
                        typ: litebox_common_linux::DirentType::from(entry.file_type.clone()) as u8,
                        __name: [0; 0],
                    };

                    // Append the dirent64 header as raw bytes.
                    let hdr_bytes: &[u8] = unsafe {
                        // SAFETY: LinuxDirent64 is repr(C) and all bit patterns
                        // from the initialized fields are valid. We read
                        // exactly `size_of::<LinuxDirent64>()` bytes from a
                        // properly aligned struct.
                        core::slice::from_raw_parts(
                            (&raw const dirent64).cast::<u8>(),
                            core::mem::size_of::<litebox_common_linux::LinuxDirent64>(),
                        )
                    };
                    kernel_buf.extend_from_slice(hdr_bytes);
                    // Pad to DIRENT_STRUCT_BYTES_WITHOUT_NAME (covers the
                    // __name[0] flexible array member offset).
                    let hdr_size = core::mem::size_of::<litebox_common_linux::LinuxDirent64>();
                    if hdr_size < DIRENT_STRUCT_BYTES_WITHOUT_NAME {
                        kernel_buf.extend(core::iter::repeat_n(
                            0u8,
                            DIRENT_STRUCT_BYTES_WITHOUT_NAME - hdr_size,
                        ));
                    }
                    // Append the name.
                    kernel_buf.extend_from_slice(entry.name.as_bytes());
                    // Null terminator + padding.
                    let zeros_len = len - (DIRENT_STRUCT_BYTES_WITHOUT_NAME + entry.name.len());
                    kernel_buf.extend(core::iter::repeat_n(0u8, zeros_len));

                    nbytes += len;
                    dir_off += 1;
                }

                // Park checkpoint: block for deferred vfork before guest write.
                self.park_if_deferred();

                // Single bulk write to guest memory.
                if nbytes > 0 {
                    dirp.copy_from_slice(0, &kernel_buf[..nbytes])
                        .ok_or(Errno::EFAULT)?;
                }

                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(file, Diroff(dir_off));
                Ok(nbytes)
            },
            |_fd| todo!("net"),
            |_fd| todo!("pipes"),
        )?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use litebox::fs::Mode;

    extern crate std;

    #[test]
    fn fspath_new() {
        // Absolute paths should never invoke the get_cwd closure.
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "/usr/bin", || {
            panic!("get_cwd should not be called for absolute paths")
        })
        .unwrap();
        assert!(matches!(fp, FsPath::Absolute { path } if path.to_str().unwrap() == "/usr/bin"));

        // Relative path resolves against CWD.
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "foo/bar", || {
            String::from("/home/")
        })
        .unwrap();
        assert!(
            matches!(fp, FsPath::Absolute { path } if path.to_str().unwrap() == "/home/foo/bar")
        );

        // Empty path at AT_FDCWD → Cwd variant.
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "", || {
            panic!("get_cwd should not be called for empty Cwd path")
        })
        .unwrap();
        assert!(matches!(fp, FsPath::Cwd));

        // Positive fd + empty path → Fd variant.
        let fp = FsPath::new(5, "", || panic!("should not be called")).unwrap();
        assert!(matches!(fp, FsPath::Fd(5)));

        // Invalid dirfd → EBADF.
        let err = FsPath::new(-1, "file.txt", || panic!("should not be called")).unwrap_err();
        assert_eq!(err, Errno::EBADF);

        // Path exceeding PATH_MAX → ENAMETOOLONG.
        let long_path = "a".repeat(PATH_MAX + 1);
        let err = FsPath::new(litebox_common_linux::AT_FDCWD, long_path.as_str(), || {
            String::from("/")
        })
        .unwrap_err();
        assert_eq!(err, Errno::ENAMETOOLONG);
    }

    #[test]
    fn getcwd_and_chdir() {
        let task = crate::syscalls::tests::init_platform(None);

        // Default CWD is root.
        let mut buf = [0u8; 256];
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap(); // strip NUL
        assert_eq!(cwd, "/");

        // chdir + getcwd round trip.
        task.sys_mkdir("/test_chdir_dir", 0o777).unwrap();
        task.sys_chdir("/test_chdir_dir").unwrap();
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap();
        assert_eq!(cwd, "/test_chdir_dir/");

        // chdir to nonexistent path → ENOENT.
        assert_eq!(
            task.sys_chdir("/does_not_exist").unwrap_err(),
            Errno::ENOENT
        );

        // chdir to a regular file → ENOTDIR.
        let fd = task
            .sys_open(
                "/test_chdir_file",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let _ = task.sys_close(i32::try_from(fd).unwrap());
        assert_eq!(
            task.sys_chdir("/test_chdir_file").unwrap_err(),
            Errno::ENOTDIR
        );

        // getcwd with too-small buffer → ERANGE.
        let mut tiny = [0u8; 1];
        assert_eq!(task.sys_getcwd(&mut tiny).unwrap_err(), Errno::ERANGE);
    }

    #[test]
    fn chdir_relative_path() {
        let task = crate::syscalls::tests::init_platform(None);

        // Create nested dirs: /rel_parent/rel_child
        task.sys_mkdir("/rel_parent", 0o777).unwrap();
        task.sys_mkdir("/rel_parent/rel_child", 0o777).unwrap();

        // chdir to /rel_parent first, then relative chdir into child.
        task.sys_chdir("/rel_parent").unwrap();
        task.sys_chdir("rel_child").unwrap();

        let mut buf = [0u8; 256];
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap();
        assert_eq!(cwd, "/rel_parent/rel_child/");

        // chdir("..") should normalize back to /rel_parent/.
        task.sys_chdir("..").unwrap();
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap();
        assert_eq!(cwd, "/rel_parent/");
    }

    /// Verify every path-taking syscall resolves relative paths after `chdir`.
    #[test]
    fn all_path_syscalls_respect_chdir() {
        use litebox_common_linux::{AccessFlags, AtFlags};

        let task = crate::syscalls::tests::init_platform(None);

        // Set up: mkdir + chdir into /cwd_test/.
        task.sys_mkdir("/cwd_test", 0o777).unwrap();
        task.sys_chdir("/cwd_test").unwrap();

        // ── sys_open: create a file via relative path ──
        let fd = task
            .sys_open(
                "file.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();

        // ── sys_stat: stat the relative file ──
        task.sys_stat("file.txt").unwrap();

        // ── sys_lstat: lstat the relative file ──
        task.sys_lstat("file.txt").unwrap();

        // ── sys_access: check relative file is accessible ──
        task.sys_access("file.txt", AccessFlags::F_OK).unwrap();

        // ── sys_mkdir: create a subdirectory via relative path ──
        task.sys_mkdir("subdir", 0o777).unwrap();
        task.sys_stat("/cwd_test/subdir").unwrap(); // verify via absolute

        // ── sys_openat (AT_FDCWD + relative): open inside the new subdir ──
        let fd = task
            .sys_openat(
                litebox_common_linux::AT_FDCWD,
                "subdir/inner.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();

        // ── sys_newfstatat (AT_FDCWD + relative) ──
        task.sys_newfstatat(
            litebox_common_linux::AT_FDCWD,
            "subdir/inner.txt",
            AtFlags::empty(),
        )
        .unwrap();

        // ── sys_unlinkat: remove a file via relative path ──
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "subdir/inner.txt",
            AtFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            task.sys_stat("/cwd_test/subdir/inner.txt").unwrap_err(),
            Errno::ENOENT
        );

        // ── sys_unlinkat (AT_REMOVEDIR): remove directory via relative path ──
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "subdir",
            AtFlags::AT_REMOVEDIR,
        )
        .unwrap();
        assert_eq!(
            task.sys_stat("/cwd_test/subdir").unwrap_err(),
            Errno::ENOENT
        );
    }
}
