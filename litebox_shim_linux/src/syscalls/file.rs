// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of file related syscalls, e.g., `open`, `read`, `write`, etc.

use alloc::{
    collections::BTreeMap,
    ffi::CString,
    string::{String, ToString as _},
    sync::Arc,
    vec,
    vec::Vec,
};
use litebox::{
    event::{Events, wait::WaitError},
    fd::{ErrRawIntFd, FdEnabledSubsystem, MetadataError, TypedFd},
    fs::{Mode, OFlags, SeekWhence},
    path,
    platform::{RawConstPointer, RawMutPointer, StdioProvider as _},
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _},
};
use litebox_common_linux::{
    AtFlags, ClockId, EfdFlags, EpollCreateFlags, FcntlArg, FileDescriptorFlags, FileStat,
    IoReadVec, IoWriteVec, IoctlArg, ItimerSpec, STATX_BASIC_STATS, StatfsBuf, StatxBuf,
    StatxTimestamp, TMPFS_MAGIC, TimeParam, TimerfdFlags, TimerfdTimerFlags, errno::Errno,
};
use litebox_platform_multiplex::Platform;

use crate::syscalls::signal::siginfo_kernel;
use crate::{ConstPtr, GlobalState, MutPtr, ShimFS, Task};
use core::sync::atomic::{AtomicUsize, Ordering};

fn host_stdio_source_for_path(path: &str) -> Option<i32> {
    match path {
        "/dev/stdin" => Some(0),
        "/dev/stdout" => Some(1),
        "/dev/stderr" => Some(2),
        _ => None,
    }
}

fn is_host_tty_path(path: &str) -> bool {
    path == "/dev/tty"
}

/// Check if a path matches the host's actual PTY device path (e.g., `/dev/pts/156`).
fn is_host_pty_device_path(path: &str, platform: &litebox_platform_multiplex::Platform) -> bool {
    platform
        .host_stdin_tty_device_info()
        .is_some_and(|info| path == info.path)
}

/// Synthetic device IDs for anonymous descriptor pseudo-filesystems,
/// mirroring the Linux kernel's `sockfs`, `pipefs`, and `anon_inodefs`.
const SOCKFS_DEV: u64 = 0x000c;
const PIPEFS_DEV: u64 = 0x000d;
const ANON_INODE_DEV: u64 = 0x000e;

/// Marker metadata attached to fds opened via the host PTY device path
/// (e.g., `/dev/pts/156`). Causes the shim's `descriptor_stat()` to override
/// `st_dev`, `st_ino`, and `st_rdev` with the real host PTY identity so that
/// `fstat(reopened_fd)` is consistent with `fstat(0)`.
#[derive(Clone)]
struct HostPtyDeviceFd;

/// Monotonically increasing counter for unique inode numbers assigned to
/// anonymous file descriptors (sockets, pipes, eventfds, epoll instances).
static ANON_INO_COUNTER: AtomicUsize = AtomicUsize::new(1);

/// Fixed inode for the `/proc/self/exe` symlink so that repeated `lstat`
/// calls return a stable identity.
static PROC_SELF_EXE_INO: AtomicUsize = AtomicUsize::new(0);

/// Stable inode number stored as entry metadata on anonymous descriptors.
/// Assigned once on first stat and reused for the lifetime of the open file
/// description (including across `dup`).
#[derive(Clone)]
struct AnonIno(u64);

/// Classification of a file descriptor for terminal ioctl routing.
enum TerminalKind {
    /// Host stdio device (major=5) — forward ioctls to host kernel.
    HostStdio,
    /// PTY slave device (major=136) — handle locally.
    Pty,
    /// Not a terminal device.
    NotTerminal,
}

struct InotifyInstanceState {
    next_watch_descriptor: i32,
    watches: BTreeMap<i32, String>,
}

impl InotifyInstanceState {
    fn new() -> Self {
        Self {
            next_watch_descriptor: 1,
            watches: BTreeMap::new(),
        }
    }

    fn add_watch(&mut self, path: String) -> Result<i32, Errno> {
        let wd = self.next_watch_descriptor;
        self.next_watch_descriptor = self
            .next_watch_descriptor
            .checked_add(1)
            .ok_or(Errno::ENOMEM)?;
        self.watches.insert(wd, path);
        Ok(wd)
    }

    fn remove_watch(&mut self, wd: i32) -> Result<(), Errno> {
        if wd <= 0 {
            return Err(Errno::EINVAL);
        }
        self.watches.remove(&wd).map(|_| ()).ok_or(Errno::EINVAL)
    }
}

/// Task state shared by `CLONE_FS`.
pub(crate) struct FsState {
    umask: core::sync::atomic::AtomicU32,
    /// The current working directory
    ///
    /// Must end with a '/'.
    cwd: litebox::sync::RwLock<Platform, String>,
    /// The path of the current executable (for `/proc/self/exe`).
    pub(crate) exe_path: litebox::sync::RwLock<Platform, String>,
}

impl Clone for FsState {
    fn clone(&self) -> Self {
        Self {
            umask: self.umask.load(Ordering::Relaxed).into(),
            cwd: litebox::sync::RwLock::new(self.cwd.read().clone()),
            exe_path: litebox::sync::RwLock::new(self.exe_path.read().clone()),
        }
    }
}

impl FsState {
    pub fn new() -> Self {
        Self {
            umask: (Mode::WGRP | Mode::WOTH).bits().into(),
            cwd: litebox::sync::RwLock::new(String::from("/")),
            exe_path: litebox::sync::RwLock::new(String::new()),
        }
    }

    /// Create a new `FsState` with a custom initial working directory.
    ///
    /// The `cwd` must be an absolute path. A trailing '/' is appended if missing.
    #[allow(dead_code)] // used by runner (deferred)
    pub fn with_cwd(mut cwd: String) -> Self {
        assert!(cwd.starts_with('/'), "initial CWD must be absolute");
        if !cwd.ends_with('/') {
            cwd.push('/');
        }
        Self {
            umask: (Mode::WGRP | Mode::WOTH).bits().into(),
            cwd: litebox::sync::RwLock::new(cwd),
            exe_path: litebox::sync::RwLock::new(String::new()),
        }
    }

    fn umask(&self) -> Mode {
        Mode::from_bits_retain(self.umask.load(Ordering::Relaxed))
    }

    /// Returns the current working directory path.
    #[allow(dead_code)] // used by runner (deferred)
    pub(crate) fn current_working_directory(&self) -> String {
        self.cwd.read().clone()
    }
}

/// Task state shared by `CLONE_FILES`.
pub(crate) struct FilesState<FS: ShimFS> {
    /// The filesystem implementation, shared across tasks that share file system.
    pub(crate) fs: alloc::sync::Arc<FS>,
    pub(crate) raw_descriptor_store:
        litebox::sync::RwLock<Platform, litebox::fd::RawDescriptorStorage>,
    file_position_lock: alloc::sync::Arc<litebox::sync::Mutex<Platform, ()>>,
    inotify_instances: litebox::sync::Mutex<
        Platform,
        BTreeMap<usize, Arc<litebox::sync::Mutex<Platform, InotifyInstanceState>>>,
    >,
    max_fd: AtomicUsize,
}

impl<FS: ShimFS> FilesState<FS> {
    pub(crate) fn new(fs: alloc::sync::Arc<FS>) -> Self {
        Self {
            fs,
            raw_descriptor_store: litebox::sync::RwLock::new(
                litebox::fd::RawDescriptorStorage::new(),
            ),
            file_position_lock: Arc::new(litebox::sync::Mutex::new(())),
            inotify_instances: litebox::sync::Mutex::new(BTreeMap::new()),
            max_fd: AtomicUsize::new(usize::MAX),
        }
    }

    pub(crate) fn set_max_fd(&self, max_fd: usize) {
        self.max_fd.store(max_fd, Ordering::Relaxed);
    }

    // Returns Ok(raw_fd) if it fits within the max limits already set up; otherwise returns the
    // Err(typed_fd)
    pub(crate) fn insert_raw_fd<Subsystem: FdEnabledSubsystem>(
        &self,
        typed_fd: TypedFd<Subsystem>,
    ) -> Result<usize, TypedFd<Subsystem>> {
        // XXX(jb): should we try to somehow enforce that it is set at the smallest
        // available/unassigned FD number?
        let mut rds = self.raw_descriptor_store.write();
        let raw_fd = rds.fd_into_raw_integer(typed_fd);
        let max_fd = self.max_fd.load(Ordering::Relaxed);
        if raw_fd > max_fd {
            let orig = rds.fd_consume_raw_integer::<Subsystem>(raw_fd).unwrap();
            return Err(alloc::sync::Arc::into_inner(orig).unwrap());
        }
        Ok(raw_fd)
    }

    fn register_inotify_fd(&self, raw_fd: usize) {
        self.inotify_instances.lock().insert(
            raw_fd,
            Arc::new(litebox::sync::Mutex::new(InotifyInstanceState::new())),
        );
    }

    fn duplicate_inotify_fd(&self, old_fd: usize, new_fd: usize) {
        let state = self.inotify_instances.lock().get(&old_fd).cloned();
        if let Some(state) = state {
            self.inotify_instances.lock().insert(new_fd, state);
        }
    }

    fn remove_inotify_fd(&self, raw_fd: usize) {
        self.inotify_instances.lock().remove(&raw_fd);
    }

    fn with_inotify_fd<R>(
        &self,
        raw_fd: usize,
        f: impl FnOnce(&mut InotifyInstanceState) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let state = self
            .inotify_instances
            .lock()
            .get(&raw_fd)
            .cloned()
            .ok_or(Errno::EBADF)?;
        let mut state = state.lock();
        f(&mut state)
    }
}

/// Path in the file system
#[derive(Debug)]
enum FsPath {
    /// Absolute path
    Absolute { path: CString },
    /// Current working directory
    Cwd,
    /// Path is relative to a file descriptor whose path is not known to
    /// the shim. Will be passed through to the `FileSystem` `*_at` methods.
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
    /// Empty paths return `ENOENT` unless `allow_empty` is true (for
    /// syscalls that support `AT_EMPTY_PATH`).
    fn new(
        dirfd: i32,
        path: impl path::Arg,
        get_cwd: impl FnOnce() -> String,
    ) -> Result<Self, Errno> {
        Self::new_inner(dirfd, path, get_cwd, false)
    }

    /// Like [`new`](Self::new) but permits empty paths, producing
    /// `FsPath::Fd` or `FsPath::Cwd`. Callers must only use this when
    /// `AT_EMPTY_PATH` is set.
    #[cfg(test)]
    fn new_empty_ok(
        dirfd: i32,
        path: impl path::Arg,
        get_cwd: impl FnOnce() -> String,
    ) -> Result<Self, Errno> {
        Self::new_inner(dirfd, path, get_cwd, true)
    }

    fn new_inner(
        dirfd: i32,
        path: impl path::Arg,
        get_cwd: impl FnOnce() -> String,
        allow_empty: bool,
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
                if !allow_empty {
                    return Err(Errno::ENOENT);
                }
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
                if !allow_empty {
                    return Err(Errno::ENOENT);
                }
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
    fn validate_removedir_path_str(path: &str) -> Result<(), Errno> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        match path.rsplit('/').find(|component| !component.is_empty()) {
            Some(".") => return Err(Errno::EINVAL),
            Some("..") => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        Ok(())
    }

    fn get_umask(&self) -> Mode {
        self.fs.borrow().umask()
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

    /// Resolve symlinks in a path to produce a canonicalized absolute path.
    fn canonicalize_path(&self, path: &str) -> Result<String, Errno> {
        let mut resolved = String::from("/");
        let mut hops_remaining: usize = 40;

        // Work queue of components still to process. Symlink expansions
        // splice their target components to the front.
        let mut remaining: alloc::vec::Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect();
        let mut idx = 0;

        while idx < remaining.len() {
            let component = remaining[idx].clone();
            idx += 1;

            match component.as_str() {
                "" | "." => continue,
                ".." => {
                    if let Some(pos) = resolved[..resolved.len().saturating_sub(1)].rfind('/') {
                        resolved.truncate(pos + 1);
                    }
                    continue;
                }
                _ => {}
            }

            if !resolved.ends_with('/') {
                resolved.push('/');
            }
            resolved.push_str(&component);

            // If this prefix is a symlink, expand it: splice the target's
            // components into the front of `remaining` and restart the
            // outer loop so each new component is individually walked.
            if let Ok(target) = self.do_readlink(&resolved) {
                if hops_remaining == 0 {
                    return Err(Errno::ELOOP);
                }
                hops_remaining -= 1;

                if target.starts_with('/') {
                    resolved = String::from("/");
                } else {
                    let parent_end = resolved.rfind('/').unwrap_or(0).max(1);
                    resolved.truncate(parent_end);
                }

                let tail: alloc::vec::Vec<String> = remaining.drain(idx..).collect();
                remaining.truncate(0);
                remaining.extend(
                    target
                        .split('/')
                        .filter(|c| !c.is_empty())
                        .map(str::to_string),
                );
                remaining.extend(tail);
                idx = 0;
            }
        }

        if resolved.len() > 1 && resolved.ends_with('/') {
            resolved.pop();
        }
        Ok(resolved)
    }

    /// Resolve an executable path to a canonical absolute path for /proc/self/exe.
    ///
    /// Linux always reports /proc/self/exe as the fully resolved path:
    /// relative paths are made absolute against CWD, `..`/`.` segments are
    /// normalized, and symlinks in every component are followed (like
    /// `realpath`).
    #[allow(dead_code)] // used by exec/runner (deferred)
    pub(crate) fn resolve_exe_path(&self, path: &str) -> String {
        let abs = if path.starts_with('/') {
            path.to_string()
        } else {
            let cwd = self.fs.borrow().cwd.read().clone();
            alloc::format!("{cwd}{path}")
        };
        self.canonicalize_path(&abs).unwrap_or(abs)
    }

    /// Open a synthetic /proc text file by piping the given contents
    /// through a one-shot pipe. The write end is closed after filling.
    #[allow(dead_code)] // caller (proc_self_maps) deferred to ProcessState PR
    fn open_synthetic_proc_text(
        &self,
        flags: OFlags,
        contents: alloc::string::String,
    ) -> Result<u32, Errno> {
        use litebox::pipes::Flags;

        if flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
            return Err(Errno::EACCES);
        }
        if flags.contains(OFlags::DIRECTORY) {
            return Err(Errno::ENOTDIR);
        }

        let mut pipe_flags = Flags::empty();
        pipe_flags.set(Flags::NON_BLOCKING, flags.contains(OFlags::NONBLOCK));
        let (writer, reader) = self.global.pipes.create_pipe(
            DEFAULT_PIPE_BUF_SIZE,
            pipe_flags,
            core::num::NonZero::new(4096),
        );

        {
            let initial_status = OFlags::from(pipe_flags);
            let mut dt = self.global.litebox.descriptor_table_mut();
            let old = dt.set_entry_metadata(
                &reader,
                crate::PipeStatusFlags(initial_status | OFlags::RDONLY),
            );
            assert!(old.is_none());
            if flags.contains(OFlags::CLOEXEC) {
                let None = dt.set_fd_metadata(&reader, FileDescriptorFlags::FD_CLOEXEC) else {
                    unreachable!()
                };
            }
        }

        let write_result = self
            .global
            .pipes
            .write(&self.wait_cx(), &writer, contents.as_bytes())
            .map_err(Errno::from);
        self.global.pipes.close(&writer).unwrap();
        let written = write_result?;
        debug_assert_eq!(written, contents.len());

        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(reader).map_err(|reader| {
            self.global.pipes.close(&reader).unwrap();
            Errno::EMFILE
        })?;
        Ok(u32::try_from(raw_fd).unwrap())
    }

    /// Get the rdev for a PTY slave fd, if it is one (major=136).
    #[allow(dead_code)] // caller (_pty_target_for_guest_fd) needed later
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
                |_fd| None,
                |_fd| None,
                |_fd| None,
            )
            .ok()
            .flatten()
    }

    #[allow(dead_code)] // needed later
    fn _pty_target_for_guest_fd(
        &self,
        files: &FilesState<FS>,
        guest_fd: u32,
    ) -> Option<(usize, usize)> {
        let raw_fd = usize::try_from(guest_fd).ok()?;
        if !files.raw_descriptor_store.read().is_alive(raw_fd) {
            return None;
        }
        let rdev = self.pty_rdev_for_raw_fd(files, raw_fd)?;
        Some((raw_fd, rdev))
    }

    fn trace_pty_open(&self, _path: &str, _guest_fd: u32, _raw_fd: usize, _rdev: Option<usize>) {}

    #[allow(dead_code)]
    fn maybe_trace_pty_dup(&self, _oldfd: u32, _newfd: u32) {}

    /// Validate that a file descriptor is open and valid.
    pub fn validate_fd(&self, fd: i32) -> Result<(), Errno> {
        let Ok(raw_fd) = usize::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files.run_on_raw_fd(raw_fd, |_| (), |_| (), |_| (), |_| (), |_| (), |_| ())?;
        Ok(())
    }

    /// Validate that a path resolves to an existing file (follows symlinks).
    pub fn validate_path(&self, pathname: impl path::Arg) -> Result<(), Errno> {
        let path = self.resolve_path(pathname)?;
        self.files
            .borrow()
            .fs
            .file_status(path)
            .map_err(Errno::from)?;
        Ok(())
    }

    /// Validate that a path entry itself exists (does not follow symlinks).
    /// A dangling symlink is considered valid.
    pub fn validate_path_nofollow(&self, pathname: impl path::Arg) -> Result<(), Errno> {
        let path = self.resolve_path(pathname)?;
        let files = self.files.borrow();
        // If the path resolves via follow (normal stat), it exists.
        if files.fs.file_status(&path).is_ok() {
            return Ok(());
        }
        // The follow-stat failed. Check if it's a symlink (possibly dangling).
        if files.fs.read_link(&path).is_ok() {
            return Ok(());
        }
        // Neither a resolvable path nor a symlink — report the original error.
        files.fs.file_status(path).map_err(Errno::from)?;
        Ok(())
    }

    /// Validate a path with symlink-follow control.
    pub fn validate_path_follow(
        &self,
        pathname: impl path::Arg,
        follow: bool,
    ) -> Result<(), Errno> {
        if follow {
            self.validate_path(pathname)
        } else {
            self.validate_path_nofollow(pathname)
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
        let path = if path.to_str().ok() == Some("/proc/self/exe") {
            let exe = self.fs.borrow().exe_path.read().clone();
            if exe.is_empty() {
                return Err(Errno::ENOENT);
            }
            CString::new(exe).map_err(|_| Errno::EINVAL)?
        } else {
            path
        };
        if path.to_str().ok() == Some("/sys/kernel/debug/tracing/trace_marker") {
            return Err(Errno::EACCES);
        }
        let mode = mode & !self.get_umask();
        let file = self
            .files
            .borrow()
            .fs
            .open(&*path, flags - OFlags::CLOEXEC, mode)
            .map_err(Errno::from)?;
        let status = flags & OFlags::STATUS_FLAGS_MASK;
        // Query file status before acquiring the descriptor table write lock
        // to avoid deadlock (fd_file_status takes a read lock on the same
        // descriptor table internally).
        let file_rdev_major = self
            .files
            .borrow()
            .fs
            .fd_file_status(&file)
            .ok()
            .and_then(|s| s.node_info.rdev)
            .map(|rdev| rdev.get() >> 8);
        {
            let mut dt = self.global.litebox.descriptor_table_mut();
            if flags.contains(OFlags::CLOEXEC) {
                let None = dt.set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC) else {
                    unreachable!()
                };
            }
            // Store access mode + status flags so F_GETFL can return them.
            let None = dt.set_entry_metadata(&file, crate::StdioStatusFlags(status)) else {
                unreachable!()
            };
            if let Ok(path_str) = path.to_str()
                && let Some(source_fd) = host_stdio_source_for_path(path_str)
            {
                let old = dt.set_entry_metadata(&file, crate::HostStdioSourceFd(source_fd));
                assert!(old.is_none());
            }
            if let Ok(path_str) = path.to_str()
                && is_host_tty_path(path_str)
            {
                let old = dt.set_entry_metadata(&file, crate::HostTtyAlias);
                assert!(old.is_none());
            }
            // Tag fds opened via the host PTY device path (e.g., /dev/pts/156)
            // so that fstat returns the host PTY identity, not the default
            // Device::Tty identity (rdev=0x500). Skip if the fd resolved to a
            // sandbox PTY (major >= 136) rather than the host tty alias.
            if let Ok(path_str) = path.to_str()
                && is_host_pty_device_path(path_str, self.global.platform)
                && file_rdev_major.is_none_or(|m| m < 136)
            {
                let old = dt.set_entry_metadata(&file, HostPtyDeviceFd);
                assert!(old.is_none());
            }
        }
        self.files
            .borrow()
            .fs
            .set_open_status_flags(&file, status)
            .map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(file).map_err(|file| {
            files.fs.close(&file).unwrap();
            Errno::EMFILE
        })?;
        let guest_fd = u32::try_from(raw_fd).unwrap();

        if let Ok(s) = path.to_str()
            && (s == "/dev/ptmx" || s.starts_with("/dev/pts/"))
        {
            let rdev = self.pty_rdev_for_raw_fd(&files, raw_fd);
            self.trace_pty_open(s, guest_fd, raw_fd, rdev);
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
                log_unsupported!("openat with empty path");
                Err(Errno::EINVAL)
            }
            FsPath::FdRelative { fd, path } => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                let mode = mode & !self.get_umask();
                let status = flags & OFlags::STATUS_FLAGS_MASK;

                let abs_path = self.resolve_dirfd_path(fd, &path).ok();
                let files = self.files.borrow();
                let file = files.run_on_raw_fd(
                    raw_fd,
                    |dirfd| {
                        files
                            .fs
                            .open_at(dirfd, path, flags - OFlags::CLOEXEC, mode)
                            .map_err(Errno::from)
                    },
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                )?;
                let file = file?;
                // Query file status before acquiring descriptor table write
                // lock to avoid deadlock (fd_file_status needs a read lock).
                let file_rdev_major = files
                    .fs
                    .fd_file_status(&file)
                    .ok()
                    .and_then(|s| s.node_info.rdev)
                    .map(|rdev| rdev.get() >> 8);
                {
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    if flags.contains(OFlags::CLOEXEC) {
                        let None = dt.set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC)
                        else {
                            unreachable!()
                        };
                    }
                    let None = dt.set_entry_metadata(&file, crate::StdioStatusFlags(status)) else {
                        unreachable!()
                    };
                    if let Some(source_fd) =
                        abs_path.as_deref().and_then(host_stdio_source_for_path)
                    {
                        let old = dt.set_entry_metadata(&file, crate::HostStdioSourceFd(source_fd));
                        assert!(old.is_none());
                    }
                    if abs_path.as_deref().is_some_and(is_host_tty_path) {
                        let old = dt.set_entry_metadata(&file, crate::HostTtyAlias);
                        assert!(old.is_none());
                    }
                    if abs_path
                        .as_deref()
                        .is_some_and(|p| is_host_pty_device_path(p, self.global.platform))
                        && file_rdev_major.is_none_or(|m| m < 136)
                    {
                        let old = dt.set_entry_metadata(&file, HostPtyDeviceFd);
                        assert!(old.is_none());
                    }
                }
                files
                    .fs
                    .set_open_status_flags(&file, status)
                    .map_err(|_| Errno::EBADF)?;
                let guest_raw = files.insert_raw_fd(file).map_err(|file| {
                    files.fs.close(&file).unwrap();
                    Errno::EMFILE
                })?;
                Ok(u32::try_from(guest_raw).unwrap())
            }
        }
    }

    /// Handle syscall `ftruncate`
    pub(crate) fn sys_ftruncate(&self, fd: i32, length: usize) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| files.fs.truncate(fd, length, false).map_err(Errno::from),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
            )
            .flatten()
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn sys_rmdir(&self, pathname: impl path::Arg) -> Result<(), Errno> {
        self.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            pathname,
            AtFlags::AT_REMOVEDIR,
        )
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
        if flags.contains(AtFlags::AT_REMOVEDIR) {
            let raw_path = pathname.as_rust_str().map_err(|_| Errno::EINVAL)?;
            Self::validate_removedir_path_str(raw_path)?;
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
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::EINVAL),
            FsPath::FdRelative { fd, path } => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                let is_rmdir = flags.contains(AtFlags::AT_REMOVEDIR);

                let files = self.files.borrow();
                files.run_on_raw_fd(
                    raw_fd,
                    |dirfd| {
                        if is_rmdir {
                            // rmdir doesn't have an _at variant yet; resolve manually.
                            // Verify dirfd refers to a directory.
                            let status = files.fs.fd_file_status(dirfd).map_err(Errno::from)?;
                            if !matches!(status.file_type, litebox::fs::FileType::Directory) {
                                return Err(Errno::ENOTDIR);
                            }
                            let dir_path = files.fs.fd_path(dirfd).ok_or(Errno::EBADF)?;
                            let rel = path.to_str().map_err(|_| Errno::EINVAL)?;
                            let abs = if rel.starts_with('/') {
                                rel.into()
                            } else if dir_path.ends_with('/') {
                                alloc::format!("{dir_path}{rel}")
                            } else {
                                alloc::format!("{dir_path}/{rel}")
                            };
                            files.fs.rmdir(abs).map_err(Errno::from)
                        } else {
                            files.fs.unlink_at(dirfd, path).map_err(Errno::from)
                        }
                    },
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                )?
            }
        }
    }

    /// Handle syscall `read`
    ///
    /// `offset` is an optional offset to read from. If `None`, it will read from the current file position.
    /// If `Some`, it will read from the specified offset without changing the current file position.
    pub fn sys_read(&self, fd: i32, buf: &mut [u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        // We need to do this cell dance because otherwise Rust can't recognize that the two
        // closures are mutually exclusive.
        let buf: core::cell::RefCell<&mut [u8]> = core::cell::RefCell::new(buf);
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    let _position_guard = if offset.is_none()
                        && matches!(
                            files.fs.fd_file_status(fd),
                            Ok(status) if status.file_type == litebox::fs::FileType::RegularFile
                        ) {
                        Some(files.file_position_lock.lock())
                    } else {
                        None
                    };
                    files
                        .fs
                        .read(fd, &mut buf.borrow_mut(), offset)
                        .map_err(Errno::from)
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
                    self.global
                        .pipes
                        .read(&self.wait_cx(), fd, &mut buf.borrow_mut())
                        .map_err(Errno::from)
                },
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        let buf = &mut buf.borrow_mut();
                        if buf.len() < size_of::<u64>() {
                            return Err(Errno::EINVAL);
                        }
                        let value = file.read(&self.wait_cx())?;
                        buf[..size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
                        Ok(size_of::<u64>())
                    })
                },
                |_fd| Err(Errno::EINVAL),
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        file.recvfrom(
                            &self.wait_cx(),
                            &mut buf.borrow_mut(),
                            litebox_common_linux::ReceiveFlags::empty(),
                            None,
                            &mut Vec::new(),
                        )
                    })
                },
            )
            .flatten()
    }

    /// Handle syscall `write`
    ///
    /// `offset` is an optional offset to write to. If `None`, it will write to the current file position.
    /// If `Some`, it will write to the specified offset without changing the current file position.
    pub fn sys_write(&self, fd: i32, buf: &[u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let res = files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    let _position_guard = if offset.is_none()
                        && matches!(
                            files.fs.fd_file_status(fd),
                            Ok(status) if status.file_type == litebox::fs::FileType::RegularFile
                        ) {
                        Some(files.file_position_lock.lock())
                    } else {
                        None
                    };
                    files.fs.write(fd, buf, offset).map_err(Errno::from)
                },
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
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        let value: u64 = u64::from_le_bytes(
                            buf[..size_of::<u64>()]
                                .try_into()
                                .map_err(|_| Errno::EINVAL)?,
                        );
                        file.write(&self.wait_cx(), value)
                    })
                },
                |_fd| Err(Errno::EINVAL),
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        file.sendto(
                            self,
                            buf,
                            litebox_common_linux::SendFlags::empty(),
                            None,
                            Vec::new(),
                        )
                    })
                },
            )
            .flatten();
        if let Err(Errno::EPIPE) = res {
            self.send_signal(
                litebox_common_linux::signal::Signal::SIGPIPE,
                siginfo_kernel(litebox_common_linux::signal::Signal::SIGPIPE),
            );
        }
        res
    }

    fn copy_file_range_explicit_offset(&self, offset: MutPtr<i64>) -> Result<Option<usize>, Errno> {
        if offset.as_usize() == 0 {
            return Ok(None);
        }
        let pos = offset.read_at_offset(0).ok_or(Errno::EFAULT)?;
        Ok(Some(usize::try_from(pos).map_err(|_| Errno::EINVAL)?))
    }

    fn finish_copy_file_range_explicit_offset(
        &self,
        offset: MutPtr<i64>,
        pos: Option<usize>,
    ) -> Result<(), Errno> {
        let Some(pos) = pos else {
            return Ok(());
        };
        let pos = i64::try_from(pos).map_err(|_| Errno::EOVERFLOW)?;
        offset.write_at_offset(0, pos).ok_or(Errno::EFAULT)?;
        Ok(())
    }

    fn regular_file_open_flags(&self, typed_fd: &TypedFd<FS>) -> OFlags {
        self.global
            .litebox
            .descriptor_table()
            .with_metadata(typed_fd, |crate::StdioStatusFlags(flags)| *flags)
            .unwrap_or(OFlags::empty())
    }

    fn validate_regular_file_typed_fd(
        &self,
        files: &FilesState<FS>,
        typed_fd: &TypedFd<FS>,
        need_read: bool,
        need_write: bool,
    ) -> Result<litebox::fs::FileStatus, Errno> {
        let status = files.fs.fd_file_status(typed_fd).map_err(Errno::from)?;
        match status.file_type {
            litebox::fs::FileType::RegularFile => {}
            litebox::fs::FileType::Directory => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
        let open_flags = self.regular_file_open_flags(typed_fd);
        if open_flags.contains(OFlags::PATH) {
            return Err(Errno::EBADF);
        }
        let access = open_flags & (OFlags::WRONLY | OFlags::RDWR);
        if need_read && access == OFlags::WRONLY {
            return Err(Errno::EBADF);
        }
        if need_write && access == OFlags::empty() {
            return Err(Errno::EBADF);
        }
        Ok(status)
    }

    pub fn sys_copy_file_range(
        &self,
        fd_in: i32,
        off_in: MutPtr<i64>,
        fd_out: i32,
        off_out: MutPtr<i64>,
        len: usize,
        flags: u32,
    ) -> Result<usize, Errno> {
        if flags != 0 {
            return Err(Errno::EINVAL);
        }
        let mut explicit_in_pos = self.copy_file_range_explicit_offset(off_in)?;
        let explicit_out_pos = self.copy_file_range_explicit_offset(off_out)?;
        let raw_fd_in = usize::try_from(fd_in).map_err(|_| Errno::EBADF)?;
        let raw_fd_out = usize::try_from(fd_out).map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();
        let (src_fd, dst_fd) = {
            let rds = files.raw_descriptor_store.read();
            let capture_fs_fd = |raw_fd| match rds.fd_from_raw_integer::<FS>(raw_fd) {
                Ok(fd) => Ok(fd),
                Err(ErrRawIntFd::NotFound) => Err(Errno::EBADF),
                Err(ErrRawIntFd::InvalidSubsystem) => Err(Errno::EINVAL),
            };
            (capture_fs_fd(raw_fd_in)?, capture_fs_fd(raw_fd_out)?)
        };
        let src_status = self.validate_regular_file_typed_fd(&files, &src_fd, true, false)?;
        let dst_status = self.validate_regular_file_typed_fd(&files, &dst_fd, false, true)?;
        if self
            .regular_file_open_flags(&dst_fd)
            .contains(OFlags::APPEND)
        {
            return Err(Errno::EBADF);
        }

        let use_position_lock = explicit_in_pos.is_none() || explicit_out_pos.is_none();
        let (copied, explicit_in_pos, out_pos) = {
            // Keep implicit-offset copies serialized against other regular-file
            // I/O on the same shared file description, but never park while
            // holding that mutex or vfork parking can deadlock on it.
            let _position_guard = use_position_lock.then(|| files.file_position_lock.lock());
            let start_in = explicit_in_pos.unwrap_or(
                files
                    .fs
                    .seek(&*src_fd, 0, SeekWhence::RelativeToCurrentOffset)
                    .map_err(Errno::from)?,
            );
            let start_out = explicit_out_pos.unwrap_or(
                files
                    .fs
                    .seek(&*dst_fd, 0, SeekWhence::RelativeToCurrentOffset)
                    .map_err(Errno::from)?,
            );
            let same_file = src_status.node_info.dev == dst_status.node_info.dev
                && src_status.node_info.ino == dst_status.node_info.ino;
            let copy_len = core::cmp::min(len, src_status.size.saturating_sub(start_in));
            start_in.checked_add(len).ok_or(Errno::EOVERFLOW)?;
            start_out.checked_add(len).ok_or(Errno::EOVERFLOW)?;
            if same_file {
                let in_end = start_in.checked_add(copy_len).ok_or(Errno::EOVERFLOW)?;
                let out_end = start_out.checked_add(copy_len).ok_or(Errno::EOVERFLOW)?;
                if start_in < out_end && start_out < in_end {
                    return Err(Errno::EINVAL);
                }
            }

            let mut copied = 0usize;
            let mut buf = [0u8; 16 * 1024];
            let mut out_pos = start_out;
            while copied < copy_len {
                let chunk_len = core::cmp::min(copy_len - copied, buf.len());
                let read = match files
                    .fs
                    .read(&*src_fd, &mut buf[..chunk_len], explicit_in_pos)
                    .map_err(Errno::from)
                {
                    Ok(n) => n,
                    Err(err) if copied == 0 => return Err(err),
                    Err(_) => break,
                };
                if read == 0 {
                    break;
                }

                let mut written = 0usize;
                let mut stop_after_chunk = false;
                while written < read {
                    let wrote = match files
                        .fs
                        .write(&*dst_fd, &buf[written..read], Some(out_pos))
                        .map_err(Errno::from)
                    {
                        Ok(0) if copied == 0 && written == 0 => {
                            if explicit_in_pos.is_none() {
                                files
                                    .fs
                                    .seek(
                                        &*src_fd,
                                        -isize::try_from(read).map_err(|_| Errno::EOVERFLOW)?,
                                        SeekWhence::RelativeToCurrentOffset,
                                    )
                                    .map_err(Errno::from)?;
                            }
                            return Err(Errno::EIO);
                        }
                        Ok(0) => {
                            stop_after_chunk = true;
                            break;
                        }
                        Ok(n) => n,
                        Err(err) if copied == 0 && written == 0 => {
                            if explicit_in_pos.is_none() {
                                files
                                    .fs
                                    .seek(
                                        &*src_fd,
                                        -isize::try_from(read).map_err(|_| Errno::EOVERFLOW)?,
                                        SeekWhence::RelativeToCurrentOffset,
                                    )
                                    .map_err(Errno::from)?;
                            }
                            return Err(err);
                        }
                        Err(_) => {
                            stop_after_chunk = true;
                            break;
                        }
                    };
                    written = written.checked_add(wrote).ok_or(Errno::EOVERFLOW)?;
                    out_pos = out_pos.checked_add(wrote).ok_or(Errno::EOVERFLOW)?;
                    if explicit_out_pos.is_none() {
                        files
                            .fs
                            .seek(
                                &*dst_fd,
                                isize::try_from(out_pos).map_err(|_| Errno::EOVERFLOW)?,
                                SeekWhence::RelativeToBeginning,
                            )
                            .map_err(Errno::from)?;
                    }
                }

                if explicit_in_pos.is_none() && written < read {
                    files
                        .fs
                        .seek(
                            &*src_fd,
                            -isize::try_from(read - written).map_err(|_| Errno::EOVERFLOW)?,
                            SeekWhence::RelativeToCurrentOffset,
                        )
                        .map_err(Errno::from)?;
                }
                copied = copied.checked_add(written).ok_or(Errno::EOVERFLOW)?;
                if let Some(pos) = explicit_in_pos.as_mut() {
                    *pos = pos.checked_add(written).ok_or(Errno::EOVERFLOW)?;
                }
                if written < read || stop_after_chunk {
                    break;
                }
            }
            (copied, explicit_in_pos, out_pos)
        };

        self.finish_copy_file_range_explicit_offset(off_in, explicit_in_pos)?;
        self.finish_copy_file_range_explicit_offset(off_out, explicit_out_pos.map(|_| out_pos))?;
        Ok(copied)
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
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    let _position_guard = if matches!(
                        files.fs.fd_file_status(fd),
                        Ok(status) if status.file_type == litebox::fs::FileType::RegularFile
                    ) {
                        Some(files.file_position_lock.lock())
                    } else {
                        None
                    };
                    files.fs.seek(fd, offset, whence).map_err(Errno::from)
                },
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
            )
            .flatten()
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

    pub(crate) fn do_close(&self, raw_fd: usize) -> Result<(), Errno> {
        let files = self.files.borrow();
        // Clean up inotify tracking for this fd (no-op if not an inotify fd).
        files.remove_inotify_fd(raw_fd);
        let mut rds = files.raw_descriptor_store.write();
        match rds.fd_consume_raw_integer(raw_fd) {
            Ok(fd) => {
                drop(rds);
                return files.fs.close(&fd).map_err(Errno::from);
            }
            Err(litebox::fd::ErrRawIntFd::NotFound) => {
                return Err(Errno::EBADF);
            }
            Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                // fallthrough
            }
        }
        if let Ok(fd) = rds.fd_consume_raw_integer(raw_fd) {
            drop(rds);
            return self.global.close_socket(&self.wait_cx(), fd);
        }
        if let Ok(fd) = rds.fd_consume_raw_integer(raw_fd) {
            drop(rds);
            return self.global.pipes.close(&fd).map_err(Errno::from);
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::eventfd::EventfdSubsystem>(raw_fd) {
            drop(rds);
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::epoll::EpollSubsystem<FS>>(raw_fd) {
            drop(rds);
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(raw_fd) {
            drop(rds);
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            drop(entry);
            return Ok(());
        }
        // All the above cases should cover all the known subsystems, and we've already
        // early-handled the "raw FD not found" case.
        unreachable!()
    }

    /// Handle syscall `close`
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        // Finalize any in-progress ELF patching for this fd (mprotect
        // trampoline RW→RX) before closing the descriptor.
        self.finalize_elf_patch(fd);

        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        self.do_close(raw_fd)
    }

    fn set_close_on_exec(&self, raw_fd: usize) -> Result<(), Errno> {
        let files = self.files.borrow();
        files.run_on_raw_fd(
            raw_fd,
            |fd| {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            },
            |fd| {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            },
            |fd| {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            },
            |fd| {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            },
            |fd| {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            },
            |fd| {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            },
        )
    }

    pub(crate) fn sys_close_range(
        &self,
        first: u32,
        last: u32,
        flags: u32,
    ) -> Result<usize, Errno> {
        const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

        if first > last || flags & !CLOSE_RANGE_CLOEXEC != 0 {
            return Err(Errno::EINVAL);
        }

        let first = first as usize;
        let last = last as usize;
        let alive_fds: alloc::vec::Vec<usize> = {
            let files = self.files.borrow();
            files.raw_descriptor_store.read().iter_alive().collect()
        };

        for raw_fd in alive_fds {
            if raw_fd < first || raw_fd > last {
                continue;
            }
            if flags == CLOSE_RANGE_CLOEXEC {
                let _ = self.set_close_on_exec(raw_fd);
            } else {
                if let Ok(fd) = i32::try_from(raw_fd) {
                    self.finalize_elf_patch(fd);
                }
                let _ = self.do_close(raw_fd);
            }
        }

        Ok(0)
    }

    /// Handle syscall `mkdirat`
    pub fn sys_mkdirat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode: u32,
    ) -> Result<(), Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        let mode = Mode::from_bits_retain(mode) & !self.get_umask();
        match fs_path {
            FsPath::Absolute { path } => self
                .files
                .borrow()
                .fs
                .mkdir(path, mode)
                .map_err(Errno::from),
            FsPath::Cwd => self
                .files
                .borrow()
                .fs
                .mkdir(get_cwd(), mode)
                .map_err(Errno::from),
            FsPath::Fd(_fd) => Err(Errno::EEXIST),
            FsPath::FdRelative { fd, path } => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                let files = self.files.borrow();
                files.run_on_raw_fd(
                    raw_fd,
                    |dirfd| files.fs.mkdir_at(dirfd, path, mode).map_err(Errno::from),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                )?
            }
        }
    }

    /// Resolve an `FsPath::FdRelative` to an absolute path, validating that
    /// the dirfd refers to a directory (not a regular file).
    fn resolve_dirfd_path(&self, fd: u32, rel_path: &CString) -> Result<String, Errno> {
        let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();
        files.run_on_raw_fd(
            raw_fd,
            |dirfd| {
                let status = files.fs.fd_file_status(dirfd).map_err(Errno::from)?;
                if !matches!(status.file_type, litebox::fs::FileType::Directory) {
                    return Err(Errno::ENOTDIR);
                }
                let dir_path = files.fs.fd_path(dirfd).ok_or(Errno::EBADF)?;
                let rel = rel_path.to_str().map_err(|_| Errno::EINVAL)?;
                Ok(if rel.is_empty() || rel == "." {
                    dir_path
                } else if rel.starts_with('/') {
                    rel.to_string()
                } else if dir_path.ends_with('/') {
                    alloc::format!("{dir_path}{rel}")
                } else {
                    alloc::format!("{dir_path}/{rel}")
                })
            },
            |_| Err(Errno::ENOTDIR),
            |_| Err(Errno::ENOTDIR),
            |_| Err(Errno::ENOTDIR),
            |_| Err(Errno::ENOTDIR),
            |_| Err(Errno::ENOTDIR),
        )?
    }

    /// Helper to resolve an `FsPath` to an absolute path string.
    fn resolve_fs_path_to_string(
        &self,
        fs_path: FsPath,
        get_cwd: &impl Fn() -> String,
    ) -> Result<String, Errno> {
        match fs_path {
            FsPath::Absolute { path } => path.into_string().map_err(|_| Errno::EINVAL),
            FsPath::Cwd => Ok(get_cwd()),
            FsPath::Fd(_) => Err(Errno::EINVAL),
            FsPath::FdRelative { fd, path } => self.resolve_dirfd_path(fd, &path),
        }
    }

    /// Handle `symlinkat` — create a symbolic link.
    pub fn sys_symlinkat(
        &self,
        target: impl path::Arg,
        newdirfd: i32,
        linkpath: impl path::Arg,
    ) -> Result<(), Errno> {
        let target_str = target.as_rust_str().map_err(|_| Errno::EINVAL)?.to_string();

        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(newdirfd, linkpath, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => self
                .files
                .borrow()
                .fs
                .symlink(target_str, path)
                .map_err(Errno::from),
            FsPath::Cwd => self
                .files
                .borrow()
                .fs
                .symlink(target_str, get_cwd())
                .map_err(Errno::from),
            FsPath::Fd(_) => Err(Errno::EEXIST),
            FsPath::FdRelative { fd, path } => {
                let abs = self.resolve_dirfd_path(fd, &path)?;
                let files = self.files.borrow();
                files.fs.symlink(target_str, abs).map_err(Errno::from)
            }
        }
    }

    /// Handle `linkat` — create a hard link.
    #[allow(clippy::needless_borrows_for_generic_args)]
    pub fn sys_linkat(
        &self,
        olddirfd: i32,
        oldpath: impl path::Arg,
        newdirfd: i32,
        newpath: impl path::Arg,
        _flags: AtFlags,
    ) -> Result<(), Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let old_fs = FsPath::new(olddirfd, oldpath, &get_cwd)?;
        let new_fs = FsPath::new(newdirfd, newpath, &get_cwd)?;

        let old_abs = self.resolve_fs_path_to_string(old_fs, &get_cwd)?;
        let new_abs = self.resolve_fs_path_to_string(new_fs, &get_cwd)?;
        self.files
            .borrow()
            .fs
            .link(old_abs, new_abs)
            .map_err(Errno::from)
    }

    pub(crate) fn sys_renameat2(
        &self,
        olddirfd: i32,
        oldpath: impl path::Arg,
        newdirfd: i32,
        newpath: impl path::Arg,
        flags: u32,
    ) -> Result<(), Errno> {
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;
        const RENAME_WHITEOUT: u32 = 4;
        let supported = RENAME_NOREPLACE;
        if flags & !supported != 0 {
            if flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
                return Err(Errno::EINVAL);
            }
            return Err(Errno::EINVAL);
        }
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let old = FsPath::new(olddirfd, oldpath, get_cwd)?;
        let new = FsPath::new(newdirfd, newpath, get_cwd)?;

        // Resolve both paths to absolute strings, supporting FdRelative.
        let resolve = |fspath: FsPath| -> Result<CString, Errno> {
            match fspath {
                FsPath::Absolute { path } => Ok(path),
                FsPath::Cwd => CString::new(get_cwd()).map_err(|_| Errno::EINVAL),
                FsPath::Fd(_) => Err(Errno::EINVAL),
                FsPath::FdRelative { fd, path } => {
                    let Ok(raw_fd) = usize::try_from(fd) else {
                        return Err(Errno::EBADF);
                    };

                    let files = self.files.borrow();
                    files.run_on_raw_fd(
                        raw_fd,
                        |dirfd| {
                            // Verify dirfd refers to a directory.
                            let status = files.fs.fd_file_status(dirfd).map_err(Errno::from)?;
                            if !matches!(status.file_type, litebox::fs::FileType::Directory) {
                                return Err(Errno::ENOTDIR);
                            }
                            let dir_path = files.fs.fd_path(dirfd).ok_or(Errno::EBADF)?;
                            let rel = path.to_str().map_err(|_| Errno::EINVAL)?;
                            // Linux returns EBUSY for rename(".") or rename("").
                            if rel.is_empty() || rel == "." {
                                return Err(Errno::EBUSY);
                            }
                            let abs = if rel.starts_with('/') {
                                rel.into()
                            } else if dir_path.ends_with('/') {
                                alloc::format!("{dir_path}{rel}")
                            } else {
                                alloc::format!("{dir_path}/{rel}")
                            };
                            CString::new(abs).map_err(|_| Errno::EINVAL)
                        },
                        |_| Err(Errno::ENOTDIR),
                        |_| Err(Errno::ENOTDIR),
                        |_| Err(Errno::ENOTDIR),
                        |_| Err(Errno::ENOTDIR),
                        |_| Err(Errno::ENOTDIR),
                    )?
                }
            }
        };
        let old_path = resolve(old)?;
        let new_path = resolve(new)?;
        if flags & RENAME_NOREPLACE != 0 {
            // Check if target exists — RENAME_NOREPLACE fails with EEXIST.
            if self.files.borrow().fs.file_status(&*new_path).is_ok() {
                return Err(Errno::EEXIST);
            }
        }
        self.files
            .borrow()
            .fs
            .rename(old_path, new_path)
            .map_err(Errno::from)
    }

    /// Handle syscall `readv`
    pub fn sys_readv(
        &self,
        fd: i32,
        iovec: ConstPtr<IoReadVec<MutPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let iovs: &[IoReadVec<MutPtr<u8>>] = &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        let files = self.files.borrow();
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    let needs_position_lock = matches!(
                        files.fs.fd_file_status(fd),
                        Ok(status) if status.file_type == litebox::fs::FileType::RegularFile
                    );
                    let _position_guard = if needs_position_lock {
                        Some(files.file_position_lock.lock())
                    } else {
                        None
                    };
                    let mut total_read = 0;
                    let kernel_buffer =
                        core::cell::RefCell::new(vec![
                            0u8;
                            iovs.iter()
                                .map(|i| i.iov_len)
                                .max()
                                .unwrap_or_default()
                                .min(super::super::MAX_KERNEL_BUF_SIZE)
                        ]);
                    for iov in iovs {
                        if iov.iov_len == 0 {
                            continue;
                        }
                        let Ok(_iov_len) = isize::try_from(iov.iov_len) else {
                            return Err(Errno::EINVAL);
                        };
                        let size = files
                            .fs
                            .read(fd, &mut kernel_buffer.borrow_mut(), None)
                            .map_err(Errno::from)?;
                        iov.iov_base
                            .copy_from_slice(0, &kernel_buffer.borrow()[..size])
                            .ok_or(Errno::EFAULT)?;
                        total_read += size;
                        if size < iov.iov_len {
                            break;
                        }
                    }
                    Ok(total_read)
                },
                |fd| {
                    read_once_to_iovecs(iovs, |buf| {
                        self.global.receive(
                            &self.wait_cx(),
                            fd,
                            buf,
                            litebox_common_linux::ReceiveFlags::empty(),
                            None,
                        )
                    })
                },
                |fd| {
                    read_once_to_iovecs(iovs, |buf| {
                        self.global
                            .pipes
                            .read(&self.wait_cx(), fd, buf)
                            .map_err(Errno::from)
                    })
                },
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        let total_len = total_readv_len(iovs)?;
                        if total_len == 0 {
                            return Ok(0);
                        }
                        if total_len < size_of::<u64>() {
                            return Err(Errno::EINVAL);
                        }
                        let bytes = file.read(&self.wait_cx())?.to_le_bytes();
                        scatter_bytes_to_iovecs(iovs, &bytes)
                    })
                },
                |_fd| Err(Errno::EINVAL),
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        read_once_to_iovecs(iovs, |buf| {
                            file.recvfrom(
                                &self.wait_cx(),
                                buf,
                                litebox_common_linux::ReceiveFlags::empty(),
                                None,
                                &mut Vec::new(),
                            )
                        })
                    })
                },
            )
            .flatten()
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

fn total_readv_len(iovs: &[IoReadVec<MutPtr<u8>>]) -> Result<usize, Errno> {
    iovs.iter().try_fold(0usize, |total, iov| {
        let Ok(_iov_len) = isize::try_from(iov.iov_len) else {
            return Err(Errno::EINVAL);
        };
        total.checked_add(iov.iov_len).ok_or(Errno::EINVAL)
    })
}

fn total_writev_len(iovs: &[IoWriteVec<ConstPtr<u8>>]) -> Result<usize, Errno> {
    iovs.iter().try_fold(0usize, |total, iov| {
        let Ok(_iov_len) = isize::try_from(iov.iov_len) else {
            return Err(Errno::EINVAL);
        };
        total.checked_add(iov.iov_len).ok_or(Errno::EINVAL)
    })
}

fn alloc_zeroed_kernel_buf(len: usize) -> Result<alloc::vec::Vec<u8>, Errno> {
    let mut buf = alloc::vec::Vec::new();
    buf.try_reserve_exact(len).map_err(|_| Errno::ENOMEM)?;
    buf.resize(len, 0);
    Ok(buf)
}

fn scatter_bytes_to_iovecs(iovs: &[IoReadVec<MutPtr<u8>>], bytes: &[u8]) -> Result<usize, Errno> {
    let mut copied = 0;
    for iov in iovs {
        if copied == bytes.len() {
            break;
        }
        if iov.iov_len == 0 {
            continue;
        }
        let chunk_len = core::cmp::min(iov.iov_len, bytes.len() - copied);
        iov.iov_base
            .copy_from_slice(0, &bytes[copied..copied + chunk_len])
            .ok_or(Errno::EFAULT)?;
        copied += chunk_len;
    }
    Ok(copied)
}

fn read_once_to_iovecs<F>(iovs: &[IoReadVec<MutPtr<u8>>], read_fn: F) -> Result<usize, Errno>
where
    F: FnOnce(&mut [u8]) -> Result<usize, Errno>,
{
    let total_len = total_readv_len(iovs)?.min(super::super::MAX_KERNEL_BUF_SIZE);
    if total_len == 0 {
        return Ok(0);
    }
    let mut kernel_buf = alloc_zeroed_kernel_buf(total_len)?;
    let size = read_fn(&mut kernel_buf)?;
    scatter_bytes_to_iovecs(iovs, &kernel_buf[..size])
}

fn gather_iovecs(iovs: &[IoWriteVec<ConstPtr<u8>>]) -> Result<alloc::vec::Vec<u8>, Errno> {
    let total_len = total_writev_len(iovs)?.min(super::super::MAX_KERNEL_BUF_SIZE);
    let mut gathered = alloc::vec::Vec::new();
    gathered
        .try_reserve_exact(total_len)
        .map_err(|_| Errno::ENOMEM)?;
    let mut remaining = total_len;
    for iov in iovs {
        if remaining == 0 {
            break;
        }
        if iov.iov_len == 0 {
            continue;
        }
        let slice = iov
            .iov_base
            .to_owned_slice(iov.iov_len)
            .ok_or(Errno::EFAULT)?;
        let chunk_len = core::cmp::min(slice.len(), remaining);
        gathered.extend_from_slice(&slice[..chunk_len]);
        remaining -= chunk_len;
    }
    Ok(gathered)
}

fn write_once_from_iovecs<F>(iovs: &[IoWriteVec<ConstPtr<u8>>], write_fn: F) -> Result<usize, Errno>
where
    F: FnOnce(&[u8]) -> Result<usize, Errno>,
{
    let gathered = gather_iovecs(iovs)?;
    if gathered.is_empty() {
        return Ok(0);
    }
    write_fn(&gathered)
}

fn fcntl_status_flags<FS: ShimFS>(
    task: &Task<FS>,
    files: &FilesState<FS>,
    desc: usize,
) -> Result<OFlags, Errno> {
    macro_rules! getfl_from_metadata {
        ($fd:expr, $MetaType:path) => {
            Ok(task
                .global
                .litebox
                .descriptor_table()
                .with_metadata($fd, |$MetaType(flags)| *flags)
                .unwrap_or(OFlags::empty()))
        };
    }
    macro_rules! getfl_from_handle {
        ($fd:ident) => {{
            let handle = task
                .global
                .litebox
                .descriptor_table()
                .entry_handle($fd)
                .ok_or(Errno::EBADF)?;
            handle.with_entry(|file| Ok(file.get_status()))
        }};
    }
    files
        .run_on_raw_fd(
            desc,
            |fd| getfl_from_metadata!(fd, crate::StdioStatusFlags),
            |fd| getfl_from_metadata!(fd, crate::syscalls::net::SocketOFlags),
            |fd| getfl_from_metadata!(fd, crate::PipeStatusFlags),
            |fd| getfl_from_handle!(fd),
            |fd| getfl_from_handle!(fd),
            |fd| getfl_from_handle!(fd),
        )
        .flatten()
        .map(|flags| flags & OFlags::STATUS_FLAGS_MASK)
}

fn validate_fcntl_lock_fd(open_flags: OFlags) -> Result<OFlags, Errno> {
    if open_flags.contains(OFlags::PATH) {
        return Err(Errno::EBADF);
    }
    Ok(open_flags & (OFlags::WRONLY | OFlags::RDWR))
}

fn emulate_fcntl_getlk(
    lock: MutPtr<litebox_common_linux::Flock>,
    park_before_guest_write: impl FnOnce(),
) -> Result<u32, Errno> {
    let mut flock = lock.read_at_offset(0).ok_or(Errno::EFAULT)?;
    let lock_type =
        litebox_common_linux::FlockType::try_from(flock.type_).map_err(|_| Errno::EINVAL)?;
    if let litebox_common_linux::FlockType::Unlock = lock_type {
        return Err(Errno::EINVAL);
    }
    flock.type_ = litebox_common_linux::FlockType::Unlock as i16;
    park_before_guest_write();
    lock.write_at_offset(0, flock).ok_or(Errno::EFAULT)?;
    Ok(0)
}

fn emulate_fcntl_setlk(
    lock: ConstPtr<litebox_common_linux::Flock>,
    open_flags: OFlags,
) -> Result<u32, Errno> {
    let flock = lock.read_at_offset(0).ok_or(Errno::EFAULT)?;
    let lock_type =
        litebox_common_linux::FlockType::try_from(flock.type_).map_err(|_| Errno::EINVAL)?;
    let access = validate_fcntl_lock_fd(open_flags)?;
    if matches!(lock_type, litebox_common_linux::FlockType::ReadLock) && access == OFlags::WRONLY {
        return Err(Errno::EBADF);
    }
    if matches!(lock_type, litebox_common_linux::FlockType::WriteLock) && access == OFlags::empty()
    {
        return Err(Errno::EBADF);
    }
    Ok(0)
}

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `writev`
    pub fn sys_writev(
        &self,
        fd: i32,
        iovec: ConstPtr<IoWriteVec<ConstPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let iovs: &[IoWriteVec<ConstPtr<u8>>] =
            &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        let files = self.files.borrow();
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        let res = files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    let _position_guard = if matches!(
                        files.fs.fd_file_status(fd),
                        Ok(status) if status.file_type == litebox::fs::FileType::RegularFile
                    ) {
                        Some(files.file_position_lock.lock())
                    } else {
                        None
                    };
                    write_to_iovec(iovs, |buf: &[u8]| {
                        files.fs.write(fd, buf, None).map_err(Errno::from)
                    })
                },
                |fd| {
                    write_once_from_iovecs(iovs, |buf| {
                        self.global.sendto(
                            &self.wait_cx(),
                            fd,
                            buf,
                            litebox_common_linux::SendFlags::empty(),
                            None,
                        )
                    })
                },
                |fd| {
                    write_once_from_iovecs(iovs, |buf| {
                        self.global
                            .pipes
                            .write(&self.wait_cx(), fd, buf)
                            .map_err(Errno::from)
                    })
                },
                |fd| {
                    let total_len = total_writev_len(iovs)?;
                    if total_len == 0 {
                        return Ok(0);
                    }
                    let Some(first_iov) = iovs.first() else {
                        return Ok(0);
                    };
                    if first_iov.iov_len != size_of::<u64>() {
                        return Err(Errno::EINVAL);
                    }
                    let bytes = first_iov
                        .iov_base
                        .to_owned_slice(size_of::<u64>())
                        .ok_or(Errno::EFAULT)?;
                    let value: u64 =
                        u64::from_le_bytes(bytes.as_ref().try_into().map_err(|_| Errno::EINVAL)?);
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| file.write(&self.wait_cx(), value))
                },
                |_fd| Err(Errno::EINVAL),
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        write_once_from_iovecs(iovs, |buf| {
                            file.sendto(
                                self,
                                buf,
                                litebox_common_linux::SendFlags::empty(),
                                None,
                                Vec::new(),
                            )
                        })
                    })
                },
            )
            .flatten();
        if let Err(Errno::EPIPE) = res {
            self.send_signal(
                litebox_common_linux::signal::Signal::SIGPIPE,
                siginfo_kernel(litebox_common_linux::signal::Signal::SIGPIPE),
            );
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
        let status = self.files.borrow().fs.file_status(&*pathname)?;
        Self::check_access_mode(&status, mode)
    }

    /// Read the target of a symbolic link
    ///
    /// The caller must pass an absolute path.
    ///
    /// Note that this function only handles the following cases that we hardcoded:
    /// - `/proc/self/fd/<fd>`
    fn do_readlink(&self, fullpath: &str) -> Result<String, Errno> {
        if fullpath == "/proc/self/cwd" {
            let cwd = self.fs.borrow().cwd.read().clone();
            // Strip trailing slash (except for root "/") — Linux's
            // readlink("/proc/self/cwd") never includes one.
            let trimmed = cwd.trim_end_matches('/');
            return Ok(if trimmed.is_empty() {
                "/".into()
            } else {
                trimmed.into()
            });
        }
        if fullpath == "/proc/self/exe" {
            let exe = self.fs.borrow().exe_path.read().clone();
            if exe.is_empty() {
                return Err(Errno::ENOENT);
            }
            return Ok(exe);
        }
        if let Some(stripped) = fullpath.strip_prefix("/proc/self/fd/") {
            let fd = stripped.parse::<u32>().map_err(|_| Errno::EINVAL)?;
            if let 0..=2 = fd {
                let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
                let files = self.files.borrow();
                let rds = files.raw_descriptor_store.read();
                if let Ok(typed_fd) = rds.fd_from_raw_integer::<FS>(raw_fd) {
                    if let Ok(source_fd) =
                        self.global.litebox.descriptor_table().with_metadata(
                            typed_fd.as_ref(),
                            |crate::HostStdioSourceFd(source_fd)| *source_fd,
                        )
                    {
                        let stream = match source_fd {
                            0 => Some(litebox::platform::StdioStream::Stdin),
                            1 => Some(litebox::platform::StdioStream::Stdout),
                            2 => Some(litebox::platform::StdioStream::Stderr),
                            _ => None,
                        };
                        if let Some(stream) = stream
                            && self.global.platform.is_a_tty(stream)
                        {
                            // Return the actual host PTY path if available,
                            // so that ttyname_r() can discover and reopen
                            // the controlling terminal by its real device path.
                            if let Some(info) = self.global.platform.host_stdin_tty_device_info() {
                                return Ok(info.path);
                            }
                            return Ok("/dev/tty".to_string());
                        }
                        return Ok(match source_fd {
                            0 => "/dev/stdin".to_string(),
                            1 => "/dev/stdout".to_string(),
                            2 => "/dev/stderr".to_string(),
                            _ => files.fs.fd_path(typed_fd.as_ref()).ok_or(Errno::ENOENT)?,
                        });
                    }
                    if self
                        .global
                        .litebox
                        .descriptor_table()
                        .with_metadata(typed_fd.as_ref(), |_alias: &crate::HostTtyAlias| ())
                        .is_ok()
                    {
                        if let Some(info) = self.global.platform.host_stdin_tty_device_info() {
                            return Ok(info.path);
                        }
                        return Ok("/dev/tty".to_string());
                    }
                    // Also check for HostPtyDeviceFd (reopened via /dev/pts/N)
                    if self
                        .global
                        .litebox
                        .descriptor_table()
                        .with_metadata(typed_fd.as_ref(), |_: &HostPtyDeviceFd| ())
                        .is_ok()
                    {
                        if let Some(info) = self.global.platform.host_stdin_tty_device_info() {
                            return Ok(info.path);
                        }
                        return Ok("/dev/tty".to_string());
                    }
                }
                return Ok(match fd {
                    0 => "/dev/stdin".to_string(),
                    1 => "/dev/stdout".to_string(),
                    2 => "/dev/stderr".to_string(),
                    _ => unreachable!(),
                });
            } else {
                // Check for HostPtyDeviceFd or HostTtyAlias metadata on
                // non-stdio fds (e.g., fds reopened via /dev/pts/N or
                // /dev/tty) so readlink returns a consistent PTY path.
                let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
                let files = self.files.borrow();
                let rds = files.raw_descriptor_store.read();
                if let Ok(typed_fd) = rds.fd_from_raw_integer::<FS>(raw_fd) {
                    let dt = self.global.litebox.descriptor_table();
                    if dt
                        .with_metadata(typed_fd.as_ref(), |_: &HostPtyDeviceFd| ())
                        .is_ok()
                        && let Some(info) = self.global.platform.host_stdin_tty_device_info()
                    {
                        return Ok(info.path);
                    }
                    if dt
                        .with_metadata(typed_fd.as_ref(), |_: &crate::HostTtyAlias| ())
                        .is_ok()
                    {
                        return Ok("/dev/tty".to_string());
                    }
                    return files.fs.fd_path(typed_fd.as_ref()).ok_or(Errno::ENOENT);
                }
                return Err(Errno::EBADF);
            }
        }

        // Try the filesystem for symlink resolution
        let result = self.files.borrow().fs.read_link(fullpath);
        match result {
            Ok(target) => Ok(target),
            Err(e) => {
                use litebox::fs::errors::ReadLinkError;
                match e {
                    ReadLinkError::PathError(pe) => Err(Errno::from(pe)),
                    ReadLinkError::ClosedFd => Err(Errno::EBADF),
                    ReadLinkError::NotADirectory => Err(Errno::ENOTDIR),
                    // Not a symlink, or FS doesn't support symlinks.
                    ReadLinkError::NotASymlink | ReadLinkError::NotSupported => Err(Errno::EINVAL),
                    _ => Err(Errno::EIO),
                }
            }
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
        let fspath = FsPath::new_inner(dirfd, pathname, get_cwd, true)?;
        let path = match fspath {
            FsPath::Absolute { path } => {
                self.do_readlink(path.to_str().map_err(|_| Errno::EINVAL)?)
            }
            // Linux only resolves empty-path readlinkat() on an O_PATH|O_NOFOLLOW
            // symlink fd. The shim does not preserve symlink fd identity yet, so
            // valid fds fall back to ENOENT instead of resolving through the
            // original path; invalid fds still return EBADF.
            FsPath::Cwd => Err(Errno::ENOENT),
            FsPath::Fd(fd) => {
                let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
                let files = self.files.borrow();
                files.run_on_raw_fd(raw_fd, |_| (), |_| (), |_| (), |_| (), |_| (), |_| ())?;
                Err(Errno::ENOENT)
            }
            FsPath::FdRelative { fd, path } => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };

                let files = self.files.borrow();
                files.run_on_raw_fd(
                    raw_fd,
                    |dirfd| {
                        files.fs.readlink_at(dirfd, path).map_err(|e| match e {
                            litebox::fs::errors::ReadLinkError::NotASymlink
                            | litebox::fs::errors::ReadLinkError::NotSupported => Errno::EINVAL,
                            litebox::fs::errors::ReadLinkError::ClosedFd => Errno::EBADF,
                            litebox::fs::errors::ReadLinkError::NotADirectory => Errno::ENOTDIR,
                            litebox::fs::errors::ReadLinkError::PathError(pe) => Errno::from(pe),
                            _ => Errno::EIO,
                        })
                    },
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                )?
            }
        }?;
        let bytes = path.as_bytes();
        let min_len = core::cmp::min(buf.len(), bytes.len());
        buf[..min_len].copy_from_slice(&bytes[..min_len]);
        Ok(min_len)
    }
}

fn synthetic_symlink_stat(target_len: usize) -> FileStat {
    FileStat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 1,
        st_mode: ((litebox_common_linux::InodeType::SymLink as u32)
            | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
        .truncate(),
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_size: target_len,
        st_blksize: 4096,
        st_blocks: 0,
        ..Default::default()
    }
}

fn descriptor_stat<FS: ShimFS>(raw_fd: usize, task: &Task<FS>) -> Result<FileStat, Errno> {
    let uid = task.credentials.euid.truncate();
    let gid = task.credentials.egid.truncate();
    let mut fstat = task
        .files
        .borrow()
        .run_on_raw_fd(
            raw_fd,
            |fd| {
                task.files
                    .borrow()
                    .fs
                    .fd_file_status(fd)
                    .map(FileStat::from)
                    .map_err(Errno::from)
            },
            |fd| {
                let ino = get_or_assign_anon_ino(task, fd);
                Ok(FileStat {
                    st_dev: SOCKFS_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (litebox_common_linux::InodeType::Socket as u32
                        | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
                    .truncate(),
                    st_uid: uid,
                    st_gid: gid,
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
                let ino = get_or_assign_anon_ino(task, fd);
                Ok(FileStat {
                    st_dev: PIPEFS_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::NamedPipe as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            },
            |fd| {
                let ino = get_or_assign_anon_ino(task, fd);
                Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (Mode::RUSR | Mode::WUSR).bits().truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            },
            |fd| {
                let ino = get_or_assign_anon_ino(task, fd);
                Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (Mode::RUSR | Mode::WUSR).bits().truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 0,
                    st_blocks: 0,
                    ..Default::default()
                })
            },
            |fd| {
                let ino = get_or_assign_anon_ino(task, fd);
                Ok(FileStat {
                    st_dev: SOCKFS_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (litebox_common_linux::InodeType::Socket as u32
                        | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
                    .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            },
        )
        .flatten()?;

    // Override st_dev/st_ino/st_rdev for fds that should report the host PTY
    // identity. This applies to:
    // - Inherited stdin/stdout/stderr (have HostStdioSourceFd metadata)
    // - Fds opened via the host PTY device path (have HostPtyDeviceFd metadata)
    // The device FS internally reports rdev=0x500 (major 5) which keeps
    // classify_terminal() routing to HostStdio. This override only affects
    // what the guest sees via fstat/statx.
    if let Some(info) = task.global.platform.host_stdin_tty_device_info() {
        let files = task.files.borrow();
        let should_override = files.run_on_raw_fd(
            raw_fd,
            |fd| {
                let table = task.global.litebox.descriptor_table();
                // Check for HostPtyDeviceFd marker (reopened via /dev/pts/N)
                if table.with_metadata(fd, |_: &HostPtyDeviceFd| ()).is_ok() {
                    return true;
                }
                // Check for HostStdioSourceFd (inherited stdin/stdout/stderr)
                if let Ok(crate::HostStdioSourceFd(source_fd)) =
                    table.with_metadata(fd, |m: &crate::HostStdioSourceFd| *m)
                    && (0..=2).contains(&source_fd)
                    && task.global.platform.is_a_tty(match source_fd {
                        0 => litebox::platform::StdioStream::Stdin,
                        1 => litebox::platform::StdioStream::Stdout,
                        _ => litebox::platform::StdioStream::Stderr,
                    })
                {
                    return true;
                }
                // Check for HostTtyAlias (/dev/tty opens)
                table
                    .with_metadata(fd, |_: &crate::HostTtyAlias| ())
                    .is_ok()
            },
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| false,
        )?;
        if should_override {
            fstat.st_dev = info.dev.truncate();
            fstat.st_ino = info.ino.truncate();
            fstat.st_rdev = info.rdev.truncate();
        }
    }

    Ok(fstat)
}

/// Return a fresh inode number for an anonymous descriptor.
fn next_anon_ino() -> u64 {
    let ino = ANON_INO_COUNTER.fetch_add(1, Ordering::Relaxed);
    assert_ne!(ino, usize::MAX, "anonymous inode counter overflow");
    ino as u64
}

/// Retrieve the cached inode for an anonymous fd, or assign a new one.
///
/// The inode is stored as [`AnonIno`] entry metadata so that repeated `fstat`
/// calls on the same fd (or a `dup`'d alias) return a stable `st_ino`.
fn get_or_assign_anon_ino<FS: ShimFS, S: litebox::fd::FdEnabledSubsystem>(
    task: &Task<FS>,
    fd: &litebox::fd::TypedFd<S>,
) -> u64 {
    // Take the write lock upfront to avoid a TOCTOU race: two threads could
    // both observe "no metadata" under a read lock and each store a different
    // inode.
    let mut dt = task.global.litebox.descriptor_table_mut();
    if let Ok(ino) = dt.with_metadata::<S, AnonIno, _>(fd, |a| a.0) {
        return ino;
    }
    let ino = next_anon_ino();
    dt.set_entry_metadata(fd, AnonIno(ino));
    ino
}

pub(crate) fn get_file_descriptor_flags<FS: ShimFS>(
    raw_fd: usize,
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
    files.run_on_raw_fd(
        raw_fd,
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
    )
}

fn set_file_descriptor_flags<FS: ShimFS>(
    raw_fd: usize,
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

    files.run_on_raw_fd(
        raw_fd,
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
    )?;
    Ok(())
}

impl<FS: ShimFS> Task<FS> {
    /// Get the file status of `pathname`.
    ///
    /// The `pathname` must be absolute.
    fn do_stat(&self, pathname: impl path::Arg, follow_symlink: bool) -> Result<FileStat, Errno> {
        let normalized_path = pathname.normalized()?;
        if normalized_path.as_str() == "/proc/self/exe" {
            let exe = self.fs.borrow().exe_path.read().clone();
            if exe.is_empty() {
                return Err(Errno::ENOENT);
            }
            if !follow_symlink {
                let mut cached = PROC_SELF_EXE_INO.load(Ordering::Relaxed);
                if cached == 0 {
                    #[allow(clippy::cast_possible_truncation)]
                    let fresh = next_anon_ino() as usize;
                    match PROC_SELF_EXE_INO.compare_exchange(
                        0,
                        fresh,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => cached = fresh,
                        Err(winner) => cached = winner,
                    }
                }
                return Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: (cached as u64).truncate(),
                    st_mode: ((litebox_common_linux::InodeType::SymLink as u32)
                        | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
                    .truncate(),
                    st_size: exe.len(),
                    st_blksize: 4096,
                    st_blocks: 0,
                    st_nlink: 1,
                    st_uid: self.credentials.euid.truncate(),
                    st_gid: self.credentials.egid.truncate(),
                    ..Default::default()
                });
            }
            let status = self.files.borrow().fs.file_status(exe.as_str())?;
            return Ok(FileStat::from(status));
        }
        let fs_walks_follow_symlinks = self.files.borrow().fs.walks_follow_symlinks();
        if !follow_symlink && fs_walks_follow_symlinks {
            match self.do_readlink(normalized_path.as_str()) {
                Ok(target) => return Ok(synthetic_symlink_stat(target.len())),
                Err(Errno::EINVAL) => {}
                Err(err) => return Err(err),
            }
        }
        // Skip client-side symlink resolution when the FS backend follows
        // symlinks during walk (e.g., 9P with a canonicalizing broker).
        let is_host_pty = is_host_pty_device_path(normalized_path.as_str(), self.global.platform);
        let path = if follow_symlink && !fs_walks_follow_symlinks {
            self.canonicalize_path(normalized_path.as_str())?
        } else {
            normalized_path
        };
        let status = self.files.borrow().fs.file_status(path)?;
        let mut result = FileStat::from(status);

        // Override st_dev/st_ino/st_rdev for the host PTY path so that
        // stat("/dev/pts/N") matches fstat(0) — required by glibc ttyname_r's
        // is_mytty() verification. Skip when a sandbox PTY shadows the path
        // (the stat already returned sandbox PTY identity with major 136-143).
        if is_host_pty
            && (result.st_rdev >> 8) < 136
            && let Some(info) = self.global.platform.host_stdin_tty_device_info()
        {
            result.st_dev = info.dev.truncate();
            result.st_ino = info.ino.truncate();
            result.st_rdev = info.rdev.truncate();
        }

        Ok(result)
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
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        descriptor_stat(raw_fd, self)
    }

    /// Handle syscall `newfstatat`
    pub fn sys_newfstatat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<FileStat, Errno> {
        let follow_symlinks = !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW);
        let allow_empty = flags.contains(AtFlags::AT_EMPTY_PATH);
        let supported_flags =
            AtFlags::AT_EMPTY_PATH | AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_NO_AUTOMOUNT;
        let unsupported = flags & supported_flags.complement();
        if !unsupported.is_empty() {
            return Err(Errno::EINVAL);
        }

        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new_inner(dirfd, pathname, get_cwd, allow_empty)?;
        let files = self.files.borrow();
        let fstat: FileStat = match fs_path {
            FsPath::Absolute { path } => self.do_stat(path, follow_symlinks)?,
            FsPath::Cwd => files.fs.file_status(get_cwd())?.into(),
            FsPath::Fd(fd) => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                descriptor_stat(raw_fd, self)?
            }
            FsPath::FdRelative { fd, path } => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                if !follow_symlinks && files.fs.walks_follow_symlinks() {
                    let mut target = [0u8; PATH_MAX];
                    let Ok(fd_i32) = i32::try_from(fd) else {
                        return Err(Errno::EBADF);
                    };
                    match self.sys_readlinkat(fd_i32, path.clone(), &mut target) {
                        Ok(len) => return Ok(synthetic_symlink_stat(len)),
                        Err(Errno::EINVAL) => {}
                        Err(err) => return Err(err),
                    }
                }

                files.run_on_raw_fd(
                    raw_fd,
                    |dirfd| {
                        files
                            .fs
                            .stat_at(dirfd, path, follow_symlinks)
                            .map(FileStat::from)
                            .map_err(Errno::from)
                    },
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                )??
            }
        };
        Ok(fstat)
    }

    pub(crate) fn sys_fcntl(
        &self,
        fd: i32,
        arg: FcntlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        let Ok(desc) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match arg {
            FcntlArg::GETFD => Ok(get_file_descriptor_flags(desc, &self.global, &files)?.bits()),
            FcntlArg::SETFD(flags) => {
                set_file_descriptor_flags(desc, &self.global, &files, flags).map(|()| 0)
            }
            FcntlArg::GETFL => Ok(fcntl_status_flags(self, &files, desc)?.bits()),
            FcntlArg::SETFL(flags) => {
                let setfl_mask = OFlags::APPEND
                    | OFlags::NONBLOCK
                    | OFlags::NDELAY
                    | OFlags::DIRECT
                    | OFlags::NOATIME;
                let flags = flags & setfl_mask;
                macro_rules! toggle_flags {
                    ($fd:ident) => {{
                        // TODO: Consider shared metadata table?
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle($fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags & setfl_mask, true);
                            file.set_status(flags.complement() & setfl_mask, false);
                        });
                    }};
                }
                macro_rules! setfl_in_metadata {
                    ($fd:expr, $MetaType:path, $no_metadata_msg:expr) => {
                        setfl_in_metadata!($fd, $MetaType, $no_metadata_msg, |diff: OFlags| {
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                        })
                    };
                    ($fd:expr, $MetaType:path, $no_metadata_msg:expr, $check_diff:expr) => {
                        self.global
                            .litebox
                            .descriptor_table_mut()
                            .with_metadata_mut($fd, |$MetaType(f)| {
                                let diff = (*f & setfl_mask) ^ flags;
                                $check_diff(diff);
                                f.toggle(diff);
                            })
                            .map_err(|err| match err {
                                MetadataError::ClosedFd => Errno::EBADF,
                                MetadataError::NoSuchMetadata => $no_metadata_msg,
                            })
                    };
                }
                files.run_on_raw_fd(
                    desc,
                    |fd| {
                        let new_flags = self
                            .global
                            .litebox
                            .descriptor_table_mut()
                            .with_metadata_mut(fd, |crate::StdioStatusFlags(f)| {
                                let diff = (*f & setfl_mask) ^ flags;
                                if diff
                                    .intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME)
                                {
                                    log_unsupported!("unsupported flags");
                                }
                                f.toggle(diff);
                                *f
                            })
                            .map_err(|err| match err {
                                MetadataError::ClosedFd | MetadataError::NoSuchMetadata => {
                                    Errno::EBADF
                                }
                            })?;
                        files
                            .fs
                            .set_open_status_flags(fd, new_flags)
                            .map_err(|_| Errno::EBADF)
                    },
                    |fd| {
                        setfl_in_metadata!(
                            fd,
                            crate::syscalls::net::SocketOFlags,
                            unreachable!("all sockets have SocketOFlags when created")
                        )
                    },
                    |fd| {
                        // Update the actual pipe non-blocking behavior
                        self.global
                            .pipes
                            .update_flags(
                                fd,
                                litebox::pipes::Flags::NON_BLOCKING,
                                flags.intersects(OFlags::NONBLOCK),
                            )
                            .map_err(Errno::from)?;
                        // Record all status flags in metadata for F_GETFL
                        setfl_in_metadata!(
                            fd,
                            crate::PipeStatusFlags,
                            unreachable!("all pipes have PipeStatusFlags when created"),
                            |_| {}
                        )
                    },
                    |fd| {
                        toggle_flags!(fd);
                        Ok(())
                    },
                    |fd| {
                        toggle_flags!(fd);
                        Ok(())
                    },
                    |fd| {
                        toggle_flags!(fd);
                        Ok(())
                    },
                )??;
                Ok(0)
            }
            FcntlArg::GETLK(lock) => {
                let open_flags = fcntl_status_flags(self, &files, desc)?;
                validate_fcntl_lock_fd(open_flags)?;
                emulate_fcntl_getlk(lock, || {})
            }
            FcntlArg::SETLK(lock) | FcntlArg::SETLKW(lock) => {
                let open_flags = fcntl_status_flags(self, &files, desc)?;
                emulate_fcntl_setlk(lock, open_flags)
            }
            FcntlArg::DUPFD { cloexec, min_fd } => {
                let max_fd = self
                    .process()
                    .limits
                    .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE);
                if min_fd as usize >= max_fd {
                    return Err(Errno::EINVAL);
                }
                let new_file = self.do_dup_at_or_above(
                    desc,
                    if cloexec {
                        OFlags::CLOEXEC
                    } else {
                        OFlags::empty()
                    },
                    min_fd as usize,
                )?;
                debug_assert!(new_file >= min_fd as usize);
                Ok(new_file.try_into().unwrap())
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

        {
            let initial_status = OFlags::from(pipe_flags);
            let mut dt = self.global.litebox.descriptor_table_mut();
            let old = dt.set_entry_metadata(
                &writer,
                crate::PipeStatusFlags(initial_status | OFlags::WRONLY),
            );
            assert!(old.is_none());
            let old = dt.set_entry_metadata(
                &reader,
                crate::PipeStatusFlags(initial_status | OFlags::RDONLY),
            );
            assert!(old.is_none());
        }

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
        let wr_raw_fd = files.insert_raw_fd(writer).map_err(|writer| {
            self.global.pipes.close(&writer).unwrap();
            Errno::EMFILE
        })?;
        let rd_raw_fd = files.insert_raw_fd(reader).map_err(|reader| {
            let writer = files
                .raw_descriptor_store
                .write()
                .fd_consume_raw_integer(wr_raw_fd)
                .unwrap();
            self.global.pipes.close(&writer).unwrap();
            self.global.pipes.close(&reader).unwrap();
            Errno::EMFILE
        })?;
        Ok((rd_raw_fd.try_into().unwrap(), wr_raw_fd.try_into().unwrap()))
    }

    pub fn sys_eventfd2(&self, initval: u32, flags: EfdFlags) -> Result<u32, Errno> {
        if flags
            .contains((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
        {
            return Err(Errno::EINVAL);
        }

        let eventfd = super::eventfd::EventFile::new(u64::from(initval), flags);
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::eventfd::EventfdSubsystem>(eventfd);
        if flags.contains(EfdFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
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

    /// Forward a terminal ioctl to the host via the platform's semantic
    /// terminal methods.
    ///
    /// Maps the fd's device type to the corresponding host stdio stream and
    /// calls `get_terminal_attributes`, `set_terminal_attributes`,
    /// `get_window_size`, or `set_window_size` as appropriate.
    fn host_stdio_stream_for_fd(
        &self,
        fs: &FS,
        fd: &TypedFd<FS>,
    ) -> Result<litebox::platform::StdioStream, Errno> {
        use litebox::platform::StdioStream;

        // Use device-FS inode numbers to guess which host stdio stream this fd
        // corresponds to.  These constants come from STDIN_NODE_INFO (ino=9),
        // STDOUT_NODE_INFO (ino=10), STDERR_NODE_INFO (ino=11), and
        // TTY_NODE_INFO (ino=12) in litebox/src/fs/devices.rs.
        let status = fs.fd_file_status(fd).map_err(|_| Errno::EBADF)?;
        #[allow(clippy::match_same_arms)]
        let preferred = match status.node_info.ino {
            9 => StdioStream::Stdin,
            10 => StdioStream::Stdout,
            11 => StdioStream::Stderr,
            // /dev/tty (ino=12) and anything unknown — try stdin first since
            // interactive programs typically read from it.
            _ => StdioStream::Stdin,
        };

        if self.global.platform.is_a_tty(preferred) {
            return Ok(preferred);
        }

        // Fallback: probe all three streams to find one that is actually a TTY.
        [StdioStream::Stdin, StdioStream::Stdout, StdioStream::Stderr]
            .into_iter()
            .find(|s| self.global.platform.is_a_tty(*s))
            .ok_or(Errno::ENOTTY)
    }

    fn host_tty_session_id(&self) -> Result<litebox::process::SessionId, Errno> {
        self.global
            .litebox
            .process_registry()
            .get_sid(self.process_id)
            .ok_or(Errno::ESRCH)
    }

    fn set_host_tty_foreground_pgrp(&self, pgrp: i32) -> Result<(), Errno> {
        use litebox::process::ProcessGroupId;

        if pgrp <= 0 {
            return Err(Errno::EINVAL);
        }
        let pgid = ProcessGroupId(u32::try_from(pgrp).map_err(|_| Errno::EINVAL)?);
        let group_exists = self
            .global
            .litebox
            .process_registry()
            .process_group_exists_in_session(self.process_id, pgid)
            .ok_or(Errno::ESRCH)?;
        if !group_exists {
            return Err(Errno::EPERM);
        }
        *self.global.host_tty_foreground_pgrp.lock() = pgid;
        Ok(())
    }

    fn host_stdio_ioctl(
        &self,
        fs: &FS,
        fd: &TypedFd<FS>,
        arg: &IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        use litebox::platform::{SetTermiosWhen, StdioIoctlError};

        /// Map a `StdioIoctlError` to an `Errno`.
        fn ioctl_err_to_errno(e: StdioIoctlError) -> Errno {
            match e {
                StdioIoctlError::NotATerminal => Errno::ENOTTY,
                _ => Errno::EIO,
            }
        }

        let stream = self.host_stdio_stream_for_fd(fs, fd)?;

        match arg {
            IoctlArg::TCGETS(termios_ptr) => {
                // Non-init processes may have a per-process shadow termios
                // from a silently-accepted TCSETS. Return it so TCGETS
                // reflects what the caller set.
                let attrs = if self.process_id == litebox::process::ProcessId::INIT {
                    None
                } else {
                    self.global
                        .host_tty_shadow_termios
                        .lock()
                        .get(&self.process_id)
                        .cloned()
                };
                let attrs = attrs.map_or_else(
                    || {
                        self.global
                            .platform
                            .get_terminal_attributes(stream)
                            .map_err(ioctl_err_to_errno)
                    },
                    Ok,
                )?;
                termios_ptr
                    .write_at_offset(
                        0,
                        litebox_common_linux::Termios {
                            c_iflag: attrs.c_iflag,
                            c_oflag: attrs.c_oflag,
                            c_cflag: attrs.c_cflag,
                            c_lflag: attrs.c_lflag,
                            c_line: attrs.c_line,
                            c_cc: attrs.c_cc,
                        },
                    )
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TCSETS(termios_ptr) => {
                let t: litebox_common_linux::Termios =
                    termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let attrs = litebox::platform::TerminalAttributes {
                    c_iflag: t.c_iflag,
                    c_oflag: t.c_oflag,
                    c_cflag: t.c_cflag,
                    c_lflag: t.c_lflag,
                    c_line: t.c_line,
                    c_cc: t.c_cc,
                };
                // Only the init process may change the real host terminal
                // attributes. Child processes update a shadow so TCGETS
                // reflects the change, but the real terminal is untouched.
                if self.process_id != litebox::process::ProcessId::INIT {
                    self.global
                        .host_tty_shadow_termios
                        .lock()
                        .insert(self.process_id, attrs);
                    return Ok(0);
                }
                self.global
                    .platform
                    .set_terminal_attributes(stream, &attrs, SetTermiosWhen::Now)
                    .map_err(ioctl_err_to_errno)?;
                // Clear stale shadow so non-init TCGETS sees the new real state.
                self.global.host_tty_shadow_termios.lock().clear();
                Ok(0)
            }
            IoctlArg::TCSETSW(termios_ptr) => {
                let t: litebox_common_linux::Termios =
                    termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let attrs = litebox::platform::TerminalAttributes {
                    c_iflag: t.c_iflag,
                    c_oflag: t.c_oflag,
                    c_cflag: t.c_cflag,
                    c_lflag: t.c_lflag,
                    c_line: t.c_line,
                    c_cc: t.c_cc,
                };
                if self.process_id != litebox::process::ProcessId::INIT {
                    self.global
                        .host_tty_shadow_termios
                        .lock()
                        .insert(self.process_id, attrs);
                    return Ok(0);
                }
                self.global
                    .platform
                    .set_terminal_attributes(stream, &attrs, SetTermiosWhen::AfterDrain)
                    .map_err(ioctl_err_to_errno)?;
                self.global.host_tty_shadow_termios.lock().clear();
                Ok(0)
            }
            IoctlArg::TCSETSF(termios_ptr) => {
                let t: litebox_common_linux::Termios =
                    termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let attrs = litebox::platform::TerminalAttributes {
                    c_iflag: t.c_iflag,
                    c_oflag: t.c_oflag,
                    c_cflag: t.c_cflag,
                    c_lflag: t.c_lflag,
                    c_line: t.c_line,
                    c_cc: t.c_cc,
                };
                if self.process_id != litebox::process::ProcessId::INIT {
                    self.global
                        .host_tty_shadow_termios
                        .lock()
                        .insert(self.process_id, attrs);
                    return Ok(0);
                }
                self.global
                    .platform
                    .set_terminal_attributes(stream, &attrs, SetTermiosWhen::AfterDrainFlushInput)
                    .map_err(ioctl_err_to_errno)?;
                self.global.host_tty_shadow_termios.lock().clear();
                Ok(0)
            }
            IoctlArg::TIOCGWINSZ(ws_ptr) => {
                let size = self
                    .global
                    .platform
                    .get_window_size(stream)
                    .map_err(ioctl_err_to_errno)?;
                ws_ptr
                    .write_at_offset(
                        0,
                        litebox_common_linux::Winsize {
                            row: size.rows,
                            col: size.cols,
                            xpixel: size.xpixel,
                            ypixel: size.ypixel,
                        },
                    )
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCSWINSZ(ws_ptr) => {
                let ws: litebox_common_linux::Winsize =
                    ws_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let size = litebox::platform::WindowSize {
                    rows: ws.row,
                    cols: ws.col,
                    xpixel: ws.xpixel,
                    ypixel: ws.ypixel,
                };
                self.global
                    .platform
                    .set_window_size(stream, &size)
                    .map_err(ioctl_err_to_errno)?;
                Ok(0)
            }
            IoctlArg::TIOCGPGRP(pgrp) => {
                // Return the caller's own pgid rather than the shared
                // host_tty_foreground_pgrp.  After setsid() the child's
                // pgid diverges from the init-owned foreground value, and
                // /dev/tty always routes here (major 5), so returning the
                // stored global would make the child think it's in the
                // background.  Returning the caller's pgid guarantees
                // tcgetpgrp() == getpgrp() for every process.
                let caller_pgid = i32::try_from(self.sys_getpgid(0).unwrap_or(1)).unwrap_or(1);
                pgrp.write_at_offset(0, caller_pgid).ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCGSID(sid) => {
                let session_id = i32::try_from(self.host_tty_session_id()?.as_u32())
                    .map_err(|_| Errno::EINVAL)?;
                sid.write_at_offset(0, session_id).ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCSPGRP(pgrp) => {
                let foreground_pgrp = pgrp.read_at_offset(0).ok_or(Errno::EFAULT)?;
                self.set_host_tty_foreground_pgrp(foreground_pgrp)?;
                Ok(0)
            }
            // These are no-ops for stdio: TIOCSCTTY (already controlling terminal),
            // TIOCNOTTY (detach), TIOCSPTLK (unlock PTY).
            IoctlArg::TIOCSCTTY | IoctlArg::TIOCNOTTY | IoctlArg::TIOCSPTLK(_) => Ok(0),
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
                            c_line: stored.c_line,
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
                let stored = litebox::platform::TerminalAttributes {
                    c_iflag: t.c_iflag,
                    c_oflag: t.c_oflag,
                    c_cflag: t.c_cflag,
                    c_lflag: t.c_lflag,
                    c_line: t.c_line,
                    c_cc: t.c_cc,
                };
                if !fs.set_pty_termios(fd, stored) {
                    return Err(Errno::ENOTTY);
                }
                Ok(0)
            }
            IoctlArg::TIOCSWINSZ(_) | IoctlArg::TIOCSPTLK(_) | IoctlArg::TIOCNOTTY => Ok(0),
            IoctlArg::TIOCSCTTY => {
                // On real Linux, TIOCSCTTY sets the controlling terminal and
                // initialises the foreground pgrp to the caller's pgid. Mirror
                // that here so tcgetpgrp() returns the right value.
                let pgid = i32::try_from(self.sys_getpgid(0).unwrap_or(1)).unwrap_or(1);
                let _ = fs.set_pty_foreground_pgrp(fd, pgid);
                Ok(0)
            }
            IoctlArg::TIOCSPGRP(pgrp_ptr) => {
                let pgrp: i32 = pgrp_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                if pgrp <= 0 {
                    return Err(Errno::EINVAL);
                }
                if !fs.set_pty_foreground_pgrp(fd, pgrp) {
                    return Err(Errno::ENOTTY);
                }
                Ok(0)
            }
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
                if !(136..=143).contains(&major) {
                    return Err(Errno::ENOTTY);
                }
                // Recover the full PTY index: major 136 holds indices
                // 0-255, major 137 holds 256-511, etc.
                let idx = u32::try_from((major - 136) * 256 + (rdev.get() & 0xFF))
                    .map_err(|_| Errno::ENOTTY)?;
                ptn.write_at_offset(0, idx).ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCGPGRP(pgrp) => {
                // Always return the caller's own pgid.  This avoids a race
                // between the parent setting the PTY foreground pgrp (via
                // TIOCSPGRP on the master) and the child checking it (via
                // TIOCGPGRP on the slave): with vfork the parent can only
                // call tcsetpgrp *after* the child execs, but bash checks
                // tcgetpgrp during early init, before the parent had a chance
                // to call setpgid+tcsetpgrp.  Returning the caller's pgid
                // guarantees tcgetpgrp() == getpgrp() so shells always see
                // themselves in the foreground.
                let value = i32::try_from(self.sys_getpgid(0).unwrap_or(1)).unwrap_or(1);
                pgrp.write_at_offset(0, value).ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    /// Handle syscall `ioctl`
    pub fn sys_ioctl(
        &self,
        fd: i32,
        arg: IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        let Ok(desc) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match arg {
            IoctlArg::FIONREAD(out) => {
                // Return the number of bytes available to read.
                files
                    .run_on_raw_fd(
                        desc,
                        |file_fd| {
                            let available = match self.classify_terminal(&files.fs, file_fd)? {
                                TerminalKind::HostStdio => self
                                    .global
                                    .platform
                                    .get_terminal_input_bytes(
                                        self.host_stdio_stream_for_fd(&files.fs, file_fd)?,
                                    )
                                    .map_err(|e| match e {
                                        litebox::platform::StdioIoctlError::NotATerminal => {
                                            Errno::ENOTTY
                                        }
                                        litebox::platform::StdioIoctlError::OsError(_) => {
                                            Errno::EIO
                                        }
                                        _ => Errno::EIO,
                                    })?,
                                TerminalKind::Pty | TerminalKind::NotTerminal => {
                                    // Known limitation: Linux returns st_size - offset for
                                    // regular files, but we don't track the current position
                                    // here.  ENOTTY is safe since most callers only use
                                    // FIONREAD on terminals and sockets.
                                    return Err(Errno::ENOTTY);
                                }
                            };
                            let available = i32::try_from(available).unwrap_or(i32::MAX);
                            out.write_at_offset(0, available).ok_or(Errno::EFAULT)?;
                            Ok(0u32)
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
                        |_fd| Err(Errno::ENOTTY),
                        |_fd| Err(Errno::ENOTTY),
                        |_fd| Err(Errno::ENOTTY),
                    )
                    .flatten()
            }
            IoctlArg::FIONBIO(arg) => {
                let val = arg.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let files = self.files.borrow();
                files
                    .run_on_raw_fd(
                        desc,
                        |file_fd| {
                            let result = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .with_metadata_mut(file_fd, |crate::StdioStatusFlags(flags)| {
                                    flags.set(OFlags::NONBLOCK, val != 0);
                                    *flags
                                });
                            match result {
                                Ok(new_flags) => files
                                    .fs
                                    .set_open_status_flags(file_fd, new_flags)
                                    .map_err(|_| Errno::EBADF)?,
                                Err(MetadataError::ClosedFd) => return Err(Errno::EBADF),
                                Err(MetadataError::NoSuchMetadata) => {
                                    // Non-stdio file FD; non-blocking is irrelevant for
                                    // in-memory files, so silently succeed.
                                }
                            }
                            Ok(())
                        },
                        |socket_fd| {
                            if let Err(e) = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .with_metadata_mut(
                                    socket_fd,
                                    |crate::syscalls::net::SocketOFlags(flags)| {
                                        flags.set(OFlags::NONBLOCK, val != 0);
                                    },
                                )
                            {
                                match e {
                                    MetadataError::ClosedFd => return Err(Errno::EBADF),
                                    MetadataError::NoSuchMetadata => unreachable!(),
                                }
                            }
                            Ok(())
                        },
                        |fd| {
                            self.global
                                .pipes
                                .update_flags(fd, litebox::pipes::Flags::NON_BLOCKING, val != 0)
                                .map_err(Errno::from)
                        },
                        |fd| {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                file.set_status(OFlags::NONBLOCK, val != 0);
                            });
                            Ok(())
                        },
                        |fd| {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                file.set_status(OFlags::NONBLOCK, val != 0);
                            });
                            Ok(())
                        },
                        |fd| {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                file.set_status(OFlags::NONBLOCK, val != 0);
                            });
                            Ok(())
                        },
                    )
                    .flatten()?;
                Ok(0)
            }
            IoctlArg::FIOCLEX => files.run_on_raw_fd(
                desc,
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
            )?,
            IoctlArg::FIONCLEX => files.run_on_raw_fd(
                desc,
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                },
            )?,
            IoctlArg::TIOCGPTPEER(open_flags) => {
                // TIOCGPTPEER: open the slave side of a PTY master, returning a new fd.
                // The argument contains O_RDWR|O_NOCTTY or similar open flags.
                //
                // We must open the slave through the device FS directly rather
                // than via sys_open("/dev/pts/N"), because the layered FS might
                // route /dev/pts/N to the 9P broker (host filesystem) instead of
                // the sandbox's PTY manager — especially when the host's terminal
                // happens to be /dev/pts/N.
                //
                // Note: we check major >= 136 which matches both masters and
                // slaves.  In practice this is harmless — calling TIOCGPTPEER on
                // a slave just re-opens the same slave.  A stricter check would
                // require the device FS to distinguish master vs slave, which is
                // not currently exposed.
                let slave_fd = files.run_on_raw_fd(
                    desc,
                    |file_fd| {
                        let status = files.fs.fd_file_status(file_fd).map_err(|_| Errno::EBADF)?;
                        let rdev = status.node_info.rdev.ok_or(Errno::ENOTTY)?;
                        let major = rdev.get() >> 8;
                        if major < 136 {
                            return Err(Errno::ENOTTY);
                        }
                        // Recover the full PTY index: major 136 holds indices
                        // 0-255, major 137 holds 256-511, etc.
                        let idx = u32::try_from((major - 136) * 256 + (rdev.get() & 0xFF))
                            .map_err(|_| Errno::ENOTTY)?;
                        let oflags =
                            OFlags::from_bits_truncate(u32::try_from(open_flags).unwrap_or(0));
                        let slave_path = alloc::format!("/dev/pts/{idx}");
                        // Strip O_CLOEXEC before passing to the FS layer — the
                        // layered FS does not support it (panics). CLOEXEC is
                        // handled as fd-level metadata after insert.
                        files
                            .fs
                            .open(
                                slave_path.as_str(),
                                oflags - OFlags::CLOEXEC,
                                litebox::fs::Mode::empty(),
                            )
                            .map_err(|_| Errno::EIO)
                    },
                    |_| Err(Errno::ENOTTY),
                    |_| Err(Errno::ENOTTY),
                    |_| Err(Errno::ENOTTY),
                    |_| Err(Errno::ENOTTY),
                    |_| Err(Errno::ENOTTY),
                )??;
                drop(files);
                let files = self.files.borrow();
                let oflags = OFlags::from_bits_truncate(u32::try_from(open_flags).unwrap_or(0));
                {
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    let None = dt.set_entry_metadata(
                        &slave_fd,
                        crate::StdioStatusFlags(oflags & OFlags::STATUS_FLAGS_MASK),
                    ) else {
                        unreachable!()
                    };
                    // Propagate O_CLOEXEC to fd-level metadata so close_on_exec
                    // sees it (the device FS only stores status flags, not
                    // descriptor flags).
                    if oflags.contains(OFlags::CLOEXEC) {
                        dt.set_fd_metadata(
                            &slave_fd,
                            litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                        );
                    }
                }
                let raw_fd = files.insert_raw_fd(slave_fd).map_err(|fd| {
                    let _ = files.fs.close(&fd);
                    Errno::EMFILE
                })?;
                Ok(u32::try_from(raw_fd).unwrap_or(u32::MAX))
            }
            IoctlArg::TCGETS(..)
            | IoctlArg::TCSETS(..)
            | IoctlArg::TCSETSW(..)
            | IoctlArg::TCSETSF(..)
            | IoctlArg::TIOCGPTN(..)
            | IoctlArg::TIOCSPTLK(..)
            | IoctlArg::TIOCSCTTY
            | IoctlArg::TIOCNOTTY
            | IoctlArg::TIOCGSID(..)
            | IoctlArg::TIOCGPGRP(..)
            | IoctlArg::TIOCSPGRP(..)
            | IoctlArg::TIOCGWINSZ(..)
            | IoctlArg::TIOCSWINSZ(..) => files.run_on_raw_fd(
                desc,
                |term_fd| match self.classify_terminal(&files.fs, term_fd)? {
                    TerminalKind::HostStdio => self.host_stdio_ioctl(&files.fs, term_fd, &arg),
                    TerminalKind::Pty => self.pty_ioctl(&files.fs, term_fd, &arg),
                    TerminalKind::NotTerminal => Err(Errno::ENOTTY),
                },
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
            )?,
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
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::epoll::EpollSubsystem<FS>>(epoll_file);
        if flags.contains(EpollCreateFlags::EPOLL_CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
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

        let epoll_fd = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::epoll::EpollSubsystem<FS>>(epfd as usize)
            .map_err(|_| Errno::EBADF)?;
        let file_descriptor =
            super::epoll::EpollDescriptor::try_from(&self.global, &files, fd as usize)?;

        let event_ptr = event;
        let event = if op == litebox_common_linux::EpollOp::EpollCtlDel {
            None
        } else {
            Some(event_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?)
        };
        let handle = self
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&epoll_fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(|entry| {
            entry.epoll_ctl(&self.global, &*files.fs, op, fd, &file_descriptor, event)
        })
    }

    /// Handle syscall `epoll_pwait`
    pub fn sys_epoll_pwait(
        &self,
        epfd: i32,
        events: MutPtr<litebox_common_linux::EpollEvent>,
        maxevents: u32,
        timeout: TimeParam<Platform>,
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
        let timeout = timeout.read()?;
        let handle = {
            let files = self.files.borrow();
            {
                let Ok(raw_fd) = usize::try_from(epfd) else {
                    if let Some(old) = saved_mask {
                        self.signals.set_blocked(old);
                    }
                    return Err(Errno::EBADF);
                };
                let Ok(fd) =
                    files
                        .raw_descriptor_store
                        .read()
                        .fd_from_raw_integer::<crate::syscalls::epoll::EpollSubsystem<FS>>(raw_fd)
                else {
                    if let Some(old) = saved_mask {
                        self.signals.set_blocked(old);
                    }
                    return Err(Errno::EBADF);
                };
                let Some(h) = self.global.litebox.descriptor_table().entry_handle(&fd) else {
                    if let Some(old) = saved_mask {
                        self.signals.set_blocked(old);
                    }
                    return Err(Errno::EBADF);
                };
                h
            }
        };
        let result = handle.with_entry(|epoll_file| {
            match epoll_file.wait(
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
            }
        });

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
        // XXX: semantic issue likely should be fixed here to make sure EBADF is triggered early
        // enough if needed. Previously, `file_table_len` used to be
        // `self.files.borrow().file_descriptors.read().len()` before `file_descriptors` was
        // removed to clean up the table handling.
        let file_table_len = usize::MAX;
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

    fn do_dup(&self, file: usize, flags: OFlags) -> Result<usize, Errno> {
        self.do_dup_inner(file, flags, None, None)
    }

    fn do_dup_at_or_above(
        &self,
        file: usize,
        flags: OFlags,
        min_fd: usize,
    ) -> Result<usize, Errno> {
        self.do_dup_inner(file, flags, None, Some(min_fd))
    }

    fn do_dup_inner(
        &self,
        file: usize,
        flags: OFlags,
        target: Option<usize>,
        min_fd: Option<usize>,
    ) -> Result<usize, Errno> {
        fn dup<FS: ShimFS, S: FdEnabledSubsystem>(
            global: &GlobalState<FS>,
            files: &FilesState<FS>,
            fd: &TypedFd<S>,
            close_on_exec: bool,
            target: Option<usize>,
            min_fd: Option<usize>,
        ) -> Result<usize, Errno> {
            let mut dt = global.litebox.descriptor_table_mut();
            let fd: TypedFd<_> = dt.duplicate(fd).ok_or(Errno::EBADF)?;
            if close_on_exec {
                let old = dt.set_fd_metadata(&fd, FileDescriptorFlags::FD_CLOEXEC);
                assert!(old.is_none());
            }
            let mut rds = files.raw_descriptor_store.write();
            if let Some(target) = target {
                if !rds.fd_into_specific_raw_integer(fd, target) {
                    return Err(Errno::EBADF);
                }
                Ok(target)
            } else if let Some(min_fd) = min_fd {
                #[allow(clippy::maybe_infinite_iter)]
                let raw_fd = (min_fd..)
                    .find(|&raw_fd| !rds.is_alive(raw_fd))
                    .expect("raw fd search should always find a slot");
                let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
                assert!(success);
                Ok(raw_fd)
            } else {
                Ok(rds.fd_into_raw_integer(fd))
            }
        }
        let close_on_exec = flags.contains(OFlags::CLOEXEC);
        let files = self.files.borrow();
        let new_fd = files.run_on_raw_fd(
            file,
            |fd| dup(&self.global, &files, fd, close_on_exec, target, min_fd),
            |fd| dup(&self.global, &files, fd, close_on_exec, target, min_fd),
            |fd| dup(&self.global, &files, fd, close_on_exec, target, min_fd),
            |fd| dup(&self.global, &files, fd, close_on_exec, target, min_fd),
            |fd| dup(&self.global, &files, fd, close_on_exec, target, min_fd),
            |fd| dup(&self.global, &files, fd, close_on_exec, target, min_fd),
        )??;
        if target.is_none() {
            let max_fd = self
                .process()
                .limits
                .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE);
            if new_fd >= max_fd {
                self.do_close(new_fd)?;
                return Err(Errno::EMFILE);
            }
        }
        files.duplicate_inotify_fd(file, new_fd);
        Ok(new_fd)
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
        let oldfd_usize = usize::try_from(oldfd).or(Err(Errno::EBADF))?;
        if !self
            .files
            .borrow()
            .raw_descriptor_store
            .read()
            .is_alive(oldfd_usize)
        {
            return Err(Errno::EBADF);
        }
        if let Some(newfd) = newfd {
            // dup2/dup3
            let Ok(newfd) = u32::try_from(newfd) else {
                return Err(Errno::EBADF);
            };
            if oldfd == newfd {
                if flags.is_some() {
                    // dup3(fd, fd) always returns EINVAL per POSIX.
                    return Err(Errno::EINVAL);
                }
                // dup2(fd, fd): verify fd is valid, then clear CLOEXEC.
                //
                // POSIX says dup2(fd, fd) "does nothing", but libuv relies on
                // inherited stdio fds surviving exec even though the parent
                // sets CLOEXEC. Clearing CLOEXEC here matches the intent of
                // the dup2 caller (set up this fd for the child) and prevents
                // close-on-exec from closing stdio fds after exec.
                let files = self.files.borrow();
                files
                    .run_on_raw_fd(
                        oldfd_usize,
                        |fd| {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        },
                        |fd| {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        },
                        |fd| {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        },
                        |fd| {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        },
                        |fd| {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        },
                        |fd| {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        },
                    )
                    .flatten()?;
                return Ok(oldfd);
            }
            // Close whatever is at newfd before duping into it
            let newfd_usize = usize::try_from(newfd).or(Err(Errno::EBADF))?;
            let _ = self.do_close(newfd_usize);
            self.do_dup_inner(
                oldfd_usize,
                flags.unwrap_or(OFlags::empty()),
                Some(newfd_usize),
                None,
            )?;
            self.maybe_trace_pty_dup(oldfd, newfd);
            Ok(newfd)
        } else {
            // dup
            let new_file = self.do_dup(oldfd_usize, flags.unwrap_or(OFlags::empty()))?;
            let newfd = u32::try_from(new_file).unwrap();
            self.maybe_trace_pty_dup(oldfd, newfd);
            Ok(newfd)
        }
    }

    /// Handle `faccessat` — check file accessibility.
    pub fn sys_faccessat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode: litebox_common_linux::AccessFlags,
        flags: litebox_common_linux::AtFlags,
    ) -> Result<(), Errno> {
        use litebox_common_linux::AtFlags;
        let supported = AtFlags::AT_EACCESS | AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_EMPTY_PATH;
        if flags.intersects(!supported) {
            return Err(Errno::EINVAL);
        }

        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let allow_empty = flags.contains(AtFlags::AT_EMPTY_PATH);
        let fs_path = FsPath::new_inner(dirfd, pathname, get_cwd, allow_empty)?;

        let follow_symlinks = !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW);

        let files = self.files.borrow();
        let status = match fs_path {
            FsPath::Absolute { path } => {
                // Skip client-side symlink resolution when the FS follows
                // symlinks during walk (e.g., 9P with canonicalizing broker).
                if follow_symlinks && !files.fs.walks_follow_symlinks() {
                    let path_str = path.to_str().map_err(|_| Errno::EINVAL)?;
                    let resolved = self.canonicalize_path(path_str)?;
                    files.fs.file_status(&*resolved)?
                } else {
                    files.fs.file_status(&*path)?
                }
            }
            FsPath::Cwd => files.fs.file_status(&*get_cwd())?,
            FsPath::Fd(raw) => {
                // AT_EMPTY_PATH: check the fd itself. For non-FS fds
                // (network, pipes, etc.), the fd is valid so F_OK succeeds
                // and we don't model fine-grained permissions.
                let raw = usize::try_from(raw).map_err(|_| Errno::EBADF)?;
                return files.run_on_raw_fd(
                    raw,
                    |fd| {
                        let s = files.fs.fd_file_status(fd).map_err(Errno::from)?;
                        Self::check_access_mode(&s, mode)
                    },
                    |_| Ok(()),
                    |_| Ok(()),
                    |_| Ok(()),
                    |_| Ok(()),
                    |_| Ok(()),
                )?;
            }
            FsPath::FdRelative { fd, path } => {
                // Use stat_at which handles follow_symlinks properly.
                let raw = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
                return files.run_on_raw_fd(
                    raw,
                    |dirfd| {
                        let s = files
                            .fs
                            .stat_at(dirfd, path, follow_symlinks)
                            .map_err(Errno::from)?;
                        Self::check_access_mode(&s, mode)
                    },
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                    |_| Err(Errno::ENOTDIR),
                )?;
            }
        };

        // AT_EACCESS: use effective IDs instead of real IDs.
        // We don't distinguish real vs effective, so this is a no-op.
        Self::check_access_mode(&status, mode)
    }

    /// Check file access permissions against the given mode flags.
    fn check_access_mode(
        status: &litebox::fs::FileStatus,
        mode: litebox_common_linux::AccessFlags,
    ) -> Result<(), Errno> {
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

    /// Handle `statx` — modern replacement for `stat`/`fstatat`.
    ///
    /// Delegates to the same resolution logic as `newfstatat`, then
    /// converts `FileStat` into the `statx` buffer layout.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::unnecessary_cast
    )]
    #[allow(clippy::useless_conversion)]
    pub fn sys_statx(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
        _mask: u32,
    ) -> Result<StatxBuf, Errno> {
        // statx shares the same AT_* flags as newfstatat.
        let stat = self.sys_newfstatat(dirfd, pathname, flags)?;
        Ok(StatxBuf {
            stx_mask: STATX_BASIC_STATS,
            stx_blksize: stat.st_blksize as u32,
            stx_attributes: 0,
            stx_nlink: stat.st_nlink as u32,
            stx_uid: stat.st_uid.into(),
            stx_gid: stat.st_gid.into(),
            stx_mode: stat.st_mode as u16,
            __spare0: [0],
            stx_ino: stat.st_ino.into(),
            stx_size: stat.st_size as u64,
            stx_blocks: stat.st_blocks as u64,
            stx_attributes_mask: 0,
            stx_atime: StatxTimestamp {
                tv_sec: stat.st_atime.into(),
                tv_nsec: stat.st_atime_nsec as u32,
                __reserved: 0,
            },
            stx_btime: StatxTimestamp::default(),
            stx_ctime: StatxTimestamp {
                tv_sec: stat.st_ctime.into(),
                tv_nsec: stat.st_ctime_nsec as u32,
                __reserved: 0,
            },
            stx_mtime: StatxTimestamp {
                tv_sec: stat.st_mtime.into(),
                tv_nsec: stat.st_mtime_nsec as u32,
                __reserved: 0,
            },
            stx_rdev_major: (stat.st_rdev >> 8) as u32,
            stx_rdev_minor: (stat.st_rdev & 0xff) as u32,
            stx_dev_major: (stat.st_dev >> 8) as u32,
            stx_dev_minor: (stat.st_dev & 0xff) as u32,
            stx_mnt_id: 0,
            stx_dio_mem_align: 0,
            stx_dio_opt_align: 0,
            __spare3: [0; 12],
        })
    }

    /// Handle `statfs` — return synthetic tmpfs-like filesystem stats.
    pub fn sys_statfs(&self, pathname: impl path::Arg) -> Result<StatfsBuf, Errno> {
        // Verify the path exists.
        let path = self.resolve_path(pathname)?;
        self.files
            .borrow()
            .fs
            .file_status(path)
            .map_err(Errno::from)?;
        Ok(Self::synthetic_statfs())
    }

    /// Handle `fstatfs` — return synthetic tmpfs-like filesystem stats.
    pub fn sys_fstatfs(&self, fd: i32) -> Result<StatfsBuf, Errno> {
        let Ok(raw_fd) = usize::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        // Verify the fd is valid by attempting to stat it.
        descriptor_stat(raw_fd, self)?;
        Ok(Self::synthetic_statfs())
    }

    fn synthetic_statfs() -> StatfsBuf {
        StatfsBuf {
            f_type: TMPFS_MAGIC,
            f_bsize: 4096,
            f_blocks: 1024 * 1024,
            f_bfree: 1024 * 1024,
            f_bavail: 1024 * 1024,
            f_files: 1024 * 1024,
            f_ffree: 1024 * 1024,
            f_fsid: [0, 0],
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: 0,
            __spare: [0; 4],
        }
    }

    /// Handle `fchmodat` — change file mode relative to directory fd.
    pub fn sys_fchmodat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode: u32,
    ) -> Result<(), Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        let mode = litebox::fs::Mode::from_bits_truncate(mode);
        match fs_path {
            FsPath::Absolute { path } => self
                .files
                .borrow()
                .fs
                .chmod(path, mode)
                .map_err(Errno::from),
            FsPath::Cwd => self
                .files
                .borrow()
                .fs
                .chmod(get_cwd(), mode)
                .map_err(Errno::from),
            FsPath::Fd(_fd) => Err(Errno::EINVAL),
            FsPath::FdRelative { fd, path } => {
                let abs = self.resolve_dirfd_path(fd, &path)?;
                self.files.borrow().fs.chmod(abs, mode).map_err(Errno::from)
            }
        }
    }

    /// Handle `fchdir` — change working directory via file descriptor.
    pub fn sys_fchdir(&self, fd: i32) -> Result<(), Errno> {
        use litebox::fs::FileType;

        let raw = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();

        // Get the path and verify it's a directory.
        let dir_path = files.run_on_raw_fd(
            raw,
            |typed_fd| {
                let status = files.fs.fd_file_status(typed_fd).map_err(Errno::from)?;
                if status.file_type != FileType::Directory {
                    return Err(Errno::ENOTDIR);
                }
                files.fs.fd_path(typed_fd).ok_or(Errno::EBADF)
            },
            |_| Err(Errno::ENOTDIR),
            |_| Err(Errno::ENOTDIR),
            |_| Err(Errno::ENOTDIR),
            |_| Err(Errno::ENOTDIR),
            |_| Err(Errno::ENOTDIR),
        )??;

        let mut new_cwd = dir_path;
        if !new_cwd.ends_with('/') {
            new_cwd.push('/');
        }

        drop(files);
        *self.fs.borrow().cwd.write() = new_cwd;
        Ok(())
    }

    /// Handle `memfd_create` — create an anonymous file in memory.
    pub fn sys_memfd_create(
        &self,
        name: alloc::ffi::CString,
        flags: litebox_common_linux::MemfdFlags,
    ) -> Result<u32, Errno> {
        use litebox::fs::errors::CreateAnonymousFileError;
        use litebox_common_linux::MemfdFlags;

        let known = MemfdFlags::CLOEXEC
            | MemfdFlags::ALLOW_SEALING
            | MemfdFlags::HUGETLB
            | MemfdFlags::NOEXEC_SEAL
            | MemfdFlags::EXEC;
        if flags.intersects(known.complement()) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(MemfdFlags::HUGETLB) {
            return Err(Errno::ENOSYS);
        }
        // MFD_EXEC and MFD_NOEXEC_SEAL are mutually exclusive.
        if flags.contains(MemfdFlags::EXEC) && flags.contains(MemfdFlags::NOEXEC_SEAL) {
            return Err(Errno::EINVAL);
        }

        let name_str = name.to_string_lossy();
        // Strip execute bits when MFD_NOEXEC_SEAL is set, matching Linux.
        let mode = if flags.contains(MemfdFlags::NOEXEC_SEAL) {
            litebox::fs::Mode::from_bits_truncate(0o666)
        } else {
            litebox::fs::Mode::from_bits_truncate(0o777)
        };
        let files = self.files.borrow();
        let file = files
            .fs
            .create_anonymous_file(&name_str, mode)
            .map_err(|e| match e {
                CreateAnonymousFileError::NotSupported => Errno::ENOSYS,
                CreateAnonymousFileError::Io | _ => Errno::EIO,
            })?;
        {
            let mut dt = self.global.litebox.descriptor_table_mut();
            if flags.contains(MemfdFlags::CLOEXEC) {
                let old = dt.set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC);
                assert!(old.is_none());
            }
            let status = OFlags::RDWR | OFlags::LARGEFILE;
            let old = dt.set_entry_metadata(&file, crate::StdioStatusFlags(status));
            assert!(old.is_none());
        }
        let raw_fd = files.insert_raw_fd(file).map_err(|file| {
            files.fs.close(&file).unwrap();
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
    }

    /// Handle `inotify_init1` — create an inotify instance.
    ///
    /// Backed by an eventfd; no real filesystem events are delivered.
    pub fn sys_inotify_init1(&self, flags: OFlags) -> Result<u32, Errno> {
        if flags.intersects((OFlags::CLOEXEC | OFlags::NONBLOCK).complement()) {
            return Err(Errno::EINVAL);
        }

        let mut eventfd_flags = EfdFlags::empty();
        if flags.contains(OFlags::CLOEXEC) {
            eventfd_flags |= EfdFlags::CLOEXEC;
        }
        if flags.contains(OFlags::NONBLOCK) {
            eventfd_flags |= EfdFlags::NONBLOCK;
        }

        let raw_fd = self.sys_eventfd2(0, eventfd_flags)?;
        self.files
            .borrow()
            .register_inotify_fd(usize::try_from(raw_fd).unwrap());
        Ok(raw_fd)
    }

    /// Handle `inotify_add_watch` — register a watch on a path.
    pub fn sys_inotify_add_watch(
        &self,
        fd: i32,
        pathname: impl path::Arg,
        _mask: u32,
    ) -> Result<u32, Errno> {
        let raw_fd = u32::try_from(fd)
            .map_err(|_| Errno::EBADF)
            .and_then(|fd| usize::try_from(fd).map_err(|_| Errno::EBADF))?;
        let resolved = self.resolve_path(pathname)?;
        self.do_stat(resolved.clone(), true)?;
        let resolved = resolved.into_string().map_err(|_| Errno::EINVAL)?;
        self.files.borrow().with_inotify_fd(raw_fd, |state| {
            state
                .add_watch(resolved.clone())
                .and_then(|wd| u32::try_from(wd).map_err(|_| Errno::EINVAL))
        })
    }

    /// Handle `inotify_rm_watch` — remove a previously registered watch.
    pub fn sys_inotify_rm_watch(&self, fd: i32, wd: i32) -> Result<(), Errno> {
        let raw_fd = u32::try_from(fd)
            .map_err(|_| Errno::EBADF)
            .and_then(|fd| usize::try_from(fd).map_err(|_| Errno::EBADF))?;
        self.files
            .borrow()
            .with_inotify_fd(raw_fd, |state| state.remove_watch(wd))
    }

    /// Handle `timerfd_create` — create a timer file descriptor.
    pub fn sys_timerfd_create(&self, clockid: ClockId, flags: TimerfdFlags) -> Result<u32, Errno> {
        if flags.intersects((TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK).complement()) {
            return Err(Errno::EINVAL);
        }
        match clockid {
            ClockId::RealTime
            | ClockId::RealtimeCoarse
            | ClockId::Monotonic
            | ClockId::MonotonicCoarse
            | ClockId::MonotonicRaw
            | ClockId::Boottime => {}
            _ => return Err(Errno::EINVAL),
        }

        let timerfd = super::eventfd::EventFile::new_timer(
            self.global.platform,
            self.global.boot_time,
            clockid,
            flags,
        );
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::eventfd::EventfdSubsystem>(timerfd);
        if flags.contains(TimerfdFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
    }

    /// Handle `timerfd_settime` — arm or disarm a timer fd.
    pub fn sys_timerfd_settime(
        &self,
        fd: i32,
        flags: TimerfdTimerFlags,
        new_value: ItimerSpec,
        old_value: Option<MutPtr<ItimerSpec>>,
    ) -> Result<(), Errno> {
        if flags.intersects(
            (TimerfdTimerFlags::ABSTIME | TimerfdTimerFlags::CANCEL_ON_SET).complement(),
        ) {
            return Err(Errno::EINVAL);
        }
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let handle = {
            let rds = files.raw_descriptor_store.read();
            let typed = rds
                .fd_from_raw_integer::<super::eventfd::EventfdSubsystem>(raw_fd)
                .map_err(|_| Errno::EBADF)?;
            self.global
                .litebox
                .descriptor_table()
                .entry_handle(&typed)
                .ok_or(Errno::EBADF)?
        };
        let old = handle.with_entry(|file| file.set_timer(flags, new_value))?;
        if let Some(old_value) = old_value {
            old_value.write_at_offset(0, old).ok_or(Errno::EFAULT)?;
        }
        Ok(())
    }

    /// Handle `timerfd_gettime` — return the current timer value.
    pub fn sys_timerfd_gettime(&self, fd: i32) -> Result<ItimerSpec, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let handle = {
            let rds = files.raw_descriptor_store.read();
            let typed = rds
                .fd_from_raw_integer::<super::eventfd::EventfdSubsystem>(raw_fd)
                .map_err(|_| Errno::EBADF)?;
            self.global
                .litebox
                .descriptor_table()
                .entry_handle(&typed)
                .ok_or(Errno::EBADF)?
        };
        handle.with_entry(super::eventfd::EventFile::get_timer)
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
        let Ok(fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files.run_on_raw_fd(
            fd,
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
                    let hdr_ptr = crate::MutPtr::from_usize(dirp.as_usize() + nbytes);
                    hdr_ptr.write_at_offset(0, dirent64).ok_or(Errno::EFAULT)?;
                    let name_ptr = crate::MutPtr::from_usize(
                        hdr_ptr.as_usize() + DIRENT_STRUCT_BYTES_WITHOUT_NAME,
                    );
                    name_ptr
                        .write_slice_at_offset(0, entry.name.as_bytes())
                        .ok_or(Errno::EFAULT)?;
                    // set the null terminator and padding
                    let zeros_len = len - (DIRENT_STRUCT_BYTES_WITHOUT_NAME + entry.name.len());
                    name_ptr
                        .write_slice_at_offset(
                            isize::try_from(entry.name.len()).unwrap(),
                            &vec![0; zeros_len],
                        )
                        .ok_or(Errno::EFAULT)?;
                    nbytes += len;
                    dir_off += 1;
                }
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(file, Diroff(dir_off));
                Ok(nbytes)
            },
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
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

        // Empty path at AT_FDCWD → ENOENT (new() rejects empty paths).
        let err = FsPath::new(litebox_common_linux::AT_FDCWD, "", || {
            panic!("get_cwd should not be called for empty path")
        })
        .unwrap_err();
        assert_eq!(err, Errno::ENOENT);

        // Positive fd + empty path → ENOENT with new().
        let err = FsPath::new(5, "", || panic!("should not be called")).unwrap_err();
        assert_eq!(err, Errno::ENOENT);

        // new_empty_ok allows empty paths (AT_EMPTY_PATH semantics).
        let fp = FsPath::new_empty_ok(litebox_common_linux::AT_FDCWD, "", || {
            panic!("get_cwd should not be called for empty Cwd path")
        })
        .unwrap();
        assert!(matches!(fp, FsPath::Cwd));

        let fp = FsPath::new_empty_ok(5, "", || panic!("should not be called")).unwrap();
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
