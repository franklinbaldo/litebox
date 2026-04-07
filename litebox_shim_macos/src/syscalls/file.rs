// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File I/O syscall handlers for the macOS shim.

use alloc::string::String;
use alloc::vec;
use core::time::Duration;
use litebox::fs::{OFlags, SeekWhence};
use litebox::net::errors::ReceiveError;
use litebox::net::{CloseBehavior, Network, ReceiveFlags, SendFlags};
use litebox::pipes::Pipes;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::errno::Errno;

use crate::{ConstPtr, MutPtr, Platform, ShimFS, Task};

/// Maximum kernel-side buffer size, to prevent OOM from huge read/write requests.
const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

/// Minimum valid guest address.  On arm64 macOS the `__PAGEZERO` segment
/// occupies 0..4 GB, so any user pointer below this threshold is invalid.
const GUEST_ADDR_MIN: usize = 0x1_0000_0000;

/// Validate that a guest buffer pointer is plausibly mapped.
///
/// Returns `Err(EFAULT)` if `addr` falls in the null page or `__PAGEZERO`
/// (0..4 GB on arm64 macOS) and `count > 0`.  Addresses above `GUEST_ADDR_MIN`
/// may still be unmapped, but catching PAGEZERO covers the most common
/// accidental cases and prevents the shim from faulting on behalf of the guest.
fn validate_guest_buf(addr: usize, count: usize) -> Result<(), Errno> {
    if count > 0 && addr < GUEST_ADDR_MIN {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// Maximum number of iovec entries (macOS IOV_MAX).
const IOV_MAX: usize = 1024;

/// Convert a raw `i32` fd to a `usize` for lookup, returning EBADF on negative values.
pub(crate) fn fd_to_usize(fd: i32) -> Result<usize, Errno> {
    usize::try_from(fd).map_err(|_| Errno::EBADF)
}

/// Read a NUL-terminated C string from guest memory (up to max_len bytes).
///
/// Reads byte-by-byte to avoid faulting past the end of a mapped region.
/// This matches the approach used by the Linux shim's `to_cstring()`.
pub(crate) fn read_cstring_from_guest(ptr: ConstPtr<u8>, max_len: usize) -> Option<String> {
    let mut buf = alloc::vec::Vec::with_capacity(256);
    for i in 0..max_len {
        let byte: u8 = ptr.read_at_offset(i.cast_signed())?;
        if byte == 0 {
            return String::from_utf8(buf).ok();
        }
        buf.push(byte);
    }
    None // no NUL terminator found within max_len
}

/// Owned duplicated FD, used by sys_dup2 to hold the result of descriptor_table.duplicate().
enum DuplicatedFd<FS: ShimFS> {
    FileSystem(litebox::fd::TypedFd<FS>),
    Pipes(litebox::fd::TypedFd<Pipes<Platform>>),
    Network(litebox::fd::TypedFd<Network<Platform>>),
}

/// Translate macOS open(2) flags to litebox OFlags.
///
/// macOS and Linux use different numeric values for O_CREAT, O_TRUNC, etc.
fn translate_open_flags(macos_flags: i32) -> OFlags {
    // O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_NONBLOCK=4, O_APPEND=8,
    // O_SHLOCK=0x10, O_EXLOCK=0x20, O_NOFOLLOW=0x100, O_CREAT=0x200,
    // O_TRUNC=0x400, O_EXCL=0x800, O_DIRECTORY=0x100000,
    // O_CLOEXEC=0x1000000, O_NOFOLLOW_ANY=0x2000000
    let mut flags = OFlags::empty();
    let access = macos_flags & 0x3;
    if access == 1 {
        flags |= OFlags::WRONLY;
    }
    if access == 2 {
        flags |= OFlags::RDWR;
    }
    // access == 0 is O_RDONLY, which is OFlags::empty() (0)
    if macos_flags & 0x0200 != 0 {
        flags |= OFlags::CREAT;
    }
    if macos_flags & 0x0400 != 0 {
        flags |= OFlags::TRUNC;
    }
    if macos_flags & 0x0800 != 0 {
        flags |= OFlags::EXCL;
    }
    if macos_flags & 0x0008 != 0 {
        flags |= OFlags::APPEND;
    }
    if macos_flags & 0x100000 != 0 {
        flags |= OFlags::DIRECTORY;
    }
    flags
}

impl<FS: ShimFS> Task<FS> {
    /// Handle `read(fd, buf, count)`.
    ///
    /// Dispatches to filesystem or pipe subsystem based on FD type.
    pub(crate) fn sys_read(&self, fd: i32, buf_addr: usize, count: usize) -> Result<usize, Errno> {
        validate_guest_buf(buf_addr, count)?;
        let raw_fd = fd_to_usize(fd)?;
        let strong_fd = {
            let rds = self.global.raw_descriptors.read();
            crate::StrongFd::from_raw(&rds, raw_fd).ok()
        };

        // Check for unix socket if not found in the raw descriptor table.
        if strong_fd.is_none() {
            let unix_sockets = self.global.unix_sockets.read();
            if let Some(socket) = unix_sockets.get(&raw_fd) {
                let socket = socket.clone();
                drop(unix_sockets);
                let read_len = count.min(MAX_KERNEL_BUF_SIZE);
                let mut kernel_buf = vec![0u8; read_len];
                let size = socket.read(&mut kernel_buf)?;
                let user_buf: MutPtr<u8> = MutPtr::from_usize(buf_addr);
                user_buf
                    .copy_from_slice(0, &kernel_buf[..size])
                    .ok_or(Errno::EFAULT)?;
                return Ok(size);
            }
            // Kqueue FDs are not readable.
            if self.global.kqueues.read().contains_key(&raw_fd) {
                return Err(Errno::EBADF);
            }
            return Err(Errno::EBADF);
        }
        let strong_fd = strong_fd.unwrap();

        let read_len = count.min(MAX_KERNEL_BUF_SIZE);
        let mut kernel_buf = vec![0u8; read_len];

        let size = match strong_fd {
            crate::StrongFd::FileSystem(ref typed_fd) => self
                .global
                .fs
                .read(typed_fd, &mut kernel_buf, None)
                .map_err(Self::read_error_to_errno)?,
            crate::StrongFd::Pipes(ref typed_fd) => {
                let cx = self.wait_cx();
                self.global
                    .pipes
                    .read(&cx, typed_fd, &mut kernel_buf)
                    .map_err(Self::pipe_read_error_to_errno)?
            }
            crate::StrongFd::Network(ref _typed_fd) => {
                // Read from the proxy ring buffer rather than directly from
                // smoltcp.  The background network thread drains smoltcp →
                // proxy, so reading smoltcp directly races with the drain.
                let proxy = self
                    .global
                    .net_proxies
                    .read()
                    .get(&raw_fd)
                    .cloned()
                    .ok_or(Errno::EBADF)?;
                // Blocking retry: data may not have been drained to the proxy
                // yet (e.g. just after select() reported readability).
                loop {
                    match proxy.try_read(&mut kernel_buf, ReceiveFlags::empty(), None) {
                        Ok(0) | Err(ReceiveError::SocketInInvalidState) => {
                            let cx = self.wait_cx().with_timeout(Duration::from_millis(1));
                            let _ = cx.sleep();
                        }
                        Ok(n) => break n,
                        Err(ReceiveError::OperationFinished) => break 0,
                        Err(e) => return Err(crate::syscalls::net::receive_error_to_errno(e)),
                    }
                }
            }
        };

        let user_buf: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        user_buf
            .copy_from_slice(0, &kernel_buf[..size])
            .ok_or(Errno::EFAULT)?;

        Ok(size)
    }

    /// Handle `write(fd, buf, count)`.
    ///
    /// Dispatches to filesystem or pipe subsystem based on FD type.
    pub(crate) fn sys_write(&self, fd: i32, buf_addr: usize, count: usize) -> Result<usize, Errno> {
        // Reject obviously-invalid buffer pointers early to avoid faulting in
        // the shim itself (e.g. when a guest passes a corrupted buffer).
        validate_guest_buf(buf_addr, count)?;

        // fd -1 is invalid — return EBADF (but we've already logged the diagnostic above).
        let raw_fd = fd_to_usize(fd)?;

        let strong_fd = {
            let rds = self.global.raw_descriptors.read();
            crate::StrongFd::from_raw(&rds, raw_fd).ok()
        };

        // Check for unix socket if not found in the raw descriptor table.
        if strong_fd.is_none() {
            let unix_sockets = self.global.unix_sockets.read();
            if let Some(socket) = unix_sockets.get(&raw_fd) {
                let socket = socket.clone();
                drop(unix_sockets);
                let user_buf: ConstPtr<u8> = ConstPtr::from_usize(buf_addr);
                let write_len = count.min(MAX_KERNEL_BUF_SIZE);
                let data = user_buf.to_owned_slice(write_len).ok_or(Errno::EFAULT)?;
                let size = socket.write(&data)?;
                return Ok(size);
            }
            // Kqueue FDs are not writable.
            if self.global.kqueues.read().contains_key(&raw_fd) {
                return Err(Errno::EBADF);
            }
            return Err(Errno::EBADF);
        }
        let strong_fd = strong_fd.unwrap();

        let user_buf: ConstPtr<u8> = ConstPtr::from_usize(buf_addr);
        let write_len = count.min(MAX_KERNEL_BUF_SIZE);
        let data = user_buf.to_owned_slice(write_len).ok_or(Errno::EFAULT)?;

        let size = match strong_fd {
            crate::StrongFd::FileSystem(ref typed_fd) => self
                .global
                .fs
                .write(typed_fd, &data, None)
                .map_err(Self::write_error_to_errno)?,
            crate::StrongFd::Pipes(ref typed_fd) => {
                let cx = self.wait_cx();
                self.global
                    .pipes
                    .write(&cx, typed_fd, &data)
                    .map_err(Self::pipe_write_error_to_errno)?
            }
            crate::StrongFd::Network(ref typed_fd) => {
                let mut net = self.global.net.lock();
                net.send(typed_fd, &data, SendFlags::empty(), None)
                    .map_err(crate::syscalls::net::send_error_to_errno)?
            }
        };

        Ok(size)
    }

    /// Handle `readv(fd, iov, iovcnt)` — scatter read.
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn sys_readv(
        &self,
        fd: i32,
        iov_addr: usize,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        if iovcnt == 0 || iovcnt > IOV_MAX {
            return Err(Errno::EINVAL);
        }
        let mut total: usize = 0;
        for i in 0..iovcnt {
            let base_ptr: ConstPtr<u64> = ConstPtr::from_usize(iov_addr + i * 16);
            let len_ptr: ConstPtr<u64> = ConstPtr::from_usize(iov_addr + i * 16 + 8);
            let iov_base: u64 = base_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let iov_len: u64 = len_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let iov_len = iov_len as usize;
            if iov_len == 0 {
                continue;
            }
            match self.sys_read(fd, iov_base as usize, iov_len) {
                Ok(n) => {
                    total += n;
                    if n < iov_len {
                        break; // short read
                    }
                }
                Err(e) => {
                    if total > 0 {
                        break; // partial transfer — return what we have
                    }
                    return Err(e);
                }
            }
        }
        Ok(total)
    }

    /// Handle `writev(fd, iov, iovcnt)` — gather write.
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn sys_writev(
        &self,
        fd: i32,
        iov_addr: usize,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        if iovcnt == 0 || iovcnt > IOV_MAX {
            return Err(Errno::EINVAL);
        }
        let mut total: usize = 0;
        for i in 0..iovcnt {
            let base_ptr: ConstPtr<u64> = ConstPtr::from_usize(iov_addr + i * 16);
            let len_ptr: ConstPtr<u64> = ConstPtr::from_usize(iov_addr + i * 16 + 8);
            let iov_base: u64 = base_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let iov_len: u64 = len_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let iov_len = iov_len as usize;
            if iov_len == 0 {
                continue;
            }
            match self.sys_write(fd, iov_base as usize, iov_len) {
                Ok(n) => {
                    total += n;
                    if n < iov_len {
                        break; // short write
                    }
                }
                Err(e) => {
                    if total > 0 {
                        break; // partial transfer — return what we have
                    }
                    return Err(e);
                }
            }
        }
        Ok(total)
    }

    /// Handle `close(fd)`.
    ///
    /// Dispatches to filesystem or pipe subsystem based on FD type.
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        // Finalize any mmap-hook trampoline for this fd
        if let Some(state) = self.patch_cache.lock().remove(&fd)
            && state.trampoline_cursor > 0
        {
            // mprotect trampoline from RW to RX
            if let Err(e) = litebox_common_linux::mm::sys_mprotect(
                &self.global.pm,
                crate::MutPtr::from_usize(state.trampoline_addr),
                crate::MMAP_HOOK_TRAMPOLINE_SIZE,
                litebox_common_linux::ProtFlags::PROT_READ_EXEC,
            ) {
                log_unsupported!("mprotect trampoline RW->RX failed: {e:?}");
            }
        }

        let raw_fd = fd_to_usize(fd)?;

        // Remove the path entry for F_GETPATH tracking.
        {
            let mut paths = self.global.fd_paths.write();
            paths.remove(&raw_fd);
        }

        // Try filesystem first, then pipes.
        {
            let mut rds = self.global.raw_descriptors.write();
            if let Ok(typed_fd) = rds.fd_consume_raw_integer::<FS>(raw_fd) {
                return self.global.fs.close(&typed_fd).map_err(|_| Errno::EIO);
            }
            if let Ok(typed_fd) = rds.fd_consume_raw_integer::<Pipes<Platform>>(raw_fd) {
                return self.global.pipes.close(&typed_fd).map_err(|_| Errno::EIO);
            }
            if let Ok(typed_fd) = rds.fd_consume_raw_integer::<Network<Platform>>(raw_fd) {
                // Remove the proxy from net_proxies.
                self.global.net_proxies.write().remove(&raw_fd);
                return self
                    .global
                    .net
                    .lock()
                    .close(&typed_fd, CloseBehavior::GracefulIfNoPendingData)
                    .map_err(crate::syscalls::net::close_error_to_errno);
            }
        }

        // Try Unix socket.
        {
            let mut unix_sockets = self.global.unix_sockets.write();
            if let Some(socket) = unix_sockets.remove(&raw_fd) {
                // Remove from address table if bound.
                let bound = socket.bound_addr();
                if let crate::syscalls::net::UnixSocketAddr::Path(ref path) = bound {
                    self.global.unix_addr_table.write().remove(path);
                }
                socket.close();
                return Ok(());
            }
        }

        // Try kqueue.
        {
            let removed = self.global.kqueues.write().remove(&raw_fd);
            if removed.is_some() {
                return Ok(());
            }
        }

        Err(Errno::EBADF)
    }

    /// Convert a filesystem `ReadError` to a macOS errno.
    fn read_error_to_errno(e: litebox::fs::errors::ReadError) -> Errno {
        match e {
            litebox::fs::errors::ReadError::ClosedFd
            | litebox::fs::errors::ReadError::NotAFile
            | litebox::fs::errors::ReadError::NotForReading => Errno::EBADF,
            _ => Errno::EIO,
        }
    }

    /// Convert a filesystem `WriteError` to a macOS errno.
    fn write_error_to_errno(e: litebox::fs::errors::WriteError) -> Errno {
        match e {
            litebox::fs::errors::WriteError::ClosedFd
            | litebox::fs::errors::WriteError::NotAFile
            | litebox::fs::errors::WriteError::NotForWriting => Errno::EBADF,
            _ => Errno::EIO,
        }
    }

    /// Convert a pipe `ReadError` to a macOS errno.
    fn pipe_read_error_to_errno(e: litebox::pipes::errors::ReadError) -> Errno {
        match e {
            litebox::pipes::errors::ReadError::ClosedFd
            | litebox::pipes::errors::ReadError::NotForReading => Errno::EBADF,
            litebox::pipes::errors::ReadError::WouldBlock => Errno::EAGAIN,
            _ => Errno::EIO,
        }
    }

    /// Convert a pipe `WriteError` to a macOS errno.
    fn pipe_write_error_to_errno(e: litebox::pipes::errors::WriteError) -> Errno {
        match e {
            litebox::pipes::errors::WriteError::ClosedFd
            | litebox::pipes::errors::WriteError::NotForWriting => Errno::EBADF,
            litebox::pipes::errors::WriteError::ReadEndClosed => Errno::EPIPE,
            litebox::pipes::errors::WriteError::WouldBlock => Errno::EAGAIN,
            _ => Errno::EIO,
        }
    }

    /// Handle `fchdir(fd)` — change working directory to the directory referenced by fd.
    ///
    /// In the macOS-on-macOS runner with an in-memory filesystem, we don't track
    /// CWD state. Return success so that programs like `/bin/ls` that save/restore
    /// CWD via fchdir don't fail.
    pub(crate) fn sys_fchdir(&self, fd: i32) -> Result<usize, Errno> {
        // Verify the fd is valid.
        let raw_fd = fd_to_usize(fd)?;
        let rds = self.global.raw_descriptors.read();
        let _strong: crate::StrongFd<FS> = crate::StrongFd::from_raw(&rds, raw_fd)?;
        drop(rds);
        // No-op: in-mem FS does not track CWD.
        Ok(0)
    }

    /// Handle `open(path, flags, mode)`.
    ///
    /// Dylib files are expected to already be populated in the in-mem FS at
    /// their original guest paths (e.g., `/usr/lib/libSystem.B.dylib`).
    pub(crate) fn sys_open(&self, path_addr: usize, flags: i32, mode: u32) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        let mut oflags = translate_open_flags(flags);

        // Translate "." to "/" — the in-mem FS root, since we don't track CWD.
        let effective_path = if path == "." { "/" } else { &path };
        let cpath =
            alloc::ffi::CString::new(effective_path.as_bytes()).map_err(|_| Errno::EINVAL)?;

        // If the target path is an existing directory, strip flags that are
        // not meaningful for directories (O_CREAT, O_TRUNC, O_EXCL) and
        // force read-only access mode.
        if let Ok(status) = self.global.fs.file_status(&cpath)
            && status.file_type == litebox::fs::FileType::Directory
        {
            oflags.remove(OFlags::CREAT);
            oflags.remove(OFlags::TRUNC);
            oflags.remove(OFlags::EXCL);
            // Also force access mode to read-only for directories.
            oflags.remove(OFlags::WRONLY);
            oflags.remove(OFlags::RDWR);
        }

        let typed_fd =
            match self
                .global
                .fs
                .open(&cpath, oflags, litebox::fs::Mode::from_bits_truncate(mode))
            {
                Ok(fd) => fd,
                Err(e) => {
                    return Err(Self::open_error_to_errno(e));
                }
            };

        let raw_fd = {
            let mut rds = self.global.raw_descriptors.write();
            rds.fd_into_raw_integer(typed_fd)
        };

        // Record the path for F_GETPATH support.
        // Use effective_path (resolved) instead of the raw user path so
        // that e.g. open(".") records "/" and fcntl(F_GETPATH) works
        // correctly for getcwd().
        {
            let mut paths = self.global.fd_paths.write();
            paths.insert(raw_fd, effective_path.into());
        }

        Ok(raw_fd)
    }

    /// Convert an `OpenError` to a macOS errno.
    fn open_error_to_errno(e: litebox::fs::errors::OpenError) -> Errno {
        match e {
            litebox::fs::errors::OpenError::PathError(ref pe) => {
                use litebox::fs::errors::PathError;
                match pe {
                    PathError::NoSuchFileOrDirectory => Errno::ENOENT,
                    PathError::NoSearchPerms { .. } => Errno::EACCES,
                    PathError::ComponentNotADirectory => Errno::ENOTDIR,
                    _ => Errno::EINVAL,
                }
            }
            litebox::fs::errors::OpenError::AccessNotAllowed
            | litebox::fs::errors::OpenError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::OpenError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::OpenError::AlreadyExists => Errno::EEXIST,
            _ => Errno::EIO,
        }
    }

    /// Handle `lseek(fd, offset, whence)`.
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn sys_lseek(&self, fd: i32, offset: i64, whence: i32) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        let seek_whence = match whence {
            0 => SeekWhence::RelativeToBeginning,
            1 => SeekWhence::RelativeToCurrentOffset,
            2 => SeekWhence::RelativeToEnd,
            _ => return Err(Errno::EINVAL),
        };

        self.global
            .fs
            .seek(&typed_fd, offset as isize, seek_whence)
            .map_err(|_| Errno::ESPIPE)
    }

    /// Handle `pread(fd, buf, count, offset)`.
    pub(crate) fn sys_pread(
        &self,
        fd: i32,
        buf_addr: usize,
        count: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        let read_len = count.min(MAX_KERNEL_BUF_SIZE);
        let mut kernel_buf = vec![0u8; read_len];
        let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        let size = self
            .global
            .fs
            .read(&typed_fd, &mut kernel_buf, Some(pos))
            .map_err(Self::read_error_to_errno)?;

        let user_buf: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        user_buf
            .copy_from_slice(0, &kernel_buf[..size])
            .ok_or(Errno::EFAULT)?;

        Ok(size)
    }

    /// Handle `fstat64(fd, buf)`.
    ///
    /// Writes a macOS `stat64` structure (144 bytes on aarch64) to guest memory.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    pub(crate) fn sys_fstat64(&self, fd: i32, buf_addr: usize) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        let status = self
            .global
            .fs
            .fd_file_status(&typed_fd)
            .map_err(|_| Errno::EBADF)?;

        // Build macOS stat64 struct (144 bytes on aarch64).
        //
        // Layout (from <sys/stat.h> on aarch64 macOS):
        //   offset  0: st_dev     (i32)
        //   offset  4: st_mode    (u16)
        //   offset  6: st_nlink   (u16)
        //   offset  8: st_ino     (u64)
        //   offset 16: st_uid     (u32)
        //   offset 20: st_gid     (u32)
        //   offset 24: st_rdev    (i32)
        //   offset 96: st_size    (i64)
        //   offset 104: st_blocks (i64)
        //   offset 112: st_blksize (i32)
        let mut stat_buf = [0u8; 144];

        // st_dev at offset 0 (i32)
        stat_buf[0..4].copy_from_slice(&(status.node_info.dev as i32).to_le_bytes());
        // st_mode at offset 4 (u16)
        let mode: u16 = match status.file_type {
            litebox::fs::FileType::Directory => 0o040755,
            litebox::fs::FileType::CharacterDevice => 0o020666,
            _ => 0o100644, // default to regular file for unknown types
        };
        stat_buf[4..6].copy_from_slice(&mode.to_le_bytes());
        // st_nlink at offset 6 (u16)
        stat_buf[6..8].copy_from_slice(&1u16.to_le_bytes());
        // st_ino at offset 8 (u64)
        stat_buf[8..16].copy_from_slice(&(status.node_info.ino as u64).to_le_bytes());
        // st_uid at offset 16 (u32)
        stat_buf[16..20].copy_from_slice(&(u32::from(status.owner.user)).to_le_bytes());
        // st_gid at offset 20 (u32)
        stat_buf[20..24].copy_from_slice(&(u32::from(status.owner.group)).to_le_bytes());
        // st_rdev at offset 24 (i32)
        let rdev = status.node_info.rdev.map_or(0, |r| r.get() as i32);
        stat_buf[24..28].copy_from_slice(&rdev.to_le_bytes());
        // st_size at offset 96 (i64)
        stat_buf[96..104].copy_from_slice(&(status.size as i64).to_le_bytes());
        // st_blksize at offset 112 (i32)
        let blksize = if status.blksize > 0 {
            status.blksize as i32
        } else {
            4096
        };
        stat_buf[112..116].copy_from_slice(&blksize.to_le_bytes());

        let dest: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        dest.copy_from_slice(0, &stat_buf).ok_or(Errno::EFAULT)?;

        Ok(0)
    }

    /// Handle `fcntl(fd, cmd, arg)` — minimal support.
    pub(crate) fn sys_fcntl(&self, fd: i32, cmd: i32, arg: usize) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        match cmd {
            3 | 4 => Ok(0), // F_GETFL / F_SETFL
            50 => {
                // F_GETPATH: write the file's path (NUL-terminated) to the
                // user buffer at `arg`. Maximum MAXPATHLEN = 1024 bytes.
                let paths = self.global.fd_paths.read();
                let path = paths.get(&raw_fd).ok_or(Errno::EBADF)?;
                let path_bytes = path.as_bytes();
                // MAXPATHLEN on macOS is 1024
                if path_bytes.len() + 1 > 1024 {
                    return Err(Errno::ERANGE);
                }
                let dest: MutPtr<u8> = MutPtr::from_usize(arg);
                dest.copy_from_slice(0, path_bytes).ok_or(Errno::EFAULT)?;
                // Write NUL terminator
                dest.write_at_offset(path_bytes.len().cast_signed(), 0u8)
                    .ok_or(Errno::EFAULT)?;
                log_unsupported!("fcntl(fd={fd}, F_GETPATH) → {path:?}");
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// Handle `dup2(oldfd, newfd)`.
    ///
    /// Duplicates `oldfd` onto `newfd`. If `newfd` is already open, it is
    /// silently closed first. If `oldfd == newfd`, just validates oldfd and
    /// returns it.
    pub(crate) fn sys_dup2(&self, oldfd: i32, newfd: i32) -> Result<usize, Errno> {
        let raw_oldfd = fd_to_usize(oldfd)?;
        let raw_newfd = fd_to_usize(newfd)?;

        // Resolve the old fd to validate it exists.
        let strong_fd: crate::StrongFd<FS> = {
            let rds = self.global.raw_descriptors.read();
            crate::StrongFd::from_raw(&rds, raw_oldfd)?
        };

        // If oldfd == newfd, dup2 is a no-op (just validates oldfd).
        if raw_oldfd == raw_newfd {
            return Ok(raw_newfd);
        }

        // Duplicate the underlying descriptor.
        // duplicate() returns Option<TypedFd<T>> (owned, no Arc).
        let duplicated = match &strong_fd {
            crate::StrongFd::FileSystem(typed_fd) => self
                .global
                .litebox
                .descriptor_table_mut()
                .duplicate(typed_fd)
                .ok_or(Errno::EBADF)
                .map(DuplicatedFd::FileSystem),
            crate::StrongFd::Pipes(typed_fd) => self
                .global
                .litebox
                .descriptor_table_mut()
                .duplicate(typed_fd)
                .ok_or(Errno::EBADF)
                .map(DuplicatedFd::Pipes),
            crate::StrongFd::Network(typed_fd) => self
                .global
                .litebox
                .descriptor_table_mut()
                .duplicate(typed_fd)
                .ok_or(Errno::EBADF)
                .map(DuplicatedFd::Network),
        }?;

        // If newfd is already open, close it first (try all subsystems).
        {
            let mut rds = self.global.raw_descriptors.write();
            if let Ok(existing_fd) = rds.fd_consume_raw_integer::<FS>(raw_newfd) {
                let _ = self.global.fs.close(&existing_fd);
            } else if let Ok(existing_fd) = rds.fd_consume_raw_integer::<Pipes<Platform>>(raw_newfd)
            {
                let _ = self.global.pipes.close(&existing_fd);
            } else if let Ok(existing_fd) =
                rds.fd_consume_raw_integer::<Network<Platform>>(raw_newfd)
            {
                let _ = self
                    .global
                    .net
                    .lock()
                    .close(&existing_fd, CloseBehavior::GracefulIfNoPendingData);
            }
        }

        // Insert the duplicated fd at the specific newfd slot.
        {
            let mut rds = self.global.raw_descriptors.write();
            let success = match duplicated {
                DuplicatedFd::FileSystem(typed_fd) => {
                    rds.fd_into_specific_raw_integer(typed_fd, raw_newfd)
                }
                DuplicatedFd::Pipes(typed_fd) => {
                    rds.fd_into_specific_raw_integer(typed_fd, raw_newfd)
                }
                DuplicatedFd::Network(typed_fd) => {
                    rds.fd_into_specific_raw_integer(typed_fd, raw_newfd)
                }
            };
            if !success {
                return Err(Errno::EBADF);
            }
        }

        // Copy the path entry from oldfd to newfd for F_GETPATH support.
        {
            let mut paths = self.global.fd_paths.write();
            if let Some(path) = paths.get(&raw_oldfd).cloned() {
                paths.insert(raw_newfd, path);
            }
        }

        Ok(raw_newfd)
    }

    /// Handle `stat64(path, buf)` — stat a file by path.
    ///
    /// Opens the file, calls fstat64, then closes it. This is a simple
    /// implementation that works for regular files and directories.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    pub(crate) fn sys_stat64(&self, path_addr: usize, buf_addr: usize) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        // Try to open the path read-only
        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        let typed_fd = self
            .global
            .fs
            .open(&cpath, OFlags::RDONLY, litebox::fs::Mode::empty())
            .map_err(Self::open_error_to_errno)?;

        // Get the raw fd number so we can call sys_fstat64
        let raw_fd = {
            let mut rds = self.global.raw_descriptors.write();
            rds.fd_into_raw_integer(typed_fd)
        };

        let result = self.sys_fstat64(raw_fd as i32, buf_addr);

        // Close the temporary fd
        let _ = self.sys_close(raw_fd as i32);

        result
    }

    /// Handle `openat(dirfd, path, flags, mode)`.
    ///
    /// When `dirfd` is AT_FDCWD (-2 on macOS), this behaves like `open()`.
    /// Other dirfd values are not yet supported.
    pub(crate) fn sys_openat(
        &self,
        dirfd: i32,
        path_addr: usize,
        flags: i32,
        mode: u32,
    ) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        // AT_FDCWD on macOS is -2
        if dirfd == -2 || path.starts_with('/') {
            // Absolute path or relative to cwd — treat like open()
            return self.sys_open(path_addr, flags, mode);
        }

        // Non-AT_FDCWD relative paths are not yet supported
        log_unsupported!("openat: unsupported dirfd={dirfd}");
        Err(Errno::ENOSYS)
    }

    /// Handle `fstatat64(dirfd, path, buf, flag)`.
    ///
    /// When `dirfd` is AT_FDCWD (-2 on macOS), this behaves like `stat64()`.
    pub(crate) fn sys_fstatat64(
        &self,
        dirfd: i32,
        path_addr: usize,
        buf_addr: usize,
        _flag: i32,
    ) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        // AT_FDCWD on macOS is -2
        if dirfd == -2 || path.starts_with('/') {
            return self.sys_stat64(path_addr, buf_addr);
        }

        log_unsupported!("fstatat64: unsupported dirfd={dirfd}");
        Err(Errno::ENOSYS)
    }

    /// Handle `unlink(path)`.
    pub(crate) fn sys_unlink(&self, path_addr: usize) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        self.global.fs.unlink(&cpath).map_err(|e| match e {
            litebox::fs::errors::UnlinkError::PathError(ref pe) => {
                use litebox::fs::errors::PathError;
                match pe {
                    PathError::NoSuchFileOrDirectory => Errno::ENOENT,
                    PathError::ComponentNotADirectory => Errno::ENOTDIR,
                    _ => Errno::EINVAL,
                }
            }
            litebox::fs::errors::UnlinkError::IsADirectory => Errno::EPERM,
            litebox::fs::errors::UnlinkError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::UnlinkError::ReadOnlyFileSystem => Errno::EROFS,
            _ => Errno::EIO,
        })?;
        Ok(0)
    }

    /// Handle `unlinkat(dirfd, path, flag)`.
    ///
    /// If `flag` contains `AT_REMOVEDIR` (0x08 on macOS), behaves like `rmdir`.
    /// Otherwise behaves like `unlink`.
    ///
    /// `dirfd` is currently ignored — paths are resolved from the process
    /// working directory (or absolute). `AT_FDCWD` (-2 on macOS) is the
    /// common case and is treated the same as any other dirfd value.
    pub(crate) fn sys_unlinkat(
        &self,
        dirfd: i32,
        path_addr: usize,
        flag: i32,
    ) -> Result<usize, Errno> {
        const AT_REMOVEDIR: i32 = 0x08;
        let _ = dirfd; // TODO: resolve relative to dirfd when not AT_FDCWD
        if flag & AT_REMOVEDIR != 0 {
            self.sys_rmdir(path_addr)
        } else {
            self.sys_unlink(path_addr)
        }
    }

    /// Handle `faccessat(dirfd, path, amode, flag)`.
    ///
    /// `dirfd` is currently ignored — paths are resolved from the process
    /// working directory (or absolute).
    pub(crate) fn sys_faccessat(
        &self,
        dirfd: i32,
        path_addr: usize,
        amode: i32,
        flag: i32,
    ) -> Result<usize, Errno> {
        let _ = (dirfd, flag); // TODO: resolve relative to dirfd; honor AT_EACCESS
        self.sys_access(path_addr, amode)
    }

    /// Handle `readlink(path, buf, bufsize)` (BSD syscall 58).
    ///
    /// Reads the target of a symbolic link and writes it to `buf`.
    /// Returns the number of bytes written (not including a null terminator).
    pub(crate) fn sys_readlink(
        &self,
        path_addr: usize,
        buf_addr: usize,
        bufsize: usize,
    ) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        let target = self.global.fs.readlink(&cpath).map_err(|e| match e {
            litebox::fs::errors::ReadlinkError::NotASymlink => Errno::EINVAL,
            litebox::fs::errors::ReadlinkError::PathError(ref pe) => {
                use litebox::fs::errors::PathError;
                match pe {
                    PathError::NoSuchFileOrDirectory => Errno::ENOENT,
                    PathError::ComponentNotADirectory => Errno::ENOTDIR,
                    _ => Errno::EINVAL,
                }
            }
            _ => Errno::EIO,
        })?;

        let copy_len = core::cmp::min(target.len(), bufsize);
        if copy_len > 0 {
            let buf_ptr: MutPtr<u8> = MutPtr::from_usize(buf_addr);
            buf_ptr
                .copy_from_slice(0, &target[..copy_len])
                .ok_or(Errno::EFAULT)?;
        }
        Ok(copy_len)
    }

    /// Handle `readlinkat(dirfd, path, buf, bufsize)` (BSD syscall 473).
    ///
    /// `dirfd` is currently ignored — paths are resolved from the process
    /// working directory (or absolute).
    pub(crate) fn sys_readlinkat(
        &self,
        dirfd: i32,
        path_addr: usize,
        buf_addr: usize,
        bufsize: usize,
    ) -> Result<usize, Errno> {
        let _ = dirfd; // TODO: resolve relative to dirfd when not AT_FDCWD
        self.sys_readlink(path_addr, buf_addr, bufsize)
    }

    /// Handle `mkdir(path, mode)`.
    pub(crate) fn sys_mkdir(&self, path_addr: usize, mode: u32) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        let fs_mode = litebox::fs::Mode::from_bits_truncate(mode);
        self.global.fs.mkdir(&cpath, fs_mode).map_err(|e| match e {
            litebox::fs::errors::MkdirError::PathError(ref pe) => {
                use litebox::fs::errors::PathError;
                match pe {
                    PathError::NoSuchFileOrDirectory => Errno::ENOENT,
                    PathError::ComponentNotADirectory => Errno::ENOTDIR,
                    _ => Errno::EINVAL,
                }
            }
            litebox::fs::errors::MkdirError::AlreadyExists => Errno::EEXIST,
            litebox::fs::errors::MkdirError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::MkdirError::ReadOnlyFileSystem => Errno::EROFS,
            _ => Errno::EIO,
        })?;
        Ok(0)
    }

    /// Handle `rmdir(path)`.
    pub(crate) fn sys_rmdir(&self, path_addr: usize) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        self.global.fs.rmdir(&cpath).map_err(|e| match e {
            litebox::fs::errors::RmdirError::PathError(ref pe) => {
                use litebox::fs::errors::PathError;
                match pe {
                    PathError::NoSuchFileOrDirectory => Errno::ENOENT,
                    PathError::ComponentNotADirectory => Errno::ENOTDIR,
                    _ => Errno::EINVAL,
                }
            }
            litebox::fs::errors::RmdirError::NotEmpty => Errno::ENOTEMPTY,
            litebox::fs::errors::RmdirError::NotADirectory => Errno::ENOTDIR,
            litebox::fs::errors::RmdirError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::RmdirError::Busy => Errno::EBUSY,
            litebox::fs::errors::RmdirError::ReadOnlyFileSystem => Errno::EROFS,
            _ => Errno::EIO,
        })?;
        Ok(0)
    }

    /// Handle `access(path, amode)` — check file accessibility.
    ///
    /// Stub: F_OK checks existence via `file_status()`, R_OK/W_OK/X_OK always succeed.
    pub(crate) fn sys_access(&self, path_addr: usize, _amode: i32) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        // F_OK (0) or any mode — just check existence.
        self.global.fs.file_status(&cpath).map_err(|e| match e {
            litebox::fs::errors::FileStatusError::PathError(ref pe) => {
                use litebox::fs::errors::PathError;
                match pe {
                    PathError::NoSuchFileOrDirectory => Errno::ENOENT,
                    PathError::ComponentNotADirectory => Errno::ENOTDIR,
                    _ => Errno::EINVAL,
                }
            }
            _ => Errno::EIO,
        })?;
        // R_OK/W_OK/X_OK: always succeed in sandbox.
        Ok(0)
    }

    /// Handle `fchmod(fd, mode)` — stub: return success.
    ///
    /// Permissions are not enforced in the sandbox, so this is a no-op.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_fchmod(&self, fd: i32, _mode: u32) -> Result<usize, Errno> {
        // Validate fd exists
        let raw_fd = fd_to_usize(fd)?;
        let rds = self.global.raw_descriptors.read();
        crate::StrongFd::<FS>::from_raw(&rds, raw_fd)?;
        Ok(0)
    }

    /// Handle `ftruncate(fd, length)`.
    pub(crate) fn sys_ftruncate(&self, fd: i32, length: i64) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        let len = usize::try_from(length).map_err(|_| Errno::EINVAL)?;
        self.global
            .fs
            .truncate(&typed_fd, len, false)
            .map_err(|e| match e {
                litebox::fs::errors::TruncateError::ClosedFd => Errno::EBADF,
                litebox::fs::errors::TruncateError::IsDirectory
                | litebox::fs::errors::TruncateError::NotForWriting
                | litebox::fs::errors::TruncateError::IsTerminalDevice => Errno::EINVAL,
                litebox::fs::errors::TruncateError::Io => Errno::EIO,
            })?;
        Ok(0)
    }

    /// Handle `getdirentries64(fd, buf, bufsize, basep)`.
    ///
    /// Reads directory entries from the directory FD and serializes them as
    /// macOS `struct dirent` records into the user buffer. Returns the number
    /// of bytes written.
    ///
    /// macOS `struct dirent` layout (aarch64):
    /// - offset 0: d_ino (u64, 8 bytes)
    /// - offset 8: d_seekoff (u64, 8 bytes)
    /// - offset 16: d_reclen (u16, 2 bytes) — total record length including padding
    /// - offset 18: d_namlen (u16, 2 bytes) — length of d_name (excluding NUL)
    /// - offset 20: d_type (u8, 1 byte) — DT_REG=8, DT_DIR=4, DT_CHR=2
    /// - offset 21: d_name (variable) — NUL-terminated name
    /// - padding to 8-byte alignment
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn sys_getdirentries64(
        &self,
        fd: i32,
        buf_addr: usize,
        bufsize: usize,
        basep: usize,
    ) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        let entries = self.global.fs.read_dir(&typed_fd).map_err(|e| match e {
            litebox::fs::errors::ReadDirError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::ReadDirError::NotADirectory => Errno::ENOTDIR,
            _ => Errno::EIO,
        })?;

        // Read the current seek position from basep to know how many entries
        // have already been returned. If basep >= entry count, return 0
        // (end-of-directory).
        let start_offset: usize = if basep != 0 {
            let basep_ptr: ConstPtr<u64> = ConstPtr::from_usize(basep);
            basep_ptr.read_at_offset(0).unwrap_or(0) as usize
        } else {
            0
        };

        let total_entries = entries.len();
        if start_offset >= total_entries {
            // All entries have been returned in previous calls.
            return Ok(0);
        }

        // Serialize entries into macOS dirent format, starting from start_offset.
        let mut output = alloc::vec::Vec::with_capacity(bufsize.min(MAX_KERNEL_BUF_SIZE));
        let mut seek_offset: u64 = start_offset as u64 + 1;

        for entry in &entries[start_offset..] {
            let name_bytes = entry.name.as_bytes();
            let namlen = name_bytes.len();
            // d_reclen = header (21 bytes) + name + NUL, rounded up to 8-byte alignment
            let reclen = (21 + namlen + 1 + 7) & !7;
            if output.len() + reclen > bufsize {
                break; // buffer full
            }

            let ino: u64 = entry
                .ino_info
                .as_ref()
                .map_or(seek_offset, |info| info.ino as u64);
            let d_type: u8 = match entry.file_type {
                litebox::fs::FileType::RegularFile => 8,     // DT_REG
                litebox::fs::FileType::Directory => 4,       // DT_DIR
                litebox::fs::FileType::CharacterDevice => 2, // DT_CHR
                _ => 0,                                      // DT_UNKNOWN
            };

            // d_ino (8 bytes)
            output.extend_from_slice(&ino.to_le_bytes());
            // d_seekoff (8 bytes)
            output.extend_from_slice(&seek_offset.to_le_bytes());
            // d_reclen (2 bytes)
            output.extend_from_slice(&(reclen as u16).to_le_bytes());
            // d_namlen (2 bytes)
            output.extend_from_slice(&(namlen as u16).to_le_bytes());
            // d_type (1 byte)
            output.push(d_type);
            // d_name (NUL-terminated)
            output.extend_from_slice(name_bytes);
            output.push(0); // NUL terminator
            // Pad to 8-byte alignment
            while output.len() % 8 != 0 {
                output.push(0);
            }

            seek_offset += 1;
        }

        // Write output to user buffer
        if !output.is_empty() {
            let user_buf: MutPtr<u8> = MutPtr::from_usize(buf_addr);
            user_buf.copy_from_slice(0, &output).ok_or(Errno::EFAULT)?;
        }

        // Write basep (position) if non-null
        if basep != 0 {
            let basep_ptr: MutPtr<u64> = MutPtr::from_usize(basep);
            basep_ptr
                .write_at_offset(0, seek_offset)
                .ok_or(Errno::EFAULT)?;
        }

        Ok(output.len())
    }

    /// Handle `getattrlistbulk(dirfd, alist, attributeBuffer, bufferSize, options)`.
    ///
    /// Returns the number of entries packed into `attributeBuffer`, or 0 for
    /// end-of-directory. Each entry is a packed record with a leading `u32`
    /// length field, followed by the requested attributes.
    ///
    /// We track the directory position using the fd's seek offset (via lseek).
    pub(crate) fn sys_getattrlistbulk(
        &self,
        dirfd: i32,
        alist_addr: usize,
        attr_buf_addr: usize,
        attr_buf_size: usize,
        _options: u64,
    ) -> Result<usize, Errno> {
        // --- Constants for ATTR_CMN_* ---
        const ATTR_CMN_RETURNED_ATTRS: u32 = 0x8000_0000;
        const ATTR_CMN_NAME: u32 = 0x0000_0001;
        const ATTR_CMN_OBJTYPE: u32 = 0x0000_0008;
        const ATTR_CMN_OBJTAG: u32 = 0x0000_0010;
        const ATTR_CMN_ACCESSMASK: u32 = 0x0002_0000;
        const ATTR_CMN_FLAGS: u32 = 0x0004_0000;
        const ATTR_CMN_FILEID: u32 = 0x0200_0000;

        // --- Constants for ATTR_DIR_* ---
        const ATTR_DIR_LINKCOUNT: u32 = 0x0000_0001;
        const ATTR_DIR_ENTRYCOUNT: u32 = 0x0000_0002;

        // --- Constants for ATTR_FILE_* ---
        const ATTR_FILE_LINKCOUNT: u32 = 0x0000_0001;
        const ATTR_FILE_TOTALSIZE: u32 = 0x0000_0002;
        const ATTR_FILE_ALLOCSIZE: u32 = 0x0000_0004;
        const ATTR_FILE_DATALENGTH: u32 = 0x0000_0200;
        const ATTR_FILE_DATAALLOCSIZE: u32 = 0x0000_0400;

        // VTYPE constants (vnode types)
        const VREG: u32 = 1;
        const VDIR: u32 = 2;
        const VCHR: u32 = 4;

        // VT tag constants
        const VT_APFS: u32 = 27;

        // --- Read the attrlist struct from guest memory ---
        // struct attrlist { u16 bitmapcount, u16 reserved, u32 commonattr, u32 volattr,
        //                   u32 dirattr, u32 fileattr, u32 forkattr }  = 24 bytes
        let alist_ptr: ConstPtr<u8> = ConstPtr::from_usize(alist_addr);
        let mut alist_raw = [0u8; 24];
        for (i, byte) in alist_raw.iter_mut().enumerate() {
            *byte = alist_ptr
                .read_at_offset(i.cast_signed())
                .ok_or(Errno::EFAULT)?;
        }
        let commonattr =
            u32::from_le_bytes([alist_raw[4], alist_raw[5], alist_raw[6], alist_raw[7]]);
        let dirattr =
            u32::from_le_bytes([alist_raw[12], alist_raw[13], alist_raw[14], alist_raw[15]]);
        let fileattr =
            u32::from_le_bytes([alist_raw[16], alist_raw[17], alist_raw[18], alist_raw[19]]);

        // --- Get directory entries ---
        let raw_fd = fd_to_usize(dirfd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        let entries = self.global.fs.read_dir(&typed_fd).map_err(|e| match e {
            litebox::fs::errors::ReadDirError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::ReadDirError::NotADirectory => Errno::ENOTDIR,
            _ => Errno::EIO,
        })?;

        // --- Determine seek position (which entries already returned) ---
        // Directory fds don't have a seek position in our in-mem FS, so we
        // track the enumeration position in Task::dir_positions.
        let current_pos = {
            let positions = self.dir_positions.lock();
            positions.get(&raw_fd).copied().unwrap_or(0)
        };

        // Skip "." and ".." entries — getattrlistbulk doesn't return them
        // (unlike getdirentries64 which does).
        let real_entries: alloc::vec::Vec<_> = entries
            .iter()
            .filter(|e| e.name != "." && e.name != "..")
            .collect();

        let total = real_entries.len();
        if current_pos >= total {
            return Ok(0); // end of directory
        }

        // --- Pack entries into the attribute buffer ---
        let mut output = alloc::vec::Vec::with_capacity(attr_buf_size.min(MAX_KERNEL_BUF_SIZE));
        let mut entry_count: usize = 0;

        for entry in &real_entries[current_pos..] {
            // Build this entry's packed record in a temp buffer
            let mut rec = alloc::vec::Vec::with_capacity(256);

            // Reserve 4 bytes for the record length (we'll fill it at the end)
            rec.extend_from_slice(&[0u8; 4]);

            // ATTR_CMN_RETURNED_ATTRS: attribute_set_t (20 bytes)
            if commonattr & ATTR_CMN_RETURNED_ATTRS != 0 {
                // Report back what we're actually returning
                let ret_common = commonattr; // we return everything requested
                let ret_dir = dirattr;
                let ret_file = fileattr;
                rec.extend_from_slice(&ret_common.to_le_bytes());
                rec.extend_from_slice(&0u32.to_le_bytes()); // volattr
                rec.extend_from_slice(&ret_dir.to_le_bytes());
                rec.extend_from_slice(&ret_file.to_le_bytes());
                rec.extend_from_slice(&0u32.to_le_bytes()); // forkattr
            }

            // ATTR_CMN_NAME: attrreference_t (8 bytes) + variable-length name
            // The name string is placed AFTER all fixed-size attributes.
            // We'll use a placeholder here and fix up the offset later.
            let name_ref_offset = rec.len();
            let has_name = commonattr & ATTR_CMN_NAME != 0;
            if has_name {
                rec.extend_from_slice(&[0u8; 8]); // placeholder for attrreference_t
            }

            // ATTR_CMN_OBJTYPE: u32 (vnode type)
            let is_dir = entry.file_type == litebox::fs::FileType::Directory;
            if commonattr & ATTR_CMN_OBJTYPE != 0 {
                let vtype = match entry.file_type {
                    litebox::fs::FileType::Directory => VDIR,
                    litebox::fs::FileType::CharacterDevice => VCHR,
                    _ => VREG,
                };
                rec.extend_from_slice(&vtype.to_le_bytes());
            }

            // ATTR_CMN_OBJTAG: u32
            if commonattr & ATTR_CMN_OBJTAG != 0 {
                rec.extend_from_slice(&VT_APFS.to_le_bytes());
            }

            // ATTR_CMN_ACCESSMASK: u32
            if commonattr & ATTR_CMN_ACCESSMASK != 0 {
                let mode: u32 = if is_dir { 0o040755 } else { 0o100644 };
                rec.extend_from_slice(&mode.to_le_bytes());
            }

            // ATTR_CMN_FLAGS: u32
            if commonattr & ATTR_CMN_FLAGS != 0 {
                rec.extend_from_slice(&0u32.to_le_bytes());
            }

            // ATTR_CMN_FILEID: u64
            if commonattr & ATTR_CMN_FILEID != 0 {
                let ino: u64 = entry
                    .ino_info
                    .as_ref()
                    .map_or(current_pos as u64 + entry_count as u64 + 2, |info| {
                        info.ino as u64
                    });
                rec.extend_from_slice(&ino.to_le_bytes());
            }

            // --- Directory-specific attributes (only if entry IS a directory) ---
            if is_dir {
                // ATTR_DIR_LINKCOUNT: u32
                if dirattr & ATTR_DIR_LINKCOUNT != 0 {
                    rec.extend_from_slice(&2u32.to_le_bytes());
                }
                // ATTR_DIR_ENTRYCOUNT: u32
                if dirattr & ATTR_DIR_ENTRYCOUNT != 0 {
                    rec.extend_from_slice(&0u32.to_le_bytes());
                }
            } else {
                // --- File-specific attributes (only if entry is NOT a directory) ---
                // ATTR_FILE_LINKCOUNT: u32
                if fileattr & ATTR_FILE_LINKCOUNT != 0 {
                    rec.extend_from_slice(&1u32.to_le_bytes());
                }
                // ATTR_FILE_TOTALSIZE: off_t (8 bytes)
                if fileattr & ATTR_FILE_TOTALSIZE != 0 {
                    rec.extend_from_slice(&0i64.to_le_bytes());
                }
                // ATTR_FILE_ALLOCSIZE: off_t (8 bytes)
                if fileattr & ATTR_FILE_ALLOCSIZE != 0 {
                    rec.extend_from_slice(&0i64.to_le_bytes());
                }
                // ATTR_FILE_DATALENGTH: off_t (8 bytes)
                if fileattr & ATTR_FILE_DATALENGTH != 0 {
                    rec.extend_from_slice(&0i64.to_le_bytes());
                }
                // ATTR_FILE_DATAALLOCSIZE: off_t (8 bytes)
                if fileattr & ATTR_FILE_DATAALLOCSIZE != 0 {
                    rec.extend_from_slice(&0i64.to_le_bytes());
                }
            }

            // --- Now append the variable-length name string ---
            if has_name {
                let name_bytes = entry.name.as_bytes();
                // The attrreference_t.attr_dataoffset is relative to the
                // start of the attrreference_t field itself.
                let name_data_start = rec.len();
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let attr_dataoffset = (name_data_start - name_ref_offset) as i32;
                #[allow(clippy::cast_possible_truncation)]
                let attr_length = (name_bytes.len() + 1) as u32; // +1 for NUL

                // Write the name string + NUL
                rec.extend_from_slice(name_bytes);
                rec.push(0); // NUL terminator

                // Fix up the attrreference_t
                rec[name_ref_offset..name_ref_offset + 4]
                    .copy_from_slice(&attr_dataoffset.to_le_bytes());
                rec[name_ref_offset + 4..name_ref_offset + 8]
                    .copy_from_slice(&attr_length.to_le_bytes());
            }

            // Pad record to 4-byte alignment
            while rec.len() % 4 != 0 {
                rec.push(0);
            }

            // Write record length into the first 4 bytes
            #[allow(clippy::cast_possible_truncation)]
            let reclen = rec.len() as u32;
            rec[0..4].copy_from_slice(&reclen.to_le_bytes());

            // Check if this record fits in the remaining buffer space
            if output.len() + rec.len() > attr_buf_size {
                if entry_count == 0 {
                    // Buffer too small for even one entry — return ERANGE
                    return Err(Errno::ERANGE);
                }
                break; // buffer full, stop here
            }

            output.extend_from_slice(&rec);
            entry_count += 1;
        }

        // --- Write output to user buffer ---
        if !output.is_empty() {
            let user_buf: MutPtr<u8> = MutPtr::from_usize(attr_buf_addr);
            user_buf.copy_from_slice(0, &output).ok_or(Errno::EFAULT)?;
        }

        // --- Advance the directory enumeration position ---
        {
            let mut positions = self.dir_positions.lock();
            positions.insert(raw_fd, current_pos + entry_count);
        }

        // Return the number of entries packed
        Ok(entry_count)
    }
}
