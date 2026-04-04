// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File I/O syscall handlers for the macOS shim.

use alloc::string::String;
use alloc::vec;
use litebox::fs::{OFlags, SeekWhence};
use litebox::pipes::Pipes;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::errno::Errno;

use crate::{ConstPtr, MutPtr, Platform, ShimFS, Task};

/// Maximum kernel-side buffer size, to prevent OOM from huge read/write requests.
const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

/// Convert a raw `i32` fd to a `usize` for lookup, returning EBADF on negative values.
fn fd_to_usize(fd: i32) -> Result<usize, Errno> {
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
}

/// Translate macOS open(2) flags to litebox OFlags.
///
/// macOS and Linux use different numeric values for O_CREAT, O_TRUNC, etc.
fn translate_open_flags(macos_flags: i32) -> OFlags {
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
        let raw_fd = fd_to_usize(fd)?;
        let strong_fd = {
            let rds = self.global.raw_descriptors.read();
            crate::StrongFd::from_raw(&rds, raw_fd)?
        };

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
        // Debug: log write calls to see dyld error messages (written to fd -1, 1, or 2)
        if fd == -1 || fd == 1 || fd == 2 {
            let user_buf_dbg: ConstPtr<u8> = ConstPtr::from_usize(buf_addr);
            if let Some(data) = user_buf_dbg.to_owned_slice(count.min(256))
                && let Ok(s) = core::str::from_utf8(&data)
            {
                log_unsupported!("write(fd={fd}, count={count}): {s:?}");
            }
        }

        // fd -1 is invalid — return EBADF (but we've already logged the diagnostic above).
        let raw_fd = fd_to_usize(fd)?;

        let strong_fd = {
            let rds = self.global.raw_descriptors.read();
            crate::StrongFd::from_raw(&rds, raw_fd)?
        };

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
        };

        Ok(size)
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
            litebox::pipes::errors::ReadError::ClosedFd => Errno::EBADF,
            litebox::pipes::errors::ReadError::NotForReading => Errno::EBADF,
            litebox::pipes::errors::ReadError::WouldBlock => Errno::EAGAIN,
            _ => Errno::EIO,
        }
    }

    /// Convert a pipe `WriteError` to a macOS errno.
    fn pipe_write_error_to_errno(e: litebox::pipes::errors::WriteError) -> Errno {
        match e {
            litebox::pipes::errors::WriteError::ClosedFd => Errno::EBADF,
            litebox::pipes::errors::WriteError::ReadEndClosed => Errno::EPIPE,
            litebox::pipes::errors::WriteError::NotForWriting => Errno::EBADF,
            litebox::pipes::errors::WriteError::WouldBlock => Errno::EAGAIN,
            _ => Errno::EIO,
        }
    }

    /// Handle `open(path, flags, mode)`.
    ///
    /// Dylib files are expected to already be populated in the in-mem FS at
    /// their original guest paths (e.g., `/usr/lib/libSystem.B.dylib`).
    pub(crate) fn sys_open(
        &self,
        path_addr: usize,
        flags: i32,
        _mode: u32,
    ) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        log_unsupported!("sys_open({path:?}, flags={flags:#x})");

        let oflags = translate_open_flags(flags);
        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;

        let typed_fd = match self
            .global
            .fs
            .open(&cpath, oflags, litebox::fs::Mode::empty())
        {
            Ok(fd) => fd,
            Err(e) => {
                let errno = Self::open_error_to_errno(e);
                log_unsupported!("sys_open({path:?}) FAILED: {errno:?}");
                return Err(errno);
            }
        };

        let raw_fd = {
            let mut rds = self.global.raw_descriptors.write();
            rds.fd_into_raw_integer(typed_fd)
        };

        // Record the path for F_GETPATH support.
        {
            let mut paths = self.global.fd_paths.write();
            paths.insert(raw_fd, path.clone());
        }

        log_unsupported!("sys_open({path:?}) → fd={raw_fd}");
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
        }?;

        // If newfd is already open, close it first (try all subsystems).
        {
            let mut rds = self.global.raw_descriptors.write();
            if let Ok(existing_fd) = rds.fd_consume_raw_integer::<FS>(raw_newfd) {
                let _ = self.global.fs.close(&existing_fd);
            } else if let Ok(existing_fd) =
                rds.fd_consume_raw_integer::<Pipes<Platform>>(raw_newfd)
            {
                let _ = self.global.pipes.close(&existing_fd);
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

        log_unsupported!("dup2({oldfd}, {newfd}) → {raw_newfd}");
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
        log_unsupported!("stat64({path:?})");

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
        log_unsupported!("openat(dirfd={dirfd}, {path:?}, flags={flags:#x})");

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
        log_unsupported!("fstatat64(dirfd={dirfd}, {path:?})");

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
        log_unsupported!("unlink({path:?})");

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

    /// Handle `mkdir(path, mode)`.
    pub(crate) fn sys_mkdir(&self, path_addr: usize, mode: u32) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;
        log_unsupported!("mkdir({path:?}, mode={mode:#o})");

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
        log_unsupported!("rmdir({path:?})");

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
    pub(crate) fn sys_access(&self, path_addr: usize, amode: i32) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;
        log_unsupported!("access({path:?}, amode={amode})");

        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        // F_OK (0) or any mode — just check existence.
        self.global
            .fs
            .file_status(&cpath)
            .map_err(|e| match e {
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
    pub(crate) fn sys_fchmod(&self, fd: i32, mode: u32) -> Result<usize, Errno> {
        log_unsupported!("fchmod(fd={fd}, mode={mode:#o}) → stub Ok(0)");
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
                litebox::fs::errors::TruncateError::IsDirectory => Errno::EINVAL,
                litebox::fs::errors::TruncateError::NotForWriting => Errno::EINVAL,
                litebox::fs::errors::TruncateError::IsTerminalDevice => Errno::EINVAL,
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

        let entries = self
            .global
            .fs
            .read_dir(&typed_fd)
            .map_err(|e| match e {
                litebox::fs::errors::ReadDirError::ClosedFd => Errno::EBADF,
                litebox::fs::errors::ReadDirError::NotADirectory => Errno::ENOTDIR,
                litebox::fs::errors::ReadDirError::Io => Errno::EIO,
                _ => Errno::EIO,
            })?;

        // Serialize entries into macOS dirent format.
        let mut output = alloc::vec::Vec::with_capacity(bufsize.min(MAX_KERNEL_BUF_SIZE));
        let mut seek_offset: u64 = 1;

        for entry in &entries {
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
                litebox::fs::FileType::RegularFile => 8,        // DT_REG
                litebox::fs::FileType::Directory => 4,           // DT_DIR
                litebox::fs::FileType::CharacterDevice => 2,     // DT_CHR
                _ => 0,                                          // DT_UNKNOWN
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
            user_buf
                .copy_from_slice(0, &output)
                .ok_or(Errno::EFAULT)?;
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
}
