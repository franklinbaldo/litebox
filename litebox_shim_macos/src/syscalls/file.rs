// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File I/O syscall handlers for the macOS shim.

use alloc::string::String;
use alloc::vec;
use litebox::fs::{OFlags, SeekWhence};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::errno::Errno;

use crate::{ConstPtr, MutPtr, ShimFS, Task};

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
        let byte: u8 = ptr.read_at_offset(i as isize)?;
        if byte == 0 {
            return String::from_utf8(buf).ok();
        }
        buf.push(byte);
    }
    None // no NUL terminator found within max_len
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
    /// Reads data from the file descriptor into a kernel buffer, then copies
    /// it to the user buffer address.
    pub(crate) fn sys_read(&self, fd: i32, buf_addr: usize, count: usize) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        let read_len = count.min(MAX_KERNEL_BUF_SIZE);
        let mut kernel_buf = vec![0u8; read_len];
        let size = self
            .global
            .fs
            .read(&typed_fd, &mut kernel_buf, None)
            .map_err(Self::read_error_to_errno)?;

        let user_buf: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        user_buf
            .copy_from_slice(0, &kernel_buf[..size])
            .ok_or(Errno::EFAULT)?;

        Ok(size)
    }

    /// Handle `write(fd, buf, count)`.
    ///
    /// Copies data from the user buffer, then writes it to the file descriptor.
    pub(crate) fn sys_write(&self, fd: i32, buf_addr: usize, count: usize) -> Result<usize, Errno> {
        // Debug: log write calls to see dyld error messages (written to fd -1, 1, or 2)
        if fd == -1 || fd == 1 || fd == 2 {
            let user_buf_dbg: ConstPtr<u8> = ConstPtr::from_usize(buf_addr);
            if let Some(data) = user_buf_dbg.to_owned_slice(count.min(256)) {
                if let Ok(s) = core::str::from_utf8(&data) {
                    log_unsupported!("write(fd={fd}, count={count}): {s:?}");
                }
            }
        }

        // fd -1 is invalid — return EBADF (but we've already logged the diagnostic above).
        let raw_fd = fd_to_usize(fd)?;

        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        let user_buf: ConstPtr<u8> = ConstPtr::from_usize(buf_addr);
        let write_len = count.min(MAX_KERNEL_BUF_SIZE);
        let data = user_buf.to_owned_slice(write_len).ok_or(Errno::EFAULT)?;

        let size = self
            .global
            .fs
            .write(&typed_fd, &data, None)
            .map_err(Self::write_error_to_errno)?;

        Ok(size)
    }

    /// Handle `close(fd)`.
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        // Finalize any mmap-hook trampoline for this fd
        if let Some(state) = self.patch_cache.borrow_mut().remove(&fd) {
            if state.trampoline_cursor > 0 {
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
        }

        // Existing close logic
        let raw_fd = fd_to_usize(fd)?;

        // Remove the path entry for F_GETPATH tracking.
        {
            let mut paths = self.global.fd_paths.write();
            paths.remove(&raw_fd);
        }

        let typed_fd = {
            let mut rds = self.global.raw_descriptors.write();
            rds.fd_consume_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        self.global.fs.close(&typed_fd).map_err(|_| Errno::EIO)
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
            litebox::fs::FileType::RegularFile => 0o100644,
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
        let rdev = status.node_info.rdev.map(|r| r.get() as i32).unwrap_or(0);
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
            3 => Ok(0), // F_GETFL: return O_RDONLY
            4 => Ok(0), // F_SETFL: pretend success
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
                dest.write_at_offset(path_bytes.len() as isize, 0u8)
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

        // Validate that oldfd exists.
        let old_typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_oldfd)
                .map_err(|_| Errno::EBADF)?
        };

        // If oldfd == newfd, dup2 is a no-op (just validates oldfd).
        if raw_oldfd == raw_newfd {
            return Ok(raw_newfd);
        }

        // Create a new TypedFd that shares the same underlying descriptor.
        let new_typed_fd = self
            .global
            .litebox
            .descriptor_table_mut()
            .duplicate(&old_typed_fd)
            .ok_or(Errno::EBADF)?;

        // If newfd is already open, close it first.
        {
            let mut rds = self.global.raw_descriptors.write();
            if let Ok(existing_fd) = rds.fd_consume_raw_integer::<FS>(raw_newfd) {
                // Best-effort close; ignore errors (matches POSIX dup2 semantics).
                let _ = self.global.fs.close(&existing_fd);
            }
        }

        // Insert the duplicated fd at the specific newfd slot.
        {
            let mut rds = self.global.raw_descriptors.write();
            let success = rds.fd_into_specific_raw_integer(new_typed_fd, raw_newfd);
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
}
