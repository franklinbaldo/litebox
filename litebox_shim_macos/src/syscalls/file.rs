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
fn read_cstring_from_guest(ptr: ConstPtr<u8>, max_len: usize) -> Option<String> {
    let bytes = ptr.to_owned_slice(max_len)?;
    let nul_pos = bytes.iter().position(|&b| b == 0)?;
    String::from_utf8(bytes[..nul_pos].to_vec()).ok()
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
        let raw_fd = fd_to_usize(fd)?;
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

    /// Handle `open(path, flags, mode)` with sysroot path rewriting.
    pub(crate) fn sys_open(
        &self,
        path_addr: usize,
        flags: i32,
        _mode: u32,
    ) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        // Apply sysroot rewriting if configured
        let actual_path = if let Some(ref sysroot) = self.global.sysroot {
            if path.starts_with("/usr/lib/") || path.starts_with("/System/Library/") {
                let mut redirected = String::from(sysroot.as_str());
                redirected.push_str(&path);
                redirected
            } else {
                path
            }
        } else {
            path
        };

        let oflags = translate_open_flags(flags);
        let cpath = alloc::ffi::CString::new(actual_path.as_bytes()).map_err(|_| Errno::EINVAL)?;

        let typed_fd = self
            .global
            .fs
            .open(&cpath, oflags, litebox::fs::Mode::empty())
            .map_err(Self::open_error_to_errno)?;

        let raw_fd = {
            let mut rds = self.global.raw_descriptors.write();
            rds.fd_into_raw_integer(typed_fd)
        };

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
        let mut stat_buf = [0u8; 144];

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
    pub(crate) fn sys_fcntl(&self, fd: i32, cmd: i32, _arg: usize) -> Result<usize, Errno> {
        let _raw_fd = fd_to_usize(fd)?;
        match cmd {
            3 => Ok(0),              // F_GETFL: return O_RDONLY
            4 => Ok(0),              // F_SETFL: pretend success
            50 => Err(Errno::EBADF), // F_GETPATH: not supported
            _ => Err(Errno::EINVAL),
        }
    }
}
