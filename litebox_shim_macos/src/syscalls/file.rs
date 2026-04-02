// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File I/O syscall handlers for the macOS shim.

use alloc::vec;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::errno::Errno;

use crate::{ConstPtr, MutPtr, ShimFS, Task};

/// Maximum kernel-side buffer size, to prevent OOM from huge read/write requests.
const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

/// Convert a raw `i32` fd to a `usize` for lookup, returning EBADF on negative values.
fn fd_to_usize(fd: i32) -> Result<usize, Errno> {
    usize::try_from(fd).map_err(|_| Errno::EBADF)
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
}
