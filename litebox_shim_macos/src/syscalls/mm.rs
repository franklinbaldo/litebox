// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management syscall handlers for the macOS shim.
//!
//! macOS uses different flag values from Linux for mmap, so we translate them
//! to `litebox_common_linux` types which the shared `PageManager` understands.

use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_linux::{MapFlags, ProtFlags};
use litebox_common_macos::errno::Errno;

use crate::{MutPtr, ShimFS, Task};

// macOS mmap protection flags (same values as Linux).
const MACOS_PROT_READ: i32 = 1;
const MACOS_PROT_WRITE: i32 = 2;
const MACOS_PROT_EXEC: i32 = 4;

// macOS mmap mapping flags.
const MACOS_MAP_SHARED: i32 = 0x0001;
const MACOS_MAP_PRIVATE: i32 = 0x0002;
const MACOS_MAP_FIXED: i32 = 0x0010;
const MACOS_MAP_ANON: i32 = 0x1000;

/// Translate macOS prot flags to Linux `ProtFlags`.
fn translate_prot(macos_prot: i32) -> ProtFlags {
    let mut flags = ProtFlags::empty();
    if macos_prot & MACOS_PROT_READ != 0 {
        flags |= ProtFlags::PROT_READ;
    }
    if macos_prot & MACOS_PROT_WRITE != 0 {
        flags |= ProtFlags::PROT_WRITE;
    }
    if macos_prot & MACOS_PROT_EXEC != 0 {
        flags |= ProtFlags::PROT_EXEC;
    }
    flags
}

/// Translate macOS map flags to Linux `MapFlags`.
fn translate_map_flags(macos_flags: i32) -> MapFlags {
    let mut flags = MapFlags::empty();
    if macos_flags & MACOS_MAP_SHARED != 0 {
        flags |= MapFlags::MAP_SHARED;
    }
    if macos_flags & MACOS_MAP_PRIVATE != 0 {
        flags |= MapFlags::MAP_PRIVATE;
    }
    if macos_flags & MACOS_MAP_FIXED != 0 {
        flags |= MapFlags::MAP_FIXED;
    }
    if macos_flags & MACOS_MAP_ANON != 0 {
        flags |= MapFlags::MAP_ANONYMOUS;
    }
    flags
}

/// Convert a `MappingError` to a macOS errno.
fn mapping_error_to_errno(e: litebox::mm::linux::MappingError) -> Errno {
    match e {
        litebox::mm::linux::MappingError::OutOfMemory
        | litebox::mm::linux::MappingError::MapError(
            litebox::platform::page_mgmt::AllocationError::OutOfMemory,
        ) => Errno::ENOMEM,
        litebox::mm::linux::MappingError::BadFD(_) => Errno::EBADF,
        litebox::mm::linux::MappingError::NotForReading => Errno::EACCES,
        _ => Errno::EINVAL,
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Handle `mmap(addr, length, prot, flags, fd, offset)`.
    ///
    /// Translates macOS flags to Linux equivalents and delegates to the
    /// shared `litebox_common_linux::mm::do_mmap`.
    pub(crate) fn sys_mmap(
        &self,
        addr: usize,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> Result<usize, Errno> {
        use litebox::mm::linux::PAGE_SIZE;

        let linux_prot = translate_prot(prot);
        let linux_flags = translate_map_flags(flags);

        // Validate alignment.
        let offset_usize = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        if !offset_usize.is_multiple_of(PAGE_SIZE) || !addr.is_multiple_of(PAGE_SIZE) || length == 0
        {
            return Err(Errno::EINVAL);
        }

        let aligned_len = align_up(length, PAGE_SIZE);
        if aligned_len == 0 {
            return Err(Errno::ENOMEM);
        }

        let suggested_addr = if addr == 0 { None } else { Some(addr) };

        if linux_flags.contains(MapFlags::MAP_ANONYMOUS) {
            // Anonymous mapping: no file involved.
            let op = |_| Ok(0);
            litebox_common_linux::mm::do_mmap(
                &self.global.pm,
                suggested_addr,
                aligned_len,
                linux_prot,
                linux_flags,
                false,
                op,
            )
            .map(|ptr: MutPtr<u8>| ptr.as_usize())
            .map_err(mapping_error_to_errno)
        } else {
            // File-backed mapping: look up the fd and read data into the mapping.
            let typed_fd = {
                let rds = self.global.raw_descriptors.read();
                #[allow(clippy::cast_sign_loss)] // fd is non-negative when valid
                rds.fd_from_raw_integer::<FS>(fd as usize)
                    .map_err(|_| Errno::EBADF)?
            };

            let op = |ptr: MutPtr<u8>| -> Result<usize, litebox::mm::linux::MappingError> {
                let mut file_offset = offset_usize;
                let mut buf = [0u8; PAGE_SIZE];
                let mut copied = 0;
                while copied < aligned_len {
                    let size = self
                        .global
                        .fs
                        .read(&typed_fd, &mut buf, Some(file_offset))
                        .map_err(|_| litebox::mm::linux::MappingError::BadFD(fd))?;
                    if size == 0 {
                        break;
                    }
                    ptr.copy_from_slice(copied, &buf[..size]).unwrap();
                    copied += size;
                    file_offset += size;
                }
                Ok(copied)
            };

            litebox_common_linux::mm::do_mmap(
                &self.global.pm,
                suggested_addr,
                aligned_len,
                linux_prot,
                linux_flags,
                false,
                op,
            )
            .map(|ptr: MutPtr<u8>| ptr.as_usize())
            .map_err(mapping_error_to_errno)
        }
    }

    /// Handle `munmap(addr, length)`.
    pub(crate) fn sys_munmap(&self, addr: usize, length: usize) -> Result<(), Errno> {
        let ptr: MutPtr<u8> = MutPtr::from_usize(addr);
        litebox_common_linux::mm::sys_munmap(&self.global.pm, ptr, length)
            .map_err(linux_errno_to_macos)
    }

    /// Handle `mprotect(addr, length, prot)`.
    pub(crate) fn sys_mprotect(&self, addr: usize, length: usize, prot: i32) -> Result<(), Errno> {
        let linux_prot = translate_prot(prot);
        let ptr: MutPtr<u8> = MutPtr::from_usize(addr);
        litebox_common_linux::mm::sys_mprotect(&self.global.pm, ptr, length, linux_prot)
            .map_err(linux_errno_to_macos)
    }
}

/// Convert a `litebox_common_linux::errno::Errno` to a macOS errno.
///
/// The shared mm implementations in `litebox_common_linux::mm` return Linux
/// errno values. We translate the ones that can actually occur to macOS errnos.
fn linux_errno_to_macos(e: litebox_common_linux::errno::Errno) -> Errno {
    match e {
        litebox_common_linux::errno::Errno::ENOMEM => Errno::ENOMEM,
        litebox_common_linux::errno::Errno::EBADF => Errno::EBADF,
        litebox_common_linux::errno::Errno::EACCES => Errno::EACCES,
        litebox_common_linux::errno::Errno::EFAULT => Errno::EFAULT,
        litebox_common_linux::errno::Errno::EPERM => Errno::EPERM,
        _ => Errno::EINVAL,
    }
}

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}
