// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux memfd-backed shared memory for the Unix socket transport.

use std::io::{Error, Result as IoResult};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::Mutex;

use rustix::fs::{
    MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, fstat, ftruncate, memfd_create,
};

use litebox_broker_protocol::shared_memory::{SharedMemory, SharedMemoryError};

use super::invalid_data;

const REQUIRED_MEMFD_SEALS: SealFlags = SealFlags::from_bits_retain(
    SealFlags::GROW.bits() | SealFlags::SHRINK.bits() | SealFlags::SEAL.bits(),
);

/// Memfd-backed shared memory transferred over a Unix control channel.
pub struct UnixSharedMemory {
    fd: OwnedFd,
    mapping: Mutex<MappedRegion>,
}

struct MappedRegion {
    address: NonNull<u8>,
    length: usize,
}

// SAFETY: `MappedRegion` exclusively owns its mapping, and all byte access is
// serialized by the enclosing `Mutex`.
unsafe impl Send for MappedRegion {}

impl UnixSharedMemory {
    pub(super) fn create(length: usize) -> IoResult<Self> {
        if length == 0 {
            return Err(invalid_data("shared memory cannot be empty"));
        }
        let fd = memfd_create(
            "litebox-broker-shm",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?;
        ftruncate(
            &fd,
            length
                .try_into()
                .map_err(|_| invalid_data("shared-memory length exceeds u64"))?,
        )?;
        fcntl_add_seals(&fd, REQUIRED_MEMFD_SEALS)?;
        Self::map(fd, length)
    }

    pub(super) fn from_received_fd(fd: OwnedFd) -> IoResult<Self> {
        // Verify the size seals before reading the size so it cannot change
        // between validation and mapping.
        let seals = fcntl_get_seals(&fd)?;
        if !seals.contains(REQUIRED_MEMFD_SEALS) {
            return Err(invalid_data("shared-memory size is not sealed"));
        }
        let length = usize::try_from(fstat(&fd)?.st_size)
            .map_err(|_| invalid_data("invalid shared-memory length"))?;
        if length == 0 {
            return Err(invalid_data("shared memory cannot be empty"));
        }
        Self::map(fd, length)
    }

    pub(super) fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    fn map(fd: OwnedFd, length: usize) -> IoResult<Self> {
        // SAFETY: `fd` refers to a file at least `length` bytes long. The
        // returned mapping is checked against `MAP_FAILED` and owned by
        // `MappedRegion`.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(Error::last_os_error());
        }
        let address =
            NonNull::new(address.cast()).ok_or_else(|| invalid_data("mmap returned null"))?;
        Ok(Self {
            fd,
            mapping: Mutex::new(MappedRegion { address, length }),
        })
    }
}

impl SharedMemory for UnixSharedMemory {
    fn len(&self) -> usize {
        self.mapping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .length
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let mapping = self
            .mapping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        offset
            .checked_add(destination.len())
            .filter(|end| *end <= mapping.length)
            .ok_or(SharedMemoryError::InvalidRange)?;
        // SAFETY: The range was checked against the live mapping, and
        // `destination` is valid for its full length. Control-channel
        // serialization prevents the peer from reusing this staging range
        // until the operation completes.
        unsafe {
            libc::memcpy(
                destination.as_mut_ptr().cast(),
                mapping.address.as_ptr().add(offset).cast(),
                destination.len(),
            );
        }
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let mapping = self
            .mapping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        offset
            .checked_add(source.len())
            .filter(|end| *end <= mapping.length)
            .ok_or(SharedMemoryError::InvalidRange)?;
        // SAFETY: The range was checked against the live mapping, and `source`
        // is valid for its full length. The mapping is byte-addressed foreign
        // memory and no Rust references into it are created.
        unsafe {
            libc::memcpy(
                mapping.address.as_ptr().add(offset).cast(),
                source.as_ptr().cast(),
                source.len(),
            );
        }
        Ok(())
    }
}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        // SAFETY: `address` and `length` describe the mapping exclusively owned
        // by this value, and it is unmapped exactly once here.
        let result = unsafe { libc::munmap(self.address.as_ptr().cast(), self.length) };
        debug_assert_eq!(result, 0, "failed to unmap broker shared memory");
    }
}
