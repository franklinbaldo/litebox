// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Address space management for multi-process support.
//!
//! Platforms implement [`AddressSpaceProvider`] to manage isolated or shared
//! memory regions for guest processes.

use core::fmt::Debug;
use core::hash::Hash;
use core::ops::Range;
use thiserror::Error;

/// Platform-wide property: are address spaces isolated or shared?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpaceKind {
    /// Each address space has independent memory (e.g., kernel page tables,
    /// separate host processes). The platform handles memory isolation;
    /// the shim does not need to manage CoW.
    Isolated,
    /// Address spaces share the same host memory (e.g., VA partitions in a
    /// single userland process). The shim is responsible for copy-on-write
    /// or other memory separation.
    SharedMemory,
}

/// Errors from address space operations.
#[derive(Error, Debug)]
pub enum AddressSpaceError {
    #[error("no space available for a new address space")]
    NoSpace,
    #[error("the address space ID is invalid")]
    InvalidId,
    #[error("address space operations are not supported by this platform")]
    NotSupported,
}

/// Address space management for multi-process support.
///
/// Platforms implement this trait to create, destroy, and switch between
/// address spaces. Each address space represents an isolated (or partitioned)
/// memory region for a guest process.
pub trait AddressSpaceProvider {
    /// An opaque identifier for an address space.
    type AddressSpaceId: Copy + Eq + Send + Sync + Hash + Debug + 'static;

    /// Platform-wide: are address spaces isolated or shared?
    const ADDRESS_SPACE_KIND: AddressSpaceKind;

    /// Create a new address space.
    fn create_address_space(&self) -> Result<Self::AddressSpaceId, AddressSpaceError> {
        Err(AddressSpaceError::NotSupported)
    }

    /// Destroy an address space, releasing all resources.
    fn destroy_address_space(&self, _id: Self::AddressSpaceId) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotSupported)
    }

    /// Make `id` the active address space for the current thread.
    ///
    /// Activation is thread-local: each thread independently tracks its
    /// active address space. On kernel platforms this switches page tables.
    /// On userland platforms this may be a no-op.
    fn activate_address_space(&self, _id: Self::AddressSpaceId) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotSupported)
    }

    /// Execute `f` with the given address space active, then restore the
    /// previously active address space.
    fn with_address_space<R>(
        &self,
        _id: Self::AddressSpaceId,
        f: impl FnOnce() -> R,
    ) -> Result<R, AddressSpaceError> {
        let _ = f;
        Err(AddressSpaceError::NotSupported)
    }

    /// Return the VA range available to the given address space.
    ///
    /// Primarily meaningful for [`AddressSpaceKind::SharedMemory`] platforms
    /// (e.g., userland VA partitions) where the shim needs to scope memory
    /// operations (mmap, brk, etc.) to the correct region. Platforms with
    /// hardware-isolated address spaces typically return `NotSupported`.
    fn address_space_range(
        &self,
        _id: Self::AddressSpaceId,
    ) -> Result<Range<usize>, AddressSpaceError> {
        Err(AddressSpaceError::NotSupported)
    }
}
