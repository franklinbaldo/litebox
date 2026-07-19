// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Transport-neutral shared-memory resources attached to control responses.

use thiserror::Error;

/// Error accessing a shared-memory resource.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedMemoryError {
    /// The requested byte range is outside the shared-memory resource.
    #[error("shared-memory range is out of bounds")]
    InvalidRange,
    /// The channel does not support shared-memory resources.
    #[error("shared memory is unsupported")]
    Unsupported,
}

/// Byte-copy access to a shared-memory resource supplied by a control channel.
///
/// Implementations must keep the backing resource alive for the lifetime of
/// the value and synchronize concurrent accesses without exposing typed
/// references into memory writable by another process.
pub trait SharedMemory: Send + Sync + 'static {
    /// Returns the mapped resource length in bytes.
    fn len(&self) -> usize;

    /// Returns whether the resource is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies bytes from shared memory into `destination`.
    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError>;

    /// Copies bytes from `source` into shared memory.
    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError>;
}

/// Shared-memory type for control channels that do not support attachments.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSharedMemory;

impl SharedMemory for NoSharedMemory {
    fn len(&self) -> usize {
        0
    }

    fn read(&self, _offset: usize, _destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        Err(SharedMemoryError::Unsupported)
    }

    fn write(&self, _offset: usize, _source: &[u8]) -> Result<(), SharedMemoryError> {
        Err(SharedMemoryError::Unsupported)
    }
}
