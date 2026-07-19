// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use crate::ObjectHandle;

/// Maximum pipe payload carried by one control-path request or response.
///
/// This leaves room for the broker envelope and operation metadata within the
/// smallest currently supported transport frame.
pub const MAX_PIPE_TRANSFER_SIZE: u32 = 32 * 1024;

/// Size of each directional shared-memory staging ring.
pub const PIPE_SHARED_MEMORY_REGION_SIZE: usize = MAX_PIPE_TRANSFER_SIZE as usize;

/// Total size of one pipe's read and write staging rings.
pub const PIPE_SHARED_MEMORY_SIZE: usize = PIPE_SHARED_MEMORY_REGION_SIZE * 2;

/// Request to create a broker-owned byte pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatePipeRequest {
    /// Maximum number of buffered bytes.
    pub capacity: u64,
    /// Maximum write size that must be accepted atomically.
    pub atomic_write_size: u64,
}

/// Response to a pipe create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatePipeResponse {
    /// Handle for the read endpoint.
    pub read_handle: ObjectHandle,
    /// Handle for the write endpoint.
    pub write_handle: ObjectHandle,
    /// Whether the control response includes the pipe's shared-memory resource.
    pub shared_memory: bool,
}

/// Request to read bytes from a pipe endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadPipeRequest {
    /// Read endpoint handle.
    pub handle: ObjectHandle,
    /// Maximum number of bytes to return.
    pub length: u32,
}

/// Response containing bytes read from a pipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadPipeResponse {
    /// Bytes removed from the pipe.
    pub data: Vec<u8>,
}

/// Request to read pipe bytes into the shared-memory read ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadPipeSharedRequest {
    /// Read endpoint handle.
    pub handle: ObjectHandle,
    /// Byte offset within the read ring.
    pub offset: u32,
    /// Maximum number of bytes to read.
    pub length: u32,
}

/// Response describing bytes placed in the shared-memory read ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadPipeSharedResponse {
    /// Number of bytes placed in the ring.
    pub read: u32,
}

/// Request to write bytes to a pipe endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WritePipeRequest {
    /// Write endpoint handle.
    pub handle: ObjectHandle,
    /// Bytes to append to the pipe.
    pub data: Vec<u8>,
}

/// Request to write bytes staged in the shared-memory write ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritePipeSharedRequest {
    /// Write endpoint handle.
    pub handle: ObjectHandle,
    /// Byte offset within the write ring.
    pub offset: u32,
    /// Number of staged bytes to write.
    pub length: u32,
}

/// Response describing a completed pipe write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritePipeResponse {
    /// Number of bytes appended to the pipe.
    pub written: u32,
}
