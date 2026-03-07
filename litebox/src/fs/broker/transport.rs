// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Transport abstraction for the broker file system.
//!
//! [`BrokerTransport`] defines the RPC-style interface that the broker
//! [`FileSystem`](super::FileSystem) uses to communicate with an external
//! broker process.  The trait is intentionally `no_std` + `alloc` compatible so
//! it can live in the litebox core crate.  A concrete implementation (e.g., a
//! Tonic gRPC client) is provided by the runner crate.

use alloc::string::String;
use alloc::vec::Vec;

/// Error returned by the broker, carrying a POSIX errno code.
#[derive(Debug)]
pub struct RemoteError {
    /// POSIX errno code.
    pub errno: u32,
}

/// File status information returned by the broker.
#[derive(Debug)]
pub struct RemoteFileStatus {
    /// File type (1 = regular, 2 = directory, 3 = symlink, 4 = char device,
    /// 5 = block device, 6 = fifo, 7 = socket).
    pub file_type: u8,
    /// Permission mode bits.
    pub mode: u32,
    /// File size in bytes.
    pub size: u64,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Device ID.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Device type (for special files; 0 otherwise).
    pub rdev: u64,
    /// Preferred I/O block size.
    pub blksize: u64,
}

/// A single directory entry returned by the broker.
#[derive(Debug)]
pub struct RemoteDirEntry {
    /// Entry name (file/directory name, without path).
    pub name: String,
    /// File type (same encoding as [`RemoteFileStatus::file_type`]).
    pub file_type: u8,
}

/// Transport trait for communicating with the file broker.
///
/// Each method maps to a single broker RPC.  Implementations must be
/// `Send + Sync` because the file system may be called from multiple threads.
///
/// All paths are relative to the broker's root directory.
pub trait BrokerTransport: Send + Sync {
    /// Open a file, returning a broker-assigned FD identifier.
    fn open(&self, path: &str, flags: u32, mode: u32) -> Result<u64, RemoteError>;

    /// Close a broker-side FD.
    fn close(&self, fd: u64) -> Result<(), RemoteError>;

    /// Read up to `count` bytes from `fd`.
    ///
    /// If `offset` is `Some`, uses pread semantics.
    fn read(&self, fd: u64, count: u32, offset: Option<u64>) -> Result<Vec<u8>, RemoteError>;

    /// Write `data` to `fd`.
    ///
    /// If `offset` is `Some`, uses pwrite semantics.  Returns the number of
    /// bytes written.
    fn write(&self, fd: u64, data: &[u8], offset: Option<u64>) -> Result<usize, RemoteError>;

    /// Seek `fd` to the given `offset` relative to `whence`
    /// (0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END).
    ///
    /// Returns the new absolute offset.
    fn seek(&self, fd: u64, offset: i64, whence: u32) -> Result<u64, RemoteError>;

    /// Truncate `fd` to `length` bytes.
    fn truncate(&self, fd: u64, length: u64) -> Result<(), RemoteError>;

    /// Change file permissions at `path`.
    fn chmod(&self, path: &str, mode: u32) -> Result<(), RemoteError>;

    /// Get file status by path.
    fn stat(&self, path: &str) -> Result<RemoteFileStatus, RemoteError>;

    /// Get file status for an open FD.
    fn fd_stat(&self, fd: u64) -> Result<RemoteFileStatus, RemoteError>;

    /// Create a directory at `path` with the given `mode`.
    fn mkdir(&self, path: &str, mode: u32) -> Result<(), RemoteError>;

    /// Remove a directory at `path`.
    fn rmdir(&self, path: &str) -> Result<(), RemoteError>;

    /// Unlink a file at `path`.
    fn unlink(&self, path: &str) -> Result<(), RemoteError>;

    /// Read directory entries from `fd`.
    fn read_dir(&self, fd: u64) -> Result<Vec<RemoteDirEntry>, RemoteError>;
}
