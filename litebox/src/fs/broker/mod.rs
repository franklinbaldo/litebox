// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A broker-backed file system for policy-enforced external file access.
//!
//! This module provides a [`FileSystem`] implementation that delegates all operations to an
//! external broker process over a pluggable transport. The broker is responsible for performing
//! the actual host file system operations and enforcing access policies.
//!
//! # Architecture
//!
//! The module is intentionally transport-agnostic (`no_std` + `alloc` compatible).
//! The [`BrokerTransport`] trait defines typed RPC-style methods that the broker FS calls.
//! A concrete implementation (e.g., a gRPC / Tonic client) lives in the runner crate and is
//! injected at construction time — following the same pattern as the [`nine_p`](super::nine_p)
//! file system.
//!
//! # Type Parameters
//!
//! - `Platform`: provides synchronization primitives via [`sync::RawSyncPrimitivesProvider`].
//! - `T`: the transport backend implementing [`BrokerTransport`].

use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroUsize;

use thiserror::Error;

use crate::fs::OFlags;
use crate::fs::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};
use crate::path::Arg;
use crate::{LiteBox, sync};

mod transport;
pub use transport::{BrokerTransport, RemoteDirEntry, RemoteError, RemoteFileStatus};

/// Unique device ID for broker-backed file systems.
const _DEVICE_ID: usize = u32::from_le_bytes(*b"BRKR") as usize;

// Common POSIX errno codes for error mapping.
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const EACCES: u32 = 13;
const EEXIST: u32 = 17;
const ENOTDIR: u32 = 20;
const EISDIR: u32 = 21;
const EINVAL: u32 = 22;
const ESPIPE: u32 = 29;
const ENAMETOOLONG: u32 = 36;
const ENOTEMPTY: u32 = 39;

// ---------------------------------------------------------------------------
// Error type and conversions (mirrored from nine_p)
// ---------------------------------------------------------------------------

/// Error type for broker file system operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io,

    #[error("Invalid pathname")]
    InvalidPathname,

    /// Error reported by the broker, carrying the raw errno.
    #[error("Remote error (errno={0})")]
    Remote(u32),
}

impl From<RemoteError> for Error {
    fn from(e: RemoteError) -> Self {
        Error::Remote(e.errno)
    }
}

impl From<Error> for OpenError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => OpenError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => OpenError::PathError(PathError::NoSuchFileOrDirectory),
                EEXIST => OpenError::AlreadyExists,
                EPERM | EACCES => OpenError::AccessNotAllowed,
                ENOTDIR => OpenError::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG => OpenError::PathError(PathError::InvalidPathname),
                _ => OpenError::Io,
            },
            Error::Io => OpenError::Io,
        }
    }
}

impl From<Error> for ReadError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT | EISDIR => ReadError::NotAFile,
                EPERM | EACCES => ReadError::NotForReading,
                _ => ReadError::Io,
            },
            Error::Io | Error::InvalidPathname => ReadError::Io,
        }
    }
}

impl From<Error> for WriteError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT | EISDIR => WriteError::NotAFile,
                EPERM | EACCES => WriteError::NotForWriting,
                _ => WriteError::Io,
            },
            Error::Io | Error::InvalidPathname => WriteError::Io,
        }
    }
}

impl From<Error> for MkdirError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => MkdirError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => MkdirError::PathError(PathError::NoSuchFileOrDirectory),
                EEXIST => MkdirError::AlreadyExists,
                EPERM | EACCES => MkdirError::NoWritePerms,
                ENOTDIR => MkdirError::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG => MkdirError::PathError(PathError::InvalidPathname),
                _ => MkdirError::Io,
            },
            Error::Io => MkdirError::Io,
        }
    }
}

impl From<Error> for ReadDirError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT | ENOTDIR => ReadDirError::NotADirectory,
                _ => ReadDirError::Io,
            },
            Error::Io | Error::InvalidPathname => ReadDirError::Io,
        }
    }
}

impl From<Error> for UnlinkError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => UnlinkError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => UnlinkError::PathError(PathError::NoSuchFileOrDirectory),
                EISDIR => UnlinkError::IsADirectory,
                EPERM | EACCES => UnlinkError::NoWritePerms,
                ENOTDIR => UnlinkError::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG => UnlinkError::PathError(PathError::InvalidPathname),
                _ => UnlinkError::Io,
            },
            Error::Io => UnlinkError::Io,
        }
    }
}

impl From<Error> for RmdirError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => RmdirError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => RmdirError::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => RmdirError::NotADirectory,
                EPERM | EACCES => RmdirError::NoWritePerms,
                ENAMETOOLONG => RmdirError::PathError(PathError::InvalidPathname),
                ENOTEMPTY => RmdirError::NotEmpty,
                _ => RmdirError::Io,
            },
            Error::Io => RmdirError::Io,
        }
    }
}

impl From<Error> for FileStatusError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => FileStatusError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => FileStatusError::PathError(PathError::NoSuchFileOrDirectory),
                ENAMETOOLONG => FileStatusError::PathError(PathError::InvalidPathname),
                ENOTDIR => FileStatusError::PathError(PathError::ComponentNotADirectory),
                EPERM | EACCES => FileStatusError::PathError(PathError::NoSearchPerms {
                    #[cfg(debug_assertions)]
                    dir: String::new(),
                    #[cfg(debug_assertions)]
                    perms: super::Mode::empty(),
                }),
                _ => FileStatusError::Io,
            },
            Error::Io => FileStatusError::Io,
        }
    }
}

impl From<Error> for SeekError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT => SeekError::ClosedFd,
                EINVAL => SeekError::InvalidOffset,
                ESPIPE => SeekError::NonSeekable,
                _ => SeekError::Io,
            },
            _ => SeekError::Io,
        }
    }
}

impl From<Error> for TruncateError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT => TruncateError::ClosedFd,
                EISDIR => TruncateError::IsDirectory,
                EPERM | EACCES => TruncateError::NotForWriting,
                _ => TruncateError::Io,
            },
            Error::Io | Error::InvalidPathname => TruncateError::Io,
        }
    }
}

impl From<Error> for ChmodError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => ChmodError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => ChmodError::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => ChmodError::PathError(PathError::ComponentNotADirectory),
                EPERM | EACCES => ChmodError::NotTheOwner,
                _ => ChmodError::Io,
            },
            Error::Io => ChmodError::Io,
        }
    }
}

impl From<Error> for ChownError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => ChownError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => ChownError::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => ChownError::PathError(PathError::ComponentNotADirectory),
                EPERM | EACCES => ChownError::NotTheOwner,
                _ => ChownError::Io,
            },
            Error::Io => ChownError::Io,
        }
    }
}

// ---------------------------------------------------------------------------
// FileSystem implementation
// ---------------------------------------------------------------------------

/// A file system backed by an external broker process.
///
/// Every operation is forwarded over the [`BrokerTransport`] to the broker,
/// which performs the actual host FS operation after consulting its policy
/// engine.
///
/// # Type Parameters
///
/// - `Platform`: provides raw synchronisation primitives.
/// - `T`: the transport backend.
pub struct FileSystem<Platform: sync::RawSyncPrimitivesProvider, T: BrokerTransport> {
    /// Reference to the LiteBox instance (for descriptor table access).
    litebox: LiteBox<Platform>,
    /// The transport to the broker.
    transport: T,
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: BrokerTransport> FileSystem<Platform, T> {
    /// Create a new broker-backed file system.
    pub fn new(litebox: &LiteBox<Platform>, transport: T) -> Self {
        Self {
            litebox: litebox.clone(),
            transport,
        }
    }

    /// Resolve a `path::Arg` into a `String`, returning an [`Error`] on
    /// failure.
    fn resolve_path(path: impl Arg) -> Result<String, Error> {
        path.as_rust_str()
            .map(String::from)
            .map_err(|_| Error::InvalidPathname)
    }

    /// Convert a [`RemoteFileStatus`] into a [`super::FileStatus`].
    #[expect(
        clippy::cast_possible_truncation,
        reason = "remote u64/u32 values are truncated to usize/u16 by design in the no_std bridge"
    )]
    fn remote_to_file_status(s: &RemoteFileStatus) -> super::FileStatus {
        let file_type = match s.file_type {
            2 => super::FileType::Directory,
            4 => super::FileType::CharacterDevice,
            _ => super::FileType::RegularFile,
        };

        super::FileStatus {
            file_type,
            mode: super::Mode::from_bits_truncate(s.mode),
            size: s.size as usize,
            owner: super::UserInfo {
                user: s.uid as u16,
                group: s.gid as u16,
            },
            node_info: super::NodeInfo {
                dev: s.dev as usize,
                ino: s.ino as usize,
                rdev: NonZeroUsize::new(s.rdev as usize),
            },
            blksize: s.blksize as usize,
        }
    }

    /// Convert a [`RemoteDirEntry`] into a [`super::DirEntry`].
    fn remote_to_dir_entry(e: RemoteDirEntry) -> super::DirEntry {
        let file_type = match e.file_type {
            2 => super::FileType::Directory,
            4 => super::FileType::CharacterDevice,
            _ => super::FileType::RegularFile,
        };

        super::DirEntry {
            name: e.name,
            file_type,
            ino_info: None,
        }
    }
}

// -- Sealed trait (required by the FileSystem trait) -------------------------

impl<Platform: sync::RawSyncPrimitivesProvider, T: BrokerTransport> super::private::Sealed
    for FileSystem<Platform, T>
{
}

// -- FileSystem trait implementation ----------------------------------------

impl<Platform: sync::RawSyncPrimitivesProvider, T: BrokerTransport> super::FileSystem
    for FileSystem<Platform, T>
{
    fn open(
        &self,
        path: impl Arg,
        flags: OFlags,
        mode: super::Mode,
    ) -> Result<crate::fd::TypedFd<Self>, OpenError> {
        let path_str = Self::resolve_path(path)?;
        let remote_fd = self
            .transport
            .open(&path_str, flags.bits(), mode.bits())
            .map_err(Error::from)?;

        let descriptor = Descriptor { remote_fd };
        let typed_fd = self.litebox.descriptor_table_mut().insert(descriptor);
        Ok(typed_fd)
    }

    fn close(&self, fd: &crate::fd::TypedFd<Self>) -> Result<(), super::errors::CloseError> {
        let remote_fd = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| desc.entry.remote_fd);
        if let Some(remote_fd) = remote_fd {
            // Best-effort close on the broker side.
            let _ = self.transport.close(remote_fd);
        }
        Ok(())
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "usize → u32/u64 casts are safe on 64-bit targets; broker protocol uses u32/u64"
    )]
    fn read(
        &self,
        fd: &crate::fd::TypedFd<Self>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let remote_fd = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| desc.entry.remote_fd)
            .ok_or(ReadError::ClosedFd)?;

        let data = self
            .transport
            .read(remote_fd, buf.len() as u32, offset.map(|o| o as u64))
            .map_err(Error::from)?;

        let n = core::cmp::min(data.len(), buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    fn write(
        &self,
        fd: &crate::fd::TypedFd<Self>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let remote_fd = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| desc.entry.remote_fd)
            .ok_or(WriteError::ClosedFd)?;

        let written = self
            .transport
            .write(remote_fd, buf, offset.map(|o| o as u64))
            .map_err(Error::from)?;
        Ok(written)
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "u64 → usize cast; 64-bit broker protocol values fit on 64-bit targets"
    )]
    fn seek(
        &self,
        fd: &crate::fd::TypedFd<Self>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, SeekError> {
        let remote_fd = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| desc.entry.remote_fd)
            .ok_or(SeekError::ClosedFd)?;

        let whence_val = match whence {
            super::SeekWhence::RelativeToBeginning => 0u32,
            super::SeekWhence::RelativeToCurrentOffset => 1u32,
            super::SeekWhence::RelativeToEnd => 2u32,
        };

        let pos = self
            .transport
            .seek(remote_fd, offset as i64, whence_val)
            .map_err(Error::from)?;
        Ok(pos as usize)
    }

    fn truncate(
        &self,
        fd: &crate::fd::TypedFd<Self>,
        length: usize,
        _reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let remote_fd = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| desc.entry.remote_fd)
            .ok_or(TruncateError::ClosedFd)?;

        self.transport
            .truncate(remote_fd, length as u64)
            .map_err(Error::from)?;
        Ok(())
    }

    fn chmod(&self, path: impl Arg, mode: super::Mode) -> Result<(), ChmodError> {
        let path_str = Self::resolve_path(path)?;
        self.transport
            .chmod(&path_str, mode.bits())
            .map_err(Error::from)?;
        Ok(())
    }

    fn chown(
        &self,
        _path: impl Arg,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        // chown is not part of the core broker operations; return a no-op
        // success for now. A future revision can add a Chown RPC.
        Ok(())
    }

    fn unlink(&self, path: impl Arg) -> Result<(), UnlinkError> {
        let path_str = Self::resolve_path(path)?;
        self.transport.unlink(&path_str).map_err(Error::from)?;
        Ok(())
    }

    fn mkdir(&self, path: impl Arg, mode: super::Mode) -> Result<(), MkdirError> {
        let path_str = Self::resolve_path(path)?;
        self.transport
            .mkdir(&path_str, mode.bits())
            .map_err(Error::from)?;
        Ok(())
    }

    fn rmdir(&self, path: impl Arg) -> Result<(), RmdirError> {
        let path_str = Self::resolve_path(path)?;
        self.transport.rmdir(&path_str).map_err(Error::from)?;
        Ok(())
    }

    fn rename(
        &self,
        _old_path: impl Arg,
        _new_path: impl Arg,
    ) -> Result<(), super::errors::RenameError> {
        // Rename is not yet supported over the broker transport.
        Err(super::errors::RenameError::ReadOnlyFileSystem)
    }

    fn read_dir(
        &self,
        fd: &crate::fd::TypedFd<Self>,
    ) -> Result<Vec<super::DirEntry>, ReadDirError> {
        let remote_fd = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| desc.entry.remote_fd)
            .ok_or(ReadDirError::ClosedFd)?;

        let entries = self.transport.read_dir(remote_fd).map_err(Error::from)?;

        Ok(entries.into_iter().map(Self::remote_to_dir_entry).collect())
    }

    fn file_status(&self, path: impl Arg) -> Result<super::FileStatus, FileStatusError> {
        let path_str = Self::resolve_path(path)?;
        let stat = self.transport.stat(&path_str).map_err(Error::from)?;
        Ok(Self::remote_to_file_status(&stat))
    }

    fn fd_file_status(
        &self,
        fd: &crate::fd::TypedFd<Self>,
    ) -> Result<super::FileStatus, FileStatusError> {
        let remote_fd = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| desc.entry.remote_fd)
            .ok_or(FileStatusError::ClosedFd)?;

        let stat = self.transport.fd_stat(remote_fd).map_err(Error::from)?;
        Ok(Self::remote_to_file_status(&stat))
    }
}

// ---------------------------------------------------------------------------
// Descriptor & FD integration
// ---------------------------------------------------------------------------

/// Internal descriptor state for a broker-backed file descriptor.
///
/// Each descriptor stores the server-assigned remote FD identifier.
#[derive(Debug)]
struct Descriptor {
    /// Broker-side file descriptor identifier.
    remote_fd: u64,
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { sync::RawSyncPrimitivesProvider }, T: { BrokerTransport };
    FileSystem<Platform, T>;
    Descriptor;
    -> BrokerFd<Platform, T>;
}
