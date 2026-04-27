// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-y devices [`super::backend::Backend`].
//!
//! Provides `/dev/{stdin,stdout,null,urandom,...}`.

// XXX(jayb): soon this will switch to just being {stdin,stdout,...}, so that it is _mounted_ at
// `/dev/` rather than associated at `/`, but that will be later.

use alloc::string::String;
use alloc::vec::Vec;

use crate::LiteBox;
use crate::sync::RawSyncPrimitivesProvider;

use super::backend::{Backend, WalkOutcome, WalkedComponent};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, UserInfo};

/// Block size for stdio devices
const STDIO_BLOCK_SIZE: usize = 1024;
/// Block size for null device
const NULL_BLOCK_SIZE: usize = 0x1000;
/// Block size for /dev/urandom
const URANDOM_BLOCK_SIZE: usize = 0x1000;

/// Constant node information for all 3 stdio devices.
const STDIO_NODE_INFO: NodeInfo = NodeInfo {
    dev: 64,
    ino: 9,
    rdev: core::num::NonZeroUsize::new(34822),
};
const NULL_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 4,
    rdev: core::num::NonZeroUsize::new(0x103),
};
const URANDOM_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 8,
    rdev: core::num::NonZeroUsize::new(0x109),
};

/// Inode info for `/dev` itself. Allocated via [`InodeAllocator`].
fn dev_dir_node_info(allocator: &InodeAllocator) -> NodeInfo {
    // Use the first allocation; for the standalone case this is
    // `(STANDALONE_DEVICE_ID, 0)`, which is stable for back-compat
    // purposes (devices was not previously addressable as a directory at
    // all, so there's no compat to break).
    allocator.next()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Device {
    Stdin,
    Stdout,
    Stderr,
    Null,
    URandom,
}

impl Device {
    const ALL: &'static [(&'static str, Device)] = &[
        ("stdin", Device::Stdin),
        ("stdout", Device::Stdout),
        ("stderr", Device::Stderr),
        ("null", Device::Null),
        ("urandom", Device::URandom),
    ];

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().find(|(n, _)| *n == name).map(|(_, d)| *d)
    }

    fn file_status(self) -> FileStatus {
        match self {
            Device::Stdin | Device::Stdout | Device::Stderr => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: STDIO_NODE_INFO,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Null => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: NULL_NODE_INFO,
                blksize: NULL_BLOCK_SIZE,
            },
            Device::URandom => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: URANDOM_NODE_INFO,
                blksize: URANDOM_BLOCK_SIZE,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// The new-trait device backend. Construct via [`Self::new`] and wrap with
/// [`super::resolver::Resolver`].
pub struct Devices<Platform>
where
    Platform: RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::CrngProvider
        + 'static,
{
    litebox: LiteBox<Platform>,
    /// Stable inode info for `/dev`.
    dev_dir_inode: NodeInfo,
    _alloc: InodeAllocator,
}

impl<Platform> Devices<Platform>
where
    Platform: RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::CrngProvider
        + 'static,
{
    /// Construct a new `Devices` backend with a standalone allocator.
    ///
    /// Single-backend usage that doesn't go through a composer.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self::with_allocator(litebox, InodeAllocator::standalone())
    }

    /// Construct a new `Devices` backend with the supplied allocator.
    #[must_use]
    pub fn with_allocator(litebox: &LiteBox<Platform>, allocator: InodeAllocator) -> Self {
        let dev_dir_inode = dev_dir_node_info(&allocator);
        Self {
            litebox: litebox.clone(),
            dev_dir_inode,
            _alloc: allocator,
        }
    }
}

// Backend handles. All trivial ZSTs aside from the file handle (which is
// just a tag).

/// Walking handle. Tracks where we are in the shallow directory namespace.
#[derive(Clone, Copy)]
pub struct DevicesWalkingHandle {
    location: WalkLocation,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WalkLocation {
    Root,
    Dev,
}

/// Owned file handle; identifies which device backs this fd.
#[derive(Debug, Clone, Copy)]
pub struct DeviceFileHandle {
    device: Device,
}

/// Owned dir handle.
#[derive(Debug, Clone, Copy)]
pub struct DeviceDirHandle {
    location: DirLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirLocation {
    Root,
    Dev,
}

impl<Platform> super::backend::private::Sealed for Devices<Platform> where
    Platform: RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::CrngProvider
        + 'static
{
}

impl<Platform> Backend for Devices<Platform>
where
    Platform: RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::CrngProvider
        + 'static,
{
    type WalkingDirHandle<'a>
        = DevicesWalkingHandle
    where
        Self: 'a;
    type FileHandle = DeviceFileHandle;
    type DirHandle = DeviceDirHandle;

    fn root(&self) -> Self::WalkingDirHandle<'_> {
        DevicesWalkingHandle {
            location: WalkLocation::Root,
        }
    }

    fn walk_directories<'a>(
        &'a self,
        from: Self::WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<Self::WalkingDirHandle<'a>>, WalkError> {
        // This backend only exposes one directory below root. Device files are
        // final path targets, so directory walking must stop before them.
        let mut location = from.location;
        let mut walked_components: Vec<WalkedComponent> = Vec::with_capacity(components.len());
        for &c in components {
            match (location, c) {
                (WalkLocation::Root, "dev") => {
                    walked_components.push(WalkedComponent { permissions: None });
                    location = WalkLocation::Dev;
                }
                (WalkLocation::Dev, name) if Device::from_name(name).is_some() => {
                    return Err(WalkError::PathError(PathError::ComponentNotADirectory));
                }
                _ => {
                    return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
                }
            }
        }
        let final_handle = DevicesWalkingHandle { location };
        Ok(WalkOutcome {
            components: walked_components,
            last: final_handle,
        })
    }

    fn owned_dir_at(&self, dir: Self::WalkingDirHandle<'_>) -> Self::DirHandle {
        DeviceDirHandle {
            location: match dir.location {
                WalkLocation::Root => DirLocation::Root,
                WalkLocation::Dev => DirLocation::Dev,
            },
        }
    }

    fn walking_dir_at<'a>(&'a self, dir: &Self::DirHandle) -> Option<Self::WalkingDirHandle<'a>> {
        Some(DevicesWalkingHandle {
            location: match dir.location {
                DirLocation::Root => WalkLocation::Root,
                DirLocation::Dev => WalkLocation::Dev,
            },
        })
    }

    fn open_file_at(
        &self,
        dir: Self::WalkingDirHandle<'_>,
        name: &str,
        _flags: OFlags,
    ) -> Result<Self::FileHandle, OpenError> {
        if dir.location != WalkLocation::Dev {
            return Err(OpenError::PathError(PathError::NoSuchFileOrDirectory));
        }
        let device = Device::from_name(name)
            .ok_or(OpenError::PathError(PathError::NoSuchFileOrDirectory))?;
        Ok(DeviceFileHandle { device })
    }

    fn list_dir_at(&self, handle: Self::DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        match handle.location {
            DirLocation::Root => Ok(alloc::vec![DirEntry {
                name: String::from("dev"),
                file_type: FileType::Directory,
                ino_info: Some(self.dev_dir_inode.clone()),
            }]),
            DirLocation::Dev => Ok(Device::ALL
                .iter()
                .map(|(n, d)| DirEntry {
                    name: String::from(*n),
                    file_type: FileType::CharacterDevice,
                    ino_info: Some(d.file_status().node_info),
                })
                .collect()),
        }
    }

    fn read(
        &self,
        h: &Self::FileHandle,
        buf: &mut [u8],
        _offset: usize,
    ) -> Result<usize, ReadError> {
        match h.device {
            Device::Stdin => self
                .litebox
                .x
                .platform
                .read_from_stdin(buf)
                .map_err(|e| match e {
                    crate::platform::StdioReadError::Closed => ReadError::Io,
                }),
            Device::Stdout | Device::Stderr => Err(ReadError::NotForReading),
            Device::Null => Ok(0),
            Device::URandom => {
                // Devices `Platform` only requires `StdioProvider`; CRNG
                // is requested separately. To keep the existing call-site
                // signature unchanged, fall back to a not-supported error
                // when the platform doesn't expose a CRNG. The legacy
                // device path required `CrngProvider`; we re-add that
                // requirement on the read paths via the `urandom_read`
                // helper below to keep the type sigs stable.
                Ok(urandom_read::<Platform>(self, buf))
            }
        }
    }

    fn write(&self, h: &Self::FileHandle, buf: &[u8], _offset: usize) -> Result<usize, WriteError> {
        let stream = match h.device {
            Device::Stdin => return Err(WriteError::NotForWriting),
            Device::Stdout => crate::platform::StdioOutStream::Stdout,
            Device::Stderr => crate::platform::StdioOutStream::Stderr,
            Device::Null | Device::URandom => return Ok(buf.len()),
        };
        self.litebox
            .x
            .platform
            .write_to(stream, buf)
            .map_err(|e| match e {
                crate::platform::StdioWriteError::Closed => WriteError::Io,
            })
    }

    fn truncate(&self, _h: &Self::FileHandle, _len: usize) -> Result<(), TruncateError> {
        Err(TruncateError::IsTerminalDevice)
    }

    fn file_status(&self, h: &Self::FileHandle) -> Result<FileStatus, FileStatusError> {
        Ok(h.device.file_status())
    }

    fn dir_status(&self, h: &Self::DirHandle) -> Result<FileStatus, FileStatusError> {
        Ok(match h.location {
            DirLocation::Root => FileStatus {
                file_type: FileType::Directory,
                mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: UserInfo::ROOT,
                node_info: NodeInfo {
                    dev: self.dev_dir_inode.dev,
                    ino: 0,
                    rdev: None,
                },
                blksize: super::DEFAULT_DIRECTORY_SIZE,
            },
            DirLocation::Dev => FileStatus {
                file_type: FileType::Directory,
                mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: UserInfo::ROOT,
                node_info: self.dev_dir_inode.clone(),
                blksize: super::DEFAULT_DIRECTORY_SIZE,
            },
        })
    }

    fn create_file_at(
        &self,
        _dir: Self::DirHandle,
        _name: &str,
        _mode: Mode,
    ) -> Result<Self::FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn mkdir_at(
        &self,
        _dir: Self::DirHandle,
        _name: &str,
        _mode: Mode,
    ) -> Result<Self::DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, _dir: Self::DirHandle, _name: &str) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_at(&self, _dir: Self::DirHandle, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn chmod_at(&self, _dir: Self::DirHandle, _name: &str, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chown_at(
        &self,
        _dir: Self::DirHandle,
        _name: &str,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        Err(ChownError::ReadOnlyFileSystem)
    }
}

// `urandom_read` is a small helper used to keep the `read` arm focused.
fn urandom_read<Platform>(backend: &Devices<Platform>, buf: &mut [u8]) -> usize
where
    Platform: RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::CrngProvider
        + 'static,
{
    backend.litebox.x.platform.fill_bytes_crng(buf);
    buf.len()
}
