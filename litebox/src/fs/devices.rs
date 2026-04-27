// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Device backend for the new [`super::backend::Backend`] trait.
//!
//! Provides `/dev/{stdin,stdout,stderr,null,urandom}`. Walking handles are
//! trivial (no lock); permissions are self-enforced (the resolver skips
//! perm checks via `permissions: None`). All mutating ops return the
//! appropriate central error variant.

use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::LiteBox;
use crate::sync::RawSyncPrimitivesProvider;

use super::backend::{
    Backend, InodeAllocator, WalkAccessMode, WalkOutcome, WalkedComponent, Write, WritePosition,
    sealed,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::resolver::BackendWithLitebox;
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

/// Walking handle. Tracks where we are in the (extremely shallow) walk.
/// `/` -> root, `/dev` -> Dev, `/dev/<name>` -> not used as a walking
/// handle directly (we never walk *past* a device file).
#[derive(Clone, Copy)]
pub struct DevicesWalkingHandle<M: WalkAccessMode> {
    location: WalkLocation,
    _mode: PhantomData<fn() -> M>,
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

/// Owned dir handle. Today only `/dev` is openable as a directory.
#[derive(Debug, Clone, Copy)]
pub struct DeviceDirHandle {
    location: DirLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirLocation {
    Root,
    Dev,
}

impl<Platform> sealed::Sealed for Devices<Platform> where
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
    type WalkingDirHandle<'a, M: WalkAccessMode>
        = DevicesWalkingHandle<M>
    where
        Self: 'a;
    type FileHandle = DeviceFileHandle;
    type OpenDirHandle = DeviceDirHandle;

    // The legacy `devices` accepted essentially all the user-facing flags
    // and silently ignored the ones it didn't care about. We declare the
    // commonly-touched flags; any others are filtered through the
    // resolver's `TRIVIALLY_IGNORED_OFLAGS` whitelist.
    const SUPPORTED_OFLAGS: OFlags = OFlags::from_bits_retain(
        OFlags::RDONLY.bits()
            | OFlags::WRONLY.bits()
            | OFlags::RDWR.bits()
            | OFlags::CREAT.bits()
            | OFlags::EXCL.bits()
            | OFlags::TRUNC.bits()
            | OFlags::APPEND.bits()
            | OFlags::CLOEXEC.bits()
            | OFlags::NOCTTY.bits()
            | OFlags::NOFOLLOW.bits()
            | OFlags::LARGEFILE.bits()
            | OFlags::NONBLOCK.bits()
            | OFlags::DIRECTORY.bits(),
    );

    fn root<M: WalkAccessMode>(&self) -> Self::WalkingDirHandle<'_, M> {
        DevicesWalkingHandle {
            location: WalkLocation::Root,
            _mode: PhantomData,
        }
    }

    fn walk<'a, M: WalkAccessMode>(
        &'a self,
        from: Self::WalkingDirHandle<'a, M>,
        components: &[&str],
    ) -> Result<WalkOutcome<'a, Self, M>, WalkError> {
        // Devices is a strictly two-level namespace: `/` -> `/dev` ->
        // device files. Walks past device files (or any other path) yield
        // not-found.
        let mut location = from.location;
        let mut statuses: Vec<WalkedComponent> = Vec::with_capacity(components.len());
        for &c in components {
            match (location, c) {
                (WalkLocation::Root, "dev") => {
                    statuses.push(WalkedComponent {
                        file_type: FileType::Directory,
                        node_info: self.dev_dir_inode.clone(),
                        size: super::DEFAULT_DIRECTORY_SIZE,
                        permissions: None,
                    });
                    location = WalkLocation::Dev;
                }
                (WalkLocation::Dev, name) if Device::from_name(name).is_some() => {
                    let dev = Device::from_name(name).unwrap();
                    let st = dev.file_status();
                    statuses.push(WalkedComponent {
                        file_type: st.file_type.clone(),
                        node_info: st.node_info,
                        size: st.size,
                        permissions: None,
                    });
                    // The resolver expects `final_handle` to be the dir
                    // *containing* the final element, so we don't advance
                    // past the device file.
                }
                _ => {
                    return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
                }
            }
        }
        let final_handle = DevicesWalkingHandle {
            location,
            _mode: PhantomData,
        };
        Ok(WalkOutcome::Complete {
            statuses,
            final_handle,
        })
    }

    fn open_file_at<'a, M: WalkAccessMode>(
        &'a self,
        dir: Self::WalkingDirHandle<'a, M>,
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

    fn open_dir_at<'a, M: WalkAccessMode>(
        &'a self,
        dir: Self::WalkingDirHandle<'a, M>,
        name: &str,
    ) -> Result<Self::OpenDirHandle, OpenError> {
        // Convention: `name = ""` means "open me as a dir" (i.e. the
        // current `dir` walking handle is the target).
        let target = match (dir.location, name) {
            (loc, "") => loc,
            (WalkLocation::Root, "dev") => WalkLocation::Dev,
            // Trying to open a device file as a directory.
            (WalkLocation::Dev, n) if Device::from_name(n).is_some() => {
                return Err(OpenError::PathError(PathError::ComponentNotADirectory));
            }
            _ => return Err(OpenError::PathError(PathError::NoSuchFileOrDirectory)),
        };
        let location = match target {
            WalkLocation::Root => DirLocation::Root,
            WalkLocation::Dev => DirLocation::Dev,
        };
        Ok(DeviceDirHandle { location })
    }

    fn list_dir(&self, handle: &Self::OpenDirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
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

    fn write(
        &self,
        h: &Self::FileHandle,
        buf: &[u8],
        _pos: WritePosition,
    ) -> Result<usize, WriteError> {
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

    fn dir_status(&self, h: &Self::OpenDirHandle) -> Result<FileStatus, FileStatusError> {
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

    fn is_seekable(&self, _h: &Self::FileHandle) -> bool {
        // All devices accept lseek and return 0 (no-op). This matches the
        // legacy behavior where stdio, null, and urandom all returned Ok(0)
        // from seek. The resolver's seek path for seekable entries falls
        // through to Ok(0) since these devices have no real cursor.
        true
    }

    // ---- Mutating ops (only callable with `Write` walking handle) ------

    fn create_file_at<'a>(
        &'a self,
        _dir: Self::WalkingDirHandle<'a, Write>,
        _name: &str,
        _mode: Mode,
    ) -> Result<Self::FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn mkdir_at<'a>(
        &'a self,
        _dir: Self::WalkingDirHandle<'a, Write>,
        _name: &str,
        _mode: Mode,
    ) -> Result<(), MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at<'a>(
        &'a self,
        _dir: Self::WalkingDirHandle<'a, Write>,
        _name: &str,
    ) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_at<'a>(
        &'a self,
        _dir: Self::WalkingDirHandle<'a, Write>,
        _name: &str,
    ) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn chmod_at<'a>(
        &'a self,
        _dir: Self::WalkingDirHandle<'a, Write>,
        _name: &str,
        _mode: Mode,
    ) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chown_at<'a>(
        &'a self,
        _dir: Self::WalkingDirHandle<'a, Write>,
        _name: &str,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        Err(ChownError::ReadOnlyFileSystem)
    }
}

impl<Platform> BackendWithLitebox for Devices<Platform>
where
    Platform: RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::CrngProvider
        + 'static,
{
    type Platform = Platform;
    fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
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
