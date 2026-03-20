// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A read-only `.lbfs`-backed file system.
//!
//! Analogous to [`super::tar_ro`], but uses the page-aligned `.lbfs` archive
//! format from [`litebox_util_fs_archive`] instead of `.tar`.

// TODO(jb): De-duplicate with the tar_ro, so that we don't have as much repetition.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

use litebox_util_fs_archive::Archive;

use crate::{
    LiteBox,
    fs::{DirEntry, FileType},
    path::Arg as _,
    sync,
};

use super::{
    Mode, NodeInfo, OFlags, SeekWhence, UserInfo,
    errors::{
        ChmodError, ChownError, CloseError, MkdirError, OpenError, PathError, ReadDirError,
        ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
    },
};

/// Distinct device ID for the lbfs filesystem: `b'lbfs'.hex()`.
const DEVICE_ID: usize = 0x6c626673;

/// Placeholder inode number for directories.
const TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER: usize = 0xFACE;

/// Block size for file system I/O operations.
const BLOCK_SIZE: usize = 4096;

/// An empty `.lbfs` archive (header only, page-padded).
///
/// Contains zero entries. The header is 28 bytes (`MAGIC` + `entry_count=0`),
/// padded to 4096 bytes with zeros.
pub static EMPTY_LBFS_FILE: &[u8] = &{
    let mut buf = [0u8; 4096];
    let magic = b"LiteBoxFSArchive v1\n";
    let mut i = 0;
    while i < magic.len() {
        buf[i] = magic[i];
        i += 1;
    }
    // entry_count = 0 as u64 LE is already all zeros at bytes 20..28
    buf
};

/// A backing implementation for [`FileSystem`](super::FileSystem), storing all
/// files in-memory via a read-only `.lbfs` archive.
pub struct FileSystem<Platform: sync::RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    index: LbfsIndex,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
}

struct IndexedFile {
    /// Byte range within the archive data for this file's content.
    data_start: usize,
    data_len: usize,
    mode: Mode,
    owner: UserInfo,
    ino: usize,
}

struct IndexedDir {
    owner: Option<UserInfo>,
    children: HashMap<String, (FileType, usize)>,
}

struct LbfsIndex {
    /// The raw archive data. Kept alive so slices remain valid.
    archive_data: Cow<'static, [u8]>,
    files: Vec<IndexedFile>,
    files_by_path: HashMap<String, usize>,
    dirs: Vec<IndexedDir>,
    dirs_by_path: HashMap<String, usize>,
}

impl LbfsIndex {
    fn new(archive_data: Cow<'static, [u8]>) -> Self {
        let archive = Archive::parse(archive_data.as_ref()).expect("invalid .lbfs archive data");

        let mut files = Vec::new();
        let mut files_by_path: HashMap<String, usize> = HashMap::new();

        for (idx, entry) in archive.entries().iter().enumerate() {
            if !entry.is_file() {
                continue;
            }

            let mode = mode_from_u32(entry.header.mode.get());
            let owner = UserInfo {
                user: entry.header.uid.get(),
                group: entry.header.gid.get(),
            };

            let file_idx = files.len();
            files.push(IndexedFile {
                data_start: usize::try_from(entry.header.data_offset.get()).unwrap(),
                data_len: usize::try_from(entry.header.byte_size.get()).unwrap(),
                mode,
                owner,
                // ino starts at 1 (zero represents deleted file)
                ino: idx + 1,
            });
            let old = files_by_path.insert(entry.path.clone(), file_idx);
            assert!(
                old.is_none(),
                "lbfs archives with duplicate file paths are unsupported"
            );
        }

        // Build directory tree implicitly from file paths.
        let mut dirs = alloc::vec![IndexedDir {
            owner: None,
            children: HashMap::new(),
        }];
        let mut dirs_by_path: HashMap<String, usize> = [(String::new(), 0)].into_iter().collect();

        // Also register explicitly declared directories from the archive.
        for entry in archive.entries() {
            if entry.is_dir() {
                let dir_path = entry.path.clone();
                let owner = UserInfo {
                    user: entry.header.uid.get(),
                    group: entry.header.gid.get(),
                };
                dirs_by_path.entry(dir_path).or_insert_with(|| {
                    dirs.push(IndexedDir {
                        owner: Some(owner),
                        children: HashMap::new(),
                    });
                    dirs.len() - 1
                });
            }
        }

        for (path, &file_idx) in &files_by_path {
            let file = &files[file_idx];
            let components: Vec<&str> = path
                .split('/')
                .filter(|component| !component.is_empty())
                .collect();

            let mut parent = String::new();
            let mut parent_dir_idx = 0;
            for (component_idx, component) in components.iter().enumerate() {
                let is_last_component = component_idx + 1 == components.len();
                let (file_type, ino) = if is_last_component {
                    (FileType::RegularFile, file.ino)
                } else {
                    (FileType::Directory, TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER)
                };

                dirs[parent_dir_idx].owner.get_or_insert(file.owner);
                dirs[parent_dir_idx]
                    .children
                    .insert((*component).into(), (file_type, ino));

                if is_last_component {
                    break;
                }

                if parent.is_empty() {
                    parent.push_str(component);
                } else {
                    parent.push('/');
                    parent.push_str(component);
                }
                let child_dir_idx = *dirs_by_path.entry(parent.clone()).or_insert_with(|| {
                    dirs.push(IndexedDir {
                        owner: Some(file.owner),
                        children: HashMap::new(),
                    });
                    dirs.len() - 1
                });
                dirs[child_dir_idx].owner.get_or_insert(file.owner);
                parent_dir_idx = child_dir_idx;
            }
        }

        Self {
            archive_data,
            files,
            files_by_path,
            dirs,
            dirs_by_path,
        }
    }

    fn file_data(&self, file_idx: usize) -> &[u8] {
        let file = &self.files[file_idx];
        &self.archive_data[file.data_start..file.data_start + file.data_len]
    }

    fn file_by_path(&self, path: &str) -> Option<(usize, &IndexedFile)> {
        let file_idx = *self.files_by_path.get(path)?;
        Some((file_idx, &self.files[file_idx]))
    }

    fn dir_by_path(&self, path: &str) -> Option<(usize, &IndexedDir)> {
        let dir_idx = *self.dirs_by_path.get(path)?;
        Some((dir_idx, &self.dirs[dir_idx]))
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> FileSystem<Platform> {
    /// Construct a new `FileSystem` instance from provided `.lbfs` archive data.
    ///
    /// The filesystem stores the provided bytes and builds an index up-front for O(1) lookups.
    /// Using `Cow` avoids an unnecessary copy while allowing either borrowed or owned input.
    ///
    /// Use [`EMPTY_LBFS_FILE`] if you need an empty file system.
    ///
    /// # Panics
    ///
    /// Panics if the provided data is not a valid `.lbfs` archive.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>, archive_data: Cow<'static, [u8]>) -> Self {
        Self {
            litebox: litebox.clone(),
            index: LbfsIndex::new(archive_data),
            current_working_dir: "/".into(),
        }
    }

    /// Gives the absolute path for `path`, resolving any `.` or `..`s, and making sure to account
    /// for any relative paths from current working directory.
    ///
    /// Note: does NOT account for symlinks.
    fn absolute_path(&self, path: impl crate::path::Arg) -> Result<String, PathError> {
        assert!(self.current_working_dir.ends_with('/'));
        let path = path.as_rust_str()?;
        if path.starts_with('/') {
            Ok(path.normalized()?)
        } else {
            Ok((self.current_working_dir.clone() + path.as_rust_str()?).normalized()?)
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::private::Sealed for FileSystem<Platform> {}

impl<Platform: sync::RawSyncPrimitivesProvider> super::FileSystem for FileSystem<Platform> {
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: OFlags,
        _mode: Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        use super::OFlags;
        let currently_supported_oflags: OFlags = OFlags::RDONLY
            | OFlags::WRONLY
            | OFlags::RDWR
            | OFlags::CREAT
            | OFlags::EXCL
            | OFlags::TRUNC
            | OFlags::NOCTTY
            | OFlags::DIRECTORY
            | OFlags::NONBLOCK
            | OFlags::LARGEFILE
            | OFlags::NOFOLLOW
            | OFlags::APPEND;
        if flags.intersects(currently_supported_oflags.complement()) {
            unimplemented!("{flags:?}")
        }
        if flags.contains(OFlags::CREAT) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        let path = self.absolute_path(path)?;
        if path.is_empty() {
            let (idx, _) = self
                .index
                .dir_by_path("")
                .expect("root directory always exists");
            return Ok(self
                .litebox
                .descriptor_table_mut()
                .insert(Descriptor::Dir { idx }));
        }
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if flags.contains(OFlags::RDWR) || flags.contains(OFlags::WRONLY) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        assert!(flags.contains(OFlags::RDONLY));
        let fd = if let Some((idx, _)) = self.index.file_by_path(path) {
            if flags.contains(OFlags::DIRECTORY) {
                return Err(OpenError::PathError(PathError::ComponentNotADirectory));
            }
            self.litebox
                .descriptor_table_mut()
                .insert(Descriptor::File { idx, position: 0 })
        } else if let Some((idx, _)) = self.index.dir_by_path(path) {
            self.litebox
                .descriptor_table_mut()
                .insert(Descriptor::Dir { idx })
        } else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        if flags.contains(OFlags::TRUNC) {
            match self.truncate(&fd, 0, true) {
                Ok(()) => {}
                Err(e) => {
                    self.close(&fd).unwrap();
                    return Err(e.into());
                }
            }
        }
        Ok(fd)
    }

    fn close(&self, fd: &FileFd<Platform>) -> Result<(), CloseError> {
        self.litebox.descriptor_table_mut().remove(fd);
        Ok(())
    }

    fn read(
        &self,
        fd: &FileFd<Platform>,
        buf: &mut [u8],
        mut offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File { idx, position } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(ReadError::ClosedFd)?
            .entry
        else {
            return Err(ReadError::NotAFile);
        };
        let position = offset.as_mut().unwrap_or(position);
        let file = self.index.file_data(*idx);
        let start = (*position).min(file.len());
        let end = position.checked_add(buf.len()).unwrap().min(file.len());
        debug_assert!(start <= end);
        let retlen = end - start;
        buf[..retlen].copy_from_slice(&file[start..end]);
        *position = end;
        Ok(retlen)
    }

    fn write(
        &self,
        fd: &FileFd<Platform>,
        _buf: &[u8],
        _offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        match self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(WriteError::ClosedFd)?
            .entry
        {
            Descriptor::File { .. } => Err(WriteError::NotForWriting),
            Descriptor::Dir { .. } => Err(WriteError::NotAFile),
        }
    }

    fn seek(
        &self,
        fd: &FileFd<Platform>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File { idx, position } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(SeekError::ClosedFd)?
            .entry
        else {
            return Err(SeekError::NotAFile);
        };
        let file_len = self.index.files[*idx].data_len;
        let base = match whence {
            SeekWhence::RelativeToBeginning => 0,
            SeekWhence::RelativeToCurrentOffset => *position,
            SeekWhence::RelativeToEnd => file_len,
        };
        let new_posn = base
            .checked_add_signed(offset)
            .ok_or(SeekError::InvalidOffset)?;
        if new_posn > file_len {
            Err(SeekError::InvalidOffset)
        } else {
            *position = new_posn;
            Ok(new_posn)
        }
    }

    fn truncate(
        &self,
        fd: &FileFd<Platform>,
        _length: usize,
        _reset_offset: bool,
    ) -> Result<(), TruncateError> {
        match self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(TruncateError::ClosedFd)?
            .entry
        {
            Descriptor::File { .. } => Err(TruncateError::NotForWriting),
            Descriptor::Dir { .. } => Err(TruncateError::IsDirectory),
        }
    }

    fn chmod(&self, path: impl crate::path::Arg, _mode: Mode) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if self.index.file_by_path(path).is_some() || self.index.dir_by_path(path).is_some() {
            Err(ChmodError::ReadOnlyFileSystem)
        } else {
            Err(PathError::NoSuchFileOrDirectory)?
        }
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if self.index.file_by_path(path).is_some() || self.index.dir_by_path(path).is_some() {
            Err(ChownError::ReadOnlyFileSystem)
        } else {
            Err(PathError::NoSuchFileOrDirectory)?
        }
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), UnlinkError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if self.index.file_by_path(path).is_some() {
            Err(UnlinkError::ReadOnlyFileSystem)
        } else if self.index.dir_by_path(path).is_some() {
            Err(UnlinkError::IsADirectory)
        } else {
            Err(PathError::NoSuchFileOrDirectory)?
        }
    }

    fn mkdir(&self, _path: impl crate::path::Arg, _mode: Mode) -> Result<(), MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn rmdir(&self, _path: impl crate::path::Arg) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn read_dir(&self, fd: &FileFd<Platform>) -> Result<Vec<DirEntry>, ReadDirError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::Dir { idx } = &descriptor_table
            .get_entry(fd)
            .ok_or(ReadDirError::ClosedFd)?
            .entry
        else {
            return Err(ReadDirError::NotADirectory);
        };
        let dir = &self.index.dirs[*idx];

        let mut out: Vec<DirEntry> = Vec::new();

        out.push(DirEntry {
            name: ".".into(),
            file_type: FileType::Directory,
            ino_info: Some(NodeInfo {
                dev: DEVICE_ID,
                ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                rdev: None,
            }),
        });

        out.push(DirEntry {
            name: "..".into(),
            file_type: FileType::Directory,
            ino_info: Some(NodeInfo {
                dev: DEVICE_ID,
                ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                rdev: None,
            }),
        });

        out.extend(
            dir.children
                .iter()
                .map(|(name, (file_type, ino))| DirEntry {
                    name: name.clone(),
                    file_type: file_type.clone(),
                    ino_info: Some(NodeInfo {
                        dev: DEVICE_ID,
                        ino: *ino,
                        rdev: None,
                    }),
                }),
        );
        Ok(out)
    }

    fn file_status(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        let path = self.absolute_path(path)?;
        let path = if path.is_empty() {
            ""
        } else {
            assert!(path.starts_with('/'));
            &path[1..]
        };
        if let Some((_, file)) = self.index.file_by_path(path) {
            Ok(super::FileStatus {
                file_type: super::FileType::RegularFile,
                mode: file.mode,
                size: file.data_len,
                owner: file.owner,
                node_info: NodeInfo {
                    dev: DEVICE_ID,
                    ino: file.ino,
                    rdev: None,
                },
                blksize: BLOCK_SIZE,
            })
        } else if let Some((_, dir)) = self.index.dir_by_path(path) {
            Ok(super::FileStatus {
                file_type: super::FileType::Directory,
                mode: DEFAULT_DIR_MODE,
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: dir.owner.unwrap_or(DEFAULT_DIRECTORY_OWNER),
                node_info: NodeInfo {
                    dev: DEVICE_ID,
                    ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                    rdev: None,
                },
                blksize: BLOCK_SIZE,
            })
        } else {
            Err(PathError::NoSuchFileOrDirectory)?
        }
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(super::errors::FileStatusError::ClosedFd)?
            .entry
        {
            Descriptor::File { idx, .. } => {
                let file = &self.index.files[*idx];
                Ok(super::FileStatus {
                    file_type: super::FileType::RegularFile,
                    mode: file.mode,
                    size: file.data_len,
                    owner: file.owner,
                    node_info: NodeInfo {
                        dev: DEVICE_ID,
                        ino: file.ino,
                        rdev: None,
                    },
                    blksize: BLOCK_SIZE,
                })
            }
            Descriptor::Dir { idx } => {
                let dir = &self.index.dirs[*idx];
                Ok(super::FileStatus {
                    file_type: super::FileType::Directory,
                    mode: DEFAULT_DIR_MODE,
                    size: super::DEFAULT_DIRECTORY_SIZE,
                    owner: dir.owner.unwrap_or(DEFAULT_DIRECTORY_OWNER),
                    node_info: NodeInfo {
                        dev: DEVICE_ID,
                        ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                        rdev: None,
                    },
                    blksize: BLOCK_SIZE,
                })
            }
        }
    }

    fn get_static_backing_data(&self, fd: &FileFd<Platform>) -> Option<&'static [u8]> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd)?;
        match &entry.entry {
            Descriptor::File { idx, .. } => {
                // Only possible when the archive data is borrowed `&'static [u8]`.
                let Cow::Borrowed(static_data) = &self.index.archive_data else {
                    return None;
                };
                let file = &self.index.files[*idx];
                Some(&static_data[file.data_start..file.data_start + file.data_len])
            }
            Descriptor::Dir { .. } => None,
        }
    }
}

const DEFAULT_DIR_MODE: Mode =
    Mode::from_bits(Mode::RWXU.bits() | Mode::RWXG.bits() | Mode::RWXO.bits()).unwrap();

const DEFAULT_DIRECTORY_OWNER: UserInfo = UserInfo {
    user: 1000,
    group: 1000,
};

fn mode_from_u32(raw: u32) -> Mode {
    // The archive stores only the lower 12 permission bits (rwxrwxrwx + setuid/setgid/sticky).
    Mode::from_bits_truncate(raw)
}

enum Descriptor {
    File { idx: usize, position: usize },
    Dir { idx: usize },
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider };
    FileSystem<Platform>;
    Descriptor;
    -> FileFd<Platform>;
}
