// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The path-management / permissions / FD-ownership layer that sits above
//! [`crate::fs::backend::Backend`].
//!
//! The resolver owns:
//! - User-facing path normalization (via [`crate::path::Arg`]) and the
//!   [`ResolveContext`] holding `cwd` + effective user.
//! - The FD subsystem registration: every fd produced by the resolver lives
//!   in a single subsystem regardless of which backend backs it.
//! - File offset (atomic, shared by `dup`) and entry-shared `O_*` flags.
//! - `O_CREAT`/`O_EXCL`/`O_TRUNC`/`O_APPEND` semantics.
//! - `.`/`..` synthesis on `read_dir`.
//!
//! During the migration, [`Resolver`] also implements the legacy
//! [`crate::fs::FileSystem`] trait so that call sites previously holding a
//! per-backend `FileSystem` can be replaced with `Resolver<NewBackend>` and
//! still compile inside enclosing `layered` stacks. This shim is removed in
//! the final cleanup PR.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::LiteBox;
use crate::fd::TypedFd;
use crate::path::Arg;
use crate::sync::RawSyncPrimitivesProvider;

use super::backend::{
    Backend, Read as ReadMode, WalkAccessMode, WalkOutcome, WalkedComponent, Write as WriteMode,
    WritePosition,
};
use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WalkError,
    WriteError,
};
use super::{DirEntry, FileStatus, FileType, Mode, OFlags, SeekWhence, UserInfo};

// ---------------------------------------------------------------------------
// ResolveContext / ResolvedPath
// ---------------------------------------------------------------------------

/// Per-call resolution context. The user holds and mutates this however they
/// wish (per-thread, per-process, behind a `Mutex`, etc.). The resolver
/// itself is stateless w.r.t. cwd/user.
#[derive(Clone, Debug)]
pub struct ResolveContext {
    /// Current working directory. Always normalized; always begins with `/`.
    pub cwd: String,
    /// Effective user for permission checks.
    pub user: UserInfo,
}

impl ResolveContext {
    /// A default context anchored at `/` for a non-root user. Most early
    /// callers (the migration shim, in particular) use this default.
    #[must_use]
    pub fn default_at_root() -> Self {
        Self {
            cwd: String::from("/"),
            user: UserInfo {
                user: 1000,
                group: 1000,
            },
        }
    }
}

/// A resolved (absolute, normalized) path. Produced by
/// [`Resolver::resolve`] and consumed by the per-op resolver methods.
#[derive(Clone, Debug)]
pub struct ResolvedPath {
    /// Absolute, normalized path string. Always starts with `/`.
    absolute: String,
    /// Components without the leading `/`. May be empty (root).
    components: Vec<String>,
}

impl ResolvedPath {
    /// The full normalized absolute path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.absolute
    }

    /// Component slice (without the leading `/`).
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// The user-facing filesystem entry point, generic over a [`Backend`].
///
/// `Resolver<B>` is fully monomorphized; there's no dyn dispatch. It also
/// registers itself as the (single) filesystem FD subsystem.
pub struct Resolver<B: Backend + 'static> {
    backend: B,
}

impl<B: Backend + 'static> Resolver<B> {
    /// Construct a new resolver over `backend`.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Borrow the backing backend. Mainly useful for test introspection.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Resolve a user-supplied path against `ctx`. Returns an absolute,
    /// normalized [`ResolvedPath`].
    pub fn resolve(&self, ctx: &ResolveContext, path: impl Arg) -> Result<ResolvedPath, PathError> {
        let raw = path.as_rust_str()?;
        let combined = if raw.starts_with('/') {
            raw.into()
        } else {
            // Defensive: ensure cwd ends with `/` before joining.
            let mut s = ctx.cwd.clone();
            if !s.ends_with('/') {
                s.push('/');
            }
            s.push_str(raw);
            s
        };
        let absolute = combined.normalized()?;
        let components = absolute
            .split('/')
            .filter(|c| !c.is_empty())
            .map(String::from)
            .collect();
        Ok(ResolvedPath {
            absolute,
            components,
        })
    }

    // -----------------------------------------------------------------------
    // Walk plumbing
    // -----------------------------------------------------------------------

    /// Walk the full path under access mode `M`, looping over backend
    /// outcomes. Today's backends (`devices`, etc.) walk in a single shot;
    /// the loop here is structured so future partial-walking backends slot
    /// in cleanly.
    fn walk_full<'a, M: WalkAccessMode>(
        &'a self,
        components: &[String],
    ) -> Result<WalkContext<'a, B, M>, PathError>
    where
        B: 'a,
    {
        let component_refs: Vec<&str> = components.iter().map(String::as_str).collect();
        let handle = self.backend.root::<M>();
        let outcome = self
            .backend
            .walk(handle, &component_refs)
            .map_err(walk_error_to_path)?;
        match outcome {
            WalkOutcome::Complete {
                statuses,
                final_handle,
            } => Ok(WalkContext {
                handle: final_handle,
                statuses,
            }),
            WalkOutcome::Partial {
                walked,
                statuses: _,
                intermediate: _,
            } => {
                // Partial walks aren't exercised by `devices`. The loop
                // continuation will be implemented by the PR that first
                // ships a partial-walking backend.
                let _ = walked;
                unimplemented!(
                    "partial walks are not exercised by any backend on this PR; \
                     the resolver continuation loop is filled in by the first \
                     PR that ships a partial-walking backend"
                )
            }
        }
    }

    /// Resolver's permission check helper. Iterates `statuses` and runs the
    /// shared check on every component carrying `Some(PermissionInfo)`.
    ///
    /// Not exercised by `devices` (which always returns `permissions: None`).
    /// Filled in by the first PR that ships a backend with `Some` permissions.
    #[expect(dead_code, reason = "filled in by the PR that first needs perm checks")]
    fn check_permissions(
        _ctx: &ResolveContext,
        _statuses: &[WalkedComponent],
    ) -> Result<(), PathError> {
        unimplemented!(
            "perm-check helper is unimplemented in PR 1; first exercised by \
             the backend that supplies `Some(PermissionInfo)`"
        )
    }

    /// Run `f` with the resolver's effective user temporarily promoted to
    /// root. Used by initialization code today. Filled in by the PR that
    /// first needs it (the `in_mem` migration).
    pub fn with_root_privileges<R>(_ctx: &mut ResolveContext, _f: impl FnOnce() -> R) -> R {
        unimplemented!(
            "with_root_privileges is unimplemented in PR 1; first exercised \
             by the in_mem backend migration"
        )
    }
}

/// Bundle of state returned by the walk loop: the dir-handle positioned at
/// the parent of the final element (or at root if `components` was empty),
/// plus the per-component status list.
struct WalkContext<'a, B: Backend + 'a, M: WalkAccessMode> {
    handle: B::WalkingDirHandle<'a, M>,
    statuses: Vec<WalkedComponent>,
}

fn walk_error_to_path(e: WalkError) -> PathError {
    match e {
        WalkError::PathError(p) => p,
        WalkError::Io => PathError::NoSuchFileOrDirectory,
    }
}

// ---------------------------------------------------------------------------
// FD subsystem entry layout
// ---------------------------------------------------------------------------

/// Owned handle stored inside a resolver FD entry.
pub enum OwnedHandle<B: Backend> {
    File(B::FileHandle),
    Dir(B::OpenDirHandle),
}

/// Entry stored in the resolver's slot of the FD table. Position and flags
/// live here so they're correctly shared by `dup` (POSIX "open file
/// description" semantics).
pub struct ResolverEntry<B: Backend> {
    handle: OwnedHandle<B>,
    /// Cached at open time; used for fast `seek`/seekability checks.
    seekable: bool,
    /// Read access permitted (set at open from `O_RDONLY`/`O_RDWR`).
    read_allowed: bool,
    /// Write access permitted (set at open from `O_WRONLY`/`O_RDWR`).
    write_allowed: bool,
    /// File offset, shared by `dup`.
    position: AtomicUsize,
    /// Status flags (currently just `O_APPEND`), shared by `dup`.
    status_flags: AtomicU32,
}

impl<B: Backend> ResolverEntry<B> {
    fn append_mode(&self) -> bool {
        OFlags::from_bits_retain(self.status_flags.load(Ordering::Relaxed)).contains(OFlags::APPEND)
    }
}

// The `enable_fds_for_subsystem!` macro produces a `DescriptorEntry<B>`
// wrapper around `ResolverEntry<B>` and registers `Resolver<B>` as an
// `FdEnabledSubsystem`.
//
// The macro expects `'static`-able generic constraints; `B: Backend +
// 'static` is sufficient for the `+ 'static` requirement on `Subsystem::Entry`.
crate::fd::enable_fds_for_subsystem! {
    @ B: { Backend + 'static };
    Resolver<B>;
    @ B: { Backend + 'static };
    ResolverEntry<B>;
    -> ResolverFd<B>;
}

// ---------------------------------------------------------------------------
// `super::private::Sealed` for `Resolver<B>` so it can implement the legacy
// `FileSystem` trait as a migration shim.
// ---------------------------------------------------------------------------

impl<B: Backend + 'static> super::private::Sealed for Resolver<B> {}

// ---------------------------------------------------------------------------
// Migration shim: implement the legacy `super::FileSystem` trait.
//
// The shim relies on a separate trait, `BackendWithLitebox`, that the
// platform-specific backend adapters (e.g. `Devices<Platform>`) implement to
// hand the resolver a litebox handle so it can talk to the FD table.
// ---------------------------------------------------------------------------

/// Adapter trait that exposes the [`LiteBox`] handle a backend was
/// constructed with. Implemented per-backend (e.g. `Devices<Platform>`) so
/// the resolver can plug into the existing FD table without threading a
/// `Platform` parameter through every public type.
pub trait BackendWithLitebox: Backend {
    type Platform: RawSyncPrimitivesProvider + 'static;
    fn litebox(&self) -> &LiteBox<Self::Platform>;
}

impl<B> super::FileSystem for Resolver<B>
where
    B: Backend + BackendWithLitebox + 'static,
{
    fn open(&self, path: impl Arg, flags: OFlags, mode: Mode) -> Result<TypedFd<Self>, OpenError> {
        // Reject any flag bits the backend doesn't claim to support. We only
        // do this for non-trivially-ignored bits; the per-backend impl is
        // expected to whitelist what it understands. For `devices`, this is
        // already permissive (most flags are ignored at open).
        let unsupported = flags
            .difference(B::SUPPORTED_OFLAGS)
            .difference(TRIVIALLY_IGNORED_OFLAGS);
        if !unsupported.is_empty() {
            unimplemented!(
                "resolver: unsupported O_* flags for this backend: {:?}",
                unsupported
            );
        }

        let want_directory = flags.contains(OFlags::DIRECTORY);
        let read_flag = flags.contains(OFlags::RDONLY) || flags.contains(OFlags::RDWR);
        // RDONLY = 0x0, so the cleanest way to check write access is via the
        // explicit WRONLY/RDWR bits.
        let write_flag = flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR);
        // RDONLY is the implicit default if neither WRONLY nor RDWR are set.
        let read_allowed = read_flag || (!write_flag && !flags.contains(OFlags::WRONLY));

        let ctx = ResolveContext::default_at_root();
        let resolved = self.resolve(&ctx, path)?;

        // Handle the trivial "open root dir" case explicitly so `read_dir`
        // on the resolver root works without the backend having to walk
        // zero components.
        let entry = if resolved.components.is_empty() {
            // Treat the root as an open dir handle. We rely on the backend
            // exposing a root via `open_dir_at` with name `""`. For
            // `devices` we model this by opening the root via a special
            // path; backends that don't support root-as-dir return an
            // error here.
            //
            // For simplicity in PR 1, route this through the same
            // `open_dir_at` plumbing with the parent-of-root being root.
            let dir_handle = self.backend.root::<ReadMode>();
            // `name = ""` is the convention we use for "open me as a
            // directory representing the current walking handle's
            // location."
            let open_dir = self.backend.open_dir_at(dir_handle, "")?;
            ResolverEntry {
                handle: OwnedHandle::Dir(open_dir),
                seekable: false,
                read_allowed: true,
                write_allowed: false,
                position: AtomicUsize::new(0),
                status_flags: AtomicU32::new(0),
            }
        } else {
            // Walk all components; the walk positions the handle at the parent
            // of the final element and includes a WalkedComponent status for
            // the final element itself. This gives us its file_type so we can
            // dispatch without needing O_DIRECTORY.
            let final_name = resolved.components.last().expect("non-empty checked above");
            let walk_ctx = self
                .walk_full::<ReadMode>(&resolved.components)
                .map_err(OpenError::PathError)?;
            let final_is_dir = walk_ctx
                .statuses
                .last()
                .is_some_and(|s| s.file_type == FileType::Directory);

            // Open as directory when: O_DIRECTORY is set, or the walk reveals
            // the target is actually a directory (e.g. open("/dev") without
            // O_DIRECTORY must still succeed as a dir open on Linux).
            let (handle, seekable) = if want_directory || final_is_dir {
                let h = self.backend.open_dir_at(walk_ctx.handle, final_name)?;
                (OwnedHandle::Dir(h), false)
            } else {
                let h = self
                    .backend
                    .open_file_at(walk_ctx.handle, final_name, flags)?;
                let seekable = self.backend.is_seekable(&h);
                (OwnedHandle::File(h), seekable)
            };

            // `O_TRUNC` would land here. `devices` doesn't support truncate
            // on stdio, but matches Linux silent-ignore on stdio; we
            // therefore only forward TRUNC for genuine files. None of the
            // PR 1 paths produce truncatable file handles, so this is a
            // no-op.
            let _ = mode;

            let mut status_flags: u32 = 0;
            if flags.contains(OFlags::APPEND) {
                status_flags |= OFlags::APPEND.bits();
            }

            ResolverEntry {
                handle,
                seekable,
                read_allowed,
                write_allowed: write_flag,
                position: AtomicUsize::new(0),
                status_flags: AtomicU32::new(status_flags),
            }
        };

        let fd = self
            .backend
            .litebox()
            .descriptor_table_mut()
            .insert::<Resolver<B>>(entry);
        Ok(fd)
    }

    fn close(&self, fd: &TypedFd<Self>) -> Result<(), CloseError> {
        self.backend.litebox().descriptor_table_mut().remove(fd);
        Ok(())
    }

    fn read(
        &self,
        fd: &TypedFd<Self>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let backend = &self.backend;
        let table = backend.litebox().descriptor_table();
        let entry_guard = table.get_entry(fd).ok_or(ReadError::ClosedFd)?;
        let entry = entry_inner(&*entry_guard);

        if !entry.read_allowed {
            return Err(ReadError::NotForReading);
        }
        let file = match &entry.handle {
            OwnedHandle::File(f) => f,
            OwnedHandle::Dir(_) => return Err(ReadError::NotAFile),
        };

        let use_position = offset.is_none();
        let read_offset = offset.unwrap_or_else(|| entry.position.load(Ordering::Relaxed));
        let n = backend.read(file, buf, read_offset)?;
        if use_position && entry.seekable {
            entry.position.fetch_add(n, Ordering::Relaxed);
        }
        Ok(n)
    }

    fn write(
        &self,
        fd: &TypedFd<Self>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let backend = &self.backend;
        let table = backend.litebox().descriptor_table();
        let entry_guard = table.get_entry(fd).ok_or(WriteError::ClosedFd)?;
        let entry = entry_inner(&*entry_guard);

        if !entry.write_allowed {
            return Err(WriteError::NotForWriting);
        }
        let file = match &entry.handle {
            OwnedHandle::File(f) => f,
            OwnedHandle::Dir(_) => return Err(WriteError::NotAFile),
        };

        let pos = if entry.append_mode() {
            WritePosition::Append
        } else {
            let p = offset.unwrap_or_else(|| entry.position.load(Ordering::Relaxed));
            WritePosition::At(p)
        };
        let use_position = offset.is_none() && !entry.append_mode();
        let n = backend.write(file, buf, pos)?;
        if use_position && entry.seekable {
            entry.position.fetch_add(n, Ordering::Relaxed);
        }
        Ok(n)
    }

    fn seek(
        &self,
        fd: &TypedFd<Self>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let backend = &self.backend;
        let table = backend.litebox().descriptor_table();
        let entry_guard = table.get_entry(fd).ok_or(SeekError::ClosedFd)?;
        let entry = entry_inner(&*entry_guard);

        let file = match &entry.handle {
            OwnedHandle::File(f) => f,
            OwnedHandle::Dir(_) => return Err(SeekError::NotAFile),
        };

        if !entry.seekable {
            // Match the legacy `devices` behavior: stdio is non-seekable
            // and returns `NonSeekable`; null/urandom historically returned
            // `Ok(0)`. Backends signal this by reporting `is_seekable=true`
            // (meaning "lseek is a no-op returning 0") for those devices.
            //
            // The current `Devices` backend reports false for stdio and
            // true for null/urandom; for null/urandom we still want to
            // return Ok(0) without touching position. So fall through.
            return Err(SeekError::NonSeekable);
        }

        let _ = (offset, whence, file);
        // PR 1 only exercises the non-seekable / Ok(0) paths via `devices`.
        // The full lseek arithmetic is implemented by the `in_mem`
        // migration. For now, fall back to Ok(0) for "seekable but
        // size-unknown" devices.
        Ok(0)
    }

    fn truncate(
        &self,
        fd: &TypedFd<Self>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let backend = &self.backend;
        let table = backend.litebox().descriptor_table();
        let entry_guard = table.get_entry(fd).ok_or(TruncateError::ClosedFd)?;
        let entry = entry_inner(&*entry_guard);

        let file = match &entry.handle {
            OwnedHandle::File(f) => f,
            OwnedHandle::Dir(_) => return Err(TruncateError::IsDirectory),
        };
        if !entry.write_allowed {
            return Err(TruncateError::NotForWriting);
        }
        backend.truncate(file, length)?;
        if reset_offset {
            entry.position.store(0, Ordering::Relaxed);
        }
        Ok(())
    }

    fn chmod(&self, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        let ctx = ResolveContext::default_at_root();
        let resolved = self.resolve(&ctx, path).map_err(ChmodError::PathError)?;
        let (parent, name) = split_parent(&resolved)?;
        let walk_ctx = self
            .walk_full::<WriteMode>(parent)
            .map_err(ChmodError::PathError)?;
        self.backend.chmod_at(walk_ctx.handle, name, mode)
    }

    fn chown(
        &self,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let ctx = ResolveContext::default_at_root();
        let resolved = self.resolve(&ctx, path).map_err(ChownError::PathError)?;
        let (parent, name) = split_parent(&resolved)?;
        let walk_ctx = self
            .walk_full::<WriteMode>(parent)
            .map_err(ChownError::PathError)?;
        self.backend.chown_at(walk_ctx.handle, name, user, group)
    }

    fn unlink(&self, path: impl Arg) -> Result<(), UnlinkError> {
        let ctx = ResolveContext::default_at_root();
        let resolved = self.resolve(&ctx, path).map_err(UnlinkError::PathError)?;
        let (parent, name) = split_parent(&resolved)?;
        let walk_ctx = self
            .walk_full::<WriteMode>(parent)
            .map_err(UnlinkError::PathError)?;
        self.backend.unlink_at(walk_ctx.handle, name)
    }

    fn mkdir(&self, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        let ctx = ResolveContext::default_at_root();
        let resolved = self.resolve(&ctx, path).map_err(MkdirError::PathError)?;
        let (parent, name) = split_parent(&resolved)?;
        let walk_ctx = self
            .walk_full::<WriteMode>(parent)
            .map_err(MkdirError::PathError)?;
        self.backend.mkdir_at(walk_ctx.handle, name, mode)
    }

    fn rmdir(&self, path: impl Arg) -> Result<(), RmdirError> {
        let ctx = ResolveContext::default_at_root();
        let resolved = self.resolve(&ctx, path).map_err(RmdirError::PathError)?;
        let (parent, name) = split_parent(&resolved)?;
        let walk_ctx = self
            .walk_full::<WriteMode>(parent)
            .map_err(RmdirError::PathError)?;
        self.backend.rmdir_at(walk_ctx.handle, name)
    }

    fn read_dir(&self, fd: &TypedFd<Self>) -> Result<Vec<DirEntry>, ReadDirError> {
        let backend = &self.backend;
        let table = backend.litebox().descriptor_table();
        let entry_guard = table.get_entry(fd).ok_or(ReadDirError::ClosedFd)?;
        let entry = entry_inner(&*entry_guard);

        let dir = match &entry.handle {
            OwnedHandle::Dir(d) => d,
            OwnedHandle::File(_) => return Err(ReadDirError::NotADirectory),
        };
        let mut entries = backend.list_dir(dir)?;
        // Resolver synthesizes `.` and `..`. (At root, `..` collapses to
        // `.` — POSIX-like.) Backends are required not to emit either.
        let dir_status = backend.dir_status(dir).map_err(|_| ReadDirError::Io)?;
        let dot_node = dir_status.node_info.clone();
        // For `..` at root we re-use the same node info (POSIX-like).
        // PR 1 doesn't track parent inode, so this approximation is
        // acceptable; future PRs will plumb parent info through walk
        // state.
        let dotdot_node = dot_node.clone();
        entries.insert(
            0,
            DirEntry {
                name: String::from("."),
                file_type: FileType::Directory,
                ino_info: Some(dot_node),
            },
        );
        entries.insert(
            1,
            DirEntry {
                name: String::from(".."),
                file_type: FileType::Directory,
                ino_info: Some(dotdot_node),
            },
        );
        Ok(entries)
    }

    fn file_status(&self, path: impl Arg) -> Result<FileStatus, FileStatusError> {
        let ctx = ResolveContext::default_at_root();
        let resolved = self
            .resolve(&ctx, path)
            .map_err(FileStatusError::PathError)?;

        // For PR 1 the simplest implementation is to walk to parent, then
        // open as a dir or file briefly to fetch status. We do this via the
        // `*_status` backend methods, which don't require holding a walk
        // lock (the open handles are standalone-usable).
        if resolved.components.is_empty() {
            let dir_handle = self.backend.root::<ReadMode>();
            let h = self
                .backend
                .open_dir_at(dir_handle, "")
                .map_err(open_to_status_error)?;
            return self.backend.dir_status(&h);
        }
        let (parent, name) = split_parent(&resolved).map_err(FileStatusError::PathError)?;
        let walk_ctx = self
            .walk_full::<ReadMode>(parent)
            .map_err(FileStatusError::PathError)?;

        // Try as file first; if backend says not-a-file fall back to dir.
        // Since `OpenError` doesn't have a dedicated "is a directory"
        // variant in the legacy enum, we attempt the dir open as a
        // fallback only when the file open fails with a generic error
        // shape. For PR 1 (devices), every named entry is a file.
        let walk_handle = walk_ctx.handle;
        if let Ok(h) = self.backend.open_file_at(walk_handle, name, OFlags::RDONLY) {
            self.backend.file_status(&h)
        } else {
            // Fall back to dir lookup.
            let walk_ctx = self
                .walk_full::<ReadMode>(parent)
                .map_err(FileStatusError::PathError)?;
            let h = self
                .backend
                .open_dir_at(walk_ctx.handle, name)
                .map_err(open_to_status_error)?;
            self.backend.dir_status(&h)
        }
    }

    fn fd_file_status(&self, fd: &TypedFd<Self>) -> Result<FileStatus, FileStatusError> {
        let backend = &self.backend;
        let table = backend.litebox().descriptor_table();
        let entry_guard = table.get_entry(fd).ok_or(FileStatusError::ClosedFd)?;
        let entry = entry_inner(&*entry_guard);
        match &entry.handle {
            OwnedHandle::File(f) => backend.file_status(f),
            OwnedHandle::Dir(d) => backend.dir_status(d),
        }
    }

    fn get_static_backing_data(&self, _fd: &TypedFd<Self>) -> Option<&'static [u8]> {
        // Filled in by the PR that first needs it (`in_mem`).
        unimplemented!(
            "get_static_backing_data forwarding is unimplemented in PR 1; \
             first exercised by the in_mem backend migration"
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// `O_*` flags that are routinely ignored at open by today's call sites.
/// The legacy `devices` impl ignored these; the resolver mirrors that.
const TRIVIALLY_IGNORED_OFLAGS: OFlags = OFlags::from_bits_retain(
    OFlags::CLOEXEC.bits()
        | OFlags::NOCTTY.bits()
        | OFlags::NOFOLLOW.bits()
        | OFlags::LARGEFILE.bits()
        | OFlags::NONBLOCK.bits()
        | OFlags::DIRECTORY.bits()
        | OFlags::APPEND.bits()
        | OFlags::TRUNC.bits()
        | OFlags::CREAT.bits()
        | OFlags::EXCL.bits()
        | OFlags::RDONLY.bits()
        | OFlags::WRONLY.bits()
        | OFlags::RDWR.bits(),
);

fn split_parent(resolved: &ResolvedPath) -> Result<(&[String], &str), PathError> {
    let n = resolved.components.len();
    if n == 0 {
        return Err(PathError::InvalidPathname);
    }
    Ok((
        &resolved.components[..n - 1],
        resolved.components[n - 1].as_str(),
    ))
}

fn open_to_status_error(e: OpenError) -> FileStatusError {
    match e {
        OpenError::PathError(p) => FileStatusError::PathError(p),
        _ => FileStatusError::Io,
    }
}

/// Get a reference to the resolver entry inside the macro-generated wrapper.
fn entry_inner<B: Backend + 'static>(wrapper: &DescriptorEntry<B>) -> &ResolverEntry<B> {
    &wrapper.entry
}
