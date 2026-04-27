// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The path-management/permissions/... layer, that sits above [`super::backend`].

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::fs::UserInfo;
use crate::path::Arg;
use crate::{LiteBox, fd::TypedFd, sync};

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};
use super::{FileType, Mode, OFlags};

/// The north-facing filesystem entry point, generic over a [`Backend`](super::backend::Backend).
///
/// The resolver _itself_ maintains no state; all state is maintained either by the backend or the
/// [`Context`]. The user may choose to store the [`Context`] as they wish.
// NOTE(jayb): the `Context` separation is in preparation for multi-process support; specifically,
// each guest process would have their own `Context` but would share the resolver. Currently, since
// we are using the `FileSystem` trait for migration, the interfaces do not show the full actual
// separated context support (yet!). Nonetheless, future changes will separate this out.
pub struct Resolver<
    Platform: sync::RawSyncPrimitivesProvider,
    Backend: super::backend::Backend + 'static,
> {
    litebox: LiteBox<Platform>,
    backend: Backend,
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Construct a new resolver over a `backend`.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>, backend: Backend) -> Self {
        Self {
            litebox: litebox.clone(),
            backend,
        }
    }
}

/// Per-call resolution context.  The user may hold and mutate this as they wish.
#[derive(Clone, Debug)]
pub struct Context {
    /// Current working directory.
    ///
    /// An empty list is equivalent to `/`. Guaranteed to never have `.` or `..`.
    cwd: Vec<String>,
    /// Effective user for permission checks.
    user_info: UserInfo,
}

impl Context {
    /// A new default context, anchored at `/` for a non-root user.
    pub fn new() -> Context {
        Self {
            cwd: vec![],
            user_info: UserInfo {
                user: 1000,
                group: 1000,
            },
        }
    }

    /// Resolve `path` against the current context.
    // XXX(jayb): if/when we support chroot, we might need to tweak this to not allow "escaping"
    // outside the chrooted part.
    // XXX(jayb): since we are migrating all resolution into the resolver, we probably don't need
    // `Arg` anymore, so could get rid of it in the future.
    fn resolve(&self, path: impl Arg) -> Result<ResolvedPath, PathError> {
        let mut components = if path.as_rust_str()?.starts_with('/') {
            vec![]
        } else {
            self.cwd.clone()
        };
        for component in path.components()? {
            match component {
                "" | "." => {}
                ".." => {
                    let _ = components.pop();
                }
                _ => {
                    components.push(component.into());
                }
            }
        }
        Ok(ResolvedPath { components })
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Absolute normalized path, must only be created from [`Context::resolve`].
struct ResolvedPath {
    components: Vec<String>,
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    super::private::Sealed for Resolver<Platform, Backend>
{
}

/// This exists purely as a migration feature, until we have completely separated contexts. See
/// comment on `Resolver`.
fn default_context_pre_context_management_changes() -> Context {
    Context::new()
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    super::FileSystem for Resolver<Platform, Backend>
{
    fn open(&self, path: impl Arg, flags: OFlags, mode: Mode) -> Result<TypedFd<Self>, OpenError> {
        /// XXX(2026-05-29)
        // let unsupported = flags.difference(Backend::SUPPORTED_OFLAGS);
        // if !unsupported.is_empty() {
        //     // XXX: we probably should have a clearer handling of this, maybe extend `OpenError`?
        //     unimplemented!(
        //         "resolver: unsupported O_* flags for this backend: {:?}",
        //         unsupported
        //     );
        // }

        // let ctx = default_context_pre_context_management_changes();
        // let resolved = self.resolve(&ctx, path)?;

        // let entry = {
        //     let final_name = resolved.components.last();
        //     let walk_ctx = self
        //         .walk_full(&resolved.components)
        //         .map_err(OpenError::PathError)?;
        //     let final_is_dir = walk_ctx
        //         .statuses
        //         .last()
        //         .is_some_and(|s| s.file_type == FileType::Directory);

        //     let (handle, seekable) = if flags.contains(OFlags::DIRECTORY) || final_is_dir {
        //         let h = self.backend.open_dir_at(walk_ctx.handle, final_name)?;
        //         (OwnedHandle::Dir(h), false)
        //     } else {
        //         let h = self
        //             .backend
        //             .open_file_at(walk_ctx.handle, final_name, flags)?;
        //         let seekable = self.backend.is_seekable(&h);
        //         (OwnedHandle::File(h), seekable)
        //     };

        //     // `O_TRUNC` would land here. `devices` doesn't support truncate
        //     // on stdio, but matches Linux silent-ignore on stdio; we
        //     // therefore only forward TRUNC for genuine files. None of the
        //     // PR 1 paths produce truncatable file handles, so this is a
        //     // no-op.
        //     let _ = mode;

        //     let mut status_flags: u32 = 0;
        //     if flags.contains(OFlags::APPEND) {
        //         status_flags |= OFlags::APPEND.bits();
        //     }

        //     ResolverEntry { handle }
        // };

        // let fd = self
        //     .backend
        //     .litebox()
        //     .descriptor_table_mut()
        //     .insert::<Resolver<B>>(entry);
        // Ok(fd)
        todo!()
    }

    fn close(&self, fd: &TypedFd<Self>) -> Result<(), CloseError> {
        todo!()
    }

    fn read(
        &self,
        fd: &TypedFd<Self>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        todo!()
    }

    fn write(
        &self,
        fd: &TypedFd<Self>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        todo!()
    }

    fn seek(
        &self,
        fd: &TypedFd<Self>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, SeekError> {
        todo!()
    }

    fn truncate(
        &self,
        fd: &TypedFd<Self>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        todo!()
    }

    fn chmod(&self, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        todo!()
    }

    fn chown(
        &self,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        todo!()
    }

    fn unlink(&self, path: impl Arg) -> Result<(), UnlinkError> {
        todo!()
    }

    fn mkdir(&self, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        todo!()
    }

    fn rmdir(&self, path: impl Arg) -> Result<(), RmdirError> {
        todo!()
    }

    fn read_dir(&self, fd: &TypedFd<Self>) -> Result<Vec<super::DirEntry>, ReadDirError> {
        todo!()
    }

    fn file_status(&self, path: impl Arg) -> Result<super::FileStatus, FileStatusError> {
        todo!()
    }

    fn fd_file_status(&self, fd: &TypedFd<Self>) -> Result<super::FileStatus, FileStatusError> {
        todo!()
    }

    fn get_static_backing_data(&self, fd: &TypedFd<Self>) -> Option<&'static [u8]> {
        todo!()
    }
}

/// A file or a directory handle
enum OwnedHandle<Backend: super::backend::Backend> {
    File(Backend::FileHandle),
    Dir(Backend::DirHandle),
}

// TODO DO NOT COMMIT
pub struct ResolverEntry<Backend: super::backend::Backend> {
    handle: OwnedHandle<Backend>,
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider }, Backend: { super::backend::Backend + 'static };
    Resolver<Platform, Backend>;
    @ Backend: { super::backend::Backend + 'static };
    ResolverEntry<Backend>;
    -> ResolverFd<Platform, Backend>;
}
