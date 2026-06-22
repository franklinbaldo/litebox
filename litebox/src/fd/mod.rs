// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File descriptors used in LiteBox

#![expect(
    dead_code,
    reason = "still under development, remove before merging PR"
)]

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::AtomicBool;
use hashbrown::HashMap;
use thiserror::Error;

use crate::sync::{RawSyncPrimitivesProvider, RwLock};
use crate::utilities::anymap::AnyMap;

#[cfg(test)]
mod tests;

/// Storage of file descriptors and their entries.
pub struct Descriptors<Platform: RawSyncPrimitivesProvider> {
    entries: Vec<Option<IndividualEntry<Platform>>>,
}

impl<Platform: RawSyncPrimitivesProvider> Descriptors<Platform> {
    /// Explicitly crate-internal: Create a new empty descriptor table.
    ///
    /// This is expected to be invoked only by [`crate::LiteBox`]'s creation method, and should not
    /// be invoked anywhere else in the codebase.
    pub(crate) fn new_from_litebox_creation() -> Self {
        Self { entries: vec![] }
    }

    /// Duplicate an entry at the given raw slot index into a new slot, returning
    /// a new [`OwnedFd`] for the new slot.
    ///
    /// The new slot shares the underlying `DescriptorEntry` (via `Arc::clone`)
    /// with the source slot. This is used by child process creation to give
    /// each process independent slots that share the same open file descriptions.
    ///
    /// Returns `None` if the source fd is already closed.
    fn duplicate_slot(&mut self, source: &OwnedFd) -> Option<OwnedFd> {
        let src_idx = source.as_usize()?;
        let shared_entry = Arc::clone(&self.entries[src_idx].as_ref().unwrap().x);
        let idx = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries.push(None);
                self.entries.len() - 1
            });
        let old = self.entries[idx].replace(IndividualEntry::new(shared_entry));
        assert!(old.is_none());
        Some(OwnedFd::new(idx))
    }

    /// Insert `entry` into the descriptor table, returning an `OwnedFd` to this entry.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics impossible due to type invariants"
    )]
    #[must_use]
    pub fn insert<Subsystem: FdEnabledSubsystem>(
        &mut self,
        entry: impl Into<Subsystem::Entry>,
    ) -> TypedFd<Subsystem> {
        let entry = DescriptorEntry {
            entry: alloc::boxed::Box::new(entry.into()),
            metadata: AnyMap::new(),
        };
        let idx = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries.push(None);
                self.entries.len() - 1
            });
        let old = self.entries[idx].replace(IndividualEntry::new(Arc::new(RwLock::new(entry))));
        assert!(old.is_none());
        TypedFd {
            _phantom: PhantomData,
            x: OwnedFd::new(idx),
        }
    }

    /// Create a duplicate of the provided `fd`.
    ///
    /// This newly-created FD shares all behavior with the existing FD, including (for example)
    /// offsets. Any metadata stored via [`Self::set_entry_metadata`] is (as expected) maintained as
    /// aliased metadata at the new FD. However, any metadata that was stored via
    /// [`Self::set_fd_metadata`] is **not** duplicated; if you want that data to be copied over to
    /// the new entry, you must copy it over yourself.
    ///
    /// If the fd has already been closed (potentially on a different thread), this duplication will
    /// fail and will return `None`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panic is impossible due to type invariants"
    )]
    pub fn duplicate<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<TypedFd<Subsystem>> {
        let idx = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries.push(None);
                self.entries.len() - 1
            });
        let new_ind_entry = IndividualEntry::new(Arc::clone(
            &self.entries[fd.x.as_usize()?].as_ref().unwrap().x,
        ));
        let old = self.entries[idx].replace(new_ind_entry);
        assert!(old.is_none());
        Some(TypedFd {
            _phantom: PhantomData,
            x: OwnedFd::new(idx),
        })
    }

    /// Removes the entry at `fd`, closing out the file descriptor.
    ///
    /// Returns the descriptor entry if this was the last reference (i.e., no
    /// other slots share the same entry via dup or child process inheritance).
    ///
    /// If the `fd` was already closed out, then (obviously) it does not return an entry.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics only on invariant violation"
    )]
    pub fn remove<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<Subsystem::Entry> {
        let idx = fd.x.as_usize()?;
        let old = self.entries[idx].take().unwrap();
        fd.x.mark_as_closed();
        Arc::into_inner(old.x)
            .map(RwLock::into_inner)
            .map(DescriptorEntry::into_subsystem_entry::<Subsystem>)
    }

    /// Close the provided `fd`, removing its slot from the descriptor table.
    ///
    /// This method takes a closure `can_close_immediately` that is called with the entry to determine
    /// whether the file descriptor can be closed immediately. This allows the caller to implement
    /// custom logic (e.g., checking for pending data) before allowing the close to proceed.
    ///
    /// When other references exist (from dup or child process inheritance), the
    /// slot is freed without teardown — the entry remains alive via the other
    /// reference's slot. The `Deferred` result is only returned when this is the
    /// last reference AND `can_close_immediately` returns false.
    pub(crate) fn close_and_remove<
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&Subsystem::Entry) -> bool,
    >(
        &mut self,
        fd: &TypedFd<Subsystem>,
        can_close_immediately: F,
    ) -> Option<CloseResult<Subsystem>> {
        let idx = fd.x.as_usize()?;
        let entry = self.entries[idx].as_ref().unwrap();

        // Only check pending data when we're the last reference.
        // If other refs exist, they'll keep the entry alive after we release our slot.
        if Arc::strong_count(&entry.x) == 1
            && !can_close_immediately(entry.x.read().as_subsystem::<Subsystem>())
        {
            // Last ref, pending data — keep entry in slot for later polling.
            return Some(CloseResult::Deferred);
        }

        // Always remove the slot.
        let old = self.entries[idx].take().unwrap();
        fd.x.mark_as_closed();

        match Arc::into_inner(old.x) {
            Some(rwlock) => {
                // Last reference — extract entry for teardown.
                let entry = RwLock::into_inner(rwlock).into_subsystem_entry::<Subsystem>();
                Some(CloseResult::Closed(entry))
            }
            None => {
                // Other references exist (dup or child). Slot freed, done.
                Some(CloseResult::Released)
            }
        }
    }

    /// Drain all entries that are fully accounted for by the `fds`, removing those FDs from `fd`s,
    /// and returning their corresponding entries.
    ///
    /// This is similar to [`Self::remove`] except it allows draining a whole collection of FDs,
    /// which is helpful if there are duplicated FDs in the mix. This is particularly useful if one
    /// is unsure if there are ongoing operations on some entries in the FD, and thus wants to delay
    /// some sort of `close` operation.
    ///
    /// No ordering guarantees are provided by this function; the resulting entries can be
    /// arbitrarily ordered.
    ///
    /// If an FD remains in `fds` after this function finishes running, then it is guaranteed to
    /// have at least one other duplicate floating around and still accessing an entry somewhere
    /// outside of `fds`; if an entry is returned, then all possible FDs to it have been removed
    /// removed from `fds` (and no other operation was concurrently accessing an entry).
    pub(crate) fn drain_entries_full_covered_by<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fds: &mut Vec<TypedFd<Subsystem>>,
    ) -> Vec<Subsystem::Entry> {
        // Each FD corresponds to an `IndividualEntry`, which has an Arc to a `DescriptorEntry`. If
        // we have the same number of FDs as matching to the strong-count of a descriptor entry,
        // then it must be the case that we have everything needed to close the entries out.
        let removable_entries: Vec<*const RwLock<_, _>> = {
            let mut strong_count_and_count = HashMap::<*const _, (usize, usize)>::new();
            for fd in fds.iter() {
                let entry = &self.entries[fd.x.as_usize().unwrap()];
                // It would not be "incorrect" to see a closed out entry, but as it currently stands, I
                // believe that we'll only see alive entries, so this `unwrap` is confirming that; if we
                // need to expand it out, we'd simply have a `continue` here.
                let entry = entry.as_ref().unwrap();
                let record = strong_count_and_count
                    .entry(Arc::as_ptr(&entry.x))
                    .or_insert((Arc::strong_count(&entry.x), 0));
                record.1 += 1;
            }
            strong_count_and_count
                .into_iter()
                .filter(|(_ptr, (sc, c))| sc == c)
                .map(|(ptr, _)| ptr)
                .collect()
        };
        // Now we can actually go and remove every single such FD.
        let entries: Vec<Subsystem::Entry> = {
            let mut entries = vec![];
            fds.retain(|fd: &TypedFd<Subsystem>| {
                let entry = &self.entries[fd.x.as_usize().unwrap()];
                let entry = entry.as_ref().unwrap();
                let entry_ptr = Arc::as_ptr(&entry.x);
                if !removable_entries.contains(&entry_ptr) {
                    return true;
                }
                // This FD is removable
                let entry = self.remove(fd);
                if let Some(entry) = entry {
                    // This is the last of the individual entries that were holding a ref to this.
                    entries.push(entry);
                }
                false
            });
            entries
        };
        debug_assert_eq!(entries.len(), removable_entries.len());
        entries
    }

    /// An iterator of descriptors and entries for a subsystem
    ///
    /// Note: each of the entries take locks, thus should not be held on to for too long, in order
    /// to prevent dead-locks.
    pub(crate) fn iter<Subsystem: FdEnabledSubsystem>(
        &self,
    ) -> impl Iterator<Item = (InternalFd, impl core::ops::Deref<Target = Subsystem::Entry>)> {
        self.entries.iter().enumerate().filter_map(|(i, entry)| {
            entry.as_ref().and_then(|e| {
                let entry = e.read();
                if entry.matches_subsystem::<Subsystem>() {
                    Some((
                        InternalFd {
                            raw: i.try_into().unwrap(),
                        },
                        crate::sync::RwLockReadGuard::map(entry, |e| e.as_subsystem::<Subsystem>()),
                    ))
                } else {
                    None
                }
            })
        })
    }

    /// An iterator of descriptors and (mutable) entries for a subsystem
    ///
    /// Note: each of the entries take locks, thus should not be held on to for too long, in order
    /// to prevent dead-locks.
    pub(crate) fn iter_mut<Subsystem: FdEnabledSubsystem>(
        &self,
    ) -> impl Iterator<
        Item = (
            InternalFd,
            impl core::ops::DerefMut<Target = Subsystem::Entry>,
        ),
    > {
        self.entries.iter().enumerate().filter_map(|(i, entry)| {
            entry.as_ref().and_then(|e| {
                if !e.read().matches_subsystem::<Subsystem>() {
                    return None;
                }
                let entry = e.write();
                assert!(entry.matches_subsystem::<Subsystem>());
                Some((
                    InternalFd {
                        raw: i.try_into().unwrap(),
                    },
                    crate::sync::RwLockWriteGuard::map(entry, |e| {
                        e.as_subsystem_mut::<Subsystem>()
                    }),
                ))
            })
        })
    }

    /// Use the entry at `fd` as read-only.
    ///
    /// If the `fd` has been closed, then skips applying `f` and returns `None`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics impossible due to type invariants"
    )]
    pub fn with_entry<Subsystem, F, R>(&self, fd: &TypedFd<Subsystem>, f: F) -> Option<R>
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&Subsystem::Entry) -> R,
    {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad cast
        // somewhere.
        let entry = self.entries[fd.x.as_usize()?].as_ref().unwrap().read();
        Some(f(entry.as_subsystem::<Subsystem>()))
    }

    /// Use the entry at `fd` as mutably.
    ///
    /// If the `fd` has been closed, then skips applying `f` and returns `None`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics impossible due to type invariants"
    )]
    pub fn with_entry_mut<Subsystem, F, R>(&self, fd: &TypedFd<Subsystem>, f: F) -> Option<R>
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&mut Subsystem::Entry) -> R,
    {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad cast
        // somewhere.
        let mut entry = self.entries[fd.x.as_usize()?].as_ref().unwrap().write();
        Some(f(entry.as_subsystem_mut::<Subsystem>()))
    }

    /// Obtain a handle to the underlying entry for the `fd`.
    ///
    /// Similar to [`Self::with_entry`], except it does not require maintaining access to the table.
    pub fn entry_handle<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<EntryHandle<Platform, Subsystem>> {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad cast
        // somewhere.
        let entry = self.entries[fd.x.as_usize()?].as_ref()?;
        Some(EntryHandle(Arc::clone(&entry.x), PhantomData))
    }

    /// Use the entry at `internal_fd` as mutably.
    ///
    /// NOTE: Ideally, prefer using [`Self::with_entry_mut`] instead of this, since it provides a
    /// nicer experience with respect to types. This current function is only to be used with
    /// specialized usages that involve dealing with stuff around [`Self::iter`] and locking
    /// disciplines, and thus should be considered an "advanced" usage.
    ///
    /// `f` is run iff it is the correct subsystem. Returns `Some` iff it is the correct subsystem.
    pub(crate) fn with_entry_mut_via_internal_fd<Subsystem, F, R>(
        &self,
        internal_fd: InternalFd,
        f: F,
    ) -> Option<R>
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&mut Subsystem::Entry) -> R,
    {
        let mut entry = self.entries[usize::try_from(internal_fd.raw).unwrap()]
            .as_ref()
            .unwrap()
            .write();
        if entry.matches_subsystem::<Subsystem>() {
            Some(f(entry.as_subsystem_mut::<Subsystem>()))
        } else {
            None
        }
    }

    /// Get the entry at `fd`.
    ///
    /// Note: this grabs a lock, thus the result should not be held for too long, to prevent
    /// deadlocks. Prefer using [`Self::with_entry`] when possible, to make life easier.
    pub(crate) fn get_entry<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<impl core::ops::Deref<Target = Subsystem::Entry> + use<'_, Platform, Subsystem>>
    {
        Some(crate::sync::RwLockReadGuard::map(
            self.entries[fd.x.as_usize()?].as_ref().unwrap().read(),
            |e| e.as_subsystem::<Subsystem>(),
        ))
    }

    /// Get the entry at `fd`, mutably.
    ///
    /// Note: this grabs a lock, thus the result should not be held for too long, to prevent
    /// deadlocks. Prefer using [`Self::with_entry_mut`] when possible, to make life easier.
    pub(crate) fn get_entry_mut<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<impl core::ops::DerefMut<Target = Subsystem::Entry> + use<'_, Platform, Subsystem>>
    {
        Some(crate::sync::RwLockWriteGuard::map(
            self.entries[fd.x.as_usize()?].as_ref().unwrap().write(),
            |e| e.as_subsystem_mut::<Subsystem>(),
        ))
    }

    /// Apply `f` on metadata at an fd, if it exists.
    ///
    /// This returns the most-specific metadata available for the file descriptor---specifically, if
    /// both [`Self::set_fd_metadata`] and [`Self::set_entry_metadata`]) are run on the same
    /// fd, this will only return the value from the fd one, which will shadow the file one. If no
    /// fd-specific one is set, this returns the entry-specific one.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn with_metadata<Subsystem, T, R>(
        &self,
        fd: &TypedFd<Subsystem>,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, MetadataError>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Send + Sync,
    {
        let ind_entry = self.entries[fd.x.as_usize().ok_or(MetadataError::ClosedFd)?]
            .as_ref()
            .unwrap();
        match ind_entry.metadata.get::<T>() {
            Some(m) => Ok(f(m)),
            None => ind_entry
                .read()
                .metadata
                .get::<T>()
                .map(f)
                .ok_or(MetadataError::NoSuchMetadata),
        }
    }

    /// Similar to [`Self::with_metadata`] but mutable.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn with_metadata_mut<Subsystem, T, R>(
        &mut self,
        fd: &TypedFd<Subsystem>,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, MetadataError>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Send + Sync,
    {
        let ind_entry = self.entries[fd.x.as_usize().ok_or(MetadataError::ClosedFd)?]
            .as_mut()
            .unwrap();
        match ind_entry.metadata.get_mut::<T>() {
            Some(m) => Ok(f(m)),
            None => ind_entry
                .write()
                .metadata
                .get_mut::<T>()
                .map(f)
                .ok_or(MetadataError::NoSuchMetadata),
        }
    }

    /// Store arbitrary metadata into a file.
    ///
    /// Such metadata is visible to any open fd on the entry associated with the fd. See similar
    /// [`Self::set_fd_metadata`] which is specific to fds, and does not alias the metadata.
    ///
    /// Returns the old metadata if any such metadata exists.
    ///
    /// Silently drops the store if the FD has been closed out.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn set_entry_metadata<Subsystem, T>(
        &mut self,
        fd: &TypedFd<Subsystem>,
        metadata: T,
    ) -> Option<T>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Send + Sync,
    {
        self.entries[fd.x.as_usize()?]
            .as_ref()
            .unwrap()
            .x
            .write()
            .metadata
            .insert(metadata)
    }

    /// Store arbitrary metadata into a file descriptor.
    ///
    /// Such metadata is specific to the current fd and is NOT shared with other open fds to the
    /// same entry. See the similar [`Self::set_entry_metadata`] which aliases metadata over all fds
    /// opened for the same entry.
    ///
    /// Silently drops the store if the FD has been closed out.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn set_fd_metadata<Subsystem, T>(
        &mut self,
        fd: &TypedFd<Subsystem>,
        metadata: T,
    ) -> Option<T>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Send + Sync,
    {
        self.entries[fd.x.as_usize()?]
            .as_mut()
            .unwrap()
            .metadata
            .insert(metadata)
    }

    /// Returns the indices of all live entries whose per-FD metadata of type `T` satisfies `pred`.
    ///
    /// **Important**: These are slot indices into `Descriptors.entries`, NOT raw FD numbers.
    /// To get raw FD numbers matching metadata, use
    /// [`RawDescriptorStorage::raw_fds_matching_metadata`] instead.
    pub fn indices_matching_metadata<T: core::any::Any + Send + Sync>(
        &self,
        pred: impl Fn(&T) -> bool,
    ) -> alloc::vec::Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(idx, slot)| {
                let entry = slot.as_ref()?;
                let matches = entry.metadata.get::<T>().is_some_and(&pred);
                matches.then_some(idx)
            })
            .collect()
    }
}

/// A handle to a descriptor entry (via [`Descriptors::entry_handle`]) that can be used without
/// maintaining access to the descriptor table itself.
pub struct EntryHandle<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem>(
    Arc<RwLock<Platform, DescriptorEntry>>,
    PhantomData<Subsystem>,
);
impl<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem>
    EntryHandle<Platform, Subsystem>
{
    pub fn with_entry<R>(&self, f: impl FnOnce(&Subsystem::Entry) -> R) -> R {
        f(self.0.read().as_subsystem::<Subsystem>())
    }

    pub fn with_entry_mut<R>(&self, f: impl FnOnce(&mut Subsystem::Entry) -> R) -> R {
        f(self.0.write().as_subsystem_mut::<Subsystem>())
    }
}

/// Result of a [`Descriptors::close_and_remove`] operation
pub(crate) enum CloseResult<Subsystem: FdEnabledSubsystem> {
    /// The FD was the last reference and has been closed, returning the entry
    Closed(Subsystem::Entry),
    /// The FD was unique but couldn't be closed immediately (e.g., due to pending data)
    Deferred,
    /// Other references exist (via dup or child process inheritance).
    /// The slot was freed; the entry remains alive via other slots.
    Released,
}

/// Safe(r) conversions between safely-typed file descriptors and unsafely-typed integers.
///
/// This particular object is also able to turn safely-typed file descriptors to/from unsafely-typed
/// integers, with a reasonable amount of safety---this will not be able to check for "ABA" style
/// issues, but will at least prevent using a descriptor for an unintended subsystem at the point of
/// conversion.
pub struct RawDescriptorStorage {
    /// Stored FDs are used to provide raw integer values in a safer way.
    stored_fds: Vec<Option<StoredFd>>,
}

struct StoredFd {
    x: Arc<OwnedFd>,
    subsystem_entry_type_id: core::any::TypeId,
}
impl StoredFd {
    fn new<Subsystem: FdEnabledSubsystem>(fd: TypedFd<Subsystem>) -> Self {
        Self {
            x: Arc::new(fd.x),
            subsystem_entry_type_id: core::any::TypeId::of::<Subsystem::Entry>(),
        }
    }
    #[must_use]
    fn matches_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> bool {
        self.subsystem_entry_type_id == core::any::TypeId::of::<Subsystem::Entry>()
    }
}

impl RawDescriptorStorage {
    #[expect(clippy::new_without_default)]
    /// Create a new raw descriptor store.
    pub fn new() -> Self {
        Self { stored_fds: vec![] }
    }

    /// Get the corresponding integer value of the provided `fd`.
    ///
    /// This explicitly consumes the `fd`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics are only within assertions"
    )]
    pub fn fd_into_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: TypedFd<Subsystem>,
    ) -> usize {
        let ret = self
            .stored_fds
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.stored_fds.len());
        let success = self.fd_into_specific_raw_integer(fd, ret);
        assert!(success);
        ret
    }

    /// Store the provided `fd` at the provided _specific_ raw integer FD.
    ///
    /// This is similar to [`Self::fd_into_raw_integer`] except that it specifies a specific FD to
    /// be stored into.
    ///
    /// Will return with `true` iff it succeeds (i.e., nothing else was using that raw integer FD).
    /// If you want to replace a used slot, you must first consume that slot via
    /// [`Self::fd_consume_raw_integer`].
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "not guaranteed as an API-level guarantee, but instead as a defensive panic to re-consider implementation if we hit it"
    )]
    pub fn fd_into_specific_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: TypedFd<Subsystem>,
        raw_fd: usize,
    ) -> bool {
        // TODO(jayb): Should we be storing things via a HashMap to make sure this operation cannot
        // be too expensive if someone tries to store into a large raw FD?
        //
        // If this assertion failure is hit in practice, we might need to be more defensive via the
        // HashMap, rather than just silently allow big growth
        assert!(
            raw_fd < self.stored_fds.len() + 256,
            "explicit upper bound restriction for now; see implementation details"
        );
        if self.stored_fds.get(raw_fd).is_some_and(Option::is_some) {
            // There's already something at this slot.
            return false;
        }
        if raw_fd >= self.stored_fds.len() {
            self.stored_fds.resize_with(raw_fd + 1, || None);
        }
        let old = self.stored_fds[raw_fd].replace(StoredFd::new(fd));
        assert!(old.is_none());
        true
    }

    /// Get the typed FD for the raw integer value of the `fd`.
    ///
    /// To fully remove this FD from see [`Self::fd_consume_raw_integer`].
    pub fn fd_from_raw_integer<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: usize,
    ) -> Result<Arc<TypedFd<Subsystem>>, ErrRawIntFd> {
        self.typed_fd_at_raw_1(fd)
    }

    /// Obtain the typed FD for the raw integer value of the `fd`, "consuming" the raw integer.
    ///
    /// Since this operation "consumes" the raw integer, future [`Self::fd_from_raw_integer`] might
    /// not refer to this file descriptor.
    ///
    /// You almost definitely want [`Self::fd_from_raw_integer`] instead, and should only use this
    /// if you really know you want to consume the descriptor.
    pub fn fd_consume_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: usize,
    ) -> Result<Arc<TypedFd<Subsystem>>, ErrRawIntFd> {
        let ret = self.fd_from_raw_integer(fd)?;
        let underlying = self.stored_fds[fd].take();
        debug_assert!(underlying.is_some());
        drop(underlying);
        Ok(ret)
    }

    /// Check if there is a valid FD at the raw integer value `fd`.
    ///
    /// This function is entirely subsystem-irrelevant. If you want to check against a subsystem,
    /// you might wish to use [`Self::fd_from_raw_integer`].
    #[must_use]
    pub fn is_alive(&self, fd: usize) -> bool {
        self.stored_fds.get(fd).is_some_and(Option::is_some)
    }

    /// Clone this FD table for a child process, optionally selecting which raw FD
    /// indices to inherit.
    ///
    /// - `inherit = None` — inherit all open FDs (bulk inheritance).
    /// - `inherit = Some(fds)` — inherit only the listed raw FD indices (selective
    ///   inheritance). Indices not present in the slice are skipped.
    /// - `inherit = Some(&[])` — inherit nothing (child gets an empty FD table).
    ///
    /// For each inherited FD, a new slot is created in the [`Descriptors`] table
    /// (via [`Descriptors::duplicate_slot`]), sharing the underlying entry via
    /// `Arc::clone`. The child's FD table points to these new slots, so parent
    /// and child can close FDs independently.
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics only on invariant violation (slot must exist during child creation)"
    )]
    pub fn clone_for_child<Platform: RawSyncPrimitivesProvider>(
        &self,
        descriptors: &mut Descriptors<Platform>,
        inherit: Option<&[usize]>,
    ) -> Self {
        let mut stored_fds = Vec::with_capacity(self.stored_fds.len());
        for (fd_index, slot) in self.stored_fds.iter().enumerate() {
            let cloned = slot.as_ref().and_then(|stored| {
                if inherit.is_some_and(|fds| !fds.contains(&fd_index)) {
                    return None;
                }
                let new_owned = descriptors
                    .duplicate_slot(&stored.x)
                    .expect("FD should not be closed during child creation");
                Some(StoredFd {
                    x: Arc::new(new_owned),
                    subsystem_entry_type_id: stored.subsystem_entry_type_id,
                })
            });
            stored_fds.push(cloned);
        }
        Self { stored_fds }
    }

    /// Returns an iterator over raw integer indices that are currently alive (i.e., occupied).
    pub fn iter_alive(&self) -> impl Iterator<Item = usize> + '_ {
        self.stored_fds
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_ref().map(|_| i))
    }

    /// Returns raw FD numbers whose corresponding `Descriptors` slot has per-FD metadata
    /// of type `T` satisfying `pred`.
    ///
    /// This resolves the raw FD → slot index mapping correctly, unlike
    /// [`Descriptors::indices_matching_metadata`] which returns slot indices.
    pub fn raw_fds_matching_metadata<
        Platform: RawSyncPrimitivesProvider,
        T: core::any::Any + Send + Sync,
    >(
        &self,
        descriptors: &Descriptors<Platform>,
        pred: impl Fn(&T) -> bool,
    ) -> alloc::vec::Vec<usize> {
        self.stored_fds
            .iter()
            .enumerate()
            .filter_map(|(raw_fd, slot)| {
                let stored = slot.as_ref()?;
                let slot_idx = stored.x.as_usize()?;
                let entry = descriptors.entries.get(slot_idx)?.as_ref()?;
                let matches = entry.metadata.get::<T>().is_some_and(&pred);
                matches.then_some(raw_fd)
            })
            .collect()
    }
}

macro_rules! multi_subsystem_generic {
    ($ident_f:ident, $ident_i:ident, $($f:ident $subsystem:ident),+ $(,)?) => {
        /// Invoke the corresponding function that matches the subsystem.
        ///
        /// Equivalent versions of this function exist at differing number of subsystems.
        fn $ident_f<R, $($subsystem),+>(
            &self,
            fd: usize,
            $(
                $f: impl FnOnce(Arc<TypedFd<$subsystem>>) -> R
            ),+
        ) -> Result<R, ErrRawIntFd>
        where
            $($subsystem: FdEnabledSubsystem),+
        {
            let Some(Some(stored_fd)) = self.stored_fds.get(fd) else {
                return Err(ErrRawIntFd::NotFound);
            };
            $(
                if stored_fd.matches_subsystem::<$subsystem>() {
                    let typed_fd: Arc<TypedFd<$subsystem>> = {
                        let fd: Arc<OwnedFd> = Arc::clone(&stored_fd.x);
                        let fd: *const OwnedFd = Arc::into_raw(fd);
                        // SAFETY: We are effectively converting an `Arc<OwnedFd>` to an
                        // `Arc<TypedFd<Subsystem>>`.
                        //
                        // This is safe because:
                        //
                        //   - `TypedFd` is a `#[repr(transparent)]` wrapper on `OwnedFd`.
                        //
                        //   - We just confirmed that it is of the correct subsystem.
                        //
                        //   - Thus, `OwnedFd` and `TypedFd` are effectively the same type, and
                        //     thus are safely castable.
                        //
                        //   - `Arc::from_raw`'s safety documentation requires the standard safe
                        //     castability constraints between the two.
                        unsafe { Arc::from_raw(fd.cast()) }
                    };
                    return Ok($f(typed_fd));
                }
            )+
                Err(ErrRawIntFd::InvalidSubsystem)
        }

        /// Get a conversion of the typed FD for any of the N subsystems for the raw integer
        /// value of the `fd`.
        ///
        /// Equivalent versions of this function exist at differing number of subsystems.
        pub fn $ident_i<R, $($subsystem),+>(
            &self,
            fd: usize,
        ) -> Result<R, ErrRawIntFd>
        where
            $($subsystem: FdEnabledSubsystem, R: From<Arc<TypedFd<$subsystem>>>),+
        {
            self.$ident_f(fd, $(
                |x: Arc<TypedFd<$subsystem>>| R::from(x)
            ),+)
        }
    };
}

impl RawDescriptorStorage {
    multi_subsystem_generic! {invoke_matching_subsystem_1, typed_fd_at_raw_1, f1 S1}
    multi_subsystem_generic! {invoke_matching_subsystem_2, typed_fd_at_raw_2, f1 S1, f2 S2}
    multi_subsystem_generic! {invoke_matching_subsystem_3, typed_fd_at_raw_3, f1 S1, f2 S2, f3 S3}
    multi_subsystem_generic! {invoke_matching_subsystem_4, typed_fd_at_raw_4, f1 S1, f2 S2, f3 S3, f4 S4}
}

/// A LiteBox subsystem that support having file descriptors.
pub trait FdEnabledSubsystem: Sized {
    /// The per-FD entry type stored in the descriptor table for this subsystem
    type Entry: FdEnabledSubsystemEntry + 'static;
}

/// A per-FD entry stored in the descriptor table for a specific [`FdEnabledSubsystem`]
pub trait FdEnabledSubsystemEntry: Send + Sync + core::any::Any {}

/// Possible errors from [`RawDescriptorStorage::fd_from_raw_integer`] and
/// [`RawDescriptorStorage::fd_consume_raw_integer`].
#[derive(Error, Debug)]
pub enum ErrRawIntFd {
    #[error("no such file descriptor found")]
    NotFound,
    #[error("fd for invalid subsystem")]
    InvalidSubsystem,
}

/// Possible errors from getting metadata
#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("no such metadata available")]
    NoSuchMetadata,
    #[error("fd has been closed")]
    ClosedFd,
}

/// A module-internal fd-specific individual entry
struct IndividualEntry<Platform: RawSyncPrimitivesProvider> {
    x: Arc<RwLock<Platform, DescriptorEntry>>,
    metadata: AnyMap,
}
impl<Platform: RawSyncPrimitivesProvider> core::ops::Deref for IndividualEntry<Platform> {
    type Target = Arc<RwLock<Platform, DescriptorEntry>>;
    fn deref(&self) -> &Self::Target {
        &self.x
    }
}
impl<Platform: RawSyncPrimitivesProvider> IndividualEntry<Platform> {
    fn new(x: Arc<RwLock<Platform, DescriptorEntry>>) -> Self {
        Self {
            x,
            metadata: AnyMap::new(),
        }
    }
}

/// A crate-internal entry for a descriptor.
pub(crate) struct DescriptorEntry {
    entry: alloc::boxed::Box<dyn FdEnabledSubsystemEntry>,
    metadata: AnyMap,
}

impl DescriptorEntry {
    /// Check if this entry matches the specified subsystem
    #[must_use]
    fn matches_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> bool {
        core::any::TypeId::of::<Subsystem::Entry>() == core::any::Any::type_id(self.entry.as_ref())
    }

    /// Obtains `self` as the subsystem's entry type.
    ///
    /// # Panics
    ///
    /// Panics if invalid for the particular subsystem.
    fn as_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> &Subsystem::Entry {
        (self.entry.as_ref() as &dyn core::any::Any)
            .downcast_ref()
            .unwrap()
    }

    /// Obtains `self` as the subsystem's entry type, mutably.
    ///
    /// # Panics
    ///
    /// Panics if invalid for the particular subsystem.
    fn as_subsystem_mut<Subsystem: FdEnabledSubsystem>(&mut self) -> &mut Subsystem::Entry {
        (self.entry.as_mut() as &mut dyn core::any::Any)
            .downcast_mut()
            .unwrap()
    }

    /// Obtains `self` as the subsystem's entry type.
    ///
    /// # Panics
    ///
    /// Panics if invalid for the particular subsystem.
    fn into_subsystem_entry<Subsystem: FdEnabledSubsystem>(self) -> Subsystem::Entry {
        *(self.entry as alloc::boxed::Box<dyn core::any::Any>)
            .downcast()
            .unwrap()
    }
}

/// A file descriptor that refers to entries by the `Subsystem`.
#[repr(transparent)] // this allows us to cast safely
pub struct TypedFd<Subsystem: FdEnabledSubsystem> {
    // Invariant in `Subsystem`: <https://doc.rust-lang.org/nomicon/phantom-data.html#table-of-phantomdata-patterns>
    _phantom: PhantomData<fn(Subsystem) -> Subsystem>,
    x: OwnedFd,
}

impl<Subsystem: FdEnabledSubsystem> TypedFd<Subsystem> {
    /// Get the "internal FD"
    pub(crate) fn as_internal_fd(&self) -> InternalFd {
        assert!(!self.x.is_closed());
        InternalFd { raw: self.x.raw }
    }
}

/// A crate-internal representation of file descriptors that supports cloning/copying, and does
/// *not* indicate validity/existence/ownership.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct InternalFd {
    pub(crate) raw: u32,
}

/// An explicitly-private shared-common element of [`TypedFd`], denoting an owned (non-clonable)
/// token of ownership over a file descriptor.
///
/// Note: this indicates ownership over the descriptor itself, but not necessarily the underlying
/// entry, since there might be duplicates to the underlying entry.
struct OwnedFd {
    raw: u32,
    closed: AtomicBool,
}

impl OwnedFd {
    /// Produce a new owned token from a raw index
    ///
    /// Panics if outside the u32 range
    pub(crate) fn new(raw: usize) -> Self {
        Self {
            raw: raw.try_into().unwrap(),
            closed: AtomicBool::new(false),
        }
    }

    /// Check if it is closed
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(core::sync::atomic::Ordering::SeqCst)
    }

    /// Mark it as closed
    pub(crate) fn mark_as_closed(&self) {
        let was_closed = self
            .closed
            .fetch_or(true, core::sync::atomic::Ordering::SeqCst);
        assert!(!was_closed);
    }

    /// Obtain the raw index it was created with if it has not been closed.
    ///
    /// Returns `None` if it has already been closed.
    pub(crate) fn as_usize(&self) -> Option<usize> {
        if self.is_closed() {
            return None;
        }
        let v: usize = self.raw.try_into().unwrap();
        Some(v)
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.is_closed() {
            // This has been closed out by a valid close operation
        } else {
            // The owned fd is dropped without being consumed by a `close` operation that has
            // properly marked it as being safely closed
            #[cfg(feature = "panic_on_unclosed_fd_drop")]
            panic!("Un-closed OwnedFd ({}) being dropped", self.raw)
        }
    }
}

/// Enable FD support for a particular subsystem conveniently
#[doc(hidden)]
macro_rules! enable_fds_for_subsystem {
    (
        $(@ $($sys_param:ident $(: { $($sys_constraint:tt)* })?),*;)?
        $system:ty;
        $(@ $($ent_param:ident $(: { $($ent_constraint:tt)* })?),*;)?
        $entry:ty;
        $(-> $fd:ident $(<$($fd_param:ident),*>)?;)?
    ) => {
        #[doc(hidden)]
        // This wrapper type exists just to make sure `$entry` itself is not public, but we can
        // still satisfy requirements for `FdEnabledSubsystem`.
        pub struct DescriptorEntry $(< $($ent_param $(: $($ent_constraint)*)?),* >)? {
            entry: $entry,
        }
        impl $(< $($sys_param $(: $($sys_constraint)*)?),* >)? $crate::fd::FdEnabledSubsystem
            for $system
        {
            type Entry = DescriptorEntry $(< $($ent_param),* >)?;
        }
        impl $(< $($ent_param $(: $($ent_constraint)*)?),* >)? $crate::fd::FdEnabledSubsystemEntry
            for DescriptorEntry $(< $($ent_param),* >)?
        {
        }
        impl $(< $($ent_param $(: $($ent_constraint)*)?),* >)? From<$entry>
            for DescriptorEntry $(< $($ent_param),* >)?
        {
            fn from(entry: $entry) -> Self {
                Self { entry }
            }
        }
        $(
            pub type $fd $(<$($fd_param),*>)? = $crate::fd::TypedFd<$system>;
        )?
    };
}
pub(crate) use enable_fds_for_subsystem;
