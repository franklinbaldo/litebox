// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Protected-frame registry and VTL0 physical-memory protection helpers.
//!
//! Tracks VTL0 frames that are non-writable to VTL0 or reserved by in-flight
//! module/kexec validation, and drives VTL0 protection updates through the
//! [`VsmPlatform::modify_vtl0_protection`] primitive. The `SpinRwLock`
//! mutual-exclusion design mirrors the original platform implementation:
//! ordinary writable mappings take shared access; reservations and protection
//! updates take exclusive access.

use alloc::vec::Vec;
use core::ops::Range;
use rangemap::RangeSet;
use spin::{Once, rwlock::RwLock as SpinRwLock};
use x86_64::structures::paging::{Size4KiB, frame::PhysFrameRange};

use litebox_common_lvbs::{MemAttr, VsmError, VsmPlatform};

/// RAII reservation over VTL0 physical frames, shared by module load and kexec validation.
/// On drop without `commit`, every newly reserved range is restored to VTL0 read/write,
/// non-executable access.
pub(crate) struct FrameReservation<'a, P: VsmPlatform> {
    platform: &'a P,
    owned_ranges: Vec<PhysFrameRange<Size4KiB>>,
    owned_frames: RangeSet<u64>,
    committed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReservationStatus {
    New,
    AlreadyOwned,
}

impl<'a, P: VsmPlatform> FrameReservation<'a, P> {
    pub(crate) fn new(platform: &'a P) -> Self {
        Self {
            platform,
            owned_ranges: Vec::new(),
            owned_frames: RangeSet::new(),
            committed: false,
        }
    }

    fn classify(
        owned: &RangeSet<u64>,
        registry: &ProtectedFrameUpdateGuard<'_>,
        range: Range<u64>,
    ) -> Result<ReservationStatus, VsmError> {
        if owned.gaps(&range).next().is_none() {
            return Ok(ReservationStatus::AlreadyOwned);
        }
        if owned.overlaps(&range) || registry.overlaps(&range) {
            Err(VsmError::ProtectedFrameOverlap)
        } else {
            Ok(ReservationStatus::New)
        }
    }

    /// Reserve `frames`. Ranges fully owned before this call are accepted idempotently. Overlap
    /// within this batch, partial overlap with prior ownership, and overlap with protected frames
    /// or another reservation are rejected.
    ///
    /// Validation and insertion are atomic under exclusive registry access. On rejection, only
    /// claims added by this call are rolled back.
    ///
    /// Note: unlike the original platform implementation, VTL1 self-protection is enforced by the
    /// platform inside its memory-access and protection primitives, so this reservation no longer
    /// special-cases the VTL1 physical range.
    pub(crate) fn reserve(
        &mut self,
        frames: impl IntoIterator<Item = PhysFrameRange<Size4KiB>>,
    ) -> Result<Vec<ReservationStatus>, VsmError> {
        protected_frame_registry().with_exclusive(|protected| {
            // Idempotence applies only to ranges owned before this call.
            let owned_before = self.owned_frames.clone();
            let mut seen = RangeSet::new();
            let mut statuses = Vec::new();
            // Frames this call adds, so a later overlap rolls back only them.
            let rollback_from = self.owned_ranges.len();
            for phys_frame_range in frames {
                let start = phys_frame_range.start.start_address().as_u64();
                let end = phys_frame_range.end.start_address().as_u64();
                if start >= end {
                    statuses.push(ReservationStatus::AlreadyOwned);
                    continue;
                }
                // `protected` holds existing non-writable frames, this reservation's earlier
                // claims, and any other concurrent reservation's in-flight claims.
                let range = start..end;
                let status = if seen.overlaps(&range) {
                    Err(VsmError::ProtectedFrameOverlap)
                } else {
                    Self::classify(&owned_before, protected, range.clone())
                };
                let status = match status {
                    Ok(status) => status,
                    Err(error) => {
                        for undo in &self.owned_ranges[rollback_from..] {
                            let range = undo.start.start_address().as_u64()
                                ..undo.end.start_address().as_u64();
                            protected.remove(range.clone());
                            self.owned_frames.remove(range);
                        }
                        self.owned_ranges.truncate(rollback_from);
                        return Err(error);
                    }
                };
                seen.insert(range.clone());
                if status == ReservationStatus::AlreadyOwned {
                    statuses.push(status);
                    continue;
                }
                protected.insert(range.clone());
                self.owned_frames.insert(range);
                self.owned_ranges.push(phys_frame_range);
                statuses.push(status);
            }
            Ok(statuses)
        })
    }

    /// Mark the reserved frames as committed; drop becomes a no-op.
    pub(crate) fn commit(&mut self) {
        self.committed = true;
    }
}

impl<P: VsmPlatform> Drop for FrameReservation<'_, P> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Rollback: restore every newly reserved range to VTL0 read/write, non-executable access.
        // Drop cannot report failure, so debug builds assert it.
        for &phys_frame_range in &self.owned_ranges {
            let result = unprotect_physical_memory_range(self.platform, phys_frame_range);
            debug_assert!(
                result.is_ok(),
                "Failed to restore VTL0 read/write access for reserved frames"
            );
        }
    }
}

/// Registry of VTL0 frames that are non-writable to VTL0 or reserved by in-flight module or kexec
/// validation. Ordinary writable mappings retain shared access for their lifetime; reservations and
/// VTL0 protection updates use exclusive access. Privileged HEKI and ring-buffer mappings bypass
/// the registry.
pub(crate) struct ProtectedFrameRegistry {
    frames: SpinRwLock<RangeSet<u64>>,
}

struct ProtectedFrameUpdateGuard<'a> {
    guard: spin::rwlock::RwLockWriteGuard<'a, RangeSet<u64>>,
}

impl ProtectedFrameUpdateGuard<'_> {
    fn overlaps(&self, range: &Range<u64>) -> bool {
        self.guard.overlaps(range)
    }

    fn insert(&mut self, range: Range<u64>) {
        self.guard.insert(range);
    }

    fn remove(&mut self, range: Range<u64>) {
        self.guard.remove(range);
    }

    fn record_protection(&mut self, phys_frame_range: PhysFrameRange<Size4KiB>, protect: bool) {
        let start = phys_frame_range.start.start_address().as_u64();
        let end = phys_frame_range.end.start_address().as_u64();
        if start >= end {
            return;
        }
        if protect {
            self.insert(start..end);
        } else {
            self.remove(start..end);
        }
    }
}

impl ProtectedFrameRegistry {
    fn new() -> Self {
        Self {
            frames: SpinRwLock::new(RangeSet::new()),
        }
    }

    /// Runs `f` with exclusive registry access.
    fn with_exclusive<R>(&self, f: impl FnOnce(&mut ProtectedFrameUpdateGuard<'_>) -> R) -> R {
        f(&mut ProtectedFrameUpdateGuard {
            guard: self.frames.write(),
        })
    }
}

pub(crate) fn protected_frame_registry() -> &'static ProtectedFrameRegistry {
    static REGISTRY: Once<ProtectedFrameRegistry> = Once::new();
    REGISTRY.call_once(ProtectedFrameRegistry::new)
}

/// Protect a VTL0 physical memory range using the platform's VTL0 protection primitive
/// (e.g., kernel code integrity).
///
/// The registry tracks non-writable VTL0 ranges and temporary validation reservations.
/// See [`protected_frame_registry`].
///
/// VTL1 self-protection is enforced by the platform inside
/// [`VsmPlatform::modify_vtl0_protection`]; this function no longer performs the VTL1-range
/// splitting the original platform implementation did.
///
/// `phys_frame_range` specifies the range whose VTL0 permissions are updated.
/// `mem_attr` specifies the memory attributes (VTL0's allowed access) to be applied.
pub(crate) fn protect_physical_memory_range<P: VsmPlatform>(
    platform: &P,
    phys_frame_range: PhysFrameRange<Size4KiB>,
    mem_attr: MemAttr,
) -> Result<(), VsmError> {
    let protect = !mem_attr.contains(MemAttr::MEM_ATTR_WRITE);

    protected_frame_registry().with_exclusive(|protected| {
        if phys_frame_range.start >= phys_frame_range.end {
            return Ok(());
        }
        platform
            .modify_vtl0_protection(phys_frame_range, mem_attr)
            .map_err(VsmError::HypercallFailed)?;
        protected.record_protection(phys_frame_range, protect);
        Ok(())
    })
}

/// Restore VTL0 read/write access while leaving execution disabled, and removes the registry entry.
pub(crate) fn unprotect_physical_memory_range<P: VsmPlatform>(
    platform: &P,
    phys_frame_range: PhysFrameRange<Size4KiB>,
) -> Result<(), VsmError> {
    protect_physical_memory_range(
        platform,
        phys_frame_range,
        MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_WRITE,
    )
}
