// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform adapter implementing the [`litebox_heki::HekiEnforcer`] port.
//!
//! This is the real ("live") adapter over the platform's existing enforcement
//! primitives: guarded VTL0 physical reads via [`crate::Vmap`]-backed
//! `PhysConstPtr`, the protected-frame reservation/transaction machinery, the
//! privileged validated VTL0 writer, and the one-time ring buffer / platform
//! root key installers. The HEKI/HVCI *algorithms* live in `litebox_heki` and
//! reach the platform only through this adapter.

use alloc::vec::Vec;
use litebox::utils::TruncateExt;
use litebox_common_linux::physical_pointers::PhysConstPtr;
use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{HekiPatch, MemAttr, PAGE_SIZE, VsmError};
use litebox_heki::{EnforceError, FrameTxn, HekiEnforcer, ReservationStatus};
use x86_64::{
    PhysAddr,
    structures::paging::{PageSize, Size4KiB, frame::PhysFrameRange},
};
use zerocopy::FromBytes;

use crate::mshv::vsm::{FrameReservation, protect_physical_memory_range};

/// A guarded, read-only physical pointer into foreign (VTL0) physical memory.
type Vtl0PhysConstPtr<T, const ALIGN: usize> = PhysConstPtr<T, ALIGN, crate::Vmap>;

/// Zero-sized live adapter implementing [`HekiEnforcer`] over the platform's
/// enforcement primitives.
pub struct PlatformHekiEnforcer;

/// Restricted transaction handle handed to a `protect_frames_transactionally`
/// closure. Wraps the private platform [`FrameReservation`] guard so the runner
/// can never hold or leak a reservation across the boundary.
struct PlatformFrameTxn<'a> {
    guard: &'a mut FrameReservation,
}

/// Map a platform reservation status to the port's status enum.
fn map_status(status: crate::mshv::vsm::ReservationStatus) -> ReservationStatus {
    match status {
        crate::mshv::vsm::ReservationStatus::New => ReservationStatus::New,
        crate::mshv::vsm::ReservationStatus::AlreadyOwned => ReservationStatus::AlreadyOwned,
    }
}

impl FrameTxn for PlatformFrameTxn<'_> {
    fn reserve(
        &mut self,
        ranges: &[PhysFrameRange<Size4KiB>],
    ) -> Result<Vec<ReservationStatus>, VsmError> {
        let statuses = self.guard.reserve(ranges.iter().copied())?;
        Ok(statuses.into_iter().map(map_status).collect())
    }

    fn protect(&mut self, range: PhysFrameRange<Size4KiB>, attr: MemAttr) -> Result<(), VsmError> {
        protect_physical_memory_range(range, attr)
    }
}

impl HekiEnforcer for PlatformHekiEnforcer {
    fn read_vtl0<T: FromBytes>(&self, pa: usize) -> Result<T, EnforceError> {
        let ptr = Vtl0PhysConstPtr::<T, PAGE_SIZE>::with_usize(pa)
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        let boxed = ptr
            .read_at_offset(0)
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        Ok(*boxed)
    }

    fn read_vtl0_pages<T: FromBytes>(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
    ) -> Result<T, EnforceError> {
        let ptr = Vtl0PhysConstPtr::<T, PAGE_SIZE>::new(pages, offset)
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        let boxed = ptr
            .read_at_offset(0)
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        Ok(*boxed)
    }

    fn read_vtl0_bytes(&self, pa: usize, out: &mut [u8]) -> Result<(), EnforceError> {
        let ptr = Vtl0PhysConstPtr::<u8, PAGE_SIZE>::with_contiguous_pages(pa, out.len())
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        ptr.read_slice_at_offset(0, out)
            .map_err(|_| EnforceError::Vtl0ReadFailed)
    }

    fn read_vtl0_bytes_pages(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), EnforceError> {
        let ptr = Vtl0PhysConstPtr::<u8, PAGE_SIZE>::new(pages, offset)
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        ptr.read_slice_at_offset(0, out)
            .map_err(|_| EnforceError::Vtl0ReadFailed)
    }

    fn protect_frames_transactionally(
        &self,
        initial: &[PhysFrameRange<Size4KiB>],
        f: &mut dyn FnMut(&mut dyn FrameTxn) -> Result<(), VsmError>,
    ) -> Result<(), VsmError> {
        let mut guard = FrameReservation::new();
        guard.reserve(initial.iter().copied())?;
        let mut txn = PlatformFrameTxn { guard: &mut guard };
        let result = f(&mut txn);
        if result.is_ok() {
            txn.guard.commit();
        }
        // On `Err`, `guard` drops here without a commit, rolling back
        // (unprotecting) every newly reserved range — preserving the existing
        // transaction semantics.
        result
    }

    fn unprotect_frames(&self, range: PhysFrameRange<Size4KiB>) -> Result<(), VsmError> {
        crate::mshv::vsm::unprotect_physical_memory_range(range)
    }

    fn apply_text_patch(&self, patch: &HekiPatch) -> Result<(), VsmError> {
        // Moved verbatim from `litebox_runner_lvbs::vsm::apply_vtl0_text_patch`.
        // `HekiPatch::is_valid` already validated both physical addresses.
        let heki_patch_pa_0 = PhysAddr::new(patch.pa[0]);
        let heki_patch_pa_1 = PhysAddr::new(patch.pa[1]);

        let code = &patch.code[..usize::from(patch.size)];
        if code.is_empty() {
            return Ok(());
        }

        if heki_patch_pa_1.is_null()
            || (heki_patch_pa_0.align_up(Size4KiB::SIZE) == heki_patch_pa_1.align_down(Size4KiB::SIZE))
        {
            // Single contiguous span: either fits in one page (pa_1 null) or pa_1 is the
            // adjacent next page. `HekiPatch::is_valid` enforces this; assert in debug builds.
            debug_assert!(
                !heki_patch_pa_1.is_null()
                    || heki_patch_pa_0.as_u64() + code.len() as u64
                        <= heki_patch_pa_0.align_down(Size4KiB::SIZE).as_u64() + Size4KiB::SIZE,
                "patch crosses page boundary but pa_1 is null"
            );
            // The patch was validated against VTL1's precomputed HEKI patch data
            // (`HekiPatch::is_valid`), satisfying the writer's caller contract.
            crate::mshv::write_validated_vtl0_patch_contiguous(
                heki_patch_pa_0.as_u64().trunc(),
                code,
            )
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        } else {
            let pages = [
                PhysPageAddr::<PAGE_SIZE>::new(
                    heki_patch_pa_0.align_down(Size4KiB::SIZE).as_u64().trunc(),
                )
                .ok_or(VsmError::Vtl0CopyFailed)?,
                PhysPageAddr::<PAGE_SIZE>::new(heki_patch_pa_1.as_u64().trunc())
                    .ok_or(VsmError::Vtl0CopyFailed)?,
            ];
            // The patch was validated against VTL1's precomputed HEKI patch data
            // (`HekiPatch::is_valid`), satisfying the writer's caller contract.
            crate::mshv::write_validated_vtl0_patch_pages(
                &pages,
                (heki_patch_pa_0 - heki_patch_pa_0.align_down(Size4KiB::SIZE)).trunc(),
                code,
            )
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        }
        Ok(())
    }

    fn install_ringbuffer(&self, pa: u64, size: usize) -> Result<(), VsmError> {
        if crate::mshv::ringbuffer::ringbuffer().is_some() {
            return Err(VsmError::AlreadyInitialized("ring buffer"));
        }
        crate::mshv::ringbuffer::set_ringbuffer(PhysAddr::new(pa), size);
        Ok(())
    }

    fn set_platform_root_key(&self, key: &[u8]) -> Result<(), VsmError> {
        if crate::host::set_platform_root_key(key) {
            Ok(())
        } else {
            Err(VsmError::AlreadyInitialized("platform root key"))
        }
    }
}
