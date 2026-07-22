// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform-side implementation of the [`litebox_common_lvbs::VsmPlatform`]
//! trait: the bridge between the VSM/HEKI service (`litebox_service_heki`) and
//! the platform's enforcement primitives (VTL0 physical-memory access,
//! frame protection hypercalls, AP bring-up, ring buffer, root key).

use alloc::vec::Vec;
use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{
    FrameTxn, HypervCallError, MemAttr, PAGE_SIZE, PRK_LEN, ReservationStatus, VsmError,
    VsmPlatform,
};
use x86_64::{
    PhysAddr,
    structures::paging::{Size4KiB, frame::PhysFrameRange},
};

use crate::mshv::HvPageProtFlags;
use crate::mshv::vsm::{
    FrameReservation, protect_physical_memory_range, unprotect_physical_memory_range,
};

/// A guarded, read-only physical pointer into foreign (VTL0) physical memory.
type Vtl0PhysConstPtr<T, const ALIGN: usize> = super::Vtl0PhysConstPtr<T, ALIGN>;

/// A mutable VTL0 pointer reserved for validated HEKI text patching and the
/// fixed-address log ring buffer.
type PrivilegedVtl0PhysMutPtr<T, const ALIGN: usize> = super::PrivilegedVtl0PhysMutPtr<T, ALIGN>;

/// Zero-sized live adapter implementing [`VsmPlatform`] over the platform's
/// enforcement primitives. Constructed by the runner's VSM dispatcher.
pub struct LvbsVsmPlatform;

/// Maps a [`MemAttr`] permission set (the VsmPlatform permission type) to the
/// corresponding Hyper-V page-protection flags.
pub(crate) fn mem_attr_to_hv_page_prot_flags(attr: MemAttr) -> HvPageProtFlags {
    let mut flags = HvPageProtFlags::empty();
    if attr.contains(MemAttr::MEM_ATTR_READ) {
        flags.set(HvPageProtFlags::HV_PAGE_READABLE, true);
        flags.set(HvPageProtFlags::HV_PAGE_USER_EXECUTABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_WRITE) {
        flags.set(HvPageProtFlags::HV_PAGE_WRITABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_EXEC) {
        flags.set(HvPageProtFlags::HV_PAGE_EXECUTABLE, true);
    }
    flags
}

/// Restricted transaction handle handed to a `protect_frames_transactionally`
/// closure. Wraps the private platform [`FrameReservation`] guard so the service
/// can never hold or leak a reservation across the trait boundary.
struct PlatformFrameTxn<'a> {
    guard: &'a mut FrameReservation,
}

/// Map a platform-internal reservation status to the common status enum.
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
        protect_physical_memory_range(range, mem_attr_to_hv_page_prot_flags(attr))
    }
}

impl VsmPlatform for LvbsVsmPlatform {
    fn read_vtl0_bytes(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), VsmError> {
        let ptr = Vtl0PhysConstPtr::<u8, PAGE_SIZE>::new(pages, offset)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        ptr.read_slice_at_offset(0, out)
            .map_err(|_| VsmError::Vtl0CopyFailed)
    }

    fn write_vtl0_privileged(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), VsmError> {
        let ptr = PrivilegedVtl0PhysMutPtr::<u8, PAGE_SIZE>::new(pages, offset)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        ptr.write_slice_at_offset(0, bytes)
            .map_err(|_| VsmError::Vtl0CopyFailed)
    }

    fn protect_frame(
        &self,
        range: PhysFrameRange<Size4KiB>,
        attr: MemAttr,
    ) -> Result<(), VsmError> {
        protect_physical_memory_range(range, mem_attr_to_hv_page_prot_flags(attr))
    }

    fn unprotect_frames(&self, range: PhysFrameRange<Size4KiB>) -> Result<(), VsmError> {
        unprotect_physical_memory_range(range)
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
        // On `Err`, `guard` drops uncommitted, rolling back every reserved range.
        result
    }

    fn init_vtl_ap(&self, core: u32) -> Result<u64, HypervCallError> {
        crate::mshv::hvcall_vp::init_vtl_ap(core)
    }

    fn install_ringbuffer(&self, pa: u64, size: usize) -> Result<(), VsmError> {
        let _ = crate::mshv::ringbuffer::set_ringbuffer(PhysAddr::new(pa), size);
        Ok(())
    }

    fn set_platform_root_key(&self, key: &[u8; PRK_LEN]) {
        crate::host::set_platform_root_key(key);
    }
}
