// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform-side implementation of the [`litebox_common_lvbs::VsmPlatform`]
//! trait: the bridge between the VSM/HEKI service (`litebox_service_heki`) and
//! the platform's enforcement primitives (VTL0 physical-memory access,
//! frame protection hypercalls, AP bring-up, ring buffer, root key).

use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{HypervCallError, MemAttr, PAGE_SIZE, VsmError, VsmPlatform};
use x86_64::{
    PhysAddr,
    structures::paging::{PhysFrame, Size4KiB, frame::PhysFrameRange},
};

use crate::mshv::{HvPageProtFlags, hvcall_mm::hv_modify_vtl_protection_mask};

/// A guarded, read-only physical pointer into foreign (VTL0) physical memory.
type Vtl0PhysConstPtr<T, const ALIGN: usize> = super::Vtl0PhysConstPtr<T, ALIGN>;

/// A mutable VTL0 pointer reserved for validated HEKI text patching and the
/// fixed-address log ring buffer.
type PrivilegedVtl0PhysMutPtr<T, const ALIGN: usize> = super::PrivilegedVtl0PhysMutPtr<T, ALIGN>;

/// Zero-sized live adapter implementing [`VsmPlatform`] over the platform's
/// enforcement primitives. Constructed by the runner's VSM dispatcher.
pub struct LvbsVsmPlatform;

/// Maps a HEKI [`MemAttr`] permission set to the corresponding Hyper-V
/// page-protection flags.
pub(crate) fn heki_mem_attr_to_hv_page_prot_flags(attr: MemAttr) -> HvPageProtFlags {
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

/// Convert a platform-internal hypercall error into the common wire error type
/// exposed by the [`VsmPlatform`] trait. Both enums are identical `#[repr(u32)]`
/// copies, so the numeric hypervisor status is preserved.
pub(crate) fn to_common_hvcall_err(e: crate::mshv::hvcall::HypervCallError) -> HypervCallError {
    HypervCallError::try_from(u32::from(e)).unwrap_or(HypervCallError::Unknown)
}

/// Set VTL0's allowed access mask on a physical frame range, skipping any
/// portion that falls within VTL1's own physical memory (VTL1 self-protection).
///
/// If the requested range overlaps VTL1 working memory, the VTL1 portion is
/// silently skipped and only the remaining VTL0 portions are protected. If the
/// range falls entirely within VTL1, no hypercall is issued.
pub(crate) fn modify_vtl0_protection(
    phys_frame_range: PhysFrameRange<Size4KiB>,
    attr: MemAttr,
) -> Result<(), HypervCallError> {
    let vtl1_range = crate::platform_low().vtl1_phys_frame_range();

    // Range fully within VTL1 — nothing to protect for VTL0.
    if phys_frame_range.start >= vtl1_range.start && phys_frame_range.end <= vtl1_range.end {
        return Ok(());
    }

    // Fast path: no overlap with VTL1 — protect the entire range directly.
    let overlaps_vtl1 =
        phys_frame_range.start < vtl1_range.end && vtl1_range.start < phys_frame_range.end;

    if !overlaps_vtl1 {
        let pa = phys_frame_range.start.start_address().as_u64();
        let num_pages = phys_frame_range.count() as u64;
        hv_modify_vtl_protection_mask(pa, num_pages, heki_mem_attr_to_hv_page_prot_flags(attr))
            .map_err(to_common_hvcall_err)?;
        return Ok(());
    }
    // Partial overlap: split into the portions before and after VTL1, skipping
    // VTL1 pages.
    let sub_ranges: [PhysFrameRange<Size4KiB>; 2] = {
        let before = PhysFrame::range(
            phys_frame_range.start,
            core::cmp::min(phys_frame_range.end, vtl1_range.start),
        );
        let after = PhysFrame::range(
            core::cmp::max(phys_frame_range.start, vtl1_range.end),
            phys_frame_range.end,
        );
        [before, after]
    };

    for sub_range in sub_ranges {
        if sub_range.start >= sub_range.end {
            continue;
        }
        let pa = sub_range.start.start_address().as_u64();
        let num_pages = sub_range.count() as u64;
        hv_modify_vtl_protection_mask(pa, num_pages, heki_mem_attr_to_hv_page_prot_flags(attr))
            .map_err(to_common_hvcall_err)?;
    }
    Ok(())
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

    fn modify_vtl0_protection(
        &self,
        range: PhysFrameRange<Size4KiB>,
        attr: MemAttr,
    ) -> Result<(), HypervCallError> {
        modify_vtl0_protection(range, attr)
    }

    fn init_vtl_ap(&self, core: u32) -> Result<u64, HypervCallError> {
        crate::mshv::hvcall_vp::init_vtl_ap(core).map_err(to_common_hvcall_err)
    }

    fn install_ringbuffer(&self, pa: u64, size: usize) -> Result<(), VsmError> {
        let _ = crate::mshv::ringbuffer::set_ringbuffer(PhysAddr::new(pa), size);
        Ok(())
    }

    fn set_platform_root_key(&self, key: &[u8]) {
        crate::host::set_platform_root_key(key);
    }
}
