// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management related functionality

pub mod allocator;
pub mod exception_table;
pub mod linux;

#[cfg(test)]
mod tests;

use core::ops::Range;

use alloc::vec::Vec;
use linux::{
    CreatePagesFlags, MappingError, PageFaultError, PageRange, VmArea, VmFlags, Vmem,
    VmemPageFaultHandler, VmemProtectError, VmemUnmapError,
};

use crate::{
    LiteBox,
    mm::linux::{NonZeroAddress, NonZeroPageSize, VmemResetError},
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{MemoryRegionPermissions, RemapError},
    },
    sync::{RawSyncPrimitivesProvider, RwLock},
};

/// A page manager to support `mmap`, `munmap`, and etc.
pub struct PageManager<Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    vmem: RwLock<Platform, Vmem<Platform, ALIGN>>,
}

impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    /// Size of the region reserved above the initial brk for future brk growth.
    ///
    /// On Linux, this is a soft VMA-tree-only reservation: the top-down allocator
    /// avoids placing hint-based anonymous mmaps in `[brk..brk + BRK_RESERVE_SIZE)`.
    /// 32 MiB is generous enough for typical programs.
    ///
    /// On macOS, the entire brk zone is hard-reserved with the kernel via
    /// `mmap(PROT_NONE, MAP_FIXED)` at `set_initial_brk` time.  256 MiB is used
    /// because it is free (no physical memory committed for PROT_NONE pages) and
    /// brk growth beyond this limit returns ENOMEM, forcing glibc to fall back to
    /// mmap-based allocation.
    #[cfg(target_os = "macos")]
    pub const BRK_RESERVE_SIZE: usize = 256 << 20; // 256 MiB
    #[cfg(not(target_os = "macos"))]
    pub const BRK_RESERVE_SIZE: usize = 32 << 20; // 32 MiB

    /// Create a new `PageManager` instance.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        let vmem = RwLock::new(linux::Vmem::new(litebox.x.platform));
        Self { vmem }
    }

    /// Create a mapping with the given flags.
    ///
    /// `suggested_new_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// `before_perms` and `after_perms` are the permissions to set before and after the call to `op`.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    unsafe fn create_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        before_perms: MemoryRegionPermissions,
        after_perms: MemoryRegionPermissions,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let addr = {
            let mut vmem = self.vmem.write();
            unsafe { vmem.create_pages(suggested_address, length, flags, before_perms) }?
        };
        // call the user function with the pages
        // Note `op` may trigger page fault handler which requires write lock to `vmem`.
        if let Err(e) = op(addr) {
            // remove the mapping if the user function fails
            let mut vmem = self.vmem.write();
            unsafe {
                vmem.remove_mapping(
                    PageRange::new(addr.as_usize(), addr.as_usize() + length.as_usize()).unwrap(),
                )
            }
            .unwrap();
            return Err(e);
        }
        if before_perms != after_perms {
            let range =
                PageRange::new(addr.as_usize(), addr.as_usize() + length.as_usize()).unwrap();
            // `protect` should succeed, as we just created the mapping.
            let mut vmem = self.vmem.write();
            unsafe { vmem.protect_mapping(range, after_perms) }.expect("failed to protect mapping");
        }
        Ok(addr)
    }

    /// Create readable and executable pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_executable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                // create READ | WRITE pages (as `op` may need to write to them, e.g., fill in the code)
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                // keep READ, turn off WRITE and turn on EXEC
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
                op,
            )
        }
    }

    /// Create readable and writable pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_writable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        unsafe { self.create_pages(suggested_address, length, flags, perms, perms, op) }
    }

    /// Create read-only pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_readable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                // create READ | WRITE pages (as `op` may need to write to them, e.g., fill in the data)
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                // keep READ, turn off WRITE
                MemoryRegionPermissions::READ,
                op,
            )
        }
    }

    /// Create inaccessible pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_inaccessible_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                MemoryRegionPermissions::empty(),
                MemoryRegionPermissions::empty(),
                op,
            )
        }
    }

    /// Create stack pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_stack_pages(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        let flags = CreatePagesFlags::IS_STACK | flags;
        unsafe { self.create_pages(suggested_address, length, flags, perms, perms, |_| Ok(0)) }
    }

    /// Set the initial program break address.
    ///
    /// This function should be called once to set the initial program break,
    /// which is usually the end of the data segment.
    ///
    /// # Panics
    ///
    /// Panics if the initial program break is already set.
    pub fn set_initial_brk(&self, brk: usize) {
        let mut vmem = self.vmem.write();
        assert_eq!(vmem.brk, 0, "initial brk is already set");
        vmem.brk = brk;
        // Reserve a region above brk for future brk growth so that the
        // top-down hint-based allocator does not place anonymous mmaps there.
        let brk_aligned = brk.next_multiple_of(linux::PAGE_SIZE);
        vmem.brk_reserved_end = brk_aligned + Self::BRK_RESERVE_SIZE;

        // On macOS, hard-reserve the free gaps within the brk zone with the
        // kernel via mmap(PROT_NONE, NoReplace).  This prevents the macOS
        // kernel from placing future mappings inside the brk zone gaps.
        //
        // We must enumerate gaps BEFORE evicting host reservation VMAs,
        // because those VMAs tell us where the host mappings are (and thus
        // which regions are genuinely free).
        //
        // We do NOT use MAP_FIXED (Replace) because the brk zone may overlap
        // live host mappings (dyld, system libraries, allocator regions).
        // Clobbering them would hang or crash the process.
        #[cfg(target_os = "macos")]
        {
            let brk_start = brk_aligned;
            let brk_end = vmem.brk_reserved_end;
            if brk_start < brk_end {
                // Collect gaps (free regions) in the VMA tree within the brk zone.
                // These are the regions not covered by host reservation VMAs.
                let gaps: alloc::vec::Vec<core::ops::Range<usize>> =
                    vmem.gaps_in_range(brk_start..brk_end);

                let mut any_reserved = false;
                for gap in gaps {
                    // Align gap to page boundaries (should already be aligned,
                    // but be defensive).
                    let gap_start = gap.start.next_multiple_of(linux::PAGE_SIZE);
                    let gap_end = gap.end & !(linux::PAGE_SIZE - 1);
                    if gap_start >= gap_end {
                        continue;
                    }
                    if vmem
                        .platform
                        .allocate_pages(
                            gap_start..gap_end,
                            MemoryRegionPermissions::empty(), // PROT_NONE
                            false,                            // can_grow_down
                            false,                            // populate_pages_immediately
                            crate::platform::page_mgmt::FixedAddressBehavior::NoReplace,
                        )
                        .is_ok()
                    {
                        // Track the reserved gap in the VMA tree.
                        if let Some(pr) = linux::PageRange::new(gap_start, gap_end) {
                            vmem.register_existing_mapping_overwrite(
                                pr,
                                linux::VmArea::new(linux::VmFlags::empty(), false),
                            );
                        }
                        any_reserved = true;
                    }
                    // If allocation failed, the host may have placed something
                    // there between enumeration and mmap.  Continue with
                    // remaining gaps.
                }
                vmem.brk_hard_reserved = any_reserved;
            }
        }

        // Evict any pre-existing host reservation VMAs (from reserved_pages)
        // that overlap the brk zone.  These were inserted at Vmem::new() time
        // before the brk address was known and would cause brk() to fail with
        // ENOMEM when it finds them via overlapping().
        vmem.evict_reserved_from_brk_zone();
    }

    /// Find a free region of at least `size` bytes at or above `min_addr`.
    ///
    /// Returns `None` if no suitable gap exists. This is useful for computing
    /// mmap hints that are known-free in the vmem VMA tree (e.g. for placing
    /// the ELF interpreter above the brk region on macOS where the host kernel
    /// may ignore hints that fall inside pre-existing host-side mappings).
    pub fn find_free_hint_above(&self, min_addr: usize, size: usize) -> Option<usize> {
        self.vmem.read().find_free_above(min_addr, size)
    }

    /// Set the program break to the given address.
    ///
    /// Increasing the program break has the effect of allocating memory to the process;
    /// decreasing the break deallocates memory.
    /// Calling `brk` with 0 can be used to find the current location of the program break.
    ///
    /// Note the initial program break is set to zero and the first call to `brk` would set it
    /// to the given address, which is usually the end of the data segment.
    ///
    /// ## Returns
    ///
    /// If the operation is successful, it returns the new program break address.
    ///
    /// # Panics
    ///
    /// Panics if the initial program break is not set yet.
    ///
    /// # Safety
    ///
    /// If shrinking the program break, the caller must ensure that the released memory region is no longer used.
    pub unsafe fn brk(&self, brk: usize) -> Result<usize, MappingError> {
        let mut vmem = self.vmem.write();
        assert_ne!(vmem.brk, 0, "initial brk is not set yet");
        if brk == 0 {
            // Calling `brk` with 0 can be used to find the current location of the program break.
            return Ok(vmem.brk);
        }

        let old_brk = vmem.brk.next_multiple_of(linux::PAGE_SIZE);
        let new_brk = brk.next_multiple_of(linux::PAGE_SIZE);

        if vmem.brk_hard_reserved {
            // ── Hard-reserved brk zone (macOS) ──────────────────────────
            //
            // The entire brk zone `[brk_aligned..brk_reserved_end)` was
            // hard-reserved with the kernel as PROT_NONE at set_initial_brk
            // time.  Growth promotes slices to RW via mprotect; shrink
            // demotes them back to PROT_NONE.  No mmap/munmap needed.

            if vmem.brk >= brk {
                // Shrink: try to demote [new_brk..old_brk) back to PROT_NONE.
                // If update_permissions fails (region may span a non-reserved
                // host mapping), fall back to remove_mapping (munmap).
                if new_brk < old_brk {
                    let range = new_brk..old_brk;
                    let demoted = unsafe {
                        vmem.platform
                            .update_permissions(range.clone(), MemoryRegionPermissions::empty())
                            .is_ok()
                    };
                    if demoted {
                        // Update the VMA entry: mark as PROT_NONE (still reserved).
                        if let Some(pr) = linux::PageRange::<ALIGN>::new(range.start, range.end) {
                            vmem.register_existing_mapping_overwrite(
                                pr,
                                linux::VmArea::new(linux::VmFlags::empty(), false),
                            );
                        }
                    } else {
                        // Fallback: munmap the region.
                        match unsafe {
                            vmem.remove_mapping(
                                PageRange::new(new_brk, old_brk).ok_or(MappingError::UnAligned)?,
                            )
                        } {
                            Ok(()) => {}
                            Err(_) => {
                                return Ok(vmem.brk); // No change
                            }
                        }
                    }
                }
                vmem.brk = brk;
                return Ok(brk);
            }

            // Grow: check hard cap, then promote [old_brk..new_brk) to RW.
            // Try update_permissions first (for gap-reserved PROT_NONE pages).
            // If it fails (the slice may span a host mapping that wasn't part
            // of the gap-fill reservation), fall back to create_pages(MAP_FIXED).
            if new_brk > vmem.brk_reserved_end {
                return Err(MappingError::MapError(
                    crate::platform::page_mgmt::AllocationError::OutOfMemory,
                ));
            }

            if old_brk < new_brk {
                let range = old_brk..new_brk;
                let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
                let promoted = unsafe {
                    vmem.platform
                        .update_permissions(range.clone(), perms)
                        .is_ok()
                };
                if promoted {
                    // update_permissions succeeded — pages were part of our
                    // gap-fill reservation.  Update VMA to RW.
                    if let Some(pr) = linux::PageRange::<ALIGN>::new(range.start, range.end) {
                        vmem.register_existing_mapping_overwrite(
                            pr,
                            linux::VmArea::new(linux::VmFlags::from(perms), false),
                        );
                    }
                } else {
                    // update_permissions failed — fall back to create_pages
                    // (mmap MAP_FIXED) which can overwrite host mappings.
                    if let Some(pr) = PageRange::<ALIGN>::new(old_brk, new_brk) {
                        let (suggested_address, length) = pr.start_and_length();
                        unsafe {
                            vmem.create_pages(
                                Some(suggested_address),
                                length,
                                CreatePagesFlags::FIXED_ADDR
                                    | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                                perms,
                            )
                        }?;
                    }
                }
            }
            vmem.brk = brk;
            Ok(brk)
        } else {
            // ── Soft-reserved brk zone (Linux / macOS fallback) ─────────
            //
            // Original path: grow via create_pages (mmap MAP_FIXED),
            // shrink via remove_mapping (munmap).

            if vmem.brk >= brk {
                // Shrink the memory region
                let brk = match unsafe {
                    vmem.remove_mapping(
                        PageRange::new(new_brk, old_brk).ok_or(MappingError::UnAligned)?,
                    )
                } {
                    Ok(()) => {
                        vmem.brk = brk;
                        brk
                    }
                    Err(_) => {
                        vmem.brk // No change, return the old brk
                    }
                };
                return Ok(brk);
            }

            if vmem.overlapping(old_brk..new_brk).next().is_some() {
                // Diagnostic: dump the overlapping VMAs to help debug brk failures.
                let mut msg = alloc::string::String::from("brk ENOMEM: overlapping VMAs:\n");
                for (range, vma) in vmem.overlapping(old_brk..new_brk) {
                    use core::fmt::Write;
                    let _ = writeln!(
                        msg,
                        "  VMA {:#x}..{:#x} flags={:?} file_backed={}",
                        range.start,
                        range.end,
                        vma.flags(),
                        vma.is_file_backed()
                    );
                }
                {
                    use core::fmt::Write;
                    let _ = write!(
                        msg,
                        "  old_brk={:#x} new_brk={:#x} vmem.brk={:#x} brk_reserved_end={:#x}",
                        old_brk, new_brk, vmem.brk, vmem.brk_reserved_end
                    );
                }
                panic!("{msg}");
            }
            if let Some(range) = PageRange::<ALIGN>::new(old_brk, new_brk) {
                let (suggested_address, length) = range.start_and_length();
                let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
                unsafe {
                    vmem.create_pages(
                        Some(suggested_address),
                        length,
                        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                        perms,
                    )
                }?;
            }
            vmem.brk = brk;
            Ok(brk)
        }
    }

    /// Release memory mappings that satisfy the given condition and reset the program break.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the released memory regions are no longer used.
    pub unsafe fn release_memory(
        &self,
        releasable: impl Fn(Range<usize>, VmFlags) -> bool,
    ) -> Result<(), VmemUnmapError> {
        for (r, vma) in self.mappings() {
            if !releasable(r.clone(), vma) {
                continue;
            }
            let mut vmem = self.vmem.write();
            let Some(range) = PageRange::new(r.start, r.end) else {
                unreachable!()
            };
            unsafe { vmem.remove_mapping(range) }?;
        }

        // reset brk
        let mut vmem = self.vmem.write();
        vmem.brk = 0;
        vmem.brk_reserved_end = 0;
        vmem.brk_hard_reserved = false;

        Ok(())
    }

    /// Expands (or shrinks) an existing memory mapping
    ///
    /// `old_addr` is the old address of the virtual memory block that you want to expand (or shrink).
    ///
    /// `old_size` is the size of the old memory block.
    ///
    /// `new_size` is the new size of the memory block.
    ///
    /// `may_move` indicates whether the memory block can be moved to a new address if there is not sufficient
    /// space to expand the old memory block at its current location.
    ///
    /// ## Returns
    ///
    /// If the operation is successful, it returns the new address of the memory block.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub unsafe fn remap_pages(
        &self,
        old_addr: Platform::RawMutPointer<u8>,
        old_size: usize,
        new_size: usize,
        may_move: bool,
    ) -> Result<Platform::RawMutPointer<u8>, RemapError> {
        let mut vmem = self.vmem.write();
        let old_range = PageRange::new(old_addr.as_usize(), old_addr.as_usize() + old_size)
            .ok_or(RemapError::Unaligned)?;
        match unsafe {
            vmem.resize_mapping(
                old_range,
                linux::NonZeroPageSize::new(new_size).ok_or(RemapError::Unaligned)?,
            )
        } {
            Ok(()) => Ok(old_addr),
            Err(linux::VmemResizeError::RangeOccupied(_)) => {
                // trying to remap a subset of an existing mapping
                if !may_move {
                    return Err(RemapError::OutOfMemory);
                }
                match unsafe {
                    vmem.move_mappings(
                        old_range,
                        None,
                        NonZeroPageSize::new(new_size).ok_or(RemapError::Unaligned)?,
                    )
                } {
                    Ok(new_addr) => Ok(new_addr),
                    Err(linux::VmemMoveError::OutOfMemory) => Err(RemapError::OutOfMemory),
                    Err(linux::VmemMoveError::UnAligned) => Err(RemapError::Unaligned),
                    Err(linux::VmemMoveError::RemapError(err)) => Err(err),
                }
            }
            Err(linux::VmemResizeError::NotExist(_)) => Err(RemapError::AlreadyUnallocated),
            Err(linux::VmemResizeError::InvalidAddr { .. }) => Err(RemapError::AlreadyAllocated),
            Err(linux::VmemResizeError::OutOfMemory) => Err(RemapError::OutOfMemory),
        }
    }

    /// Remove pages from the mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub unsafe fn remove_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemUnmapError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len).ok_or(VmemUnmapError::UnAligned)?;
        unsafe { vmem.remove_mapping(range) }
    }

    /// Reset pages without removing its mapping.
    ///
    /// If `anonymous_only` is true and any part of the range is non‑anonymous (i.e., file‑backed),
    /// returns `Err(VmemResetError::FileBacked)`.
    ///
    /// After calling this function, the memory region remains mapped, but its contents are invalidated.
    /// Subsequent accesses to the region will result in repopulating the memory contents, either from
    /// the underlying mapped file (for file-backed mappings, which is supported) or as zero-filled pages
    /// (for anonymous mappings).
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory contents in the affected region are no longer accessed or
    /// relied upon. Any pointers or references to the previous contents become invalid.
    pub unsafe fn reset_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        anonymous_only: bool,
    ) -> Result<(), VmemResetError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len).ok_or(VmemResetError::UnAligned)?;
        unsafe { vmem.reset_pages(range, anonymous_only) }
    }

    /// Internal common function used by `make_pages_*` to change page permissions.
    fn change_page_permissions(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len)
            .ok_or(VmemProtectError::InvalidRange(start..start + len))?;
        unsafe { vmem.protect_mapping(range, new_permissions) }
    }

    /// Make pages readable and writable.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `execute` access to the memory region.
    pub unsafe fn make_pages_writable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
        )
    }

    /// Make pages readable and executable.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `write` access to the memory region.
    pub unsafe fn make_pages_executable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
        )
    }

    /// Make pages readable only.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `write/execute` access to the memory region.
    pub unsafe fn make_pages_readable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(ptr, len, MemoryRegionPermissions::READ)
    }

    /// Make pages inaccessible.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent access to the memory region.
    pub unsafe fn make_pages_inaccessible(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(ptr, len, MemoryRegionPermissions::empty())
    }

    /// Make pages readable, writable and executable.
    ///
    /// # Safety
    ///
    /// This operation is inherently dangerous and should be used with extreme caution.
    /// Allowing pages to be both writable and executable can lead to severe security vulnerabilities,
    /// such as code injection attacks or exploitation of memory corruption bugs.
    ///
    /// The caller must ensure the following:
    /// 1. The memory region is only used for legitimate purposes, such as JIT compilation,
    ///    where writable and executable permissions are strictly necessary.
    /// 2. The memory region is properly sanitized and does not contain malicious or unintended code.
    ///
    /// It is highly recommended to minimize the use of this function and to prefer safer alternatives
    /// whenever possible. If this function must be used, ensure that the memory region is locked down
    /// and access is strictly controlled.
    pub unsafe fn make_pages_rwx(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ
                | MemoryRegionPermissions::WRITE
                | MemoryRegionPermissions::EXEC,
        )
    }

    /// Register an already-allocated memory region in the VMA tracker.
    ///
    /// This is used when memory has been allocated by some means other than the normal
    /// `create_*_pages` path (e.g., CoW mappings created directly by the platform), so that the
    /// page manager tracks the region for future `mprotect`, `munmap`, etc.
    ///
    /// If `replace` is `true`, any overlapping tracked mappings are evicted from the tracker
    /// (without calling the platform deallocator) before inserting. Otherwise, returns `None`
    /// without registering if the provided `range` overlaps with any existing mapping.
    ///
    /// # Safety
    ///
    /// The `range` must be an already-mapped region with the given `permissions`.
    #[must_use]
    pub unsafe fn register_existing_mapping(
        &self,
        range: PageRange<ALIGN>,
        permissions: MemoryRegionPermissions,
        is_file_backed: bool,
        replace: bool,
        shared: bool,
    ) -> Option<()> {
        let vma = VmArea::new(
            VmFlags::from(permissions) | VmFlags::may_flags_for_mapping(shared, is_file_backed),
            is_file_backed,
        );
        let mut vmem = self.vmem.write();
        if !replace && vmem.overlapping(range.into()).next().is_some() {
            return None;
        }
        vmem.register_existing_mapping_overwrite(range, vma);
        Some(())
    }

    /// Returns all mappings in a vector.
    pub fn mappings(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmem
            .read()
            .iter()
            .map(|(r, vma)| (r.start..r.end, vma.flags()))
            .collect()
    }

    /// Get the memory permissions of a given address range.
    ///
    /// `ptr` specifies the start address of the memory range.
    /// `len` specifies the length of the memory range.
    /// This function returns `MemoryRegionPermissions` only if the range is valid.
    /// A memory range is invalid if it contains:
    /// - Unmapped pages
    /// - Memory pages with different permissions
    pub fn get_memory_permissions(
        &self,
        ptr: NonZeroAddress<ALIGN>,
        len: NonZeroPageSize<ALIGN>,
    ) -> Option<MemoryRegionPermissions> {
        let vmem = self.vmem.read();
        let start = ptr.as_usize();
        let end = start + len.as_usize();
        let page_range = PageRange::<ALIGN>::new(start, end)?;
        vmem.get_memory_permissions(page_range)
    }
}

/// If Backend also implements [`VmemPageFaultHandler`], it can handle page faults.
impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
    Platform: VmemPageFaultHandler,
{
    /// Handle page fault at the given address.
    ///
    /// # Safety
    ///
    /// This should only be called from the kernel page fault handler.
    pub unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        error_code: u64,
    ) -> Result<(), PageFaultError> {
        let fault_addr = fault_addr & !(ALIGN - 1);
        if !(Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX).contains(&fault_addr) {
            return Err(PageFaultError::AccessError("Invalid address"));
        }

        let mut vmem = self.vmem.write();
        // Find the range closest to the fault address
        let (start, vma) = {
            let (r, vma) = vmem
                .overlapping(fault_addr..Platform::TASK_ADDR_MAX)
                .next()
                .ok_or(PageFaultError::AccessError("no mapping"))?;
            (r.start, *vma)
        };
        if fault_addr < start {
            // address is out of range, test if it is next to a stack
            if !vma.flags().contains(VmFlags::VM_GROWSDOWN) {
                return Err(PageFaultError::AccessError("no mapping"));
            }

            if !vmem
                .overlapping(Platform::TASK_ADDR_MIN..fault_addr)
                .next_back()
                .is_none_or(|(prev_range, prev_vma)| {
                    // Enforce gap between stack and other preceding non-stack mappings.
                    // Either the previous mapping is also a stack mapping w/ some access flags
                    // or the previous mapping is far enough from the fault address
                    (prev_vma.flags().contains(VmFlags::VM_GROWSDOWN)
                        && !(prev_vma.flags() & VmFlags::VM_ACCESS_FLAGS).is_empty())
                        || fault_addr - prev_range.end >= Vmem::<Platform, ALIGN>::STACK_GUARD_GAP
                })
            {
                return Err(PageFaultError::AllocationFailed);
            }
            let Some(range) = PageRange::new(fault_addr, start) else {
                unreachable!()
            };
            if let Err(err) = unsafe {
                vmem.insert_mapping(
                    range,
                    vma,
                    false,
                    crate::platform::page_mgmt::FixedAddressBehavior::NoReplace,
                )
            } {
                unimplemented!("failed to grow stack: {:?}", err)
            }
        }

        if <Platform as VmemPageFaultHandler>::access_error(error_code, vma.flags()) {
            return Err(PageFaultError::AccessError("access error"));
        }

        unsafe {
            vmem.platform
                .handle_page_fault(fault_addr, vma.flags(), error_code)
        }
    }
}
