// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module implements a virtual memory manager `Vmem` that manages virtual address spaces
//! backed by a memory [backend](PageManagementProvider). It provides functionality to create, remove, resize,
//! move, and protect memory mappings within a process's virtual address space.

use core::ops::Range;

use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

use crate::platform::PageManagementProvider;
use crate::platform::RawConstPointer;
use crate::platform::page_mgmt::AllocationError;
use crate::platform::page_mgmt::DeallocationError;
use crate::platform::page_mgmt::FixedAddressBehavior;
use crate::platform::page_mgmt::MemoryRegionPermissions;

/// Diagnostic stderr writer for macOS debugging (no_std compatible).
/// Writes a formatted message to fd 2 (stderr) via raw syscall.
#[cfg(target_os = "macos")]
macro_rules! mm_diag {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut buf = [0u8; 512];
        let mut cursor = $crate::mm::linux::DiagCursor { buf: &mut buf, pos: 0 };
        let _ = write!(cursor, $($arg)*);
        let _ = write!(cursor, "\n");
        let len = cursor.pos;
        // Raw write(2, buf, len) syscall — macOS aarch64 syscall 0x2000004
        unsafe {
            core::arch::asm!(
                "mov x0, #2",       // fd = stderr
                "mov x1, {buf}",    // buf
                "mov x2, {len}",    // count
                "mov x16, #0x4",    // SYS_write (macOS: 0x2000000 | 4)
                "movk x16, #0x200, lsl #16",
                "svc #0x80",
                buf = in(reg) buf.as_ptr(),
                len = in(reg) len,
                out("x0") _,
                out("x1") _,
                out("x2") _,
                out("x16") _,
                clobber_abi("C"),
            );
        }
    }};
}

/// Helper for mm_diag! macro — a cursor over a fixed byte buffer.
#[cfg(target_os = "macos")]
pub struct DiagCursor<'a> {
    pub buf: &'a mut [u8],
    pub pos: usize,
}

#[cfg(target_os = "macos")]
impl core::fmt::Write for DiagCursor<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.pos;
        let to_copy = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        Ok(())
    }
}

/// Page size in bytes
pub const PAGE_SIZE: usize = 4096;

bitflags::bitflags! {
    /// Flags to describe the properties of a memory region.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VmFlags: u32 {
        /// Readable.
        const VM_READ = 1 << 0;
        /// Writable.
        const VM_WRITE = 1 << 1;
        /// Executable.
        const VM_EXEC = 1 << 2;
        /// Shared between processes.
        const VM_SHARED = 1 << 3;

        /* limits for mprotect() etc */
        /// `mprotect` can turn on VM_READ
        const VM_MAYREAD = 1 << 4;
        /// `mprotect` can turn on VM_WRITE
        const VM_MAYWRITE = 1 << 5;
        /// `mprotect` can turn on VM_EXEC
        const VM_MAYEXEC = 1 << 6;
        /// `mprotect` can turn on VM_SHARED
        const VM_MAYSHARE = 1 << 7;

        /// The area can grow downward upon page fault.
        const VM_GROWSDOWN = 1 << 8;

        const VM_ACCESS_FLAGS = Self::VM_READ.bits()
            | Self::VM_WRITE.bits()
            | Self::VM_EXEC.bits();
        const VM_MAY_ACCESS_FLAGS = Self::VM_MAYREAD.bits()
            | Self::VM_MAYWRITE.bits()
            | Self::VM_MAYEXEC.bits();
    }
}

impl VmFlags {
    /// Compute the default `VM_MAY*` and `VM_SHARED` flags for a mapping.
    ///
    /// Write permission (`VM_MAYWRITE`) is restricted only for shared **file-backed**
    /// mappings, because writes cannot be propagated back to the underlying file.
    pub(super) fn may_flags_for_mapping(shared: bool, file_backed: bool) -> Self {
        let restrict_write = shared && file_backed;
        let may = if restrict_write {
            Self::VM_MAY_ACCESS_FLAGS & !Self::VM_MAYWRITE
        } else {
            Self::VM_MAY_ACCESS_FLAGS
        };
        let shared_flag = if shared {
            Self::VM_SHARED
        } else {
            Self::empty()
        };
        may | shared_flag
    }
}

impl From<MemoryRegionPermissions> for VmFlags {
    fn from(value: MemoryRegionPermissions) -> Self {
        let mut flags = VmFlags::empty();
        flags.set(
            VmFlags::VM_READ,
            value.contains(MemoryRegionPermissions::READ),
        );
        flags.set(
            VmFlags::VM_WRITE,
            value.contains(MemoryRegionPermissions::WRITE),
        );
        flags.set(
            VmFlags::VM_EXEC,
            value.contains(MemoryRegionPermissions::EXEC),
        );
        if value.contains(MemoryRegionPermissions::SHARED) {
            unimplemented!("SHARED permission is not supported yet");
        }
        flags
    }
}

impl From<VmFlags> for MemoryRegionPermissions {
    fn from(value: VmFlags) -> Self {
        let mut flags = MemoryRegionPermissions::empty();
        flags.set(
            MemoryRegionPermissions::READ,
            value.contains(VmFlags::VM_READ),
        );
        flags.set(
            MemoryRegionPermissions::WRITE,
            value.contains(VmFlags::VM_WRITE),
        );
        flags.set(
            MemoryRegionPermissions::EXEC,
            value.contains(VmFlags::VM_EXEC),
        );
        flags.set(
            MemoryRegionPermissions::SHARED,
            value.contains(VmFlags::VM_SHARED),
        );
        flags
    }
}

const DEFAULT_RESERVED_SPACE_SIZE: usize = 0x100_0000; // 16 MiB

bitflags::bitflags! {
    /// Options for page creation.
    pub struct CreatePagesFlags: u8 {
        /// Force the mapping to be created at the given address, resulting in any
        /// existing overlapping mappings being removed.
        const FIXED_ADDR     = 1 << 0;
        /// The mapping is used for stack.
        const IS_STACK       = 1 << 1;
        /// Populate the pages immediately.
        const POPULATE_PAGES_IMMEDIATELY = 1 << 2;
        /// Ensure there is more space (i.e., `DEFAULT_RESERVED_SPACE_SIZE`) after the
        /// mapping so that user can grow the mapping later.
        const ENSURE_SPACE_AFTER = 1 << 3;
        // This flag indicates that the mapping is backed by a file.
        const MAP_FILE = 1 << 4;
        /// When combined with [`Self::FIXED_ADDR`], fail with [`AllocationError::AddressInUse`]
        /// if any part of the range is already mapped, instead of replacing existing mappings.
        const NOREPLACE = 1 << 5;
        /// The mapping is shared.
        const SHARED = 1 << 6;
    }
}

/// A non-empty range of page-aligned addresses
#[derive(Clone, Copy)]
pub struct PageRange<const ALIGN: usize> {
    /// Start page of the range.
    pub start: usize,
    /// End page of the range.
    pub end: usize,
}

impl<const ALIGN: usize> From<PageRange<ALIGN>> for Range<usize> {
    fn from(range: PageRange<ALIGN>) -> Self {
        range.start..range.end
    }
}

impl<const ALIGN: usize> IntoIterator for PageRange<ALIGN> {
    type Item = usize;
    type IntoIter = core::iter::StepBy<Range<usize>>;

    fn into_iter(self) -> Self::IntoIter {
        (self.start..self.end).step_by(ALIGN)
    }
}

impl<const ALIGN: usize> PageRange<ALIGN> {
    /// Create a new [`PageRange`].
    ///
    /// Returns `None` if the range is not `ALIGN`-aligned or empty.
    pub fn new(start: usize, end: usize) -> Option<Self> {
        if !start.is_multiple_of(ALIGN) || !end.is_multiple_of(ALIGN) {
            return None;
        }
        if start >= end {
            return None;
        }
        Some(Self { start, end })
    }

    /// Get the size of this `ALIGN`-aligned range
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the range is empty or not
    ///
    /// Note this range is never empty.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Get the start address and length of this range as a tuple.
    #[allow(
        clippy::missing_panics_doc,
        reason = "This function should not fail as the range is guaranteed to be non-empty and aligned."
    )]
    pub fn start_and_length(&self) -> (NonZeroAddress<ALIGN>, NonZeroPageSize<ALIGN>) {
        (
            NonZeroAddress::new(self.start).unwrap(),
            NonZeroPageSize::new(self.len()).unwrap(),
        )
    }
}

/// A non-zero `ALIGN`-aligned size in bytes.
#[derive(Clone, Copy)]
pub struct NonZeroPageSize<const ALIGN: usize> {
    size: usize,
}

impl<const ALIGN: usize> NonZeroPageSize<ALIGN> {
    /// Create a new non-zero `ALIGN`-aligned size.
    ///
    /// Returns `None` if the size is zero or not `ALIGN`-aligned.
    pub fn new(size: usize) -> Option<Self> {
        if size == 0 || !size.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self { size })
    }

    /// Get the size
    #[inline]
    pub fn as_usize(self) -> usize {
        self.size
    }
}

impl<const ALIGN: usize> core::ops::Add<usize> for NonZeroPageSize<ALIGN> {
    type Output = Option<Self>;

    fn add(self, rhs: usize) -> Self::Output {
        NonZeroPageSize::new(self.size + rhs)
    }
}

/// A non-zero address that is `ALIGN`-aligned.
#[derive(Clone, Copy)]
pub struct NonZeroAddress<const ALIGN: usize>(usize);

impl<const ALIGN: usize> NonZeroAddress<ALIGN> {
    /// Create a new `NonZeroAddress`, if the address is non-zero and aligned.
    pub fn new(address: usize) -> Option<Self> {
        if address == 0 || !address.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self(address))
    }

    /// Get the address
    #[inline]
    pub fn as_usize(self) -> usize {
        self.0
    }
}

/// Virtual memory area
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VmArea {
    /// Flags describing the properties of the memory region.
    flags: VmFlags,
    /// Whether this area is backed by a file
    is_file_backed: bool,
}

impl VmArea {
    /// Get the [flags](`VmFlags`) of this memory area.
    #[inline]
    pub(super) fn flags(self) -> VmFlags {
        self.flags
    }

    /// Check if this area is backed by a file.
    #[inline]
    pub(super) fn is_file_backed(self) -> bool {
        self.is_file_backed
    }

    /// Create a new [`VmArea`] with the given flags.
    #[inline]
    pub(super) fn new(flags: VmFlags, is_file_backed: bool) -> Self {
        Self {
            flags,
            is_file_backed,
        }
    }
}

/// Virtual Memory Manager
///
/// This struct mantains the virtual memory ranges backed by a memory [backend](PageManagementProvider).
/// Each range needs to be `ALIGN`-aligned.
pub(super) struct Vmem<Platform: PageManagementProvider<ALIGN> + 'static, const ALIGN: usize> {
    /// Memory backend that provides the actual memory.
    pub(super) platform: &'static Platform,
    /// Current program break address.
    pub(super) brk: usize,
    /// End of the reserved region above brk for future brk growth.
    ///
    /// When `brk` is set via [`super::PageManager::set_initial_brk`], we reserve a region
    /// `[brk_aligned..brk_reserved_end)` so that the top-down allocator in
    /// [`Vmem::get_unmmaped_area`] will not place hint-based anonymous mmaps in this region.
    /// This prevents the common failure mode where anonymous mmaps fill the gap right above
    /// brk, blocking brk growth (which manifests as `malloc(): corrupted top size`).
    ///
    /// This is a virtual reservation only — no platform allocation or VMA entry is created.
    /// The `brk()` syscall handler ignores this field and grows brk normally.
    pub(super) brk_reserved_end: usize,
    /// Virtual memory areas.
    vmas: RangeMap<usize, VmArea>,
}

impl<Platform: PageManagementProvider<ALIGN> + 'static, const ALIGN: usize> Vmem<Platform, ALIGN> {
    pub(super) const STACK_GUARD_GAP: usize = 256 << 12;

    /// Create a new [`Vmem`] instance with the given memory [backend](PageManagementProvider).
    pub(super) fn new(platform: &'static Platform) -> Self {
        let mut vmem = Self {
            vmas: RangeMap::new(),
            brk: 0,
            brk_reserved_end: 0,
            platform,
        };
        for each in platform.reserved_pages() {
            assert!(
                each.start % ALIGN == 0 && each.end % ALIGN == 0,
                "Vmem: reserved range is not aligned to {ALIGN} bytes"
            );
            vmem.vmas.insert(
                each.start..each.end,
                VmArea {
                    flags: VmFlags::empty(),
                    is_file_backed: false,
                },
            );
        }
        vmem
    }

    /// Gets an iterator over all pairs of ([`Range<usize>`], [`VmArea`]),
    /// ordered by key range.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.iter()
    }

    /// Insert an already-allocated region (e.g., via CoW) without calling the platform allocator.
    ///
    /// Any existing tracked mappings that overlap `range` are silently removed from tracking
    /// (without calling the platform deallocator) before inserting. Use [`Self::overlapping`] to
    /// check for overlap before running this if needed.
    pub(super) fn register_existing_mapping_overwrite(
        &mut self,
        range: PageRange<ALIGN>,
        vma: VmArea,
    ) {
        self.vmas.insert(range.into(), vma);
    }

    /// Evict pre-existing reserved-pages VMAs from the brk zone.
    ///
    /// `reserved_pages()` inserts host VM regions as VMAs with `VmFlags::empty()`
    /// before the brk zone is established. If ASLR places the guest binary such
    /// that its brk zone overlaps a host reservation, `brk()` will fail because
    /// it finds an existing VMA.
    ///
    /// This method removes those stale tracking entries from
    /// `[brk_start..brk_reserved_end)`. It does NOT call
    /// `platform.deallocate_pages()` because these are host-owned regions, not
    /// guest allocations. The `brk()` handler will later overwrite them with
    /// `FIXED_ADDR | Replace` semantics.
    pub(super) fn evict_reserved_from_brk_zone(&mut self) {
        if self.brk_reserved_end == 0 {
            return;
        }
        let brk_start = self.brk.next_multiple_of(ALIGN);
        let brk_end = self.brk_reserved_end;

        // Collect ranges to remove (can't mutate while iterating).
        let to_remove: Vec<Range<usize>> = self
            .vmas
            .overlapping(brk_start..brk_end)
            .filter(|(_, vma)| vma.flags() == VmFlags::empty() && !vma.is_file_backed())
            .map(|(range, _)| range.clone())
            .collect();

        for range in to_remove {
            self.vmas.remove(range);
        }
    }

    /// Gets an iterator over all the stored ranges that are
    /// either partially or completely overlapped by the given range.
    pub(super) fn overlapping(
        &self,
        range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.overlapping(range)
    }

    /// Remove a range from its virtual address space, if all or any of it was present.
    ///
    /// If the range to be removed _partially_ overlaps any ranges, then those ranges will
    /// be contracted to no longer cover the removed range.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub(super) unsafe fn remove_mapping(
        &mut self,
        range: PageRange<ALIGN>,
    ) -> Result<(), VmemUnmapError> {
        unsafe {
            self.platform
                .deallocate_pages(range.into())
                .map_err(VmemUnmapError::UnmapError)?;
        }
        self.vmas.remove(range.into());
        Ok(())
    }

    /// Reset pages without removing its mapping (similar to Linux `madvise` with
    /// `MADV_DONTNEED` or `MADV_FREE`).
    ///
    /// If `anonymous_only` is true and any part of the range is non‑anonymous (i.e., file‑backed),
    /// returns `Err(VmemResetError::FileBacked)`.
    ///
    /// The current implementation effectively re-inserts the mapping with the same
    /// `VmArea` properties, which will cause the pages to be unmapped and mapped again.
    ///
    /// # Panics
    ///
    /// File-backed mapping is not supported yet.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory contents in the affected region are no longer accessed or
    /// relied upon. Any pointers or references to the previous contents become invalid.
    pub(super) unsafe fn reset_pages(
        &mut self,
        range: PageRange<ALIGN>,
        anonymous_only: bool,
    ) -> Result<(), VmemResetError> {
        let range: Range<usize> = range.into();
        // Any unmapped regions in the original range will result in this function returning `DeallocationError::AlreadyUnallocated`
        // while still resetting all of the existing vmas in the range.
        let unmapped_error = self.vmas.gaps(&range).next().is_some();
        let overlapping_ranges: Vec<(Range<usize>, VmArea)> = self
            .overlapping(range.clone())
            .map(|(r, vma)| (r.clone(), *vma))
            .collect();
        for (r, vma) in overlapping_ranges {
            if vma.is_file_backed() {
                if anonymous_only {
                    return Err(VmemResetError::FileBacked);
                }
                unimplemented!("resetting file-backed mappings is not supported yet");
            }
            let start = r.start.max(range.start);
            let end = r.end.min(range.end);
            let new_range = PageRange::new(start, end).unwrap();
            unsafe { self.insert_mapping(new_range, vma, false, FixedAddressBehavior::Replace) }
                .expect("failed to reset pages");
        }
        if unmapped_error {
            Err(VmemResetError::AlreadyUnallocated)
        } else {
            Ok(())
        }
    }

    /// Insert a range to its virtual address space.
    ///
    /// If the inserted range partially or completely overlaps any
    /// existing range in the map, then the existing range (or ranges) will be
    /// partially or completely replaced by the inserted range.
    ///
    /// If the inserted range either overlaps or is immediately adjacent
    /// any existing range _mapping to the same value_, then the ranges
    /// will be coalesced into a single contiguous range.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is not used by any other (i.e., safe
    /// to unmap all overlapping mappings if any).
    pub(super) unsafe fn insert_mapping(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        vma: VmArea,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let (start, end) = (suggested_range.start, suggested_range.end);
        if start < Platform::TASK_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if end > Platform::TASK_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        let platform_fixed_address_behavior = match fixed_address_behavior {
            FixedAddressBehavior::Hint => FixedAddressBehavior::Hint,
            FixedAddressBehavior::NoReplace => {
                // Ensure there are no mappings managed by us.
                if self.vmas.overlaps(&(start..end)) {
                    return Err(AllocationError::AddressInUse);
                }
                FixedAddressBehavior::NoReplace
            }
            FixedAddressBehavior::Replace => {
                if self.vmas.overlaps(&(start..end)) {
                    if self.vmas.gaps(&(start..end)).next().is_some() {
                        // The range is partially overlapping with existing
                        // mappings. We remove the overlapping portions first,
                        // then allocate the full range as NoReplace.
                        let overlapping: Vec<Range<usize>> = self
                            .vmas
                            .overlapping(&(start..end))
                            .map(|(r, _)| {
                                // Clamp to our target range
                                r.start.max(start)..r.end.min(end)
                            })
                            .collect();
                        for r in &overlapping {
                            unsafe {
                                match self.platform.deallocate_pages(r.clone()) {
                                    // Not a real error — pages may not have been
                                    // populated yet (e.g. lazy allocation).
                                    Ok(()) | Err(DeallocationError::AlreadyUnallocated) => {}
                                    Err(_) => return Err(AllocationError::OutOfMemory),
                                }
                            }
                        }
                        self.vmas.remove(start..end);
                        FixedAddressBehavior::NoReplace
                    } else {
                        FixedAddressBehavior::Replace
                    }
                } else {
                    // There are no mappings managed by us, so just treat this
                    // as NoReplace.
                    FixedAddressBehavior::NoReplace
                }
            }
        };
        let permissions: u8 = vma
            .flags
            .intersection(VmFlags::VM_ACCESS_FLAGS)
            .bits()
            .try_into()
            .unwrap();
        let max_permissions: u8 = (vma.flags.intersection(VmFlags::VM_MAY_ACCESS_FLAGS).bits()
            >> 4)
            .try_into()
            .unwrap();
        // The `max_permissions` is tracked by `VMem::protect_mapping` and thus doesn't need to be
        // passed to `allocate_pages`.
        let _ = max_permissions;
        let can_grow_down = vma.flags.contains(VmFlags::VM_GROWSDOWN);
        let permissions_enum = MemoryRegionPermissions::from_bits(permissions).unwrap();
        let alloc_result = self.platform.allocate_pages(
            suggested_range.into(),
            permissions_enum,
            can_grow_down,
            populate_pages_immediately,
            platform_fixed_address_behavior,
        );
        #[cfg(target_os = "macos")]
        mm_diag!("[insert_mapping] allocate_pages(range={:#x}..{:#x}, behavior={:?}) → ok={}",
            suggested_range.start, suggested_range.end,
            platform_fixed_address_behavior,
            alloc_result.is_ok());
        // Note: The macOS platform layer retries internally (mmap with hint,
        // mmap with NULL, mach_vm_allocate), so no additional retry is needed
        // here.  On Linux, the hint is almost always accepted.
        let ret = alloc_result.map_err(|err| match err {
            AllocationError::AddressInUse => AllocationError::AddressInUseByPlatform,
            other => other,
        })?;
        let mut new_start = ret.as_usize();
        #[cfg(target_os = "macos")]
        mm_diag!("[insert_mapping] platform returned addr={:#x}", new_start);

        // On platforms where the host kernel may ignore mmap hints (e.g. macOS),
        // the platform can return an address different from what get_unmmaped_area
        // chose.  If the returned address falls inside the brk reservation, future
        // brk() calls will fail with ENOMEM.  Detect this and retry with MAP_FIXED
        // at an address that is known-free in the VMA tree and outside the brk zone.
        if matches!(fixed_address_behavior, FixedAddressBehavior::Hint) && self.brk_reserved_end > 0
        {
            let brk_start = self.brk.next_multiple_of(ALIGN);
            let new_end_tentative = new_start + suggested_range.len();
            if new_start < self.brk_reserved_end && new_end_tentative > brk_start {
                #[cfg(target_os = "macos")]
                mm_diag!("[insert_mapping] brk-zone conflict: addr={:#x}..{:#x} brk={:#x}..{:#x}",
                    new_start, new_end_tentative, brk_start, self.brk_reserved_end);
                // The platform placed the mapping inside the brk reservation.
                // Deallocate it and retry at a safe address, even if the host
                // returned the exact hint we asked for: the chosen hint itself
                // may already be inside the reserved brk-growth window.
                let bad_range = new_start..new_end_tentative;
                unsafe {
                    // Ignore AlreadyUnallocated — platform may not have fully
                    // committed pages yet.
                    let _ = self.platform.deallocate_pages(bad_range);
                }
                let size = suggested_range.len();
                let safe_addr = self.find_free_above(self.brk_reserved_end, size);
                #[cfg(target_os = "macos")]
                mm_diag!("[insert_mapping] brk-zone safe_addr: {:?}",
                    safe_addr.map(|a| a as u64));
                let safe_addr = match safe_addr {
                    Some(a) => a,
                    None => return Err(AllocationError::OutOfMemory),
                };
                let safe_range = safe_addr..(safe_addr + size);
                let retry_ret = self
                    .platform
                    .allocate_pages(
                        safe_range,
                        permissions_enum,
                        can_grow_down,
                        populate_pages_immediately,
                        FixedAddressBehavior::NoReplace,
                    )
                    .map_err(|err| match err {
                        AllocationError::AddressInUse => AllocationError::AddressInUseByPlatform,
                        other => other,
                    })?;
                new_start = retry_ret.as_usize();
            }
        }

        let new_end = new_start + suggested_range.len();
        self.vmas.insert(new_start..new_end, vma);
        debug_assert!(new_start >= Platform::TASK_ADDR_MIN);
        debug_assert!(new_end <= Platform::TASK_ADDR_MAX);
        Ok(Platform::RawMutPointer::from_usize(new_start))
    }

    /// Create a new mapping in the virtual address space.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// Return `Some(new_addr)` if the mapping is created successfully.
    /// The returned address is `ALIGN`-aligned.
    ///
    /// # Fixed Address Behavior
    ///
    /// - [`CreatePagesFlags::FIXED_ADDR`] alone: Forces allocation at the exact address, replacing
    ///   any existing overlapping mappings. Caller must ensure overlapping mappings are not in use.
    /// - [`CreatePagesFlags::FIXED_ADDR`] with [`CreatePagesFlags::NOREPLACE`]: Forces allocation at
    ///   the exact address, but fails with [`AllocationError::AddressInUse`] if any part of the
    ///   range is already mapped. This is safe to use without checking for existing mappings first.
    /// - Without [`CreatePagesFlags::FIXED_ADDR`], the address is treated as a hint.
    ///
    /// Note: `NOREPLACE` error responses (`AddressInUse` / `EEXIST`) can be used to probe memory
    /// layout. This matches Linux kernel behavior for `MAP_FIXED_NOREPLACE`.
    ///
    /// # Safety
    ///
    /// When using [`CreatePagesFlags::FIXED_ADDR`] without [`CreatePagesFlags::NOREPLACE`], the
    /// caller must ensure any overlapping mappings are not used by any other code, as they will be
    /// unmapped.
    pub(super) unsafe fn create_mapping(
        &mut self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        vma: VmArea,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        #[cfg(target_os = "macos")]
        mm_diag!("[create_mapping] hint={:#x} len={:#x} flags={:#x}",
            suggested_address.map_or(0, |a| a.0), length.as_usize(), flags.bits());
        let total_length = (length
            + if flags.contains(CreatePagesFlags::ENSURE_SPACE_AFTER) {
                DEFAULT_RESERVED_SPACE_SIZE
            } else {
                0
            })
        .unwrap();
        let is_fixed = flags.contains(CreatePagesFlags::FIXED_ADDR);
        let new_addr = self.get_unmmaped_area(suggested_address, total_length, is_fixed);

        let new_addr = match new_addr {
            Some(addr) => {
                #[cfg(target_os = "macos")]
                mm_diag!("[create_mapping] get_unmmaped_area → {:#x}", addr);
                addr
            }
            None if is_fixed => {
                #[cfg(target_os = "macos")]
                mm_diag!("[create_mapping] FAIL: fixed addr, no area found");
                return Err(AllocationError::OutOfMemory);
            }
            None => {
                #[cfg(target_os = "macos")]
                mm_diag!("[create_mapping] get_unmmaped_area → None, fallback to TASK_ADDR_MIN={:#x}",
                    Platform::TASK_ADDR_MIN);
                // The VMA-tree-based search found no suitable gap.  On platforms
                // like macOS, the host kernel aggressively ignores mmap hints and
                // finds gaps between existing host mappings on its own.  Rather
                // than failing, delegate to the platform with a dummy hint and let
                // it allocate wherever it can, then track the result.
                //
                // Use TASK_ADDR_MIN as the hint — the platform is free to ignore
                // it, and the brk-zone retry logic in insert_mapping will
                // re-locate if the kernel places it in the reservation.
                Platform::TASK_ADDR_MIN
            }
        };

        // new_addr must be ALIGN aligned
        let new_range = PageRange::new(new_addr, new_addr + length.as_usize()).unwrap();
        #[cfg(target_os = "macos")]
        mm_diag!("[create_mapping] calling insert_mapping range={:#x}..{:#x}",
            new_range.start, new_range.end);
        let result = unsafe {
            self.insert_mapping(
                new_range,
                vma,
                flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY),
                if is_fixed {
                    if flags.contains(CreatePagesFlags::NOREPLACE) {
                        FixedAddressBehavior::NoReplace
                    } else {
                        FixedAddressBehavior::Replace
                    }
                } else {
                    FixedAddressBehavior::Hint
                },
            )
        };
        #[cfg(target_os = "macos")]
        {
            let ok = result.is_ok();
            let addr = result.as_ref().map(|p| p.as_usize()).unwrap_or(0);
            mm_diag!("[create_mapping] insert_mapping → ok={} addr={:#x}", ok, addr);
        }
        result
    }

    /// Resize a range in the virtual address space.
    /// Shrink the range if it is larger than `new_size`.
    /// Enlarge the range if it is smaller than `new_size` and will not overlap with
    /// next mapping after the expansion.
    ///
    /// It fails if it resizes more than one mapping or needs to split the current mapping
    /// (due to enlarging).
    ///
    /// See <https://elixir.bootlin.com/linux/v5.19.17/source/mm/mremap.c#L886> for reference.
    ///
    /// # Safety
    ///
    /// If it shrinks, the caller must ensure that the unmapped memory region is not used by any other.
    pub(super) unsafe fn resize_mapping(
        &mut self,
        range: PageRange<ALIGN>,
        new_size: NonZeroPageSize<ALIGN>,
    ) -> Result<(), VmemResizeError> {
        let range = range.start..range.end;
        // `cur_range` contains `range.start`
        let (cur_range, cur_vma) = self
            .vmas
            .get_key_value(&range.start)
            .ok_or(VmemResizeError::NotExist(range.start))?;

        let new_end = range.start + new_size.as_usize();
        match new_end.cmp(&range.end) {
            core::cmp::Ordering::Equal => {
                // no change
                return Ok(());
            }
            core::cmp::Ordering::Less => {
                // shrink
                let range = PageRange::new(new_end, range.end).unwrap();
                unsafe { self.remove_mapping(range) }.unwrap();
                return Ok(());
            }
            core::cmp::Ordering::Greater => {}
        }

        // grow
        if range.end > cur_range.end {
            // we can't remap across vm area boundaries
            return Err(VmemResizeError::InvalidAddr {
                range: cur_range.clone(),
                addr: range.end,
            });
        }

        if range.end == cur_range.end {
            // expand the current range
            let r = range.end..new_end;
            if self.vmas.overlaps(&r) {
                return Err(VmemResizeError::RangeOccupied(r));
            }
            if cur_vma.is_file_backed() {
                unimplemented!("file-backed mapping expansion is not supported yet");
            }
            let range = PageRange::new(range.end, new_end).unwrap();
            // Try to extend the mapping. Although we checked that there are no
            // litebox mappings in this range, this may fail if there are
            // platform mappings in the way.
            match unsafe {
                self.insert_mapping(range, *cur_vma, false, FixedAddressBehavior::NoReplace)
            } {
                Ok(_) => {}
                Err(AllocationError::OutOfMemory) => return Err(VmemResizeError::OutOfMemory),
                Err(
                    AllocationError::AddressInUse
                    | AllocationError::AddressInUseByPlatform
                    | AllocationError::AddressPartiallyInUse,
                ) => return Err(VmemResizeError::RangeOccupied(range.into())),
                Err(
                    AllocationError::Unaligned
                    | AllocationError::BelowMinAddress
                    | AllocationError::AboveMaxAddress,
                ) => unreachable!(),
            }
            return Ok(());
        }

        // has to split the current range and move it to somewhere else
        Err(VmemResizeError::RangeOccupied(range.end..cur_range.end))
    }

    /// Move a range from `old_range` to `suggested_new_range`.
    /// Use it together with [`Vmem::resize_mapping`] to achieve `mremap`.
    ///
    /// The `suggested_new_range.start` is used as a hint for the new address.
    /// If it is zero, kernel will choose a new suitable address freely.
    ///
    /// Returns `Some(new_addr)` if the range is moved successfully
    /// Otherwise, returns `None`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the given `range` is safe to be unmapped.
    ///
    /// # Panics
    ///
    /// Panics if the size of `suggested_new_range` is smaller than the size of `old_range`.
    /// Panics if the `old_range` is not covered by exactly one mapping.
    pub(super) unsafe fn move_mappings(
        &mut self,
        old_range: PageRange<ALIGN>,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        new_size: NonZeroPageSize<ALIGN>,
    ) -> Result<Platform::RawMutPointer<u8>, VmemMoveError> {
        assert!(new_size.as_usize() >= old_range.len());

        // Check if the given range is covered by exactly one mapping
        let (cur_range, vma) = self
            .vmas
            .get_key_value(&old_range.start)
            .expect("VMEM: range not found");
        assert!(cur_range.contains(&(old_range.end - 1)));

        if vma.is_file_backed() {
            unimplemented!("file-backed mapping move is not supported yet");
        }
        let new_addr = self
            .get_unmmaped_area(suggested_new_address, new_size, false)
            .ok_or(VmemMoveError::OutOfMemory)?;
        let new_range = PageRange::<ALIGN>::new(new_addr, new_addr + new_size.as_usize()).unwrap();
        let new_addr = unsafe {
            self.platform
                .remap_pages(old_range.into(), new_range.into(), vma.flags.into())
        }
        .map_err(VmemMoveError::RemapError)?;

        let new_start = new_addr.as_usize();
        let new_end = new_start + new_size.as_usize();
        self.vmas.insert(new_start..new_end, *vma);
        self.vmas.remove(old_range.into());
        Ok(new_addr)
    }

    /// Change the permissions ([`VmFlags::VM_ACCESS_FLAGS`]) of a range in the virtual address space.
    ///
    /// See <https://elixir.bootlin.com/linux/v5.19.17/source/mm/mprotect.c#L617> for reference.
    ///
    /// # Safety
    ///
    /// The caller must ensure it is safe to change the permissions of the given range, e.g., no more
    /// write access to the range if it is changed to read-only.
    pub(super) unsafe fn protect_mapping(
        &mut self,
        range: PageRange<ALIGN>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        // `MemoryRegionPermissions` is a subset of `VmFlags` and we only change the access flags
        let flags =
            VmFlags::from_bits(u32::from(permissions.bits())).unwrap() & VmFlags::VM_ACCESS_FLAGS;
        let range = range.start..range.end;
        let mut mappings_to_change = Vec::new();
        for (r, vma) in self.vmas.overlapping(range.clone()) {
            mappings_to_change.push((r.start, r.end, *vma));
        }
        if mappings_to_change.is_empty() {
            return Err(VmemProtectError::InvalidRange(range));
        }

        for (start, end, vma) in mappings_to_change {
            if vma.flags & VmFlags::VM_ACCESS_FLAGS == flags {
                continue;
            }
            // flags >> 4 shift VM_MAY% in place of VM_%
            // turning on VM_% requires VM_MAY%
            if (!(vma.flags.bits() >> 4) & flags.bits()) & VmFlags::VM_ACCESS_FLAGS.bits() != 0 {
                return Err(VmemProtectError::NoAccess {
                    old: vma.flags,
                    new: flags,
                });
            }

            self.vmas.remove(start..end);
            let intersection = range.start.max(start)..range.end.min(end);
            // split r into three parts: before, intersection, and after
            let before = start..intersection.start;
            let after = intersection.end..end;

            let new_flags = (vma.flags & !VmFlags::VM_ACCESS_FLAGS) | flags;
            // `intersection` is page aligned.
            unsafe {
                self.platform
                    .update_permissions(intersection.clone(), permissions)
            }
            .map_err(|e| {
                // restore the original mapping
                self.vmas.insert(start..end, vma);
                VmemProtectError::ProtectError(e)
            })?;

            self.vmas.insert(
                intersection,
                VmArea {
                    flags: new_flags,
                    is_file_backed: vma.is_file_backed,
                },
            );
            if !before.is_empty() {
                self.vmas.insert(before, vma);
            }
            if !after.is_empty() {
                self.vmas.insert(after, vma);
            }
        }

        Ok(())
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
    /// `perm` is the permissions to set for the created pages.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    pub(super) unsafe fn create_pages(
        &mut self,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        perms: MemoryRegionPermissions,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let shared = flags.contains(CreatePagesFlags::SHARED);
        let file_backed = flags.contains(CreatePagesFlags::MAP_FILE);
        unsafe {
            self.create_mapping(
                suggested_new_address,
                length,
                VmArea::new(
                    VmFlags::from(perms)
                        | VmFlags::may_flags_for_mapping(shared, file_backed)
                        | if flags.contains(CreatePagesFlags::IS_STACK) {
                            VmFlags::VM_GROWSDOWN
                        } else {
                            VmFlags::empty()
                        },
                    flags.contains(CreatePagesFlags::MAP_FILE),
                ),
                flags,
            )
        }
        .map_err(MappingError::MapError)
    }

    /// Get the memory permissions of a given address range.
    ///
    /// `page_range` specifies the range of pages to check the memory permissions.
    /// This function returns `MemoryRegionPermissions` only if the range is valid.
    pub(super) fn get_memory_permissions(
        &self,
        page_range: PageRange<ALIGN>,
    ) -> Option<MemoryRegionPermissions> {
        let (range_start, range_end) = (page_range.start, page_range.end);
        let range: core::ops::Range<usize> = page_range.into();
        if let Some(iter) = self.overlapping(range).next() {
            if iter.0.start > range_start || iter.0.end < range_end {
                // partial overlap implies that the given range contains unmapped pages or
                // consists of memory pages with different permissions.
                return None;
            }
            let vmflags = iter.1.flags();
            Some(vmflags.into())
        } else {
            None
        }
    }

    /// Find a free (unoccupied) region of at least `size` bytes at or above `min_addr`.
    ///
    /// Scans gaps in the VMA tree from `min_addr` upward, also respecting the brk
    /// reservation. Returns `None` if no suitable gap exists below `TASK_ADDR_MAX`.
    ///
    /// This is used to compute mmap hints that are known-free in the vmem layer,
    /// which matters on platforms (e.g. macOS) where the host kernel may ignore
    /// hints that fall inside pre-existing host-side mappings.
    pub(super) fn find_free_above(&self, min_addr: usize, size: usize) -> Option<usize> {
        let min_addr = min_addr.next_multiple_of(ALIGN);
        if size == 0 || min_addr.checked_add(size)? > Platform::TASK_ADDR_MAX {
            return None;
        }
        let outer = min_addr..Platform::TASK_ADDR_MAX;
        for gap in self.vmas.gaps(&outer) {
            let start = gap.start.next_multiple_of(ALIGN);
            if let Some(end) = start.checked_add(size)
                && end <= gap.end
                && !self.range_is_occupied(&(start..end))
            {
                return Some(start);
            }
        }
        None
    }

    /*================================Internal Functions================================ */

    /// Check if the given range overlaps with any VMA **or** the brk reservation.
    fn range_is_occupied(&self, range: &Range<usize>) -> bool {
        if self.vmas.overlaps(range) {
            return true;
        }
        // Check overlap with brk reserved region [brk_aligned..brk_reserved_end)
        if self.brk_reserved_end > 0 {
            let brk_start = self.brk.next_multiple_of(ALIGN);
            if range.start < self.brk_reserved_end && range.end > brk_start {
                return true;
            }
        }
        false
    }

    /// Get an unmapped area in the virtual address space.
    /// `suggested_range` and `fixed_addr` are the hint address and MAP_FIXED flag respectively,
    /// similar to how `mmap` works.
    ///
    /// Returns `None` if no area found. Otherwise, returns the start address of a page-aligned area.
    fn get_unmmaped_area(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        fixed_addr: bool,
    ) -> Option<usize> {
        let size = length.as_usize();
        #[cfg(target_os = "macos")]
        mm_diag!("[get_unmmaped_area] size={:#x} fixed={} hint={:#x}",
            size, fixed_addr,
            suggested_address.map_or(0, |a| a.0));
        if size > Platform::TASK_ADDR_MAX {
            #[cfg(target_os = "macos")]
            mm_diag!("[get_unmmaped_area] FAIL: size > TASK_ADDR_MAX");
            return None;
        }
        if let Some(suggested_address) = suggested_address {
            if (Platform::TASK_ADDR_MAX - size) < suggested_address.0 {
                #[cfg(target_os = "macos")]
                mm_diag!("[get_unmmaped_area] FAIL: hint too high");
                return None;
            }
            if fixed_addr
                || !self.range_is_occupied(&(suggested_address.0..(suggested_address.0 + size)))
            {
                #[cfg(target_os = "macos")]
                mm_diag!("[get_unmmaped_area] OK: using hint {:#x}", suggested_address.0);
                return Some(suggested_address.0);
            }
            #[cfg(target_os = "macos")]
            mm_diag!("[get_unmmaped_area] hint {:#x} occupied, trying top-down", suggested_address.0);
        } else if fixed_addr {
            // MAP_FIXED with addr=0: return 0 so insert_mapping rejects it
            // via the TASK_ADDR_MIN check (BelowMinAddress → EPERM).
            return Some(0);
        }

        // top down
        // 1. check [last_end, TASK_SIZE_MAX)
        let (low_limit, high_limit) = (
            Platform::TASK_ADDR_MIN,
            Platform::TASK_ADDR_MAX - length.as_usize(),
        );
        debug_assert!(Platform::TASK_ADDR_MIN % ALIGN == 0);
        debug_assert!(Platform::TASK_ADDR_MAX % ALIGN == 0);
        let last_end = self.vmas.last_range_value().map_or(low_limit, |r| r.0.end);
        #[cfg(target_os = "macos")]
        mm_diag!("[get_unmmaped_area] top-down step1: last_end={:#x} high_limit={:#x}",
            last_end, high_limit);
        if last_end <= high_limit && !self.range_is_occupied(&(high_limit..high_limit + size)) {
            #[cfg(target_os = "macos")]
            mm_diag!("[get_unmmaped_area] OK: top-down step1 → {:#x}", high_limit);
            return Some(high_limit);
        }
        #[cfg(target_os = "macos")]
        {
            let brk_s = self.brk.next_multiple_of(ALIGN);
            mm_diag!("[get_unmmaped_area] step1 failed: brk={:#x} brk_reserved_end={:#x} brk_aligned={:#x}",
                self.brk, self.brk_reserved_end, brk_s);
            let occ = self.vmas.overlaps(&(high_limit..high_limit + size));
            mm_diag!("[get_unmmaped_area] step1: vma_overlaps={} range_is_occupied={}",
                occ, self.range_is_occupied(&(high_limit..high_limit + size)));
        }

        // 2. check gaps between ranges (top-down heuristic)
        //
        // NOTE: The loop below tries exactly one candidate per VMA (`vma.start - size`).
        // On macOS, `read_maps()` may insert many host-owned reserved VMAs that
        // fragment the VMA tree in ways where those single candidates all collide
        // with another VMA or the brk reservation, even though large gaps exist
        // between VMAs.  The bottom-up fallback (step 3) handles that case.
        let top_down_result = (|| {
            for (r, flags) in self.vmas.iter().rev() {
                let start = r.start.checked_sub(
                    size + if flags.flags.contains(VmFlags::VM_GROWSDOWN) {
                        // If it is a stack, we need to leave enough space for the stack to grow downwards.
                        Self::STACK_GUARD_GAP << 1
                    } else {
                        0
                    },
                )?;
                if start < low_limit {
                    return None;
                }
                if start > high_limit {
                    // Note we may have pre-allocated memory that are higher than `TASK_ADDR_MAX`
                    // (See [`Vmem::new`]) and thus `start` may be larger than `high_limit`.
                    continue;
                }
                if !self.range_is_occupied(&(start..start + size)) {
                    #[cfg(target_os = "macos")]
                    mm_diag!("[get_unmmaped_area] OK: top-down step2 → {:#x}", start);
                    return Some(start);
                }
            }
            None
        })();

        if top_down_result.is_some() {
            return top_down_result;
        }

        #[cfg(target_os = "macos")]
        mm_diag!("[get_unmmaped_area] top-down failed, trying bottom-up from {:#x}", low_limit);

        // 3. Bottom-up fallback: exhaustive gap search.
        //
        // The top-down heuristic only probes one address per VMA.  If all those
        // addresses happen to be occupied (common on macOS where host VM regions
        // are dense), we fall through to an exhaustive scan of every gap in the
        // VMA tree from `low_limit` upward.
        let result = self.find_free_above(low_limit, size);
        #[cfg(target_os = "macos")]
        mm_diag!("[get_unmmaped_area] bottom-up result: {:?}",
            result.map(|a| a as u64));
        result
    }
}

/// Error for removing mappings
#[derive(Error, Debug)]
pub enum VmemUnmapError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("failed to unmap pages: {0}")]
    UnmapError(#[from] crate::platform::page_mgmt::DeallocationError),
}

/// Error for resetting pages
#[derive(Error, Debug)]
pub enum VmemResetError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("provided range contains unallocated pages")]
    AlreadyUnallocated,
    #[error("reset file-backed mapping")]
    FileBacked,
}

/// Error for [`Vmem::resize_mapping`]
#[derive(Error, Debug)]
pub(super) enum VmemResizeError {
    #[error("no mapping containing the address {0:?}")]
    NotExist(usize),
    #[error("invalid address {addr:?} exceeds range {range:?}")]
    InvalidAddr { range: Range<usize>, addr: usize },
    #[error("range {0:?} is already (partially) occupied")]
    RangeOccupied(Range<usize>),
    #[error("out of memory")]
    OutOfMemory,
}

/// Error for moving mappings
#[derive(Error, Debug)]
pub enum VmemMoveError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("out of memory")]
    OutOfMemory,
    #[error("remap failed: {0}")]
    RemapError(#[from] crate::platform::page_mgmt::RemapError),
}

/// Error for protecting mappings
#[derive(Error, Debug)]
pub enum VmemProtectError {
    #[error("the range {0:?} is not aligned")]
    UnAligned(Range<usize>),
    #[error("the range {0:?} has no mapping memory")]
    InvalidRange(Range<usize>),
    #[error("failed to change permissions from {old:?} to {new:?}")]
    NoAccess { old: VmFlags, new: VmFlags },
    #[error("mprotect failed: {0}")]
    ProtectError(#[from] crate::platform::page_mgmt::PermissionUpdateError),
}

/// Error for creating mappings
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MappingError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("not enough memory")]
    OutOfMemory,

    // Errors from mapping a file
    #[error("bad file descriptor: {0}")]
    BadFD(i32),
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("file not open for reading")]
    NotForReading,

    #[error("mapping failed: {0}")]
    MapError(#[from] crate::platform::page_mgmt::AllocationError),
}

/// Enable [`super::PageManager`] to handle page faults if its platform implements this trait
pub trait VmemPageFaultHandler {
    /// Handle a page fault for the given address.
    ///
    /// # Safety
    ///
    /// This should only be called from the kernel page fault handler.
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: VmFlags,
        error_code: u64,
    ) -> Result<(), PageFaultError>;

    /// Check if it has access to the fault address.
    fn access_error(error_code: u64, flags: VmFlags) -> bool;
}

/// Error for handling page fault
#[derive(Error, Debug)]
pub enum PageFaultError {
    #[error("no access: {0}")]
    AccessError(&'static str),
    #[error("allocation failed")]
    AllocationFailed,
    #[error("given page is part of an already mapped huge page")]
    HugePage,
}
