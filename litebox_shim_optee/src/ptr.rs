// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Physical Pointer Abstraction with On-demand Mapping
//!
//! This module adds supports for accessing physical addresses (e.g., VTL0 or
//! normal-world physical memory) from LiteBox with on-demand mapping.
//! In the context of LVBS and OP-TEE, accessing physical memory is necessary
//! because VTL0 and VTL1 as well as normal world and secure world do not share
//! the same virtual address space, but they still have to share data through memory.
//! VTL1 and secure world receive physical addresses from VTL0 and normal world,
//! respectively, and they need to read from or write to those addresses.
//!
//! To simplify all these, we could persistently map the entire VTL0/normal-world
//! physical memory into VTL1/secure-world address space at once and just access them
//! through corresponding virtual addresses. However, this module does not take these
//! approaches due to scalability (e.g., how to deal with a system with terabytes of
//! physical memory?) and security concerns (e.g., data corruption or information
//! leakage due to concurrent or persistent access).
//!
//! Instead, the approach this module takes is to map the required physical memory
//! region on-demand when accessing them while using a LiteBox-owned buffer to copy
//! data to/from those regions. This way, this module can ensure that data must be
//! copied into LiteBox-owned memory before being used while avoiding any unknown
//! side effects due to persistent memory mapping.
//!
//! Considerations:
//!
//! Ideally, this module should be able to validate whether a given physical address
//! is okay to access or even exists in the first place. For example, accessing
//! LiteBox's own memory with this physical pointer abstraction must be prohibited to
//! prevent the Boomerang attack and any other undefined memory access. Also, some
//! device memory is mapped to certain physical address ranges and LiteBox should not
//! touch them without in-depth knowledge. However, this is a bit tricky because, in
//! many cases, LiteBox does not directly interact with the underlying hardware or
//! BIOS/UEFI such that it does not have complete knowledge of the physical memory
//! layout. In the case of LVBS, LiteBox obtains the physical memory information
//! from VTL0 including the total physical memory size and the memory range assigned
//! to VTL1/LiteBox. Thus, this module can at least confirm a given physical address
//! does not belong to VTL1's physical memory.
//!
//! This module should allow byte-level access while transparently handling page
//! mapping and data access across page boundaries. This could become complicated
//! when we consider multiple page sizes (e.g., 4 KiB, 2 MiB, 1 GiB). Also,
//! unaligned access is a matter to be considered.
//!
//! In addition, often times, this physical pointer abstraction is involved with
//! a list of physical addresses (i.e., scatter-gather list). For example, in
//! the worse case, a two-byte value can span across two non-contiguous physical
//! pages (the last byte of the first page and the first byte of the second page).
//! Thus, to enhance the performance, we may need to consider mapping multiple pages
//! at once, copy data from/to them, and unmap them later.
//!
//! When this module needs to access data across physical page boundaries, it assumes
//! that those physical pages are virtually contiguous in VTL0 or normal-world address
//! space. Otherwise, this module could end up with accessing misordered data. This is
//! best-effort assumption and ensuring this is the caller's responsibility (e.g., even
//! if this module always requires a list of physical addresses, the caller might
//! provide a wrong list by mistake or intentionally).

// TODO: Since the below `PhysMutPtr` and `PhysConstPtr` are not OP-TEE specific,
// we can move them to a different crate (e.g., `litebox`) if needed.

use litebox_common_linux::vmap::{
    PhysPageAddr, PhysPageMapInfo, PhysPageMapPermissions, PhysPointerError, VmapManager,
};
use litebox_platform_multiplex::platform;
use zerocopy::FromBytes;

/// Allocate a zeroed `Box<T>` on the heap.
///
/// # Panics
///
/// Panics if `T` is a zero-sized type, since `alloc_zeroed` with a zero-sized
/// layout is undefined behavior.
fn box_new_zeroed<T: FromBytes>() -> alloc::boxed::Box<T> {
    assert!(
        core::mem::size_of::<T>() > 0,
        "box_new_zeroed does not support zero-sized types"
    );
    let layout = core::alloc::Layout::new::<T>();
    // Safety: layout has a non-zero size and correct alignment for T.
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) }.cast::<T>();
    if ptr.is_null() {
        alloc::alloc::handle_alloc_error(layout);
    }
    // Safety: ptr is a valid, zeroed, properly aligned heap allocation for T.
    // T: FromBytes guarantees all-zero is a valid bit pattern.
    unsafe { alloc::boxed::Box::from_raw(ptr) }
}

#[inline]
fn align_down(address: usize, align: usize) -> usize {
    address & !(align - 1)
}

/// Represent a physical pointer to an object with on-demand mapping.
/// - `pages`: An array of page-aligned physical addresses. We expect physical addresses in this array are
///   virtually contiguous.
/// - `offset`: The offset within `pages[0]` where the object starts. It should be smaller than `ALIGN`.
/// - `count`: The number of objects of type `T` that can be accessed from this pointer.
/// - `T`: The type of the object being pointed to. `pages` with respect to `offset` should cover enough
///   memory for an object of type `T`.
///
/// This is a pure, immutable *descriptor*. Each access maps the required frames to a private, throwaway
/// virtual address (via `vmap`), copies data in/out with a byte-bounded `memcpy`, then unmaps.
#[derive(Clone)]
#[repr(C)]
pub struct PhysMutPtr<T: Clone, const ALIGN: usize> {
    pages: alloc::boxed::Box<[PhysPageAddr<ALIGN>]>,
    offset: usize,
    count: usize,
    _type: core::marker::PhantomData<T>,
}

impl<T: Clone, const ALIGN: usize> PhysMutPtr<T, ALIGN> {
    /// Create a new `PhysMutPtr` from the given physical page array and offset.
    ///
    /// All addresses in `pages` should be valid and aligned to `ALIGN`, and `offset` should be
    /// smaller than `ALIGN`. Also, `pages` should contain enough pages to cover at least one
    /// object of type `T` starting from `offset`. If these conditions are not met, this function
    /// returns `Err(PhysPointerError)`.
    pub fn new(pages: &[PhysPageAddr<ALIGN>], offset: usize) -> Result<Self, PhysPointerError> {
        if offset >= ALIGN {
            return Err(PhysPointerError::InvalidBaseOffset(offset, ALIGN));
        }
        let size = if pages.is_empty() {
            0
        } else {
            pages
                .len()
                .checked_mul(ALIGN)
                .ok_or(PhysPointerError::Overflow)?
                - offset
        };
        if size < core::mem::size_of::<T>() {
            return Err(PhysPointerError::InsufficientPhysicalPages(
                size,
                core::mem::size_of::<T>(),
            ));
        }
        platform().validate_unowned(pages)?;
        Ok(Self {
            pages: pages.into(),
            offset,
            count: size / core::mem::size_of::<T>(),
            _type: core::marker::PhantomData,
        })
    }

    /// Create a new `PhysMutPtr` from the given contiguous physical address and length.
    ///
    /// This is a shortcut for
    /// `PhysMutPtr::new([align_down(pa), align_down(pa) + ALIGN, ..., align_up(pa + bytes) - ALIGN], pa % ALIGN)`.
    /// This function assumes that `pa`, ..., `pa+bytes` are both physically and virtually contiguous. If not,
    /// later accesses through `PhysMutPtr` may read/write data in a wrong order.
    pub fn with_contiguous_pages(pa: usize, bytes: usize) -> Result<Self, PhysPointerError> {
        if bytes < core::mem::size_of::<T>() {
            return Err(PhysPointerError::InsufficientPhysicalPages(
                bytes,
                core::mem::size_of::<T>(),
            ));
        }
        let start_page = align_down(pa, ALIGN);
        let end_page = pa
            .checked_add(bytes)
            .and_then(|end| end.checked_next_multiple_of(ALIGN))
            .ok_or(PhysPointerError::Overflow)?;
        let span = end_page
            .checked_sub(start_page)
            .ok_or(PhysPointerError::Overflow)?;
        let mut pages = alloc::vec::Vec::with_capacity(span / ALIGN);
        let mut current_page = start_page;
        while current_page < end_page {
            pages.push(
                PhysPageAddr::<ALIGN>::new(current_page)
                    .ok_or(PhysPointerError::InvalidPhysicalAddress(current_page))?,
            );
            current_page = current_page
                .checked_add(ALIGN)
                .ok_or(PhysPointerError::Overflow)?;
        }
        Self::new(&pages, pa - start_page)
    }

    /// Create a new `PhysMutPtr` from the given physical address for a single object.
    ///
    /// This is a shortcut for `PhysMutPtr::with_contiguous_pages(pa, size_of::<T>())`.
    ///
    /// Note: This module doesn't provide `as_usize` because LiteBox should not dereference physical addresses directly.
    pub fn with_usize(pa: usize) -> Result<Self, PhysPointerError> {
        Self::with_contiguous_pages(pa, core::mem::size_of::<T>())
    }

    /// Read the value at the given offset from the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently written by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, it might read corrupt data.
    /// `FromBytes` is required to ensure T is valid for any bit pattern from untrusted physical memory.
    pub unsafe fn read_at_offset(
        &self,
        count: usize,
    ) -> Result<alloc::boxed::Box<T>, PhysPointerError>
    where
        T: FromBytes,
    {
        if count >= self.count {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let skip = self.element_skip(count)?;
        let mut boxed = box_new_zeroed::<T>();
        unsafe {
            self.read_region(
                skip,
                core::mem::size_of::<T>(),
                core::ptr::from_mut::<T>(boxed.as_mut()).cast::<u8>(),
            )?;
        }
        Ok(boxed)
    }

    /// Read a slice of values at the given offset from the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently written by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, it might read corrupt data.
    /// `FromBytes` is required to ensure T is valid for any bit pattern from untrusted physical memory.
    pub unsafe fn read_slice_at_offset(
        &self,
        count: usize,
        values: &mut [T],
    ) -> Result<(), PhysPointerError>
    where
        T: FromBytes,
    {
        if count
            .checked_add(values.len())
            .is_none_or(|end| end > self.count)
        {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let skip = self.element_skip(count)?;
        unsafe {
            self.read_region(
                skip,
                core::mem::size_of_val(values),
                values.as_mut_ptr().cast::<u8>(),
            )?;
        }
        Ok(())
    }

    /// Write the value at the given offset to the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently written by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, data it writes might be overwritten.
    pub unsafe fn write_at_offset(&self, count: usize, value: T) -> Result<(), PhysPointerError> {
        if count >= self.count {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let skip = self.element_skip(count)?;
        unsafe {
            self.write_region(
                skip,
                core::mem::size_of::<T>(),
                core::ptr::from_ref(&value).cast::<u8>(),
            )?;
        }
        Ok(())
    }

    /// Write a slice of values at the given offset to the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently written by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, data it writes might be overwritten.
    pub unsafe fn write_slice_at_offset(
        &self,
        count: usize,
        values: &[T],
    ) -> Result<(), PhysPointerError> {
        if count
            .checked_add(values.len())
            .is_none_or(|end| end > self.count)
        {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let skip = self.element_skip(count)?;
        unsafe {
            self.write_region(
                skip,
                core::mem::size_of_val(values),
                values.as_ptr().cast::<u8>(),
            )?;
        }
        Ok(())
    }

    /// Compute the byte offset (`skip`) from the start of `pages[0]` at which element `count` begins.
    fn element_skip(&self, count: usize) -> Result<usize, PhysPointerError> {
        self.offset
            .checked_add(
                count
                    .checked_mul(core::mem::size_of::<T>())
                    .ok_or(PhysPointerError::Overflow)?,
            )
            .ok_or(PhysPointerError::Overflow)
    }

    /// Read `size` bytes starting at byte offset `skip` (from `pages[0]`) into `dst`.
    ///
    /// Maps the page set to a private throwaway virtual address, copies into the LiteBox-owned
    /// `dst` buffer, then unmaps.
    ///
    /// # Safety
    ///
    /// `dst` must be valid for writes of `size` bytes. The physical source may be concurrently
    /// written by other entities (the normal world, or another LiteBox core), so the data read
    /// might be transiently inconsistent — callers must treat it as untrusted and validate it (see
    /// the module-level note on the copy-once discipline).
    unsafe fn read_region(
        &self,
        skip: usize,
        size: usize,
        dst: *mut u8,
    ) -> Result<(), PhysPointerError> {
        if size == 0 {
            return Ok(());
        }
        let (start, end) = self.span_bounds(skip, size)?;
        let map = MapGuard::<ALIGN>::new(&self.pages[start..end], PhysPageMapPermissions::READ)?;

        let src = map.base().wrapping_add(skip % ALIGN);
        // Fallible: guards against a spurious fault while copying from the mapped page.
        let result = unsafe { litebox::mm::exception_table::memcpy_fallible(dst, src, size) };
        debug_assert!(result.is_ok(), "fault reading from mapped physical page");
        result.map_err(|_| PhysPointerError::CopyFailed)?;
        Ok(())
    }

    /// Write `size` bytes from `src` to the region starting at byte offset `skip` (from `pages[0]`).
    ///
    /// Maps the page set to a private throwaway virtual address, copies from the LiteBox-owned
    /// `src` buffer, then unmaps. The copy is byte-bounded to `[skip, skip + size)`, so it never
    /// touches neighboring sub-page slots that may belong to concurrent, unrelated requests.
    ///
    /// # Safety
    ///
    /// `src` must be valid for reads of `size` bytes. The physical destination may be concurrently
    /// accessed by other entities.
    unsafe fn write_region(
        &self,
        skip: usize,
        size: usize,
        src: *const u8,
    ) -> Result<(), PhysPointerError> {
        if size == 0 {
            return Ok(());
        }
        let (start, end) = self.span_bounds(skip, size)?;
        let map = MapGuard::<ALIGN>::new(
            &self.pages[start..end],
            PhysPageMapPermissions::READ | PhysPageMapPermissions::WRITE,
        )?;

        let dst = map.base().wrapping_add(skip % ALIGN);
        // Fallible: guards against a spurious fault while copying to the mapped page.
        let result = unsafe { litebox::mm::exception_table::memcpy_fallible(dst, src, size) };
        debug_assert!(result.is_ok(), "fault writing to mapped physical page");
        result.map_err(|_| PhysPointerError::CopyFailed)?;
        Ok(())
    }

    /// Compute the `[start, end)` page-index range (within `self.pages`) covered by a `size`-byte
    /// access at byte offset `skip`, validating the range against the descriptor's page count.
    fn span_bounds(&self, skip: usize, size: usize) -> Result<(usize, usize), PhysPointerError> {
        let start = skip / ALIGN;
        let end = skip
            .checked_add(size)
            .ok_or(PhysPointerError::Overflow)?
            .div_ceil(ALIGN);
        if start >= end || end > self.pages.len() {
            return Err(PhysPointerError::IndexOutOfBounds(end, self.pages.len()));
        }
        Ok((start, end))
    }
}

/// RAII guard owning a private, throwaway physical mapping for the duration of a single access.
///
/// On drop it unmaps the virtual address window. Each access creates its own mapping (the VA is
/// never shared across cores or page tables), so unmapping never disturbs another accessor.
struct MapGuard<const ALIGN: usize> {
    info: Option<PhysPageMapInfo<ALIGN>>,
}

impl<const ALIGN: usize> MapGuard<ALIGN> {
    /// Map `pages` to a fresh private virtual address with the given permissions.
    fn new(
        pages: &[PhysPageAddr<ALIGN>],
        perms: PhysPageMapPermissions,
    ) -> Result<Self, PhysPointerError> {
        // SAFETY: `pages` were validated as not owned by LiteBox at descriptor construction. The
        // platform maps them into a fresh private VA window used only transiently for this copy.
        let info = unsafe { platform().vmap(pages, perms)? };
        Ok(Self { info: Some(info) })
    }

    /// Base virtual address of the mapped window.
    fn base(&self) -> *mut u8 {
        self.info
            .as_ref()
            .map_or(core::ptr::null_mut(), |info| info.base)
    }
}

impl<const ALIGN: usize> Drop for MapGuard<ALIGN> {
    fn drop(&mut self) {
        if let Some(info) = self.info.take() {
            // SAFETY: This mapping is private to the current access and no longer in use.
            let result = unsafe { platform().vunmap(info) };
            debug_assert!(result.is_ok(), "unexpected error during vunmap: {result:?}");
        }
    }
}

impl<T: Clone, const ALIGN: usize> core::fmt::Debug for PhysMutPtr<T, ALIGN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysMutPtr")
            .field("pages[0]", &self.pages.first().map_or(0, |p| p.as_usize()))
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

/// Represent a physical pointer to a read-only object. This wraps around [`PhysMutPtr`] and
/// exposes only read access.
#[derive(Clone)]
#[repr(C)]
pub struct PhysConstPtr<T: Clone, const ALIGN: usize> {
    inner: PhysMutPtr<T, ALIGN>,
}

impl<T: Clone + FromBytes, const ALIGN: usize> PhysConstPtr<T, ALIGN> {
    /// Create a new `PhysConstPtr` from the given physical page array and offset.
    ///
    /// All addresses in `pages` should be valid and aligned to `ALIGN`, and `offset` should be smaller
    /// than `ALIGN`. Also, `pages` should contain enough pages to cover at least one object of
    /// type `T` starting from `offset`. If these conditions are not met, this function returns
    /// `Err(PhysPointerError)`.
    pub fn new(pages: &[PhysPageAddr<ALIGN>], offset: usize) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::new(pages, offset)?,
        })
    }

    /// Create a new `PhysConstPtr` from the given contiguous physical address and length.
    ///
    /// This is a shortcut for
    /// `PhysConstPtr::new([align_down(pa), align_down(pa) + ALIGN, ..., align_up(pa + bytes) - ALIGN], pa % ALIGN)`.
    /// This function assumes that `pa`, ..., `pa+bytes` are both physically and virtually contiguous. If not,
    /// later accesses through `PhysConstPtr` may read data in a wrong order.
    pub fn with_contiguous_pages(pa: usize, bytes: usize) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::with_contiguous_pages(pa, bytes)?,
        })
    }

    /// Create a new `PhysConstPtr` from the given physical address for a single object.
    ///
    /// This is a shortcut for `PhysConstPtr::with_contiguous_pages(pa, size_of::<T>())`.
    ///
    /// Note: This module doesn't provide `as_usize` because LiteBox should not dereference physical addresses directly.
    pub fn with_usize(pa: usize) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::with_usize(pa)?,
        })
    }

    /// Read the value at the given offset from the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently written by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, it might read corrupt data.
    pub unsafe fn read_at_offset(
        &self,
        count: usize,
    ) -> Result<alloc::boxed::Box<T>, PhysPointerError>
    where
        T: FromBytes,
    {
        unsafe { self.inner.read_at_offset(count) }
    }

    /// Read a slice of values at the given offset from the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently written by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, it might read corrupt data.
    pub unsafe fn read_slice_at_offset(
        &self,
        count: usize,
        values: &mut [T],
    ) -> Result<(), PhysPointerError>
    where
        T: FromBytes,
    {
        unsafe { self.inner.read_slice_at_offset(count, values) }
    }
}

impl<T: Clone, const ALIGN: usize> core::fmt::Debug for PhysConstPtr<T, ALIGN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysConstPtr")
            .field(
                "pages[0]",
                &self.inner.pages.first().map_or(0, |p| p.as_usize()),
            )
            .field("offset", &self.inner.offset)
            .finish_non_exhaustive()
    }
}
