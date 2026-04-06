// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bump + free-list allocator for the in-memory shmem data region.
//!
//! This allocator manages two resources within the shmem region:
//!
//! 1. **File slots** — fixed-size [`FileSlot`] entries in the slot array,
//!    managed by a simple free-list (`Vec<u32>`).
//!
//! 2. **Data bytes** — variable-size allocations in the bulk data region,
//!    managed by a bump pointer for new allocations and a first-fit free-list
//!    for reclamation (with block splitting when remainder ≥ 64 bytes).
//!
//! The allocator lives entirely on central's heap — only central calls it.
//! All access is serialised by an `Arc<Mutex<>>` wrapper.

// Methods are defined now but consumed by later tasks in the implementation
// sequence.
#![allow(dead_code)]

use litebox_ipc::inmem_shmem::{self, FileSlot};

/// Minimum remainder size (in bytes) to split a free block.
const MIN_SPLIT_SIZE: usize = 64;

/// Alignment for all data allocations.
const DATA_ALIGNMENT: usize = 8;

/// A free block in the data region.
#[derive(Clone, Copy, Debug)]
struct FreeBlock {
    /// Offset from the start of the data region.
    offset: usize,
    /// Size of the free block in bytes.
    size: usize,
}

/// Bump + free-list allocator for the in-memory shmem data region.
///
/// Manages both file slot indices and variable-size data allocations within
/// a memory-mapped shared region.
pub struct InMemAllocator {
    /// Pointer to the start of the entire shmem region.
    base: *mut u8,
    /// Byte offset of the data region from `base`.
    data_offset: usize,
    /// Total size of the data region in bytes.
    data_size: usize,
    /// Next bump offset (relative to data region start).
    bump: usize,
    /// Free blocks available for reclamation (first-fit).
    // TODO: add coalescing of adjacent free blocks to reduce fragmentation.
    free_list: Vec<FreeBlock>,
    /// Maximum number of file slots.
    max_slots: u32,
    /// Free slot indices (pop to alloc, push to free).
    slot_free_list: Vec<u32>,
}

// SAFETY: The base pointer points to process-lifetime mmap'd shared memory
// that is never freed. All access is serialised by the Arc<Mutex<>> wrapper.
unsafe impl Send for InMemAllocator {}

impl InMemAllocator {
    /// Create a new allocator for the given shmem region.
    ///
    /// If `base` is null or `size` is too small, the allocator is created in
    /// an unavailable state where all allocations fail.
    #[must_use]
    pub fn new(base: *mut u8, size: usize) -> Self {
        if base.is_null() || size == 0 {
            return Self {
                base: std::ptr::null_mut(),
                data_offset: 0,
                data_size: 0,
                bump: 0,
                free_list: Vec::new(),
                max_slots: 0,
                slot_free_list: Vec::new(),
            };
        }

        let max_slots = inmem_shmem::DEFAULT_MAX_SLOTS;
        let data_offset = inmem_shmem::data_region_offset(max_slots);

        // Ensure the region is large enough for the data region to exist.
        let data_size = size.saturating_sub(data_offset);

        // All slots start free (0..max_slots), in reverse order so that
        // pop() returns the lowest index first.
        let slot_free_list: Vec<u32> = (0..max_slots).rev().collect();

        Self {
            base,
            data_offset,
            data_size,
            bump: 0,
            free_list: Vec::new(),
            max_slots,
            slot_free_list,
        }
    }

    /// Check if the allocator is available (has a valid base pointer).
    #[must_use]
    pub fn is_available(&self) -> bool {
        !self.base.is_null()
    }

    // -----------------------------------------------------------------------
    // Slot management
    // -----------------------------------------------------------------------

    /// Allocate a metadata slot index.
    ///
    /// Returns `None` if no slots are available.
    #[must_use]
    pub fn alloc_slot(&mut self) -> Option<u32> {
        if !self.is_available() {
            return None;
        }
        self.slot_free_list.pop()
    }

    /// Free a metadata slot, clearing it under its seqlock.
    ///
    /// # Panics
    ///
    /// Panics if `index >= max_slots` or (in debug mode) if the slot is
    /// already in the free list.
    pub fn free_slot(&mut self, index: u32) {
        assert!(index < self.max_slots, "slot index out of range");
        debug_assert!(
            !self.slot_free_list.contains(&index),
            "double-free of slot {index}"
        );
        // SAFETY: base is valid and index is in range (checked above).
        // We are the sole writer (access serialised by Mutex).
        let slot = unsafe { inmem_shmem::slot_ptr(self.base, index) };
        unsafe { slot.clear() };
        self.slot_free_list.push(index);
    }

    /// Get a shared reference to the [`FileSlot`] at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= max_slots`.
    #[must_use]
    pub fn slot(&self, index: u32) -> &FileSlot {
        assert!(index < self.max_slots, "slot index out of range");
        // SAFETY: base is valid and index is in range (checked above).
        unsafe { inmem_shmem::slot_ptr(self.base, index) }
    }

    /// Update a slot's data fields under its seqlock.
    ///
    /// # Panics
    ///
    /// Panics if `index >= max_slots`.
    pub fn update_slot(&self, index: u32, data_offset: u64, data_len: u64, capacity: u64) {
        let slot = self.slot(index);
        // SAFETY: We are the sole writer (access serialised by Mutex).
        unsafe { slot.begin_write() };
        slot.data_offset
            .store(data_offset, core::sync::atomic::Ordering::Relaxed);
        slot.data_len
            .store(data_len, core::sync::atomic::Ordering::Relaxed);
        slot.capacity
            .store(capacity, core::sync::atomic::Ordering::Relaxed);
        unsafe { slot.end_write() };
    }

    // -----------------------------------------------------------------------
    // Data region management
    // -----------------------------------------------------------------------

    /// Allocate `size` bytes from the data region.
    ///
    /// Returns the offset from the **region start** (i.e. from `base`), or
    /// `None` if there is insufficient space. All allocations are 8-byte
    /// aligned.
    #[must_use]
    pub fn alloc_data(&mut self, size: usize) -> Option<u64> {
        if !self.is_available() || size == 0 {
            return None;
        }

        let aligned_size = align_up(size, DATA_ALIGNMENT);

        // Try the free-list first (first-fit).
        if let Some(offset) = self.alloc_from_free_list(aligned_size) {
            return Some(offset);
        }

        // Fall back to bump allocation.
        let alloc_offset = align_up(self.bump, DATA_ALIGNMENT);
        let new_bump = alloc_offset + aligned_size;
        if new_bump > self.data_size {
            return None;
        }
        self.bump = new_bump;

        // Return offset from region start.
        Some((self.data_offset + alloc_offset) as u64)
    }

    /// Free a data block at the given offset (from region start) with given size.
    ///
    /// Returns early (with a warning) if the offset is outside the data region.
    #[allow(clippy::cast_possible_truncation)] // offsets fit in usize on 64-bit
    pub fn free_data(&mut self, offset: u64, size: usize) {
        if !self.is_available() || size == 0 {
            return;
        }

        let offset_usize = offset as usize;
        if offset_usize < self.data_offset {
            eprintln!(
                "[inmem_alloc] free_data: offset {offset:#x} is before data region ({:#x})",
                self.data_offset
            );
            return;
        }
        let relative_offset = offset_usize - self.data_offset;
        let aligned_size = align_up(size, DATA_ALIGNMENT);

        self.free_list.push(FreeBlock {
            offset: relative_offset,
            size: aligned_size,
        });
    }

    /// Get a mutable pointer to data at the given offset (from region start).
    ///
    /// # Safety
    ///
    /// The returned pointer is valid only as long as the shmem region is mapped.
    /// Callers must ensure the offset and access size are within the allocated
    /// block.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // offsets fit in usize on 64-bit
    pub fn data_ptr_mut(&self, offset: u64) -> *mut u8 {
        debug_assert!(self.is_available(), "data_ptr_mut on unavailable allocator");
        // SAFETY: base is valid, offset is within the mapped region.
        unsafe { self.base.add(offset as usize) }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Try to allocate from the free-list using first-fit with block splitting.
    ///
    /// Returns the offset from region start, or `None` if no suitable block
    /// was found.
    fn alloc_from_free_list(&mut self, aligned_size: usize) -> Option<u64> {
        let idx = self.free_list.iter().position(|b| b.size >= aligned_size)?;

        let block = self.free_list[idx];
        let remainder = block.size - aligned_size;

        if remainder >= MIN_SPLIT_SIZE {
            // Split: shrink the free block, return the beginning.
            self.free_list[idx] = FreeBlock {
                offset: block.offset + aligned_size,
                size: remainder,
            };
        } else {
            // Use the whole block.
            self.free_list.swap_remove(idx);
        }

        Some((self.data_offset + block.offset) as u64)
    }
}

/// Round `value` up to the next multiple of `alignment`.
///
/// `alignment` must be a power of two.
const fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test allocator backed by a heap-allocated buffer.
    fn test_allocator(size: usize) -> (Vec<u8>, InMemAllocator) {
        let mut buf = vec![0u8; size];
        let base = buf.as_mut_ptr();
        let alloc = InMemAllocator::new(base, size);
        (buf, alloc)
    }

    #[test]
    fn null_allocator_is_unavailable() {
        let mut alloc = InMemAllocator::new(std::ptr::null_mut(), 0);
        assert!(!alloc.is_available());
        assert!(alloc.alloc_slot().is_none());
        assert!(alloc.alloc_data(64).is_none());
    }

    #[test]
    fn slot_alloc_and_free() {
        let (_buf, mut alloc) = test_allocator(1024 * 1024);
        assert!(alloc.is_available());

        // Allocate all slots.
        let mut slots = Vec::new();
        for _ in 0..inmem_shmem::DEFAULT_MAX_SLOTS {
            slots.push(alloc.alloc_slot().unwrap());
        }
        // No more slots available.
        assert!(alloc.alloc_slot().is_none());

        // Free one and re-allocate.
        alloc.free_slot(slots[0]);
        let s = alloc.alloc_slot().unwrap();
        assert_eq!(s, slots[0]);
    }

    #[test]
    fn data_alloc_alignment() {
        let (_buf, mut alloc) = test_allocator(1024 * 1024);
        let off1 = alloc.alloc_data(1).unwrap();
        let off2 = alloc.alloc_data(1).unwrap();

        // Both offsets should be 8-byte aligned.
        assert_eq!(off1 % 8, 0);
        assert_eq!(off2 % 8, 0);
        // Second allocation should be at least 8 bytes after the first.
        assert!(off2 >= off1 + 8);
    }

    #[test]
    fn data_free_and_reuse() {
        let (_buf, mut alloc) = test_allocator(1024 * 1024);
        let off = alloc.alloc_data(128).unwrap();
        alloc.free_data(off, 128);

        // The freed block should be reused.
        let off2 = alloc.alloc_data(64).unwrap();
        assert_eq!(off2, off);
    }

    #[test]
    fn data_free_list_splitting() {
        let (_buf, mut alloc) = test_allocator(1024 * 1024);
        let off = alloc.alloc_data(256).unwrap();
        alloc.free_data(off, 256);

        // Allocate a smaller block — should split the free block.
        let off2 = alloc.alloc_data(64).unwrap();
        assert_eq!(off2, off);

        // Allocate again — should come from the remainder.
        let off3 = alloc.alloc_data(64).unwrap();
        assert_eq!(off3, off + 64);
    }

    #[test]
    fn data_alloc_exhaustion() {
        // Tiny region: just enough for header + slots + a little data.
        let data_offset = inmem_shmem::data_region_offset(inmem_shmem::DEFAULT_MAX_SLOTS);
        let total_size = data_offset + 128;
        let (_buf, mut alloc) = test_allocator(total_size);

        // Allocate all available data.
        let _off = alloc.alloc_data(128).unwrap();
        // No more space.
        assert!(alloc.alloc_data(1).is_none());
    }

    #[test]
    fn data_ptr_mut_returns_correct_address() {
        let (_buf, alloc) = test_allocator(1024 * 1024);
        let base = alloc.base;
        let ptr = alloc.data_ptr_mut(100);
        assert_eq!(ptr, unsafe { base.add(100) });
    }
}
