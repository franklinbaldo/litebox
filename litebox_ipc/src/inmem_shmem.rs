// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared-memory region structures for the in-memory filesystem upper layer.
//!
//! Both central and micro share a memory-mapped region that contains a
//! [`RegionHeader`] followed by an array of [`FileSlot`] entries and a bulk
//! data area.  Each [`FileSlot`] is protected by a sequence lock so that
//! the writer (central) can update offset/length atomically with respect to
//! the reader (micro).

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic number identifying a valid in-memory shmem region.
pub const INMEM_MAGIC: u32 = 0x4C42_494D; // "LBIM"

/// Current version of the region layout.
pub const INMEM_VERSION: u32 = 1;

/// Default maximum number of file slots in the region.
pub const DEFAULT_MAX_SLOTS: u32 = 512;

/// Default total size of the in-memory shmem region (16 MiB).
pub const DEFAULT_INMEM_REGION_SIZE: usize = 16 * 1024 * 1024;

/// Sentinel value meaning "no in-memory slot assigned".
pub const INMEM_NO_SLOT: u32 = u32::MAX;

/// Size of the [`RegionHeader`] in bytes.
pub const REGION_HEADER_SIZE: usize = 64;

/// Size of a single [`FileSlot`] in bytes.
pub const FILE_SLOT_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Region header
// ---------------------------------------------------------------------------

/// Fixed header at the start of the in-memory shmem region.
///
/// Layout (64 bytes, cache-line sized):
///
/// | offset | size | field               |
/// |--------|------|---------------------|
/// |   0    |  4   | magic               |
/// |   4    |  4   | version             |
/// |   8    |  4   | max_slots           |
/// |  12    |  4   | _pad0               |
/// |  16    |  8   | data_region_offset  |
/// |  24    |  8   | data_region_size    |
/// |  32    | 32   | _reserved           |
#[derive(Clone, Copy)]
#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
pub struct RegionHeader {
    /// Must equal [`INMEM_MAGIC`].
    pub magic: u32,
    /// Must equal [`INMEM_VERSION`].
    pub version: u32,
    /// Number of file slots in the slot array.
    pub max_slots: u32,
    /// Padding for alignment.
    pub _pad0: u32,
    /// Byte offset from region start to the bulk data area.
    pub data_region_offset: u64,
    /// Size of the bulk data area in bytes.
    pub data_region_size: u64,
    /// Reserved for future use (zero-filled).
    pub _reserved: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<RegionHeader>() == REGION_HEADER_SIZE);

// ---------------------------------------------------------------------------
// File slot (sequence-locked)
// ---------------------------------------------------------------------------

/// A single file metadata slot protected by a sequence lock.
///
/// The `sequence` field doubles as the seqlock counter:
///   - Even → slot is consistent and readable.
///   - Odd  → a write is in progress; readers must spin.
///
/// Layout (32 bytes):
///
/// | offset | size | field       |
/// |--------|------|-------------|
/// |   0    |  8   | sequence    |
/// |   8    |  8   | data_offset |
/// |  16    |  8   | data_len    |
/// |  24    |  8   | capacity    |
#[repr(C)]
pub struct FileSlot {
    /// Sequence counter (even = consistent, odd = write in progress).
    pub sequence: AtomicU64,
    /// Byte offset into the data region where file content starts.
    pub data_offset: AtomicU64,
    /// Current length of the file data in bytes.
    pub data_len: AtomicU64,
    /// Allocated capacity in the data region for this file.
    pub capacity: AtomicU64,
}

const _: () = assert!(core::mem::size_of::<FileSlot>() == FILE_SLOT_SIZE);

/// A point-in-time snapshot of a [`FileSlot`] read under the sequence lock.
#[derive(Clone, Copy, Debug)]
pub struct FileSlotSnapshot {
    /// Byte offset into the data region.
    pub data_offset: u64,
    /// Current length of the file data.
    pub data_len: u64,
    /// Allocated capacity.
    pub capacity: u64,
}

impl FileSlot {
    /// Read a consistent snapshot of this slot.
    ///
    /// Spins while the sequence counter is odd (write in progress) and
    /// retries if the counter changed between the start and end of the read.
    #[inline]
    pub fn read_snapshot(&self) -> FileSlotSnapshot {
        loop {
            let seq1 = self.sequence.load(Acquire);
            if seq1 & 1 != 0 {
                // Write in progress — spin.
                core::hint::spin_loop();
                continue;
            }

            let data_offset = self.data_offset.load(Relaxed);
            let data_len = self.data_len.load(Relaxed);
            let capacity = self.capacity.load(Relaxed);

            let seq2 = self.sequence.load(Acquire);
            if seq1 == seq2 {
                return FileSlotSnapshot {
                    data_offset,
                    data_len,
                    capacity,
                };
            }
            // Sequence changed — retry.
            core::hint::spin_loop();
        }
    }

    /// Begin a write to this slot.
    ///
    /// Increments the sequence counter to an odd value, signalling readers
    /// that a write is in progress.  Must be paired with [`end_write`].
    ///
    /// # Safety
    ///
    /// Caller must be the sole writer for this slot.
    ///
    /// [`end_write`]: Self::end_write
    #[inline]
    pub unsafe fn begin_write(&self) {
        self.sequence.fetch_add(1, Release);
    }

    /// End a write to this slot.
    ///
    /// Increments the sequence counter to an even value, allowing readers
    /// to observe the new data.
    ///
    /// # Safety
    ///
    /// Must be called after [`begin_write`] by the same writer.
    ///
    /// [`begin_write`]: Self::begin_write
    #[inline]
    pub unsafe fn end_write(&self) {
        self.sequence.fetch_add(1, Release);
    }

    /// Clear this slot under the sequence lock.
    ///
    /// Sets `data_offset`, `data_len`, and `capacity` to zero.
    ///
    /// # Safety
    ///
    /// Caller must be the sole writer for this slot.
    #[inline]
    pub unsafe fn clear(&self) {
        unsafe { self.begin_write() };
        self.data_offset.store(0, Relaxed);
        self.data_len.store(0, Relaxed);
        self.capacity.store(0, Relaxed);
        unsafe { self.end_write() };
    }
}

// ---------------------------------------------------------------------------
// Layout helpers
// ---------------------------------------------------------------------------

/// Byte offset from the region start to the first [`FileSlot`].
///
/// Slots begin immediately after the [`RegionHeader`].
#[inline]
#[must_use]
pub const fn slots_offset() -> usize {
    REGION_HEADER_SIZE
}

/// Byte offset from the region start to the bulk data area, page-aligned.
///
/// The data region starts after the slot array, rounded up to the next
/// 4 KiB page boundary.
#[inline]
#[must_use]
pub const fn data_region_offset(max_slots: u32) -> usize {
    let raw = REGION_HEADER_SIZE + (max_slots as usize) * FILE_SLOT_SIZE;
    // Round up to next 4 KiB page.
    (raw + 4095) & !4095
}

/// Return a shared reference to the [`FileSlot`] at `index` within a
/// region that starts at `base`.
///
/// # Safety
///
/// - `base` must point to a valid, mapped in-memory shmem region.
/// - `index` must be less than the region's `max_slots`.
/// - The returned reference must not outlive the mapping.
#[inline]
#[allow(clippy::cast_ptr_alignment)] // caller guarantees proper alignment
pub unsafe fn slot_ptr(base: *const u8, index: u32) -> &'static FileSlot {
    let offset = slots_offset() + (index as usize) * FILE_SLOT_SIZE;
    unsafe { &*base.add(offset).cast::<FileSlot>() }
}
