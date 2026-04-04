// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared-memory ring buffer types for IPC between micro-LiteBox and central
//! LiteBox.

// Padding fields on repr(C) IPC structs are intentionally public for
// construction and zerocopy compatibility.
#![allow(clippy::pub_underscore_fields)]

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Number of entries in each ring.
pub const RING_SIZE: usize = 256;

/// Mask for wrapping ring indices (RING_SIZE - 1).
pub const RING_MASK: usize = 255;

/// Maximum number of guest threads that can be multiplexed.
pub const MAX_THREADS: usize = 64;

/// Default size of the shared data region (8 MiB).
///
/// Must be large enough to hold the biggest mmap segment from an ELF
/// binary plus the trampoline descriptor and code that follow it.
pub const DEFAULT_DATA_REGION_SIZE: usize = 8 * 1024 * 1024;

/// Base offset within the data region where pipe ring buffers start.
///
/// Layout: [pathnames: 1 MiB][write data: 4 MiB][pipe zone: 3 MiB]
pub const PIPE_ZONE_BASE_OFFSET: usize = 5 * 1024 * 1024; // 0x500000

/// Size of each pipe slot (header + data buffer).
/// Header: 64 bytes (cache-line aligned). Data: 64 KiB (power-of-2).
pub const PIPE_SLOT_SIZE: usize = 64 + 65536;

/// Capacity of the pipe data buffer (must be power-of-2).
pub const PIPE_DATA_CAPACITY: usize = 65536;

/// Maximum number of concurrent pipe slots.
/// floor((8 MiB - 5 MiB) / PIPE_SLOT_SIZE) = floor(3145728 / 65600) = 47
pub const MAX_PIPE_SLOTS: usize = 47;

/// Flags for submission queue entries.
pub mod sq_flags {
    /// Batch this entry with the next one.
    pub const BATCH: u16 = 1 << 0;
    /// This syscall requires authentication before execution.
    pub const NEED_AUTH: u16 = 1 << 1;
    /// Report the result of this syscall back to the guest.
    pub const REPORT_RESULT: u16 = 1 << 2;
    /// This entry is a one-way notification — central should process it
    /// but NOT write a CQ entry or wake the sender.
    pub const NOTIFY_ONLY: u16 = 1 << 3;
}

/// Flags for completion queue entries.
pub mod cq_flags {
    /// The syscall was executed locally (without round-tripping to host).
    pub const EXEC_LOCAL: u16 = 1 << 0;
    /// The completion carries associated data in the data region.
    pub const HAS_DATA: u16 = 1 << 1;
    /// The completion includes trampoline data for a dynamically-loaded
    /// rewritten ELF.  Set alongside `HAS_DATA` on file-backed mmap
    /// responses.  The data region layout is:
    ///   `[mmap_data (data_len bytes)][TrampolineDescriptor][trampoline code]`
    pub const TRAMPOLINE: u16 = 1 << 2;
    /// Central does not need a result report for this EXEC_LOCAL entry.
    /// Micro should skip `report_local_result()` after local execution.
    pub const NO_REPORT: u16 = 1 << 4;
}

/// Descriptor appended to the data region when `cq_flags::TRAMPOLINE` is set.
///
/// Immediately follows the mmap data (at `data_offset + data_len`).
/// The trampoline code bytes follow this descriptor.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct TrampolineDescriptor {
    /// Virtual address offset of the trampoline relative to the mmap base.
    pub vaddr_offset: u32,
    /// Size of the trampoline code in bytes (follows this descriptor).
    pub size: u32,
}

/// A submission queue entry describing a syscall request from guest to host.
///
/// This struct is exactly 128 bytes (two cache lines) and cache-line aligned.
/// The larger size is necessary to hold all 6 Linux syscall arguments as u64
/// values alongside the control fields.
///
/// Note: `SqEntry` cannot derive `FromBytes`/`IntoBytes` because it contains
/// `AtomicU8`.
#[repr(C, align(64))]
pub struct SqEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Linux syscall number.
    pub syscall_nr: u32,
    /// Thread slot index (0..MAX_THREADS).
    pub thread_slot: u16,
    /// Combination of `sq_flags::*`.
    pub flags: u16,
    /// Syscall arguments (up to 6, matching the Linux syscall ABI).
    pub args: [u64; 6],
    /// Offset into the shared data region for inline data.
    pub data_offset: u32,
    /// Length of inline data.
    pub data_len: u32,
    /// Set to 1 by the producer once all other fields are written.
    pub ready: AtomicU8,
    /// Padding to fill to 128 bytes.
    pub _pad: [u8; 23],
}

const _: () = assert!(size_of::<SqEntry>() == 128);

/// A completion queue entry describing a syscall result from host to guest.
///
/// This struct is exactly 32 bytes.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct CqEntry {
    /// Sequence number matching the corresponding `SqEntry`.
    pub seq: u64,
    /// Syscall return value (or negated errno).
    pub result: i64,
    /// Combination of `cq_flags::*`.
    pub flags: u16,
    /// Thread slot index this completion is for.
    pub thread_slot: u16,
    /// Reserved padding.
    pub _pad: [u8; 4],
    /// Offset into the shared data region for result data.
    pub data_offset: u32,
    /// Length of result data.
    pub data_len: u32,
}

const _: () = assert!(size_of::<CqEntry>() == 32);

/// Header for a shmem-backed pipe ring buffer.
///
/// Lives at the start of each pipe slot in the pipe zone. Both micro and
/// central access this through the shared memory mapping. The ring buffer
/// data immediately follows this header.
///
/// Invariants:
/// - `tail - head` = bytes available to read (always non-negative)
/// - `capacity - (tail - head)` = bytes available to write
/// - Data index: `cursor & (capacity - 1)` (power-of-2 masking)
#[repr(C, align(64))]
pub struct ShmemPipeHeader {
    /// Consumer (reader) position — byte offset of next read.
    pub head: AtomicU64,
    /// Producer (writer) position — byte offset of next write.
    pub tail: AtomicU64,
    /// Usable buffer capacity in bytes (always power-of-2).
    pub capacity: u64,
    /// Pipe status flags (bitwise OR of `pipe_flags::*`).
    pub flags: AtomicU32,
    /// The read-end fd number (for identification).
    pub read_fd: i32,
    /// The write-end fd number (for identification).
    pub write_fd: i32,
    /// Padding to fill to 64 bytes (one cache line).
    pub _pad: [u8; 24],
}

const _: () = assert!(size_of::<ShmemPipeHeader>() == 64);

/// Flags for `ShmemPipeHeader::flags`.
pub mod pipe_flags {
    /// The read end has been closed. Writers should get EPIPE/SIGPIPE.
    pub const READER_CLOSED: u32 = 1 << 0;
    /// The write end has been closed. Readers should get EOF (0) when buffer empty.
    pub const WRITER_CLOSED: u32 = 1 << 1;
    /// The pipe is non-blocking (O_NONBLOCK was set).
    pub const NONBLOCK: u32 = 1 << 2;
}

/// Header at the start of the shared memory region containing ring metadata.
///
/// The SQ and CQ head/tail pairs are placed on separate cache lines to avoid
/// false sharing between producer and consumer.
#[repr(C, align(64))]
pub struct RingHeader {
    // --- First cache line: submission queue metadata ---
    /// SQ consumer position (read by producer to check for space).
    pub sq_head: AtomicU64,
    /// SQ producer position (read by consumer to find new entries).
    pub sq_tail: AtomicU64,
    /// Notification futex for waking the host when new SQ entries arrive.
    pub sq_notify: AtomicU32,
    /// Set to 1 by central when it is shutting down (normal exit, panic, or
    /// signal). Micro checks this after futex timeouts to detect central death
    /// and exit gracefully instead of hanging forever.
    pub is_exiting: AtomicU32,
    /// Set to 1 by central when it enters futex sleep waiting for SQ entries.
    /// Cleared by central when it wakes up. Micro checks this before issuing
    /// FUTEX_WAKE on sq_notify — if central is still spinning, the wake is skipped.
    pub sq_consumer_sleeping: AtomicU32,
    /// Padding to fill the first cache line.
    pub _pad_sq: [u8; 36],

    // --- Second cache line: completion queue metadata ---
    /// CQ consumer position (read by producer to check for space).
    pub cq_head: AtomicU64,
    /// CQ producer position (read by consumer to find new entries).
    pub cq_tail: AtomicU64,
    /// Bitmask: bit N is set when thread N has entered futex sleep on its
    /// `cq_notify_slots[N]`. Central checks this before issuing FUTEX_WAKE.
    pub cq_consumers_sleeping: AtomicU64,
    /// Padding to fill the second cache line.
    pub _pad_cq: [u8; 40],

    // --- Per-thread wake slots ---
    /// Per-thread notification futexes for waking individual guest threads.
    pub cq_notify_slots: [AtomicU32; MAX_THREADS],
}

/// Describes the layout and offsets of the shared memory region.
#[derive(Debug, Clone, Copy)]
pub struct SharedRingLayout {
    /// Total size of the shared memory region in bytes.
    pub total_size: usize,
    /// Byte offset of the SQ entry array from the start of the region.
    pub sq_entries_offset: usize,
    /// Byte offset of the CQ entry array from the start of the region.
    pub cq_entries_offset: usize,
    /// Byte offset of the data region from the start of the region.
    pub data_region_offset: usize,
    /// Size of the data region in bytes.
    pub data_region_size: usize,
}

/// Round `value` up to the nearest multiple of `align`.
///
/// `align` must be a power of two.
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

impl SharedRingLayout {
    /// Compute the shared memory layout for a given data region size.
    ///
    /// SQ entries are aligned to 64 bytes (cache line). The data region is
    /// aligned to 4096 bytes (page boundary).
    #[must_use]
    pub const fn new(data_region_size: usize) -> Self {
        let header_size = size_of::<RingHeader>();

        // SQ entries start after the header, aligned to 64 bytes.
        let sq_entries_offset = align_up(header_size, 64);
        let sq_entries_size = RING_SIZE * size_of::<SqEntry>();

        // CQ entries follow SQ entries (SqEntry is 64-byte aligned, so CQ is
        // naturally aligned for its 32-byte entries).
        let cq_entries_offset = sq_entries_offset + sq_entries_size;
        let cq_entries_size = RING_SIZE * size_of::<CqEntry>();

        // Data region follows CQ entries, aligned to page boundary.
        let data_region_offset = align_up(cq_entries_offset + cq_entries_size, 4096);

        let total_size = data_region_offset + data_region_size;

        Self {
            total_size,
            sq_entries_offset,
            cq_entries_offset,
            data_region_offset,
            data_region_size,
        }
    }

    /// Compute the default layout using `DEFAULT_DATA_REGION_SIZE`.
    #[must_use]
    pub const fn default_layout() -> Self {
        Self::new(DEFAULT_DATA_REGION_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn sq_entry_size() {
        assert_eq!(size_of::<SqEntry>(), 128);
    }

    #[test]
    fn sq_entry_alignment() {
        assert_eq!(align_of::<SqEntry>(), 64);
    }

    #[test]
    fn cq_entry_size() {
        assert_eq!(size_of::<CqEntry>(), 32);
    }

    #[test]
    fn ring_size_is_power_of_two() {
        assert!(RING_SIZE.is_power_of_two());
    }

    #[test]
    fn ring_mask_matches_ring_size() {
        assert_eq!(RING_MASK, RING_SIZE - 1);
    }

    #[test]
    fn default_layout_sections_dont_overlap() {
        let layout = SharedRingLayout::default_layout();

        let header_end = size_of::<RingHeader>();
        assert!(
            layout.sq_entries_offset >= header_end,
            "SQ entries ({}) must start at or after header end ({})",
            layout.sq_entries_offset,
            header_end,
        );

        let sq_entries_end = layout.sq_entries_offset + RING_SIZE * size_of::<SqEntry>();
        assert!(
            layout.cq_entries_offset >= sq_entries_end,
            "CQ entries ({}) must start at or after SQ entries end ({})",
            layout.cq_entries_offset,
            sq_entries_end,
        );

        let cq_entries_end = layout.cq_entries_offset + RING_SIZE * size_of::<CqEntry>();
        assert!(
            layout.data_region_offset >= cq_entries_end,
            "Data region ({}) must start at or after CQ entries end ({})",
            layout.data_region_offset,
            cq_entries_end,
        );
    }

    #[test]
    fn layout_data_region_is_page_aligned() {
        let layout = SharedRingLayout::default_layout();
        assert_eq!(
            layout.data_region_offset % 4096,
            0,
            "data_region_offset ({}) must be page-aligned",
            layout.data_region_offset,
        );
    }

    #[test]
    fn layout_sq_entries_are_cache_line_aligned() {
        let layout = SharedRingLayout::default_layout();
        assert_eq!(
            layout.sq_entries_offset % 64,
            0,
            "sq_entries_offset ({}) must be cache-line aligned",
            layout.sq_entries_offset,
        );
    }

    #[test]
    fn layout_with_custom_data_size() {
        let eight_mib = 8 * 1024 * 1024;
        let layout = SharedRingLayout::new(eight_mib);
        assert_eq!(layout.data_region_size, eight_mib);
    }

    #[test]
    fn pipe_zone_fits_in_default_data_region() {
        let end = PIPE_ZONE_BASE_OFFSET + MAX_PIPE_SLOTS * PIPE_SLOT_SIZE;
        assert!(
            end <= DEFAULT_DATA_REGION_SIZE,
            "pipe zone end ({end}) exceeds data region size ({DEFAULT_DATA_REGION_SIZE})"
        );
    }

    #[test]
    fn pipe_data_capacity_is_power_of_two() {
        assert!(PIPE_DATA_CAPACITY.is_power_of_two());
    }

    #[test]
    fn shmem_pipe_header_size() {
        assert_eq!(size_of::<ShmemPipeHeader>(), 64);
    }

    #[test]
    fn pipe_slot_size_matches_header_plus_data() {
        assert_eq!(
            PIPE_SLOT_SIZE,
            size_of::<ShmemPipeHeader>() + PIPE_DATA_CAPACITY
        );
    }
}
