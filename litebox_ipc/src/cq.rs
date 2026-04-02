// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Completion queue (CQ) producer/consumer operations.
//!
//! The CQ is single-producer (central) and multi-consumer (guest threads
//! reading their own entries).

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::{Acquire, Release};

use crate::ring::{CqEntry, RING_MASK, RingHeader};

/// Push a completion entry onto the CQ.
///
/// Writes `entry` at the current `cq_tail` slot and then advances `cq_tail`
/// with `Release` ordering so that consumers observe the fully written entry.
///
/// # Safety
///
/// - `cq_entries` must point to a valid array of at least `RING_SIZE` entries
///   in the shared memory region.
/// - The caller must be the sole producer (single-producer discipline).
pub unsafe fn cq_push(header: &RingHeader, cq_entries: *mut CqEntry, entry: CqEntry) {
    let tail = header.cq_tail.load(Acquire);
    #[allow(clippy::cast_possible_truncation)] // masked to RING_MASK (8 bits)
    let idx = tail as usize & RING_MASK;

    // SAFETY: Caller guarantees `cq_entries` is valid and `idx < RING_SIZE`.
    unsafe {
        cq_entries.add(idx).write(entry);
    }

    header.cq_tail.store(tail + 1, Release);
}

/// Increment a thread's CQ notification slot and return a reference to it.
///
/// Uses `fetch_add(1, Release)` so that the guest thread observing the new
/// value (via `Acquire`) also sees all preceding CQ writes.
///
/// The caller typically follows this with a futex-wake on the returned
/// `AtomicU32`.
pub fn cq_notify_thread(header: &RingHeader, thread_slot: u16) -> &AtomicU32 {
    let slot = &header.cq_notify_slots[thread_slot as usize];
    slot.fetch_add(1, Release);
    slot
}

/// Scan the CQ for a completion entry matching `target_seq`.
///
/// Searches entries from `start_index` (inclusive) up to the current `cq_tail`
/// (exclusive). Returns the first entry whose `seq` field matches
/// `target_seq`, or `None` if no match is found.
///
/// # Safety
///
/// - `cq_entries` must point to a valid array of at least `RING_SIZE` entries
///   in the shared memory region.
/// - The caller must ensure that the entries being scanned are not
///   concurrently overwritten.
pub unsafe fn cq_find_by_seq(
    header: &RingHeader,
    cq_entries: *const CqEntry,
    start_index: u64,
    target_seq: u64,
) -> Option<CqEntry> {
    let tail = header.cq_tail.load(Acquire);
    let mut i = start_index;

    while i < tail {
        #[allow(clippy::cast_possible_truncation)] // masked to RING_MASK (8 bits)
        let idx = i as usize & RING_MASK;
        // SAFETY: Caller guarantees `cq_entries` is valid and `idx < RING_SIZE`.
        let entry = unsafe { *cq_entries.add(idx) };
        if entry.seq == target_seq {
            return Some(entry);
        }
        i += 1;
    }

    None
}

/// Load the current CQ tail position.
///
/// Uses `Acquire` ordering to synchronise with the producer's `Release` store
/// when advancing the tail.
pub fn cq_tail(header: &RingHeader) -> u64 {
    header.cq_tail.load(Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring::RING_SIZE;

    /// Create a zero-initialized `RingHeader`.
    fn zeroed_header() -> RingHeader {
        unsafe { core::mem::zeroed() }
    }

    /// Create a zero-initialized `CqEntry`.
    fn zeroed_cq_entry() -> CqEntry {
        CqEntry {
            seq: 0,
            result: 0,
            flags: 0,
            thread_slot: 0,
            _pad: [0; 4],
            data_offset: 0,
            data_len: 0,
        }
    }

    #[test]
    fn push_and_find_single_entry() {
        let header = zeroed_header();
        let zero = zeroed_cq_entry();
        let mut cq_entries = [zero; RING_SIZE];

        let entry = CqEntry {
            seq: 42,
            result: 100,
            flags: 0,
            thread_slot: 3,
            _pad: [0; 4],
            data_offset: 0,
            data_len: 0,
        };

        // SAFETY: cq_entries is a valid array of RING_SIZE entries.
        unsafe { cq_push(&header, cq_entries.as_mut_ptr(), entry) };

        let found = unsafe { cq_find_by_seq(&header, cq_entries.as_ptr(), 0, 42) };
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.seq, 42);
        assert_eq!(found.result, 100);
        assert_eq!(found.thread_slot, 3);
    }

    #[test]
    fn find_returns_none_for_missing_seq() {
        let header = zeroed_header();
        let zero = zeroed_cq_entry();
        let cq_entries = [zero; RING_SIZE];

        let found = unsafe { cq_find_by_seq(&header, cq_entries.as_ptr(), 0, 999) };
        assert!(found.is_none());
    }

    #[test]
    fn notify_thread_increments_slot() {
        let header = zeroed_header();
        let slot_idx: u16 = 5;

        let slot = cq_notify_thread(&header, slot_idx);
        assert_eq!(slot.load(core::sync::atomic::Ordering::Relaxed), 1);

        let slot = cq_notify_thread(&header, slot_idx);
        assert_eq!(slot.load(core::sync::atomic::Ordering::Relaxed), 2);
    }
}
