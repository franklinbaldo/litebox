// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Submission queue (SQ) producer/consumer operations.
//!
//! The SQ is multi-producer (multiple guest threads) and single-consumer
//! (central's worker thread).

use core::hint::spin_loop;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

use crate::ring::{RING_MASK, RING_SIZE, RingHeader, SqEntry};

/// Acquire an SQ slot by advancing `sq_tail` with a CAS loop.
///
/// If the ring is full (`tail - head >= RING_SIZE`), this function spins until
/// a slot becomes available.
///
/// # Returns
///
/// The masked slot index (`tail & RING_MASK`) for the acquired entry.
///
/// # Safety
///
/// The caller must ensure that the `SqEntry` at the returned index is not
/// concurrently in use by another producer that hasn't yet published it.
pub unsafe fn sq_acquire_slot(header: &RingHeader) -> u64 {
    loop {
        let tail = header.sq_tail.load(Acquire);
        let head = header.sq_head.load(Acquire);

        // Spin if the ring is full.
        if tail.wrapping_sub(head) >= RING_SIZE as u64 {
            spin_loop();
            continue;
        }

        // Try to claim this slot by advancing tail.
        if header
            .sq_tail
            .compare_exchange_weak(tail, tail + 1, Release, Relaxed)
            .is_ok()
        {
            #[allow(clippy::cast_possible_truncation)] // masked to RING_MASK (8 bits)
            return (tail as usize & RING_MASK) as u64;
        }

        // CAS failed — another producer beat us; retry.
        spin_loop();
    }
}

/// Publish an SQ entry by setting its ready flag.
///
/// This must be called after all other fields in the entry have been written.
/// Uses `Release` ordering so that all preceding field writes are visible to
/// the consumer before it observes the ready flag.
pub fn sq_publish(entry: &SqEntry) {
    entry.ready.store(1, Release);
}

/// Check whether an SQ entry is ready for consumption.
///
/// Uses `Acquire` ordering so that all field writes performed before the
/// producer's `Release` store of the ready flag are visible to the consumer.
///
/// Returns `true` if the entry is ready.
pub fn sq_try_consume(entry: &SqEntry) -> bool {
    entry.ready.load(Acquire) != 0
}

/// Advance the SQ head after consuming an entry.
///
/// Clears the entry's ready flag (Release) and then increments `sq_head`
/// (Release) to make the slot available for reuse by producers.
pub fn sq_advance_head(header: &RingHeader, entry: &SqEntry) {
    entry.ready.store(0, Release);
    header.sq_head.fetch_add(1, Release);
}

/// Load the current SQ head position.
///
/// Uses `Acquire` ordering to synchronise with the consumer's `Release` store
/// when advancing the head.
pub fn sq_head_index(header: &RingHeader) -> u64 {
    header.sq_head.load(Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a zero-initialized `RingHeader`. This is valid because all fields
    /// are atomics, and zero is a valid initial value for them.
    fn zeroed_header() -> RingHeader {
        unsafe { core::mem::zeroed() }
    }

    /// Create a zero-initialized `SqEntry`.
    fn zeroed_sq_entry() -> SqEntry {
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn acquire_slot_returns_sequential_indices() {
        let header = zeroed_header();
        // SAFETY: header is valid and no concurrent producers.
        let idx0 = unsafe { sq_acquire_slot(&header) };
        let idx1 = unsafe { sq_acquire_slot(&header) };
        let idx2 = unsafe { sq_acquire_slot(&header) };
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);
    }

    #[test]
    fn publish_sets_ready_flag() {
        let entry = zeroed_sq_entry();
        assert_eq!(entry.ready.load(core::sync::atomic::Ordering::Relaxed), 0);
        sq_publish(&entry);
        assert_eq!(entry.ready.load(core::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn try_consume_when_not_ready() {
        let entry = zeroed_sq_entry();
        assert!(!sq_try_consume(&entry));
    }

    #[test]
    fn try_consume_when_ready() {
        let entry = zeroed_sq_entry();
        sq_publish(&entry);
        assert!(sq_try_consume(&entry));
    }

    #[test]
    fn advance_head_clears_ready_and_increments_head() {
        let header = zeroed_header();
        let entry = zeroed_sq_entry();

        sq_publish(&entry);
        assert!(sq_try_consume(&entry));

        sq_advance_head(&header, &entry);
        assert_eq!(entry.ready.load(core::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(sq_head_index(&header), 1);
    }
}
