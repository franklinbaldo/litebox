// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-memory [`HekiEnforcer`] used to host-test the HEKI/HVCI algorithms.
//!
//! [`MockEnforcer`] implements the [`crate::HekiEnforcer`] port entirely in
//! memory — no platform, no Hyper-V. VTL0 physical memory is a byte map that
//! tests stage with [`MockEnforcer::write_vtl0`]; frame protections, reservations,
//! text patches, and the one-time ring buffer / platform root key installs are
//! captured so tests can assert exactly what the algorithms would have enforced.
//!
//! Transaction semantics mirror the real adapter's intent for testability:
//! `protect_frames_transactionally` reserves `initial` (rejecting overlap with an
//! already-reserved range with the same [`VsmError::ProtectedFrameOverlap`] the
//! live adapter returns), runs the closure against a [`MockFrameTxn`], and either
//! commits every reserve/protect it recorded (closure `Ok`) or discards them all
//! (closure `Err`) so rollback is observable.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;

use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{HekiPatch, MemAttr, PAGE_SIZE, VsmError};
use x86_64::structures::paging::{Size4KiB, frame::PhysFrameRange};
use zerocopy::FromBytes;

use crate::{EnforceError, FrameTxn, HekiEnforcer, ReservationStatus};

/// Fully in-memory implementation of [`HekiEnforcer`] for host unit tests.
pub struct MockEnforcer {
    /// Staged VTL0 physical memory: physical address -> byte.
    vtl0: RefCell<BTreeMap<usize, u8>>,
    /// Committed frame protections (`protect` calls that survived a transaction).
    protections: RefCell<Vec<(PhysFrameRange<Size4KiB>, MemAttr)>>,
    /// Committed frame reservations.
    reserved: RefCell<Vec<PhysFrameRange<Size4KiB>>>,
    /// Ranges handed back to VTL0 via `unprotect_frames`.
    unprotected: RefCell<Vec<PhysFrameRange<Size4KiB>>>,
    /// Text patches that `apply_text_patch` would have written.
    patches: RefCell<Vec<HekiPatch>>,
    /// Installed ring buffer (`pa`, `size`), if any.
    ringbuffer: RefCell<Option<(u64, usize)>>,
    /// Installed platform root key, if any.
    prk: RefCell<Option<Vec<u8>>>,
}

impl Default for MockEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockEnforcer {
    pub fn new() -> Self {
        Self {
            vtl0: RefCell::new(BTreeMap::new()),
            protections: RefCell::new(Vec::new()),
            reserved: RefCell::new(Vec::new()),
            unprotected: RefCell::new(Vec::new()),
            patches: RefCell::new(Vec::new()),
            ringbuffer: RefCell::new(None),
            prk: RefCell::new(None),
        }
    }

    /// Stage `bytes` into VTL0 physical memory starting at physical address `pa`.
    pub fn write_vtl0(&self, pa: usize, bytes: &[u8]) {
        let mut mem = self.vtl0.borrow_mut();
        for (i, &b) in bytes.iter().enumerate() {
            mem.insert(pa + i, b);
        }
    }

    /// Read `len` bytes from the flat VTL0 map at physical address `pa`.
    /// Returns `None` if any byte in the range was never staged.
    fn read_flat(&self, pa: usize, len: usize) -> Option<Vec<u8>> {
        let mem = self.vtl0.borrow();
        let mut buf = Vec::with_capacity(len);
        for i in 0..len {
            buf.push(*mem.get(&(pa + i))?);
        }
        Some(buf)
    }

    /// Read `len` bytes across the virtually-contiguous span formed by `pages`,
    /// starting `offset` bytes into that span. Byte `i` of the span lives at
    /// `pages[i / PAGE_SIZE] + (i % PAGE_SIZE)`, matching the real adapter's
    /// page+offset addressing. Returns `None` if any byte was not staged or the
    /// span runs past the listed pages.
    fn read_pages(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
        len: usize,
    ) -> Option<Vec<u8>> {
        let mem = self.vtl0.borrow();
        let mut buf = Vec::with_capacity(len);
        for j in 0..len {
            let span_index = offset + j;
            let page = pages.get(span_index / PAGE_SIZE)?;
            let pa = page.as_usize() + (span_index % PAGE_SIZE);
            buf.push(*mem.get(&pa)?);
        }
        Some(buf)
    }

    // --- Inspectors used by tests ---

    /// Committed frame protections recorded so far.
    pub fn protections(&self) -> Vec<(PhysFrameRange<Size4KiB>, MemAttr)> {
        self.protections.borrow().clone()
    }

    /// Committed frame reservations recorded so far.
    pub fn reservations(&self) -> Vec<PhysFrameRange<Size4KiB>> {
        self.reserved.borrow().clone()
    }

    /// Ranges released back to VTL0 via `unprotect_frames`.
    pub fn unprotected(&self) -> Vec<PhysFrameRange<Size4KiB>> {
        self.unprotected.borrow().clone()
    }

    /// Text patches captured by `apply_text_patch`.
    pub fn patches(&self) -> Vec<HekiPatch> {
        self.patches.borrow().clone()
    }

    /// Installed ring buffer, if any.
    pub fn ringbuffer(&self) -> Option<(u64, usize)> {
        *self.ringbuffer.borrow()
    }

    /// Installed platform root key, if any.
    pub fn prk(&self) -> Option<Vec<u8>> {
        self.prk.borrow().clone()
    }
}

/// Two ranges overlap if they share any frame.
fn ranges_overlap(a: PhysFrameRange<Size4KiB>, b: PhysFrameRange<Size4KiB>) -> bool {
    let a_start = a.start.start_address().as_u64();
    let a_end = a.end.start_address().as_u64();
    let b_start = b.start.start_address().as_u64();
    let b_end = b.end.start_address().as_u64();
    a_start < b_end && b_start < a_end
}

fn ranges_equal(a: PhysFrameRange<Size4KiB>, b: PhysFrameRange<Size4KiB>) -> bool {
    a.start.start_address() == b.start.start_address()
        && a.end.start_address() == b.end.start_address()
}

/// Restricted transaction handle. Reserves/protects are held here until the
/// enclosing `protect_frames_transactionally` commits (closure `Ok`) or discards
/// them (closure `Err`).
pub struct MockFrameTxn<'a> {
    enforcer: &'a MockEnforcer,
    added_reservations: Vec<PhysFrameRange<Size4KiB>>,
    added_protections: Vec<(PhysFrameRange<Size4KiB>, MemAttr)>,
}

impl MockFrameTxn<'_> {
    /// Classify a single range against already-reserved frames (committed plus
    /// this transaction's in-flight claims), mirroring the live adapter.
    fn classify(&self, range: PhysFrameRange<Size4KiB>) -> Result<ReservationStatus, VsmError> {
        let start = range.start.start_address().as_u64();
        let end = range.end.start_address().as_u64();
        if start >= end {
            // Empty range: accepted idempotently, like the real reservation.
            return Ok(ReservationStatus::AlreadyOwned);
        }

        let committed = self.enforcer.reserved.borrow();
        let existing = committed
            .iter()
            .copied()
            .chain(self.added_reservations.iter().copied());
        for other in existing {
            if ranges_equal(other, range) {
                return Ok(ReservationStatus::AlreadyOwned);
            }
            if ranges_overlap(other, range) {
                return Err(VsmError::ProtectedFrameOverlap);
            }
        }
        Ok(ReservationStatus::New)
    }
}

impl FrameTxn for MockFrameTxn<'_> {
    fn reserve(
        &mut self,
        ranges: &[PhysFrameRange<Size4KiB>],
    ) -> Result<Vec<ReservationStatus>, VsmError> {
        let mut statuses = Vec::with_capacity(ranges.len());
        for &range in ranges {
            let status = self.classify(range)?;
            if status == ReservationStatus::New {
                self.added_reservations.push(range);
            }
            statuses.push(status);
        }
        Ok(statuses)
    }

    fn protect(&mut self, range: PhysFrameRange<Size4KiB>, attr: MemAttr) -> Result<(), VsmError> {
        self.added_protections.push((range, attr));
        Ok(())
    }
}

impl HekiEnforcer for MockEnforcer {
    fn read_vtl0<T: FromBytes>(&self, pa: usize) -> Result<T, EnforceError> {
        let buf = self
            .read_flat(pa, core::mem::size_of::<T>())
            .ok_or(EnforceError::Vtl0ReadFailed)?;
        T::read_from_bytes(&buf).map_err(|_| EnforceError::Vtl0ReadFailed)
    }

    fn read_vtl0_pages<T: FromBytes>(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
    ) -> Result<T, EnforceError> {
        let buf = self
            .read_pages(pages, offset, core::mem::size_of::<T>())
            .ok_or(EnforceError::Vtl0ReadFailed)?;
        T::read_from_bytes(&buf).map_err(|_| EnforceError::Vtl0ReadFailed)
    }

    fn read_vtl0_bytes(&self, pa: usize, out: &mut [u8]) -> Result<(), EnforceError> {
        let buf = self
            .read_flat(pa, out.len())
            .ok_or(EnforceError::Vtl0ReadFailed)?;
        out.copy_from_slice(&buf);
        Ok(())
    }

    fn read_vtl0_bytes_pages(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), EnforceError> {
        let buf = self
            .read_pages(pages, offset, out.len())
            .ok_or(EnforceError::Vtl0ReadFailed)?;
        out.copy_from_slice(&buf);
        Ok(())
    }

    fn protect_frames_transactionally(
        &self,
        initial: &[PhysFrameRange<Size4KiB>],
        f: &mut dyn FnMut(&mut dyn FrameTxn) -> Result<(), VsmError>,
    ) -> Result<(), VsmError> {
        let mut txn = MockFrameTxn {
            enforcer: self,
            added_reservations: Vec::new(),
            added_protections: Vec::new(),
        };
        // Reserve the initial set; overlap with an already-reserved range is
        // rejected before the closure runs (nothing committed).
        txn.reserve(initial)?;

        let result = f(&mut txn);
        if result.is_ok() {
            // Commit everything the transaction recorded.
            self.reserved.borrow_mut().extend(txn.added_reservations);
            self.protections.borrow_mut().extend(txn.added_protections);
        }
        // On `Err`, `txn` is dropped without committing: reserves and protects
        // added during the transaction roll back, leaving no trace.
        result
    }

    fn unprotect_frames(&self, range: PhysFrameRange<Size4KiB>) -> Result<(), VsmError> {
        self.protections
            .borrow_mut()
            .retain(|(r, _)| !ranges_equal(*r, range));
        self.reserved
            .borrow_mut()
            .retain(|r| !ranges_equal(*r, range));
        self.unprotected.borrow_mut().push(range);
        Ok(())
    }

    fn apply_text_patch(&self, patch: &HekiPatch) -> Result<(), VsmError> {
        self.patches.borrow_mut().push(*patch);
        Ok(())
    }

    fn install_ringbuffer(&self, pa: u64, size: usize) -> Result<(), VsmError> {
        let mut rb = self.ringbuffer.borrow_mut();
        if rb.is_some() {
            return Err(VsmError::AlreadyInitialized("ring buffer"));
        }
        *rb = Some((pa, size));
        Ok(())
    }

    fn set_platform_root_key(&self, key: &[u8]) -> Result<(), VsmError> {
        let mut prk = self.prk.borrow_mut();
        if prk.is_some() {
            return Err(VsmError::AlreadyInitialized("platform root key"));
        }
        *prk = Some(key.to_vec());
        Ok(())
    }
}
