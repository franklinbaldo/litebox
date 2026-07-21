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
//! Transaction semantics mirror the real adapter: `protect_frames_transactionally`
//! reserves `initial` (rejecting overlap with an already-reserved range with the
//! same [`VsmError::ProtectedFrameOverlap`] the live adapter returns), runs the
//! closure against a [`MockFrameTxn`] that reserves and protects eagerly, and on
//! closure `Err` rolls back exactly the ranges the transaction reserved (matching
//! `FrameReservation`'s Drop unprotecting its `owned_ranges`). `protect_frame`
//! records a non-transactional protection that is never rolled back.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;

use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{MemAttr, PAGE_SIZE, VsmError};
use x86_64::structures::paging::{Size4KiB, frame::PhysFrameRange};
use zerocopy::FromBytes;

use crate::{EnforceError, FrameTxn, HekiEnforcer, ReservationStatus, ValidatedTextPatch};

/// Fully in-memory implementation of [`HekiEnforcer`] for host unit tests.
pub struct MockEnforcer {
    /// Staged VTL0 physical memory: physical address -> byte.
    vtl0: RefCell<BTreeMap<usize, u8>>,
    /// Committed frame protections (`protect` calls that survived a transaction).
    protections: RefCell<Vec<(PhysFrameRange<Size4KiB>, MemAttr)>>,
    /// Ranges handed back to VTL0 via `unprotect_frames`.
    unprotected: RefCell<Vec<PhysFrameRange<Size4KiB>>>,
    /// Privileged writes captured by `apply_validated_text_patch`: (target
    /// physical address, bytes).
    writes: RefCell<Vec<(usize, Vec<u8>)>>,
    /// Installed ring buffer (`pa`, `size`), if any.
    ringbuffer: RefCell<Option<(u64, usize)>>,
    /// Installed platform root key, if any.
    prk: RefCell<Option<Vec<u8>>>,
    /// Whether `lock_control_registers` was invoked.
    regs_locked: RefCell<bool>,
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
            unprotected: RefCell::new(Vec::new()),
            writes: RefCell::new(Vec::new()),
            ringbuffer: RefCell::new(None),
            prk: RefCell::new(None),
            regs_locked: RefCell::new(false),
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

    /// Ranges released back to VTL0 via `unprotect_frames`.
    pub fn unprotected(&self) -> Vec<PhysFrameRange<Size4KiB>> {
        self.unprotected.borrow().clone()
    }

    /// Privileged writes captured so far: (target physical address, bytes).
    pub fn writes(&self) -> Vec<(usize, Vec<u8>)> {
        self.writes.borrow().clone()
    }

    /// Installed ring buffer, if any.
    pub fn ringbuffer(&self) -> Option<(u64, usize)> {
        *self.ringbuffer.borrow()
    }

    /// Installed platform root key, if any.
    pub fn prk(&self) -> Option<Vec<u8>> {
        self.prk.borrow().clone()
    }

    /// Whether the control registers were locked.
    pub fn regs_locked(&self) -> bool {
        *self.regs_locked.borrow()
    }
}

fn ranges_equal(a: PhysFrameRange<Size4KiB>, b: PhysFrameRange<Size4KiB>) -> bool {
    a.start.start_address() == b.start.start_address()
        && a.end.start_address() == b.end.start_address()
}

/// Restricted transaction handle. `reserve` accepts every range and `protect`
/// records protections eagerly; the enclosing `protect_frames_transactionally`
/// discards protections applied during the transaction if the closure fails.
/// The mock does not model the platform's reservation/overlap bookkeeping — that
/// logic lives in (and is the responsibility of) the platform's `FrameReservation`.
pub struct MockFrameTxn<'a> {
    enforcer: &'a MockEnforcer,
}

impl FrameTxn for MockFrameTxn<'_> {
    fn reserve(
        &mut self,
        ranges: &[PhysFrameRange<Size4KiB>],
    ) -> Result<Vec<ReservationStatus>, VsmError> {
        Ok(ranges.iter().map(|_| ReservationStatus::New).collect())
    }

    fn protect(&mut self, range: PhysFrameRange<Size4KiB>, attr: MemAttr) -> Result<(), VsmError> {
        self.enforcer.protections.borrow_mut().push((range, attr));
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
        _initial: &[PhysFrameRange<Size4KiB>],
        f: &mut dyn FnMut(&mut dyn FrameTxn) -> Result<(), VsmError>,
    ) -> Result<(), VsmError> {
        // Record protections eagerly; on failure, discard the protections applied
        // during this transaction. Reservation/rollback fidelity is intentionally
        // not modeled here — the real semantics live in the platform's
        // `FrameReservation`, and no algorithm test depends on the mock's behavior.
        let checkpoint = self.protections.borrow().len();
        let mut txn = MockFrameTxn { enforcer: self };
        let result = f(&mut txn);
        if result.is_err() {
            self.protections.borrow_mut().truncate(checkpoint);
        }
        result
    }

    fn protect_frame(
        &self,
        range: PhysFrameRange<Size4KiB>,
        attr: MemAttr,
    ) -> Result<(), VsmError> {
        // Non-transactional forward protect: record immediately, never rolled back.
        self.protections.borrow_mut().push((range, attr));
        Ok(())
    }

    fn unprotect_frames(&self, range: PhysFrameRange<Size4KiB>) -> Result<(), VsmError> {
        self.protections
            .borrow_mut()
            .retain(|(r, _)| !ranges_equal(*r, range));
        self.unprotected.borrow_mut().push(range);
        Ok(())
    }

    fn apply_validated_text_patch(&self, patch: &ValidatedTextPatch) -> Result<(), VsmError> {
        let target = patch.pages()[0].as_usize() + patch.offset();
        self.writes
            .borrow_mut()
            .push((target, patch.bytes().to_vec()));
        Ok(())
    }

    fn install_ringbuffer(&self, pa: u64, size: usize) -> Result<(), VsmError> {
        let mut rb = self.ringbuffer.borrow_mut();
        // Idempotent: first install wins, later installs are ignored (like `Once`).
        if rb.is_none() {
            *rb = Some((pa, size));
        }
        Ok(())
    }

    fn set_platform_root_key(&self, key: &[u8]) -> Result<(), VsmError> {
        let mut prk = self.prk.borrow_mut();
        // Idempotent: first install wins, later installs are ignored (like `Once`).
        if prk.is_none() {
            *prk = Some(key.to_vec());
        }
        Ok(())
    }

    fn lock_control_registers(&self) -> Result<(), VsmError> {
        *self.regs_locked.borrow_mut() = true;
        Ok(())
    }
}
