// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! HEKI/HVCI algorithms and the `HekiEnforcer` port.
//!
//! This crate holds the host-testable HEKI/HVCI *algorithms* (what to validate,
//! crypto, ELF parsing, which frames to protect, which patches to apply) and the
//! `HekiEnforcer` trait — the "port" through which those algorithms reach the
//! platform. The algorithms are generic over `HekiEnforcer`, so a mock
//! implementation can unit-test HEKI/HVCI logic on the host with plain byte
//! buffers, with no real LVBS platform and no Hyper-V.
//!
//! This is hexagonal architecture: `HekiEnforcer` is the port (defined here with
//! the algorithms); the platform provides the adapter (the real implementation);
//! the runner is the composition root that wires them together.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{HekiPatch, MemAttr, PAGE_SIZE, VsmError};
use x86_64::structures::paging::{Size4KiB, frame::PhysFrameRange};
use zerocopy::FromBytes;

/// Error returned by enforcer read operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforceError {
    /// A VTL0 physical read failed (bad address, unmapped, etc.).
    Vtl0ReadFailed,
    /// A one-time security resource was already initialized.
    AlreadyInitialized,
}

/// Outcome of reserving a physical frame range within a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationStatus {
    /// The range was newly reserved by this transaction.
    New,
    /// The range was already owned by the protected-frame registry.
    AlreadyOwned,
}

/// Restricted handle handed to a `protect_frames_transactionally` closure.
///
/// The only way to reserve/protect frames; the concrete reservation guard stays
/// private in the platform adapter.
pub trait FrameTxn {
    /// Reserve the given physical frame ranges within this transaction,
    /// returning the reservation status of each range.
    fn reserve(
        &mut self,
        ranges: &[PhysFrameRange<Size4KiB>],
    ) -> Result<Vec<ReservationStatus>, VsmError>;

    /// Apply the given memory attributes to a reserved physical frame range.
    fn protect(&mut self, range: PhysFrameRange<Size4KiB>, attr: MemAttr) -> Result<(), VsmError>;
}

/// The platform-enforcement port. HEKI/HVCI algorithms are generic over this.
///
/// A mock implementation enables host unit testing without a real LVBS platform.
pub trait HekiEnforcer {
    /// Read a `FromBytes` value from the given VTL0 physical address (guarded).
    fn read_vtl0<T: FromBytes>(&self, pa: usize) -> Result<T, EnforceError>;

    /// Read a `FromBytes` value spanning the given VTL0 physical pages, starting
    /// at `offset` within the mapped page span (guarded).
    fn read_vtl0_pages<T: FromBytes>(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
    ) -> Result<T, EnforceError>;

    /// Read bytes from the given VTL0 physical address into `out` (guarded).
    fn read_vtl0_bytes(&self, pa: usize, out: &mut [u8]) -> Result<(), EnforceError>;

    /// Read bytes spanning the given VTL0 physical pages, starting at `offset`
    /// within the mapped page span, into `out` (guarded).
    fn read_vtl0_bytes_pages(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), EnforceError>;

    /// Reserve `initial` frames, run `f` (which may reserve/protect more via the
    /// `FrameTxn` handle), then commit on `Ok` or roll back on `Err`.
    fn protect_frames_transactionally(
        &self,
        initial: &[PhysFrameRange<Size4KiB>],
        f: &mut dyn FnMut(&mut dyn FrameTxn) -> Result<(), VsmError>,
    ) -> Result<(), VsmError>;

    /// Apply a HEKI text patch that the caller has already validated against
    /// VTL1's precomputed patch data, via the privileged VTL0 writer.
    fn apply_text_patch(&self, patch: &HekiPatch) -> Result<(), VsmError>;

    /// Install the debug ring buffer. Returns `Err` if already installed.
    fn install_ringbuffer(&self, pa: u64, size: usize) -> Result<(), VsmError>;

    /// Install the platform root key. Returns `Err` if already installed.
    fn set_platform_root_key(&self, key: &[u8]) -> Result<(), VsmError>;
}
