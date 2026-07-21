// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! HEKI/HVCI algorithms and the `HekiEnforcer` port.
//!
//! Holds the HEKI/HVCI *algorithms* (module/kexec validation, text patching,
//! kernel-data load, signature/ELF checks) and the `HekiEnforcer` trait — the
//! port through which they reach the platform. The algorithms are generic over
//! `HekiEnforcer`: the platform provides the real adapter, and the trait is the
//! seam that lets the logic be exercised on the host without an LVBS platform.

#![no_std]

extern crate alloc;

pub mod mem_integrity;
pub mod vsm;

pub use vsm::{
    HekiState, ValidatedTextPatch, mshv_vsm_allocate_ringbuffer_memory,
    mshv_vsm_copy_secondary_key, mshv_vsm_end_of_boot, mshv_vsm_free_guest_module_init,
    mshv_vsm_kexec_validate, mshv_vsm_load_kdata, mshv_vsm_lock_regs, mshv_vsm_patch_text,
    mshv_vsm_protect_memory, mshv_vsm_set_platform_root_key, mshv_vsm_unload_guest_module,
    mshv_vsm_validate_guest_module,
};

use alloc::vec::Vec;
use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{MemAttr, PAGE_SIZE, VsmError};
use x86_64::structures::paging::{Size4KiB, frame::PhysFrameRange};
use zerocopy::FromBytes;

/// Error returned by enforcer read operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforceError {
    /// A VTL0 physical read failed (bad address, unmapped, etc.).
    Vtl0ReadFailed,
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
// TODO: add a mock implementation to enable host testing without a real LVBS platform.
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

    /// Protect a single physical frame range with `attr`, outside any transaction
    /// (no rollback). For forward protects on frames not part of a reserve/commit flow.
    fn protect_frame(&self, range: PhysFrameRange<Size4KiB>, attr: MemAttr)
    -> Result<(), VsmError>;

    /// Unprotect (release) a previously protected/committed physical frame range,
    /// returning it to VTL0's control. Standalone — not part of any transaction.
    fn unprotect_frames(&self, range: PhysFrameRange<Size4KiB>) -> Result<(), VsmError>;

    /// Apply a [`ValidatedTextPatch`] to VTL0 text through the privileged mapping
    /// that bypasses protected-frame checks.
    ///
    /// The [`ValidatedTextPatch`] capability is proof the destination was checked
    /// against VTL1's precomputed HEKI patch data: it is constructible only after
    /// a successful validation, so this method cannot be invoked with an
    /// unvalidated destination.
    fn apply_validated_text_patch(&self, patch: &ValidatedTextPatch) -> Result<(), VsmError>;

    /// Install the log ring buffer. Succeeds idempotently (first install wins).
    fn install_ringbuffer(&self, pa: u64, size: usize) -> Result<(), VsmError>;

    /// Install the platform root key. Succeeds idempotently (first install wins).
    fn set_platform_root_key(&self, key: &[u8]) -> Result<(), VsmError>;

    /// Lock the control registers HEKI protects from VTL0 modification. The
    /// specific register set is a platform enforcement detail; HEKI decides when
    /// to invoke this.
    fn lock_control_registers(&self) -> Result<(), VsmError>;
}
