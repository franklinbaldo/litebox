// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform-side implementation of the [`litebox_service_heki::HekiEnforcer`]
//! port: the bridge between the HEKI/HVCI algorithms and the platform's
//! enforcement primitives (VTL0 access, frame protection, hypercalls).

use alloc::vec::Vec;
use litebox::utils::TruncateExt;
use litebox_common_linux::errno::Errno;
use litebox_common_linux::physical_pointers::PhysConstPtr;
use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{MemAttr, PAGE_SIZE, VsmError, VsmFunction};
use litebox_service_heki::{
    EnforceError, FrameTxn, HekiEnforcer, HekiState, ReservationStatus, ValidatedTextPatch,
    mshv_vsm_allocate_ringbuffer_memory, mshv_vsm_copy_secondary_key, mshv_vsm_end_of_boot,
    mshv_vsm_free_guest_module_init, mshv_vsm_kexec_validate, mshv_vsm_load_kdata,
    mshv_vsm_lock_regs, mshv_vsm_patch_text, mshv_vsm_protect_memory,
    mshv_vsm_set_platform_root_key, mshv_vsm_unload_guest_module, mshv_vsm_validate_guest_module,
};
use spin::Once;
use x86_64::{
    PhysAddr,
    structures::paging::{Size4KiB, frame::PhysFrameRange},
};
use zerocopy::FromBytes;

use crate::mshv::HvPageProtFlags;
use crate::mshv::PrivilegedVtl0PhysMutPtr;
use crate::mshv::vsm::{
    FrameReservation, mshv_vsm_boot_aps, mshv_vsm_enable_aps, protect_physical_memory_range,
};

/// A guarded, read-only physical pointer into foreign (VTL0) physical memory.
type Vtl0PhysConstPtr<T, const ALIGN: usize> = PhysConstPtr<T, ALIGN, crate::Vmap>;

/// Zero-sized live adapter implementing [`HekiEnforcer`] over the platform's
/// enforcement primitives.
///
/// Crate-private on purpose: it is constructed only by [`vsm_dispatch`], which
/// reaches these privileged operations (text patching, frame protection) only
/// after the HEKI validation and end-of-boot policy. Exposing it would let
/// external crates bypass that policy.
pub(crate) struct PlatformHekiEnforcer;

/// Restricted transaction handle handed to a `protect_frames_transactionally`
/// closure. Wraps the private platform [`FrameReservation`] guard so the runner
/// can never hold or leak a reservation across the boundary.
struct PlatformFrameTxn<'a> {
    guard: &'a mut FrameReservation,
}

/// Map a platform reservation status to the port's status enum.
fn map_status(status: crate::mshv::vsm::ReservationStatus) -> ReservationStatus {
    match status {
        crate::mshv::vsm::ReservationStatus::New => ReservationStatus::New,
        crate::mshv::vsm::ReservationStatus::AlreadyOwned => ReservationStatus::AlreadyOwned,
    }
}

impl FrameTxn for PlatformFrameTxn<'_> {
    fn reserve(
        &mut self,
        ranges: &[PhysFrameRange<Size4KiB>],
    ) -> Result<Vec<ReservationStatus>, VsmError> {
        let statuses = self.guard.reserve(ranges.iter().copied())?;
        Ok(statuses.into_iter().map(map_status).collect())
    }

    fn protect(&mut self, range: PhysFrameRange<Size4KiB>, attr: MemAttr) -> Result<(), VsmError> {
        protect_physical_memory_range(range, heki_mem_attr_to_hv_page_prot_flags(attr))
    }
}

impl HekiEnforcer for PlatformHekiEnforcer {
    fn read_vtl0<T: FromBytes>(&self, pa: usize) -> Result<T, EnforceError> {
        let ptr = Vtl0PhysConstPtr::<T, PAGE_SIZE>::with_usize(pa)
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        let boxed = ptr
            .read_at_offset(0)
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        Ok(*boxed)
    }

    fn read_vtl0_pages<T: FromBytes>(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
    ) -> Result<T, EnforceError> {
        let ptr = Vtl0PhysConstPtr::<T, PAGE_SIZE>::new(pages, offset)
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        let boxed = ptr
            .read_at_offset(0)
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        Ok(*boxed)
    }

    fn read_vtl0_bytes(&self, pa: usize, out: &mut [u8]) -> Result<(), EnforceError> {
        let ptr = Vtl0PhysConstPtr::<u8, PAGE_SIZE>::with_contiguous_pages(pa, out.len())
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        ptr.read_slice_at_offset(0, out)
            .map_err(|_| EnforceError::Vtl0ReadFailed)
    }

    fn read_vtl0_bytes_pages(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), EnforceError> {
        let ptr = Vtl0PhysConstPtr::<u8, PAGE_SIZE>::new(pages, offset)
            .map_err(|_| EnforceError::Vtl0ReadFailed)?;
        ptr.read_slice_at_offset(0, out)
            .map_err(|_| EnforceError::Vtl0ReadFailed)
    }

    fn protect_frames_transactionally(
        &self,
        initial: &[PhysFrameRange<Size4KiB>],
        f: &mut dyn FnMut(&mut dyn FrameTxn) -> Result<(), VsmError>,
    ) -> Result<(), VsmError> {
        let mut guard = FrameReservation::new();
        guard.reserve(initial.iter().copied())?;
        let mut txn = PlatformFrameTxn { guard: &mut guard };
        let result = f(&mut txn);
        if result.is_ok() {
            txn.guard.commit();
        }
        // On `Err`, `guard` drops uncommitted, rolling back every reserved range.
        result
    }

    fn unprotect_frames(&self, range: PhysFrameRange<Size4KiB>) -> Result<(), VsmError> {
        crate::mshv::vsm::unprotect_physical_memory_range(range)
    }

    fn apply_validated_text_patch(&self, patch: &ValidatedTextPatch) -> Result<(), VsmError> {
        let ptr = PrivilegedVtl0PhysMutPtr::<u8, PAGE_SIZE>::new(patch.pages(), patch.offset())
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        ptr.write_slice_at_offset(0, patch.bytes())
            .map_err(|_| VsmError::Vtl0CopyFailed)
    }

    fn protect_frame(
        &self,
        range: PhysFrameRange<Size4KiB>,
        attr: MemAttr,
    ) -> Result<(), VsmError> {
        crate::mshv::vsm::protect_physical_memory_range(
            range,
            heki_mem_attr_to_hv_page_prot_flags(attr),
        )
    }

    fn install_ringbuffer(&self, pa: u64, size: usize) -> Result<(), VsmError> {
        crate::mshv::log_ringbuffer::set_log_ringbuffer(PhysAddr::new(pa), size);
        Ok(())
    }

    fn set_platform_root_key(&self, key: &[u8]) -> Result<(), VsmError> {
        crate::host::set_platform_root_key(key);
        Ok(())
    }

    fn lock_control_registers(&self) -> Result<(), VsmError> {
        crate::mshv::vsm::lock_control_registers()
    }
}

/// Maps a HEKI [`MemAttr`] permission set to the corresponding Hyper-V
/// page-protection flags.
pub(crate) fn heki_mem_attr_to_hv_page_prot_flags(attr: MemAttr) -> HvPageProtFlags {
    let mut flags = HvPageProtFlags::empty();
    if attr.contains(MemAttr::MEM_ATTR_READ) {
        flags.set(HvPageProtFlags::HV_PAGE_READABLE, true);
        flags.set(HvPageProtFlags::HV_PAGE_USER_EXECUTABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_WRITE) {
        flags.set(HvPageProtFlags::HV_PAGE_WRITABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_EXEC) {
        flags.set(HvPageProtFlags::HV_PAGE_EXECUTABLE, true);
    }
    flags
}

// VSM dispatch — composition glue. Owns the `HekiState`, wires the
// `PlatformHekiEnforcer` adapter into the `litebox_service_heki` algorithms, and
// calls the VSM-core functions in `mshv::vsm` directly. Stays in the platform
// for now; a follow-up relocates this composition root into the runner.

/// The single long-lived HEKI algorithm state, initialized on first use.
static HEKI_STATE: Once<HekiState> = Once::new();

/// Returns the process-wide [`HekiState`], initializing it on first access.
fn heki_state() -> &'static HekiState {
    HEKI_STATE.call_once(HekiState::new)
}

/// Dispatch a VSM function to its handler and return the result.
///
/// Policy functions are delegated to `litebox_service_heki` through the
/// `PlatformHekiEnforcer` adapter; VSM-core functions call into `mshv::vsm`.
/// The `LockRegs` end-of-boot guard reads the platform-owned `HekiState`.
pub fn vsm_dispatch(func_id: VsmFunction, params: &[u64]) -> i64 {
    let enforcer = PlatformHekiEnforcer;
    let state = heki_state();
    let result: Result<i64, VsmError> = match func_id {
        VsmFunction::EnableAPsVtl => mshv_vsm_enable_aps(params[0]),
        VsmFunction::BootAPs => mshv_vsm_boot_aps(params[0]),
        VsmFunction::LockRegs => mshv_vsm_lock_regs(&enforcer, state),
        VsmFunction::SignalEndOfBoot => Ok(mshv_vsm_end_of_boot(state)),
        VsmFunction::ProtectMemory => {
            mshv_vsm_protect_memory(&enforcer, state, params[0], params[1])
        }
        VsmFunction::LoadKData => mshv_vsm_load_kdata(&enforcer, state, params[0], params[1]),
        VsmFunction::ValidateModule => {
            mshv_vsm_validate_guest_module(&enforcer, state, params[0], params[1], params[2])
        }
        #[allow(clippy::cast_possible_wrap)]
        VsmFunction::FreeModuleInit => {
            mshv_vsm_free_guest_module_init(&enforcer, state, params[0] as i64)
        }
        #[allow(clippy::cast_possible_wrap)]
        VsmFunction::UnloadModule => {
            mshv_vsm_unload_guest_module(&enforcer, state, params[0] as i64)
        }
        VsmFunction::CopySecondaryKey => mshv_vsm_copy_secondary_key(params[0], params[1]),
        VsmFunction::KexecValidate => {
            mshv_vsm_kexec_validate(&enforcer, state, params[0], params[1], params[2])
        }
        VsmFunction::PatchText => mshv_vsm_patch_text(&enforcer, state, params[0], params[1]),
        VsmFunction::AllocateRingbufferMemory => {
            let size: usize = params[1].trunc();
            mshv_vsm_allocate_ringbuffer_memory(&enforcer, state, params[0], size)
        }
        VsmFunction::SetPlatformRootKey => {
            mshv_vsm_set_platform_root_key(&enforcer, state, params[0])
        }
        VsmFunction::OpteeMessage => Err(VsmError::OperationNotSupported("OP-TEE communication")),
    };
    match result {
        Ok(value) => value,
        Err(e) => Errno::from(e).as_neg().into(),
    }
}
