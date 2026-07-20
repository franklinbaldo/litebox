// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VSM dispatch: the runner is the composition root. It owns the single
//! long-lived [`HekiState`] and a [`PlatformHekiEnforcer`] instance, dispatches
//! policy VSM functions to the `litebox_heki` algorithms (generic over the
//! `HekiEnforcer` port), and forwards the VSM-core arms
//! (`EnableAPsVtl`/`BootAPs`/`LockRegs`) directly to the platform.

use litebox::utils::TruncateExt;
use litebox_common_linux::errno::Errno;
use litebox_common_lvbs::{VsmError, VsmFunction};
use litebox_heki::{
    HekiState, mshv_vsm_allocate_ringbuffer_memory, mshv_vsm_copy_secondary_key,
    mshv_vsm_end_of_boot, mshv_vsm_free_guest_module_init, mshv_vsm_kexec_validate,
    mshv_vsm_load_kdata, mshv_vsm_patch_text, mshv_vsm_protect_memory,
    mshv_vsm_set_platform_root_key, mshv_vsm_unload_guest_module, mshv_vsm_validate_guest_module,
};
use litebox_platform_lvbs::heki_enforcer::PlatformHekiEnforcer;
use litebox_platform_lvbs::mshv::vsm::{
    mshv_vsm_boot_aps, mshv_vsm_enable_aps, mshv_vsm_lock_regs,
};
use spin::Once;

/// The single long-lived HEKI algorithm state, initialized on first use.
static HEKI_STATE: Once<HekiState> = Once::new();

/// Returns the process-wide [`HekiState`], initializing it on first access.
fn heki_state() -> &'static HekiState {
    HEKI_STATE.call_once(HekiState::new)
}

/// VSM function dispatcher for policy (and platform-subset) functions.
pub(crate) fn vsm_dispatch(func_id: VsmFunction, params: &[u64]) -> i64 {
    let enforcer = PlatformHekiEnforcer;
    let state = heki_state();
    let result: Result<i64, VsmError> = match func_id {
        VsmFunction::EnableAPsVtl => mshv_vsm_enable_aps(params[0]),
        VsmFunction::BootAPs => mshv_vsm_boot_aps(params[0]),
        VsmFunction::LockRegs => {
            // The end-of-boot guard lives here because `HekiState` is owned by the runner.
            // Behavior is byte-for-byte identical: same condition, same error, same mapping.
            if state.check_end_of_boot() {
                Err(VsmError::OperationAfterEndOfBoot(
                    "control register locking",
                ))
            } else {
                mshv_vsm_lock_regs()
            }
        }
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
