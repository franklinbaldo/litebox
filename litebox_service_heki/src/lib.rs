// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![no_std]

//! HEKI/HVCI + VSM service. Owns VSM dispatch and HEKI enforcement policy on
//! top of a platform-provided hypercall trait ([`litebox_common_lvbs::VsmPlatform`]).
//!
//! The VSM/HEKI algorithms (module/kexec validation, text patching, kernel-data
//! load, signature/ELF checks) live here and are generic over `VsmPlatform`: the
//! platform provides the real implementor, and the trait is the seam that
//! decouples the policy from any concrete platform.

extern crate alloc;

pub mod mem_integrity;
pub mod state;
pub mod vsm;

pub use litebox_common_lvbs::ReservationStatus;
pub use state::HekiState;
pub use vsm::{
    ValidatedTextPatch, mshv_vsm_allocate_ringbuffer_memory, mshv_vsm_boot_aps,
    mshv_vsm_copy_secondary_key, mshv_vsm_enable_aps, mshv_vsm_end_of_boot,
    mshv_vsm_free_guest_module_init, mshv_vsm_kexec_validate, mshv_vsm_load_kdata,
    mshv_vsm_patch_text, mshv_vsm_protect_memory, mshv_vsm_set_platform_root_key,
    mshv_vsm_unload_guest_module, mshv_vsm_validate_guest_module,
};
