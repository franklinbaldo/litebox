// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform-side VSM bring-up and control-register locking.
//!
//! The VSM/HEKI policy and handlers now live in `litebox_service_heki` over the
//! [`litebox_common_lvbs::VsmPlatform`] trait. What remains here is the
//! platform-only bring-up (partition/VTL0 secure configuration, VTL1
//! self-protection) and the control-register lock code, which reach hardware
//! state that is unavoidably platform-owned.

use crate::{
    debug_serial_println,
    host::{bootparam::get_vtl1_memory_info, per_cpu_variables::with_per_cpu_variables},
    mshv::{
        HV_REGISTER_CR_INTERCEPT_CONTROL, HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        HV_REGISTER_CR_INTERCEPT_CR4_MASK, HV_REGISTER_VSM_PARTITION_CONFIG,
        HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, HV_X64_REGISTER_APIC_BASE, HV_X64_REGISTER_CR0,
        HV_X64_REGISTER_CR4, HV_X64_REGISTER_CSTAR, HV_X64_REGISTER_EFER, HV_X64_REGISTER_LSTAR,
        HV_X64_REGISTER_SFMASK, HV_X64_REGISTER_STAR, HV_X64_REGISTER_SYSENTER_CS,
        HV_X64_REGISTER_SYSENTER_EIP, HV_X64_REGISTER_SYSENTER_ESP, HvCrInterceptControlFlags,
        HvPageProtFlags, HvRegisterVsmPartitionConfig, HvRegisterVsmVpSecureVtlConfig, X86Cr0Flags,
        X86Cr4Flags,
        error::VsmError,
        hvcall::HypervCallError,
        hvcall_mm::hv_modify_vtl_protection_mask,
        hvcall_vp::{hvcall_get_vp_vtl0_registers, hvcall_set_vp_registers},
        vsm_platform::heki_mem_attr_to_hv_page_prot_flags,
        vtl_switch::mshv_vsm_get_code_page_offsets,
    },
};

use litebox_common_lvbs::MemAttr;
use x86_64::{
    PhysAddr,
    structures::paging::{PhysFrame, Size4KiB, frame::PhysFrameRange},
};

pub(crate) fn init(is_bsp: bool) {
    assert!(
        !(is_bsp && mshv_vsm_configure_partition().is_err()),
        "Failed to configure VSM partition"
    );

    assert!(
        mshv_vsm_get_code_page_offsets().is_ok(),
        "Failed to retrieve Hypercall page offsets to execute VTL returns"
    );

    assert!(
        mshv_vsm_secure_config_vtl0().is_ok(),
        "Failed to secure VTL0 configuration"
    );

    if is_bsp {
        if let Ok((start, size)) = get_vtl1_memory_info() {
            let Some(end) = start.checked_add(size) else {
                panic!("Failed to protect VTL1 memory");
            };
            debug_serial_println!("VSM: Protect GPAs from {:#x} to {:#x}", start, end);
            let Ok(end) = PhysAddr::try_new(end) else {
                panic!("Failed to protect VTL1 memory");
            };
            let start = PhysAddr::new(start);
            if protect_vtl1_physical_memory_range(PhysFrame::range(
                PhysFrame::from_start_address(start)
                    .expect("VTL1 memory start address is not page-aligned"),
                PhysFrame::from_start_address(end)
                    .expect("VTL1 memory end address is not page-aligned"),
            ))
            .is_err()
            {
                panic!("Failed to protect VTL1 memory");
            }
        } else {
            panic!("Failed to get VTL1 memory info");
        }
    }
}

/// VSM function for enforcing certain security features of VTL0
pub fn mshv_vsm_secure_config_vtl0() -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Secure VTL0 configuration");

    let mut config = HvRegisterVsmVpSecureVtlConfig::new();
    config.set_mbec_enabled(true);
    config.set_tlb_locked(true);

    hvcall_set_vp_registers(HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, config.as_u64())
        .map_err(VsmError::HypercallFailed)?;

    Ok(0)
}

/// VSM function to configure a VSM partition for VTL1
pub fn mshv_vsm_configure_partition() -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Configure partition");

    let mut config = HvRegisterVsmPartitionConfig::new();
    config.set_default_vtl_protection_mask(HvPageProtFlags::HV_PAGE_FULL_ACCESS.bits());
    config.set_enable_vtl_protection(true);

    hvcall_set_vp_registers(HV_REGISTER_VSM_PARTITION_CONFIG, config.as_u64())
        .map_err(VsmError::HypercallFailed)?;

    Ok(0)
}

/// VSM function for locking VTL0's control registers.
///
/// The end-of-boot guard is enforced by the runner-side dispatcher (which owns
/// the `HekiState`) before this is called.
///
/// Returns the common wire error type so the runner can uniformly combine this
/// platform-owned operation with the `litebox_service_heki` handlers.
pub fn mshv_vsm_lock_regs() -> Result<i64, litebox_common_lvbs::VsmError> {
    use crate::mshv::vsm_platform::to_common_hvcall_err;
    let hvcall_failed = |e| litebox_common_lvbs::VsmError::HypercallFailed(to_common_hvcall_err(e));

    debug_serial_println!("VSM: Lock control registers");

    let flag = HvCrInterceptControlFlags::CR0_WRITE.bits()
        | HvCrInterceptControlFlags::CR4_WRITE.bits()
        | HvCrInterceptControlFlags::GDTR_WRITE.bits()
        | HvCrInterceptControlFlags::IDTR_WRITE.bits()
        | HvCrInterceptControlFlags::LDTR_WRITE.bits()
        | HvCrInterceptControlFlags::TR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_LSTAR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_STAR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_CSTAR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_APIC_BASE_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_EFER_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SYSENTER_CS_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SYSENTER_ESP_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SYSENTER_EIP_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SFMASK_WRITE.bits();

    save_vtl0_locked_regs().map_err(hvcall_failed)?;

    hvcall_set_vp_registers(HV_REGISTER_CR_INTERCEPT_CONTROL, flag).map_err(hvcall_failed)?;

    hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR4_MASK,
        X86Cr4Flags::CR4_PIN_MASK.bits().into(),
    )
    .map_err(hvcall_failed)?;

    hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        X86Cr0Flags::CR0_PIN_MASK.bits().into(),
    )
    .map_err(hvcall_failed)?;

    Ok(0)
}

pub const NUM_CONTROL_REGS: usize = 11;

/// Data structure for maintaining MSRs and control registers whose values are locked.
/// This structure is expected to be stored in per-core kernel context, so we do not protect it with a lock.
#[derive(Debug, Clone, Copy)]
pub struct ControlRegMap {
    pub entries: [(u32, u64); NUM_CONTROL_REGS],
}

impl ControlRegMap {
    pub fn init(&mut self) {
        [
            HV_X64_REGISTER_CR0,
            HV_X64_REGISTER_CR4,
            HV_X64_REGISTER_LSTAR,
            HV_X64_REGISTER_STAR,
            HV_X64_REGISTER_CSTAR,
            HV_X64_REGISTER_APIC_BASE,
            HV_X64_REGISTER_EFER,
            HV_X64_REGISTER_SYSENTER_CS,
            HV_X64_REGISTER_SYSENTER_ESP,
            HV_X64_REGISTER_SYSENTER_EIP,
            HV_X64_REGISTER_SFMASK,
        ]
        .iter()
        .enumerate()
        .for_each(|(i, &reg_name)| {
            self.entries[i] = (reg_name, 0);
        });
    }

    pub fn get(&self, reg_name: u32) -> Option<u64> {
        for entry in &self.entries {
            if entry.0 == reg_name {
                return Some(entry.1);
            }
        }
        None
    }

    pub fn set(&mut self, reg_name: u32, value: u64) {
        for entry in &mut self.entries {
            if entry.0 == reg_name {
                entry.1 = value;
                return;
            }
        }
    }

    // consider implementing a mutable iterator (if we plan to lock many control registers)
    pub fn reg_names(&self) -> [u32; NUM_CONTROL_REGS] {
        let mut names = [0; NUM_CONTROL_REGS];
        for (i, entry) in self.entries.iter().enumerate() {
            names[i] = entry.0;
        }
        names
    }
}

#[allow(clippy::unnecessary_wraps)]
fn save_vtl0_locked_regs() -> Result<u64, HypervCallError> {
    let reg_names = with_per_cpu_variables(|per_cpu_variables| {
        let mut regs = per_cpu_variables.vtl0_locked_regs.get();
        regs.init();
        per_cpu_variables.vtl0_locked_regs.set(regs);
        regs.reg_names()
    });
    for reg_name in reg_names {
        if let Ok(value) = hvcall_get_vp_vtl0_registers(reg_name) {
            with_per_cpu_variables(|per_cpu_variables| {
                let mut regs = per_cpu_variables.vtl0_locked_regs.get();
                regs.set(reg_name, value);
                per_cpu_variables.vtl0_locked_regs.set(regs);
            });
        }
    }

    Ok(0)
}

/// This function protects a VTL1 physical memory range, securing VTL1's own pages.
/// VTL0 should never access VTL1 memory, so the memory attribute is always empty (no read, write, or execute).
///
/// Note. This function doesn't check whether `phys_frame_range` belongs to VTL1 because it is called by BSP
/// before the kernel platform data structure is initialized. To this end, one might call this function with
/// a VTL0 physical memory range which only restricts access to the range.
#[inline]
pub(crate) fn protect_vtl1_physical_memory_range(
    phys_frame_range: PhysFrameRange<Size4KiB>,
) -> Result<(), VsmError> {
    let pa = phys_frame_range.start.start_address().as_u64();
    let num_pages = phys_frame_range.count() as u64;
    if num_pages > 0 {
        hv_modify_vtl_protection_mask(
            pa,
            num_pages,
            heki_mem_attr_to_hv_page_prot_flags(MemAttr::empty()),
        )
        .map_err(VsmError::HypercallFailed)?;
    }
    Ok(())
}
