// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// TSC-based monotonic clock. KVM guests have no Hyper-V reference counter,
/// so the TSC is the only cheap monotonic source available.
#[cfg(feature = "host_kvm")]
pub mod clock;
pub mod gdt;
pub mod instrs;
pub mod interrupts;
pub mod ioport;
pub mod mm;
pub mod msr;
/// Hyper-V synthetic-timer (STIMER) preemption timer.
///
/// Note: roughly half of this module is architectural x2APIC bring-up code
/// (`IA32_APIC_BASE`, `X2APIC_SVR`, `X2APIC_EOI`) that is not Hyper-V specific
/// and is worth lifting out when an APIC-timer preemption source lands.
#[cfg(feature = "host_lvbs")]
pub mod timer;

/// Ticks per microsecond of the *Hyper-V partition reference counter*
/// (`HV_X64_MSR_TIME_REF_COUNT`): 100 ns per tick, i.e. 10 per microsecond.
///
/// This is a property of a Hyper-V synthetic MSR, not of x86. It is gated on
/// `host_lvbs` so that a host without that MSR cannot accidentally inherit its
/// granularity; see `Instant::TICK_NANOS` in `lib.rs`.
#[cfg(feature = "host_lvbs")]
pub(crate) const REF_TICKS_PER_MICRO: u64 = 10;

/// Nanoseconds per tick of the *Hyper-V partition reference counter*: the
/// counter runs at 10 MHz (`REF_TICKS_PER_MICRO` ticks per microsecond).
#[cfg(feature = "host_lvbs")]
pub(crate) const REF_COUNTER_TICK_NANOS: u64 = 1_000 / REF_TICKS_PER_MICRO;

/// Vector the local APIC delivers for a *spurious* interrupt (programmed
/// into the SVR). `0xff` is conventional (top of range). Requires no EOI;
/// handled by the bare `iretq` stub `isr_spurious`.
pub(crate) const SPURIOUS_VECTOR: u8 = 0xff;

pub(crate) use x86_64::{
    addr::{PhysAddr, VirtAddr},
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    },
};

use core::arch::x86_64::__cpuid_count as cpuid_count;

#[cfg(test)]
pub(crate) use x86_64::structures::paging::mapper::{MappedFrame, TranslateResult};

/// Get the APIC ID of the current core.
#[inline]
pub fn get_core_id() -> usize {
    const CPU_VERSION_INFO: u32 = 1;

    let result = cpuid_count(CPU_VERSION_INFO, 0x0);
    let apic_id = (result.ebx >> 24) & 0xff;

    apic_id as usize
}

/// Enable FSGSBASE instructions
#[inline]
pub fn enable_fsgsbase() {
    let mut flags = x86_64::registers::control::Cr4::read();
    flags.insert(x86_64::registers::control::Cr4Flags::FSGSBASE);
    unsafe {
        x86_64::registers::control::Cr4::write(flags);
    }
}

/// Enable CPU extended states such as XMM and instructions to use and manage them
/// such as SSE and XSAVE
///
/// VTL0 and VTL1 share the same XCR0 register. This function verifies that XCR0 already
/// has x87 and SSE enabled (by VTL0) rather than modifying it.
///
/// # Panics
///
/// Panics if XCR0 (from the VTL0 kernel) does not have x87 and SSE enabled.
#[cfg(target_arch = "x86_64")]
pub fn enable_extended_states() {
    let mut flags = x86_64::registers::control::Cr0::read();
    flags.remove(x86_64::registers::control::Cr0Flags::EMULATE_COPROCESSOR);
    flags.insert(x86_64::registers::control::Cr0Flags::MONITOR_COPROCESSOR);
    unsafe {
        x86_64::registers::control::Cr0::write(flags);
    }

    let mut flags = x86_64::registers::control::Cr4::read();
    flags.insert(x86_64::registers::control::Cr4Flags::OSFXSR);
    flags.insert(x86_64::registers::control::Cr4Flags::OSXMMEXCPT_ENABLE);
    flags.insert(x86_64::registers::control::Cr4Flags::OSXSAVE);
    unsafe {
        x86_64::registers::control::Cr4::write(flags);
    }

    // VTL1 should not modify XCR0 - verify that VTL0 has already enabled x87 and SSE
    let xcr0 = x86_64::registers::xcontrol::XCr0::read();
    assert!(
        xcr0.contains(x86_64::registers::xcontrol::XCr0Flags::X87),
        "XCR0 must have x87 enabled by VTL0"
    );
    assert!(
        xcr0.contains(x86_64::registers::xcontrol::XCr0Flags::SSE),
        "XCR0 must have SSE enabled by VTL0"
    );
}

#[inline]
pub fn write_kernel_gsbase_msr(addr: VirtAddr) {
    x86_64::registers::model_specific::KernelGsBase::write(addr);
}

/// Enable Data Execution Prevention (DEP).
///
/// This enables support for the `NO_EXECUTE` page table flag, allowing
/// data pages to be marked non-executable.
///
/// # Panics
///
/// Panics if CPUID does not advertise NX support.
#[cfg(target_arch = "x86_64")]
pub fn enable_dep() {
    // CPUID.80000001h:EDX bit 20 = NX support
    let ext_features = cpuid_count(0x8000_0001, 0);
    assert!(
        ext_features.edx & (1 << 20) != 0,
        "CPU does not support NX/XD bit"
    );

    unsafe {
        let efer = x86_64::registers::model_specific::Efer::read();
        x86_64::registers::model_specific::Efer::write(
            efer | x86_64::registers::model_specific::EferFlags::NO_EXECUTE_ENABLE,
        );
    }
}

/// Enable Supervisor Mode Execution/Access Prevention (SMEP & SMAP).
///
/// - **CR4.SMEP**: prevents the kernel from executing code that resides
///   in user-accessible pages.
/// - **CR4.SMAP**: prevents the kernel from accessing user-accessible pages
///   unless explicitly overridden (via `STAC`/`CLAC`).
///
/// # Panics
///
/// Panics if the CPUID does not advertise SMEP or SMAP support.
#[cfg(target_arch = "x86_64")]
pub fn enable_smep_smap() {
    // CPUID.07h:EBX bit 7 = SMEP, bit 20 = SMAP
    let structured_features = cpuid_count(0x07, 0);
    assert!(
        structured_features.ebx & (1 << 7) != 0,
        "CPU does not support SMEP"
    );
    assert!(
        structured_features.ebx & (1 << 20) != 0,
        "CPU does not support SMAP"
    );

    let mut cr4 = x86_64::registers::control::Cr4::read();
    cr4.insert(x86_64::registers::control::Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION);
    cr4.insert(x86_64::registers::control::Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);
    unsafe {
        x86_64::registers::control::Cr4::write(cr4);
    }
}
