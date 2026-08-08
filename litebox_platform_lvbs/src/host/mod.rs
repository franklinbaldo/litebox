// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Different host implementations of [`super::HostInterface`]
pub mod bootparam;
#[cfg(feature = "host_kvm")]
pub mod kvm_impl;
pub mod linux;
#[cfg(feature = "host_lvbs")]
pub mod lvbs_impl;
pub mod per_cpu_variables;

#[cfg(feature = "host_kvm")]
pub use kvm_impl::KvmGuest;
#[cfg(feature = "host_lvbs")]
pub use lvbs_impl::LvbsLinuxKernel;
#[cfg(feature = "host_lvbs")]
pub(crate) use lvbs_impl::set_platform_root_key;

#[cfg(test)]
pub mod mock;

/// Anchor byte that ensures the `.hvcall_page` linker section is emitted.
#[cfg(feature = "host_lvbs")]
#[used]
#[unsafe(link_section = ".hvcall_page")]
static HVCALL_PAGE_ANCHOR: u8 = 0;

/// Get the address of the Hyper-V hypercall code page.
///
/// The page is defined in the linker script (`.hvcall_page` section) so that it
/// has a well-known, page-aligned location. The hypervisor writes executable
/// code into it at runtime via wrmsr(`HV_X64_MSR_HYPERCALL`).
/// A `call` instruction to this address performs a trap-based hypercall.
///
/// Different Virtual Processors (VPs) can share the same address because
/// Hyper-V identifies the calling VP internally.
#[cfg(feature = "host_lvbs")]
#[inline]
pub fn hv_hypercall_page_address() -> u64 {
    crate::mshv::vtl1_mem_layout::get_hvcall_page_start_address()
}
