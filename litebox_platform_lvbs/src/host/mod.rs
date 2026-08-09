// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Different host implementations of [`super::HostInterface`]
//!
//! # Planned: rename the crate to `litebox_platform_kernel`
//!
//! `litebox_platform_lvbs` is now a misnomer: half of it is a generic x86_64
//! kernel, and a KVM guest that never touches VTL still depends on a crate
//! named after it. The intended name is `litebox_platform_kernel`, with the
//! `Lvbs`-prefixed shared types (`LvbsPhysPageMapInfo`, `LvbsValidateAccess`)
//! and the VTL language in shared doc comments renamed with it. Deferred, not
//! forgotten.
//!
//! Two items still sit outside `host/` that the invariant below says belong
//! inside it: `arch::x86::REF_TICKS_PER_MICRO` and `REF_COUNTER_TICK_NANOS`,
//! whose own docs describe them as properties of a Hyper-V synthetic MSR
//! rather than of x86. They are `pub(crate)` consts with no symbols, so moving
//! them is free whenever someone is in here.
//!
//! # Invariant: host-specific code lives under `host/<name>/`
//!
//! Everything specific to a single host lives under `host/lvbs/` (Hyper-V
//! VTL1) or `host/kvm/` (plain KVM/QEMU guest). Nothing else in the crate may
//! be host-specific. The point of stating it here is that it makes the
//! converse checkable: **anything outside `host/lvbs/` and `host/kvm/` is
//! shared by both hosts, by construction.**
//!
//! Concretely, that means a reviewer can reject, on sight:
//!
//! * a Hyper-V or KVM concept named anywhere under `arch/`, `mm/`, or
//!   `syscall_entry.rs` — those are the shared kernel;
//! * a new top-level module that only one host compiles.
//!
//! The exceptions are deliberate and are exactly these three files, which are
//! shared *code* carrying per-host `cfg` seams rather than host-specific code
//! in the wrong place: `lib.rs`, `per_cpu_variables.rs`, and
//! `arch/x86/interrupts.rs` (plus smaller seams in `arch/x86/mod.rs`,
//! `arch/x86/ioport.rs`, and `arch/x86/mm/paging.rs`). Those seams are shared
//! logic that *differs* between hosts, not host logic that could be relocated;
//! collapsing them into traits is separate work. A seam is acceptable there. A
//! whole host-specific module is not.
//!
//! `CpuMask` used to sit in a shared `linux.rs` alongside `pt_regs` and
//! `Timespec`. Those two turned out to be dead legacy from the SNP platform,
//! which sandboxes a normal-world Linux in VMPL1: nothing imported them, and
//! `Timespec` duplicated `litebox_common_linux::Timespec`. They are gone, and
//! `CpuMask` now lives in `host/lvbs/cpu_mask.rs` for exactly the reason above.

#[cfg(feature = "host_kvm")]
pub mod kvm;
#[cfg(feature = "host_lvbs")]
pub mod lvbs;
pub mod per_cpu_variables;

#[cfg(feature = "host_kvm")]
pub use kvm::KvmGuest;
#[cfg(feature = "host_lvbs")]
pub use lvbs::LvbsLinuxKernel;
#[cfg(feature = "host_lvbs")]
pub(crate) use lvbs::set_platform_root_key;

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
    crate::host::lvbs::mshv::vtl1_mem_layout::get_hvcall_page_start_address()
}
