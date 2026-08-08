// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The firmware-neutral boot handoff contract, and the dispatch to whichever
//! backend implements it.
//!
//! Everything under this module exists to get the machine from "whatever the
//! firmware left us" to the state [`crate::kvm_long_mode_entry`] assumes.
//! Nothing above this module may assume anything about the firmware; nothing
//! below it may assume anything about what the kernel does afterwards.
//!
//! The contract itself is documented as this module grows; see
//! [`apply_relocations`] for the one obligation that is already stated here,
//! and which is neutral because any firmware loading a PIE image has it.

pub mod pvh;
mod reloc;

pub use reloc::apply_relocations;

/// Base of the high-canonical kernel window: `VA = PA + KERNEL_OFFSET`.
///
/// This must match `litebox_platform_lvbs::KERNEL_OFFSET` (lib.rs:160), which
/// is what that crate's `MemoryProvider::pa_to_va` assumes. A backend
/// installs this window before entering Rust, so the platform crate's
/// assumption already holds by the time any of it is called.
pub const KERNEL_OFFSET: u64 = 0xFFFF_E200_0000_0000;

/// The stack the active backend was running on when it entered
/// [`crate::kvm_long_mode_entry`], as physical addresses `[floor, top)`.
///
/// The stack grows down, so `top` is the initial `%rsp` and `floor` is the
/// lowest address it may reach before it starts destroying whatever the
/// backend put underneath it. Nothing on this path has a guard page, so
/// `floor` is a fact about the layout rather than an enforced boundary.
///
/// Exists so that `crate::check_cpu_state` can assert it has genuinely left
/// this stack without knowing which backend provided it.
pub fn former_stack_range() -> (u64, u64) {
    pvh::boot_stack_range()
}

/// One past the highest physical address the loaded image may occupy.
///
/// A backend reserves memory for its own early use -- page tables, a GDT,
/// saved firmware pointers, a stack -- and the image has to end below it. The
/// linker script `ASSERT`s exactly this.
///
/// Exists so that `crate::kvm_long_mode_entry`'s relocation probe can assert
/// that a relocated pointer landed inside the image without knowing which
/// backend chose the bound.
pub fn image_limit_pa() -> u64 {
    pvh::image_limit_pa()
}
