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

mod reloc;

pub use reloc::apply_relocations;

/// Base of the high-canonical kernel window: `VA = PA + KERNEL_OFFSET`.
///
/// This must match `litebox_platform_lvbs::KERNEL_OFFSET` (lib.rs:160), which
/// is what that crate's `MemoryProvider::pa_to_va` assumes. A backend
/// installs this window before entering Rust, so the platform crate's
/// assumption already holds by the time any of it is called.
pub const KERNEL_OFFSET: u64 = 0xFFFF_E200_0000_0000;
