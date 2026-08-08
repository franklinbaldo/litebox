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
//! Today there is exactly one backend, [`pvh`]. BIOS and UEFI are planned.
//! The point of writing the contract down rather than leaving it implicit in
//! [`pvh`]'s assembly is that a second backend should be *additive*: a new
//! `boot/uefi.rs` plus a line of dispatch here, and no edit to `main.rs` or
//! `memmap.rs`.
//!
//! # What a backend must guarantee
//!
//! By the time the first 64-bit Rust function is entered, a backend must have
//! established all of the following. Each is load-bearing: something in this
//! crate breaks, usually silently, if it does not hold.
//!
//! 1. **The CPU is in 64-bit long mode.** Not compatibility mode: the code
//!    below is compiled for `x86_64` throughout and there is no 32-bit
//!    codegen anywhere outside a backend's own entry stub.
//!
//!    Note this is *not* universal work. PVH and BIOS enter in 32-bit
//!    protected mode with paging off, so both need a mode-switch stub and
//!    early page tables of their own. UEFI hands over 64-bit long mode with
//!    paging already enabled, so a UEFI backend needs neither. That is why
//!    the stub and the trampoline live in [`pvh`] rather than here.
//!
//! 2. **Execution is in the [`KERNEL_OFFSET`] alias**, i.e. `%rip` and `%rsp`
//!    are both `PA + KERNEL_OFFSET`, and low physical memory is mapped
//!    read/write at that offset. This is what `litebox_platform_lvbs`'s
//!    `MemoryProvider::pa_to_va` assumes, so it must already hold before any
//!    of that crate is called.
//!
//!    A UEFI backend gets identity mapping for free but *not* this alias, and
//!    will have to install it.
//!
//! 3. **Physical memory below [`BootInfo::mapped_limit`] is mapped read/write
//!    through that alias.** Two things depend on this and neither fails
//!    cleanly: `memmap`'s reads of the firmware's own structures, and the
//!    clamp it applies to every RAM range before offering it to the heap. A
//!    backend that maps a different amount reports a different limit; nothing
//!    downstream needs to change.
//!
//! 4. **There is a valid stack**, with enough headroom for a debug build of
//!    everything on the boot path. Note that nothing on this path has a guard
//!    page, so "enough" is not enforced -- see [`pvh::OFF_STACK_TOP`] for what
//!    running out looks like.
//!
//! 5. **`.rela.dyn` relocations have been applied** by [`apply_relocations`].
//!    The image is linked `--pie`, so until this runs *every* pointer-bearing
//!    static reads as zero. A backend must call it before touching one, and
//!    must do so from the alias in (2) so the resulting pointers come out
//!    high-canonical. This is neutral work -- any firmware that loads a PIE
//!    image needs it -- which is why it lives in [`reloc`] and not in a
//!    backend.
//!
//! 6. **SSE is enabled**: `CR0.EM` clear, `CR0.MP` set, `CR4.OSFXSR` and
//!    `CR4.OSXMMEXCPT` set. SSE2 is part of the x86-64 ABI baseline, so the
//!    compiler may emit xmm instructions in *any* function without asking,
//!    and with no IDT yet a `#UD` is a silent triple fault.
//!
//!    Note the specific bits: `CR4.OSXSAVE` is deliberately *not* among them.
//!    AVX is disabled in the target spec, so nothing needs XCR0 this early;
//!    `enable_extended_states()` sets `OSXSAVE` later.
//!
//! 7. **Interrupts are disabled** (`EFLAGS.IF` clear). Phrased as "inherits
//!    or establishes": the PVH backend inherits this from the boot protocol
//!    and never executes `sti`, so it does no work to satisfy it. A backend
//!    whose firmware leaves interrupts on must clear `IF` itself. There is no
//!    IDT at handoff, so an interrupt delivered here is a triple fault.
//!
//! 8. **A [`BootInfo`] is obtainable** from [`boot_info`], describing usable
//!    RAM and the ranges the firmware wants withheld from the heap.
//!
//! # What a backend must *not* be assumed to have done
//!
//! A contract that only says what is true is half a contract. At handoff,
//! none of the following hold, and `main.rs` establishes each one itself:
//!
//! - **`CR0.WP` is clear.** Until `init_platform` sets it, a supervisor write
//!   to a read-only page succeeds silently, so a read-only `.text` mapping
//!   would be advisory.
//! - **There is no IDT.** Any fault before `init_idt()` is a triple fault
//!   with no output at all.
//! - **`CR4.FSGSBASE` and `CR4.OSXSAVE` are clear**, so `wrgsbase` `#UD`s and
//!   XCR0 is unreadable until `enable_fsgsbase()` / `enable_extended_states()`
//!   run. Likewise `CR4.SMEP`/`SMAP`, set later by `enable_smep_smap()`.
//! - **The heap does not exist.** Nothing before `memmap::init_heap` may
//!   allocate.
//!
//! # Observations that are not guarantees
//!
//! [`pvh`] happens to leave the low 1 GiB identity-mapped as well as aliased,
//! because a stub that enables paging while executing at a low physical
//! address cannot survive without it. That is an artefact of *how* PVH
//! reaches long mode, not something a backend owes anyone, and a UEFI backend
//! would have the inverse property: identity mapping without the alias.
//!
//! It is called out here because `crate::check_interrupts` currently *relies*
//! on it -- it declines to probe VA 0, on the grounds that VA 0 is mapped and
//! a successful read would prove nothing. A backend that does not identity-map
//! low memory will make that check silently vacuous rather than fail, so
//! whoever writes the second backend should revisit it deliberately.

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

/// A half-open physical range `[start, end)`.
///
/// Contract vocabulary: it is how a backend describes both the RAM it found
/// and the memory it wants withheld, so it cannot live in the consumer.
#[derive(Clone, Copy)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}

/// Largest number of usable-RAM regions a backend may report.
///
/// QEMU's PVH memory map has nine entries in total, two of which are RAM, so
/// this is generous. It is a cap rather than a growable list because there is
/// no heap yet: this is decided in order to *create* the heap.
pub const MAX_RAM_REGIONS: usize = 32;

/// Largest number of ranges a backend may ask to have withheld.
///
/// PVH's worst case is four fixed structures (the start info, the memory map
/// table, the command line, the module list) plus one per module image, capped
/// at eight modules: twelve. The slack is so that adding one more does not
/// require thinking about this number.
pub const MAX_FIRMWARE_RESERVED: usize = 14;

/// What the active backend learned from the firmware.
///
/// Deliberately minimal: it carries what `crate::memmap` actually consumes and
/// nothing else. Adding a field when a second backend needs one is a one-line
/// change; removing a wrong abstraction is not.
///
/// In particular it does not carry the firmware's own structures, their
/// version, or anything about how the memory was described -- a UEFI backend
/// has none of those in the same shape, and `memmap` has no use for them.
pub struct BootInfo {
    /// Usable RAM, exactly as the firmware described it: unfiltered by
    /// anything but "the firmware called this RAM", and unclamped.
    ///
    /// `memmap` does the subtraction of reserved ranges and the clamping to
    /// [`mapped_limit`](Self::mapped_limit); doing it here would mean every
    /// backend reimplementing it.
    pub usable: arrayvec::ArrayVec<Range, MAX_RAM_REGIONS>,

    /// Ranges the firmware's own structures occupy, which must never reach the
    /// heap.
    ///
    /// Opaque here on purpose: *which* structure each range is, is the
    /// backend's business, and a consumer that knew would be firmware-specific
    /// again. `memmap` adds its own firmware-neutral exclusions (the first
    /// megabyte, the loaded image) to these.
    pub reserved: arrayvec::ArrayVec<Range, MAX_FIRMWARE_RESERVED>,

    /// One past the highest physical address the backend guarantees is mapped
    /// read/write at `PA + KERNEL_OFFSET`.
    ///
    /// A field rather than a constant because it is genuinely per-backend:
    /// PVH's stub builds a single 1 GiB PD, while UEFI arrives with whatever
    /// its firmware mapped. Carrying it means the clamp in `memmap` reads
    /// `info.mapped_limit` and needs no edit when a second backend lands.
    pub mapped_limit: u64,
}

/// Obtains the [`BootInfo`] from the active backend.
///
/// # Panics
///
/// Panics if the firmware's description of memory is missing, malformed, or
/// larger than this can represent. Continuing would only defer the failure to
/// the first allocation, where the cause would be far less obvious -- and the
/// failure mode is the heap being handed memory that is not free.
pub fn boot_info() -> BootInfo {
    pvh::boot_info()
}

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
