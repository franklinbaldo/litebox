// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Declares the build inputs cargo cannot see for itself.
//!
//! Two files decide what this crate links to and neither is a Rust source
//! file, so neither appears in the dep-info cargo rebuilds on:
//!
//! * `x86_64_kvm.ld`, which places `.text` at 0x200000, gives `.rodata` and the
//!   exception table their own read-only section, reserves the boot scratch
//!   region at a fixed physical address, and asserts the entry address the PVH
//!   note hardcodes.
//! * `x86_64_kvm.json`, the target specification, which names the linker
//!   script and the code model.
//!
//! Without this file, editing either of them and rebuilding produced the *old*
//! binary. `cargo build` said `Finished`, and there was no indication that the
//! change had not been applied -- the layout only moves when something else
//! happens to dirty the crate. That is the worst kind of stale build: for a
//! linker script it means the boot stub's hardcoded addresses and the image's
//! actual layout can disagree while every command reports success.
//!
//! # Why this is not where the entry address is checked
//!
//! `src/boot/pvh.rs` hardcodes `PVH_ENTRY_ADDR = 0x200000` in the ELF note
//! QEMU reads, and it has to match `_start`. A build script cannot check that:
//! it runs *before* the link, so there is no ELF to run `nm` over, and the only
//! thing it could compare is one copy of a constant against another.
//!
//! The check belongs where the address is decided, which is the linker. So
//! `x86_64_kvm.ld` carries
//!
//! ```text
//! ASSERT(_start == 0x200000, ...)
//! ```
//!
//! which fails the *link* -- not a later test, and not the boot -- if the entry
//! point ever moves. That closes the loop this file opens: the assertion is
//! what makes the claim true, and the `rerun-if-changed` below is what makes
//! sure the assertion is re-evaluated when the script it lives in changes.

fn main() {
    for input in ["x86_64_kvm.ld", "x86_64_kvm.json"] {
        println!("cargo::rerun-if-changed={input}");
    }
}
