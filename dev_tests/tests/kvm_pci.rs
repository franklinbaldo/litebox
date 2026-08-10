// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs `litebox_runner_optee_on_kvm`'s PCI configuration-space code on the
//! host.
//!
//! Same arrangement, and same reasoning, as `kvm_proto.rs`,
//! `kvm_pci_bar.rs` and `kvm_virtio_queue.rs`: the crate builds only for the
//! bare-metal `x86_64_kvm.json` target, so it has no test harness of its own.
//! This file includes `src/pci/mod.rs` with `#[path]`, so there is exactly one
//! copy of the code and the guest and the test cannot drift.
//!
//! `kvm_pci_bar.rs` already hosts `src/pci/bar.rs`, which was split out
//! because it is pure. The rest of `pci.rs` was not hosted because of one
//! thing: `litebox_platform_lvbs::arch::ioport::{inl, outl}`, which do not
//! compile for the host. Those two functions are now the module's only
//! platform dependency *by construction* -- `cfg(test)` swaps in
//! `pci::fake_bus`, a host bridge with one device behind it that answers the
//! way hardware does, read-only bits and write-1-to-clear bits included.
//!
//! Everything above the port pair is therefore the guest's own code: the
//! configuration-address encoding, the byte-lane selection, the BAR decode,
//! the sizing probe with its `COMMAND` bracket, and the capability walk.
//!
//! `pci.rs` names `alloc` paths through `bar.rs` and its own tests; `alloc` is
//! not in the extern prelude of a std crate, so it is declared here.

extern crate alloc;

#[path = "../../litebox_runner_optee_on_kvm/src/pci/mod.rs"]
#[expect(
    dead_code,
    reason = "the harness compiles the whole module, but several accessors and constants \
              exist for `virtio::VirtioDevice` and `main.rs`, neither of which is hosted here"
)]
mod pci;
