// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs `litebox_runner_optee_on_kvm`'s PCI BAR sizing arithmetic on the host.
//!
//! Same arrangement, and same reasoning, as `kvm_proto.rs`: the crate builds
//! only for the bare-metal `x86_64_kvm.json` target, so it has no test harness
//! of its own. `src/pci.rs` as a whole cannot be hosted -- it is built on
//! `litebox_platform_lvbs::arch::ioport`, which does not compile for the host
//! -- but the BAR *arithmetic* is pure, and was split into `src/pci/bar.rs`
//! precisely so that it could be compiled somewhere a test harness exists.
//! This file is that somewhere. It includes the module by path, so there is
//! exactly one copy of the code and the guest and this test cannot drift, and
//! `cfg(test)` is true here, so the module's own `mod tests` runs under the
//! ordinary `cargo test` / `cargo nextest` machinery.

#[path = "../../litebox_runner_optee_on_kvm/src/pci/bar.rs"]
mod bar;
