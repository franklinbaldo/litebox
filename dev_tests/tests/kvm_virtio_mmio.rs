// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs `litebox_runner_optee_on_kvm`'s device-MMIO span arithmetic on the
//! host.
//!
//! Same arrangement, and same reasoning, as `kvm_proto.rs`, `kvm_pci_bar.rs`,
//! `kvm_pci.rs` and `kvm_virtio_queue.rs`: the crate builds only for the
//! bare-metal `x86_64_kvm.json` target, so it has no test harness of its own.
//! This file includes `src/virtio/mmio.rs` with `#[path]`, so there is exactly
//! one copy of the code and the guest and the test cannot drift.
//!
//! Only part of `mmio.rs` can run here, and the split is deliberate rather
//! than convenient. `map_device_memory` first decides whether the request is
//! *representable* and whether it *fits in the window*, and then walks the
//! page tables the CPU is currently using to install it. The second half
//! cannot be hosted and cannot be faked -- it edits the live tables -- and the
//! QEMU boot test exercises it on every run. The first half is the whole of
//! what `759a187f` changed, and it rejects a hostile request before the walk
//! begins, so it is reachable here with `read_cr3` and friends stubbed out to
//! `unreachable!`. A test that did reach the walk would fail loudly rather
//! than quietly pass.

#[path = "../../litebox_runner_optee_on_kvm/src/virtio/mmio.rs"]
#[expect(
    dead_code,
    reason = "the harness compiles the whole module, but the register accessors exist for \
              `virtio::Transport`, which is not hosted here"
)]
mod mmio;
