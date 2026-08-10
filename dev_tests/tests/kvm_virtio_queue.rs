// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs `litebox_runner_optee_on_kvm`'s virtqueue bookkeeping on the host.
//!
//! Same arrangement, and same reasoning, as `kvm_proto.rs` and
//! `kvm_pci_bar.rs`: the crate builds only for the bare-metal
//! `x86_64_kvm.json` target, so it has no test harness of its own. This file
//! includes `src/virtio/queue.rs` with `#[path]`, so there is exactly one copy
//! of the code and the guest and the test cannot drift, and `cfg(test)` is
//! true here, so the module's own `mod tests` runs under the ordinary
//! `cargo test` / `cargo nextest` machinery.
//!
//! `queue.rs` is not *quite* pure: `Dma` needs pages and the physical address
//! of them, which on the guest come from the platform's buddy allocator. That
//! is the only thing it needs, and it is behind `Dma::allocate`, which has a
//! `cfg(test)` arm using the host allocator instead. Everything else -- the
//! descriptor table, the available and used rings, the free list, the
//! per-descriptor states, `submit`, `abandon` and `take_used` -- is the
//! guest's code running against real memory.
//!
//! The tests act as the *device*, because the device is the untrusted party:
//! a virtqueue driver's exposure is exactly the used-ring entries the device
//! writes, and it is free to write nonsense.

// `queue.rs` is `no_std` code and names `alloc` paths directly. `alloc` is not
// in the extern prelude of a std crate, so it is declared here.
extern crate alloc;

#[path = "../../litebox_runner_optee_on_kvm/src/virtio/queue.rs"]
#[expect(
    dead_code,
    reason = "the harness compiles the whole module, but a queue's accessors exist for \
              `virtio::Console` and `virtio::Transport`, which are not hosted here"
)]
mod queue;
