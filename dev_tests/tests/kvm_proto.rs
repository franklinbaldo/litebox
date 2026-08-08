// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs `litebox_runner_optee_on_kvm`'s wire-protocol tests on the host.
//!
//! `litebox_runner_optee_on_kvm` builds only for the bare-metal `x86_64_kvm.json`
//! target, with `-Z build-std`, on a pinned nightly. `cargo test -p
//! litebox_runner_optee_on_kvm` therefore cannot work: there is no test harness, no
//! std, and no way to run the resulting binary except under QEMU.
//!
//! `src/proto.rs` is the one part of that crate which is pure: it depends on
//! `core` and `alloc` and on nothing else in the tree, precisely so that it
//! can be compiled somewhere a test harness exists. This file is that
//! somewhere. It includes the module by path -- so there is exactly one copy
//! of the code, and the guest and this test cannot drift -- and `cfg(test)` is
//! true here, so the module's own `mod tests` is compiled and run by the
//! ordinary `cargo test` / `cargo nextest` machinery.
//!
//! The alternative -- a second crate wrapping the file -- would add a
//! manifest, a workspace member and a dependency edge to achieve the same
//! thing. The alternative to *that* -- moving the codec into a shared crate --
//! is worth doing if a second consumer ever appears, and is not worth doing
//! for one.

// `proto.rs` is `no_std` code and names `alloc` paths directly. `alloc` is not
// in the extern prelude of a std crate, so it is declared here.
extern crate alloc;

#[path = "../../litebox_runner_optee_on_kvm/src/proto.rs"]
mod proto;
