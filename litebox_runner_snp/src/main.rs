// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// This binary is x86-64-only: `src/entry.S` is x86-64 assembly, and it depends on
// `litebox_platform_linux_kernel`, which is itself gated on `target_arch = "x86_64"` and so
// compiles to an empty crate elsewhere.
//
// The real entry point lives in `snp.rs` and is a freestanding `no_std`/`no_main` image. A
// crate-level `#![cfg]` cannot be used here because it would also cfg away `#![no_main]`, leaving a
// `no_std` binary with no `main` (E0601). Instead, apply `no_std`/`no_main` only on x86-64 and
// provide an ordinary `main` stub elsewhere.
#![cfg_attr(target_arch = "x86_64", no_std, no_main)]

// `pub` so that the `#[unsafe(no_mangle)]` entry points keep the same effective visibility
// they had when they lived directly in the crate root; some `pub`-only lints (e.g.
// `clippy::missing_safety_doc`) would otherwise stop firing.
#[cfg(target_arch = "x86_64")]
pub mod snp;

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!(
        "litebox_runner_snp is only supported on x86-64; this binary was built for {}.",
        std::env::consts::ARCH
    );
    std::process::exit(1);
}
