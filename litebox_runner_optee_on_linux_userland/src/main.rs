// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The library half of this crate is x86-64-only (see `lib.rs`), so on other architectures it
// compiles to an empty crate and there is no `run`/`CliArgs` to call. A binary target must still
// provide a `main`, so dispatch here instead of gating the whole binary away.

#[cfg(target_arch = "x86_64")]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use litebox_runner_optee_on_linux_userland::CliArgs;

    litebox_runner_optee_on_linux_userland::run(CliArgs::parse())
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!(
        "litebox_runner_optee_on_linux_userland is only supported on x86-64; \
         this binary was built for {}.",
        std::env::consts::ARCH
    );
    std::process::exit(1);
}
