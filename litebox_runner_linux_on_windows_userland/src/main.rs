// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Windows (x86-64 or ARM64).

#[cfg(all(
    target_os = "windows",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use litebox_runner_linux_on_windows_userland::CliArgs;
    litebox_runner_linux_on_windows_userland::run(CliArgs::parse())
}

#[cfg(not(all(
    target_os = "windows",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn main() {
    eprintln!("This program is only supported on Windows x86_64 or ARM64");
    std::process::exit(1);
}
