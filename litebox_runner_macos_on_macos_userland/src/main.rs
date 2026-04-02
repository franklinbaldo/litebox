// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    let cli_args = <litebox_runner_macos_on_macos_userland::CliArgs as clap::Parser>::parse();
    if let Err(e) = litebox_runner_macos_on_macos_userland::run(cli_args) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("This program is only supported on macOS aarch64");
    std::process::exit(1);
}
