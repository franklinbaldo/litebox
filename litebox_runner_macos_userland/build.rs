// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::PathBuf;

const PREBUILT_RTLD_AUDIT_SO: &str = "../litebox_rtld_audit/litebox_rtld_audit.so";

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_arch != "aarch64" {
        return;
    }

    // On macOS arm64, shrink __PAGEZERO from the default 4 GB down to 64 KB.
    // Without this, the first 4 GB of virtual address space is unmappable,
    // which prevents loading ET_EXEC ELF binaries at their fixed Linux load
    // address (typically 0x400000).
    if target_os == "macos" {
        println!("cargo:rustc-link-arg-bins=-Wl,-pagezero_size,0x10000");
        println!("cargo:rustc-link-arg-tests=-Wl,-pagezero_size,0x10000");
    }

    let src = PathBuf::from(PREBUILT_RTLD_AUDIT_SO);
    assert!(
        src.exists(),
        "missing prebuilt rtld_audit.so at {}. Build it on Linux first",
        src.display()
    );

    let dst = out_dir.join("litebox_rtld_audit.so");
    std::fs::copy(&src, &dst).unwrap_or_else(|err| {
        panic!(
            "failed to copy prebuilt rtld_audit.so from {} to {}: {}",
            src.display(),
            dst.display(),
            err
        )
    });
    assert!(dst.exists(), "Build failed to create necessary file");

    println!("cargo:rerun-if-changed={PREBUILT_RTLD_AUDIT_SO}");
    println!("cargo:rerun-if-changed=build.rs");
}
