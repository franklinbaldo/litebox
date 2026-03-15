// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::PathBuf;

/// Prebuilt aarch64-linux ELF shared object for rtld_audit (ARM64 target).
const PREBUILT_RTLD_AUDIT_SO_AARCH64: &str = "tests/test-bins-aarch64/litebox_rtld_audit.so";

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    if target_arch == "aarch64" {
        validate_and_copy_rtld_audit(
            PREBUILT_RTLD_AUDIT_SO_AARCH64,
            0xb7, // EM_AARCH64
            "EM_AARCH64",
            &out_dir,
        );
    }
}

fn validate_and_copy_rtld_audit(
    prebuilt_path: &str,
    expected_machine: u16,
    machine_name: &str,
    out_dir: &std::path::Path,
) {
    let src = PathBuf::from(prebuilt_path);
    if !src.exists() {
        // Test binaries may not be present in all checkouts (e.g., CI cross-check).
        return;
    }

    let header = std::fs::read(&src).expect("failed to read rtld_audit.so");
    assert!(
        header.len() >= 20,
        "rtld_audit.so is too small ({} bytes) to be a valid ELF",
        header.len()
    );
    assert_eq!(
        &header[..4],
        b"\x7fELF",
        "rtld_audit.so is not a valid ELF file"
    );
    let e_machine = u16::from_le_bytes([header[18], header[19]]);
    assert_eq!(
        e_machine, expected_machine,
        "rtld_audit.so has wrong architecture: e_machine={e_machine:#x} (expected {expected_machine:#x} = {machine_name})",
    );

    let dst = out_dir.join("litebox_rtld_audit.so");
    std::fs::copy(&src, &dst).unwrap_or_else(|err| {
        panic!(
            "failed to copy prebuilt rtld_audit.so from {} to {}: {err}",
            src.display(),
            dst.display(),
        )
    });

    println!("cargo:rerun-if-changed={prebuilt_path}");
    println!("cargo:rerun-if-changed=build.rs");
}
