// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::PathBuf;

/// The git-tracked prebuilt aarch64-linux ELF shared object for rtld_audit.
/// This is the authoritative copy — do NOT use the .gitignore'd build artifact
/// in `../litebox_rtld_audit/` which may have the wrong architecture.
const PREBUILT_RTLD_AUDIT_SO: &str = "tests/test-bins/litebox_rtld_audit.so";

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if target_arch != "aarch64" {
        return;
    }

    let src = PathBuf::from(PREBUILT_RTLD_AUDIT_SO);
    assert!(
        src.exists(),
        "missing prebuilt rtld_audit.so at {}",
        src.display()
    );

    // Validate that the prebuilt .so is an aarch64 ELF (e_machine = 0xb7 at offset 18).
    // This prevents subtle runtime failures if the wrong architecture is embedded.
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
        e_machine,
        0xb7, // EM_AARCH64
        "rtld_audit.so has wrong architecture: e_machine={e_machine:#x} (expected 0xb7 = EM_AARCH64). \
         This binary must be a Linux aarch64 ELF.",
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
