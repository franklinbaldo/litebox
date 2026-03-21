// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::PathBuf;

/// Centralized prebuilt directory for rtld_audit shared objects.
/// The macOS runner executes Linux aarch64 binaries on macOS, so it needs
/// the macOS-targeted variant (compiled with -DTARGET_MACOS).
const PREBUILT_RTLD_AUDIT_SO: &str =
    "../litebox_rtld_audit/prebuilt/litebox_rtld_audit_aarch64_macos.so";

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if target_arch != "aarch64" {
        return;
    }

    let src = PathBuf::from(PREBUILT_RTLD_AUDIT_SO);
    assert!(
        src.exists(),
        "missing prebuilt rtld_audit.so at {}.\n\
         Rebuild on a Linux aarch64 host with:\n\
         make -C litebox_rtld_audit ARCH=aarch64 TARGET_OS=macos \\\n\
             OUTPUT=litebox_rtld_audit/prebuilt/litebox_rtld_audit_aarch64_macos.so",
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
