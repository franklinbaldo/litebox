// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::PathBuf;

const RTLD_AUDIT_DIR: &str = "../litebox_rtld_audit";
const PREBUILT_DIR: &str = "../litebox_rtld_audit/prebuilt";

fn output_name(target_os: &str) -> String {
    format!("litebox_rtld_audit_{target_os}.so")
}

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if target_arch != "x86_64" && target_arch != "aarch64" {
        return;
    }

    let host_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    if host_os == "linux" {
        // On Linux: build from source for all target OS variants.
        // x86_64 only needs "linux" (platform-specific code is aarch64-only).
        // aarch64 needs linux, windows, and macos.
        let variants: &[&str] = match target_arch.as_str() {
            "x86_64" => &["linux"],
            "aarch64" => &["linux", "windows", "macos"],
            _ => unreachable!(),
        };
        build_from_source(&target_arch, variants, &out_dir);
    } else {
        // On non-Linux (macOS, Windows): use prebuilt binary for the host OS.
        // The packager on these platforms only targets the host OS, so we only
        // need that single variant.
        let variant = match host_os.as_str() {
            "macos" => "macos",
            "windows" => "windows",
            other => panic!("unsupported host OS for packager: {other}"),
        };
        copy_prebuilt(&target_arch, variant, &out_dir);
    }

    println!("cargo:rerun-if-changed={RTLD_AUDIT_DIR}/rtld_audit.c");
    println!("cargo:rerun-if-changed={RTLD_AUDIT_DIR}/Makefile");
    println!("cargo:rerun-if-changed={PREBUILT_DIR}");
    println!("cargo:rerun-if-changed=build.rs");
}

fn build_from_source(target_arch: &str, variants: &[&str], out_dir: &PathBuf) {
    for &target_os in variants {
        let out_name = output_name(target_os);
        let out_path = out_dir.join(&out_name);

        // Force rebuild in case a stale artifact exists from a different config.
        let _ = std::fs::remove_file(&out_path);

        let mut make_cmd = std::process::Command::new("make");
        make_cmd
            .current_dir(RTLD_AUDIT_DIR)
            .env("ARCH", target_arch)
            .env("TARGET_OS", target_os)
            .arg(format!("OUTPUT={}", out_path.display()));
        // Always build without DEBUG for the packager -- packaged binaries are
        // release artifacts.
        make_cmd.env_remove("DEBUG");

        let output = make_cmd
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute make for rtld_audit ({target_os}): {e}"));
        assert!(
            output.status.success(),
            "failed to build {out_name} via make:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(out_path.exists(), "Build failed to create {out_name}");
    }
}

fn copy_prebuilt(target_arch: &str, target_os: &str, out_dir: &PathBuf) {
    let prebuilt_dir = PathBuf::from(PREBUILT_DIR);
    let prebuilt_name = format!("litebox_rtld_audit_{target_arch}_{target_os}.so");
    let prebuilt_path = prebuilt_dir.join(&prebuilt_name);
    let out_name = output_name(target_os);
    let out_path = out_dir.join(&out_name);

    std::fs::copy(&prebuilt_path, &out_path).unwrap_or_else(|e| {
        panic!(
            "Failed to copy prebuilt {}: {e}\n\
             Prebuilt binaries are expected at {PREBUILT_DIR}/{prebuilt_name}.\n\
             Rebuild on a Linux host with:\n\
             \n\
             make -C litebox_rtld_audit ARCH={target_arch} TARGET_OS={target_os} \\\n\
                 OUTPUT=litebox_rtld_audit/prebuilt/{prebuilt_name}",
            prebuilt_path.display()
        )
    });
}
