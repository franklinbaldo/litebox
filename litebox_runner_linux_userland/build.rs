// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Links this crate's binary and integration tests against
//! `litebox_platform_linux_userland/litebox_tls.ld`, which pins
//! `.tdata.litebox_tls` to the front of the static TLS block on AArch64. See
//! that file for why it is needed.
//!
//! It cannot be inherited: Cargo build scripts only add link arguments to their
//! own package's artifacts, so a dependency cannot supply this on our behalf.
//! Without it this crate links two `tracing_subscriber` thread-locals ahead of
//! the block, moving `guest_tpidr` off the `litebox_syscall_rewriter` ABI's +16
//! and tripping `assert_tls_layout()` at startup.

fn main() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has a workspace-root parent")
        .join("litebox_platform_linux_userland")
        .join("litebox_tls.ld");

    println!("cargo::rerun-if-changed={}", script.display());

    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64") {
        let script = script.display();
        println!("cargo::rustc-link-arg-bins=-Wl,-T,{script}");
        println!("cargo::rustc-link-arg-tests=-Wl,-T,{script}");
    }
}
