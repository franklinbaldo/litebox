// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::process::Command;

#[test]
#[ignore] // Run with: cargo nextest run -p litebox_launcher -- --ignored
fn test_hello_nolibc_end_to_end() {
    // Step 1: Compile the nolibc binary
    let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let c_src = test_dir.join("hello_nolibc.c");
    let compiled = test_dir.join("hello_nolibc");
    let status = Command::new("gcc")
        .args(["-static", "-nostdlib", "-o"])
        .arg(&compiled)
        .arg(&c_src)
        .status()
        .expect("gcc should run");
    assert!(status.success(), "gcc compilation failed");

    // Step 2: Rewrite with litebox_syscall_rewriter
    let elf_data = std::fs::read(&compiled).expect("read compiled binary");
    let rewritten_data = litebox_syscall_rewriter::hook_syscalls_in_elf(&elf_data, None)
        .expect("syscall rewriter should succeed");
    let rewritten = test_dir.join("hello_nolibc.hooked");
    std::fs::write(&rewritten, &rewritten_data).expect("write rewritten binary");

    // Make it executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&rewritten, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Step 3: Build launcher + central
    let status = Command::new("cargo")
        .args(["build", "-p", "litebox_launcher", "-p", "litebox_central"])
        .status()
        .expect("cargo build should run");
    assert!(status.success(), "cargo build failed");

    // Step 4: Find the built binaries
    // target/debug/ directory
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let target_dir = workspace_root.join("target").join("debug");
    let launcher_bin = target_dir.join("litebox_launcher");
    assert!(
        launcher_bin.exists(),
        "litebox_launcher binary not found at {}",
        launcher_bin.display()
    );

    // Step 5: Run the launcher
    let output = Command::new(&launcher_bin)
        .arg(&rewritten)
        .env("LITEBOX_CENTRAL_PATH", target_dir.join("litebox_central"))
        .output()
        .expect("launcher should run");

    // Step 6: Check output
    // Central's StdioProvider writes guest stdout to host stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("=== launcher stdout ===\n{stdout}");
    eprintln!("=== launcher stderr ===\n{stderr}");

    assert!(
        stderr.contains("Hello from micro-LiteBox!"),
        "Expected guest output in stderr, got:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        output.status.success(),
        "launcher exited with status: {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
}
