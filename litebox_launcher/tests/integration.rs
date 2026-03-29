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
    // With EXEC_LOCAL, micro executes write(1, ...) locally, so the
    // guest message appears on stdout (fd 1) of the launcher process.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("=== launcher stdout ===\n{stdout}");
    eprintln!("=== launcher stderr ===\n{stderr}");

    assert!(
        stdout.contains("Hello from micro-LiteBox!"),
        "Expected guest output in stdout, got:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        output.status.success(),
        "launcher exited with status: {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
}

#[test]
#[ignore] // Run with: cargo nextest run -p litebox_launcher -- --ignored test_thread_nolibc
fn test_thread_nolibc_end_to_end() {
    // Step 1: Compile the nolibc binary
    let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let c_src = test_dir.join("thread_nolibc.c");
    let compiled = test_dir.join("thread_nolibc");
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
    let rewritten = test_dir.join("thread_nolibc.hooked");
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

    // Step 5: Run the launcher with a timeout to prevent hangs
    let child = Command::new(&launcher_bin)
        .arg(&rewritten)
        .env("LITEBOX_CENTRAL_PATH", target_dir.join("litebox_central"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("launcher should start");

    let output = child
        .wait_with_output()
        .expect("launcher should produce output");

    // Step 6: Check output
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("=== launcher stdout ===\n{stdout}");
    eprintln!("=== launcher stderr ===\n{stderr}");

    assert!(
        stdout.contains("Hello from main thread!"),
        "Missing main thread output:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("Hello from child thread!"),
        "Missing child thread output:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        output.status.success(),
        "launcher exited with status: {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
}

#[test]
#[ignore] // Run with: cargo nextest run -p litebox_launcher -- --ignored test_fork_nolibc
fn test_fork_nolibc_end_to_end() {
    // Step 1: Compile the nolibc fork binary
    let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let c_src = test_dir.join("fork_nolibc.c");
    let compiled = test_dir.join("fork_nolibc");
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
    let rewritten = test_dir.join("fork_nolibc.hooked");
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

    // Step 5: Run the launcher with the rewritten fork binary
    let child = Command::new(&launcher_bin)
        .arg(&rewritten)
        .env("LITEBOX_CENTRAL_PATH", target_dir.join("litebox_central"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("launcher should start");

    let output = child
        .wait_with_output()
        .expect("launcher should produce output");

    // Step 6: Check output
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("=== launcher stdout ===\n{stdout}");
    eprintln!("=== launcher stderr ===\n{stderr}");

    assert!(
        stdout.contains("Hello from fork child!"),
        "Missing fork child output:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("Hello from fork parent!"),
        "Missing fork parent output:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        output.status.success(),
        "launcher exited with status: {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
}

#[test]
#[ignore] // Run with: cargo nextest run -p litebox_launcher -- --ignored test_dynamic_hello
fn test_dynamic_hello_world() {
    let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let target_dir = workspace_root.join("target").join("debug");

    // Step 1: Compile a dynamically-linked C program.
    let c_src = test_dir.join("hello_dynamic.c");
    let compiled = test_dir.join("hello_dynamic");
    let status = Command::new("gcc")
        .args(["-o"])
        .arg(&compiled)
        .arg(&c_src)
        .status()
        .expect("gcc should run");
    assert!(status.success(), "gcc compilation failed");

    // Step 2: Build launcher + central + packager.
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "litebox_launcher",
            "-p",
            "litebox_central",
            "-p",
            "litebox_packager",
        ])
        .status()
        .expect("cargo build should run");
    assert!(status.success(), "cargo build failed");

    // Step 3: Run litebox_packager to produce a tar with rewritten ELFs.
    let tar_path = test_dir.join("hello_dynamic.tar");
    let packager_bin = target_dir.join("litebox_packager");
    assert!(
        packager_bin.exists(),
        "litebox_packager binary not found at {}",
        packager_bin.display()
    );

    let output = Command::new(&packager_bin)
        .args(["-v", "-o"])
        .arg(&tar_path)
        .arg(&compiled)
        .output()
        .expect("litebox_packager should run");
    let packager_stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("=== packager stderr ===\n{packager_stderr}");
    assert!(
        output.status.success(),
        "litebox_packager failed: {packager_stderr}"
    );

    // Step 4: Extract the tar to a temp directory so the launcher can find
    // the rewritten main binary and the rewritten interpreter.
    let extract_dir = test_dir.join("hello_dynamic_rootfs");
    if extract_dir.exists() {
        std::fs::remove_dir_all(&extract_dir).expect("clean up old extraction dir");
    }
    std::fs::create_dir_all(&extract_dir).expect("create extraction dir");

    let status = Command::new("tar")
        .args(["xf"])
        .arg(&tar_path)
        .arg("-C")
        .arg(&extract_dir)
        .status()
        .expect("tar extraction should run");
    assert!(status.success(), "tar extraction failed");

    // Step 5: Find the rewritten main binary inside the extracted rootfs.
    // The packager stores files without leading '/', e.g. for
    // /workspace/.../tests/hello_dynamic → workspace/.../tests/hello_dynamic
    let compiled_abs = std::fs::canonicalize(&compiled).expect("canonicalize compiled binary");
    let rel_path = compiled_abs
        .to_str()
        .unwrap()
        .strip_prefix('/')
        .unwrap_or(compiled_abs.to_str().unwrap());
    let extracted_binary = extract_dir.join(rel_path);
    assert!(
        extracted_binary.exists(),
        "Rewritten binary not found in extracted tar at {}",
        extracted_binary.display()
    );

    // Make it executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&extracted_binary, std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    // Step 6: Run the launcher with the rewritten binary.
    let launcher_bin = target_dir.join("litebox_launcher");
    assert!(
        launcher_bin.exists(),
        "litebox_launcher binary not found at {}",
        launcher_bin.display()
    );

    let rootfs_tar_arg = format!("--rootfs-tar={}", tar_path.display());
    let rootfs_prefix_arg = format!("--rootfs-prefix={}", extract_dir.display());

    let child = Command::new(&launcher_bin)
        .arg(&extracted_binary)
        .arg(&rootfs_tar_arg)
        .arg(&rootfs_prefix_arg)
        .env("LITEBOX_CENTRAL_PATH", target_dir.join("litebox_central"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("launcher should start");

    let output = child
        .wait_with_output()
        .expect("launcher should produce output");

    // Step 7: Check output.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("=== launcher stdout ===\n{stdout}");
    eprintln!("=== launcher stderr ===\n{stderr}");

    assert!(
        stdout.contains("Hello from dynamic libc!"),
        "Expected 'Hello from dynamic libc!' in stdout, got:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        output.status.success(),
        "launcher exited with status: {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&extract_dir);
    let _ = std::fs::remove_file(&tar_path);
}
