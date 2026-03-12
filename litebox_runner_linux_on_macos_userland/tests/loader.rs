// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

fn run_dynamic_linked_prog_with_rewriter(
    libs_to_rewrite: &[(&str, &str)],
    libs_without_rewrite: &[(&str, &str)],
    exec_name: &str,
    cmd_args: &[&str],
    install_files: fn(std::path::PathBuf),
) {
    // Use the already compiled executable from the tests folder.
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests/test-bins");

    let prog_name = exec_name;
    let prog_name_hooked = format!("{prog_name}.hooked");

    let path = test_dir.join(prog_name);
    let hooked_path = test_dir.join(&prog_name_hooked);

    let out_path = std::env::var("OUT_DIR").unwrap();

    // Rewrite the target ELF executable file.
    let _ = std::fs::remove_file(hooked_path.clone());
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(&cargo)
        .args([
            "run",
            "-p",
            "litebox_syscall_rewriter",
            "--",
            path.to_str().unwrap(),
            "-o",
            hooked_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run syscall rewriter");
    assert!(
        output.status.success(),
        "failed to run syscall rewriter {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

    // Create tar file containing all dependencies.
    let tar_src_path = std::path::Path::new(&out_path).join("test_program_tar");
    println!(
        "Creating tar source directory path: {}",
        tar_src_path.to_str().unwrap()
    );

    std::fs::create_dir_all(tar_src_path.join("out")).unwrap();

    // Rewrite all libraries that are required for initialization.
    for (file, prefix) in libs_to_rewrite {
        let src = test_dir.join(file);
        let dst_dir = tar_src_path.join(prefix.trim_start_matches('/'));
        let dst = dst_dir.join(file);
        std::fs::create_dir_all(&dst_dir).unwrap();
        let _ = std::fs::remove_file(&dst);
        println!(
            "Running `cargo run -p litebox_syscall_rewriter -- {} -o {}`",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        );
        let output = std::process::Command::new(&cargo)
            .args([
                "run",
                "-p",
                "litebox_syscall_rewriter",
                "--",
                src.to_str().unwrap(),
                "-o",
                dst.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to run syscall rewriter");
        assert!(
            output.status.success(),
            "failed to run syscall rewriter {:?}",
            std::str::from_utf8(output.stderr.as_slice()).unwrap()
        );
    }

    // Copy libraries that don't need rewriting (litebox_rtld_audit.so)
    // to the tar directory.
    for (file, prefix) in libs_without_rewrite {
        let src = test_dir.join(file);
        let dst_dir = tar_src_path.join(prefix.trim_start_matches('/'));
        let dst = dst_dir.join(file);
        std::fs::create_dir_all(&dst_dir).unwrap();
        let _ = std::fs::remove_file(&dst);
        println!(
            "Copying {} to {}",
            src.to_str().unwrap(),
            dst.to_str().unwrap()
        );
        std::fs::copy(&src, &dst).unwrap();
    }

    // Install the required files (e.g., scripts) to the tar directory's /out.
    install_files(tar_src_path.join("out"));

    // Create tar. Use ustar format because macOS `tar` defaults to pax, and
    // the `tar-no-std` crate used by litebox cannot parse pax extended headers.
    // COPYFILE_DISABLE=1 prevents macOS from adding AppleDouble `._` resource fork files.
    let tar_target_file = std::path::Path::new(&out_path).join("rootfs_rewriter.tar");
    let tar_data = std::process::Command::new("tar")
        .args([
            "--format=ustar",
            "-cvf",
            tar_target_file.to_str().unwrap(),
            "lib",
            "out",
        ])
        .env("COPYFILE_DISABLE", "1")
        .current_dir(&tar_src_path)
        .output()
        .expect("Failed to create tar file");
    assert!(
        tar_data.status.success(),
        "failed to create tar file {:?}",
        std::str::from_utf8(tar_data.stderr.as_slice()).unwrap()
    );
    println!("Tar file created at: {}", tar_target_file.to_str().unwrap());

    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_on_macos_userland")
        .unwrap_or_else(|_| {
            env!("CARGO_BIN_EXE_litebox_runner_linux_on_macos_userland").to_string()
        });

    // Run litebox_runner_linux_on_macos_userland with the tar file and the compiled executable.
    let mut args = vec![
        "--unstable",
        // Tell ld where to find the libraries.
        "--env",
        "LD_LIBRARY_PATH=/lib:/lib/aarch64-linux-gnu",
        "--initial-files",
        tar_target_file.to_str().unwrap(),
        "--env",
        "LD_AUDIT=/lib/litebox_rtld_audit.so",
    ];
    args.push(hooked_path.to_str().unwrap());
    args.extend_from_slice(cmd_args);

    let mut command = std::process::Command::new(&binary_path);
    command.args(&args);
    println!("Running `{command:?}`");
    let output = command
        .output()
        .expect("Failed to run litebox_runner_linux_on_macos_userland");
    if !output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout).unwrap_or("<non-utf8>");
        let stderr = std::str::from_utf8(&output.stderr).unwrap_or("<non-utf8>");
        panic!(
            "failed to run litebox_runner_linux_on_macos_userland: {}\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        );
    }
}

#[test]
fn test_dynamic_linked_prog_with_rewriter() {
    let exec_name = "hello_world_dyn";
    // aarch64 Linux library paths.
    let libs_to_rewrite = [
        ("libc.so.6", "/lib/aarch64-linux-gnu"),
        ("ld-linux-aarch64.so.1", "/lib"),
    ];
    let libs_without_rewrite = [("litebox_rtld_audit.so", "/lib")];

    run_dynamic_linked_prog_with_rewriter(
        &libs_to_rewrite,
        &libs_without_rewrite,
        exec_name,
        &[],
        |_| {},
    );
}

#[test]
fn test_dynamic_linked_hello_thread() {
    let exec_name = "hello_thread";
    let libs_to_rewrite = [
        ("libc.so.6", "/lib/aarch64-linux-gnu"),
        ("ld-linux-aarch64.so.1", "/lib"),
    ];
    let libs_without_rewrite = [("litebox_rtld_audit.so", "/lib")];

    run_dynamic_linked_prog_with_rewriter(
        &libs_to_rewrite,
        &libs_without_rewrite,
        exec_name,
        &[],
        |_| {},
    );
}
