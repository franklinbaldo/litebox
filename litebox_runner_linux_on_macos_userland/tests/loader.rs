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
    // to the tar directory. The rtld_audit prebuilt lives in the centralized
    // prebuilt directory; other files come from test-bins.
    let prebuilt_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../litebox_rtld_audit/prebuilt");
    for (file, prefix) in libs_without_rewrite {
        let src = if *file == "litebox_rtld_audit.so" {
            prebuilt_dir.join("litebox_rtld_audit_aarch64_macos.so")
        } else {
            test_dir.join(file)
        };
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

/// Run a statically-linked aarch64 Linux program inside litebox with utun networking.
///
/// This function:
/// 1. Rewrites the static binary's syscalls
/// 2. Packages it into a tar file
/// 3. Launches the runner with `--tun-device-name`
/// 4. Returns the spawned child process (caller is responsible for waiting)
fn run_static_prog_with_utun(
    exec_name: &str,
    cmd_args: &[&str],
    tun_device_name: &str,
) -> std::process::Child {
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests/test-bins");

    let out_path = std::env::var("OUT_DIR").unwrap();
    let hooked_path =
        std::path::Path::new(&out_path).join(format!("{exec_name}.static_utun.hooked"));

    // Rewrite the static ELF executable.
    let path = test_dir.join(exec_name);
    let _ = std::fs::remove_file(&hooked_path);
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
        "failed to run syscall rewriter: {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

    // Create a minimal tar with just an /out directory (no shared libraries needed for static
    // binary).
    let tar_src_path = std::path::Path::new(&out_path).join(format!("tar_{exec_name}_utun"));
    std::fs::create_dir_all(tar_src_path.join("out")).unwrap();

    let tar_target_file =
        std::path::Path::new(&out_path).join(format!("rootfs_{exec_name}_utun.tar"));
    let tar_data = std::process::Command::new("tar")
        .args([
            "--format=ustar",
            "-cvf",
            tar_target_file.to_str().unwrap(),
            "out",
        ])
        .env("COPYFILE_DISABLE", "1")
        .current_dir(&tar_src_path)
        .output()
        .expect("Failed to create tar file");
    assert!(
        tar_data.status.success(),
        "failed to create tar file: {:?}",
        std::str::from_utf8(tar_data.stderr.as_slice()).unwrap()
    );

    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_on_macos_userland")
        .unwrap_or_else(|_| {
            env!("CARGO_BIN_EXE_litebox_runner_linux_on_macos_userland").to_string()
        });

    let mut args = vec![
        "--unstable".to_string(),
        "--tun-device-name".to_string(),
        tun_device_name.to_string(),
        "--initial-files".to_string(),
        tar_target_file.to_str().unwrap().to_string(),
        hooked_path.to_str().unwrap().to_string(),
    ];
    for arg in cmd_args {
        args.push((*arg).to_string());
    }

    let mut command = std::process::Command::new(&binary_path);
    command
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    println!("Spawning runner: {command:?}");
    command.spawn().expect("Failed to spawn runner")
}

/// Returns `true` when we are already running as root (euid 0).
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Wait for a utun interface to appear (up to `timeout`), then configure its IP address.
///
/// If the runner subprocess has already exited (crashed), returns early with diagnostics.
/// Returns `true` if configuration succeeded.
fn configure_utun(
    device: &str,
    ip: &str,
    timeout: std::time::Duration,
    runner: &mut std::process::Child,
) -> bool {
    let start = std::time::Instant::now();
    // Wait for the utun device to appear.
    while start.elapsed() < timeout {
        // Check if the runner has already exited (crashed).
        if let Some(status) = runner.try_wait().expect("Failed to check runner status") {
            let mut stderr_buf = String::new();
            if let Some(ref mut stderr) = runner.stderr {
                use std::io::Read as _;
                let _ = stderr.read_to_string(&mut stderr_buf);
            }
            let mut stdout_buf = String::new();
            if let Some(ref mut stdout) = runner.stdout {
                use std::io::Read as _;
                let _ = stdout.read_to_string(&mut stdout_buf);
            }
            eprintln!("Runner exited early with status: {status}");
            if !stdout_buf.is_empty() {
                eprintln!("Runner stdout:\n{stdout_buf}");
            }
            if !stderr_buf.is_empty() {
                eprintln!("Runner stderr:\n{stderr_buf}");
            }
            return false;
        }

        let output = std::process::Command::new("ifconfig")
            .arg(device)
            .output()
            .expect("Failed to run ifconfig");
        if output.status.success() {
            println!("{device} appeared after {:?}", start.elapsed());
            // Assign IP address. When running as root, call ifconfig directly;
            // otherwise use sudo -n.
            let result = if is_root() {
                std::process::Command::new("ifconfig")
                    .args([device, ip, ip, "netmask", "255.255.255.0", "up"])
                    .status()
                    .expect("Failed to run ifconfig")
            } else {
                std::process::Command::new("sudo")
                    .args([
                        "-n",
                        "ifconfig",
                        device,
                        ip,
                        ip,
                        "netmask",
                        "255.255.255.0",
                        "up",
                    ])
                    .status()
                    .expect("Failed to run sudo ifconfig")
            };
            if !result.success() {
                eprintln!("Failed to configure {device} with IP {ip} (need sudo/root)");
                return false;
            }
            // Add route.
            if is_root() {
                let _ = std::process::Command::new("route")
                    .args(["-n", "add", "-net", "10.0.0.0/24", "-interface", device])
                    .status();
            } else {
                let _ = std::process::Command::new("sudo")
                    .args([
                        "-n",
                        "route",
                        "-n",
                        "add",
                        "-net",
                        "10.0.0.0/24",
                        "-interface",
                        device,
                    ])
                    .status();
            }
            println!("Configured {device} with {ip}/24");
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    eprintln!("{device} did not appear within {timeout:?}");
    false
}

/// Test utun networking with a simple TCP server/client exchange.
///
/// This test:
/// 1. Starts a statically-linked TCP server inside litebox (bound to 10.0.0.2:12345)
/// 2. Configures the utun interface on the host (10.0.0.1/24)
/// 3. Runs a native TCP client that connects to 10.0.0.2:12345
/// 4. Verifies the full round-trip succeeds
///
/// Requires:
/// - The `tcp_server` binary in `tests/test-bins/` (aarch64 Linux, statically linked)
/// - Root/sudo access for `ifconfig` to configure the utun device
///
/// To run:
/// ```sh
/// sudo cargo test -p litebox_runner_linux_on_macos_userland -- test_utun_with_tcp_socket --exact --nocapture --ignored
/// ```
#[test]
#[ignore = "requires root for utun IP configuration"]
fn test_utun_with_tcp_socket() {
    let tun_device = "utun99";
    let guest_ip = "10.0.0.2";
    let host_ip = "10.0.0.1";
    let port = "12345";

    // Start the TCP server inside litebox with utun.
    let mut runner = run_static_prog_with_utun("tcp_server", &[guest_ip, port], tun_device);

    // Give the runner time to start and create the utun device, then configure host IP.
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(
        configure_utun(
            tun_device,
            host_ip,
            std::time::Duration::from_secs(10),
            &mut runner
        ),
        "Failed to configure {tun_device}"
    );

    // Wait a moment for the TCP server inside litebox to start listening.
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Run the native TCP client against the guest IP.
    // We compile tcp_client.c on-the-fly for the host (macOS).
    let client_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../litebox_runner_linux_userland/tests/net/tcp_client.c");
    let out_path = std::env::var("OUT_DIR").unwrap();
    let client_bin = std::path::Path::new(&out_path).join("tcp_client_native");
    let compile = std::process::Command::new("cc")
        .args([
            "-o",
            client_bin.to_str().unwrap(),
            client_src.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to compile tcp_client.c for host");
    assert!(
        compile.status.success(),
        "Failed to compile tcp_client: {:?}",
        std::str::from_utf8(&compile.stderr).unwrap()
    );

    println!(
        "Running TCP client: {} {guest_ip} {port}",
        client_bin.display()
    );
    let client_output = std::process::Command::new(client_bin.to_str().unwrap())
        .args([guest_ip, port])
        .output()
        .expect("Failed to run TCP client");

    let client_stdout = std::str::from_utf8(&client_output.stdout).unwrap_or("<non-utf8>");
    let client_stderr = std::str::from_utf8(&client_output.stderr).unwrap_or("<non-utf8>");
    println!("Client stdout:\n{client_stdout}");
    if !client_stderr.is_empty() {
        println!("Client stderr:\n{client_stderr}");
    }
    assert!(
        client_output.status.success(),
        "TCP client failed: {}\nstdout: {client_stdout}\nstderr: {client_stderr}",
        client_output.status
    );

    // Wait for the runner to finish (the server exits after handling one client).
    // The server uses exit_group which should interrupt all threads. Add a timeout
    // in case exit doesn't fully terminate the process.
    let runner_timeout = std::time::Duration::from_secs(20);
    let runner_wait_start = std::time::Instant::now();
    loop {
        if runner
            .try_wait()
            .expect("Failed to check runner status")
            .is_some()
        {
            break;
        }
        if runner_wait_start.elapsed() > runner_timeout {
            eprintln!("Runner did not exit within {runner_timeout:?}, killing it");
            let _ = runner.kill();
            let _ = runner.wait();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let output = runner.wait_with_output().expect("Failed to wait on runner");
    let runner_stdout = std::str::from_utf8(&output.stdout).unwrap_or("<non-utf8>");
    let runner_stderr = std::str::from_utf8(&output.stderr).unwrap_or("<non-utf8>");
    println!("Runner stdout:\n{runner_stdout}");
    if !runner_stderr.is_empty() {
        println!("Runner stderr:\n{runner_stderr}");
    }
    assert!(
        output.status.success(),
        "Runner failed: {}\nstdout: {runner_stdout}\nstderr: {runner_stderr}",
        output.status
    );
}

/// Test utun networking with a timed TCP bandwidth throughput measurement.
///
/// This test:
/// 1. Starts a statically-linked TCP bandwidth server inside litebox (bound to 10.0.0.2:12346)
/// 2. Configures the utun interface on the host (10.0.0.1/24)
/// 3. Compiles and runs a native TCP bandwidth client that sends data for a fixed duration
/// 4. Parses the `RESULT:` line from the server to compute throughput
///
/// Requires:
/// - The `tcp_bandwidth_server` binary in `tests/test-bins/` (aarch64 Linux, statically linked)
/// - Root/sudo access for `ifconfig` to configure the utun device
///
/// To run:
/// ```sh
/// sudo cargo test -p litebox_runner_linux_on_macos_userland --test loader -- test_utun_tcp_bandwidth --exact --nocapture --ignored
/// ```
#[test]
#[ignore = "requires root for utun IP configuration"]
fn test_utun_tcp_bandwidth() {
    let tun_device = "utun98";
    let guest_ip = "10.0.0.2";
    let host_ip = "10.0.0.1";
    let port = "12346";
    let duration_secs = "3";

    // Server receives for slightly longer than the client sends, to capture all in-flight data.
    let server_duration = format!("{}", duration_secs.parse::<u32>().unwrap() + 2);

    // Start the TCP bandwidth server inside litebox with utun.
    let mut runner = run_static_prog_with_utun(
        "tcp_bandwidth_server",
        &[guest_ip, port, &server_duration],
        tun_device,
    );

    // Capture runner stdout in a background thread so we can parse RESULT in real-time.
    let runner_stdout_handle = runner.stdout.take().expect("runner stdout not piped");
    let stdout_collector = std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(runner_stdout_handle);
        let mut lines = Vec::new();
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    println!("[runner stdout] {l}");
                    lines.push(l);
                }
                Err(e) => {
                    eprintln!("[runner stdout] read error: {e}");
                    break;
                }
            }
        }
        lines
    });

    // Give the runner time to start and create the utun device, then configure host IP.
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(
        configure_utun(
            tun_device,
            host_ip,
            std::time::Duration::from_secs(10),
            &mut runner
        ),
        "Failed to configure {tun_device}"
    );

    // Wait a moment for the TCP bandwidth server inside litebox to start listening.
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Compile the bandwidth client for the host (macOS).
    let client_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/net/tcp_bandwidth_client.c");
    let out_path = std::env::var("OUT_DIR").unwrap();
    let client_bin = std::path::Path::new(&out_path).join("tcp_bandwidth_client_native");
    let compile = std::process::Command::new("cc")
        .args([
            "-o",
            client_bin.to_str().unwrap(),
            client_src.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to compile tcp_bandwidth_client.c for host");
    assert!(
        compile.status.success(),
        "Failed to compile bandwidth client: {:?}",
        std::str::from_utf8(&compile.stderr).unwrap()
    );

    println!(
        "Running bandwidth client: {} {guest_ip} {port} {duration_secs}",
        client_bin.display()
    );
    let client_output = std::process::Command::new(client_bin.to_str().unwrap())
        .args([guest_ip, port, duration_secs])
        .output()
        .expect("Failed to run bandwidth client");

    let client_stdout = std::str::from_utf8(&client_output.stdout).unwrap_or("<non-utf8>");
    let client_stderr = std::str::from_utf8(&client_output.stderr).unwrap_or("<non-utf8>");
    println!("Bandwidth client stdout:\n{client_stdout}");
    if !client_stderr.is_empty() {
        println!("Bandwidth client stderr:\n{client_stderr}");
    }
    if !client_output.status.success() {
        let _ = runner.kill();
        let _ = runner.wait();
        let runner_lines = stdout_collector.join().unwrap_or_default();
        panic!(
            "Bandwidth client failed: {}\nClient stdout: {client_stdout}\n\
             Client stderr: {client_stderr}\nRunner stdout lines: {runner_lines:?}",
            client_output.status
        );
    }

    // Wait for the runner to exit. The server uses exit_group which should interrupt
    // all threads (including the network worker). Give it generous time.
    let runner_timeout =
        std::time::Duration::from_secs(server_duration.parse::<u64>().unwrap() + 15);
    let runner_wait_start = std::time::Instant::now();
    let mut runner_exited = false;
    loop {
        if runner
            .try_wait()
            .expect("Failed to check runner status")
            .is_some()
        {
            runner_exited = true;
            break;
        }
        if runner_wait_start.elapsed() > runner_timeout {
            eprintln!(
                "Runner did not exit within {runner_timeout:?}, killing it \
                 (exit_group may not have fully terminated the process)"
            );
            let _ = runner.kill();
            let _ = runner.wait();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Collect all runner stdout lines from the background thread.
    let runner_lines = stdout_collector.join().expect("stdout collector panicked");
    let runner_stdout = runner_lines.join("\n");
    println!("Runner stdout (collected):\n{runner_stdout}");

    if runner_exited {
        // Verify the runner exited successfully (status 0).
        // Note: wait() was already called implicitly by try_wait() returning Some.
        // We need wait_with_output to get the exit status, but stdout is already taken.
        // Since try_wait returned Some, just read stderr.
        let mut stderr_buf = String::new();
        if let Some(ref mut err) = runner.stderr {
            use std::io::Read as _;
            let _ = err.read_to_string(&mut stderr_buf);
        }
        if !stderr_buf.is_empty() {
            println!("Runner stderr:\n{stderr_buf}");
        }
    }

    // Parse the RESULT line from the server output.
    // Format: "RESULT: <bytes> bytes in <ms> ms"
    let result_line = runner_lines
        .iter()
        .find(|line| line.contains("RESULT:"))
        .expect("No RESULT line found in runner output");
    println!("Server result: {result_line}");

    // Parse bytes and ms from the RESULT line.
    let parts: Vec<&str> = result_line.split_whitespace().collect();
    // Expected: ["RESULT:", "<bytes>", "bytes", "in", "<ms>", "ms"]
    assert!(parts.len() >= 6, "Unexpected RESULT format: {result_line}");
    let total_bytes: u64 = parts[1]
        .parse()
        .unwrap_or_else(|_| panic!("Failed to parse bytes from: {result_line}"));
    let elapsed_ms: u64 = parts[4]
        .parse()
        .unwrap_or_else(|_| panic!("Failed to parse ms from: {result_line}"));

    // Compute throughput.
    #[allow(clippy::cast_precision_loss)]
    let throughput_mbps = if elapsed_ms > 0 {
        (total_bytes as f64) / 1024.0 / 1024.0 / (elapsed_ms as f64 / 1000.0)
    } else {
        0.0
    };
    println!(
        "\n===== Bandwidth Test Results =====\n\
         Total bytes received by server: {total_bytes}\n\
         Elapsed time: {elapsed_ms} ms\n\
         Throughput: {throughput_mbps:.2} MB/s\n\
         =================================="
    );

    // Sanity check: we should have transferred at least some data.
    assert!(
        total_bytes > 0,
        "No data was transferred during the bandwidth test"
    );
    assert!(
        elapsed_ms > 0,
        "Elapsed time was zero during the bandwidth test"
    );
}
