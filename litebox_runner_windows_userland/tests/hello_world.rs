// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

const HELLO_MESSAGE: &[u8] = b"Hello, World!\r\n";

const REQUIRED_SUPPORT: &str = "required support: load a PE32+ x86_64 console executable from the initial tar filesystem; map its image sections; resolve KERNEL32.dll imports for GetStdHandle, WriteFile, and ExitProcess; initialize a first thread stack/register context; route WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), ...) to runner stdout; propagate ExitProcess(0) as process exit code 0";

const HELLO_WORLD_SOURCE: &str = r#"
#![no_std]
#![no_main]

use core::ffi::c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetStdHandle(nStdHandle: u32) -> *mut c_void;
    fn WriteFile(
        hFile: *mut c_void,
        lpBuffer: *const u8,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> i32;
    fn ExitProcess(uExitCode: u32) -> !;
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn mainCRTStartup() -> ! {
    let message = b"Hello, World!\r\n";
    let mut written = 0u32;
    let stdout = unsafe { GetStdHandle(-11i32 as u32) };
    unsafe {
        WriteFile(
            stdout,
            message.as_ptr(),
            message.len() as u32,
            &raw mut written,
            core::ptr::null_mut(),
        );
    }
    unsafe { ExitProcess(0) }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { ExitProcess(101) }
}
"#;

struct CommandOutput {
    output: std::process::Output,
    timed_out: bool,
}

#[test]
fn run_minimal_hello_world_pe() {
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("hello_world_{}", std::process::id()));
    std::fs::create_dir_all(&test_dir).unwrap();
    let pe_path = build_minimal_hello_world_pe(&test_dir);
    println!("Built hello-world PE fixture at `{}`", pe_path.display());
    let ntdll_path = build_rewritten_ntdll(&test_dir);
    println!(
        "Built rewritten ntdll fixture at `{}`",
        ntdll_path.display()
    );
    let tar_path = test_dir.join("hello_world.tar");
    create_tar_with_hello_exe(&test_dir, &tar_path);

    let mut command =
        std::process::Command::new(env!("CARGO_BIN_EXE_litebox_runner_windows_userland"));
    command.args(["--initial-files", tar_path.to_str().unwrap(), "/hello.exe"]);
    println!("Running `{command:?}`");
    let output = command
        .output()
        .expect("failed to run litebox_runner_windows_userland");

    assert!(
        output.status.success(),
        "runner exited with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output
            .stdout
            .windows(HELLO_MESSAGE.len())
            .any(|window| window == HELLO_MESSAGE),
        "guest hello-world output was not observed; {REQUIRED_SUPPORT}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "documents the current incomplete guest ntdll loader path"]
fn forced_ntdll_loader_reports_current_blocker() {
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("hello_world_ntdll_loader_{}", std::process::id()));
    std::fs::create_dir_all(&test_dir).unwrap();
    let pe_path = build_minimal_hello_world_pe(&test_dir);
    println!("Built hello-world PE fixture at `{}`", pe_path.display());
    let ntdll_path = build_rewritten_ntdll(&test_dir);
    println!(
        "Built rewritten ntdll fixture at `{}`",
        ntdll_path.display()
    );
    let tar_path = test_dir.join("hello_world_ntdll_loader.tar");
    create_tar_with_hello_exe(&test_dir, &tar_path);

    let mut command =
        std::process::Command::new(env!("CARGO_BIN_EXE_litebox_runner_windows_userland"));
    command.env("LITEBOX_LOG", "debug").args([
        "-Z",
        "--force-ntdll-loader",
        "--initial-files",
        tar_path.to_str().unwrap(),
        "/hello.exe",
    ]);
    println!("Running `{command:?}`");
    let CommandOutput { output, timed_out } =
        run_with_timeout(command, std::time::Duration::from_secs(10));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{stdout}\n{stderr}");

    assert!(
        timed_out || !output.status.success(),
        "forced ntdll loader path unexpectedly succeeded; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        combined_output.contains("Starting Windows guest through ntdll!LdrInitializeThunk"),
        "forced ntdll loader path did not reach LdrInitializeThunk\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        combined_output.contains("Guest called NtRaiseHardError")
            || combined_output.contains("Windows guest exception")
            || combined_output.contains("Unsupported Windows syscall")
            || combined_output.contains("Windows vectored exception while in guest"),
        "forced ntdll loader path did not report a useful blocker\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

fn run_with_timeout(
    mut command: std::process::Command,
    timeout: std::time::Duration,
) -> CommandOutput {
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to run litebox_runner_windows_userland");
    let deadline = std::time::Instant::now() + timeout;
    let mut timed_out = false;
    while child
        .try_wait()
        .expect("failed to poll runner child")
        .is_none()
    {
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            child.kill().expect("failed to kill timed-out runner child");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let output = child
        .wait_with_output()
        .expect("failed to collect runner child output");
    CommandOutput { output, timed_out }
}

fn build_minimal_hello_world_pe(test_dir: &std::path::Path) -> std::path::PathBuf {
    let source_path = test_dir.join("hello.rs");
    let exe_path = test_dir.join("hello.exe");
    std::fs::write(&source_path, HELLO_WORLD_SOURCE).unwrap();

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = std::process::Command::new(rustc)
        .args([
            "--edition=2024",
            source_path.to_str().unwrap(),
            "-C",
            "panic=abort",
            "-C",
            "link-arg=/ENTRY:mainCRTStartup",
            "-C",
            "link-arg=/SUBSYSTEM:CONSOLE",
            "-o",
            exe_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run rustc for the minimal Windows PE fixture");

    assert!(
        output.status.success(),
        "failed to build minimal Windows PE fixture\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    exe_path
}

fn build_rewritten_ntdll(test_dir: &std::path::Path) -> std::path::PathBuf {
    let ntdll_path = test_dir.join("ntdll.dll");
    let host_ntdll = std::fs::read(host_ntdll_path()).expect("failed to read host ntdll.dll");
    let rewritten = match litebox_syscall_rewriter::rewrite_binary(&host_ntdll, None) {
        Ok(rewritten) => rewritten,
        Err(litebox_syscall_rewriter::Error::UnpatchableSyscalls(_)) => panic!(
            "failed to rewrite host ntdll.dll; required support: patch dense ntdll syscall stubs or provide a pre-rewritten guest ntdll.dll"
        ),
        Err(error) => panic!("failed to rewrite host ntdll.dll: {error}"),
    };
    std::fs::write(&ntdll_path, rewritten).unwrap();
    ntdll_path
}

fn host_ntdll_path() -> std::path::PathBuf {
    std::env::var_os("SystemRoot")
        .map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        )
        .join("System32")
        .join("ntdll.dll")
}

fn create_tar_with_hello_exe(test_dir: &std::path::Path, tar_path: &std::path::Path) {
    let output = std::process::Command::new("tar.exe")
        .args([
            "-cf",
            tar_path.to_str().unwrap(),
            "-C",
            test_dir.to_str().unwrap(),
            "hello.exe",
            "ntdll.dll",
        ])
        .output()
        .expect("failed to run tar.exe for the minimal Windows PE fixture");

    assert!(
        output.status.success(),
        "failed to create tar for minimal Windows PE fixture\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
