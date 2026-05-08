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
    for dll_name in ["kernel32.dll", "kernelbase.dll"] {
        let dll_path = build_rewritten_system_dll(&test_dir, dll_name);
        println!(
            "Built rewritten {dll_name} fixture at `{}`",
            dll_path.display()
        );
    }
    let tar_path = test_dir.join("hello_world.tar");
    create_tar_with_hello_exe(&test_dir, &tar_path);

    let mut command =
        std::process::Command::new(env!("CARGO_BIN_EXE_litebox_runner_windows_userland"));
    command.env("LITEBOX_LOG", "debug").args([
        "--initial-files",
        tar_path.to_str().unwrap(),
        "/hello.exe",
    ]);
    println!("Running `{command:?}`");
    let CommandOutput { output, timed_out } =
        run_with_timeout(command, std::time::Duration::from_secs(30));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{stdout}\n{stderr}");

    assert!(!timed_out, "ntdll loader path timed out");
    assert!(
        output.status.success(),
        "runner exited with status {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    assert!(
        combined_output.contains("Starting Windows guest through ntdll!LdrInitializeThunk"),
        "runner did not enter through LdrInitializeThunk\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        output
            .stdout
            .windows(HELLO_MESSAGE.len())
            .any(|window| window == HELLO_MESSAGE),
        "guest hello-world output was not observed; {REQUIRED_SUPPORT}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

fn run_with_timeout(
    mut command: std::process::Command,
    timeout: std::time::Duration,
) -> CommandOutput {
    use std::io::Read as _;

    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to run litebox_runner_windows_userland");
    let mut stdout = child.stdout.take().expect("child stdout was piped");
    let stdout_reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .read_to_end(&mut output)
            .expect("failed to read child stdout");
        output
    });
    let mut stderr = child.stderr.take().expect("child stderr was piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stderr
            .read_to_end(&mut output)
            .expect("failed to read child stderr");
        output
    });
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

    let status = child.wait().expect("failed to collect runner child status");
    let output = std::process::Output {
        status,
        stdout: stdout_reader.join().expect("stdout reader panicked"),
        stderr: stderr_reader.join().expect("stderr reader panicked"),
    };
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
    build_rewritten_system_dll(test_dir, "ntdll.dll")
}

fn build_rewritten_system_dll(test_dir: &std::path::Path, dll_name: &str) -> std::path::PathBuf {
    let system32_dir = test_dir.join("Windows").join("System32");
    std::fs::create_dir_all(&system32_dir).unwrap();
    let dll_path = system32_dir.join(dll_name);
    let host_dll = std::fs::read(host_system32_dll_path(dll_name))
        .unwrap_or_else(|error| panic!("failed to read host {dll_name}: {error}"));
    let rewritten = match litebox_syscall_rewriter::rewrite_binary(&host_dll, None) {
        Ok(rewritten) => rewritten,
        Err(litebox_syscall_rewriter::Error::UnpatchableSyscalls(_)) => panic!(
            "failed to rewrite host {dll_name}; required support: patch dense ntdll syscall stubs or provide a pre-rewritten guest DLL"
        ),
        Err(error) => panic!("failed to rewrite host {dll_name}: {error}"),
    };
    std::fs::write(&dll_path, rewritten).unwrap();
    dll_path
}

fn host_system32_dll_path(dll_name: &str) -> std::path::PathBuf {
    std::env::var_os("SystemRoot")
        .map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        )
        .join("System32")
        .join(dll_name)
}

fn create_tar_with_hello_exe(test_dir: &std::path::Path, tar_path: &std::path::Path) {
    let output = std::process::Command::new("tar.exe")
        .args([
            "-cf",
            tar_path.to_str().unwrap(),
            "-C",
            test_dir.to_str().unwrap(),
            "hello.exe",
            "Windows/System32/ntdll.dll",
            "Windows/System32/kernel32.dll",
            "Windows/System32/kernelbase.dll",
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
