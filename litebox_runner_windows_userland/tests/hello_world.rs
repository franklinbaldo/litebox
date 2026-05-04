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

#[test]
fn run_minimal_hello_world_pe() {
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("hello_world");
    let pe_path = build_minimal_hello_world_pe(&test_dir);
    println!("Built hello-world PE fixture at `{}`", pe_path.display());
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

fn create_tar_with_hello_exe(test_dir: &std::path::Path, tar_path: &std::path::Path) {
    let output = std::process::Command::new("tar.exe")
        .args([
            "-cf",
            tar_path.to_str().unwrap(),
            "-C",
            test_dir.to_str().unwrap(),
            "hello.exe",
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
