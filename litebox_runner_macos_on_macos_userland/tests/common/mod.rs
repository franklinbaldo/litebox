// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};

/// Serialize test execution. Each test creates its own `MacosShimBuilder`
/// and `PageManager`, but the platform and global `HOST_TLS_TABLE_ADDR`
/// are process-wide singletons. Running tests concurrently causes the
/// second test's `update_host_tls_entry()` to access stale TLS table
/// memory from the first test's (now-dropped) `PageManager`.
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Ensure the litebox platform is initialized exactly once per test binary.
fn ensure_platform() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let platform = litebox_platform_macos_userland::MacosUserland::new(None);
        litebox_platform_multiplex::set_platform(platform);
    });
}

/// Assemble and link an aarch64 Mach-O binary from assembly source.
///
/// Uses Xcode `as` and `ld` to produce a static MH_EXECUTE with LC_UNIXTHREAD
/// (no dyld, no libc).
pub fn assemble_macho(asm_source: &str, name: &str) -> PathBuf {
    let dir = std::env::var("OUT_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().to_str().unwrap().to_string());
    let dir = Path::new(&dir);

    let asm_path = dir.join(format!("{name}.s"));
    let obj_path = dir.join(format!("{name}.o"));
    let bin_path = dir.join(name);

    std::fs::write(&asm_path, asm_source).expect("write asm source");

    // Assemble
    let output = std::process::Command::new("as")
        .args([
            "-arch",
            "arm64",
            asm_path.to_str().unwrap(),
            "-o",
            obj_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run assembler");
    assert!(
        output.status.success(),
        "assembler failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Link with -static -e _start (LC_UNIXTHREAD entry)
    // -headerpad 0x1000 ensures there is enough header space for the
    // syscall rewriter to inject the __LITEBOX trampoline segment.
    let output = std::process::Command::new("ld")
        .args([
            "-arch",
            "arm64",
            "-static",
            "-headerpad",
            "0x1000",
            "-e",
            "_start",
            obj_path.to_str().unwrap(),
            "-o",
            bin_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run linker");
    assert!(
        output.status.success(),
        "linker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    bin_path
}

/// Compile a C file to a static Mach-O binary using clang (no libc).
pub fn compile_macho_nolibc(c_source: &str, name: &str) -> PathBuf {
    let dir = std::env::var("OUT_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().to_str().unwrap().to_string());
    let dir = Path::new(&dir);

    let src_path = dir.join(format!("{name}.c"));
    let bin_path = dir.join(name);

    std::fs::write(&src_path, c_source).expect("write C source");

    let output = std::process::Command::new("clang")
        .args([
            "-arch",
            "arm64",
            "-static",
            "-nostdlib",
            "-Wl,-headerpad,0x1000",
            "-e",
            "__start",
            "-o",
            bin_path.to_str().unwrap(),
            src_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run clang");
    assert!(
        output.status.success(),
        "clang failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    bin_path
}

/// Rewrite a Mach-O binary using the Mach-O syscall rewriter.
pub fn rewrite_macho(input: &Path) -> Vec<u8> {
    let data = std::fs::read(input).expect("read binary");
    litebox_syscall_rewriter_macho::hook_syscalls_in_macho(&data).expect("Mach-O rewriter failed")
}

/// Run a rewritten Mach-O binary through litebox, capturing stdout and exit code.
pub fn run_macho_binary(binary_data: &[u8], argv: &[&str]) -> (i32, Vec<u8>) {
    use litebox::fs::{FileSystem as _, Mode};

    // Serialize: only one test can use the platform + TLS table at a time.
    let _guard = TEST_LOCK.lock().unwrap();

    ensure_platform();

    // Reset the global TLS table address so the new shim's loader can
    // allocate a fresh one. The old table (if any) belonged to a previous
    // test's PageManager which has since been dropped.
    litebox_common_linux::HOST_TLS_TABLE_ADDR.store(0, std::sync::atomic::Ordering::Release);

    let mut shim_builder =
        litebox_shim_macos::MacosShimBuilder::<litebox_shim_macos::DefaultFS>::new();
    let litebox = shim_builder.litebox();

    // Create a default layered file system
    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem_fs.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        let _ = fs.mkdir("/tmp", mode);
    });
    let tar_ro_fs =
        litebox::fs::tar_ro::FileSystem::new(litebox, litebox::fs::tar_ro::EMPTY_TAR_FILE.into());
    let fs = shim_builder.default_fs(in_mem_fs, tar_ro_fs);
    shim_builder.set_fs(fs);
    let shim = shim_builder.build();

    let argv_cstrings: Vec<std::ffi::CString> = argv
        .iter()
        .map(|s| std::ffi::CString::new(*s).unwrap())
        .collect();
    let envp = vec![std::ffi::CString::new("PATH=/bin").unwrap()];

    let program = shim
        .load_program(binary_data, argv_cstrings, envp)
        .expect("load_program failed");

    let litebox_shim_macos::LoadedProgram {
        entrypoints,
        process,
        mut initial_ctx,
    } = program;

    unsafe {
        litebox_platform_macos_userland::run_thread(entrypoints, &mut initial_ctx);
    }

    let exit_code = process.wait();
    // Phase 1: stdout is written to the host's fd 1 via the /dev/stdout
    // device. We can't easily capture it. Return empty for now.
    // The test verifies exit code; stdout capture is a future enhancement.
    (exit_code, Vec::new())
}
