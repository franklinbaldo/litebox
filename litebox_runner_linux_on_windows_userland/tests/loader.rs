// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(
    target_os = "windows",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod common;

#[expect(
    unused,
    reason = "This code snippet is just used to illustrate the source code of the `hello_exec_nolibc` test."
)]
#[cfg(target_arch = "x86_64")]
const HELLO_WORLD_NOLIBC: &str = r#"
// gcc tests/test.c -o test -static -nostdlib (-m32)
#if defined(__x86_64__)
int write(int fd, const char *buf, int length)
{
    int ret;

    asm("mov %1, %%eax\n\t"
        "mov %2, %%edi\n\t"
        "mov %3, %%rsi\n\t"
        "mov %4, %%edx\n\t"
        "syscall\n\t"
        "mov %%eax, %0"
        : "=r" (ret)
        : "i" (1), // #define SYS_write 1
          "r" (fd),
          "r" (buf),
          "r" (length)
        : "%eax", "%edi", "%rsi", "%edx");

    return ret;
}

_Noreturn void exit_group(int code)
{
    /* Infinite for-loop since this function can't return */
    for (;;) {
        asm("mov %0, %%eax\n\t"
            "mov %1, %%edi\n\t"
            "syscall\n\t"
            :
            : "i" (231), // #define SYS_exit_group 231
              "r" (code)
            : "%eax", "%edi");
    }
}
#elif defined(__i386__)
int write(int fd, const char *buf, int length)
{
    int ret;

    asm("mov %1, %%eax\n\t"
        "mov %2, %%ebx\n\t"
        "mov %3, %%ecx\n\t"
        "mov %4, %%edx\n\t"
        "int $0x80\n\t"
        "mov %%eax, %0"
        : "=r" (ret)
        : "i" (4), // #define SYS_write 4
          "g" (fd),
          "g" (buf),
          "g" (length)
        : "%eax", "%ebx", "%ecx", "%edx");

    return ret;
}
_Noreturn void exit_group(int code)
{
    /* Infinite for-loop since this function can't return */
    for (;;) {
        asm("mov %0, %%eax\n\t"
            "mov %1, %%ebx\n\t"
            "int $0x80\n\t"
            :
            : "i" (252), // #define SYS_exit_group 252
              "r" (code)
            : "%eax", "%ebx");
    }
}
#else
#error "Unsupported architecture"
#endif

int main() {
    // use write to print a string
    write(1, "Hello, World!\n", 14);
    return 0;
}

void _start() {
    exit_group(main());
}
"#;

#[expect(
    unused,
    reason = "This code snippet is just used to illustrate the source code of the `hello_exec_nolibc` test."
)]
#[cfg(target_arch = "aarch64")]
const HELLO_WORLD_NOLIBC: &str = r#"
// gcc tests/test.c -o test -static -nostdlib
#if defined(__aarch64__)
int write(int fd, const char *buf, int length)
{
    register long x0 asm("x0") = fd;
    register const char *x1 asm("x1") = buf;
    register long x2 asm("x2") = length;
    register long x8 asm("x8") = 64; // SYS_write

    asm volatile("svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory");

    return x0;
}

_Noreturn void exit_group(int code)
{
    register long x0 asm("x0") = code;
    register long x8 asm("x8") = 94; // SYS_exit_group

    for (;;) {
        asm volatile("svc #0"
            :
            : "r"(x0), "r"(x8)
            : "memory");
    }
}
#else
#error "Unsupported architecture"
#endif

int main() {
    // use write to print a string
    write(1, "Hello, World!\n", 14);
    return 0;
}

void _start() {
    exit_group(main());
}
"#;

#[expect(
    unused,
    reason = "This code snippet is just used to illustrate the source code of the `hello_thread_static/dynamic` test."
)]
const HELLO_WORLD: &str = r#"
// gcc -o hello_world_static hello_world_static.c -static
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
"#;

#[expect(
    unused,
    reason = "This code snippet is just used to illustrate the source code of the `hello_thread_static/dynamic` test."
)]
const HELLO_THREAD: &str = r#"
// gcc hello_thread.c -o hello_thread_static -static
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void* child_thread_func(void* arg) {
    (void)arg;
    printf("Hello from child thread.\n");
    return NULL;
}

int main(void) {
    pthread_t tid;

    if (pthread_create(&tid, NULL, child_thread_func, NULL) != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }

    printf("Hello from main thread.\n");

    if (pthread_join(tid, NULL) != 0) {
        perror("pthread_join");
        exit(EXIT_FAILURE);
    }

    return 0;
}
"#;

/// Directory name for architecture-specific test binaries.
#[cfg(target_arch = "x86_64")]
const TEST_BINS_DIR: &str = "tests/test-bins";
#[cfg(target_arch = "aarch64")]
const TEST_BINS_DIR: &str = "tests/test-bins-aarch64";

#[cfg(target_arch = "x86_64")]
#[test]
fn test_static_linked_prog_with_rewriter() {
    println!("Running statically linked binary + rewriter test...");
    // Use the already compiled executable from the tests folder (same dir as this file)
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push(TEST_BINS_DIR);

    let prog_name = "hello_world_static";
    let prog_name_hooked = format!("{prog_name}.hooked");

    let path = test_dir.join(prog_name);
    let hooked_path = test_dir.join(&prog_name_hooked);

    // rewrite the target ELF executable file
    let _ = std::fs::remove_file(hooked_path.clone());
    println!(
        "Running `cargo run -p litebox_syscall_rewriter -- -o {} {}`",
        hooked_path.to_str().unwrap(),
        path.to_str().unwrap()
    );
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(cargo)
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

    let executable_path = format!("/{prog_name_hooked}");
    let executable_data = std::fs::read(hooked_path).unwrap();

    let mut launcher = common::TestLauncher::init_platform(&[], &[], &[]);
    launcher.install_file(executable_data, &executable_path);
    launcher.test_load_exec_common(&executable_path);
}

fn run_dynamic_linked_prog_with_rewriter(
    libs_to_rewrite: &[(&str, &str)],
    libs_without_rewrite: &[(&str, &str)],
    exec_name: &str,
    cmd_args: &[&str],
    install_files: fn(std::path::PathBuf),
) {
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push(TEST_BINS_DIR);

    let prog_name = exec_name;
    let prog_name_hooked = format!("{prog_name}.hooked");

    let path = test_dir.join(prog_name);
    let hooked_path = test_dir.join(&prog_name_hooked);

    let out_path = std::env::var("OUT_DIR").unwrap();

    // Rewrite the target ELF executable file
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

    // Create tar file containing all dependencies
    let tar_src_path = std::path::Path::new(&out_path).join("test_program_tar");
    println!(
        "Creating tar source directory path: {}",
        tar_src_path.to_str().unwrap()
    );

    std::fs::create_dir_all(tar_src_path.join("out")).unwrap();

    // Rewrite all libraries that are required for initialization
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

    // Copy libraries that are not needed to be rewritten (`litebox_rtld_audit.so`)
    // to the tar directory. The rtld_audit prebuilt lives in the centralized
    // prebuilt directory; other files come from test-bins.
    let prebuilt_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../litebox_rtld_audit/prebuilt");
    for (file, prefix) in libs_without_rewrite {
        let src = if *file == "litebox_rtld_audit.so" {
            #[cfg(target_arch = "aarch64")]
            let p = prebuilt_dir.join("litebox_rtld_audit_aarch64_windows.so");
            #[cfg(target_arch = "x86_64")]
            let p = prebuilt_dir.join("litebox_rtld_audit_x86_64_linux.so");
            p
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

    // Install the required files (e.g., scripts) to tar directory's /out
    install_files(tar_src_path.join("out"));

    // tar — collect all subdirectories that exist under the tar source path
    let tar_target_file = std::path::Path::new(&out_path).join("rootfs_rewriter.tar");
    let mut tar_args: Vec<&str> = vec!["-cvf", tar_target_file.to_str().unwrap()];
    for dir in ["lib", "lib64", "lib32", "out"] {
        if tar_src_path.join(dir).exists() {
            tar_args.push(dir);
        }
    }
    let tar_data = std::process::Command::new("tar")
        .args(&tar_args)
        .current_dir(&tar_src_path)
        .output()
        .expect("Failed to create tar file");
    assert!(
        tar_data.status.success(),
        "failed to create tar file {:?}",
        std::str::from_utf8(tar_data.stderr.as_slice()).unwrap()
    );
    println!("Tar file created at: {}", tar_target_file.to_str().unwrap());

    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_on_windows_userland")
        .unwrap_or_else(|_| {
            env!("CARGO_BIN_EXE_litebox_runner_linux_on_windows_userland").to_string()
        });

    // Run litebox_runner_linux_on_windows_userland with the tar file and the compiled executable
    // Determine where the rtld_audit library was placed
    let audit_path = libs_to_rewrite
        .iter()
        .chain(libs_without_rewrite.iter())
        .find(|(name, _)| *name == "litebox_rtld_audit.so")
        .map(|(_, prefix)| format!("{prefix}/litebox_rtld_audit.so"))
        .unwrap_or_else(|| "/lib64/litebox_rtld_audit.so".to_string());
    let audit_env = format!("LD_AUDIT={audit_path}");

    // Build LD_LIBRARY_PATH from all library prefixes used (test paths first).
    let mut ld_paths: Vec<&str> = Vec::new();
    for (_, prefix) in libs_to_rewrite.iter().chain(libs_without_rewrite.iter()) {
        if !ld_paths.contains(prefix) {
            ld_paths.push(prefix);
        }
    }
    for default in ["/lib64", "/lib32", "/lib"] {
        if !ld_paths.contains(&default) {
            ld_paths.push(default);
        }
    }
    let ld_library_path = format!("LD_LIBRARY_PATH={}", ld_paths.join(":"));

    let mut args = vec![
        "--unstable",
        "--env",
        &ld_library_path,
        "--initial-files",
        tar_target_file.to_str().unwrap(),
        "--env",
        &audit_env,
    ];
    args.push(hooked_path.to_str().unwrap());
    args.extend_from_slice(cmd_args);

    let mut command = std::process::Command::new(&binary_path);
    command.args(&args);
    println!("Running `{command:?}`");
    let status = command
        .status()
        .expect("Failed to run litebox_runner_linux_on_windows_userland");
    assert!(
        status.success(),
        "failed to run litebox_runner_linux_on_windows_userland: {status}",
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_testcase_dynamic_with_rewriter() {
    let exec_name = "hello_world_dyn";
    let libs_to_rewrite = [
        ("libc.so.6", "/lib/x86_64-linux-gnu"),
        ("ld-linux-x86-64.so.2", "/lib64"),
    ];
    let libs_without_rewrite = [("litebox_rtld_audit.so", "/lib64")];

    // Run
    run_dynamic_linked_prog_with_rewriter(
        &libs_to_rewrite,
        &libs_without_rewrite,
        exec_name,
        &[],
        |_| {},
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn test_testcase_dynamic_with_rewriter() {
    let exec_name = "hello_world_dyn";
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

#[cfg(target_arch = "aarch64")]
#[test]
fn test_testcase_thread_dynamic_with_rewriter() {
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

/// Run a statically linked binary through the syscall rewriter and execute it
/// with the runner binary. Static binaries do not require shared libraries,
/// so no tar of initial files or LD_AUDIT/LD_LIBRARY_PATH environment is needed.
#[cfg(target_arch = "aarch64")]
fn run_static_linked_prog_with_rewriter(exec_name: &str) {
    println!("Running statically linked binary + rewriter test for {exec_name}...");

    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push(TEST_BINS_DIR);

    let prog_name_hooked = format!("{exec_name}.hooked");

    let path = test_dir.join(exec_name);
    let hooked_path = test_dir.join(&prog_name_hooked);

    // Rewrite the target ELF executable file
    let _ = std::fs::remove_file(hooked_path.clone());
    println!(
        "Running `cargo run -p litebox_syscall_rewriter -- {} -o {}`",
        path.to_str().unwrap(),
        hooked_path.to_str().unwrap()
    );
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(cargo)
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

    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_on_windows_userland")
        .unwrap_or_else(|_| {
            env!("CARGO_BIN_EXE_litebox_runner_linux_on_windows_userland").to_string()
        });

    // Run litebox_runner_linux_on_windows_userland with the rewritten static binary.
    // No --initial-files, --env LD_AUDIT, or --env LD_LIBRARY_PATH needed for static binaries.
    let args = vec!["--unstable", hooked_path.to_str().unwrap()];

    let mut command = std::process::Command::new(&binary_path);
    command.args(&args);
    println!("Running `{command:?}`");
    let status = command
        .status()
        .expect("Failed to run litebox_runner_linux_on_windows_userland");
    assert!(
        status.success(),
        "failed to run litebox_runner_linux_on_windows_userland: {status}",
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn test_static_linked_prog_with_rewriter() {
    run_static_linked_prog_with_rewriter("hello_world_static");
}

#[cfg(target_arch = "aarch64")]
#[test]
fn test_static_linked_nolibc_with_rewriter() {
    run_static_linked_prog_with_rewriter("hello_exec_nolibc");
}

#[cfg(target_arch = "aarch64")]
#[test]
fn test_static_linked_thread_with_rewriter() {
    run_static_linked_prog_with_rewriter("hello_thread_static");
}

#[cfg(target_arch = "aarch64")]
#[test]
fn test_static_linked_multithread_with_rewriter() {
    run_static_linked_prog_with_rewriter("thread_static");
}
