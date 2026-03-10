// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

#[expect(
    unused,
    reason = "This code snippet is just used to illustrate the source code of the `hello_exec_nolibc` test."
)]
const HELLO_WORLD_NOLIBC: &str = r#"
// gcc hello_nolibc.c -o hello_exec_nolibc -static -nostdlib
#if defined(__aarch64__)
int write(int fd, const char *buf, int length)
{
    register int x0 __asm__("x0") = fd;
    register const char *x1 __asm__("x1") = buf;
    register int x2 __asm__("x2") = length;
    register int w8 __asm__("w8") = 64; // __NR_write
    register int ret __asm__("x0");
    __asm__ volatile(
        "svc #0"
        : "=r"(ret)
        : "r"(x0), "r"(x1), "r"(x2), "r"(w8)
        : "memory"
    );
    return ret;
}

_Noreturn void exit_group(int code)
{
    register int x0 __asm__("x0") = code;
    register int w8 __asm__("w8") = 94; // __NR_exit_group
    for (;;) {
        __asm__ volatile(
            "svc #0"
            :
            : "r"(x0), "r"(w8)
            : "memory"
        );
    }
}
#else
#error "Only aarch64 supported"
#endif

int main() {
    write(1, "Hello, World!\n", 14);
    return 0;
}

void _start() {
    exit_group(main());
}
"#;

#[expect(
    unused,
    reason = "This code snippet is just used to illustrate the source code of the `hello_world_static` test."
)]
const HELLO_WORLD: &str = r#"
// gcc -o hello_world_static hello.c -static -lpthread
#include <stdio.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char *argv[], char *envp[]) {
    int i;
    for (i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    for (i = 0; envp[i] != NULL; i++) {
        printf("envp[%d] = %s\n", i, envp[i]);
    }
    return 0;
}
"#;

#[expect(
    unused,
    reason = "This code snippet is just used to illustrate the source code of the `hello_thread_static` test."
)]
const HELLO_THREAD: &str = r#"
// gcc hello_thread.c -o hello_thread_static -static -lpthread
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

/// ET_EXEC (non-PIE, statically linked) binaries with load addresses below 4GB
/// are unsupported on macOS arm64 due to the mandatory 4GB `__PAGEZERO` segment.
///
/// This test verifies that loading such a binary fails with a clear error rather
/// than a confusing ENOMEM from mmap.
#[test]
fn test_static_linked_prog_with_rewriter() {
    println!("Running statically linked binary + rewriter test (expect load failure)...");
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests/test-bins");

    let prog_name = "hello_world_static";
    let prog_name_hooked = format!("{prog_name}.hooked");

    let path = test_dir.join(prog_name);
    let hooked_path = test_dir.join(&prog_name_hooked);

    // Rewrite the target ELF executable file.
    let _ = std::fs::remove_file(hooked_path.clone());
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

    // ET_EXEC with segments at 0x400000 (below 4GB __PAGEZERO) must fail to load.
    launcher.test_load_exec_expect_failure(&executable_path);
}

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

    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_macos_userland")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_macos_userland").to_string());

    // Run litebox_runner_macos_userland with the tar file and the compiled executable.
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
        .expect("Failed to run litebox_runner_macos_userland");
    if !output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout).unwrap_or("<non-utf8>");
        let stderr = std::str::from_utf8(&output.stderr).unwrap_or("<non-utf8>");
        panic!(
            "failed to run litebox_runner_macos_userland: {}\nstdout:\n{}\nstderr:\n{}",
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
