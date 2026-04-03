// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

/// Minimal aarch64 Mach-O assembly: write(1, "hello\n", 6) + exit(0)
/// using BSD syscall ABI (syscall number in x16, svc #0x80).
const HELLO_NOLIBC_ASM: &str = r#"
.global _start
.align 4

_start:
    // write(1, msg, 6)
    mov x0, #1          // fd = stdout
    adrp x1, msg@PAGE
    add x1, x1, msg@PAGEOFF
    mov x2, #6          // count = 6
    mov x16, #4         // SYS_write = 4
    svc #0x80

    // exit(0)
    mov x0, #0          // status = 0
    mov x16, #1         // SYS_exit = 1
    svc #0x80

.data
msg:
    .asciz "hello\n"
"#;

#[test]
fn test_hello_nolibc_asm() {
    let bin_path = common::assemble_macho(HELLO_NOLIBC_ASM, "hello_nolibc_asm");
    let rewritten = common::rewrite_macho(&bin_path);
    let (exit_code, _stdout) = common::run_macho_binary(&rewritten, &["hello_nolibc_asm"]);
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}

/// Nolibc C program with raw BSD syscall wrappers.
const HELLO_NOLIBC_C: &str = r#"
// Compile: clang -arch arm64 -static -nostdlib -e __start -o hello hello.c

static int bsd_write(int fd, const void *buf, unsigned long count)
{
    register long x0 __asm__("x0") = fd;
    register const void *x1 __asm__("x1") = buf;
    register unsigned long x2 __asm__("x2") = count;
    register long x16 __asm__("x16") = 4; // SYS_write

    __asm__ volatile("svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x16)
        : "memory", "cc");

    return (int)x0;
}

_Noreturn static void bsd_exit(int status)
{
    register long x0 __asm__("x0") = status;
    register long x16 __asm__("x16") = 1; // SYS_exit

    for (;;) {
        __asm__ volatile("svc #0x80"
            :
            : "r"(x0), "r"(x16)
            : "memory", "cc");
    }
}

void _start(void)
{
    bsd_write(1, "Hello from C!\n", 14);
    bsd_exit(0);
}
"#;

#[test]
fn test_hello_nolibc_c() {
    let bin_path = common::compile_macho_nolibc(HELLO_NOLIBC_C, "hello_nolibc_c");
    let rewritten = common::rewrite_macho(&bin_path);
    let (exit_code, _stdout) = common::run_macho_binary(&rewritten, &["hello_nolibc_c"]);
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}

/// Assembly that exits with code 42.
const EXIT_42_ASM: &str = r"
.global _start
.align 4

_start:
    mov x0, #42         // status = 42
    mov x16, #1         // SYS_exit = 1
    svc #0x80
";

#[test]
fn test_exit_code_42() {
    let bin_path = common::assemble_macho(EXIT_42_ASM, "exit_42_asm");
    let rewritten = common::rewrite_macho(&bin_path);
    let (exit_code, _) = common::run_macho_binary(&rewritten, &["exit_42"]);
    assert_eq!(exit_code, 42, "expected exit code 42, got {exit_code}");
}

/// Dynamically linked hello world using libc's printf.
/// This is the target program for Phase 2 — it requires dyld, libSystem, and
/// the mmap-hook code patching pipeline.
const HELLO_DYNAMIC_C: &str = r#"
#include <stdio.h>

int main(int argc, char *argv[]) {
    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    return 0;
}
"#;

#[test]
#[ignore = "requires sysroot extraction: run extract_sysroot.sh first"]
fn test_hello_dynamic() {
    let sysroot = std::env::var("LITEBOX_MACOS_SYSROOT").unwrap_or_else(|_| {
        // Default sysroot location next to the test binary
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        format!("{manifest_dir}/test-sysroot")
    });

    // Check if sysroot exists
    if !std::path::Path::new(&sysroot)
        .join("usr/lib/libSystem.B.dylib")
        .exists()
    {
        panic!(
            "Sysroot not found at {sysroot}/usr/lib/libSystem.B.dylib. \
             Run extract_sysroot.sh first:\n  \
             ./litebox_runner_macos_on_macos_userland/extract_sysroot.sh {sysroot}"
        );
    }

    let bin_path = common::compile_macho_dynamic(HELLO_DYNAMIC_C, "hello_dynamic");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    // Rewrite the main binary's SVC sites
    let rewritten = litebox_syscall_rewriter_macho::hook_syscalls_in_macho(&binary_data)
        .expect("rewrite failed");

    let (exit_code, _stdout) =
        common::run_macho_dynamic(&rewritten, &["hello_dynamic", "arg1", "arg2"], &sysroot);
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}
