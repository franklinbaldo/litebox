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
