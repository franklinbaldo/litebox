// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest entry point — jumps to the loaded ELF's entry address.
//!
//! On x86\_64, the kernel-to-user transition initialises all general-purpose
//! registers to zero, clears the flags, sets RSP to the user stack (pointing
//! at `argc`), and transfers control to the entry point.  This module
//! replicates that contract so the guest's C runtime startup (`_start` →
//! `__libc_start_main`) sees exactly the environment it expects.

/// Jump to the guest ELF entry point.  Does not return.
///
/// # Safety
///
/// * `entry_point` must be a valid executable address.
/// * `stack_pointer` must be a valid, aligned stack pointer with
///   `argc`/`argv`/`envp`/`auxv` properly initialised on the stack.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)] // Called during guest launch in later phases
pub unsafe fn jump_to_guest(entry_point: usize, stack_pointer: usize) -> ! {
    // SAFETY: The caller guarantees `entry_point` is a valid executable
    // address and `stack_pointer` is a properly aligned and initialised
    // user stack.  The inline assembly zeros all GPRs, sets RSP, and
    // jumps to the entry — matching the kernel's ELF-exec ABI contract.
    unsafe {
        core::arch::asm!(
            // Zero every general-purpose register to match the kernel's
            // ELF-exec ABI (all GPRs = 0, flags cleared).
            "xor rax, rax",
            "xor rbx, rbx",
            "xor rcx, rcx",
            "xor rdx, rdx",
            "xor rsi, rsi",
            "xor rdi, rdi",
            "xor rbp, rbp",
            "xor r8, r8",
            "xor r9, r9",
            "xor r10, r10",
            "xor r11, r11",
            "xor r12, r12",
            "xor r13, r13",
            "xor r14, r14",
            "xor r15, r15",
            // Set the stack pointer and jump to the entry point.
            "mov rsp, {stack}",
            "jmp {entry}",
            stack = in(reg) stack_pointer,
            entry = in(reg) entry_point,
            options(noreturn),
        );
    }
}
