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
    //
    // We bind `entry_point` to RDX and `stack_pointer` to RCX via
    // explicit register constraints, and zero those two registers last
    // (after the `mov rsp` / `jmp` that consume them).
    unsafe {
        core::arch::asm!(
            // Zero all GPRs except RCX (stack) and RDX (entry) which we
            // need for the final mov+jmp.
            "xor rax, rax",
            "xor rbx, rbx",
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
            // Switch stack and jump.  RCX and RDX are consumed here.
            "mov rsp, rcx",
            "xor rcx, rcx",  // zero rcx now that it's consumed
            // RDX still holds entry_point; jump consumes it.
            "push rdx",
            "xor rdx, rdx",  // zero rdx
            "ret",            // pop entry_point into RIP
            in("rcx") stack_pointer,
            in("rdx") entry_point,
            options(noreturn),
        );
    }
}
