// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! x86_64 assembly trampoline for micro-LiteBox syscall interception.

/// Syscall arguments as laid out on the stack by the assembly trampoline.
#[repr(C)]
pub struct SyscallArgs {
    /// Linux syscall number (from RAX).
    pub nr: u64,
    /// Syscall arguments (RDI, RSI, RDX, R10, R8, R9).
    pub args: [u64; 6],
}

const _: () = assert!(core::mem::size_of::<SyscallArgs>() == 56);

core::arch::global_asm!(
    ".text",
    ".globl micro_syscall_entry",
    ".type micro_syscall_entry, @function",
    ".balign 16",
    "micro_syscall_entry:",
    "mov gs:[0x20], rcx", // save return addr
    // Stack alignment: the binary rewriter's trampoline stub uses
    // `LEA RCX, [RIP+disp]` + `JMP [RIP+disp]`, so on entry here RSP ≡ 8
    // (mod 16) — same as after a CALL. Subtracting 56 (≡ 8 mod 16) gives
    // RSP ≡ 0 (mod 16) before the CALL below, satisfying the x86_64 ABI.
    "sub rsp, 56",         // allocate SyscallArgs
    "mov [rsp+0x00], rax", // nr
    "mov [rsp+0x08], rdi", // arg0
    "mov [rsp+0x10], rsi", // arg1
    "mov [rsp+0x18], rdx", // arg2
    "mov [rsp+0x20], r10", // arg3
    "mov [rsp+0x28], r8",  // arg4
    "mov [rsp+0x30], r9",  // arg5
    "mov rdi, rsp",        // C arg0 = &SyscallArgs
    "call micro_handle_syscall",
    "add rsp, 56",        // clean up
    "mov rcx, gs:[0x20]", // restore return addr
    "jmp rcx",
    ".size micro_syscall_entry, . - micro_syscall_entry",
);

unsafe extern "C" {
    fn micro_syscall_entry();
}

/// Returns the address of the assembly syscall entry point.
pub fn get_syscall_entry_point() -> usize {
    micro_syscall_entry as *const () as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_args_size() {
        assert_eq!(core::mem::size_of::<SyscallArgs>(), 56);
    }

    #[test]
    fn entry_point_is_nonzero() {
        assert_ne!(get_syscall_entry_point(), 0);
    }
}
