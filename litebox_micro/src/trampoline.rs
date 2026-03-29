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
    // ── Fast path: rt_sigreturn (syscall 15) ──────────────────────────
    // rt_sigreturn is a no-return syscall that restores the entire CPU
    // context from the signal frame on the stack.  The kernel locates
    // that frame via the RSP captured at the `syscall` instruction:
    //
    //     frame = (struct rt_sigframe *)(regs->sp - 8)
    //
    // If we let rt_sigreturn fall through to the normal handler path,
    // RSP will be shifted down by the red-zone skip + SyscallArgs
    // allocation, causing the kernel to read garbage instead of the
    // real signal frame → instant SIGSEGV.
    //
    // Fix: detect RAX == 15 before touching RSP and issue the real
    // `syscall` instruction directly.  rt_sigreturn never returns, so
    // we never reach the epilogue.  No authorization is needed — the
    // kernel can only restore a frame it previously created.
    "cmp rax, 15",
    "je .Lrt_sigreturn",
    //
    "mov gs:[0x20], rcx", // save return addr
    // Skip the 128-byte red zone mandated by the x86_64 ABI. Leaf functions
    // (and inline-asm `syscall` sites) are allowed to use 128 bytes below RSP
    // without adjusting it. We must not clobber that region.
    //
    // ── Stack layout (addresses grow upward) ──────────────────────────
    //
    //   +--------+------- original guest RSP (X)
    //   |  128B  |  red zone (untouched)
    //   +--------+------- X − 128
    //   |  56B   |  SyscallArgs  [rsp+48 .. rsp+103]
    //   +--------+------- X − 184
    //   |  48B   |  saved guest regs: RDI, RSI, RDX, R10, R8, R9
    //   +--------+------- X − 232  ← RSP at `call`
    //
    // Alignment: total sub = 128 + 104 = 232 ≡ 8 mod 16.
    // This matches the old trampoline's 128+56 = 184 ≡ 8 mod 16,
    // preserving the same alignment class for the CALL instruction.
    //
    "sub rsp, 128", // skip red zone
    //
    // Save guest registers BEFORE clobbering RDI for the C call.
    // We save 6 registers × 8 bytes = 48 bytes, then SyscallArgs = 56
    // bytes.  Total = 104 bytes.
    "sub rsp, 104",
    // Save area at [rsp+0 .. rsp+47] (48 bytes)
    "mov [rsp+0x00], rdi", // guest RDI — saved BEFORE overwrite
    "mov [rsp+0x08], rsi", // guest RSI
    "mov [rsp+0x10], rdx", // guest RDX
    "mov [rsp+0x18], r10", // guest R10
    "mov [rsp+0x20], r8",  // guest R8
    "mov [rsp+0x28], r9",  // guest R9
    //
    // SyscallArgs at [rsp+48 .. rsp+103] (56 bytes)
    "mov [rsp+0x30], rax", // nr          (offset 48)
    "mov [rsp+0x38], rdi", // arg0 = RDI  (offset 56)
    "mov [rsp+0x40], rsi", // arg1 = RSI  (offset 64)
    "mov [rsp+0x48], rdx", // arg2 = RDX  (offset 72)
    "mov [rsp+0x50], r10", // arg3 = R10  (offset 80)
    "mov [rsp+0x58], r8",  // arg4 = R8   (offset 88)
    "mov [rsp+0x60], r9",  // arg5 = R9   (offset 96)
    //
    // RDI = &SyscallArgs for the C call.
    "lea rdi, [rsp+0x30]",
    "call micro_handle_syscall",
    // RAX = syscall return value.
    //
    // Restore saved guest registers.  The C call may have clobbered all
    // caller-saved registers, but the real `syscall` instruction would
    // preserve everything except RAX, RCX, R11.
    "mov rdi, [rsp+0x00]",
    "mov rsi, [rsp+0x08]",
    "mov rdx, [rsp+0x10]",
    "mov r10, [rsp+0x18]",
    "mov r8,  [rsp+0x20]",
    "mov r9,  [rsp+0x28]",
    "add rsp, 104",       // deallocate save area + SyscallArgs
    "add rsp, 128",       // restore red zone
    "mov rcx, gs:[0x20]", // restore return addr
    "jmp rcx",
    //
    // ── rt_sigreturn fast path ────────────────────────────────────────
    // RAX already holds 15 (SYS_rt_sigreturn).  RSP is untouched, so
    // the kernel will find the signal frame at exactly the right place.
    // This syscall never returns — the kernel restores the full context.
    ".Lrt_sigreturn:",
    "syscall",
    "ud2", // unreachable — guard against kernel bugs
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
