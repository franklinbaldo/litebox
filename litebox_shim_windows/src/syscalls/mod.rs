// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT syscall handler implementations.
//!
//! Each handler receives the execution context and returns an `NtStatus`.
//! Arguments are read from the Windows x64 syscall convention registers:
//! - r10: arg0, rdx: arg1, r8: arg2, r9: arg3

use crate::handle_table::HandleTable;
use litebox_common_windows::ntstatus::NtStatus;

pub(crate) mod file;
pub(crate) mod k32_handlers;
pub(crate) mod memory;
pub(crate) mod port;
pub(crate) mod process;
pub(crate) mod section;
pub(crate) mod sync;
pub(crate) mod sysinfo;
pub(crate) mod thread;
pub(crate) mod win32k;

/// Helper to read NT syscall arguments from the execution context.
pub(crate) struct NtSyscallArgs {
    pub arg0: usize, // r10
    pub arg1: usize, // rdx
    pub arg2: usize, // r8
    pub arg3: usize, // r9
}

impl NtSyscallArgs {
    pub fn from_ctx(ctx: &super::ExecutionContext) -> Self {
        Self {
            arg0: ctx.regs.r10,
            arg1: ctx.regs.rdx,
            arg2: ctx.regs.r8,
            arg3: ctx.regs.r9,
        }
    }

    /// Read the 5th argument from the caller's stack frame.
    ///
    /// Both the ntdll trampoline and the PE-builder stubs preserve the
    /// return address on the stack, so ctx.regs.rsp points at it and the
    /// standard Windows x64 callee view applies:
    ///   [rsp + 0x00] = return address
    ///   [rsp + 0x08..0x20] = shadow space (4 × 8)
    ///   [rsp + 0x28] = 5th arg
    ///   [rsp + 0x30] = 6th arg
    pub fn arg4(ctx: &super::ExecutionContext) -> usize {
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0)
    }

    /// Read the 6th argument from the caller's stack frame.
    pub fn arg5(ctx: &super::ExecutionContext) -> usize {
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0)
    }

    /// Read the 7th argument from the caller's stack frame.
    pub fn arg6(ctx: &super::ExecutionContext) -> usize {
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x38).unwrap_or(0)
    }

    /// Read the 8th argument from the caller's stack frame.
    pub fn arg7(ctx: &super::ExecutionContext) -> usize {
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x40).unwrap_or(0)
    }
}

/// NtClose — close a handle.
pub(crate) fn nt_close<FS: crate::NtShimFS>(
    handles: &mut HandleTable<FS>,
    handle: u32,
) -> NtStatus {
    if handles.close(handle) {
        NtStatus::STATUS_SUCCESS
    } else {
        NtStatus::STATUS_INVALID_HANDLE
    }
}
