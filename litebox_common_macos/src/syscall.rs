// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS BSD syscall request decoding.

use crate::errno::Errno;
use litebox_common_linux::PtRegs;

// BSD syscall numbers (aarch64 macOS).
pub mod nr {
    pub const EXIT: usize = 1;
    pub const READ: usize = 3;
    pub const WRITE: usize = 4;
    pub const OPEN: usize = 5;
    pub const CLOSE: usize = 6;
    pub const GETPID: usize = 20;
    pub const GETUID: usize = 24;
    pub const GETEUID: usize = 25;
    pub const GETEGID: usize = 43;
    pub const SIGACTION: usize = 46;
    pub const GETGID: usize = 47;
    pub const SIGPROCMASK: usize = 48;
    pub const IOCTL: usize = 54;
    pub const MUNMAP: usize = 73;
    pub const MPROTECT: usize = 74;
    pub const MADVISE: usize = 75;
    pub const MMAP: usize = 197;
    pub const LSEEK: usize = 199;
    pub const SYSCTL: usize = 202;
    pub const ISSETUGID: usize = 327;
    pub const FSTAT64: usize = 339;
}

/// A decoded macOS BSD syscall request.
///
/// Address arguments are stored as raw `usize` values; the shim converts
/// them to typed pointers using the platform's pointer types.
pub enum MacosSyscallRequest {
    Exit {
        status: i32,
    },
    Read {
        fd: i32,
        buf: usize,
        count: usize,
    },
    Write {
        fd: i32,
        buf: usize,
        count: usize,
    },
    Close {
        fd: i32,
    },
    Getpid,
    Getuid,
    Geteuid,
    Getgid,
    Getegid,
    Issetugid,
    Mmap {
        addr: usize,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    },
    Munmap {
        addr: usize,
        length: usize,
    },
    Mprotect {
        addr: usize,
        length: usize,
        prot: i32,
    },
    Unknown {
        number: usize,
    },
}

impl MacosSyscallRequest {
    /// Decode a syscall request from the register state.
    ///
    /// macOS aarch64: syscall number in x16, args in x0-x5.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)] // Intentional: register values (usize/u64) → syscall arg types (i32, i64).
    pub fn try_from_raw(ctx: &PtRegs) -> Self {
        let nr = ctx.regs[16];
        let a0 = ctx.regs[0];
        let a1 = ctx.regs[1];
        let a2 = ctx.regs[2];
        let a3 = ctx.regs[3];
        let a4 = ctx.regs[4];
        let a5 = ctx.regs[5];

        match nr {
            nr::EXIT => MacosSyscallRequest::Exit { status: a0 as i32 },
            nr::READ => MacosSyscallRequest::Read {
                fd: a0 as i32,
                buf: a1,
                count: a2,
            },
            nr::WRITE => MacosSyscallRequest::Write {
                fd: a0 as i32,
                buf: a1,
                count: a2,
            },
            nr::CLOSE => MacosSyscallRequest::Close { fd: a0 as i32 },
            nr::GETPID => MacosSyscallRequest::Getpid,
            nr::GETUID => MacosSyscallRequest::Getuid,
            nr::GETEUID => MacosSyscallRequest::Geteuid,
            nr::GETGID => MacosSyscallRequest::Getgid,
            nr::GETEGID => MacosSyscallRequest::Getegid,
            nr::ISSETUGID => MacosSyscallRequest::Issetugid,
            nr::MMAP => MacosSyscallRequest::Mmap {
                addr: a0,
                length: a1,
                prot: a2 as i32,
                flags: a3 as i32,
                fd: a4 as i32,
                offset: a5 as i64,
            },
            nr::MUNMAP => MacosSyscallRequest::Munmap {
                addr: a0,
                length: a1,
            },
            nr::MPROTECT => MacosSyscallRequest::Mprotect {
                addr: a0,
                length: a1,
                prot: a2 as i32,
            },
            _ => MacosSyscallRequest::Unknown { number: nr },
        }
    }
}

/// The NZCV carry bit in CPSR/PSTATE (bit 29).
pub const CARRY_BIT: usize = 1 << 29;

/// Set the syscall return value per macOS ABI.
///
/// On success: x0 = result, carry clear.
/// On error: x0 = errno (positive), carry set.
pub fn set_syscall_return(ctx: &mut PtRegs, result: Result<usize, Errno>) {
    match result {
        Ok(val) => {
            ctx.regs[0] = val;
            ctx.pstate &= !CARRY_BIT;
        }
        Err(errno) => {
            ctx.regs[0] = errno.raw();
            ctx.pstate |= CARRY_BIT;
        }
    }
}
