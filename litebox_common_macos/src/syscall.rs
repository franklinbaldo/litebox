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
    pub const FCNTL: usize = 92;
    pub const PREAD: usize = 153;
    pub const CSOPS: usize = 169;
    pub const MMAP: usize = 197;
    pub const LSEEK: usize = 199;
    pub const SYSCTL: usize = 202;
    pub const SHARED_REGION_CHECK_NP: usize = 294;
    pub const ISSETUGID: usize = 327;
    pub const FSTAT64: usize = 339;
    pub const GETENTROPY: usize = 500;
}

/// Mach trap numbers (negative x16 values, stored as positive constants).
/// The actual x16 value is the negation of these.
pub mod mach_trap {
    pub const MACH_REPLY_PORT: usize = 26;
    pub const THREAD_SELF_TRAP: usize = 27;
    pub const TASK_SELF_TRAP: usize = 28;
    pub const HOST_SELF_TRAP: usize = 29;
    pub const MACH_MSG_TRAP: usize = 31;
    pub const THREAD_GET_SPECIAL_REPLY_PORT: usize = 50;
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
    Open {
        path: usize,
        flags: i32,
        mode: u32,
    },
    Sigaction {
        signum: i32,
        new_act: usize,
        old_act: usize,
    },
    Sigprocmask {
        how: i32,
        set: usize,
        oldset: usize,
    },
    Ioctl {
        fd: i32,
        request: usize,
        arg: usize,
    },
    Madvise {
        addr: usize,
        length: usize,
        advice: i32,
    },
    Fcntl {
        fd: i32,
        cmd: i32,
        arg: usize,
    },
    Pread {
        fd: i32,
        buf: usize,
        count: usize,
        offset: i64,
    },
    Csops {
        pid: i32,
        ops: u32,
        useraddr: usize,
        usersize: usize,
    },
    Lseek {
        fd: i32,
        offset: i64,
        whence: i32,
    },
    Sysctl {
        name: usize,
        namelen: u32,
        old: usize,
        oldlenp: usize,
        new_val: usize,
        newlen: usize,
    },
    SharedRegionCheckNp {
        start_address: usize,
    },
    Fstat64 {
        fd: i32,
        buf: usize,
    },
    Getentropy {
        buf: usize,
        count: usize,
    },
    /// A Mach trap (negative x16 value).
    MachTrap {
        number: usize,
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
        let nr_raw = ctx.regs[16];
        let a0 = ctx.regs[0];
        let a1 = ctx.regs[1];
        let a2 = ctx.regs[2];
        let a3 = ctx.regs[3];
        let a4 = ctx.regs[4];
        let a5 = ctx.regs[5];

        // Mach traps use negative x16 values.
        if (nr_raw as i64) < 0 {
            let number = (-(nr_raw as i64)) as usize;
            return MacosSyscallRequest::MachTrap { number };
        }

        match nr_raw {
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
            nr::OPEN => MacosSyscallRequest::Open {
                path: a0,
                flags: a1 as i32,
                mode: a2 as u32,
            },
            nr::CLOSE => MacosSyscallRequest::Close { fd: a0 as i32 },
            nr::GETPID => MacosSyscallRequest::Getpid,
            nr::GETUID => MacosSyscallRequest::Getuid,
            nr::GETEUID => MacosSyscallRequest::Geteuid,
            nr::GETGID => MacosSyscallRequest::Getgid,
            nr::GETEGID => MacosSyscallRequest::Getegid,
            nr::SIGACTION => MacosSyscallRequest::Sigaction {
                signum: a0 as i32,
                new_act: a1,
                old_act: a2,
            },
            nr::SIGPROCMASK => MacosSyscallRequest::Sigprocmask {
                how: a0 as i32,
                set: a1,
                oldset: a2,
            },
            nr::IOCTL => MacosSyscallRequest::Ioctl {
                fd: a0 as i32,
                request: a1,
                arg: a2,
            },
            nr::MADVISE => MacosSyscallRequest::Madvise {
                addr: a0,
                length: a1,
                advice: a2 as i32,
            },
            nr::FCNTL => MacosSyscallRequest::Fcntl {
                fd: a0 as i32,
                cmd: a1 as i32,
                arg: a2,
            },
            nr::PREAD => MacosSyscallRequest::Pread {
                fd: a0 as i32,
                buf: a1,
                count: a2,
                offset: a3 as i64,
            },
            nr::CSOPS => MacosSyscallRequest::Csops {
                pid: a0 as i32,
                ops: a1 as u32,
                useraddr: a2,
                usersize: a3,
            },
            nr::ISSETUGID => MacosSyscallRequest::Issetugid,
            nr::MMAP => MacosSyscallRequest::Mmap {
                addr: a0,
                length: a1,
                prot: a2 as i32,
                flags: a3 as i32,
                fd: a4 as i32,
                offset: a5 as i64,
            },
            nr::LSEEK => MacosSyscallRequest::Lseek {
                fd: a0 as i32,
                offset: a1 as i64,
                whence: a2 as i32,
            },
            nr::SYSCTL => MacosSyscallRequest::Sysctl {
                name: a0,
                namelen: a1 as u32,
                old: a2,
                oldlenp: a3,
                new_val: a4,
                newlen: a5,
            },
            nr::SHARED_REGION_CHECK_NP => {
                MacosSyscallRequest::SharedRegionCheckNp { start_address: a0 }
            }
            nr::MUNMAP => MacosSyscallRequest::Munmap {
                addr: a0,
                length: a1,
            },
            nr::MPROTECT => MacosSyscallRequest::Mprotect {
                addr: a0,
                length: a1,
                prot: a2 as i32,
            },
            nr::FSTAT64 => MacosSyscallRequest::Fstat64 {
                fd: a0 as i32,
                buf: a1,
            },
            nr::GETENTROPY => MacosSyscallRequest::Getentropy { buf: a0, count: a1 },
            _ => MacosSyscallRequest::Unknown { number: nr_raw },
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
