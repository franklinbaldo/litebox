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
    pub const THREAD_SELFID: usize = 372;
    pub const CSRCTL: usize = 483;
    /// `mach_msg2_trap` — modern Mach message passing (macOS 12+).
    /// This uses x16 = 0x80000000 (NOT sign-extended, so it's a positive BSD-style number).
    pub const MACH_MSG2_TRAP: usize = 0x8000_0000;
    pub const GETENTROPY: usize = 500;
    pub const CROSSARCH_TRAP: usize = 38;
    pub const DUP2: usize = 90;
    pub const FSCTL: usize = 242;
    pub const MAC_SYSCALL: usize = 381;
    pub const SHARED_REGION_MAP_AND_SLIDE_2_NP: usize = 536;
    pub const KDEBUG_TRACE_STRING: usize = 178;
    pub const REBOOT: usize = 55;
    pub const STATFS64: usize = 345;
    pub const TERMINATE_WITH_PAYLOAD: usize = 520;
    pub const ABORT_WITH_PAYLOAD: usize = 521;
    pub const STAT64: usize = 338;
    pub const OPENAT: usize = 463;
    pub const FSTATAT64: usize = 470;
    pub const BSDTHREAD_CREATE: usize = 360;
    pub const BSDTHREAD_TERMINATE: usize = 361;
    pub const BSDTHREAD_REGISTER: usize = 366;
    pub const BSDTHREAD_CTL: usize = 478;
    pub const SIGRETURN: usize = 184;
    pub const UNLINK: usize = 10;
    pub const ACCESS: usize = 33;
    pub const PIPE: usize = 42;
    pub const FCHMOD: usize = 124;
    pub const MKDIR: usize = 136;
    pub const RMDIR: usize = 137;
    pub const FTRUNCATE: usize = 201;
    pub const SEMWAIT_SIGNAL: usize = 334;
    pub const GETDIRENTRIES64: usize = 344;
    pub const RECVMSG: usize = 27;
    pub const SENDMSG: usize = 28;
    pub const RECVFROM: usize = 29;
    pub const ACCEPT: usize = 30;
    pub const GETPEERNAME: usize = 31;
    pub const GETSOCKNAME: usize = 32;
    pub const SOCKET: usize = 97;
    pub const CONNECT: usize = 98;
    pub const BIND: usize = 104;
    pub const SETSOCKOPT: usize = 105;
    pub const LISTEN: usize = 106;
    pub const GETSOCKOPT: usize = 118;
    pub const SENDTO: usize = 133;
    pub const SHUTDOWN: usize = 134;
    pub const SOCKETPAIR: usize = 135;
}

/// Mach trap numbers (negative x16 values, stored as positive constants).
/// The actual x16 value is the negation of these.
pub mod mach_trap {
    pub const KERNELRPC_MACH_VM_ALLOCATE_TRAP: usize = 10;
    pub const KERNELRPC_MACH_VM_DEALLOCATE_TRAP: usize = 12;
    pub const KERNELRPC_MACH_VM_PROTECT_TRAP: usize = 14;
    pub const KERNELRPC_MACH_VM_MAP_TRAP: usize = 15;
    pub const MACH_PORT_CONSTRUCT_TRAP: usize = 24;
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
    ThreadSelfid,
    /// `mach_msg2_trap` — modern Mach message passing.
    MachMsg2Trap {
        data: usize,
        options: usize,
        msgh_bits: u32,
    },
    /// A Mach trap (negative x16 value).
    MachTrap {
        number: usize,
    },
    CrossarchTrap,
    Csrctl,
    Dup2 {
        oldfd: i32,
        newfd: i32,
    },
    MacSyscall,
    Fsctl,
    SharedRegionMapAndSlide2Np,
    KdebugTraceString,
    Statfs64 {
        path: usize,
        buf: usize,
    },
    /// `terminate_with_payload(pid, namespace, code, payload, payload_size)`
    TerminateWithPayload {
        namespace: usize,
        code: usize,
    },
    /// `abort_with_payload(namespace, code, payload, payload_size, reason, flags)`
    AbortWithPayload {
        namespace: usize,
        code: usize,
    },
    Stat64 {
        path: usize,
        buf: usize,
    },
    Openat {
        dirfd: i32,
        path: usize,
        flags: i32,
        mode: u32,
    },
    Fstatat64 {
        dirfd: i32,
        path: usize,
        buf: usize,
        flag: i32,
    },
    /// `bsdthread_register(threadstart, wqthread, pthsize, pthread_init_data, pthread_init_data_size, dispatchqueue_offset, tsd_offset)`
    BsdthreadRegister {
        threadstart: usize,
        wqthread: usize,
        pthsize: u32,
        pthread_init_data: usize,
        pthread_init_data_size: usize,
    },
    /// `bsdthread_create(func, func_arg, stack, pthread, flags)`
    BsdthreadCreate {
        func: usize,
        func_arg: usize,
        stack: usize,
        pthread: usize,
        flags: u32,
    },
    /// `bsdthread_terminate(stackaddr, freesize, port, sema_or_ulock)`
    BsdthreadTerminate {
        stackaddr: usize,
        freesize: usize,
        port: u32,
        sema_or_ulock: usize,
    },
    /// `bsdthread_ctl(cmd, arg1, arg2, arg3)`
    BsdthreadCtl {
        cmd: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    },
    /// `sigreturn(uctx, infostyle, token)` — restore context after signal handler.
    Sigreturn {
        uctx: usize,
        infostyle: i32,
    },
    Unlink {
        path: usize,
    },
    Access {
        path: usize,
        amode: i32,
    },
    Pipe,
    Fchmod {
        fd: i32,
        mode: u32,
    },
    Mkdir {
        path: usize,
        mode: u32,
    },
    Rmdir {
        path: usize,
    },
    Ftruncate {
        fd: i32,
        length: i64,
    },
    SemwaitSignal {
        cond_sem: i32,
        mutex_sem: i32,
        timeout: i32,
        relative: i32,
        tv_sec: i64,
        tv_nsec: i32,
    },
    Getdirentries64 {
        fd: i32,
        buf: usize,
        bufsize: usize,
        basep: usize,
    },
    Socket {
        domain: u32,
        sock_type: u32,
        protocol: u32,
    },
    Bind {
        fd: u32,
        addr: u64,
        addrlen: u32,
    },
    Listen {
        fd: u32,
        backlog: u32,
    },
    Accept {
        fd: u32,
        addr: u64,
        addrlen: u64,
    },
    Connect {
        fd: u32,
        addr: u64,
        addrlen: u32,
    },
    Sendto {
        fd: u32,
        buf: u64,
        len: u64,
        flags: u32,
        dest_addr: u64,
        addrlen: u32,
    },
    Recvfrom {
        fd: u32,
        buf: u64,
        len: u64,
        flags: u32,
        src_addr: u64,
        addrlen: u64,
    },
    Sendmsg {
        fd: u32,
        msg: u64,
        flags: u32,
    },
    Recvmsg {
        fd: u32,
        msg: u64,
        flags: u32,
    },
    Shutdown {
        fd: u32,
        how: u32,
    },
    Socketpair {
        domain: u32,
        sock_type: u32,
        protocol: u32,
        sv: u64,
    },
    Setsockopt {
        fd: u32,
        level: u32,
        optname: u32,
        optval: u64,
        optlen: u32,
    },
    Getsockopt {
        fd: u32,
        level: u32,
        optname: u32,
        optval: u64,
        optlen: u64,
    },
    Getsockname {
        fd: u32,
        addr: u64,
        addrlen: u64,
    },
    Getpeername {
        fd: u32,
        addr: u64,
        addrlen: u64,
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
            #[allow(clippy::cast_sign_loss)]
            // Mach trap numbers are always small positive after negation
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
            nr::THREAD_SELFID => MacosSyscallRequest::ThreadSelfid,
            nr::MACH_MSG2_TRAP => MacosSyscallRequest::MachMsg2Trap {
                data: a0,
                options: a1,
                msgh_bits: a2 as u32,
            },
            nr::CROSSARCH_TRAP => MacosSyscallRequest::CrossarchTrap,
            nr::CSRCTL => MacosSyscallRequest::Csrctl,
            nr::DUP2 => MacosSyscallRequest::Dup2 {
                oldfd: a0 as i32,
                newfd: a1 as i32,
            },
            nr::MAC_SYSCALL => MacosSyscallRequest::MacSyscall,
            nr::FSCTL => MacosSyscallRequest::Fsctl,
            nr::SHARED_REGION_MAP_AND_SLIDE_2_NP => MacosSyscallRequest::SharedRegionMapAndSlide2Np,
            nr::KDEBUG_TRACE_STRING => MacosSyscallRequest::KdebugTraceString,
            nr::STATFS64 => MacosSyscallRequest::Statfs64 { path: a0, buf: a1 },
            // nr::REBOOT is intentionally not decoded — falls through to the wildcard arm.
            nr::TERMINATE_WITH_PAYLOAD => MacosSyscallRequest::TerminateWithPayload {
                namespace: a1,
                code: a2,
            },
            nr::ABORT_WITH_PAYLOAD => MacosSyscallRequest::AbortWithPayload {
                namespace: a0,
                code: a1,
            },
            nr::STAT64 => MacosSyscallRequest::Stat64 { path: a0, buf: a1 },
            nr::OPENAT => MacosSyscallRequest::Openat {
                dirfd: a0 as i32,
                path: a1,
                flags: a2 as i32,
                mode: a3 as u32,
            },
            nr::FSTATAT64 => MacosSyscallRequest::Fstatat64 {
                dirfd: a0 as i32,
                path: a1,
                buf: a2,
                flag: a3 as i32,
            },
            nr::BSDTHREAD_REGISTER => Self::BsdthreadRegister {
                threadstart: a0,
                wqthread: a1,
                pthsize: a2 as u32,
                pthread_init_data: a3,
                pthread_init_data_size: a4,
            },
            nr::BSDTHREAD_CREATE => Self::BsdthreadCreate {
                func: a0,
                func_arg: a1,
                stack: a2,
                pthread: a3,
                flags: a4 as u32,
            },
            nr::BSDTHREAD_TERMINATE => Self::BsdthreadTerminate {
                stackaddr: a0,
                freesize: a1,
                port: a2 as u32,
                sema_or_ulock: a3,
            },
            nr::SIGRETURN => MacosSyscallRequest::Sigreturn {
                uctx: a0,
                infostyle: a1 as i32,
            },
            nr::BSDTHREAD_CTL => Self::BsdthreadCtl {
                cmd: a0,
                arg1: a1,
                arg2: a2,
                arg3: a3,
            },
            nr::UNLINK => MacosSyscallRequest::Unlink { path: a0 },
            nr::ACCESS => MacosSyscallRequest::Access {
                path: a0,
                amode: a1 as i32,
            },
            nr::PIPE => MacosSyscallRequest::Pipe,
            nr::FCHMOD => MacosSyscallRequest::Fchmod {
                fd: a0 as i32,
                mode: a1 as u32,
            },
            nr::MKDIR => MacosSyscallRequest::Mkdir {
                path: a0,
                mode: a1 as u32,
            },
            nr::RMDIR => MacosSyscallRequest::Rmdir { path: a0 },
            nr::FTRUNCATE => MacosSyscallRequest::Ftruncate {
                fd: a0 as i32,
                length: a1 as i64,
            },
            nr::SEMWAIT_SIGNAL => MacosSyscallRequest::SemwaitSignal {
                cond_sem: a0 as i32,
                mutex_sem: a1 as i32,
                timeout: a2 as i32,
                relative: a3 as i32,
                tv_sec: a4 as i64,
                tv_nsec: a5 as i32,
            },
            nr::GETDIRENTRIES64 => MacosSyscallRequest::Getdirentries64 {
                fd: a0 as i32,
                buf: a1,
                bufsize: a2,
                basep: a3,
            },
            nr::SOCKET => MacosSyscallRequest::Socket {
                domain: a0 as u32,
                sock_type: a1 as u32,
                protocol: a2 as u32,
            },
            nr::BIND => MacosSyscallRequest::Bind {
                fd: a0 as u32,
                addr: a1 as u64,
                addrlen: a2 as u32,
            },
            nr::LISTEN => MacosSyscallRequest::Listen {
                fd: a0 as u32,
                backlog: a1 as u32,
            },
            nr::ACCEPT => MacosSyscallRequest::Accept {
                fd: a0 as u32,
                addr: a1 as u64,
                addrlen: a2 as u64,
            },
            nr::CONNECT => MacosSyscallRequest::Connect {
                fd: a0 as u32,
                addr: a1 as u64,
                addrlen: a2 as u32,
            },
            nr::SENDTO => MacosSyscallRequest::Sendto {
                fd: a0 as u32,
                buf: a1 as u64,
                len: a2 as u64,
                flags: a3 as u32,
                dest_addr: a4 as u64,
                addrlen: a5 as u32,
            },
            nr::RECVFROM => MacosSyscallRequest::Recvfrom {
                fd: a0 as u32,
                buf: a1 as u64,
                len: a2 as u64,
                flags: a3 as u32,
                src_addr: a4 as u64,
                addrlen: a5 as u64,
            },
            nr::SENDMSG => MacosSyscallRequest::Sendmsg {
                fd: a0 as u32,
                msg: a1 as u64,
                flags: a2 as u32,
            },
            nr::RECVMSG => MacosSyscallRequest::Recvmsg {
                fd: a0 as u32,
                msg: a1 as u64,
                flags: a2 as u32,
            },
            nr::SHUTDOWN => MacosSyscallRequest::Shutdown {
                fd: a0 as u32,
                how: a1 as u32,
            },
            nr::SOCKETPAIR => MacosSyscallRequest::Socketpair {
                domain: a0 as u32,
                sock_type: a1 as u32,
                protocol: a2 as u32,
                sv: a3 as u64,
            },
            nr::SETSOCKOPT => MacosSyscallRequest::Setsockopt {
                fd: a0 as u32,
                level: a1 as u32,
                optname: a2 as u32,
                optval: a3 as u64,
                optlen: a4 as u32,
            },
            nr::GETSOCKOPT => MacosSyscallRequest::Getsockopt {
                fd: a0 as u32,
                level: a1 as u32,
                optname: a2 as u32,
                optval: a3 as u64,
                optlen: a4 as u64,
            },
            nr::GETSOCKNAME => MacosSyscallRequest::Getsockname {
                fd: a0 as u32,
                addr: a1 as u64,
                addrlen: a2 as u64,
            },
            nr::GETPEERNAME => MacosSyscallRequest::Getpeername {
                fd: a0 as u32,
                addr: a1 as u64,
                addrlen: a2 as u64,
            },
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
