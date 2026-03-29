// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Raw syscall wrappers using inline assembly.
//!
//! These bypass glibc entirely, avoiding any `%fs`-based TLS access (e.g. for
//! `errno`). This is critical after an in-process `execve`: the guest's old
//! FS base is zeroed (so the new ld-linux can set up fresh TLS), but micro's
//! syscall handling code still runs. If it called glibc's `syscall()` wrapper
//! and the kernel returned an error, glibc would try to store `errno` via
//! `%fs:offset`, hitting address 0 → SIGSEGV.
//!
//! All functions return the raw kernel result (negative errno on error).
//!
//! # Safety
//!
//! All functions in this module are `unsafe` because they issue raw syscalls.
//! The caller must ensure arguments are valid for the given syscall number.

// The entire module wraps syscalls — every function is unsafe with the same
// safety contract, and sign-loss casts are intentional (kernel ABI uses
// unsigned register values). Lint allows are on the `mod` declaration in lib.rs.

/// Issue a syscall with 0 arguments.
#[inline]
pub unsafe fn syscall0(nr: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 1 argument.
#[inline]
pub unsafe fn syscall1(nr: i64, a0: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a0,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 2 arguments.
#[inline]
pub unsafe fn syscall2(nr: i64, a0: u64, a1: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 3 arguments.
#[inline]
pub unsafe fn syscall3(nr: i64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 4 arguments.
#[inline]
pub unsafe fn syscall4(nr: i64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 5 arguments.
#[inline]
pub unsafe fn syscall5(nr: i64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 6 arguments.
#[inline]
pub unsafe fn syscall6(nr: i64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

// ── Convenience wrappers for common syscalls ────────────────────────────

/// Raw `mmap(addr, length, prot, flags, fd, offset)`.
///
/// Returns the mapped address as `usize`, or a negative errno cast to `i64`.
#[inline]
pub unsafe fn mmap(addr: usize, length: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> i64 {
    unsafe {
        syscall6(
            libc::SYS_mmap,
            addr as u64,
            length as u64,
            prot as u64,
            flags as u64,
            fd as u64,
            offset as u64,
        )
    }
}

/// Raw `munmap(addr, length)`.
#[inline]
pub unsafe fn munmap(addr: usize, length: usize) -> i64 {
    unsafe { syscall2(libc::SYS_munmap, addr as u64, length as u64) }
}

/// Raw `mprotect(addr, length, prot)`.
#[inline]
pub unsafe fn mprotect(addr: usize, length: usize, prot: i32) -> i64 {
    unsafe { syscall3(libc::SYS_mprotect, addr as u64, length as u64, prot as u64) }
}

/// Raw `close(fd)`.
#[inline]
pub unsafe fn close(fd: i32) -> i64 {
    unsafe { syscall1(libc::SYS_close, fd as u64) }
}

/// Raw `write(fd, buf, count)`.
#[inline]
pub unsafe fn write(fd: i32, buf: *const u8, count: usize) -> i64 {
    unsafe { syscall3(libc::SYS_write, fd as u64, buf as u64, count as u64) }
}

/// Raw `read(fd, buf, count)`.
#[inline]
pub unsafe fn read(fd: i32, buf: *mut u8, count: usize) -> i64 {
    unsafe { syscall3(libc::SYS_read, fd as u64, buf as u64, count as u64) }
}

/// Raw `open(path, flags)` — via `openat(AT_FDCWD, ...)`.
#[inline]
pub unsafe fn open(path: *const u8, flags: i32) -> i64 {
    // AT_FDCWD = -100
    unsafe {
        syscall3(
            libc::SYS_openat,
            (-100i64) as u64,
            path as u64,
            flags as u64,
        )
    }
}

/// Raw `arch_prctl(code, addr)`.
#[inline]
pub unsafe fn arch_prctl(code: i32, addr: usize) -> i64 {
    unsafe { syscall2(libc::SYS_arch_prctl, code as u64, addr as u64) }
}

/// Raw `futex(addr, op, val, timeout)` with 4 args.
#[inline]
pub unsafe fn futex4(addr: usize, op: i32, val: u32, timeout: usize) -> i64 {
    unsafe {
        syscall4(
            libc::SYS_futex,
            addr as u64,
            op as u64,
            u64::from(val),
            timeout as u64,
        )
    }
}

/// `MAP_FAILED` as i64 for comparison with `mmap()` return values.
pub const MAP_FAILED: i64 = -1;

/// Check if a raw syscall result indicates an error (negative value in
/// the -4095..=-1 range, which is the kernel's errno encoding).
#[inline]
pub const fn is_error(ret: i64) -> bool {
    // Kernel returns -errno for errors, in the range -4095 to -1.
    ret < 0 && ret >= -4095
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_mmap_and_munmap() {
        let addr = unsafe {
            mmap(
                0,
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(!is_error(addr), "mmap failed: {addr}");
        assert_ne!(addr, 0);

        let ret = unsafe { munmap(addr as usize, 4096) };
        assert_eq!(ret, 0, "munmap failed: {ret}");
    }

    #[test]
    fn raw_write_to_dev_null() {
        let msg = b"test\n";
        // Open /dev/null
        let fd = unsafe { open(b"/dev/null\0".as_ptr(), libc::O_WRONLY) };
        assert!(!is_error(fd), "open /dev/null failed: {fd}");

        let ret = unsafe { write(fd as i32, msg.as_ptr(), msg.len()) };
        assert_eq!(ret, 5);

        let ret = unsafe { close(fd as i32) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn raw_getpid() {
        let pid = unsafe { syscall0(libc::SYS_getpid) };
        assert!(pid > 0);
    }
}
