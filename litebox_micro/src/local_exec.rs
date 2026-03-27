// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local execution of syscalls authorized by central.

use litebox_ipc::ring::CqEntry;

/// Execute a locally-authorized syscall.
///
/// Central has determined that this syscall can be safely executed in-process.
/// The result is returned to the caller, which then reports it back to central
/// via `MSG_LOCAL_RESULT`.
///
/// # Safety
///
/// The caller must ensure `syscall_nr` and `args` describe a valid syscall
/// that central has authorized for local execution.
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
pub unsafe fn execute_locally(syscall_nr: u32, args: &[u64; 6], _cq: &CqEntry) -> i64 {
    match syscall_nr {
        nr if nr == libc::SYS_mmap as u32 => unsafe {
            libc::syscall(
                libc::SYS_mmap,
                args[0] as usize,
                args[1] as usize,
                args[2] as i32,
                args[3] as i32,
                args[4] as i32,
                args[5] as i64,
            )
        },
        nr if nr == libc::SYS_munmap as u32 => unsafe {
            libc::syscall(libc::SYS_munmap, args[0] as usize, args[1] as usize)
        },
        nr if nr == libc::SYS_mprotect as u32 => unsafe {
            libc::syscall(
                libc::SYS_mprotect,
                args[0] as usize,
                args[1] as usize,
                args[2] as i32,
            )
        },
        nr if nr == libc::SYS_mremap as u32 => unsafe {
            libc::syscall(
                libc::SYS_mremap,
                args[0] as usize,
                args[1] as usize,
                args[2] as usize,
                args[3] as i32,
                args[4] as usize,
            )
        },
        nr if nr == libc::SYS_madvise as u32 => unsafe {
            libc::syscall(
                libc::SYS_madvise,
                args[0] as usize,
                args[1] as usize,
                args[2] as i32,
            )
        },
        nr if nr == libc::SYS_brk as u32 => unsafe {
            libc::syscall(libc::SYS_brk, args[0] as usize)
        },
        nr if nr == libc::SYS_arch_prctl as u32 => unsafe {
            libc::syscall(libc::SYS_arch_prctl, args[0] as i32, args[1] as usize)
        },
        _ => -i64::from(libc::ENOSYS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_ipc::ring::CqEntry;

    fn dummy_cq() -> CqEntry {
        CqEntry {
            seq: 0,
            result: 0,
            flags: 0,
            thread_slot: 0,
            _pad: [0; 4],
            data_offset: 0,
            data_len: 0,
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn local_exec_mmap_anonymous() {
        let args = [
            0u64,
            4096u64,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            u64::MAX, // fd = -1
            0u64,
        ];
        let cq = dummy_cq();
        let result = unsafe { execute_locally(libc::SYS_mmap as u32, &args, &cq) };
        assert_ne!(result, -1, "mmap failed");
        assert_ne!(result, 0, "mmap returned NULL");

        let unmap_args = [result.cast_unsigned(), 4096u64, 0, 0, 0, 0];
        let unmap_result = unsafe { execute_locally(libc::SYS_munmap as u32, &unmap_args, &cq) };
        assert_eq!(unmap_result, 0, "munmap failed");
    }

    #[test]
    fn local_exec_unknown_returns_enosys() {
        let args = [0u64; 6];
        let cq = dummy_cq();
        let result = unsafe { execute_locally(0xFFFF, &args, &cq) };
        assert_eq!(result, -i64::from(libc::ENOSYS));
    }
}
