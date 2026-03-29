// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local execution of syscalls authorized by central.

use litebox_ipc::ring::{cq_flags, CqEntry};

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
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
pub unsafe fn execute_locally(
    syscall_nr: u32,
    args: &[u64; 6],
    cq: &CqEntry,
    ring_base: *mut u8,
    layout: &litebox_ipc::ring::SharedRingLayout,
    syscall_entry_point: usize,
) -> i64 {
    match syscall_nr {
        nr if nr == libc::SYS_mmap as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                // File-backed mmap: central populated the data in the shmem data region.
                let map_addr = cq.result as usize;
                let map_len = args[1] as usize;
                let final_prot = args[2] as i32;
                let data_len = cq.data_len as usize;

                // 1. Create anonymous mapping at the address central chose.
                let ptr = unsafe {
                    libc::mmap(
                        map_addr as *mut libc::c_void,
                        map_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                if ptr == libc::MAP_FAILED {
                    return -i64::from(libc::ENOMEM);
                }

                // 2. Copy data from the shared data region.
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, ptr.cast::<u8>(), data_len);
                    }
                }

                // 3. Set final permissions (skip if already RW).
                if final_prot != (libc::PROT_READ | libc::PROT_WRITE) {
                    unsafe { libc::mprotect(ptr, map_len, final_prot) };
                }

                // 4. If TRAMPOLINE flag is set, map the trampoline page for
                //    this dynamically-loaded rewritten ELF.
                if cq.flags & cq_flags::TRAMPOLINE != 0 && !ring_base.is_null() {
                    let desc_offset = cq.data_offset as usize + cq.data_len as usize;
                    let data_region_base = unsafe { ring_base.add(layout.data_region_offset) };

                    // Read TrampolineDescriptor (8 bytes: vaddr_offset u32 LE
                    // + size u32 LE).
                    let desc_ptr = unsafe { data_region_base.add(desc_offset) };
                    let vaddr_offset = unsafe {
                        u32::from_le_bytes(
                            core::slice::from_raw_parts(desc_ptr, 4).try_into().unwrap(),
                        ) as usize
                    };
                    let tramp_size = unsafe {
                        u32::from_le_bytes(
                            core::slice::from_raw_parts(desc_ptr.add(4), 4)
                                .try_into()
                                .unwrap(),
                        ) as usize
                    };

                    if tramp_size > 0 {
                        let tramp_data_src = unsafe { desc_ptr.add(8) };
                        let tramp_addr = map_addr + vaddr_offset;
                        let tramp_page_size = (tramp_size + 0xFFF) & !0xFFF;

                        // Map anonymous writable page at the trampoline address.
                        let tramp_ptr = unsafe {
                            libc::mmap(
                                tramp_addr as *mut libc::c_void,
                                tramp_page_size,
                                libc::PROT_READ | libc::PROT_WRITE,
                                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                                -1,
                                0,
                            )
                        };
                        if tramp_ptr != libc::MAP_FAILED {
                            // Copy trampoline code from the data region.
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    tramp_data_src,
                                    tramp_ptr.cast::<u8>(),
                                    tramp_size,
                                );
                            }

                            // Patch the syscall entry point at offset 0 (first
                            // 8 bytes of the trampoline, used by the rewritten
                            // `JMP [RIP+disp]` instructions).
                            unsafe {
                                *(tramp_ptr.cast::<u64>()) = syscall_entry_point as u64;
                            }

                            // Protect as read + execute.
                            unsafe {
                                libc::mprotect(
                                    tramp_ptr,
                                    tramp_page_size,
                                    libc::PROT_READ | libc::PROT_EXEC,
                                );
                            }
                        }
                    }
                }

                map_addr as i64
            } else if cq.result > 0 {
                // Anonymous mmap: central chose the address via PageManager.
                // Use MAP_FIXED at central's chosen address.
                unsafe {
                    libc::syscall(
                        libc::SYS_mmap,
                        cq.result as usize,
                        args[1] as usize,
                        args[2] as i32,
                        (args[3] as i32) | libc::MAP_FIXED,
                        args[4] as i32,
                        args[5] as i64,
                    )
                }
            } else {
                // cq.result == 0: execute with original args (fallback).
                unsafe {
                    libc::syscall(
                        libc::SYS_mmap,
                        args[0] as usize,
                        args[1] as usize,
                        args[2] as i32,
                        args[3] as i32,
                        args[4] as i32,
                        args[5] as i64,
                    )
                }
            }
        }
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
        nr if nr == libc::SYS_write as u32 => unsafe {
            libc::syscall(
                libc::SYS_write,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
            )
        },
        nr if nr == libc::SYS_read as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                // Central read file data into the shmem data region.
                // Copy it into the guest's buffer.
                let guest_buf = args[1] as *mut u8;
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
                cq.result
            } else if cq.result == -i64::from(libc::EBADF) {
                // EBADF fallback: central's shim doesn't know this fd (e.g. pipe).
                // Execute read locally — the fd is a real OS fd.
                unsafe {
                    libc::syscall(
                        libc::SYS_read,
                        args[0] as i32,
                        args[1] as usize,
                        args[2] as usize,
                    )
                }
            } else {
                // EOF or other error: return the result directly.
                cq.result
            }
        }
        nr if nr == libc::SYS_exit_group as u32 => unsafe {
            libc::syscall(libc::SYS_exit_group, args[0] as i32)
        },
        nr if nr == libc::SYS_exit as u32 => unsafe {
            libc::syscall(libc::SYS_exit, args[0] as i32)
        },
        nr if nr == libc::SYS_clone as u32 => {
            let flags = args[0];
            // CLONE_VM = 0x100: present → thread clone; absent → fork.
            if flags & 0x100 != 0 {
                unsafe { crate::thread::handle_clone(args, cq) }
            } else {
                unsafe { crate::fork::handle_fork(cq) }
            }
        }
        nr if nr == libc::SYS_fstat as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                // Central stat'd the fd and put struct stat in the data region.
                let guest_buf = args[1] as *mut u8;
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
                cq.result
            } else {
                cq.result
            }
        }
        nr if nr == libc::SYS_newfstatat as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                // Central stat'd the path and put struct stat in the data region.
                let guest_buf = args[2] as *mut u8; // arg2 = statbuf for newfstatat
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
                cq.result
            } else {
                cq.result
            }
        }
        nr if nr == libc::SYS_set_tid_address as u32 => unsafe {
            libc::syscall(libc::SYS_set_tid_address, args[0] as usize)
        },
        nr if nr == libc::SYS_set_robust_list as u32 => unsafe {
            libc::syscall(
                libc::SYS_set_robust_list,
                args[0] as usize,
                args[1] as usize,
            )
        },
        nr if nr == libc::SYS_rseq as u32 => unsafe {
            libc::syscall(
                libc::SYS_rseq,
                args[0] as usize,
                args[1] as u32,
                args[2] as i32,
                args[3] as u32,
            )
        },
        nr if nr == libc::SYS_prlimit64 as u32 => unsafe {
            libc::syscall(
                libc::SYS_prlimit64,
                args[0] as i32,
                args[1] as i32,
                args[2] as usize,
                args[3] as usize,
            )
        },
        nr if nr == libc::SYS_getrandom as u32 => unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                args[0] as usize,
                args[1] as usize,
                args[2] as u32,
            )
        },
        nr if nr == libc::SYS_rt_sigaction as u32 => unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
                args[3] as usize,
            )
        },
        nr if nr == libc::SYS_rt_sigprocmask as u32 => unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
                args[3] as usize,
            )
        },
        nr if nr == libc::SYS_sched_getaffinity as u32 => unsafe {
            libc::syscall(
                libc::SYS_sched_getaffinity,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
            )
        },
        nr if nr == libc::SYS_clock_gettime as u32 => unsafe {
            libc::syscall(libc::SYS_clock_gettime, args[0] as i32, args[1] as usize)
        },
        nr if nr == libc::SYS_gettimeofday as u32 => unsafe {
            libc::syscall(libc::SYS_gettimeofday, args[0] as usize, args[1] as usize)
        },
        nr if nr == libc::SYS_pread64 as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                // Central read file data into the shmem data region.
                let guest_buf = args[1] as *mut u8;
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
                cq.result
            } else {
                cq.result
            }
        }
        nr if nr == libc::SYS_pwrite64 as u32 => unsafe {
            libc::syscall(
                libc::SYS_pwrite64,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
                args[3] as i64,
            )
        },
        nr if nr == libc::SYS_wait4 as u32 => unsafe {
            libc::syscall(
                libc::SYS_wait4,
                args[0] as i32,   // pid
                args[1] as usize, // wstatus
                args[2] as i32,   // options
                args[3] as usize, // rusage
            )
        },
        nr if nr == libc::SYS_pipe2 as u32 => unsafe {
            libc::syscall(
                libc::SYS_pipe2,
                args[0] as usize, // pipefd[2] pointer
                args[1] as i32,   // flags
            )
        },
        nr if nr == libc::SYS_alarm as u32 => unsafe {
            libc::syscall(libc::SYS_alarm, args[0] as u32)
        },
        nr if nr == libc::SYS_writev as u32 => unsafe {
            libc::syscall(
                libc::SYS_writev,
                args[0] as i32,
                args[1] as usize,
                args[2] as i32,
            )
        },
        nr if nr == libc::SYS_close as u32 => unsafe {
            libc::syscall(libc::SYS_close, args[0] as i32)
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
        let result = unsafe {
            execute_locally(
                libc::SYS_mmap as u32,
                &args,
                &cq,
                core::ptr::null_mut(),
                &litebox_ipc::ring::SharedRingLayout::default_layout(),
                0,
            )
        };
        assert_ne!(result, -1, "mmap failed");
        assert_ne!(result, 0, "mmap returned NULL");

        let unmap_args = [result.cast_unsigned(), 4096u64, 0, 0, 0, 0];
        let unmap_result = unsafe {
            execute_locally(
                libc::SYS_munmap as u32,
                &unmap_args,
                &cq,
                core::ptr::null_mut(),
                &litebox_ipc::ring::SharedRingLayout::default_layout(),
                0,
            )
        };
        assert_eq!(unmap_result, 0, "munmap failed");
    }

    #[test]
    fn local_exec_unknown_returns_enosys() {
        let args = [0u64; 6];
        let cq = dummy_cq();
        let result = unsafe {
            execute_locally(
                0xFFFF,
                &args,
                &cq,
                core::ptr::null_mut(),
                &litebox_ipc::ring::SharedRingLayout::default_layout(),
                0,
            )
        };
        assert_eq!(result, -i64::from(libc::ENOSYS));
    }
}
