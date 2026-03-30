// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local execution of syscalls authorized by central.

use crate::raw_syscall;
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
                let ptr_ret = unsafe {
                    raw_syscall::mmap(
                        map_addr,
                        map_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                if raw_syscall::is_error(ptr_ret) {
                    return -i64::from(libc::ENOMEM);
                }

                // 2. Copy data from the shared data region.
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, ptr_ret as *mut u8, data_len);
                    }
                }

                // 3. Set final permissions (skip if already RW).
                if final_prot != (libc::PROT_READ | libc::PROT_WRITE) {
                    unsafe { raw_syscall::mprotect(ptr_ret as usize, map_len, final_prot) };
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
                        let tramp_ret = unsafe {
                            raw_syscall::mmap(
                                tramp_addr,
                                tramp_page_size,
                                libc::PROT_READ | libc::PROT_WRITE,
                                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                                -1,
                                0,
                            )
                        };
                        if !raw_syscall::is_error(tramp_ret) {
                            // Copy trampoline code from the data region.
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    tramp_data_src,
                                    tramp_ret as *mut u8,
                                    tramp_size,
                                );
                            }

                            // Patch the syscall entry point at offset 0 (first
                            // 8 bytes of the trampoline, used by the rewritten
                            // `JMP [RIP+disp]` instructions).
                            unsafe {
                                *(tramp_ret as *mut u64) = syscall_entry_point as u64;
                            }

                            // Protect as read + execute.
                            unsafe {
                                raw_syscall::mprotect(
                                    tramp_ret as usize,
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
                    raw_syscall::mmap(
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
                    raw_syscall::mmap(
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
            raw_syscall::munmap(args[0] as usize, args[1] as usize)
        },
        nr if nr == libc::SYS_mprotect as u32 => unsafe {
            raw_syscall::mprotect(args[0] as usize, args[1] as usize, args[2] as i32)
        },
        nr if nr == libc::SYS_mremap as u32 => unsafe {
            raw_syscall::syscall5(
                libc::SYS_mremap,
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
            )
        },
        nr if nr == libc::SYS_madvise as u32 => unsafe {
            raw_syscall::syscall3(libc::SYS_madvise, args[0], args[1], args[2])
        },
        nr if nr == libc::SYS_brk as u32 => {
            let requested = args[0] as usize;
            let state = unsafe { crate::state::global_micro_state() };
            let current = state.guest_brk.load(core::sync::atomic::Ordering::Acquire);

            if current == 0 {
                // Pre-execve: pass through to real brk.
                unsafe { raw_syscall::syscall1(libc::SYS_brk, requested as u64) }
            } else if requested == 0 {
                // brk(0): query current break.
                current as i64
            } else if requested > current {
                // Grow: map anonymous pages from current to requested.
                let page_current = (current + 0xFFF) & !0xFFF;
                let page_requested = (requested + 0xFFF) & !0xFFF;
                if page_requested > page_current {
                    let ret = unsafe {
                        raw_syscall::mmap(
                            page_current,
                            page_requested - page_current,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                            -1,
                            0,
                        )
                    };
                    if raw_syscall::is_error(ret) {
                        // Return current brk (failure).
                        return current as i64;
                    }
                }
                state
                    .guest_brk
                    .store(requested, core::sync::atomic::Ordering::Release);
                requested as i64
            } else if requested < current {
                // Shrink: unmap pages from requested to current.
                let page_requested = (requested + 0xFFF) & !0xFFF;
                let page_current = (current + 0xFFF) & !0xFFF;
                if page_current > page_requested {
                    unsafe {
                        raw_syscall::munmap(page_requested, page_current - page_requested);
                    }
                }
                state
                    .guest_brk
                    .store(requested, core::sync::atomic::Ordering::Release);
                requested as i64
            } else {
                // No change.
                current as i64
            }
        }
        nr if nr == libc::SYS_arch_prctl as u32 => unsafe {
            raw_syscall::arch_prctl(args[0] as i32, args[1] as usize)
        },
        nr if nr == libc::SYS_write as u32 => unsafe {
            raw_syscall::write(args[0] as i32, args[1] as *const u8, args[2] as usize)
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
                unsafe { raw_syscall::read(args[0] as i32, args[1] as *mut u8, args[2] as usize) }
            } else {
                // EOF or other error: return the result directly.
                cq.result
            }
        }
        nr if nr == libc::SYS_exit_group as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_exit_group, args[0])
        },
        nr if nr == libc::SYS_exit as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_exit, args[0])
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
        nr if nr == libc::SYS_fork as u32 || nr == libc::SYS_vfork as u32 => unsafe {
            crate::fork::handle_fork(cq)
        },
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
        nr if nr == libc::SYS_stat as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                // Central stat'd the path and put struct stat in the data region.
                let guest_buf = args[1] as *mut u8; // arg1 = statbuf for stat
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
        nr if nr == libc::SYS_lstat as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                // Central lstat'd the path and put struct stat in the data region.
                let guest_buf = args[1] as *mut u8; // arg1 = statbuf for lstat
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
        nr if nr == libc::SYS_readlink as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                let guest_buf = args[1] as *mut u8; // arg1 = buf
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
        nr if nr == libc::SYS_readlinkat as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                let guest_buf = args[2] as *mut u8; // arg2 = buf for readlinkat
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
        nr if nr == libc::SYS_getdents64 as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                let guest_buf = args[1] as *mut u8; // arg1 = dirp
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
            } else if cq.result == 0 {
                // End of directory.
                0
            } else {
                cq.result
            }
        }
        nr if nr == libc::SYS_getcwd as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                let guest_buf = args[0] as *mut u8; // arg0 = buf
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
            raw_syscall::syscall1(libc::SYS_set_tid_address, args[0])
        },
        nr if nr == libc::SYS_set_robust_list as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_set_robust_list, args[0], args[1])
        },
        nr if nr == libc::SYS_rseq as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_rseq, args[0], args[1], args[2], args[3])
        },
        nr if nr == libc::SYS_prlimit64 as u32 => {
            // Bidirectional: old_limit output comes back via HAS_DATA.
            if cq.flags & cq_flags::HAS_DATA != 0 {
                let guest_buf = args[3] as *mut u8; // old_limit (r10)
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
            }
            cq.result
        }
        nr if nr == libc::SYS_getrandom as u32 => {
            if cq.flags & cq_flags::HAS_DATA != 0 {
                let guest_buf = args[0] as *mut u8; // buf (rdi)
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
            }
            cq.result
        }
        nr if nr == libc::SYS_sched_getaffinity as u32 => {
            if cq.flags & cq_flags::HAS_DATA != 0 {
                let guest_buf = args[2] as *mut u8; // mask (rdx)
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
            }
            cq.result
        }
        nr if nr == libc::SYS_clock_gettime as u32 => {
            if cq.flags & cq_flags::HAS_DATA != 0 {
                let guest_buf = args[1] as *mut u8; // tp (rsi)
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
            }
            cq.result
        }
        nr if nr == libc::SYS_gettimeofday as u32 => {
            if cq.flags & cq_flags::HAS_DATA != 0 {
                let guest_buf = args[0] as *mut u8; // tv (rdi)
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
            }
            cq.result
        }
        // Sleep: dereference guest timespec struct for duration
        nr if nr == libc::SYS_nanosleep as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_nanosleep, args[0], args[1])
        },
        nr if nr == libc::SYS_clock_nanosleep as u32 => unsafe {
            raw_syscall::syscall4(
                libc::SYS_clock_nanosleep,
                args[0],
                args[1],
                args[2],
                args[3],
            )
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
            raw_syscall::syscall4(libc::SYS_pwrite64, args[0], args[1], args[2], args[3])
        },
        nr if nr == libc::SYS_wait4 as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_wait4, args[0], args[1], args[2], args[3])
        },
        nr if nr == libc::SYS_pipe2 as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_pipe2, args[0], args[1])
        },
        // Signal syscalls: executed locally via raw kernel syscalls (micro-local
        // fast-path normally handles these, but these arms serve as fallback).
        nr if nr == libc::SYS_alarm as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_alarm, args[0])
        },
        nr if nr == libc::SYS_rt_sigsuspend as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_rt_sigsuspend, args[0], args[1])
        },
        nr if nr == libc::SYS_rt_sigaction as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_rt_sigaction, args[0], args[1], args[2], args[3])
        },
        nr if nr == libc::SYS_rt_sigprocmask as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_rt_sigprocmask, args[0], args[1], args[2], args[3])
        },
        nr if nr == libc::SYS_sigaltstack as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_sigaltstack, args[0], args[1])
        },
        nr if nr == libc::SYS_time as u32 => {
            if cq.flags & cq_flags::HAS_DATA != 0 {
                let guest_buf = args[0] as *mut u8; // tloc (rdi)
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
            }
            cq.result
        }
        nr if nr == libc::SYS_uname as u32 => {
            if cq.flags & cq_flags::HAS_DATA != 0 {
                let guest_buf = args[0] as *mut u8; // buf (rdi)
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
            }
            cq.result
        }
        nr if nr == libc::SYS_sysinfo as u32 => {
            if cq.flags & cq_flags::HAS_DATA != 0 {
                let guest_buf = args[0] as *mut u8; // info (rdi)
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
            }
            cq.result
        }
        nr if nr == libc::SYS_getrlimit as u32 => {
            if cq.flags & cq_flags::HAS_DATA != 0 {
                let guest_buf = args[1] as *mut u8; // rlim (rsi)
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
            }
            cq.result
        }
        nr if nr == libc::SYS_clock_getres as u32 => {
            if cq.flags & cq_flags::HAS_DATA != 0 {
                let guest_buf = args[1] as *mut u8; // res (rsi)
                let data_len = cq.data_len as usize;
                if !ring_base.is_null() && data_len > 0 {
                    unsafe {
                        let data_src = ring_base
                            .add(layout.data_region_offset)
                            .add(cq.data_offset as usize);
                        core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
                    }
                }
            }
            cq.result
        }
        nr if nr == libc::SYS_writev as u32 => unsafe {
            raw_syscall::syscall3(libc::SYS_writev, args[0], args[1], args[2])
        },
        nr if nr == libc::SYS_close as u32 => unsafe { raw_syscall::close(args[0] as i32) },
        // FD manipulation: operates on real OS fds (pipes from pipe2, etc.)
        nr if nr == libc::SYS_dup as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_dup, args[0])
        },
        nr if nr == libc::SYS_dup2 as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_dup2, args[0], args[1])
        },
        nr if nr == libc::SYS_dup3 as u32 => unsafe {
            raw_syscall::syscall3(libc::SYS_dup3, args[0], args[1], args[2])
        },
        nr if nr == libc::SYS_fcntl as u32 => unsafe {
            raw_syscall::syscall3(libc::SYS_fcntl, args[0], args[1], args[2])
        },
        // Process/user identity: libOS-emulated from MicroState / virtual values.
        // These MUST NOT do raw kernel syscalls — LiteBox is a libOS.
        nr if nr == libc::SYS_getpid as u32 => {
            let state = unsafe { crate::state::global_micro_state() };
            i64::from(state.pid)
        }
        nr if nr == libc::SYS_getppid as u32 => {
            let state = unsafe { crate::state::global_micro_state() };
            i64::from(state.ppid)
        }
        // Virtual root identity (uid=0, gid=0) — container-like behavior.
        nr if nr == libc::SYS_getuid as u32 => 0,
        nr if nr == libc::SYS_getgid as u32 => 0,
        nr if nr == libc::SYS_geteuid as u32 => 0,
        nr if nr == libc::SYS_getegid as u32 => 0,
        // Memory query: mincore checks page residency
        nr if nr == libc::SYS_mincore as u32 => unsafe {
            raw_syscall::syscall3(libc::SYS_mincore, args[0], args[1], args[2])
        },
        // Filesystem sync: no arguments, must run locally
        nr if nr == libc::SYS_sync as u32 => unsafe { raw_syscall::syscall0(libc::SYS_sync) },
        _ => -i64::from(libc::ENOSYS),
    }
}

/// Map a Tier 2 syscall number to its `MSG_NOTIFY_*` control message number.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn tier2_notify_message(nr: u32) -> u32 {
    match i64::from(nr) {
        libc::SYS_alarm => litebox_ipc::messages::MSG_NOTIFY_ALARM,
        libc::SYS_pipe2 => litebox_ipc::messages::MSG_NOTIFY_PIPE2,
        libc::SYS_wait4 => litebox_ipc::messages::MSG_NOTIFY_WAIT4,
        _ => unreachable!("tier2_notify_message called for non-Tier-2 syscall {nr}"),
    }
}

/// Build the notification args for a Tier 2 syscall.
///
/// Packs the relevant arguments and result into a 6-element array
/// matching the `MSG_NOTIFY_*` protocol defined in `litebox_ipc::messages`.
///
/// # Safety
///
/// For `pipe2`: if `result == 0`, reads the two i32 fd values from the
/// pointer in `args[0]` (which the kernel just wrote to).
/// For `wait4`: if `result > 0` and `args[1]` is non-null, reads the
/// i32 status value from that pointer.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) unsafe fn tier2_notify_args(nr: u32, args: &[u64; 6], result: i64) -> [u64; 6] {
    match i64::from(nr) {
        libc::SYS_alarm => {
            // args[0] = seconds requested, result = remaining seconds
            [args[0], result.cast_unsigned(), 0, 0, 0, 0]
        }
        libc::SYS_pipe2 => {
            // Read fd values from the int[2] output buffer after successful syscall
            let (fd0, fd1) = if result == 0 {
                let fds_ptr = args[0] as *const i32;
                unsafe { ((*fds_ptr) as u64, (*fds_ptr.add(1)) as u64) }
            } else {
                (0, 0)
            };
            // fd[0], fd[1], flags, result, 0, 0
            [fd0, fd1, args[1], result.cast_unsigned(), 0, 0]
        }
        libc::SYS_wait4 => {
            // Read status from output pointer after successful wait
            let status = if result > 0 {
                let status_ptr = args[1] as *const i32;
                if status_ptr.is_null() {
                    0
                } else {
                    unsafe { (*status_ptr) as u64 }
                }
            } else {
                0
            };
            // pid_arg, returned_pid (result), status, options, 0, 0
            [args[0], result.cast_unsigned(), status, args[2], 0, 0]
        }
        _ => unreachable!("tier2_notify_args called for non-Tier-2 syscall {nr}"),
    }
}

/// Execute a micro-local syscall directly, without consulting central.
///
/// SYNC NOTE: The match arms here must stay in sync with `is_tier1_micro_local()`
/// and `is_tier2_notify()` in `handler.rs` and the overlapping arms in
/// `execute_locally()` above. Both Tier 1 and Tier 2 syscalls are handled here;
/// the difference is only whether `notify_central` is called afterward.
/// The `tier_classification_covers_all` test below enforces the invariant.
///
/// # Safety
///
/// The caller must ensure `syscall_nr` and `args` describe a valid syscall
/// that is in the micro-local set (or brk post-execve).
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]
pub unsafe fn execute_micro_local(syscall_nr: u32, args: &[u64; 6]) -> i64 {
    match syscall_nr {
        // Process/user identity: libOS-emulated from MicroState / virtual values.
        // These MUST NOT do raw kernel syscalls — LiteBox is a libOS.
        nr if nr == libc::SYS_getpid as u32 => {
            let state = unsafe { crate::state::global_micro_state() };
            i64::from(state.pid)
        }
        nr if nr == libc::SYS_getppid as u32 => {
            let state = unsafe { crate::state::global_micro_state() };
            i64::from(state.ppid)
        }
        // Virtual root identity (uid=0, gid=0) — container-like behavior.
        nr if nr == libc::SYS_getuid as u32 => 0,
        nr if nr == libc::SYS_getgid as u32 => 0,
        nr if nr == libc::SYS_geteuid as u32 => 0,
        nr if nr == libc::SYS_getegid as u32 => 0,
        // Sleep: blocking, no shared state
        nr if nr == libc::SYS_nanosleep as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_nanosleep, args[0], args[1])
        },
        nr if nr == libc::SYS_clock_nanosleep as u32 => unsafe {
            raw_syscall::syscall4(
                libc::SYS_clock_nanosleep,
                args[0],
                args[1],
                args[2],
                args[3],
            )
        },
        // Thread setup: thread-local only
        nr if nr == libc::SYS_arch_prctl as u32 => unsafe {
            raw_syscall::arch_prctl(args[0] as i32, args[1] as usize)
        },
        nr if nr == libc::SYS_set_tid_address as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_set_tid_address, args[0])
        },
        nr if nr == libc::SYS_set_robust_list as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_set_robust_list, args[0], args[1])
        },
        nr if nr == libc::SYS_rseq as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_rseq, args[0], args[1], args[2], args[3])
        },
        // Signal suspend: must block in micro where real signals are delivered.
        nr if nr == libc::SYS_rt_sigsuspend as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_rt_sigsuspend, args[0], args[1])
        },
        // Signal management: must execute locally because micro is the process
        // that receives real kernel signals (alarm timers, SIGCHLD, etc.).
        nr if nr == libc::SYS_rt_sigaction as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_rt_sigaction, args[0], args[1], args[2], args[3])
        },
        nr if nr == libc::SYS_rt_sigprocmask as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_rt_sigprocmask, args[0], args[1], args[2], args[3])
        },
        nr if nr == libc::SYS_sigaltstack as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_sigaltstack, args[0], args[1])
        },
        nr if nr == libc::SYS_alarm as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_alarm, args[0])
        },
        // Memory query: checks pages in micro's address space
        nr if nr == libc::SYS_mincore as u32 => unsafe {
            raw_syscall::syscall3(libc::SYS_mincore, args[0], args[1], args[2])
        },
        // Process wait: must run in micro's PID namespace
        nr if nr == libc::SYS_wait4 as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_wait4, args[0], args[1], args[2], args[3])
        },
        // Pipe creation: real OS pipes, no shim state
        nr if nr == libc::SYS_pipe2 as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_pipe2, args[0], args[1])
        },
        // Filesystem sync: no arguments
        nr if nr == libc::SYS_sync as u32 => unsafe { raw_syscall::syscall0(libc::SYS_sync) },
        // brk: post-execve, managed entirely by micro's guest_brk watermark.
        // Only called when guest_brk != 0 (handler.rs checks this precondition).
        nr if nr == libc::SYS_brk as u32 => {
            let requested = args[0] as usize;
            let state = unsafe { crate::state::global_micro_state() };
            let current = state.guest_brk.load(core::sync::atomic::Ordering::Acquire);
            debug_assert!(current != 0, "execute_micro_local(brk) called pre-execve");

            if requested == 0 {
                // brk(0): query current break.
                current as i64
            } else if requested > current {
                // Grow: map anonymous pages from current to requested.
                let page_current = (current + 0xFFF) & !0xFFF;
                let page_requested = (requested + 0xFFF) & !0xFFF;
                if page_requested > page_current {
                    let ret = unsafe {
                        raw_syscall::mmap(
                            page_current,
                            page_requested - page_current,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                            -1,
                            0,
                        )
                    };
                    if raw_syscall::is_error(ret) {
                        // Return current brk (failure).
                        return current as i64;
                    }
                }
                state
                    .guest_brk
                    .store(requested, core::sync::atomic::Ordering::Release);
                requested as i64
            } else if requested < current {
                // Shrink: unmap pages from requested to current.
                let page_requested = (requested + 0xFFF) & !0xFFF;
                let page_current = (current + 0xFFF) & !0xFFF;
                if page_current > page_requested {
                    unsafe {
                        raw_syscall::munmap(page_requested, page_current - page_requested);
                    }
                }
                state
                    .guest_brk
                    .store(requested, core::sync::atomic::Ordering::Release);
                requested as i64
            } else {
                // No change.
                current as i64
            }
        }
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

    /// Verify that `is_tier1_micro_local`, `is_tier2_notify`, and
    /// `execute_micro_local` stay in sync. Tests that every syscall in
    /// each tier is accepted by the corresponding classifier and handled
    /// by `execute_micro_local` (doesn't return -ENOSYS for safe zero-arg
    /// calls). Also verifies Tier 1 and Tier 2 don't overlap.
    ///
    /// Note: Group 1 syscalls (uname, sysinfo, getrlimit, prlimit64,
    /// sched_getaffinity, getrandom, clock_gettime, gettimeofday, time,
    /// clock_getres) are routed through central's shim via HAS_DATA,
    /// not micro-local.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn tier_classification_covers_all() {
        // Tier 1: silent micro-local (no notification needed).
        let tier1_nrs: &[i64] = &[
            libc::SYS_getpid,
            libc::SYS_getppid,
            libc::SYS_getuid,
            libc::SYS_getgid,
            libc::SYS_geteuid,
            libc::SYS_getegid,
            libc::SYS_nanosleep,
            libc::SYS_clock_nanosleep,
            libc::SYS_arch_prctl,
            libc::SYS_set_tid_address,
            libc::SYS_set_robust_list,
            libc::SYS_rseq,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_sigaltstack,
            libc::SYS_rt_sigsuspend,
            libc::SYS_mincore,
            libc::SYS_sync,
        ];

        for &sys_nr in tier1_nrs {
            let nr = sys_nr as u32;
            assert!(
                crate::handler::is_tier1_micro_local(nr),
                "SYS {sys_nr} should be Tier 1 but is_tier1_micro_local returned false"
            );
            assert!(
                !crate::handler::is_tier2_notify(nr),
                "SYS {sys_nr} is in both Tier 1 and Tier 2"
            );
        }

        // Tier 2: notify-after-execute.
        let tier2_nrs: &[i64] = &[libc::SYS_alarm, libc::SYS_pipe2, libc::SYS_wait4];

        for &sys_nr in tier2_nrs {
            let nr = sys_nr as u32;
            assert!(
                crate::handler::is_tier2_notify(nr),
                "SYS {sys_nr} should be Tier 2 but is_tier2_notify returned false"
            );
            assert!(
                !crate::handler::is_tier1_micro_local(nr),
                "SYS {sys_nr} is in both Tier 1 and Tier 2"
            );
        }

        // Verify that zero-arg identity syscalls are properly dispatched
        // (not returning -ENOSYS). These are safe to call unconditionally.
        let safe_zero_arg: &[i64] = &[
            libc::SYS_getpid,
            libc::SYS_getppid,
            libc::SYS_getuid,
            libc::SYS_getgid,
            libc::SYS_geteuid,
            libc::SYS_getegid,
        ];
        for &sys_nr in safe_zero_arg {
            let nr = sys_nr as u32;
            let args = [0u64; 6];
            let result = unsafe { execute_micro_local(nr, &args) };
            assert_ne!(
                result,
                -i64::from(libc::ENOSYS),
                "execute_micro_local returned -ENOSYS for SYS {sys_nr}"
            );
        }

        // Unknown syscall still returns -ENOSYS.
        let args = [0u64; 6];
        let result = unsafe { execute_micro_local(0xFFFF, &args) };
        assert_eq!(result, -i64::from(libc::ENOSYS));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn tier2_notify_message_maps_correctly() {
        assert_eq!(
            tier2_notify_message(libc::SYS_alarm as u32),
            litebox_ipc::messages::MSG_NOTIFY_ALARM
        );
        assert_eq!(
            tier2_notify_message(libc::SYS_pipe2 as u32),
            litebox_ipc::messages::MSG_NOTIFY_PIPE2
        );
        assert_eq!(
            tier2_notify_message(libc::SYS_wait4 as u32),
            litebox_ipc::messages::MSG_NOTIFY_WAIT4
        );
    }

    /// Basic smoke test: `execute_micro_local` for getpid returns the
    /// virtual PID from `MicroState`, not the host kernel PID.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn micro_local_getpid() {
        // MicroState.pid defaults to 0 in the static initializer.
        let args = [0u64; 6];
        let result = unsafe { execute_micro_local(libc::SYS_getpid as u32, &args) };
        let state = unsafe { crate::state::global_micro_state() };
        assert_eq!(
            result,
            i64::from(state.pid),
            "micro_local getpid should return virtual PID from MicroState"
        );
    }

    /// Identity syscalls return virtual root (uid=0, gid=0) — libOS emulation.
    #[test]
    fn micro_local_identity_returns_virtual_root() {
        let args = [0u64; 6];
        for &(nr, name) in &[
            (libc::SYS_getuid, "getuid"),
            (libc::SYS_getgid, "getgid"),
            (libc::SYS_geteuid, "geteuid"),
            (libc::SYS_getegid, "getegid"),
        ] {
            let result = unsafe { execute_micro_local(nr as u32, &args) };
            assert_eq!(result, 0, "{name} should return 0 (virtual root)");
        }
    }

    /// `execute_micro_local` for unknown syscall returns -ENOSYS.
    #[test]
    fn micro_local_unknown_returns_enosys() {
        let args = [0u64; 6];
        let result = unsafe { execute_micro_local(0xFFFF, &args) };
        assert_eq!(result, -i64::from(libc::ENOSYS));
    }
}
