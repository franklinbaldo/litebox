// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Core syscall handler called from the assembly trampoline.

use core::sync::atomic::Ordering::Acquire;

use litebox_ipc::cq::{cq_find_by_seq, cq_tail};
use litebox_ipc::ring::{cq_flags, CqEntry, RingHeader, SharedRingLayout, SqEntry};
use litebox_ipc::sq::{sq_acquire_slot, sq_publish};
use litebox_ipc::wait::spin_then_wait;

use crate::local_exec::execute_locally;
use crate::tls::MicroTls;
use crate::trampoline::SyscallArgs;

fn futex_wait(addr: &core::sync::atomic::AtomicU32, expected: u32) {
    unsafe {
        crate::raw_syscall::futex4(
            core::ptr::from_ref(addr) as usize,
            libc::FUTEX_WAIT,
            expected,
            0,
        );
    }
}

fn futex_wake(addr: &core::sync::atomic::AtomicU32) {
    unsafe {
        crate::raw_syscall::futex4(core::ptr::from_ref(addr) as usize, libc::FUTEX_WAKE, 1, 0);
    }
}

#[inline]
#[allow(clippy::cast_ptr_alignment)] // ring_base is guaranteed to be properly aligned
unsafe fn ring_ptrs(
    base: *mut u8,
    layout: &SharedRingLayout,
) -> (&'static RingHeader, *mut SqEntry, *const CqEntry) {
    let header = unsafe { &*(base.cast::<RingHeader>()) };
    let sq_entries = unsafe { base.add(layout.sq_entries_offset).cast::<SqEntry>() };
    let cq_entries = unsafe { base.add(layout.cq_entries_offset).cast::<CqEntry>() };
    (header, sq_entries, cq_entries)
}

/// Per-thread region size in the data region for pathname transfer.
const PATHNAME_REGION_SIZE: usize = 4096;

/// Returns the argument index that contains a pathname pointer for the given
/// syscall, or `None` if the syscall doesn't carry a pathname argument that
/// central needs to dereference.
#[allow(clippy::cast_possible_truncation)]
fn pathname_arg_index(nr: u32) -> Option<usize> {
    #[allow(clippy::match_same_arms)] // arms kept separate for per-syscall documentation
    match i64::from(nr) {
        libc::SYS_openat => Some(1),   // openat(dirfd, pathname, flags, mode)
        libc::SYS_open => Some(0),     // open(pathname, flags, mode)
        libc::SYS_creat => Some(0),    // creat(pathname, mode)
        libc::SYS_access => Some(0),   // access(pathname, mode)
        libc::SYS_stat => Some(0),     // stat(pathname, statbuf)
        libc::SYS_lstat => Some(0),    // lstat(pathname, statbuf)
        libc::SYS_readlink => Some(0), // readlink(pathname, buf, bufsiz)
        libc::SYS_unlink => Some(0),   // unlink(pathname)
        libc::SYS_chdir => Some(0),    // chdir(pathname)
        libc::SYS_mkdir => Some(0),    // mkdir(pathname, mode)
        libc::SYS_unlinkat => Some(1), // unlinkat(dirfd, pathname, flags)
        libc::SYS_newfstatat
            if {
                // newfstatat(dirfd, pathname, statbuf, flags)
                // Only if pathname != empty string (AT_EMPTY_PATH uses fd only)
                true
            } =>
        {
            Some(1)
        }
        libc::SYS_faccessat => Some(1), // faccessat(dirfd, pathname, mode)
        libc::SYS_faccessat2 => Some(1), // faccessat2(dirfd, pathname, mode, flags)
        _ => None,
    }
}

/// Copy the pathname string from the guest's memory into the shared data
/// region. Updates the SQ entry's `data_offset` and `data_len` fields.
///
/// Each thread uses a 4 KiB region at `thread_slot * 4096` within the data
/// region, avoiding conflicts between concurrent threads.
///
/// # Safety
///
/// The pathname pointer (from `args`) must be a valid C string in the guest's
/// address space.
fn copy_pathname_to_data_region(
    entry: &mut SqEntry,
    args: &[u64; 6],
    syscall_nr: u32,
    ring_base: *mut u8,
    layout: &SharedRingLayout,
) {
    let Some(arg_idx) = pathname_arg_index(syscall_nr) else {
        return;
    };

    let pathname_ptr = args[arg_idx] as *const u8;
    if pathname_ptr.is_null() {
        return;
    }

    // Read the pathname as a C string (NUL-terminated) from guest memory.
    // SAFETY: The guest passed this pointer as a syscall argument, so it
    // should point to a valid NUL-terminated string in guest memory.
    let cstr = unsafe { core::ffi::CStr::from_ptr(pathname_ptr.cast()) };
    let bytes = cstr.to_bytes_with_nul();

    // Compute per-thread offset in the data region.
    let thread_offset = entry.thread_slot as usize * PATHNAME_REGION_SIZE;
    let max_len = PATHNAME_REGION_SIZE.min(bytes.len());
    if thread_offset + max_len > layout.data_region_size {
        // Data region too small — skip the copy. Central will segfault,
        // but this shouldn't happen with the default 4 MiB region.
        return;
    }

    // Copy into the data region.
    unsafe {
        let dst = ring_base.add(layout.data_region_offset + thread_offset);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, max_len);
    }

    #[allow(clippy::cast_possible_truncation)]
    {
        entry.data_offset = thread_offset as u32;
        entry.data_len = max_len as u32;
    }
}

/// Base offset in the data region where write data starts.
///
/// Pathname slots use `thread_slot * PATHNAME_REGION_SIZE` (up to
/// `MAX_PATHNAME_SLOTS * 4096 = 256 * 4096 = 1 MiB`).  Write data is placed
/// past all pathname slots to avoid conflicts with concurrent pathname
/// transfers from other threads.
const WRITE_DATA_BASE_OFFSET: usize = 256 * PATHNAME_REGION_SIZE; // 1 MiB

/// Per-thread region size for write data in the data region (64 KiB).
///
/// Each thread can write up to this many bytes per syscall. Writes larger
/// than this are capped (the kernel will return a short write).
const WRITE_DATA_REGION_SIZE: usize = 65536;

/// Returns `(buf_arg_index, count_arg_index)` for write-family syscalls,
/// or `None` if this is not a write syscall.
#[allow(clippy::cast_possible_truncation)]
fn write_data_arg_info(nr: u32) -> Option<(usize, usize)> {
    #[allow(clippy::match_same_arms)] // arms kept separate for per-syscall documentation
    match i64::from(nr) {
        libc::SYS_write => Some((1, 2)),    // write(fd, buf, count)
        libc::SYS_pwrite64 => Some((1, 2)), // pwrite64(fd, buf, count, offset)
        _ => None,
    }
}

/// Copy write data from the guest's memory into the shared data region.
///
/// Updates the SQ entry's `data_offset` and `data_len` fields so central
/// knows where to find the data.
///
/// Each thread uses a separate region in the data region past the pathname
/// slots: `WRITE_DATA_BASE_OFFSET + thread_slot * WRITE_DATA_REGION_SIZE`.
///
/// # Safety
///
/// The buffer pointer (from `args`) must point to valid readable memory of
/// at least `count` bytes in the guest's address space.
#[allow(clippy::cast_possible_truncation)]
fn copy_write_data_to_data_region(
    entry: &mut SqEntry,
    args: &[u64; 6],
    syscall_nr: u32,
    ring_base: *mut u8,
    layout: &SharedRingLayout,
) {
    let Some((buf_idx, count_idx)) = write_data_arg_info(syscall_nr) else {
        return;
    };

    let buf_ptr = args[buf_idx] as *const u8;
    let count = args[count_idx] as usize;

    if buf_ptr.is_null() || count == 0 {
        return;
    }

    // Compute per-thread offset in the write data zone.
    let thread_offset =
        WRITE_DATA_BASE_OFFSET + entry.thread_slot as usize * WRITE_DATA_REGION_SIZE;
    let max_len = count.min(WRITE_DATA_REGION_SIZE);
    if thread_offset + max_len > layout.data_region_size {
        // Data region too small — skip the copy.
        return;
    }

    // Copy from guest memory into the data region.
    unsafe {
        let dst = ring_base.add(layout.data_region_offset + thread_offset);
        core::ptr::copy_nonoverlapping(buf_ptr, dst, max_len);
    }

    #[allow(clippy::cast_possible_truncation)]
    {
        entry.data_offset = thread_offset as u32;
        entry.data_len = max_len as u32;
    }
}

/// Submit an `SqEntry` and wait for the corresponding `CqEntry`.
///
/// # Safety
///
/// - `tls` must point to a valid, initialized `MicroTls`.
/// - The ring buffer referenced by the TLS must be valid and properly mapped.
#[allow(clippy::cast_possible_truncation)] // slot indices and thread_slot fit in smaller types
pub(crate) unsafe fn submit_and_wait(
    tls: *mut MicroTls,
    syscall_nr: u32,
    args: &[u64; 6],
    flags: u16,
) -> CqEntry {
    let micro = unsafe { &*(*tls).micro };
    let (header, sq_entries, cq_entries) = unsafe { ring_ptrs(micro.ring_base, &micro.layout) };

    let seq = unsafe { (*tls).seq_counter };
    unsafe { (*tls).seq_counter += 1 };

    // Capture the CQ tail BEFORE publishing the SQ entry so that we
    // don't miss a fast completion that arrives before we start scanning.
    let thread_slot = unsafe { (*tls).thread_slot as u16 };
    let notify_slot = &header.cq_notify_slots[thread_slot as usize];
    let search_start = cq_tail(header);

    let slot_idx = unsafe { sq_acquire_slot(header) };
    let entry = unsafe { &mut *sq_entries.add(slot_idx as usize) };

    entry.seq = seq;
    entry.syscall_nr = syscall_nr;
    entry.thread_slot = thread_slot;
    entry.flags = flags;
    entry.args = *args;
    entry.data_offset = 0;
    entry.data_len = 0;

    // For pathname syscalls, copy the pathname string from the guest's address
    // space into the shared data region so central can read it (central is a
    // separate process and cannot dereference guest pointers directly).
    copy_pathname_to_data_region(entry, args, syscall_nr, micro.ring_base, &micro.layout);

    // For write-family syscalls, copy the write buffer from the guest's
    // address space into the data region so central can dispatch through
    // the shim (which may handle virtual fds).
    copy_write_data_to_data_region(entry, args, syscall_nr, micro.ring_base, &micro.layout);

    sq_publish(entry);
    header
        .sq_notify
        .fetch_add(1, core::sync::atomic::Ordering::Release);
    futex_wake(&header.sq_notify);

    loop {
        if let Some(cq) = unsafe { cq_find_by_seq(header, cq_entries, search_start, seq) } {
            return cq;
        }
        let current = notify_slot.load(Acquire);
        if let Some(cq) = unsafe { cq_find_by_seq(header, cq_entries, search_start, seq) } {
            return cq;
        }
        spin_then_wait(notify_slot, current, futex_wait);
    }
}

/// Report the result of a locally-executed syscall back to central.
///
/// # Safety
///
/// - `tls` must point to a valid, initialized `MicroTls`.
#[allow(clippy::cast_sign_loss)] // result is intentionally reinterpreted as u64 for transport
unsafe fn report_local_result(tls: *mut MicroTls, original_seq: u64, result: i64) {
    let args = [original_seq, result.cast_unsigned(), 0, 0, 0, 0];
    unsafe {
        submit_and_wait(tls, litebox_ipc::messages::MSG_LOCAL_RESULT, &args, 0);
    }
}

/// Returns `true` if this syscall can be executed entirely within micro
/// without consulting central. These are syscalls where central provably
/// does zero work — it always returns `EXEC_LOCAL` with no shim dispatch,
/// no state update, and no side effects.
#[allow(clippy::cast_possible_truncation)]
fn is_micro_local(nr: u32) -> bool {
    matches!(
        i64::from(nr),
        // Process/user identity: return kernel constants
        libc::SYS_getpid
            | libc::SYS_getppid
            | libc::SYS_getuid
            | libc::SYS_getgid
            | libc::SYS_geteuid
            | libc::SYS_getegid
            // Time: read-only kernel state, writes to guest buffer
            | libc::SYS_clock_gettime
            | libc::SYS_gettimeofday
            | libc::SYS_time
            | libc::SYS_clock_getres
            // Sleep: blocking, no shared state
            | libc::SYS_nanosleep
            | libc::SYS_clock_nanosleep
            // Thread setup: thread-local only
            | libc::SYS_arch_prctl
            | libc::SYS_set_tid_address
            | libc::SYS_set_robust_list
            | libc::SYS_rseq
            // Signals: process-local signal state
            | libc::SYS_rt_sigaction
            | libc::SYS_rt_sigprocmask
            | libc::SYS_sigaltstack
            | libc::SYS_rt_sigsuspend
            | libc::SYS_alarm
            // Random/info: write to guest buffer, no shared state
            | libc::SYS_getrandom
            | libc::SYS_sched_getaffinity
            | libc::SYS_prlimit64
            | libc::SYS_uname
            | libc::SYS_sysinfo
            | libc::SYS_getrlimit
            | libc::SYS_mincore
            // Process wait: must run in micro's PID namespace
            | libc::SYS_wait4
            // Pipe creation: real OS pipes, no shim state
            | libc::SYS_pipe2
            // Filesystem sync: no arguments
            | libc::SYS_sync
    )
}

/// Main syscall handler called from the assembly trampoline.
///
/// # Safety
///
/// - `args` must point to a valid `SyscallArgs` struct on the stack.
/// - GS-based TLS must have been initialized for the current thread.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation)] // nr is a syscall number, always fits in u32
pub unsafe extern "C" fn micro_handle_syscall(args: *const SyscallArgs) -> i64 {
    let args = unsafe { &*args };
    let tls = unsafe { crate::tls::current_tls() };

    // Execve: special handling — serialize args and manage the exec protocol.
    #[allow(clippy::cast_possible_truncation)]
    if args.nr as u32 == libc::SYS_execve as u32 {
        return unsafe { crate::execve::handle_execve(tls, args) };
    }

    // Micro-local fast-path: syscalls that central always stamps EXEC_LOCAL
    // with zero work. Execute directly without any ring-buffer round-trip.
    #[allow(clippy::cast_possible_truncation)]
    let nr = args.nr as u32;
    if is_micro_local(nr) {
        return unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
    }

    // brk fast-path: post-execve, brk is entirely managed by micro's
    // guest_brk watermark. Central does zero work for brk.
    if nr == libc::SYS_brk as u32 {
        let state = unsafe { crate::state::global_micro_state() };
        let current = state.guest_brk.load(core::sync::atomic::Ordering::Acquire);
        if current != 0 {
            return unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
        }
        // Pre-execve: fall through to central round-trip.
    }

    let cq = unsafe {
        submit_and_wait(
            tls,
            args.nr as u32,
            &args.args,
            litebox_ipc::ring::sq_flags::NEED_AUTH,
        )
    };

    if cq.flags & cq_flags::EXEC_LOCAL != 0 {
        // For SYS_exit: deregister thread before it dies
        #[allow(clippy::cast_possible_truncation)]
        if args.nr as u32 == libc::SYS_exit as u32 {
            let dereg_args = [unsafe { (*tls).thread_slot }, 0, 0, 0, 0, 0];
            unsafe {
                submit_and_wait(
                    tls,
                    litebox_ipc::messages::MSG_THREAD_DEREGISTER,
                    &dereg_args,
                    0,
                );
            }
        }

        let micro = unsafe { &*(*tls).micro };
        let result = unsafe {
            execute_locally(
                args.nr as u32,
                &args.args,
                &cq,
                micro.ring_base,
                &micro.layout,
                micro.syscall_entry_point,
            )
        };

        // After a fork, the child has remapped to a new ring and already sent
        // MSG_CHILD_READY.  Sending report_local_result on the child's ring
        // would confuse central, so skip it.
        #[allow(clippy::cast_possible_truncation)]
        let is_fork_child = result == 0
            && (args.nr as u32 == libc::SYS_fork as u32
                || args.nr as u32 == libc::SYS_vfork as u32
                || (args.nr as u32 == libc::SYS_clone as u32 && args.args[0] & 0x100 == 0)); // no CLONE_VM → fork
        if !is_fork_child {
            unsafe { report_local_result(tls, cq.seq, result) };
        }

        result
    } else {
        cq.result
    }
}
