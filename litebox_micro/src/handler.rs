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
        libc::syscall(
            libc::SYS_futex,
            core::ptr::from_ref(addr) as usize,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            core::ptr::null::<libc::timespec>(),
        );
    }
}

fn futex_wake(addr: &core::sync::atomic::AtomicU32) {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            core::ptr::from_ref(addr) as usize,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            1i32,
        );
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

    let slot_idx = unsafe { sq_acquire_slot(header) };
    let entry = unsafe { &mut *sq_entries.add(slot_idx as usize) };

    entry.seq = seq;
    entry.syscall_nr = syscall_nr;
    entry.thread_slot = unsafe { (*tls).thread_slot as u16 };
    entry.flags = flags;
    entry.args = *args;
    entry.data_offset = 0;
    entry.data_len = 0;

    sq_publish(entry);
    futex_wake(&header.sq_notify);

    let thread_slot = unsafe { (*tls).thread_slot as u16 };
    let notify_slot = &header.cq_notify_slots[thread_slot as usize];
    let mut search_start = cq_tail(header);

    loop {
        if let Some(cq) = unsafe { cq_find_by_seq(header, cq_entries, search_start, seq) } {
            return cq;
        }
        let current = notify_slot.load(Acquire);
        if let Some(cq) = unsafe { cq_find_by_seq(header, cq_entries, search_start, seq) } {
            return cq;
        }
        spin_then_wait(notify_slot, current, futex_wait);
        search_start = cq_tail(header);
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

    let cq = unsafe {
        submit_and_wait(
            tls,
            args.nr as u32,
            &args.args,
            litebox_ipc::ring::sq_flags::NEED_AUTH,
        )
    };

    if cq.flags & cq_flags::EXEC_LOCAL != 0 {
        let result = unsafe { execute_locally(args.nr as u32, &args.args, &cq) };
        unsafe { report_local_result(tls, cq.seq, result) };
        result
    } else {
        cq.result
    }
}
