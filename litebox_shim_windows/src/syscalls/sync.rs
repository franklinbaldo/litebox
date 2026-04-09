// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT synchronization syscall handlers.
//!
//! Implements keyed events, events, semaphores, and wait operations.
//!
//! **Deadlock avoidance**: Blocking wait handlers (`wait_for_keyed_event`,
//! `release_keyed_event`, `wait_single`, `nt_wait_for_multiple_objects`)
//! accept pre-looked-up `Arc<T>` objects. The dispatch code in `lib.rs`
//! locks the handle table briefly to clone the `Arc`, then drops the lock
//! before calling the handler. This ensures the handle table mutex is never
//! held while a thread spins on a poll loop.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::time::Duration;

use litebox::event::wait::WaitContext;
use litebox::mm::linux::{NonZeroAddress, NonZeroPageSize};
use litebox::mm::PageManager;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox_platform_multiplex::Platform;

use crate::handle_table::{
    EventObject, HandleTable, IoCompletionEntry, IoCompletionObject, KeyedEventObject,
    MutantObject, NtObject, ProcessObject, SemaphoreObject, ThreadObject, Timer2Object,
};
use litebox_common_windows::ntstatus::NtStatus;

use super::NtSyscallArgs;

// ---------------------------------------------------------------------------
// NtCreateKeyedEvent
// ---------------------------------------------------------------------------

/// NtCreateKeyedEvent(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG)
///
/// Creates a keyed event object. Returns the handle in *arg0.
pub(crate) fn nt_create_keyed_event<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_va = args.arg0;
    // arg1 = desired_access (ignored)
    // arg2 = object_attributes (ignored)
    // arg3 = flags (ignored)

    let obj = NtObject::KeyedEvent(Arc::new(KeyedEventObject::new()));
    let handle = handles.insert(obj);

    if handle_out_va == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    if !crate::try_write_guest_value_unaligned::<u32>(handle_out_va, handle) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Lookup helpers — lock handle table briefly, clone Arc, drop lock.
// ---------------------------------------------------------------------------

/// Look up a keyed event object by handle. Returns the Arc if found.
pub(crate) fn lookup_keyed_event<FS: crate::NtShimFS>(
    handles: &HandleTable<FS>,
    handle: u32,
) -> Option<Arc<KeyedEventObject>> {
    handles
        .with(handle, |entry| match &entry.object {
            NtObject::KeyedEvent(k) => Some(Arc::clone(k)),
            _ => None,
        })
        .flatten()
}

/// Create an I/O completion port and return its handle.
pub(crate) fn nt_create_io_completion<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_va = args.arg0;
    let handle = handles.insert(NtObject::IoCompletion(Arc::new(IoCompletionObject::new())));
    if handle_out_va == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    if !crate::try_write_guest_value_unaligned::<usize>(handle_out_va, handle as usize) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    NtStatus::STATUS_SUCCESS
}

/// Look up an I/O completion port by handle.
pub(crate) fn lookup_io_completion<FS: crate::NtShimFS>(
    handles: &HandleTable<FS>,
    handle: u32,
) -> Option<Arc<IoCompletionObject>> {
    handles
        .with(handle, |entry| match &entry.object {
            NtObject::IoCompletion(port) => Some(Arc::clone(port)),
            _ => None,
        })
        .flatten()
}

/// Queue a completion packet via NtSetIoCompletion.
pub(crate) fn nt_set_io_completion<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let Some(port) = lookup_io_completion(handles, args.arg0 as u32) else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };
    let io_status = NtStatus::from_raw(args.arg3 as u32);
    let information = NtSyscallArgs::arg4(ctx);
    port.push(IoCompletionEntry {
        key_context: args.arg1,
        apc_context: args.arg2,
        status: io_status,
        information,
    });
    NtStatus::STATUS_SUCCESS
}

/// Queue a completion packet via NtSetIoCompletionEx.
pub(crate) fn nt_set_io_completion_ex<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let Some(port) = lookup_io_completion(handles, args.arg0 as u32) else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };
    let io_status = NtStatus::from_raw(NtSyscallArgs::arg4(ctx) as u32);
    let information = NtSyscallArgs::arg5(ctx);
    port.push(IoCompletionEntry {
        key_context: args.arg2,
        apc_context: args.arg3,
        status: io_status,
        information,
    });
    NtStatus::STATUS_SUCCESS
}

/// Public wrapper for wait_for_io_completion_packets, for use by
/// NtWaitForWorkViaWorkerFactory in the main shim dispatch.
pub(crate) fn wait_for_io_completion_packets_pub(
    port: &Arc<IoCompletionObject>,
    count: usize,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
    alert_thread: Option<&Arc<ThreadObject>>,
    timer2_list: &spin::Mutex<alloc::vec::Vec<Arc<Timer2Object>>>,
) -> Result<Vec<IoCompletionEntry>, NtStatus> {
    wait_for_io_completion_packets(port, count, timeout, wait_cx, alert_thread, timer2_list)
}

/// Public wrapper for write_file_io_completion_information, for use by
/// NtWaitForWorkViaWorkerFactory in the main shim dispatch.
pub(crate) fn write_file_io_completion_information_pub(ptr: usize, entry: IoCompletionEntry) {
    write_file_io_completion_information(ptr, entry);
}

/// Check all Timer2 objects in the global list, fire any that have expired,
/// and return the duration until the next expiry (if any armed timers remain).
///
/// When a timer fires:
/// - Its IOCP waiter (if registered) receives a completion entry.
/// - One-shot timers are disarmed; periodic timers are re-armed to the next period.
fn fire_expired_timers(
    timer2_list: &spin::Mutex<alloc::vec::Vec<Arc<Timer2Object>>>,
) -> Option<Duration> {
    let now = super::sysinfo::windows_filetime_now_pub();
    let list = timer2_list.lock();
    let mut nearest: Option<i64> = None;
    for timer in list.iter() {
        let mut armed = timer.armed.lock();
        if let Some(ref mut a) = *armed {
            if now >= a.due_time {
                // Timer has expired — fire it.
                let waiter = timer.iocp_waiter.lock().take();
                if let Some((iocp, entry)) = waiter {
                    iocp.push(entry);
                }
                if a.period > 0 {
                    // Periodic: re-arm for the next period.
                    a.due_time = now.saturating_add(a.period);
                    // Track this new due time.
                    match nearest {
                        Some(n) if a.due_time < n => nearest = Some(a.due_time),
                        None => nearest = Some(a.due_time),
                        _ => {}
                    }
                } else {
                    // One-shot: disarm.
                    *armed = None;
                }
            } else {
                // Not yet expired — track nearest future expiry.
                match nearest {
                    Some(n) if a.due_time < n => nearest = Some(a.due_time),
                    None => nearest = Some(a.due_time),
                    _ => {}
                }
            }
        }
    }
    // Convert absolute FILETIME to duration from now.
    nearest.and_then(|abs| {
        let diff_100ns = abs.saturating_sub(now);
        if diff_100ns <= 0 {
            // Already expired — will be caught next iteration.
            Some(Duration::from_millis(1))
        } else {
            Some(Duration::from_nanos(diff_100ns as u64 * 100))
        }
    })
}

fn wait_for_io_completion_packets(
    port: &Arc<IoCompletionObject>,
    count: usize,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
    alert_thread: Option<&Arc<ThreadObject>>,
    timer2_list: &spin::Mutex<alloc::vec::Vec<Arc<Timer2Object>>>,
) -> Result<Vec<IoCompletionEntry>, NtStatus> {
    let drained = RefCell::new(None::<Vec<IoCompletionEntry>>);
    port.waiters.lock().push(wait_cx.waker().clone());
    register_alertable_waiter(alert_thread, wait_cx);

    // Fire any already-expired timers before entering the wait.
    let timer_due = fire_expired_timers(timer2_list);

    // Clamp the timeout to the nearest timer expiry so we wake up in time.
    let effective_timeout = match (timeout, timer_due) {
        (Some(t), Some(d)) => Some(core::cmp::min(t, d)),
        (Some(t), None) => Some(t),
        (None, Some(d)) => Some(d),
        (None, None) => None,
    };

    let cx = wait_cx.with_timeout(effective_timeout);
    let alerted = Cell::new(AlertOrApc::None);
    let result = cx.wait_until(|| {
        // Fire expired timers on each wake-up so IOCP entries get posted.
        fire_expired_timers(timer2_list);

        let aoa = take_pending_alert_or_user_apc(alert_thread);
        if aoa.is_wake() {
            alerted.set(aoa);
            return true;
        }
        let mut queue = port.queue.lock();
        if queue.is_empty() {
            return false;
        }

        let mut entries = Vec::with_capacity(core::cmp::min(count, queue.len()));
        for _ in 0..count {
            let Some(entry) = queue.pop_front() else {
                break;
            };
            entries.push(entry);
        }
        *drained.borrow_mut() = Some(entries);
        true
    });

    port.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));
    unregister_alertable_waiter(alert_thread, wait_cx);

    match result {
        Ok(()) => {
            if alerted.get().is_wake() {
                Err(alerted.get().to_status())
            } else {
                Ok(drained.into_inner().unwrap_or_default())
            }
        }
        Err(_) => {
            // Timeout — but check if any timers fired while we were exiting.
            // Fire them so the next wait iteration picks them up.
            fire_expired_timers(timer2_list);

            // Check if any entries were posted to the queue while we exited.
            let mut queue = port.queue.lock();
            if !queue.is_empty() {
                let mut entries = Vec::with_capacity(core::cmp::min(count, queue.len()));
                for _ in 0..count {
                    let Some(entry) = queue.pop_front() else {
                        break;
                    };
                    entries.push(entry);
                }
                return Ok(entries);
            }
            drop(queue);

            Err(NtStatus::STATUS_TIMEOUT)
        }
    }
}

#[repr(C)]
struct RawIoStatusBlock {
    status_or_pointer: usize,
    information: usize,
}

#[repr(C)]
struct RawFileIoCompletionInformation {
    key_context: usize,
    apc_context: usize,
    io_status_block: RawIoStatusBlock,
}

fn write_io_status_block(ptr: usize, entry: IoCompletionEntry) {
    if crate::is_addr_range_writable(ptr, core::mem::size_of::<RawIoStatusBlock>()) {
        unsafe {
            core::ptr::write_unaligned(
                ptr as *mut RawIoStatusBlock,
                RawIoStatusBlock {
                    status_or_pointer: entry.status.raw() as usize,
                    information: entry.information,
                },
            );
        }
    }
}

fn write_file_io_completion_information(ptr: usize, entry: IoCompletionEntry) {
    if crate::is_addr_range_writable(ptr, core::mem::size_of::<RawFileIoCompletionInformation>()) {
        unsafe {
            core::ptr::write_unaligned(
                ptr as *mut RawFileIoCompletionInformation,
                RawFileIoCompletionInformation {
                    key_context: entry.key_context,
                    apc_context: entry.apc_context,
                    io_status_block: RawIoStatusBlock {
                        status_or_pointer: entry.status.raw() as usize,
                        information: entry.information,
                    },
                },
            );
        }
    }
}

fn validate_writable_output_buffer(
    pm: &PageManager<Platform, { crate::PAGE_SIZE }>,
    ptr: usize,
    len: usize,
) -> bool {
    if ptr == 0 || len == 0 {
        return false;
    }
    let Some(end) = ptr.checked_add(len) else {
        return false;
    };
    let aligned_base = ptr & !(crate::PAGE_SIZE - 1);
    let aligned_size = (end - aligned_base + crate::PAGE_SIZE - 1) & !(crate::PAGE_SIZE - 1);
    let (Some(addr), Some(size)) = (
        NonZeroAddress::<{ crate::PAGE_SIZE }>::new(aligned_base),
        NonZeroPageSize::<{ crate::PAGE_SIZE }>::new(aligned_size),
    ) else {
        return false;
    };
    pm.get_memory_permissions(addr, size)
        .is_some_and(|perms| perms.contains(MemoryRegionPermissions::WRITE))
}

/// Remove one completion packet via NtRemoveIoCompletion.
pub(crate) fn nt_remove_io_completion(
    ctx: &mut super::super::ExecutionContext,
    port: &Arc<IoCompletionObject>,
    pm: &PageManager<Platform, { crate::PAGE_SIZE }>,
    wait_cx: &WaitContext<'_, Platform>,
    timer2_list: &spin::Mutex<alloc::vec::Vec<Arc<Timer2Object>>>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    if args.arg1 != 0
        && !validate_writable_output_buffer(pm, args.arg1, core::mem::size_of::<usize>())
    {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    if args.arg2 != 0
        && !validate_writable_output_buffer(pm, args.arg2, core::mem::size_of::<usize>())
    {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    if args.arg3 != 0
        && !validate_writable_output_buffer(pm, args.arg3, core::mem::size_of::<RawIoStatusBlock>())
    {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let timeout = match read_timeout(NtSyscallArgs::arg4(ctx)) {
        Ok(timeout) => timeout,
        Err(status) => return status,
    };
    let Ok(mut entries) =
        wait_for_io_completion_packets(port, 1, timeout, wait_cx, None, timer2_list)
    else {
        return NtStatus::STATUS_TIMEOUT;
    };
    let Some(entry) = entries.pop() else {
        return NtStatus::STATUS_TIMEOUT;
    };

    if args.arg1 != 0 {
        unsafe {
            core::ptr::write_unaligned(args.arg1 as *mut usize, entry.key_context);
        }
    }
    if args.arg2 != 0 {
        unsafe {
            core::ptr::write_unaligned(args.arg2 as *mut usize, entry.apc_context);
        }
    }
    if args.arg3 != 0 {
        write_io_status_block(args.arg3, entry);
    }
    NtStatus::STATUS_SUCCESS
}

/// Remove up to `Count` completion packets via NtRemoveIoCompletionEx.
pub(crate) fn nt_remove_io_completion_ex(
    ctx: &mut super::super::ExecutionContext,
    port: &Arc<IoCompletionObject>,
    pm: &PageManager<Platform, { crate::PAGE_SIZE }>,
    wait_cx: &WaitContext<'_, Platform>,
    current_thread: Option<&Arc<ThreadObject>>,
    timer2_list: &spin::Mutex<alloc::vec::Vec<Arc<Timer2Object>>>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let count = args.arg2;
    let removed_count_writable = args.arg3 == 0
        || validate_writable_output_buffer(pm, args.arg3, core::mem::size_of::<u32>());
    if count == 0 {
        if !removed_count_writable {
            return NtStatus::STATUS_ACCESS_VIOLATION;
        }
        if args.arg3 != 0 {
            unsafe {
                core::ptr::write_unaligned(args.arg3 as *mut u32, 0);
            }
        }
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let entry_size = core::mem::size_of::<RawFileIoCompletionInformation>();
    let Some(output_len) = count.checked_mul(entry_size) else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };
    if !validate_writable_output_buffer(pm, args.arg1, output_len) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    if !removed_count_writable {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let timeout = match read_timeout(NtSyscallArgs::arg4(ctx)) {
        Ok(timeout) => timeout,
        Err(status) => return status,
    };
    let alert_thread = if NtSyscallArgs::arg5(ctx) != 0 {
        current_thread
    } else {
        None
    };
    let entries = match wait_for_io_completion_packets(
        port,
        count,
        timeout,
        wait_cx,
        alert_thread,
        timer2_list,
    ) {
        Ok(entries) => entries,
        Err(status) => {
            if args.arg3 != 0 {
                unsafe {
                    core::ptr::write_unaligned(args.arg3 as *mut u32, 0);
                }
            }
            return status;
        }
    };

    for (index, entry) in entries.iter().copied().enumerate() {
        let Some(slot_offset) = index.checked_mul(entry_size) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        let Some(slot_ptr) = args.arg1.checked_add(slot_offset) else {
            return NtStatus::STATUS_ACCESS_VIOLATION;
        };
        write_file_io_completion_information(slot_ptr, entry);
    }
    if args.arg3 != 0 {
        unsafe {
            core::ptr::write_unaligned(args.arg3 as *mut u32, entries.len() as u32);
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// A waitable object (event, semaphore, or thread) extracted from the handle table.
pub(crate) enum Waitable {
    Event(Arc<EventObject>),
    Semaphore(Arc<SemaphoreObject>),
    Mutant(Arc<MutantObject>),
    Thread(Arc<ThreadObject>),
    Process(Arc<ProcessObject>),
}

/// Look up a waitable object by handle. Returns the typed Arc if found.
pub(crate) fn lookup_waitable<FS: crate::NtShimFS>(
    handles: &HandleTable<FS>,
    handle: u32,
) -> Option<Waitable> {
    handles
        .with(handle, |entry| match &entry.object {
            NtObject::Event(e) => Some(Waitable::Event(Arc::clone(e))),
            NtObject::Semaphore(s) => Some(Waitable::Semaphore(Arc::clone(s))),
            NtObject::Mutant(m) => Some(Waitable::Mutant(Arc::clone(m))),
            NtObject::Thread(t) => Some(Waitable::Thread(Arc::clone(t))),
            NtObject::Process { state } => Some(Waitable::Process(Arc::clone(state))),
            NtObject::VirtualThread { process } => Some(Waitable::Process(Arc::clone(process))),
            _ => None,
        })
        .flatten()
}

/// Get the raw pointer address of a waitable object for deduplication/sorting.
fn waitable_addr(w: &Waitable) -> usize {
    match w {
        Waitable::Event(e) => Arc::as_ptr(e) as usize,
        Waitable::Semaphore(s) => Arc::as_ptr(s) as usize,
        Waitable::Mutant(m) => Arc::as_ptr(m) as usize,
        Waitable::Thread(t) => Arc::as_ptr(t) as usize,
        Waitable::Process(p) => Arc::as_ptr(p) as usize,
    }
}

use crate::handle_table::ReleaseToken;

/// Register a waker on a waitable object so signal paths can wake this thread.
fn register_waker(w: &Waitable, waker: &litebox::event::wait::Waker<Platform>) {
    match w {
        Waitable::Event(e) => e.waiters.lock().push(waker.clone()),
        Waitable::Semaphore(s) => s.waiters.lock().push(waker.clone()),
        Waitable::Mutant(m) => m.waiters.lock().push(waker.clone()),
        Waitable::Thread(t) => t.waiters.lock().push(waker.clone()),
        Waitable::Process(p) => p.waiters.lock().push(waker.clone()),
    }
}

/// Unregister a waker from a waitable object.
fn unregister_waker(w: &Waitable, waker: &litebox::event::wait::Waker<Platform>) {
    match w {
        Waitable::Event(e) => e.waiters.lock().retain(|w| !w.ptr_eq(waker)),
        Waitable::Semaphore(s) => s.waiters.lock().retain(|w| !w.ptr_eq(waker)),
        Waitable::Mutant(m) => m.waiters.lock().retain(|w| !w.ptr_eq(waker)),
        Waitable::Thread(t) => t.waiters.lock().retain(|w| !w.ptr_eq(waker)),
        Waitable::Process(p) => p.waiters.lock().retain(|w| !w.ptr_eq(waker)),
    }
}

// ---------------------------------------------------------------------------
// NtWaitForKeyedEvent (blocking — handle table lock NOT held)
// ---------------------------------------------------------------------------

/// NtWaitForKeyedEvent(IN HANDLE, IN PVOID Key, IN BOOLEAN Alertable, IN PLARGE_INTEGER Timeout)
///
/// Blocks until another thread calls NtReleaseKeyedEvent with the same key.
/// Each wait/release pair is matched 1:1 via per-releaser tokens.
/// The keyed event Arc must be looked up before calling this.
pub(crate) fn wait_for_keyed_event(
    ctx: &mut super::super::ExecutionContext,
    keyed: &Arc<KeyedEventObject>,
    wait_cx: &WaitContext<'_, Platform>,
    current_thread: Option<&Arc<ThreadObject>>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let key = args.arg1;
    let _tid = current_thread.map_or(0, |t| t.thread_id);
    let alert_thread = if args.arg2 != 0 { current_thread } else { None };
    let timeout_ptr = args.arg3;
    let timeout = match read_timeout(timeout_ptr) {
        Ok(timeout) => timeout,
        Err(status) => return status,
    };

    let mut state = keyed.state.lock();
    let q = state.entry(key).or_default();

    // If a pending release token exists AND no older waiters are queued,
    // pop and consume the front token so that specific releaser can wake up.
    if q.waiter_ids.is_empty() {
        if let Some(token) = q.pending_releases.front_mut() {
            token.consumed = true;
            let _ = q.pending_releases.pop_front();
            if q.is_empty() {
                state.remove(&key);
            }
            drop(state);
            // Wake releasers so they can see their token was consumed.
            keyed.wake_waiters();
            return NtStatus::STATUS_SUCCESS;
        }
    }

    // No release available — register as a waiter and spin-poll.
    let my_id = keyed.alloc_release_id(); // reuse the ID allocator for waiter IDs
    q.waiter_ids.push_back(my_id);
    drop(state);

    keyed.waiters.lock().push(wait_cx.waker().clone());
    register_alertable_waiter(alert_thread, wait_cx);

    let cx = wait_cx.with_timeout(timeout);
    let alerted = Cell::new(AlertOrApc::None);
    let result = cx.wait_until(|| {
        let aoa = take_pending_alert_or_user_apc(alert_thread);
        if aoa.is_wake() {
            alerted.set(aoa);
            return true;
        }
        let mut state = keyed.state.lock();
        if let Some(q) = state.get_mut(&key) {
            // Check if our specific ID has been marked ready by a releaser.
            if q.ready_ids.remove(&my_id) {
                q.waiter_ids.retain(|&id| id != my_id);
                if q.is_empty() {
                    state.remove(&key);
                }
                return true;
            }
            // Check for a pending release token (releaser arrived after us).
            if let Some(token) = q.pending_releases.front_mut() {
                // Only the oldest waiter can consume a pending release.
                if q.waiter_ids.front() == Some(&my_id) {
                    token.consumed = true;
                    let _ = q.pending_releases.pop_front();
                    q.waiter_ids.pop_front();
                    if q.is_empty() {
                        state.remove(&key);
                    }
                    return true;
                }
            }
            false
        } else {
            // Queue was removed — our waiter entry was already cleaned up
            // by the releaser that matched us. Treat as success.
            true
        }
    });

    keyed.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));
    unregister_alertable_waiter(alert_thread, wait_cx);

    match result {
        Ok(()) => {
            if alerted.get().is_wake() {
                let mut state = keyed.state.lock();
                let mut need_wake = false;
                if let Some(q) = state.get_mut(&key) {
                    let was_front = q.waiter_ids.front() == Some(&my_id);
                    q.waiter_ids.retain(|&id| id != my_id);
                    if q.ready_ids.remove(&my_id) {
                        let next = q
                            .waiter_ids
                            .iter()
                            .find(|id| !q.ready_ids.contains(id))
                            .copied();
                        if let Some(next_id) = next {
                            q.ready_ids.insert(next_id);
                            need_wake = true;
                        } else {
                            q.pending_releases.push_front(ReleaseToken {
                                id: keyed.alloc_release_id(),
                                consumed: false,
                            });
                        }
                    } else if was_front && !q.pending_releases.is_empty() {
                        // We were blocking the front with no ready token, but
                        // a pending release exists. Transfer it to the new
                        // front waiter so the releaser can complete.
                        if let Some(next_id) = q.waiter_ids.front().copied() {
                            let _ = q.pending_releases.pop_front();
                            q.ready_ids.insert(next_id);
                            need_wake = true;
                        }
                    }
                    if q.is_empty() {
                        state.remove(&key);
                    }
                }
                drop(state);
                if need_wake {
                    keyed.wake_waiters();
                }
                alerted.get().to_status()
            } else {
                keyed.wake_waiters();
                NtStatus::STATUS_SUCCESS
            }
        }
        Err(litebox::event::wait::WaitError::TimedOut)
        | Err(litebox::event::wait::WaitError::Interrupted) => {
            let mut state = keyed.state.lock();
            let mut need_wake = false;
            if let Some(q) = state.get_mut(&key) {
                let was_front = q.waiter_ids.front() == Some(&my_id);
                q.waiter_ids.retain(|&id| id != my_id);
                if q.ready_ids.remove(&my_id) {
                    let next = q
                        .waiter_ids
                        .iter()
                        .find(|id| !q.ready_ids.contains(id))
                        .copied();
                    if let Some(next_id) = next {
                        q.ready_ids.insert(next_id);
                        need_wake = true;
                    } else {
                        q.pending_releases.push_front(ReleaseToken {
                            id: keyed.alloc_release_id(),
                            consumed: false,
                        });
                    }
                } else if was_front && !q.pending_releases.is_empty() {
                    // Transfer the front pending release to the new front
                    // waiter so the releaser can complete.
                    if let Some(next_id) = q.waiter_ids.front().copied() {
                        let _ = q.pending_releases.pop_front();
                        q.ready_ids.insert(next_id);
                        need_wake = true;
                    }
                }
                if q.is_empty() {
                    state.remove(&key);
                }
            }
            drop(state);
            if need_wake {
                keyed.wake_waiters();
            }
            NtStatus::STATUS_TIMEOUT
        }
    }
}

// ---------------------------------------------------------------------------
// NtReleaseKeyedEvent (blocking — handle table lock NOT held)
// ---------------------------------------------------------------------------

/// NtReleaseKeyedEvent(IN HANDLE, IN PVOID Key, IN BOOLEAN Alertable, IN PLARGE_INTEGER Timeout)
///
/// Wakes one thread waiting on the given key via NtWaitForKeyedEvent.
/// Each release is matched to exactly one waiter via per-releaser tokens.
/// The keyed event Arc must be looked up before calling this.
pub(crate) fn release_keyed_event(
    ctx: &mut super::super::ExecutionContext,
    keyed: &Arc<KeyedEventObject>,
    wait_cx: &WaitContext<'_, Platform>,
    current_thread: Option<&Arc<ThreadObject>>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let key = args.arg1;
    let _tid = current_thread.map_or(0, |t| t.thread_id);
    let alert_thread = if args.arg2 != 0 { current_thread } else { None };
    let timeout_ptr = args.arg3;

    let timeout = match read_timeout(timeout_ptr) {
        Ok(timeout) => timeout,
        Err(status) => return status,
    };

    let mut state = keyed.state.lock();
    let q = state.entry(key).or_default();

    // Find the oldest waiter that doesn't already have a ready token.
    let unserved = q
        .waiter_ids
        .iter()
        .find(|id| !q.ready_ids.contains(id))
        .copied();
    if let Some(target_id) = unserved {
        q.ready_ids.insert(target_id);
        drop(state);
        keyed.wake_waiters();
        return NtStatus::STATUS_SUCCESS;
    }

    // No waiter yet — push a per-releaser token and spin-poll until consumed.
    let my_id = keyed.alloc_release_id();
    q.pending_releases.push_back(ReleaseToken {
        id: my_id,
        consumed: false,
    });
    drop(state);

    keyed.waiters.lock().push(wait_cx.waker().clone());
    register_alertable_waiter(alert_thread, wait_cx);

    let cx = wait_cx.with_timeout(timeout);
    let alerted = Cell::new(AlertOrApc::None);
    let result = cx.wait_until(|| {
        let aoa = take_pending_alert_or_user_apc(alert_thread);
        if aoa.is_wake() {
            alerted.set(aoa);
            return true;
        }
        let state = keyed.state.lock();
        if let Some(q) = state.get(&key) {
            !q.pending_releases.iter().any(|t| t.id == my_id)
        } else {
            true
        }
    });

    keyed.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));
    unregister_alertable_waiter(alert_thread, wait_cx);

    match result {
        Ok(()) => {
            if alerted.get().is_wake() {
                let mut state = keyed.state.lock();
                if let Some(q) = state.get_mut(&key) {
                    q.pending_releases.retain(|t| t.id != my_id);
                    if q.is_empty() {
                        state.remove(&key);
                    }
                }
                alerted.get().to_status()
            } else {
                NtStatus::STATUS_SUCCESS
            }
        }
        Err(litebox::event::wait::WaitError::TimedOut)
        | Err(litebox::event::wait::WaitError::Interrupted) => {
            let mut state = keyed.state.lock();
            if let Some(q) = state.get_mut(&key) {
                q.pending_releases.retain(|t| t.id != my_id);
                if q.is_empty() {
                    state.remove(&key);
                }
            }
            NtStatus::STATUS_TIMEOUT
        }
    }
}

// ---------------------------------------------------------------------------
// NtCreateEvent
// ---------------------------------------------------------------------------

/// NtCreateEvent(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES,
///               IN EVENT_TYPE, IN BOOLEAN InitialState)
pub(crate) fn nt_create_event<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_va = args.arg0;
    // arg1 = desired_access (ignored)
    // arg2 = object_attributes (ignored)
    let event_type = args.arg3; // 0 = NotificationEvent (manual), 1 = SynchronizationEvent (auto)
    if event_type > 1 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }
    // InitialState is at [rsp+0x28] in the caller's frame. Read from guest stack.
    let initial_state =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x28).unwrap_or(0) != 0;

    let manual_reset = event_type == 0; // NotificationEvent = manual-reset
    let obj = NtObject::Event(Arc::new(EventObject::new(manual_reset, initial_state)));
    let handle = handles.insert(obj);

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtCreateEvent(handle=0x{handle:X}, event_type={event_type}, manual_reset={manual_reset}, initial_state={initial_state}) -> STATUS_SUCCESS\n"
        ));
    }

    if handle_out_va == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    if !crate::try_write_guest_value_unaligned::<u32>(handle_out_va, handle) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// NtSetEvent
// ---------------------------------------------------------------------------

/// NtSetEvent(IN HANDLE, OUT PLONG PreviousState OPTIONAL)
pub(crate) fn nt_set_event<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    let prev_state_va = args.arg1;

    let event = match handles.with(handle, |entry| match &entry.object {
        NtObject::Event(e) => Some(Arc::clone(e)),
        _ => None,
    }) {
        Some(Some(e)) => e,
        _ => return NtStatus::STATUS_INVALID_HANDLE,
    };

    let mut signaled = event.state.lock();
    let prev = *signaled as i32;
    *signaled = true;
    drop(signaled);
    // Wake all blocked waiters so they re-evaluate.
    event.wake_waiters();

    if prev_state_va != 0 {
        let _ = crate::try_write_guest_value_unaligned::<i32>(prev_state_va, prev);
    }

    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// NtResetEvent / NtClearEvent
// ---------------------------------------------------------------------------

/// NtResetEvent(IN HANDLE, OUT PLONG PreviousState OPTIONAL)
pub(crate) fn nt_reset_event<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    let prev_state_va = args.arg1;

    let event = match handles.with(handle, |entry| match &entry.object {
        NtObject::Event(e) => Some(Arc::clone(e)),
        _ => None,
    }) {
        Some(Some(e)) => e,
        _ => return NtStatus::STATUS_INVALID_HANDLE,
    };

    let mut signaled = event.state.lock();
    let prev = *signaled as i32;
    *signaled = false;

    if prev_state_va != 0 {
        let _ = crate::try_write_guest_value_unaligned::<i32>(prev_state_va, prev);
    }

    NtStatus::STATUS_SUCCESS
}

/// NtClearEvent(IN HANDLE) — same as NtResetEvent without previous state output.
pub(crate) fn nt_clear_event<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;

    let event = match handles.with(handle, |entry| match &entry.object {
        NtObject::Event(e) => Some(Arc::clone(e)),
        _ => None,
    }) {
        Some(Some(e)) => e,
        _ => return NtStatus::STATUS_INVALID_HANDLE,
    };

    let mut signaled = event.state.lock();
    *signaled = false;

    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// NtCreateSemaphore / NtReleaseSemaphore
// ---------------------------------------------------------------------------

/// NtCreateSemaphore(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES,
///                   IN LONG InitialCount, IN LONG MaximumCount)
pub(crate) fn nt_create_semaphore<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_va = args.arg0;
    // arg1 = desired_access (ignored)
    // arg2 = object_attributes (ignored)
    let initial_count = args.arg3 as i32;
    // MaximumCount at [rsp+0x28]
    let max_count = crate::try_read_guest_value_unaligned::<i32>(ctx.regs.rsp + 0x28).unwrap_or(0);

    if initial_count < 0 || max_count <= 0 || initial_count > max_count {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let obj = NtObject::Semaphore(Arc::new(SemaphoreObject::new(initial_count, max_count)));
    let handle = handles.insert(obj);

    if handle_out_va == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    if !crate::try_write_guest_value_unaligned::<u32>(handle_out_va, handle) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    NtStatus::STATUS_SUCCESS
}

/// NtReleaseSemaphore(IN HANDLE, IN LONG ReleaseCount, OUT PLONG PreviousCount OPTIONAL)
pub(crate) fn nt_release_semaphore<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    let release_count = args.arg1 as i32;
    let prev_count_va = args.arg2;

    let sem = match handles.with(handle, |entry| match &entry.object {
        NtObject::Semaphore(s) => Some(Arc::clone(s)),
        _ => None,
    }) {
        Some(Some(s)) => s,
        _ => return NtStatus::STATUS_INVALID_HANDLE,
    };

    let mut count = sem.state.lock();
    let prev = *count;

    let new_count = match prev.checked_add(release_count) {
        Some(c) if release_count > 0 && c <= sem.max_count => c,
        _ => return NtStatus::STATUS_SEMAPHORE_LIMIT_EXCEEDED,
    };

    *count = new_count;
    drop(count);
    // Wake all blocked waiters so they re-evaluate.
    sem.wake_waiters();

    if prev_count_va != 0 {
        let _ = crate::try_write_guest_value_unaligned::<i32>(prev_count_va, prev);
    }

    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// NtWaitForSingleObject (blocking — handle table lock NOT held)
// ---------------------------------------------------------------------------

/// Wait on a pre-looked-up waitable object. The handle table lock is NOT held.
pub(crate) fn wait_single(
    ctx: &mut super::super::ExecutionContext,
    waitable: &Waitable,
    wait_cx: &WaitContext<'_, Platform>,
    current_thread_id: u32,
    current_thread: Option<&Arc<ThreadObject>>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let alert_thread = if args.arg1 != 0 { current_thread } else { None };
    let timeout_ptr = args.arg2;
    let timeout = match read_timeout(timeout_ptr) {
        Ok(timeout) => timeout,
        Err(status) => return status,
    };

    match waitable {
        Waitable::Event(e) => wait_event(e, timeout, wait_cx, alert_thread),
        Waitable::Semaphore(s) => wait_semaphore(s, timeout, wait_cx, alert_thread),
        Waitable::Mutant(m) => wait_mutant(m, timeout, wait_cx, current_thread_id, alert_thread),
        Waitable::Thread(t) => wait_thread(t, timeout, wait_cx, alert_thread),
        Waitable::Process(p) => wait_process(p, timeout, wait_cx, alert_thread),
    }
}

/// Wait for an event object with a timeout (for K32 WaitForSingleObject).
pub(crate) fn wait_event_with_timeout(
    event: &Arc<EventObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    wait_event(event, timeout, wait_cx, None)
}

/// Wait for a semaphore object with a timeout (for K32 WaitForSingleObject).
pub(crate) fn wait_semaphore_with_timeout(
    sem: &Arc<SemaphoreObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    wait_semaphore(sem, timeout, wait_cx, None)
}

/// Wait for a mutant object with a timeout (for K32 WaitForSingleObject).
pub(crate) fn wait_mutant_with_timeout(
    mutant: &Arc<MutantObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
    current_thread_id: u32,
) -> NtStatus {
    wait_mutant(mutant, timeout, wait_cx, current_thread_id, None)
}

/// Wait for a thread object with a timeout (for K32 WaitForSingleObject).
pub(crate) fn wait_thread_with_timeout(
    thread: &Arc<ThreadObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    wait_thread(thread, timeout, wait_cx, None)
}

/// NtWaitForAlertByThreadId(IN PVOID Address, IN PLARGE_INTEGER Timeout)
///
/// Blocks the current thread until another thread calls
/// NtAlertThreadByThreadId for this thread ID or
/// NtAlertThreadByThreadIdEx with a matching lock address. Plain alerts behave
/// like a per-thread wildcard wake, while Ex alerts are keyed by the supplied
/// address.
pub(crate) fn nt_wait_for_alert_by_thread_id<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    shared: &crate::NtSharedState<FS>,
    thread: &Arc<ThreadObject>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let address = args.arg0;
    thread.set_last_wait_alert_addr(address);
    let timeout = match read_timeout(args.arg1) {
        Ok(timeout) => timeout,
        Err(status) => return status,
    };

    if thread.take_pending_alert_by_id(address) {
        thread.note_wait_alert_pending(address);
        thread.note_wait_alert_consume(address);
        crate::push_recent_chain_event(
            &shared.recent_chain_events,
            alloc::format!("waitpend:{}@0x{:X}", thread.thread_id, address),
        );
        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtWaitForAlertByThreadId(tid={}, addr=0x{:X}) -> STATUS_ALERTED (pending)\n",
                thread.thread_id, address,
            ));
        }
        return NtStatus::STATUS_ALERTED;
    }

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtWaitForAlertByThreadId(tid={}, addr=0x{:X}, timeout={:?}) waiting\n",
            thread.thread_id,
            address,
            timeout,
        ));
    }

    thread
        .alert_by_id_waiters
        .lock()
        .push(wait_cx.waker().clone());
    thread.note_wait_alert_block(address);
    crate::push_recent_chain_event(
        &shared.recent_chain_events,
        alloc::format!("waitblk:{}@0x{:X}", thread.thread_id, address),
    );

    let cx = wait_cx.with_timeout(timeout);
    let result = cx.wait_until(|| {
        let signaled = thread.take_pending_alert_by_id(address);
        if signaled {
            thread.note_wait_alert_consume(address);
        }
        signaled
    });

    thread
        .alert_by_id_waiters
        .lock()
        .retain(|w| !w.ptr_eq(wait_cx.waker()));

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtWaitForAlertByThreadId(tid={}, addr=0x{:X}) -> {:?}\n",
            thread.thread_id,
            address,
            result,
        ));
    }

    thread.note_wait_alert_result(address, result.is_ok());
    crate::push_recent_chain_event(
        &shared.recent_chain_events,
        alloc::format!(
            "{}:{}@0x{:X}",
            if result.is_ok() { "waitok" } else { "waitto" },
            thread.thread_id,
            address
        ),
    );

    match result {
        Ok(()) => NtStatus::STATUS_ALERTED,
        Err(litebox::event::wait::WaitError::TimedOut)
        | Err(litebox::event::wait::WaitError::Interrupted) => NtStatus::STATUS_TIMEOUT,
    }
}

/// NtWaitForMultipleObjects(IN ULONG Count, IN PHANDLE Handles[],
///                          IN WAIT_TYPE WaitType, IN BOOLEAN Alertable,
///                          IN PLARGE_INTEGER Timeout)
///
/// Takes &Mutex<HandleTable> so it can lock/unlock between poll iterations.
/// Returns STATUS_WAIT_0 + index (for WaitAny) or STATUS_SUCCESS (for WaitAll).
pub(crate) fn nt_wait_for_multiple_objects<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles_mutex: &spin::Mutex<HandleTable<FS>>,
    wait_cx: &WaitContext<'_, Platform>,
    current_thread_id: u32,
    current_thread: Option<&Arc<ThreadObject>>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let count = args.arg0;
    let handles_va = args.arg1;
    let wait_type = args.arg2; // 0 = WaitAll, 1 = WaitAny
    let alert_thread = if args.arg3 != 0 { current_thread } else { None };
    let timeout_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);

    if count == 0 || count > 64 || wait_type > 1 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let timeout = match read_timeout(timeout_ptr) {
        Ok(timeout) => timeout,
        Err(status) => return status,
    };

    // Read handle array from guest memory. HANDLE is pointer-sized (8 bytes
    // on x64), so the array stride is `size_of::<usize>()`, not 4 bytes.
    let mut handle_array = alloc::vec::Vec::with_capacity(count);
    for index in 0..count {
        let Some(handle_addr) = handles_va.checked_add(index * core::mem::size_of::<usize>())
        else {
            return NtStatus::STATUS_ACCESS_VIOLATION;
        };
        let Some(handle_val) = crate::try_read_guest_value_unaligned::<usize>(handle_addr) else {
            return NtStatus::STATUS_ACCESS_VIOLATION;
        };
        handle_array.push(handle_val as u32);
    }

    if wait_type == 1 {
        // WaitAny: poll each handle, return first signaled.
        // Pre-extract Arc references and validate all handles upfront.
        let waitables: alloc::vec::Vec<Waitable> = {
            let handles = handles_mutex.lock();
            let mut v = alloc::vec::Vec::with_capacity(handle_array.len());
            for &h in &handle_array {
                let w = handles
                    .with(h, |entry| match &entry.object {
                        NtObject::Event(e) => Some(Waitable::Event(Arc::clone(e))),
                        NtObject::Semaphore(s) => Some(Waitable::Semaphore(Arc::clone(s))),
                        NtObject::Mutant(m) => Some(Waitable::Mutant(Arc::clone(m))),
                        NtObject::Thread(t) => Some(Waitable::Thread(Arc::clone(t))),
                        NtObject::Process { state } => Some(Waitable::Process(Arc::clone(state))),
                        NtObject::VirtualThread { process } => {
                            Some(Waitable::Process(Arc::clone(process)))
                        }
                        _ => None,
                    })
                    .flatten();
                match w {
                    Some(waitable) => v.push(waitable),
                    None => return NtStatus::STATUS_INVALID_HANDLE,
                }
            }
            v
        };

        // Register our waker on all waitable objects.
        for w in &waitables {
            register_waker(w, wait_cx.waker());
        }
        register_alertable_waiter(alert_thread, wait_cx);

        let cx = wait_cx.with_timeout(timeout);
        let mut result_status = NtStatus::STATUS_TIMEOUT;
        let wait_result = cx.wait_until(|| {
            let aoa = take_pending_alert_or_user_apc(alert_thread);
            if aoa.is_wake() {
                result_status = aoa.to_status();
                return true;
            }
            for (i, w) in waitables.iter().enumerate() {
                match w {
                    Waitable::Event(e) => {
                        let mut signaled = e.state.lock();
                        if *signaled {
                            if !e.manual_reset {
                                *signaled = false;
                            }
                            result_status = NtStatus(i as i32);
                            return true;
                        }
                    }
                    Waitable::Semaphore(s) => {
                        let mut count = s.state.lock();
                        if *count > 0 {
                            *count -= 1;
                            result_status = NtStatus(i as i32);
                            return true;
                        }
                    }
                    Waitable::Mutant(m) => {
                        let mut state = m.state.lock();
                        if state.owner_thread_id.is_none() {
                            let was_abandoned = state.abandoned;
                            state.owner_thread_id = Some(current_thread_id);
                            state.recursion_count = 1;
                            state.abandoned = false;
                            result_status = if was_abandoned {
                                NtStatus(NtStatus::STATUS_ABANDONED_WAIT_0.0 + i as i32)
                            } else {
                                NtStatus(i as i32)
                            };
                            return true;
                        }
                        if state.owner_thread_id == Some(current_thread_id) {
                            state.recursion_count = state.recursion_count.saturating_add(1);
                            result_status = NtStatus(i as i32);
                            return true;
                        }
                    }
                    Waitable::Thread(t) => {
                        if t.has_exited() {
                            result_status = NtStatus(i as i32);
                            return true;
                        }
                    }
                    Waitable::Process(p) => {
                        if p.exited.load(core::sync::atomic::Ordering::Acquire) {
                            result_status = NtStatus(i as i32);
                            return true;
                        }
                    }
                }
            }
            false
        });

        // Unregister wakers.
        for w in &waitables {
            unregister_waker(w, wait_cx.waker());
        }
        unregister_alertable_waiter(alert_thread, wait_cx);

        match wait_result {
            Ok(()) => result_status,
            Err(_) => NtStatus::STATUS_TIMEOUT,
        }
    } else {
        // WaitAll: atomically check and consume all handles in one pass.
        // To avoid ABBA deadlock when two threads wait on overlapping objects
        // in different orders, we sort objects by raw pointer address before
        // locking. We also deduplicate aliased handles (same Arc) to avoid
        // self-deadlock.

        // Pre-extract Arc references.
        let waitables: alloc::vec::Vec<Waitable> = {
            let handles = handles_mutex.lock();
            let mut v = alloc::vec::Vec::with_capacity(handle_array.len());
            for &h in &handle_array {
                let w = handles
                    .with(h, |entry| match &entry.object {
                        NtObject::Event(e) => Some(Waitable::Event(Arc::clone(e))),
                        NtObject::Semaphore(s) => Some(Waitable::Semaphore(Arc::clone(s))),
                        NtObject::Mutant(m) => Some(Waitable::Mutant(Arc::clone(m))),
                        NtObject::Thread(t) => Some(Waitable::Thread(Arc::clone(t))),
                        NtObject::Process { state } => Some(Waitable::Process(Arc::clone(state))),
                        NtObject::VirtualThread { process } => {
                            Some(Waitable::Process(Arc::clone(process)))
                        }
                        _ => None,
                    })
                    .flatten();
                match w {
                    Some(waitable) => v.push(waitable),
                    None => return NtStatus::STATUS_INVALID_HANDLE,
                }
            }
            v
        };

        // Build a sorted, deduplicated list of unique objects to lock.
        // Each entry is (pointer_address, index_into_waitables).
        let mut unique_indices: alloc::vec::Vec<(usize, usize)> =
            alloc::vec::Vec::with_capacity(waitables.len());
        for (i, w) in waitables.iter().enumerate() {
            let addr = waitable_addr(w);
            if !unique_indices.iter().any(|(a, _)| *a == addr) {
                unique_indices.push((addr, i));
            }
        }
        unique_indices.sort_unstable_by_key(|(addr, _)| *addr);

        // Register our waker on all unique waitable objects.
        for &(_, idx) in &unique_indices {
            register_waker(&waitables[idx], wait_cx.waker());
        }
        register_alertable_waiter(alert_thread, wait_cx);

        let cx = wait_cx.with_timeout(timeout);
        let abandoned_status = Cell::new(None::<NtStatus>);
        let alerted = Cell::new(AlertOrApc::None);
        let wait_result = cx.wait_until(|| {
            let aoa = take_pending_alert_or_user_apc(alert_thread);
            if aoa.is_wake() {
                alerted.set(aoa);
                return true;
            }
            abandoned_status.set(None);
            // Lock unique objects in sorted address order, check all signaled.
            let mut event_guards: alloc::vec::Vec<(usize, spin::MutexGuard<'_, bool>)> =
                alloc::vec::Vec::new();
            let mut sem_guards: alloc::vec::Vec<(usize, spin::MutexGuard<'_, i32>)> =
                alloc::vec::Vec::new();
            let mut mutant_guards: alloc::vec::Vec<(
                usize,
                spin::MutexGuard<'_, crate::handle_table::MutantState>,
            )> = alloc::vec::Vec::new();
            let mut thread_guards: alloc::vec::Vec<(usize, spin::MutexGuard<'_, Option<i32>>)> =
                alloc::vec::Vec::new();

            let mut ok = true;
            for &(addr, idx) in &unique_indices {
                match &waitables[idx] {
                    Waitable::Event(e) => {
                        let g = e.state.lock();
                        if !*g {
                            ok = false;
                        }
                        event_guards.push((addr, g));
                    }
                    Waitable::Semaphore(s) => {
                        let g = s.state.lock();
                        let occurrences = waitables
                            .iter()
                            .filter(|w| matches!(w, Waitable::Semaphore(s2) if Arc::as_ptr(s2) as usize == addr))
                            .count() as i32;
                        if *g < occurrences {
                            ok = false;
                        }
                        sem_guards.push((addr, g));
                    }
                    Waitable::Mutant(m) => {
                        let g = m.state.lock();
                        if g.owner_thread_id.is_some() && g.owner_thread_id != Some(current_thread_id)
                        {
                            ok = false;
                        }
                        mutant_guards.push((addr, g));
                    }
                    Waitable::Thread(t) => {
                        let g = t.exit_status.lock();
                        if g.is_none() {
                            ok = false;
                        }
                        thread_guards.push((addr, g));
                    }
                    Waitable::Process(p) => {
                        if !p.exited.load(core::sync::atomic::Ordering::Acquire) {
                            ok = false;
                        }
                    }
                }
            }

            if ok {
                // All signaled — consume while still holding all locks.
                for (i, w) in waitables.iter().enumerate() {
                    match w {
                        Waitable::Event(e) => {
                            if !e.manual_reset {
                                let addr = Arc::as_ptr(e) as usize;
                                if let Some((_, g)) =
                                    event_guards.iter_mut().find(|(a, _)| *a == addr)
                                {
                                    **g = false;
                                }
                            }
                        }
                        Waitable::Semaphore(s) => {
                            let addr = Arc::as_ptr(s) as usize;
                            if let Some((_, g)) =
                                sem_guards.iter_mut().find(|(a, _)| *a == addr)
                            {
                                **g -= 1;
                            }
                        }
                        Waitable::Mutant(m) => {
                            let addr = Arc::as_ptr(m) as usize;
                            if let Some((_, g)) =
                                mutant_guards.iter_mut().find(|(a, _)| *a == addr)
                            {
                                if g.owner_thread_id.is_none() {
                                    let was_abandoned = g.abandoned;
                                    g.owner_thread_id = Some(current_thread_id);
                                    g.recursion_count = 1;
                                    g.abandoned = false;
                                    if was_abandoned && abandoned_status.get().is_none() {
                                        abandoned_status.set(Some(NtStatus(
                                            NtStatus::STATUS_ABANDONED_WAIT_0.0 + i as i32,
                                        )));
                                    }
                                } else {
                                    g.recursion_count = g.recursion_count.saturating_add(1);
                                }
                            }
                        }
                        Waitable::Thread(_) => {}
                        Waitable::Process(_) => {}
                    }
                }
            }
            ok
            // All guards drop here — locks released.
        });

        // Unregister wakers.
        for &(_, idx) in &unique_indices {
            unregister_waker(&waitables[idx], wait_cx.waker());
        }
        unregister_alertable_waiter(alert_thread, wait_cx);

        match wait_result {
            Ok(()) => {
                if alerted.get().is_wake() {
                    alerted.get().to_status()
                } else {
                    abandoned_status.get().unwrap_or(NtStatus::STATUS_SUCCESS)
                }
            }
            Err(_) => NtStatus::STATUS_TIMEOUT,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn take_pending_alert(alert_thread: Option<&Arc<ThreadObject>>) -> bool {
    alert_thread.is_some_and(|thread| thread.take_pending_alert())
}

/// Check for a pending plain alert OR pending user APCs.
///
/// Returns the kind of wake-up detected:
/// - `AlertOrApc::UserApc` if user-mode APCs are pending (higher priority).
/// - `AlertOrApc::Alert` if a plain thread alert was consumed.
/// - `AlertOrApc::None` if nothing is pending.
///
/// **Important**: APCs are NOT drained here.  The actual drain + delivery
/// happens in `EnterShim::syscall()` after `dispatch_syscall()` returns
/// `STATUS_USER_APC`, where the shim has access to the execution context.
fn take_pending_alert_or_user_apc(alert_thread: Option<&Arc<ThreadObject>>) -> AlertOrApc {
    if let Some(thread) = alert_thread {
        // Check user APCs first (higher priority than plain alerts on real Windows).
        if thread.has_pending_user_apcs() {
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform()
                    .debug_log_print("alertable wait: pending user APCs detected\n");
            }
            return AlertOrApc::UserApc;
        }
        if thread.take_pending_alert() {
            return AlertOrApc::Alert;
        }
    }
    AlertOrApc::None
}

/// Result of checking for pending alerts / user APCs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AlertOrApc {
    /// Nothing pending.
    None,
    /// A plain thread alert was consumed (`STATUS_ALERTED`).
    Alert,
    /// User-mode APCs were drained (`STATUS_USER_APC`).
    UserApc,
}

impl AlertOrApc {
    fn is_wake(&self) -> bool {
        *self != AlertOrApc::None
    }

    fn to_status(&self) -> NtStatus {
        match self {
            AlertOrApc::None => NtStatus::STATUS_SUCCESS,
            AlertOrApc::Alert => NtStatus::STATUS_ALERTED,
            // STATUS_USER_APC = 0xC0
            AlertOrApc::UserApc => NtStatus(0xC0u32 as i32),
        }
    }
}

fn register_alertable_waiter(
    alert_thread: Option<&Arc<ThreadObject>>,
    wait_cx: &WaitContext<'_, Platform>,
) {
    if let Some(thread) = alert_thread {
        thread.alert_waiters.lock().push(wait_cx.waker().clone());
    }
}

fn unregister_alertable_waiter(
    alert_thread: Option<&Arc<ThreadObject>>,
    wait_cx: &WaitContext<'_, Platform>,
) {
    if let Some(thread) = alert_thread {
        thread
            .alert_waiters
            .lock()
            .retain(|w| !w.ptr_eq(wait_cx.waker()));
    }
}

/// Wait on an event object using the platform's blocking wait.
fn wait_event(
    event: &Arc<EventObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
    alert_thread: Option<&Arc<ThreadObject>>,
) -> NtStatus {
    // Register our waker so signal paths can wake us.
    event.waiters.lock().push(wait_cx.waker().clone());
    register_alertable_waiter(alert_thread, wait_cx);

    let cx = wait_cx.with_timeout(timeout);
    let alerted = Cell::new(AlertOrApc::None);
    let result = cx.wait_until(|| {
        let aoa = take_pending_alert_or_user_apc(alert_thread);
        if aoa.is_wake() {
            alerted.set(aoa);
            return true;
        }
        let mut signaled = event.state.lock();
        if *signaled {
            if !event.manual_reset {
                *signaled = false;
            }
            return true;
        }
        false
    });

    // Unregister our waker.
    event.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));
    unregister_alertable_waiter(alert_thread, wait_cx);

    match result {
        Ok(()) => {
            if alerted.get().is_wake() {
                alerted.get().to_status()
            } else {
                NtStatus::STATUS_SUCCESS
            }
        }
        Err(_) => NtStatus::STATUS_TIMEOUT,
    }
}

/// Wait on a semaphore object using the platform's blocking wait.
fn wait_semaphore(
    sem: &Arc<SemaphoreObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
    alert_thread: Option<&Arc<ThreadObject>>,
) -> NtStatus {
    sem.waiters.lock().push(wait_cx.waker().clone());
    register_alertable_waiter(alert_thread, wait_cx);

    let cx = wait_cx.with_timeout(timeout);
    let alerted = Cell::new(AlertOrApc::None);
    let result = cx.wait_until(|| {
        let aoa = take_pending_alert_or_user_apc(alert_thread);
        if aoa.is_wake() {
            alerted.set(aoa);
            return true;
        }
        let mut count = sem.state.lock();
        if *count > 0 {
            *count -= 1;
            return true;
        }
        false
    });

    sem.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));
    unregister_alertable_waiter(alert_thread, wait_cx);

    match result {
        Ok(()) => {
            if alerted.get().is_wake() {
                alerted.get().to_status()
            } else {
                NtStatus::STATUS_SUCCESS
            }
        }
        Err(_) => NtStatus::STATUS_TIMEOUT,
    }
}

/// Wait for a thread to exit using the platform's blocking wait.
fn wait_thread(
    thread: &Arc<ThreadObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
    alert_thread: Option<&Arc<ThreadObject>>,
) -> NtStatus {
    #[cfg(all(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: wait_thread(tid={}, timeout={:?}, exited={}) waiting\n",
            thread.thread_id,
            timeout,
            thread.has_exited(),
        ));
    }

    thread.waiters.lock().push(wait_cx.waker().clone());
    register_alertable_waiter(alert_thread, wait_cx);

    let cx = wait_cx.with_timeout(timeout);
    let alerted = Cell::new(AlertOrApc::None);
    let result = cx.wait_until(|| {
        let aoa = take_pending_alert_or_user_apc(alert_thread);
        if aoa.is_wake() {
            alerted.set(aoa);
            return true;
        }
        let status = thread.exit_status.lock();
        status.is_some()
    });

    thread.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));
    unregister_alertable_waiter(alert_thread, wait_cx);

    #[cfg(all(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: wait_thread(tid={}) -> {:?} exit_status={:?}\n",
            thread.thread_id,
            result,
            *thread.exit_status.lock(),
        ));
    }

    match result {
        Ok(()) => {
            if alerted.get().is_wake() {
                alerted.get().to_status()
            } else {
                NtStatus::STATUS_SUCCESS
            }
        }
        Err(_) => NtStatus::STATUS_TIMEOUT,
    }
}

/// Wait on a virtual process object (NtCreateUserProcess).
///
/// Since our virtual processes run synchronously and are already exited by the
/// time the handle is returned, this should return immediately in practice.
fn wait_process(
    process: &Arc<ProcessObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
    alert_thread: Option<&Arc<ThreadObject>>,
) -> NtStatus {
    // Fast path: process already exited.
    if process.exited.load(core::sync::atomic::Ordering::Acquire) {
        return NtStatus::STATUS_SUCCESS;
    }

    // Slow path: wait for exit.
    process.waiters.lock().push(wait_cx.waker().clone());
    register_alertable_waiter(alert_thread, wait_cx);

    let cx = wait_cx.with_timeout(timeout);
    let alerted = Cell::new(AlertOrApc::None);
    let result = cx.wait_until(|| {
        let aoa = take_pending_alert_or_user_apc(alert_thread);
        if aoa.is_wake() {
            alerted.set(aoa);
            return true;
        }
        process.exited.load(core::sync::atomic::Ordering::Acquire)
    });

    process
        .waiters
        .lock()
        .retain(|w| !w.ptr_eq(wait_cx.waker()));
    unregister_alertable_waiter(alert_thread, wait_cx);

    match result {
        Ok(()) => {
            if alerted.get().is_wake() {
                alerted.get().to_status()
            } else {
                NtStatus::STATUS_SUCCESS
            }
        }
        Err(_) => NtStatus::STATUS_TIMEOUT,
    }
}

/// Wait on a mutant object using the platform's blocking wait.
fn wait_mutant(
    mutant: &Arc<MutantObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
    current_thread_id: u32,
    alert_thread: Option<&Arc<ThreadObject>>,
) -> NtStatus {
    mutant.waiters.lock().push(wait_cx.waker().clone());
    register_alertable_waiter(alert_thread, wait_cx);

    let cx = wait_cx.with_timeout(timeout);
    let abandoned = Cell::new(false);
    let alerted = Cell::new(AlertOrApc::None);
    let result = cx.wait_until(|| {
        let aoa = take_pending_alert_or_user_apc(alert_thread);
        if aoa.is_wake() {
            alerted.set(aoa);
            return true;
        }
        let mut state = mutant.state.lock();
        if state.owner_thread_id.is_none() {
            abandoned.set(state.abandoned);
            state.owner_thread_id = Some(current_thread_id);
            state.recursion_count = 1;
            state.abandoned = false;
            return true;
        }
        if state.owner_thread_id == Some(current_thread_id) {
            state.recursion_count = state.recursion_count.saturating_add(1);
            return true;
        }
        false
    });

    mutant.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));
    unregister_alertable_waiter(alert_thread, wait_cx);

    match result {
        Ok(()) => {
            if alerted.get().is_wake() {
                alerted.get().to_status()
            } else if abandoned.get() {
                NtStatus::STATUS_ABANDONED_WAIT_0
            } else {
                NtStatus::STATUS_SUCCESS
            }
        }
        Err(_) => NtStatus::STATUS_TIMEOUT,
    }
}

/// Read a LARGE_INTEGER timeout from guest memory.
///
/// Windows semantics:
/// - NULL pointer → no timeout (infinite wait)
/// - Negative value → relative timeout in 100ns intervals
/// - Zero → no wait (poll)
/// - Positive value → absolute system time in 100ns intervals since 1601
fn duration_from_100ns_intervals(intervals_100ns: u64) -> Duration {
    Duration::from_nanos(intervals_100ns.saturating_mul(100))
}

fn read_timeout(ptr: usize) -> Result<Option<Duration>, NtStatus> {
    if ptr == 0 {
        return Ok(None); // Infinite wait
    }
    let Some(raw) = crate::try_read_guest_value_unaligned::<i64>(ptr) else {
        return Err(NtStatus::STATUS_ACCESS_VIOLATION);
    };
    if raw == 0 {
        return Ok(Some(Duration::ZERO)); // Poll (no wait)
    }

    if raw < 0 {
        return Ok(Some(duration_from_100ns_intervals(raw.unsigned_abs())));
    }

    let now = super::sysinfo::windows_filetime_now_pub();
    let remaining_100ns = raw.saturating_sub(now);
    Ok(Some(duration_from_100ns_intervals(
        u64::try_from(remaining_100ns).unwrap_or(0),
    )))
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::read_timeout;

    #[test]
    fn read_timeout_null_ptr_is_infinite() {
        assert_eq!(read_timeout(0), Ok(None));
    }

    #[test]
    fn read_timeout_invalid_pointer_is_access_violation() {
        assert_eq!(
            read_timeout(1),
            Err(litebox_common_windows::ntstatus::NtStatus::STATUS_ACCESS_VIOLATION)
        );
    }

    #[test]
    fn read_timeout_negative_value_is_relative() {
        let raw = -50_000i64; // 5 ms
        assert_eq!(
            read_timeout(core::ptr::from_ref(&raw) as usize),
            Ok(Some(Duration::from_millis(5)))
        );
    }

    #[test]
    fn read_timeout_i64_min_is_relative_without_overflow() {
        let raw = i64::MIN;
        assert_eq!(
            read_timeout(core::ptr::from_ref(&raw) as usize),
            Ok(Some(Duration::from_nanos(u64::MAX)))
        );
    }

    #[test]
    fn read_timeout_past_absolute_deadline_polls_immediately() {
        let raw = super::super::sysinfo::windows_filetime_now_pub() - 10_000;
        assert_eq!(
            read_timeout(core::ptr::from_ref(&raw) as usize),
            Ok(Some(Duration::ZERO))
        );
    }
}
