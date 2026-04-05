// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! kqueue/kevent implementation for the macOS shim.
//!
//! Follows the same observer-based pattern as the Linux epoll implementation
//! (`litebox_shim_linux/src/syscalls/epoll.rs`).

use core::{
    convert::Infallible,
    marker::PhantomData,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use litebox::{
    event::{
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::{WaitContext, WaitError},
        Events, IOPollable,
    },
    platform::{RawConstPointer as _, RawMutPointer as _},
};
use litebox_common_macos::errno::Errno;

use crate::{ConstPtr, MutPtr, Platform, ShimFS, Task};

use super::file::fd_to_usize;

// ---------------------------------------------------------------------------
// kqueue constants (from <sys/event.h>)
// ---------------------------------------------------------------------------

const EVFILT_READ: i16 = -1;
const EVFILT_WRITE: i16 = -2;

const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_ENABLE: u16 = 0x0004;
const EV_DISABLE: u16 = 0x0008;
const EV_ONESHOT: u16 = 0x0010;
const EV_CLEAR: u16 = 0x0020;
const EV_EOF: u16 = 0x8000;
const EV_ERROR: u16 = 0x4000;

// ---------------------------------------------------------------------------
// Guest memory layout for struct kevent (32 bytes on arm64)
// ---------------------------------------------------------------------------
//
// offset 0:  uintptr_t ident  (8 bytes)
// offset 8:  int16_t   filter (2 bytes)
// offset 10: uint16_t  flags  (2 bytes)
// offset 12: uint32_t  fflags (4 bytes)
// offset 16: intptr_t  data   (8 bytes)
// offset 24: void*     udata  (8 bytes)

const KEVENT_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// RawKevent — output struct written back to guest memory
// ---------------------------------------------------------------------------

struct RawKevent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: usize,
}

// ---------------------------------------------------------------------------
// KqueueKey — uniquely identifies an interest registration
// ---------------------------------------------------------------------------

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
struct KqueueKey {
    ident: usize, // FD number
    filter: i16,  // EVFILT_READ or EVFILT_WRITE
}

// ---------------------------------------------------------------------------
// KqueueEntry — a single registered interest; implements Observer<Events>
// ---------------------------------------------------------------------------

struct KqueueEntry {
    key: KqueueKey,
    flags: u16,
    fflags: u32,
    udata: usize,
    ready: Arc<ReadySet>,
    is_ready: AtomicBool,
    is_enabled: AtomicBool,
    weak_self: Weak<Self>,
}

impl KqueueEntry {
    fn new(
        key: KqueueKey,
        flags: u16,
        fflags: u32,
        udata: usize,
        ready: Arc<ReadySet>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| KqueueEntry {
            key,
            flags,
            fflags,
            udata,
            ready,
            is_ready: AtomicBool::new(false),
            is_enabled: AtomicBool::new(true),
            weak_self: weak_self.clone(),
        })
    }

    /// Check the underlying pollable for current events and produce a kevent
    /// result if ready.
    ///
    /// Returns `(Some(kevent), is_still_ready)` if the entry is active and has
    /// matching events, `(None, false)` if no events, or `None` if the entry is
    /// disabled.
    fn poll<FS: ShimFS>(&self, task: &Task<FS>) -> Option<(Option<RawKevent>, bool)> {
        if !self.is_enabled.load(Ordering::Relaxed) {
            return None;
        }

        let events = check_fd_events(task, self.key.ident, self.key.filter);

        let interested = match self.key.filter {
            EVFILT_READ => events.intersects(Events::IN | Events::HUP | Events::ERR),
            EVFILT_WRITE => events.intersects(Events::OUT | Events::HUP | Events::ERR),
            _ => false,
        };

        if !interested {
            return Some((None, false));
        }

        let mut out_flags: u16 = 0;
        if events.intersects(Events::HUP) {
            out_flags |= EV_EOF;
        }

        // Handle oneshot: disable after reporting.
        let is_oneshot = self.flags & EV_ONESHOT != 0;
        if is_oneshot {
            self.is_enabled.store(false, Ordering::Relaxed);
        }

        // For EV_CLEAR entries, the ready state is cleared after retrieval,
        // so they should NOT be re-added to the ready list.
        let is_clear = self.flags & EV_CLEAR != 0;
        let is_still_ready = !is_oneshot && !is_clear;

        Some((
            Some(RawKevent {
                ident: self.key.ident,
                filter: self.key.filter,
                flags: out_flags,
                fflags: self.fflags,
                data: 0, // simplified: no data count
                udata: self.udata,
            }),
            is_still_ready,
        ))
    }
}

impl Observer<Events> for KqueueEntry {
    fn on_events(&self, events: &Events) {
        let interested = match self.key.filter {
            EVFILT_READ => events.intersects(Events::IN | Events::HUP | Events::ERR),
            EVFILT_WRITE => events.intersects(Events::OUT | Events::HUP | Events::ERR),
            _ => false,
        };
        if interested {
            self.ready.push(self);
        }
    }
}

// ---------------------------------------------------------------------------
// ReadySet — deque of ready entries, same pattern as Linux epoll
// ---------------------------------------------------------------------------

struct ReadySet {
    entries: litebox::sync::Mutex<Platform, VecDeque<Weak<KqueueEntry>>>,
    pollee: Pollee<Platform>,
}

impl ReadySet {
    fn new() -> Self {
        Self {
            entries: litebox::sync::Mutex::new(VecDeque::new()),
            pollee: Pollee::new(),
        }
    }

    fn push(&self, entry: &KqueueEntry) {
        if !entry.is_enabled.load(Ordering::Relaxed) {
            return;
        }

        if !entry.is_ready.swap(true, Ordering::Relaxed) {
            let mut entries = self.entries.lock();
            entries.push_back(entry.weak_self.clone());
        }

        self.pollee.notify_observers(Events::IN);
    }

    fn pop_multiple<FS: ShimFS>(
        &self,
        task: &Task<FS>,
        maxevents: usize,
        events: &mut Vec<RawKevent>,
    ) {
        let mut nums = self.entries.lock().len();
        while nums > 0 {
            nums -= 1;
            if events.len() >= maxevents {
                break;
            }

            // Release the lock inside the loop to avoid holding it while calling poll().
            let Some(weak_entry) = self.entries.lock().pop_front() else {
                break;
            };

            let Some(entry) = weak_entry.upgrade() else {
                // Entry has been deleted.
                continue;
            };
            entry.is_ready.store(false, Ordering::Relaxed);

            let Some((event, is_still_ready)) = entry.poll(task) else {
                // Entry is disabled.
                continue;
            };

            if let Some(event) = event {
                events.push(event);
            }

            if is_still_ready {
                // Re-add to the ready list if not already marked ready by another event.
                if !entry.is_ready.swap(true, Ordering::Relaxed) {
                    self.entries.lock().push_back(weak_entry);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// KqueueFile — the kqueue instance
// ---------------------------------------------------------------------------

pub(crate) struct KqueueFile<FS: ShimFS> {
    interests: litebox::sync::Mutex<Platform, BTreeMap<KqueueKey, Arc<KqueueEntry>>>,
    ready: Arc<ReadySet>,
    _marker: PhantomData<FS>,
}

impl<FS: ShimFS> KqueueFile<FS> {
    pub(crate) fn new() -> Self {
        KqueueFile {
            interests: litebox::sync::Mutex::new(BTreeMap::new()),
            ready: Arc::new(ReadySet::new()),
            _marker: PhantomData,
        }
    }

    fn add_interest(
        &self,
        task: &Task<FS>,
        key: KqueueKey,
        flags: u16,
        fflags: u32,
        udata: usize,
    ) -> Result<(), Errno> {
        let mut interests = self.interests.lock();

        // If the key already exists, remove the old entry first (EV_ADD replaces).
        interests.remove(&key);

        let entry = KqueueEntry::new(key, flags, fflags, udata, self.ready.clone());

        // Register observer on the underlying pollable.
        let mask = match key.filter {
            EVFILT_READ => Events::IN | Events::ALWAYS_POLLED,
            EVFILT_WRITE => Events::OUT | Events::ALWAYS_POLLED,
            _ => return Err(Errno::EINVAL),
        };

        let initial_events = register_observer_on_fd(
            task,
            key.ident,
            entry.weak_self.clone() as Weak<dyn Observer<Events>>,
            mask,
        )?;

        // If already ready, push to the ready set.
        let interested = match key.filter {
            EVFILT_READ => initial_events.intersects(Events::IN | Events::HUP | Events::ERR),
            EVFILT_WRITE => initial_events.intersects(Events::OUT | Events::HUP | Events::ERR),
            _ => false,
        };
        if interested {
            self.ready.push(&entry);
        }

        interests.insert(key, entry);
        Ok(())
    }

    fn delete_interest(&self, key: &KqueueKey) -> Result<(), Errno> {
        let mut interests = self.interests.lock();
        interests.remove(key).ok_or(Errno::ENOENT)?;
        // Dropping the Arc<KqueueEntry> will eventually cause the weak observer
        // to fail to upgrade, lazily unregistering it.
        Ok(())
    }

    fn enable_interest(&self, key: &KqueueKey) -> Result<(), Errno> {
        let interests = self.interests.lock();
        let entry = interests.get(key).ok_or(Errno::ENOENT)?;
        entry.is_enabled.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn disable_interest(&self, key: &KqueueKey) -> Result<(), Errno> {
        let interests = self.interests.lock();
        let entry = interests.get(key).ok_or(Errno::ENOENT)?;
        entry.is_enabled.store(false, Ordering::Relaxed);
        Ok(())
    }

    fn wait(
        &self,
        task: &Task<FS>,
        cx: &WaitContext<'_, Platform>,
        maxevents: usize,
    ) -> Result<Vec<RawKevent>, WaitError> {
        let mut events = Vec::new();
        match self.ready.pollee.wait(cx, false, Events::IN, || {
            self.ready.pop_multiple(task, maxevents, &mut events);
            if events.is_empty() {
                return Err(TryOpError::<Infallible>::TryAgain);
            }
            Ok(())
        }) {
            Ok(()) => Ok(events),
            Err(TryOpError::TryAgain) => unreachable!(),
            Err(TryOpError::WaitError(e)) => Err(e),
        }
    }
}

impl<FS: ShimFS> IOPollable for KqueueFile<FS> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.ready.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        if !self.ready.entries.lock().is_empty() {
            Events::IN
        } else {
            Events::empty()
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: resolve fd and register an observer, returning initial events
// ---------------------------------------------------------------------------

/// Register an observer on the pollable identified by `fd` and return its
/// current IO events. Returns `Err(EBADF)` if the fd cannot be resolved.
fn register_observer_on_fd<FS: ShimFS>(
    task: &Task<FS>,
    fd: usize,
    observer: Weak<dyn Observer<Events>>,
    mask: Events,
) -> Result<Events, Errno> {
    let raw_fd = fd;

    // Try the raw descriptor table.
    let strong_fd = {
        let rds = task.global.raw_descriptors.read();
        crate::StrongFd::<FS>::from_raw(&rds, raw_fd).ok()
    };

    if let Some(strong) = strong_fd {
        return match strong {
            crate::StrongFd::FileSystem(_) => {
                // Regular files / stdio — always ready.
                Ok(Events::IN | Events::OUT)
            }
            crate::StrongFd::Pipes(typed_fd) => {
                let result = task.global.pipes.with_iopollable(&typed_fd, |pollable| {
                    pollable.register_observer(observer, mask);
                    pollable.check_io_events()
                });
                match result {
                    Ok(events) => Ok(events),
                    Err(_closed) => Ok(Events::HUP),
                }
            }
            crate::StrongFd::Network(_net_fd) => {
                let proxies = task.global.net_proxies.read();
                if let Some(proxy) = proxies.get(&raw_fd) {
                    proxy.register_observer(observer, mask);
                    Ok(proxy.check_io_events())
                } else {
                    Ok(Events::IN | Events::OUT)
                }
            }
        };
    }

    // Check unix sockets — always ready (no IOPollable yet).
    {
        let unix_sockets = task.global.unix_sockets.read();
        if unix_sockets.contains_key(&raw_fd) {
            return Ok(Events::IN | Events::OUT);
        }
    }

    // Check kqueues.
    {
        let kqueues = task.global.kqueues.read();
        if let Some(kq) = kqueues.get(&raw_fd) {
            kq.register_observer(observer, mask);
            return Ok(kq.check_io_events());
        }
    }

    Err(Errno::EBADF)
}

/// Check current IO events on a file descriptor without registering an observer.
fn check_fd_events<FS: ShimFS>(task: &Task<FS>, fd: usize, filter: i16) -> Events {
    let raw_fd = fd;

    let strong_fd = {
        let rds = task.global.raw_descriptors.read();
        crate::StrongFd::<FS>::from_raw(&rds, raw_fd).ok()
    };

    if let Some(strong) = strong_fd {
        return match strong {
            crate::StrongFd::FileSystem(_) => Events::IN | Events::OUT,
            crate::StrongFd::Pipes(typed_fd) => {
                let result = task
                    .global
                    .pipes
                    .with_iopollable(&typed_fd, |pollable| pollable.check_io_events());
                match result {
                    Ok(events) => events,
                    Err(_closed) => Events::HUP,
                }
            }
            crate::StrongFd::Network(_net_fd) => {
                let proxies = task.global.net_proxies.read();
                if let Some(proxy) = proxies.get(&raw_fd) {
                    proxy.check_io_events()
                } else {
                    Events::IN | Events::OUT
                }
            }
        };
    }

    // Unix sockets — always ready.
    {
        let unix_sockets = task.global.unix_sockets.read();
        if unix_sockets.contains_key(&raw_fd) {
            return Events::IN | Events::OUT;
        }
    }

    // kqueues.
    {
        let kqueues = task.global.kqueues.read();
        if let Some(kq) = kqueues.get(&raw_fd) {
            return kq.check_io_events();
        }
    }

    // Unknown fd — return nothing (will be caught upstream).
    let _ = filter;
    Events::empty()
}

// ---------------------------------------------------------------------------
// Syscall implementations
// ---------------------------------------------------------------------------

/// Create a new kqueue and return its virtual fd number.
pub(crate) fn sys_kqueue<FS: ShimFS>(task: &Task<FS>) -> Result<usize, Errno> {
    let kq = Arc::new(KqueueFile::new());
    let fd = task
        .global
        .kqueue_fd_counter
        .fetch_add(1, Ordering::Relaxed);
    task.global.kqueues.write().insert(fd, kq);
    Ok(fd)
}

/// Process changelist entries and/or wait for events on a kqueue.
pub(crate) fn sys_kevent<FS: ShimFS>(
    task: &Task<FS>,
    kq_fd: i32,
    changelist_addr: usize,
    nchanges: i32,
    eventlist_addr: usize,
    nevents: i32,
    timeout_addr: usize,
) -> Result<usize, Errno> {
    let kq_fd_usize = fd_to_usize(kq_fd)?;
    let kq = {
        let kqueues = task.global.kqueues.read();
        kqueues.get(&kq_fd_usize).cloned().ok_or(Errno::EBADF)?
    };

    let mut error_events: Vec<RawKevent> = Vec::new();

    // Phase 1: process changelist.
    if nchanges > 0 {
        for i in 0..nchanges as usize {
            let base = changelist_addr + i * KEVENT_SIZE;

            let ident = read_guest_u64(base)? as usize;
            let filter = read_guest_i16(base + 8)?;
            let flags = read_guest_u16(base + 10)?;
            let fflags = read_guest_u32(base + 12)?;
            let _data = read_guest_i64(base + 16)?; // currently unused
            let udata = read_guest_u64(base + 24)? as usize;

            let key = KqueueKey { ident, filter };

            let result = if flags & EV_ADD != 0 {
                kq.add_interest(task, key, flags, fflags, udata)
            } else if flags & EV_DELETE != 0 {
                kq.delete_interest(&key)
            } else if flags & EV_ENABLE != 0 {
                kq.enable_interest(&key)
            } else if flags & EV_DISABLE != 0 {
                kq.disable_interest(&key)
            } else {
                // Unknown flags combination — ignore.
                Ok(())
            };

            if let Err(errno) = result {
                // If we have space in the eventlist, write an error event.
                if nevents > 0 && error_events.len() < nevents as usize {
                    error_events.push(RawKevent {
                        ident,
                        filter,
                        flags: EV_ERROR,
                        fflags: 0,
                        data: errno as isize,
                        udata,
                    });
                }
            }
        }
    }

    // If nevents == 0, only changelist processing was requested.
    if nevents <= 0 {
        return Ok(0);
    }

    // Write any error events first.
    let mut out_count = 0usize;
    for ev in &error_events {
        if out_count >= nevents as usize {
            break;
        }
        write_kevent_to_guest(eventlist_addr + out_count * KEVENT_SIZE, ev)?;
        out_count += 1;
    }

    // If we had error events, return them immediately without waiting.
    if !error_events.is_empty() {
        return Ok(out_count);
    }

    // Phase 2: wait for events.
    let remaining_slots = (nevents as usize).saturating_sub(out_count);
    if remaining_slots == 0 {
        return Ok(out_count);
    }

    // Parse timeout.
    let timeout: Option<Duration> = if timeout_addr == 0 {
        None // block indefinitely
    } else {
        let tv_sec = read_guest_i64(timeout_addr)?;
        let tv_nsec = read_guest_i64(timeout_addr + 8)?;
        if tv_sec == 0 && tv_nsec == 0 {
            Some(Duration::ZERO) // non-blocking
        } else if tv_sec < 0 || tv_nsec < 0 {
            return Err(Errno::EINVAL);
        } else {
            Some(Duration::from_secs(tv_sec as u64) + Duration::from_nanos(tv_nsec as u64))
        }
    };

    let cx = task.wait_cx().with_timeout(timeout);

    // Nonblocking mode if timeout is zero.
    let is_nonblock = timeout.is_some_and(|d| d.is_zero());

    let wait_result = if is_nonblock {
        // Non-blocking: just try once.
        let mut events = Vec::new();
        kq.ready.pop_multiple(task, remaining_slots, &mut events);
        if events.is_empty() {
            Ok(Vec::new()) // Return 0 events (timeout expired immediately).
        } else {
            Ok(events)
        }
    } else {
        kq.wait(task, &cx, remaining_slots)
    };

    match wait_result {
        Ok(ready_events) => {
            for ev in &ready_events {
                write_kevent_to_guest(eventlist_addr + out_count * KEVENT_SIZE, ev)?;
                out_count += 1;
            }
            Ok(out_count)
        }
        Err(WaitError::Interrupted) => Err(Errno::EINTR),
        Err(WaitError::TimedOut) => {
            // Timeout: return whatever we have (0 events is valid).
            Ok(out_count)
        }
    }
}

// ---------------------------------------------------------------------------
// Guest memory read/write helpers
// ---------------------------------------------------------------------------

fn read_guest_u64(addr: usize) -> Result<u64, Errno> {
    let ptr: ConstPtr<u64> = ConstPtr::from_usize(addr);
    ptr.read_at_offset(0).ok_or(Errno::EFAULT)
}

fn read_guest_i64(addr: usize) -> Result<i64, Errno> {
    let ptr: ConstPtr<i64> = ConstPtr::from_usize(addr);
    ptr.read_at_offset(0).ok_or(Errno::EFAULT)
}

fn read_guest_i16(addr: usize) -> Result<i16, Errno> {
    let ptr: ConstPtr<i16> = ConstPtr::from_usize(addr);
    ptr.read_at_offset(0).ok_or(Errno::EFAULT)
}

fn read_guest_u16(addr: usize) -> Result<u16, Errno> {
    let ptr: ConstPtr<u16> = ConstPtr::from_usize(addr);
    ptr.read_at_offset(0).ok_or(Errno::EFAULT)
}

fn read_guest_u32(addr: usize) -> Result<u32, Errno> {
    let ptr: ConstPtr<u32> = ConstPtr::from_usize(addr);
    ptr.read_at_offset(0).ok_or(Errno::EFAULT)
}

fn write_kevent_to_guest(addr: usize, ev: &RawKevent) -> Result<(), Errno> {
    let ident_ptr: MutPtr<u64> = MutPtr::from_usize(addr);
    let filter_ptr: MutPtr<i16> = MutPtr::from_usize(addr + 8);
    let flags_ptr: MutPtr<u16> = MutPtr::from_usize(addr + 10);
    let fflags_ptr: MutPtr<u32> = MutPtr::from_usize(addr + 12);
    let data_ptr: MutPtr<i64> = MutPtr::from_usize(addr + 16);
    let udata_ptr: MutPtr<u64> = MutPtr::from_usize(addr + 24);

    ident_ptr
        .write_at_offset(0, ev.ident as u64)
        .ok_or(Errno::EFAULT)?;
    filter_ptr
        .write_at_offset(0, ev.filter)
        .ok_or(Errno::EFAULT)?;
    flags_ptr
        .write_at_offset(0, ev.flags)
        .ok_or(Errno::EFAULT)?;
    fflags_ptr
        .write_at_offset(0, ev.fflags)
        .ok_or(Errno::EFAULT)?;
    data_ptr
        .write_at_offset(0, ev.data as i64)
        .ok_or(Errno::EFAULT)?;
    udata_ptr
        .write_at_offset(0, ev.udata as u64)
        .ok_or(Errno::EFAULT)?;

    Ok(())
}
