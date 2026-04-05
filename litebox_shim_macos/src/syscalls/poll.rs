// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Polling infrastructure for select(2) and poll(2) syscalls.

use alloc::sync::Arc;
use core::time::Duration;
use litebox::event::observer::Observer;
use litebox::event::wait::{WaitContext, WaitError, Waker};
use litebox::event::{Events, IOPollable};
use litebox::fd::TypedFd;
use litebox::pipes::Pipes;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::errno::Errno;

use crate::{ConstPtr, MutPtr, Platform, ShimFS, Task};

use super::file::fd_to_usize;

// macOS poll event flags.
const POLLIN: i16 = 0x0001;
const POLLPRI: i16 = 0x0002;
const POLLOUT: i16 = 0x0004;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;

/// Maximum number of file descriptors for select(2).
const FD_SETSIZE: u32 = 1024;

/// Number of u32 words in an fd_set (32 * 32 = 1024 bits).
const FD_SET_INTS: usize = 32;

/// A reference to a pollable resource resolved from a guest file descriptor.
enum PollableRef {
    /// A pipe file descriptor — holds the typed fd for `with_iopollable`.
    Pipe(Arc<TypedFd<Pipes<Platform>>>),
    /// A network socket — the proxy implements `IOPollable`.
    Network(Arc<litebox::net::socket_channel::NetworkProxy<Platform>>),
    /// A Unix domain socket — always reports ready (no IOPollable impl yet).
    Unix,
    /// A regular file / stdio — always ready for I/O.
    AlwaysReady,
}

/// Resolve a guest file descriptor to a `PollableRef`.
///
/// Returns `None` if the fd is invalid (not found in any subsystem).
fn resolve_pollable<FS: ShimFS>(task: &Task<FS>, fd: i32) -> Option<PollableRef> {
    let raw_fd = fd_to_usize(fd).ok()?;

    // Try the raw descriptor table first.
    let strong_fd = {
        let rds = task.global.raw_descriptors.read();
        crate::StrongFd::<FS>::from_raw(&rds, raw_fd).ok()
    };

    if let Some(strong) = strong_fd {
        return match strong {
            crate::StrongFd::FileSystem(_) => Some(PollableRef::AlwaysReady),
            crate::StrongFd::Pipes(typed_fd) => Some(PollableRef::Pipe(typed_fd)),
            crate::StrongFd::Network(_net_fd) => {
                // Look up the NetworkProxy for this fd.
                let proxies = task.global.net_proxies.read();
                if let Some(proxy) = proxies.get(&raw_fd) {
                    Some(PollableRef::Network(proxy.clone()))
                } else {
                    // Network fd without a proxy; treat as always ready.
                    Some(PollableRef::AlwaysReady)
                }
            }
        };
    }

    // Check unix sockets.
    {
        let unix_sockets = task.global.unix_sockets.read();
        if unix_sockets.contains_key(&raw_fd) {
            return Some(PollableRef::Unix);
        }
    }

    // Check kqueues.
    {
        let kqueues = task.global.kqueues.read();
        if kqueues.contains_key(&raw_fd) {
            // Kqueue fds are always ready for now (Task 4 will refine this).
            return Some(PollableRef::AlwaysReady);
        }
    }

    None
}

/// Observer that wakes a `Waker` when events occur.
#[derive(Clone)]
struct PollEntryObserver(Waker<Platform>);

impl Observer<Events> for PollEntryObserver {
    fn on_events(&self, _events: &Events) {
        self.0.wake();
    }
}

/// A single entry in a `PollSet`.
struct PollEntry {
    fd: i32,
    mask: Events,
    revents: Events,
    /// Holds the observer alive so the `Weak` registered with the pollable stays valid.
    observer: Option<Arc<PollEntryObserver>>,
}

/// A set of file descriptors to poll for I/O readiness.
pub(crate) struct PollSet {
    entries: alloc::vec::Vec<PollEntry>,
}

impl PollSet {
    /// Create a new empty `PollSet` with the given capacity hint.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: alloc::vec::Vec::with_capacity(capacity),
        }
    }

    /// Add a file descriptor with the given event mask.
    ///
    /// Negative fds are stored but skipped during scanning (poll(2) semantics).
    pub fn add_fd(&mut self, fd: i32, mask: Events) {
        self.entries.push(PollEntry {
            fd,
            mask: mask | Events::ALWAYS_POLLED,
            revents: Events::empty(),
            observer: None,
        });
    }

    /// Scan all entries once, checking for ready events.
    ///
    /// If `waker` is `Some`, registers an observer on each pollable so that
    /// the waker is notified when events change. Returns `true` if any entry
    /// has non-empty revents.
    fn scan<FS: ShimFS>(&mut self, task: &Task<FS>, waker: Option<&Waker<Platform>>) -> bool {
        let mut is_ready = false;
        for entry in &mut self.entries {
            if entry.fd < 0 {
                continue;
            }

            entry.revents = match resolve_pollable(task, entry.fd) {
                None => Events::NVAL,
                Some(PollableRef::AlwaysReady) | Some(PollableRef::Unix) => {
                    (Events::IN | Events::OUT) & entry.mask
                }
                Some(PollableRef::Pipe(typed_fd)) => {
                    let result = task.global.pipes.with_iopollable(&typed_fd, |pollable| {
                        let events = pollable.check_io_events() & entry.mask;
                        if !is_ready {
                            if let Some(waker) = waker {
                                let observer = Arc::new(PollEntryObserver(waker.clone()));
                                let weak = Arc::downgrade(&observer) as _;
                                pollable.register_observer(weak, entry.mask);
                                entry.observer = Some(observer);
                            }
                        }
                        events
                    });
                    match result {
                        Ok(events) => events,
                        Err(_closed) => Events::HUP,
                    }
                }
                Some(PollableRef::Network(proxy)) => {
                    let events = proxy.check_io_events() & entry.mask;
                    if !is_ready {
                        if let Some(waker) = waker {
                            let observer = Arc::new(PollEntryObserver(waker.clone()));
                            let weak = Arc::downgrade(&observer) as _;
                            proxy.register_observer(weak, entry.mask);
                            entry.observer = Some(observer);
                        }
                    }
                    events
                }
            };

            if !entry.revents.is_empty() {
                is_ready = true;
            }
        }
        is_ready
    }

    /// Wait for any entry to become ready.
    ///
    /// First scans without registering observers. If nothing is ready, enters
    /// a wait loop with observer registration.
    pub fn wait<FS: ShimFS>(
        &mut self,
        task: &Task<FS>,
        cx: &WaitContext<'_, Platform>,
    ) -> Result<(), WaitError> {
        if self.scan(task, None) {
            return Ok(());
        }

        let mut register = true;
        cx.wait_until(|| {
            if self.scan(task, register.then_some(cx.waker())) {
                return true;
            }
            // Don't register observers again in the next iteration.
            register = false;
            false
        })
    }

    /// Returns an iterator over the accumulated `revents` for each entry.
    pub fn revents(&self) -> impl Iterator<Item = Events> + '_ {
        self.entries.iter().map(|entry| entry.revents)
    }

    /// Returns an iterator over `(fd, revents)` pairs.
    pub fn revents_with_fds(&self) -> impl Iterator<Item = (i32, Events)> + '_ {
        self.entries.iter().map(|entry| (entry.fd, entry.revents))
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Convert macOS poll(2) event flags to litebox `Events`.
fn poll_events_to_litebox(events: i16) -> Events {
    let mut result = Events::empty();
    if events & POLLIN != 0 {
        result |= Events::IN;
    }
    if events & POLLPRI != 0 {
        result |= Events::PRI;
    }
    if events & POLLOUT != 0 {
        result |= Events::OUT;
    }
    if events & POLLERR != 0 {
        result |= Events::ERR;
    }
    if events & POLLHUP != 0 {
        result |= Events::HUP;
    }
    if events & POLLNVAL != 0 {
        result |= Events::NVAL;
    }
    result
}

/// Convert litebox `Events` to macOS poll(2) event flags.
fn litebox_to_poll_events(events: Events) -> i16 {
    let mut result: i16 = 0;
    if events.contains(Events::IN) {
        result |= POLLIN;
    }
    if events.contains(Events::PRI) {
        result |= POLLPRI;
    }
    if events.contains(Events::OUT) {
        result |= POLLOUT;
    }
    if events.contains(Events::ERR) {
        result |= POLLERR;
    }
    if events.contains(Events::HUP) {
        result |= POLLHUP;
    }
    if events.contains(Events::NVAL) {
        result |= POLLNVAL;
    }
    result
}

// ---------------------------------------------------------------------------
// fd_set helpers for select(2)
// ---------------------------------------------------------------------------

/// Read an fd_set bitmap from guest memory.
///
/// An fd_set is `[u32; FD_SET_INTS]` = 128 bytes on macOS (1024 bits).
/// If `addr` is 0 (NULL pointer), returns an all-zero set.
fn read_fd_set(addr: usize, nfds: u32) -> Result<[u32; FD_SET_INTS], Errno> {
    if addr == 0 {
        return Ok([0u32; FD_SET_INTS]);
    }
    let mut set = [0u32; FD_SET_INTS];
    let words_needed = (nfds as usize).div_ceil(32);
    let ptr: ConstPtr<u32> = ConstPtr::from_usize(addr);
    for i in 0..words_needed {
        set[i] = ptr.read_at_offset(i as isize).ok_or(Errno::EFAULT)?;
    }
    Ok(set)
}

/// Write an fd_set bitmap back to guest memory.
fn write_fd_set(addr: usize, set: &[u32; FD_SET_INTS], nfds: u32) -> Result<(), Errno> {
    if addr == 0 {
        return Ok(());
    }
    let words_needed = (nfds as usize).div_ceil(32);
    let ptr: MutPtr<u32> = MutPtr::from_usize(addr);
    for i in 0..words_needed {
        ptr.write_at_offset(i as isize, set[i])
            .ok_or(Errno::EFAULT)?;
    }
    Ok(())
}

/// Check if a file descriptor bit is set in an fd_set.
fn is_fd_set(set: &[u32; FD_SET_INTS], fd: u32) -> bool {
    let word = (fd / 32) as usize;
    let bit = fd % 32;
    set[word] & (1 << bit) != 0
}

/// Set a file descriptor bit in an fd_set.
fn set_fd_bit(set: &mut [u32; FD_SET_INTS], fd: u32) {
    let word = (fd / 32) as usize;
    let bit = fd % 32;
    set[word] |= 1 << bit;
}

// ---------------------------------------------------------------------------
// Syscall implementations
// ---------------------------------------------------------------------------

impl<FS: ShimFS> Task<FS> {
    /// Handle `poll(fds, nfds, timeout)`.
    ///
    /// - `fds_addr`: pointer to array of pollfd structs (8 bytes each).
    /// - `nfds`: number of pollfd entries.
    /// - `timeout_ms`: -1 = block indefinitely, 0 = non-blocking, >0 = ms timeout.
    pub(crate) fn sys_poll(
        &self,
        fds_addr: usize,
        nfds: u32,
        timeout_ms: i32,
    ) -> Result<usize, Errno> {
        let mut set = PollSet::with_capacity(nfds as usize);

        // Read pollfd structs from guest memory.
        // struct pollfd { int fd; short events; short revents; } = 8 bytes
        for i in 0..nfds {
            let base = fds_addr + (i as usize) * 8;
            let fd_ptr: ConstPtr<i32> = ConstPtr::from_usize(base);
            let events_ptr: ConstPtr<i16> = ConstPtr::from_usize(base + 4);

            let fd: i32 = fd_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let events: i16 = events_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;

            if fd < 0 {
                // poll(2): negative fd is ignored, revents set to 0.
                set.add_fd(fd, Events::empty());
            } else {
                set.add_fd(fd, poll_events_to_litebox(events));
            }
        }

        // Compute timeout.
        let timeout = match timeout_ms {
            -1 => None, // block indefinitely
            0 => Some(Duration::ZERO),
            ms => Some(Duration::from_millis(ms as u64)),
        };

        // Wait for events.
        let cx = self.wait_cx().with_timeout(timeout);
        match set.wait(self, &cx) {
            Ok(()) => {}
            Err(WaitError::Interrupted) => return Err(Errno::EINTR),
            Err(WaitError::TimedOut) => {
                // Timeout: scan one final time.
                set.scan(self, None);
            }
        }

        // Write revents back and count ready fds.
        let mut ready_count = 0usize;
        for (i, revents) in set.revents().enumerate() {
            let revents_val = litebox_to_poll_events(revents);
            let base = fds_addr + i * 8;
            let revents_ptr: MutPtr<i16> = MutPtr::from_usize(base + 6);
            revents_ptr
                .write_at_offset(0, revents_val)
                .ok_or(Errno::EFAULT)?;
            if revents_val != 0 {
                ready_count += 1;
            }
        }

        Ok(ready_count)
    }

    /// Handle `select(nfds, readfds, writefds, errorfds, timeout)`.
    ///
    /// - `nfds`: highest fd + 1.
    /// - `readfds_addr`, `writefds_addr`, `errorfds_addr`: pointers to fd_set bitmaps (0 = NULL).
    /// - `timeout_addr`: pointer to timeval struct (0 = NULL = block indefinitely).
    pub(crate) fn sys_select(
        &self,
        nfds: u32,
        readfds_addr: usize,
        writefds_addr: usize,
        errorfds_addr: usize,
        timeout_addr: usize,
    ) -> Result<usize, Errno> {
        if nfds > FD_SETSIZE {
            return Err(Errno::EINVAL);
        }

        // Read timeout: struct timeval { int64 tv_sec; int64 tv_usec; } = 16 bytes.
        let timeout = if timeout_addr == 0 {
            None // block indefinitely
        } else {
            let tv_sec_ptr: ConstPtr<i64> = ConstPtr::from_usize(timeout_addr);
            let tv_usec_ptr: ConstPtr<i64> = ConstPtr::from_usize(timeout_addr + 8);
            let tv_sec: i64 = tv_sec_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let tv_usec: i64 = tv_usec_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            if tv_sec < 0 || tv_usec < 0 {
                return Err(Errno::EINVAL);
            }
            Some(Duration::from_secs(tv_sec as u64) + Duration::from_micros(tv_usec as u64))
        };

        // Read fd_set bitmaps.
        let readfds = read_fd_set(readfds_addr, nfds)?;
        let writefds = read_fd_set(writefds_addr, nfds)?;
        let errorfds = read_fd_set(errorfds_addr, nfds)?;

        // Build PollSet from set bits.
        let mut set = PollSet::with_capacity(nfds as usize);
        for fd in 0..nfds {
            let mut events = Events::empty();
            if is_fd_set(&readfds, fd) {
                events |= Events::IN;
            }
            if is_fd_set(&writefds, fd) {
                events |= Events::OUT;
            }
            if is_fd_set(&errorfds, fd) {
                events |= Events::PRI;
            }
            if !events.is_empty() {
                set.add_fd(fd as i32, events);
            }
        }

        // Wait for events.
        let cx = self.wait_cx().with_timeout(timeout);
        match set.wait(self, &cx) {
            Ok(()) => {}
            Err(WaitError::Interrupted) => return Err(Errno::EINTR),
            Err(WaitError::TimedOut) => {
                // Timeout: scan one final time.
                set.scan(self, None);
            }
        }

        // Build result fd_sets.
        let mut result_readfds = [0u32; FD_SET_INTS];
        let mut result_writefds = [0u32; FD_SET_INTS];
        let mut result_errorfds = [0u32; FD_SET_INTS];
        let mut ready_count = 0usize;

        for (fd, revents) in set.revents_with_fds() {
            if revents.contains(Events::NVAL) {
                return Err(Errno::EBADF);
            }
            let fdu = fd as u32;
            if revents.intersects(Events::IN | Events::ALWAYS_POLLED) && is_fd_set(&readfds, fdu) {
                set_fd_bit(&mut result_readfds, fdu);
                ready_count += 1;
            }
            if revents.intersects(Events::OUT | Events::ALWAYS_POLLED) && is_fd_set(&writefds, fdu)
            {
                set_fd_bit(&mut result_writefds, fdu);
                ready_count += 1;
            }
            if revents.intersects(Events::PRI) && is_fd_set(&errorfds, fdu) {
                set_fd_bit(&mut result_errorfds, fdu);
                ready_count += 1;
            }
        }

        // Write result fd_sets back.
        write_fd_set(readfds_addr, &result_readfds, nfds)?;
        write_fd_set(writefds_addr, &result_writefds, nfds)?;
        write_fd_set(errorfds_addr, &result_errorfds, nfds)?;

        Ok(ready_count)
    }
}
