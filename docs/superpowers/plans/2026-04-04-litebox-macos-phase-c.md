# Phase C: I/O Multiplexing (select/poll/kqueue) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add select, poll, and kqueue/kevent syscall support to `litebox_shim_macos`, enabling guest programs to wait for FD readiness.

**Architecture:** Builds on litebox core's `Pollee`/`IOPollable`/`Observer` infrastructure. `PollSet` (shared by select/poll) resolves FDs to pollable types and does scan/wait loops. `KqueueFile` (modeled after Linux epoll's `EpollFile`) manages persistent interests with a `ReadySet` deque.

**Tech Stack:** Rust (no_std, edition 2024), litebox core event infrastructure, macOS native ABI (aarch64)

---

## File Structure

### Files to CREATE
- `litebox_shim_macos/src/syscalls/poll.rs` — PollSet, PollableRef, resolve_pollable, sys_select, sys_poll
- `litebox_shim_macos/src/syscalls/kqueue.rs` — KqueueFile, KqueueEntry, ReadySet, KqueueKey, sys_kqueue, sys_kevent, constants

### Files to MODIFY
- `litebox_common_macos/src/syscall.rs` — Add syscall number constants + enum variants + decode arms
- `litebox_shim_macos/src/lib.rs` — Add GlobalState fields (kqueues, kqueue_fd_counter, net_proxies) + init
- `litebox_shim_macos/src/syscalls/mod.rs` — Add `mod poll;`, `mod kqueue;`, dispatch arms
- `litebox_shim_macos/src/syscalls/file.rs` — kqueue fallbacks in close/read/write, make fd_to_usize pub(crate), net_proxies cleanup
- `litebox_shim_macos/src/syscalls/net.rs` — modify initialize_inet_socket to also store proxy in net_proxies side table

### Test files to CREATE
- `litebox_runner_macos_on_macos_userland/tests/select.c`
- `litebox_runner_macos_on_macos_userland/tests/poll.c`
- `litebox_runner_macos_on_macos_userland/tests/kqueue.c`
- `litebox_runner_macos_on_macos_userland/tests/select_socket.c`

### Test file to MODIFY
- `litebox_runner_macos_on_macos_userland/tests/loader.rs` — Add 4 new test functions

---

## Workspace Conventions
- Copyright header on all new files: `// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.`
- edition 2024, version 0.1.0
- All crates use `[lints] workspace = true`
- Internal deps use both path and version
- Test C files compiled with `compile_macho_dynamic`, run with `run_macho_dynamic`
- `run_macho_dynamic` returns `(exit_code, Vec::new())` — verify behavior through exit code only (stdout NOT captured)
- Tests run without `#[ignore]`

## Key API References (read these files for context)
- `litebox/src/event/mod.rs` lines 10-51 — Events bitflags, IOPollable trait
- `litebox/src/event/polling.rs` lines 24-130 — Pollee struct, wait(), register_observer()
- `litebox/src/event/observer.rs` lines 25-70 — Observer trait, Subject type
- `litebox/src/event/wait.rs` — WaitState, WaitContext, Waker, WaitError, with_timeout(), wait_until()
- `litebox/src/pipes.rs` lines 167-177 — Pipes::with_iopollable()
- `litebox/src/net/socket_channel.rs` line 168 — NetworkProxy IOPollable impl
- `litebox_shim_linux/src/syscalls/epoll.rs` lines 469-594 — PollSet reference implementation
- `litebox_shim_linux/src/syscalls/epoll.rs` lines 135-465 — EpollFile/ReadySet reference

---

### Task 1: Add syscall number constants + enum variants + decode arms

**Files:**
- Modify: `litebox_common_macos/src/syscall.rs`

This is a mechanical task: add 4 syscall numbers, 4 enum variants, and 4 decode arms.

- [ ] **Step 1: Add syscall number constants**

In `litebox_common_macos/src/syscall.rs`, inside the `pub mod nr` block (after the existing constants around line 84), add:

```rust
pub const SELECT: u64 = 93;
pub const POLL: u64 = 230;
pub const KQUEUE: u64 = 362;
pub const KEVENT: u64 = 363;
```

- [ ] **Step 2: Add enum variants**

In the `pub enum MacosSyscallRequest` (after the existing variants, before `Unknown`), add:

```rust
Select {
    nfds: u32,
    readfds: usize,
    writefds: usize,
    errorfds: usize,
    timeout: usize,
},
Poll {
    fds: usize,
    nfds: u32,
    timeout: i32,
},
Kqueue,
Kevent {
    kq: i32,
    changelist: usize,
    nchanges: i32,
    eventlist: usize,
    nevents: i32,
    timeout: usize,
},
```

- [ ] **Step 3: Add decode arms**

In the `try_from_raw` function's match block (before the wildcard `_` arm at line ~731), add:

```rust
nr::SELECT => MacosSyscallRequest::Select {
    nfds: x0 as u32,
    readfds: x1,
    writefds: x2,
    errorfds: x3,
    timeout: x4,
},
nr::POLL => MacosSyscallRequest::Poll {
    fds: x0,
    nfds: x1 as u32,
    timeout: x2 as i32,
},
nr::KQUEUE => MacosSyscallRequest::Kqueue,
nr::KEVENT => MacosSyscallRequest::Kevent {
    kq: x0 as i32,
    changelist: x1,
    nchanges: x2 as i32,
    eventlist: x3,
    nevents: x4 as i32,
    timeout: x5,
},
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p litebox_common_macos`
Expected: compiles with no errors (warnings OK for unused variants)

- [ ] **Step 5: Commit**

```bash
git add litebox_common_macos/src/syscall.rs
git commit -m "feat(macos): add select/poll/kqueue/kevent syscall numbers and enum variants"
```

---

### Task 2: Add GlobalState fields + net_proxies infrastructure

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs` — add kqueues, kqueue_fd_counter, net_proxies fields + init
- Modify: `litebox_shim_macos/src/syscalls/net.rs` — modify initialize_inet_socket to store proxy in net_proxies
- Modify: `litebox_shim_macos/src/syscalls/file.rs` — add net_proxies cleanup on Network close, make fd_to_usize pub(crate)
- Create: `litebox_shim_macos/src/syscalls/kqueue.rs` — stub file (just the module declaration, actual impl in Task 4)

**Context:** The macOS shim uses `RawDescriptorStorage` which doesn't provide access to `NetworkProxy` metadata needed for polling. We need a side table `net_proxies` keyed by raw fd number that stores `Arc<NetworkProxy>` at socket creation time. We also need `kqueues` and `kqueue_fd_counter` for kqueue FD management.

- [ ] **Step 1: Add imports and fields to GlobalState**

In `litebox_shim_macos/src/lib.rs`, add these fields to the `GlobalState<FS>` struct (after `unix_fd_counter`):

```rust
pub(crate) kqueues: RwLock<BTreeMap<usize, Arc<kqueue::KqueueFile<FS>>>>,
pub(crate) kqueue_fd_counter: AtomicUsize,
pub(crate) net_proxies: RwLock<BTreeMap<usize, Arc<litebox::net::NetworkProxy<Platform>>>>,
```

You will need to add the necessary imports. The `kqueue` module doesn't exist yet, so for now use a forward reference — or create the stub first (Step 2).

- [ ] **Step 2: Create kqueue.rs stub**

Create `litebox_shim_macos/src/syscalls/kqueue.rs` with just:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use litebox::sync::{Mutex, RwLock};

use crate::ShimFS;

/// Placeholder for KqueueFile — full implementation in Task 4.
pub(crate) struct KqueueFile<FS: ShimFS> {
    _marker: core::marker::PhantomData<FS>,
}
```

Add `mod kqueue;` to `litebox_shim_macos/src/syscalls/mod.rs` (after `mod unix;`).

- [ ] **Step 3: Initialize new GlobalState fields**

In the `build()` method in `litebox_shim_macos/src/lib.rs` (around line 253-271), add initialization for the new fields:

```rust
kqueues: RwLock::new(BTreeMap::new()),
kqueue_fd_counter: AtomicUsize::new(0x2_0000),
net_proxies: RwLock::new(BTreeMap::new()),
```

- [ ] **Step 4: Modify initialize_inet_socket to store proxy in net_proxies**

In `litebox_shim_macos/src/syscalls/net.rs`, the `initialize_inet_socket` function (lines 547-556) currently creates a `NetworkProxy` and calls `net.lock().set_socket_proxy(fd, proxy)`. Modify it to ALSO store the proxy in `self.global.net_proxies`:

```rust
fn initialize_inet_socket(&self, fd: i32, sock_type: SockType) {
    let proxy = match sock_type {
        SockType::Stream => {
            litebox::net::NetworkProxy::Stream(
                litebox::net::StreamSocketChannel::new(),
            )
        }
        SockType::Datagram => {
            litebox::net::NetworkProxy::Datagram(
                litebox::net::DatagramSocketChannel::new(),
            )
        }
    };
    let proxy = Arc::new(proxy);
    self.global
        .net_proxies
        .write()
        .insert(fd as usize, proxy.clone());
    self.global
        .net
        .lock()
        .set_socket_proxy(fd, proxy);
}
```

Note: Check the actual types — `NetworkProxy` might use different constructor patterns. Read `litebox/src/net/socket_channel.rs` for the actual API.

- [ ] **Step 5: Make fd_to_usize pub(crate)**

In `litebox_shim_macos/src/syscalls/file.rs`, change `fn fd_to_usize` (line 20) from private to:

```rust
pub(crate) fn fd_to_usize(fd: i32) -> Result<usize, Errno> {
```

- [ ] **Step 6: Add net_proxies cleanup on Network close**

In `litebox_shim_macos/src/syscalls/file.rs`, in the `sys_close` function, find the arm that handles `StrongFd::Network(net)` close. After dropping the network fd, also remove from net_proxies:

```rust
// After the existing Network close logic:
self.global.net_proxies.write().remove(&(fd as usize));
```

- [ ] **Step 7: Verify compilation**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles (warnings OK for unused fields/imports)

- [ ] **Step 8: Commit**

```bash
git add litebox_shim_macos/src/lib.rs litebox_shim_macos/src/syscalls/mod.rs litebox_shim_macos/src/syscalls/kqueue.rs litebox_shim_macos/src/syscalls/net.rs litebox_shim_macos/src/syscalls/file.rs
git commit -m "feat(macos): add GlobalState fields for kqueue/net_proxies, create kqueue stub"
```

---

### Task 3: Create poll.rs — PollSet, PollableRef, sys_select, sys_poll

**Files:**
- Create: `litebox_shim_macos/src/syscalls/poll.rs`
- Modify: `litebox_shim_macos/src/syscalls/mod.rs` — add `mod poll;`

**Context:** This is the largest task. It creates the shared polling infrastructure used by both select and poll syscalls.

**Key references to read:**
- `litebox_shim_linux/src/syscalls/epoll.rs` lines 469-594 — PollSet reference
- `litebox/src/event/mod.rs` — Events bitflags (IN=0x01, OUT=0x04, PRI=0x02, ERR=0x08, HUP=0x10, NVAL=0x20, ALWAYS_POLLED=0x2000)
- `litebox/src/event/mod.rs` lines 37-51 — IOPollable trait (register_observer + check_io_events)
- `litebox/src/event/polling.rs` — Pollee.wait(), Pollee.register_observer()
- `litebox/src/pipes.rs` lines 167-177 — `with_iopollable(fd, callback)`
- `litebox/src/net/socket_channel.rs` — NetworkProxy implements IOPollable
- `litebox_shim_macos/src/syscalls/unix.rs` — UnixSocket (does NOT implement IOPollable)
- `litebox_shim_macos/src/wait.rs` — WaitState, wait_cx()

**Important ABI details:**
- macOS `fd_set`: `[u32; 32]` = 1024-bit bitmap (32 x 32-bit ints, NOT 16 x 64-bit longs like Linux)
- macOS `timeval`: `{ i64 tv_sec; i64 tv_usec; }` = 16 bytes on arm64
- macOS `pollfd`: `{ i32 fd; i16 events; i16 revents; }` = 8 bytes
- Poll constants: POLLIN=0x0001, POLLPRI=0x0002, POLLOUT=0x0004, POLLERR=0x0008, POLLHUP=0x0010, POLLNVAL=0x0020

**Important design decisions:**
- `PollableRef::Unix` is `AlwaysReady` — returns `Events::IN | Events::OUT & mask` (known limitation)
- `PollableRef::Kqueue` delegates to `KqueueFile`'s IOPollable impl (to be added in Task 4)
- `resolve_pollable` is a free function that takes `&Task<FS>` and `fd: i32`
- The PollSet uses a `PollEntryObserver(Waker)` that implements `Observer<Events>` (same as Linux)
- Use `litebox::platform::RawConstPointer` and `litebox::platform::RawMutPointer` traits for pointer operations

- [ ] **Step 1: Add `mod poll;` to mod.rs**

In `litebox_shim_macos/src/syscalls/mod.rs`, add after the `mod unix;` line:

```rust
mod poll;
```

- [ ] **Step 2: Create poll.rs with constants and PollableRef**

Create `litebox_shim_macos/src/syscalls/poll.rs`. Start with:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! I/O multiplexing: select(2) and poll(2) syscall implementations.
//!
//! Uses a shared `PollSet` infrastructure that resolves guest FDs to pollable
//! types and performs scan/wait loops using litebox's `Pollee`/`IOPollable`/`Observer`
//! infrastructure.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use litebox::event::observer::Observer;
use litebox::event::{Events, IOPollable};
use litebox::fd::StrongFd;
use litebox::pipes::Pipes;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::sync::Mutex;
use litebox_common_macos::Errno;
use litebox_platform_multiplex::Platform;

use crate::{ConstPtr, MutPtr, ShimFS, Task};
use super::file::fd_to_usize;

// macOS poll event constants (identical to Events bitflag values)
const POLLIN: i16 = 0x0001;
const POLLPRI: i16 = 0x0002;
const POLLOUT: i16 = 0x0004;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;

/// Maximum number of FDs for select (macOS FD_SETSIZE)
const FD_SETSIZE: u32 = 1024;
/// Number of u32 elements in an fd_set
const FD_SET_INTS: usize = 32;
```

- [ ] **Step 3: Implement PollableRef and resolve_pollable**

Add to poll.rs:

```rust
/// Resolved pollable reference for an FD.
enum PollableRef {
    /// Pipe fd — delegates to Pipes::with_iopollable
    Pipe(i32),
    /// Network socket — uses NetworkProxy from net_proxies side table
    Network(Arc<litebox::net::NetworkProxy<Platform>>),
    /// Unix socket — always ready (does not implement IOPollable)
    Unix,
    /// Regular file, stdin/stdout/stderr — always ready
    AlwaysReady,
    // Kqueue variant will be added in Task 4
}

/// Resolve a guest FD to a pollable type.
///
/// Resolution order:
/// 1. RawDescriptorStorage -> StrongFd::Pipes -> Pipe
/// 2. RawDescriptorStorage -> StrongFd::Network -> Network (via net_proxies)
/// 3. RawDescriptorStorage -> StrongFd::FileSystem -> AlwaysReady
/// 4. global.unix_sockets -> Unix (always ready)
/// 5. None (invalid FD)
fn resolve_pollable<FS: ShimFS>(task: &Task<FS>, fd: i32) -> Option<PollableRef> {
    let fd_usize = fd_to_usize(fd).ok()?;

    // Try RawDescriptorStorage first
    if let Some(strong) = task.global.raw_descriptors.read().get(fd) {
        return Some(match strong {
            StrongFd::Pipes(_) => PollableRef::Pipe(fd),
            StrongFd::Network(_) => {
                // Get the NetworkProxy from the side table
                match task.global.net_proxies.read().get(&fd_usize) {
                    Some(proxy) => PollableRef::Network(proxy.clone()),
                    None => PollableRef::AlwaysReady, // fallback
                }
            }
            StrongFd::FileSystem(_) => PollableRef::AlwaysReady,
        });
    }

    // Try unix sockets
    if task.global.unix_sockets.read().contains_key(&fd_usize) {
        return Some(PollableRef::Unix);
    }

    // Try kqueues (will be added in Task 4)
    // if task.global.kqueues.read().contains_key(&fd_usize) { ... }

    None
}
```

Note: The actual `StrongFd` variants and `RawDescriptorStorage::get()` API need to be verified by reading `litebox/src/fd/mod.rs`. The Linux shim uses `descriptor_table().get(fd)` — the macOS shim uses `raw_descriptors`. Adapt accordingly.

- [ ] **Step 4: Implement PollSet**

Add to poll.rs the `PollSet`, `PollEntry`, and `PollEntryObserver` following the Linux shim's pattern at `litebox_shim_linux/src/syscalls/epoll.rs:469-594`:

```rust
/// Observer that wakes the wait context when events fire.
struct PollEntryObserver(litebox::event::wait::Waker<Platform>);

impl Observer<Events> for PollEntryObserver {
    fn on_events(&self, _events: &Events) {
        self.0.wake();
    }
}

struct PollEntry {
    fd: i32,
    mask: Events,
    revents: Events,
    observer: Option<Arc<PollEntryObserver>>,
}

struct PollSet {
    entries: Vec<PollEntry>,
}

impl PollSet {
    fn with_capacity(n: usize) -> Self {
        Self {
            entries: Vec::with_capacity(n),
        }
    }

    fn add_fd(&mut self, fd: i32, mask: Events) {
        self.entries.push(PollEntry {
            fd,
            mask,
            revents: Events::empty(),
            observer: None,
        });
    }

    /// Single-pass scan: resolve each FD, check events, optionally register observers.
    /// Returns true if any entry has non-empty revents.
    fn scan<FS: ShimFS>(
        &mut self,
        task: &Task<FS>,
        waker: Option<&litebox::event::wait::Waker<Platform>>,
    ) -> bool {
        let mut any_ready = false;
        for entry in &mut self.entries {
            match resolve_pollable(task, entry.fd) {
                None => {
                    entry.revents = Events::NVAL;
                    any_ready = true;
                }
                Some(PollableRef::AlwaysReady | PollableRef::Unix) => {
                    // Always-ready: return requested read/write events
                    entry.revents = (Events::IN | Events::OUT) & entry.mask;
                    if !entry.revents.is_empty() {
                        any_ready = true;
                    }
                }
                Some(PollableRef::Pipe(fd)) => {
                    let result = task.global.pipes.with_iopollable(fd, |pollable| {
                        let events = pollable.check_io_events() & entry.mask;
                        if events.is_empty() {
                            if let Some(w) = waker {
                                if entry.observer.is_none() {
                                    let obs = Arc::new(PollEntryObserver(w.clone()));
                                    pollable.register_observer(
                                        Arc::downgrade(&obs),
                                        entry.mask,
                                    );
                                    entry.observer = Some(obs);
                                }
                            }
                        }
                        events
                    });
                    entry.revents = result.unwrap_or(Events::NVAL);
                    if !entry.revents.is_empty() {
                        any_ready = true;
                    }
                }
                Some(PollableRef::Network(proxy)) => {
                    let events = proxy.check_io_events() & entry.mask;
                    if events.is_empty() {
                        if let Some(w) = waker {
                            if entry.observer.is_none() {
                                let obs = Arc::new(PollEntryObserver(w.clone()));
                                proxy.register_observer(
                                    Arc::downgrade(&obs),
                                    entry.mask,
                                );
                                entry.observer = Some(obs);
                            }
                        }
                    }
                    entry.revents = events;
                    if !entry.revents.is_empty() {
                        any_ready = true;
                    }
                }
            }
        }
        any_ready
    }

    /// Wait for any FD to become ready.
    fn wait<FS: ShimFS>(
        &mut self,
        task: &Task<FS>,
        cx: &litebox::event::wait::WaitContext<Platform>,
    ) -> Result<(), litebox::event::wait::WaitError> {
        // First scan without registering observers
        if self.scan(task, None) {
            return Ok(());
        }
        // Nothing ready — register observers and wait
        cx.wait_until(|| self.scan(task, Some(&cx.waker())))
    }
}
```

- [ ] **Step 5: Implement sys_poll**

Add to poll.rs:

```rust
/// poll(2) syscall implementation.
///
/// Reads pollfd structs from guest memory, builds a PollSet, waits for events,
/// writes revents back.
pub(crate) fn sys_poll<FS: ShimFS>(
    task: &Task<FS>,
    fds_ptr: MutPtr<u8>,
    nfds: u32,
    timeout_ms: i32,
) -> Result<usize, Errno> {
    let nfds = nfds as usize;

    // Read pollfd structs from guest memory (8 bytes each: i32 fd, i16 events, i16 revents)
    let mut pollfds: Vec<(i32, i16)> = Vec::with_capacity(nfds);
    for i in 0..nfds {
        let base = fds_ptr.offset((i * 8) as isize);
        let fd = i32::from_ne_bytes(
            base.read_bytes(4).try_into().map_err(|_| Errno::EFAULT)?,
        );
        let events = i16::from_ne_bytes(
            base.offset(4).read_bytes(2).try_into().map_err(|_| Errno::EFAULT)?,
        );
        pollfds.push((fd, events));
    }

    // Build PollSet
    let mut poll_set = PollSet::with_capacity(nfds);
    for &(fd, events) in &pollfds {
        if fd < 0 {
            // POSIX: negative fd means skip this entry
            continue;
        }
        let mask = poll_events_to_litebox(events);
        poll_set.add_fd(fd, mask);
    }

    // Wait with timeout
    let cx = task.wait_state.wait_cx();
    let result = if timeout_ms < 0 {
        // Block indefinitely
        poll_set.wait(task, &cx)
    } else if timeout_ms == 0 {
        // Non-blocking: just scan once
        poll_set.scan(task, None);
        Ok(())
    } else {
        // Timeout in milliseconds
        let timeout_cx = cx.with_timeout(Duration::from_millis(timeout_ms as u64));
        let r = poll_set.wait(task, &timeout_cx);
        if matches!(r, Err(litebox::event::wait::WaitError::TimedOut)) {
            // Final scan after timeout
            poll_set.scan(task, None);
            Ok(())
        } else {
            r
        }
    };

    if let Err(e) = result {
        if !matches!(e, litebox::event::wait::WaitError::TimedOut) {
            return Err(Errno::EINTR);
        }
    }

    // Write revents back and count ready fds
    let mut count = 0usize;
    let mut poll_idx = 0usize;
    for (i, &(fd, _events)) in pollfds.iter().enumerate() {
        let base = fds_ptr.offset((i * 8) as isize);
        if fd < 0 {
            // Write revents = 0 for negative fd entries
            let zero: i16 = 0;
            base.offset(6).write_bytes(&zero.to_ne_bytes());
            continue;
        }
        let revents = litebox_to_poll_events(poll_set.entries[poll_idx].revents);
        base.offset(6).write_bytes(&revents.to_ne_bytes());
        if revents != 0 {
            count += 1;
        }
        poll_idx += 1;
    }

    Ok(count)
}

/// Convert macOS poll event bits to litebox Events
fn poll_events_to_litebox(events: i16) -> Events {
    let mut result = Events::empty();
    if events & POLLIN != 0 {
        result |= Events::IN;
    }
    if events & POLLOUT != 0 {
        result |= Events::OUT;
    }
    if events & POLLPRI != 0 {
        result |= Events::PRI;
    }
    // ERR, HUP, NVAL are output-only but always polled
    result |= Events::ALWAYS_POLLED;
    result
}

/// Convert litebox Events to macOS poll event bits
fn litebox_to_poll_events(events: Events) -> i16 {
    let mut result: i16 = 0;
    if events.contains(Events::IN) {
        result |= POLLIN;
    }
    if events.contains(Events::OUT) {
        result |= POLLOUT;
    }
    if events.contains(Events::PRI) {
        result |= POLLPRI;
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
```

- [ ] **Step 6: Implement sys_select**

Add to poll.rs:

```rust
/// select(2) syscall implementation.
///
/// Reads fd_set bitmaps from guest memory, builds a PollSet, waits for events,
/// writes results back to bitmaps.
pub(crate) fn sys_select<FS: ShimFS>(
    task: &Task<FS>,
    nfds: u32,
    readfds_addr: usize,
    writefds_addr: usize,
    errorfds_addr: usize,
    timeout_addr: usize,
) -> Result<usize, Errno> {
    if nfds > FD_SETSIZE {
        return Err(Errno::EINVAL);
    }

    // Read timeout
    let timeout = if timeout_addr == 0 {
        None // block indefinitely
    } else {
        let tv_ptr = ConstPtr::<u8>::from_raw(timeout_addr);
        let tv_sec = i64::from_ne_bytes(
            tv_ptr.read_bytes(8).try_into().map_err(|_| Errno::EFAULT)?,
        );
        let tv_usec = i64::from_ne_bytes(
            tv_ptr.offset(8).read_bytes(8).try_into().map_err(|_| Errno::EFAULT)?,
        );
        if tv_sec < 0 || tv_usec < 0 {
            return Err(Errno::EINVAL);
        }
        Some(Duration::from_secs(tv_sec as u64) + Duration::from_micros(tv_usec as u64))
    };

    // Read fd_set bitmaps (each is [u32; 32] = 128 bytes)
    let read_bits = read_fd_set(readfds_addr, nfds)?;
    let write_bits = read_fd_set(writefds_addr, nfds)?;
    let error_bits = read_fd_set(errorfds_addr, nfds)?;

    // Build PollSet from all set bits
    let mut poll_set = PollSet::with_capacity(nfds as usize);
    let mut fd_masks: Vec<(i32, Events)> = Vec::new();

    for fd in 0..nfds as i32 {
        let mut mask = Events::empty();
        if is_fd_set(&read_bits, fd) {
            mask |= Events::IN;
        }
        if is_fd_set(&write_bits, fd) {
            mask |= Events::OUT;
        }
        if is_fd_set(&error_bits, fd) {
            mask |= Events::PRI;
        }
        if !mask.is_empty() {
            mask |= Events::ALWAYS_POLLED;
            poll_set.add_fd(fd, mask);
            fd_masks.push((fd, mask));
        }
    }

    // Wait with timeout
    let cx = task.wait_state.wait_cx();
    let result = match timeout {
        None => poll_set.wait(task, &cx),
        Some(d) if d.is_zero() => {
            poll_set.scan(task, None);
            Ok(())
        }
        Some(d) => {
            let timeout_cx = cx.with_timeout(d);
            let r = poll_set.wait(task, &timeout_cx);
            if matches!(r, Err(litebox::event::wait::WaitError::TimedOut)) {
                poll_set.scan(task, None);
                Ok(())
            } else {
                r
            }
        }
    };

    if let Err(e) = result {
        if !matches!(e, litebox::event::wait::WaitError::TimedOut) {
            return Err(Errno::EINTR);
        }
    }

    // Process results: clear all bitmaps, set bits for ready FDs
    let mut out_read = [0u32; FD_SET_INTS];
    let mut out_write = [0u32; FD_SET_INTS];
    let mut out_error = [0u32; FD_SET_INTS];
    let mut count = 0usize;

    for (i, &(fd, mask)) in fd_masks.iter().enumerate() {
        let revents = poll_set.entries[i].revents;
        if revents.contains(Events::NVAL) {
            return Err(Errno::EBADF);
        }

        let mut fd_counted = false;

        // Read readiness: IN, or ERR/HUP (readable when error/hangup)
        if mask.contains(Events::IN)
            && revents.intersects(Events::IN | Events::ERR | Events::HUP)
        {
            set_fd_bit(&mut out_read, fd);
            fd_counted = true;
        }

        // Write readiness: OUT, or ERR/HUP
        if mask.contains(Events::OUT)
            && revents.intersects(Events::OUT | Events::ERR | Events::HUP)
        {
            set_fd_bit(&mut out_write, fd);
            fd_counted = true;
        }

        // Error readiness: PRI
        if mask.contains(Events::PRI) && revents.contains(Events::PRI) {
            set_fd_bit(&mut out_error, fd);
            fd_counted = true;
        }

        if fd_counted {
            count += 1;
        }
    }

    // Write results back to guest memory
    write_fd_set(readfds_addr, &out_read, nfds)?;
    write_fd_set(writefds_addr, &out_write, nfds)?;
    write_fd_set(errorfds_addr, &out_error, nfds)?;

    Ok(count)
}

// fd_set helper functions

fn read_fd_set(addr: usize, nfds: u32) -> Result<[u32; FD_SET_INTS], Errno> {
    if addr == 0 {
        return Ok([0u32; FD_SET_INTS]);
    }
    let ptr = ConstPtr::<u8>::from_raw(addr);
    let n_ints = ((nfds + 31) / 32) as usize;
    let mut bits = [0u32; FD_SET_INTS];
    for i in 0..n_ints {
        bits[i] = u32::from_ne_bytes(
            ptr.offset((i * 4) as isize)
                .read_bytes(4)
                .try_into()
                .map_err(|_| Errno::EFAULT)?,
        );
    }
    Ok(bits)
}

fn write_fd_set(addr: usize, bits: &[u32; FD_SET_INTS], nfds: u32) -> Result<(), Errno> {
    if addr == 0 {
        return Ok(());
    }
    let ptr = MutPtr::<u8>::from_raw(addr);
    let n_ints = ((nfds + 31) / 32) as usize;
    for i in 0..n_ints {
        ptr.offset((i * 4) as isize).write_bytes(&bits[i].to_ne_bytes());
    }
    Ok(())
}

fn is_fd_set(bits: &[u32; FD_SET_INTS], fd: i32) -> bool {
    let idx = fd as usize / 32;
    let bit = fd as usize % 32;
    bits[idx] & (1 << bit) != 0
}

fn set_fd_bit(bits: &mut [u32; FD_SET_INTS], fd: i32) {
    let idx = fd as usize / 32;
    let bit = fd as usize % 32;
    bits[idx] |= 1 << bit;
}
```

- [ ] **Step 7: Verify compilation**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles. Fix any type errors by reading the actual API from the referenced files.

- [ ] **Step 8: Commit**

```bash
git add litebox_shim_macos/src/syscalls/poll.rs litebox_shim_macos/src/syscalls/mod.rs
git commit -m "feat(macos): implement PollSet, PollableRef, sys_select, sys_poll"
```

---

### Task 4: Implement KqueueFile, KqueueEntry, ReadySet, sys_kqueue, sys_kevent

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/kqueue.rs` — replace stub with full implementation

**Context:** This replaces the stub from Task 2 with the full kqueue implementation, modeled after the Linux epoll's `EpollFile`. The `KqueueFile` manages persistent interests with a `ReadySet` deque and supports `EV_ADD`, `EV_DELETE`, `EV_ONESHOT`, `EV_CLEAR`.

**Key references to read:**
- `litebox_shim_linux/src/syscalls/epoll.rs` lines 135-465 — EpollFile, ReadySet, EpollEntry (the model)
- `litebox/src/event/observer.rs` — Observer trait, Subject type
- `litebox/src/event/wait.rs` — WaitContext, Waker, wait_until(), with_timeout()
- Design spec section "KqueueFile — Persistent Event Notification"

**Key design decisions:**
- `KqueueKey { ident: usize, filter: i16 }` is the key for interests BTreeMap
- `KqueueEntry` implements `Observer<Events>` — on matching events, pushes self to ReadySet
- `ReadySet` has a `Pollee` so KqueueFile itself can be polled (by select/poll/other kqueues)
- Use `Arc::new_cyclic` for self-referential `weak_self` in entries
- Kevent struct is 32 bytes on arm64: `{ uintptr_t ident; int16_t filter; uint16_t flags; uint32_t fflags; intptr_t data; void *udata; }`
- `KqueueFile` should implement `IOPollable` so it can be polled by PollSet

**Constants:**
- EVFILT_READ = -1i16, EVFILT_WRITE = -2i16
- EV_ADD = 0x0001u16, EV_DELETE = 0x0002u16, EV_ENABLE = 0x0004u16, EV_DISABLE = 0x0008u16
- EV_ONESHOT = 0x0010u16, EV_CLEAR = 0x0020u16, EV_EOF = 0x8000u16, EV_ERROR = 0x4000u16

- [ ] **Step 1: Write constants and KqueueKey**

Replace the kqueue.rs stub with the full file header, constants, and key type.

- [ ] **Step 2: Write KqueueEntry with Observer impl**

Implement `KqueueEntry<FS>` with `Observer<Events>` that pushes to `ReadySet` on matching events.

- [ ] **Step 3: Write ReadySet**

Implement `ReadySet<FS>` with `push()`, `pop_multiple()`, and `Pollee` for self-polling.

- [ ] **Step 4: Write KqueueFile with IOPollable impl**

Implement `KqueueFile<FS>` with `add_interest()`, `delete_interest()`, `wait()`, `close()`, and `IOPollable` impl.

- [ ] **Step 5: Write sys_kqueue**

```rust
pub(crate) fn sys_kqueue<FS: ShimFS>(task: &Task<FS>) -> Result<usize, Errno> {
    let kq = Arc::new(KqueueFile::new());
    let fd = task.global.kqueue_fd_counter.fetch_add(1, Ordering::Relaxed);
    task.global.kqueues.write().insert(fd, kq);
    Ok(fd)
}
```

- [ ] **Step 6: Write sys_kevent**

Two-phase: process changelist (EV_ADD/DELETE/ENABLE/DISABLE), then wait for events.

Read changelist from guest memory (32 bytes per kevent), process changes, then if nevents > 0, wait and write results back.

- [ ] **Step 7: Verify compilation**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles

- [ ] **Step 8: Commit**

```bash
git add litebox_shim_macos/src/syscalls/kqueue.rs
git commit -m "feat(macos): implement KqueueFile, ReadySet, sys_kqueue, sys_kevent"
```

---

### Task 5: Add dispatch arms + kqueue fallbacks + integration wiring

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/mod.rs` — add dispatch arms for Select, Poll, Kqueue, Kevent
- Modify: `litebox_shim_macos/src/syscalls/file.rs` — add kqueue fallbacks in sys_close, sys_read, sys_write
- Modify: `litebox_shim_macos/src/syscalls/poll.rs` — add Kqueue variant to PollableRef + resolve_pollable

**Context:** This wires everything together: dispatch arms in the main syscall handler, kqueue FD handling in file operations, and kqueue support in the polling infrastructure.

- [ ] **Step 1: Add dispatch arms in mod.rs**

In `litebox_shim_macos/src/syscalls/mod.rs`, in the `do_syscall` match block (before `Unknown`), add:

```rust
MacosSyscallRequest::Select { nfds, readfds, writefds, errorfds, timeout } => {
    poll::sys_select(self, nfds, readfds, writefds, errorfds, timeout)
}
MacosSyscallRequest::Poll { fds, nfds, timeout } => {
    poll::sys_poll(self, MutPtr::from_raw(fds), nfds, timeout)
}
MacosSyscallRequest::Kqueue => {
    kqueue::sys_kqueue(self)
}
MacosSyscallRequest::Kevent { kq, changelist, nchanges, eventlist, nevents, timeout } => {
    kqueue::sys_kevent(self, kq, changelist, nchanges, eventlist, nevents, timeout)
}
```

- [ ] **Step 2: Add kqueue fallback in sys_close**

In `litebox_shim_macos/src/syscalls/file.rs`, in `sys_close` (after the unix socket close fallback), add:

```rust
// Try kqueue
if let Some(kq) = self.global.kqueues.write().remove(&(fd as usize)) {
    kq.close();
    return Ok(());
}
```

- [ ] **Step 3: Add kqueue fallback in sys_read**

In `sys_read`, after the unix socket read attempt, add:

```rust
// kqueue FDs are not readable
if self.global.kqueues.read().contains_key(&(fd as usize)) {
    return Err(Errno::EBADF);
}
```

- [ ] **Step 4: Add kqueue fallback in sys_write**

In `sys_write`, after the unix socket write attempt, add:

```rust
// kqueue FDs are not writable
if self.global.kqueues.read().contains_key(&(fd as usize)) {
    return Err(Errno::EBADF);
}
```

- [ ] **Step 5: Add Kqueue variant to PollableRef in poll.rs**

Update `PollableRef` to include a Kqueue variant and update `resolve_pollable` to check kqueues.

- [ ] **Step 6: Run existing tests for regression check**

Run: `cargo test -p litebox_runner_macos_on_macos_userland`
Expected: all 15 existing tests pass (0 failures)

- [ ] **Step 7: Run clippy**

Run: `cargo clippy -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland -- -D warnings`
Expected: no errors

- [ ] **Step 8: Commit**

```bash
git add litebox_shim_macos/src/syscalls/mod.rs litebox_shim_macos/src/syscalls/file.rs litebox_shim_macos/src/syscalls/poll.rs
git commit -m "feat(macos): wire select/poll/kqueue dispatch arms and kqueue fallbacks"
```

---

### Task 6: End-to-end test — test_select

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/select.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

**Context:** Self-pipe pattern test for select(2). Uses existing `compile_macho_dynamic` and `run_macho_dynamic` infrastructure. Verify behavior through exit code only (stdout NOT captured).

- [ ] **Step 1: Write select.c**

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <sys/select.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) return 1;

    // Write to make read end readable
    const char *msg = "hello";
    if (write(fds[1], msg, 5) != 5) return 2;

    // Test 1: select on read end should report readable
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fds[0], &readfds);
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

    int ret = select(fds[0] + 1, &readfds, (fd_set *)0, (fd_set *)0, &tv);
    if (ret != 1) return 10;
    if (!FD_ISSET(fds[0], &readfds)) return 11;

    // Test 2: select on write end for readability with zero timeout should return 0
    // (write end is not readable)
    fd_set readfds2;
    FD_ZERO(&readfds2);
    FD_SET(fds[1], &readfds2);
    struct timeval tv2 = { .tv_sec = 0, .tv_usec = 0 };

    ret = select(fds[1] + 1, &readfds2, (fd_set *)0, (fd_set *)0, &tv2);
    if (ret != 0) return 20;

    // Test 3: select on write end for writability should report writable
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(fds[1], &writefds);
    struct timeval tv3 = { .tv_sec = 1, .tv_usec = 0 };

    ret = select(fds[1] + 1, (fd_set *)0, &writefds, (fd_set *)0, &tv3);
    if (ret != 1) return 30;
    if (!FD_ISSET(fds[1], &writefds)) return 31;

    close(fds[0]);
    close(fds[1]);
    return 0;
}
```

- [ ] **Step 2: Add test function to loader.rs**

```rust
#[test]
fn test_select() {
    let binary = compile_macho_dynamic(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/select.c"),
    );
    let (exit_code, _stdout) = run_macho_dynamic(&binary);
    assert_eq!(exit_code, 0, "select test failed with exit code {exit_code}");
}
```

- [ ] **Step 3: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_select -- --nocapture`
Expected: PASS with exit code 0

- [ ] **Step 4: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/select.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add select end-to-end test"
```

---

### Task 7: End-to-end test — test_poll

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/poll.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

- [ ] **Step 1: Write poll.c**

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <poll.h>
#include <unistd.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) return 1;

    // Write data to make read end readable
    if (write(fds[1], "data", 4) != 4) return 2;

    // Test 1: poll read end for POLLIN — should be ready
    struct pollfd pfd = { .fd = fds[0], .events = POLLIN, .revents = 0 };
    int ret = poll(&pfd, 1, 0);
    if (ret != 1) return 10;
    if (!(pfd.revents & POLLIN)) return 11;

    // Test 2: poll write end for POLLOUT — pipe not full, should be ready
    struct pollfd pfd2 = { .fd = fds[1], .events = POLLOUT, .revents = 0 };
    ret = poll(&pfd2, 1, 0);
    if (ret != 1) return 20;
    if (!(pfd2.revents & POLLOUT)) return 21;

    // Test 3: create fresh pipe, poll read end with timeout=0 — nothing to read
    int fds2[2];
    if (pipe(fds2) != 0) return 3;
    struct pollfd pfd3 = { .fd = fds2[0], .events = POLLIN, .revents = 0 };
    ret = poll(&pfd3, 1, 0);
    if (ret != 0) return 30;

    close(fds[0]);
    close(fds[1]);
    close(fds2[0]);
    close(fds2[1]);
    return 0;
}
```

- [ ] **Step 2: Add test function to loader.rs**

```rust
#[test]
fn test_poll() {
    let binary = compile_macho_dynamic(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/poll.c"),
    );
    let (exit_code, _stdout) = run_macho_dynamic(&binary);
    assert_eq!(exit_code, 0, "poll test failed with exit code {exit_code}");
}
```

- [ ] **Step 3: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_poll -- --nocapture`
Expected: PASS with exit code 0

- [ ] **Step 4: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/poll.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add poll end-to-end test"
```

---

### Task 8: End-to-end test — test_kqueue

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/kqueue.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

- [ ] **Step 1: Write kqueue.c**

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) return 1;

    // Write data to make read end readable
    if (write(fds[1], "test", 4) != 4) return 2;

    // Create kqueue
    int kq = kqueue();
    if (kq < 0) return 3;

    // Test 1: Register EVFILT_READ on read end, wait for event
    struct kevent change;
    EV_SET(&change, fds[0], EVFILT_READ, EV_ADD, 0, 0, (void *)0);
    if (kevent(kq, &change, 1, (struct kevent *)0, 0, (struct timespec *)0) < 0) return 10;

    struct kevent event;
    struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
    int ret = kevent(kq, (struct kevent *)0, 0, &event, 1, &timeout);
    if (ret != 1) return 11;
    if ((int)event.ident != fds[0]) return 12;
    if (event.filter != EVFILT_READ) return 13;

    // Test 2: EVFILT_WRITE on write end — pipe not full, should fire
    struct kevent change2;
    EV_SET(&change2, fds[1], EVFILT_WRITE, EV_ADD, 0, 0, (void *)0);
    if (kevent(kq, &change2, 1, (struct kevent *)0, 0, (struct timespec *)0) < 0) return 20;

    struct kevent event2;
    ret = kevent(kq, (struct kevent *)0, 0, &event2, 1, &timeout);
    if (ret != 1) return 21;
    if ((int)event2.ident != fds[1]) return 22;
    if (event2.filter != EVFILT_WRITE) return 23;

    // Test 3: EV_DELETE — remove read interest, verify no longer fires
    struct kevent change3;
    EV_SET(&change3, fds[0], EVFILT_READ, EV_DELETE, 0, 0, (void *)0);
    if (kevent(kq, &change3, 1, (struct kevent *)0, 0, (struct timespec *)0) < 0) return 30;

    // Only write interest should remain — poll with short timeout
    struct kevent events[2];
    struct timespec short_timeout = { .tv_sec = 0, .tv_nsec = 0 };
    ret = kevent(kq, (struct kevent *)0, 0, events, 2, &short_timeout);
    // Should get 1 event (write end only, read interest was deleted)
    if (ret != 1) return 31;
    if ((int)events[0].ident != fds[1]) return 32;

    close(kq);
    close(fds[0]);
    close(fds[1]);
    return 0;
}
```

- [ ] **Step 2: Add test function to loader.rs**

```rust
#[test]
fn test_kqueue() {
    let binary = compile_macho_dynamic(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kqueue.c"),
    );
    let (exit_code, _stdout) = run_macho_dynamic(&binary);
    assert_eq!(exit_code, 0, "kqueue test failed with exit code {exit_code}");
}
```

- [ ] **Step 3: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_kqueue -- --nocapture`
Expected: PASS with exit code 0

- [ ] **Step 4: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/kqueue.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add kqueue end-to-end test"
```

---

### Task 9: End-to-end test — test_select_socket

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/select_socket.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

**Context:** Integration test across Phase B (sockets) and Phase C (select). TCP server/client with select for readability.

- [ ] **Step 1: Write select_socket.c**

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    // Create TCP server socket
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return 1;

    // Bind to loopback
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0; // let kernel assign port
    addr.sin_addr.s_addr = 0x0100007f; // 127.0.0.1 in network byte order (little-endian stored)

    // Actually we need htons for port and htonl for addr
    // On little-endian arm64: htonl(INADDR_LOOPBACK) = 0x7f000001 byte-swapped
    // Use raw bytes: 127.0.0.1 = 0x7f, 0x00, 0x00, 0x01
    unsigned char *ip = (unsigned char *)&addr.sin_addr;
    ip[0] = 127; ip[1] = 0; ip[2] = 0; ip[3] = 1;

    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 2;
    if (listen(server, 1) < 0) return 3;

    // Get assigned port
    struct sockaddr_in bound_addr;
    unsigned int addrlen = sizeof(bound_addr);
    if (getsockname(server, (struct sockaddr *)&bound_addr, &addrlen) < 0) return 4;

    // Create client socket and connect
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0) return 5;

    struct sockaddr_in connect_addr;
    memset(&connect_addr, 0, sizeof(connect_addr));
    connect_addr.sin_family = AF_INET;
    connect_addr.sin_port = bound_addr.sin_port;
    connect_addr.sin_addr = bound_addr.sin_addr;

    if (connect(client, (struct sockaddr *)&connect_addr, sizeof(connect_addr)) < 0) return 6;

    // Accept on server side
    int accepted = accept(server, (struct sockaddr *)0, (unsigned int *)0);
    if (accepted < 0) return 7;

    // Write from client
    const char *msg = "hi";
    if (write(client, msg, 2) != 2) return 8;

    // Select on accepted fd for readability
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(accepted, &readfds);
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

    int ret = select(accepted + 1, &readfds, (fd_set *)0, (fd_set *)0, &tv);
    if (ret != 1) return 10;
    if (!FD_ISSET(accepted, &readfds)) return 11;

    // Read and verify
    char buf[16];
    int n = (int)read(accepted, buf, sizeof(buf));
    if (n != 2) return 12;
    if (buf[0] != 'h' || buf[1] != 'i') return 13;

    close(accepted);
    close(client);
    close(server);
    return 0;
}
```

- [ ] **Step 2: Add test function to loader.rs**

```rust
#[test]
fn test_select_socket() {
    let binary = compile_macho_dynamic(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/select_socket.c"),
    );
    let (exit_code, _stdout) = run_macho_dynamic(&binary);
    assert_eq!(exit_code, 0, "select_socket test failed with exit code {exit_code}");
}
```

- [ ] **Step 3: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_select_socket -- --nocapture`
Expected: PASS with exit code 0

- [ ] **Step 4: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/select_socket.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add select+TCP integration end-to-end test"
```

---

### Task 10: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run all tests**

Run: `cargo test -p litebox_runner_macos_on_macos_userland`
Expected: 19 tests passed (15 existing + 4 new), 0 failures

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland -- -D warnings`
Expected: no errors

- [ ] **Step 3: Run fmt check**

Run: `cargo fmt --check -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland`
Expected: no formatting issues

- [ ] **Step 4: Verify git status is clean**

Run: `git status`
Expected: working tree clean, all changes committed
