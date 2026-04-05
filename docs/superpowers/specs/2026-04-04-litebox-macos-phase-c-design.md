# Phase C Design: I/O Multiplexing (select/poll/kqueue)

## Overview

Phase C adds I/O multiplexing syscalls to `litebox_shim_macos`, enabling guest programs to
wait for readiness on file descriptors. This covers three macOS syscalls: `select`, `poll`,
and `kqueue`/`kevent`.

The implementation builds on the core litebox library's existing `Pollee`/`IOPollable`/`Observer`
infrastructure and follows the Linux shim's proven `PollSet` and `EpollFile` patterns, adapted
for macOS semantics.

## Scope

**In scope:**
- `select` (syscall 93) — POSIX fd_set-based multiplexing
- `poll` (syscall 230) — POSIX pollfd-based multiplexing
- `kqueue` (syscall 362) — create a kqueue descriptor
- `kevent` (syscall 363) — register interests and wait for events
- kqueue filters: `EVFILT_READ` (-1) and `EVFILT_WRITE` (-2) only

**Out of scope (future work):**
- `kevent64` (syscall 369)
- `pselect` (syscall 394)
- `ppoll` (not native on macOS)
- kqueue filters: `EVFILT_TIMER`, `EVFILT_VNODE`, `EVFILT_PROC`, `EVFILT_USER`, etc.
- Process lifecycle (fork/exec/waitpid) — deferred to a future phase

## Syscall Surface

| Syscall | macOS Number | Guest Signature |
|---------|-------------|-----------------|
| `select` | 93 | `select(nfds: i32, readfds: *mut fd_set, writefds: *mut fd_set, errorfds: *mut fd_set, timeout: *mut timeval) -> i32` |
| `poll` | 230 | `poll(fds: *mut pollfd, nfds: u32, timeout: i32) -> i32` |
| `kqueue` | 362 | `kqueue() -> i32` |
| `kevent` | 363 | `kevent(kq: i32, changelist: *const kevent, nchanges: i32, eventlist: *mut kevent, nevents: i32, timeout: *const timespec) -> i32` |

### macOS ABI Details

**`fd_set`** — 1024-bit bitmap using `int32` elements (vs Linux `unsigned long`):
```c
struct fd_set {
    __int32_t fds_bits[32];  // 32 * 32 = 1024 bits
};
```

**`timeval`** — used by `select`:
```c
struct timeval {
    long tv_sec;    // 8 bytes on arm64
    long tv_usec;   // 8 bytes on arm64
};
```

**`pollfd`** — identical to Linux:
```c
struct pollfd {
    int   fd;       // 4 bytes
    short events;   // 2 bytes — requested events
    short revents;  // 2 bytes — returned events
};
// Total: 8 bytes
```

**`struct kevent`** — 32 bytes on arm64:
```c
struct kevent {
    uintptr_t  ident;    // 8 bytes — FD number
    int16_t    filter;   // 2 bytes — EVFILT_READ or EVFILT_WRITE
    uint16_t   flags;    // 2 bytes — EV_ADD, EV_DELETE, etc.
    uint32_t   fflags;   // 4 bytes — filter-specific flags (unused for read/write)
    intptr_t   data;     // 8 bytes — filter-specific data
    void      *udata;    // 8 bytes — opaque user pointer
};
```

## Architecture

### PollSet — Shared Infrastructure for select and poll

A direct port of the Linux shim's `PollSet` pattern, adapted for the macOS shim's
FD resolution.

```rust
struct PollSet {
    entries: Vec<PollEntry>,
}

struct PollEntry {
    fd: i32,
    mask: Events,       // what events we're interested in
    revents: Events,    // what events occurred
}
```

**Core methods:**
- `with_capacity(n) -> Self`
- `add_fd(fd: i32, mask: Events)` — add an FD with interest mask
- `scan(&mut self, task: &Task<FS>)` — single-pass: resolve each FD to a pollable
  type, call `check_io_events()`, set `revents`. Invalid FDs get `Events::NVAL`.
- `wait(&mut self, task: &Task<FS>, cx: &WaitContext) -> Result<(), WaitError>` —
  scan once; if any revents non-zero, return. Otherwise register a temporary observer
  on each FD's `Pollee`, wait until woken, re-scan, unregister.
- `revents() -> impl Iterator<Item = Events>` — iterate results

### PollableRef — FD-to-IOPollable Resolution

```rust
enum PollableRef<FS: ShimFS> {
    Pipe(Arc<TypedFd<Pipes<Platform>>>),
    Network(Arc<TypedFd<Network<Platform>>>),
    Unix(Arc<UnixSocket<FS>>),
    Kqueue(Arc<KqueueFile<FS>>),
    AlwaysReady,  // regular files, stdin/stdout/stderr
}
```

A new method on `Task<FS>`:
```rust
fn resolve_pollable(&self, fd: i32) -> Option<PollableRef<FS>>
```

Resolution order (matches existing `StrongFd::from_raw` pattern + unix/kqueue fallbacks):
1. `RawDescriptorStorage` -> `StrongFd::Pipes` -> `PollableRef::Pipe`
2. `RawDescriptorStorage` -> `StrongFd::Network` -> `PollableRef::Network`
3. `RawDescriptorStorage` -> `StrongFd::FileSystem` -> `PollableRef::AlwaysReady`
4. `global.unix_sockets` -> `PollableRef::Unix`
5. `global.kqueues` -> `PollableRef::Kqueue`
6. `None` (invalid FD -> `Events::NVAL`)

Each variant delegates `check_io_events()` and `register_observer()` to the
underlying type. `TypedFd<Pipes>` and `TypedFd<Network>` are `IOPollable` directly.
`AlwaysReady` returns `Events::IN | Events::OUT` immediately and no-ops for
observer registration.

### KqueueFile — Persistent Event Notification

Modeled after the Linux shim's `EpollFile`, adapted for kqueue semantics.

```rust
struct KqueueFile<FS: ShimFS> {
    interests: Mutex<BTreeMap<KqueueKey, Arc<KqueueEntry<FS>>>>,
    ready: Arc<ReadySet<FS>>,
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
struct KqueueKey {
    ident: usize,   // FD number
    filter: i16,    // EVFILT_READ or EVFILT_WRITE
}
```

**KqueueEntry:**
```rust
struct KqueueEntry<FS: ShimFS> {
    key: KqueueKey,
    flags: u16,              // EV_ADD, EV_ONESHOT, EV_CLEAR, etc.
    fflags: u32,
    data: isize,
    udata: usize,            // opaque user pointer, passed through
    pollable: PollableRef<FS>,
    ready: Arc<ReadySet<FS>>,
    is_ready: AtomicBool,
    is_enabled: AtomicBool,
    weak_self: Weak<Self>,
}
```

Implements `Observer<Events>`: when `on_events()` fires with matching events
(`Events::IN` for `EVFILT_READ`, `Events::OUT` for `EVFILT_WRITE`), pushes self
to the `ReadySet`.

**ReadySet** (identical pattern to Linux epoll):
```rust
struct ReadySet<FS: ShimFS> {
    entries: Mutex<VecDeque<Weak<KqueueEntry<FS>>>>,
    pollee: Pollee<Platform>,
}
```
- `push(entry)` — marks ready, pushes to deque, notifies pollee with `Events::IN`
- `pop_multiple(nevents) -> Vec<kevent>` — pops entries, polls current events,
  handles `EV_ONESHOT` (removes after fire) and `EV_CLEAR` (resets ready state)

**KqueueFile as IOPollable:** returns `Events::IN` if ready deque is non-empty.
Allows kqueues to be polled by select/poll/other kqueues.

### kqueue FD Namespace

Kqueue FDs use a separate virtual namespace starting at `0x2_0000` (131072),
avoiding collision with unix socket FDs at `0x1_0000`. Tracked in:
```rust
// New GlobalState fields
kqueues: RwLock<BTreeMap<usize, Arc<KqueueFile<FS>>>>,
kqueue_fd_counter: AtomicUsize,  // starts at 0x2_0000
```

## Syscall Implementations

### sys_select

```
sys_select(nfds: u32, readfds: Option<MutPtr<u32>>, writefds: Option<MutPtr<u32>>,
           errorfds: Option<MutPtr<u32>>, timeout: Option<ConstPtr<u8>>)
           -> Result<usize, Errno>
```

1. Validate `nfds <= 1024` (FD_SETSIZE). Return `EINVAL` if exceeded.
2. Read timeout from guest memory if provided. Convert `timeval` to `Duration`.
   Zero timeout = non-blocking scan. NULL = block indefinitely.
3. Copy `fd_set` bitmaps from guest memory into local `[u32; 32]` arrays.
4. Build `PollSet`: iterate set bits, mapping readfds to `Events::IN | Events::ALWAYS_POLLED`,
   writefds to `Events::OUT | Events::ALWAYS_POLLED`, errorfds to `Events::PRI`.
5. Call `poll_set.wait(task, cx.with_timeout(timeout))`.
6. On `WaitError::TimedOut`, do a final `poll_set.scan()`.
7. Process results: clear all bitmaps, set bits for ready FDs.
   `Events::NVAL` returns `EBADF`. `Events::ERR | Events::HUP` count for
   readfds and writefds.
8. Copy result bitmaps back to guest memory.
9. Return count of ready FDs.

### sys_poll

```
sys_poll(fds: MutPtr<u8>, nfds: u32, timeout: i32) -> Result<usize, Errno>
```

1. Read `nfds` `pollfd` structs from guest memory (8 bytes each).
2. Build `PollSet`: for each pollfd, add `(fd, events_mask)`.
   FDs with `fd < 0` are skipped (POSIX: ignore them, set `revents = 0`).
3. Convert timeout: `-1` = block indefinitely, `0` = non-blocking, `>0` = milliseconds.
4. Call `poll_set.wait(task, cx.with_timeout(timeout))`.
5. On `WaitError::TimedOut`, do a final `poll_set.scan()`.
6. Write `revents` back into each guest pollfd struct (offset 6 within each 8-byte struct).
7. Return count of pollfds with non-zero revents.

### sys_kqueue

```
sys_kqueue() -> Result<usize, Errno>
```

1. Create a new `KqueueFile`.
2. Allocate FD from `kqueue_fd_counter` (fetch_add 1).
3. Insert into `global.kqueues`.
4. Return FD number.

### sys_kevent

```
sys_kevent(kq: i32, changelist: ConstPtr<u8>, nchanges: i32,
           eventlist: MutPtr<u8>, nevents: i32,
           timeout: Option<ConstPtr<u8>>) -> Result<usize, Errno>
```

**Phase 1 — Process changelist** (if `nchanges > 0`):
For each `kevent` in changelist:
- `EV_ADD`: Resolve `ident` to `PollableRef`, create `KqueueEntry`, register as
  observer on the pollable's pollee, insert into `interests`. If entry already
  exists, update it (re-register observer).
- `EV_DELETE`: Remove from `interests`, unregister observer. If not found, report
  `EV_ERROR` with `ENOENT` in output (if eventlist available).
- `EV_ENABLE`: Re-enable a disabled entry.
- `EV_DISABLE`: Disable entry (observer stays but doesn't fire).

Errors during changelist processing are reported as events with `EV_ERROR` flag and
`data = errno`. Processing continues with the next change.

**Phase 2 — Wait for events** (if `nevents > 0`):
1. Read timeout: NULL = block indefinitely, `{0,0}` = non-blocking, else convert
   `timespec` to `Duration`.
2. Call `kqueue_file.wait(cx.with_timeout(timeout), nevents)`.
3. For each ready event, fill `data` field: bytes available for `EVFILT_READ`,
   buffer space for `EVFILT_WRITE`. Approximate from channel state.
4. Write kevent results to guest memory.
5. Return count of events.

If `nevents == 0`, only changelist processing happens. Return 0.

## Integration Points

### sys_close — kqueue FD cleanup

After the existing unix socket fallback check in `sys_close`, add:
```rust
if let Some(kq) = self.global.kqueues.write().remove(&(fd as usize)) {
    kq.close();  // unregister all observers from all entries
    return Ok(());
}
```

### sys_read / sys_write — kqueue FD rejection

kqueue FDs are not readable/writable. If an FD falls through to the kqueue
check in `sys_read` or `sys_write`, return `EBADF`.

### New Constants

**Syscall numbers** (in `litebox_common_macos/src/syscall.rs`):
- `SELECT = 93`
- `POLL = 230`
- `KQUEUE = 362`
- `KEVENT = 363`

**Poll event constants** (in `litebox_shim_macos/src/syscalls/poll.rs`):
- `POLLIN = 0x0001`, `POLLPRI = 0x0002`, `POLLOUT = 0x0004`
- `POLLERR = 0x0008`, `POLLHUP = 0x0010`, `POLLNVAL = 0x0020`

These map 1:1 to the core `Events` bitflags. No translation needed.

**Kevent constants** (in `litebox_shim_macos/src/syscalls/kqueue.rs`):
- Filters: `EVFILT_READ = -1`, `EVFILT_WRITE = -2`
- Flags: `EV_ADD = 0x0001`, `EV_DELETE = 0x0002`, `EV_ENABLE = 0x0004`,
  `EV_DISABLE = 0x0008`, `EV_ONESHOT = 0x0010`, `EV_CLEAR = 0x0020`,
  `EV_EOF = 0x8000`, `EV_ERROR = 0x4000`

### New MacosSyscallRequest Variants

```rust
Select { nfds: u32, readfds: usize, writefds: usize, errorfds: usize, timeout: usize }
Poll { fds: usize, nfds: u32, timeout: i32 }
Kqueue
Kevent { kq: i32, changelist: usize, nchanges: i32, eventlist: usize, nevents: i32, timeout: usize }
```

### New Files

- `litebox_shim_macos/src/syscalls/poll.rs` — `PollSet`, `PollableRef`, `sys_select`, `sys_poll`
- `litebox_shim_macos/src/syscalls/kqueue.rs` — `KqueueFile`, `KqueueEntry`, `ReadySet`,
  `KqueueKey`, `sys_kqueue`, `sys_kevent`

### New GlobalState Fields

```rust
kqueues: RwLock<BTreeMap<usize, Arc<KqueueFile<FS>>>>,
kqueue_fd_counter: AtomicUsize,  // starts at 0x2_0000
```

## Tests

Four end-to-end tests following the existing dynamic test pattern (compile C,
run through shim, verify exit code 0):

### test_select — `tests/select.c`

Self-pipe pattern:
1. `pipe(fds)`, `write(fds[1], "hello", 5)` — makes read end readable
2. `select(fds[0]+1, &readfds, NULL, NULL, &timeout)` with read end in readfds
3. Verify returns 1, `FD_ISSET(fds[0], &readfds)` is true
4. Test timeout: `select` on write end for readability with zero timeout — returns 0
5. Exit 0 on success

### test_poll — `tests/poll.c`

Self-pipe pattern:
1. `pipe(fds)`, `write(fds[1], "data", 4)`
2. `poll(&pollfd, 1, 0)` with `POLLIN` on read end — returns 1 with `POLLIN` in revents
3. Test write end: `poll` with `POLLOUT` — returns 1 (pipe not full)
4. Test timeout: `poll` on read end of fresh empty pipe with timeout=0 — returns 0
5. Exit 0 on success

### test_kqueue — `tests/kqueue.c`

Kqueue with pipe:
1. `pipe(fds)`, `write(fds[1], "test", 4)`
2. `kqueue()` — get kq fd
3. `kevent(kq, &change, 1, NULL, 0, NULL)` — register `EVFILT_READ` on `fds[0]` with `EV_ADD`
4. `kevent(kq, NULL, 0, &event, 1, &timeout)` — wait with short timeout
5. Verify returns 1, `ident == fds[0]`, `filter == EVFILT_READ`
6. Test `EVFILT_WRITE` on `fds[1]` — verify fires (pipe not full)
7. Test `EV_DELETE` — remove read interest, verify no longer fires
8. Exit 0 on success

### test_select_socket — `tests/select_socket.c`

Select with TCP (integration across Phase B + C):
1. Create TCP server socket, bind loopback, listen
2. Create TCP client socket, connect
3. Accept on server side
4. Write on client, select on accepted fd for readability
5. Verify select reports readable, read data, verify content via exit code
6. Exit 0 on success
