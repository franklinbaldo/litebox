# Divergence Detection and Side-Effect Gap Fixes

## Date: 2026-03-23

## Overview

Two improvements to record-replay reliability:

1. **Divergence detection** — When replay encounters a syscall mismatch, report rich
   diagnostic information instead of silently corrupting state or crashing mysteriously.
2. **Side-effect gap fixes** — Five syscalls have missing output buffer capture, causing
   replay divergence for programs that use them.

## 1. Divergence Detection

### Problem

When replay diverges (guest makes a different syscall than what the trace expects), the
current code either panics with a cryptic message or silently produces incorrect results.
There is no systematic detection or diagnostic reporting.

### Design

#### What to check

At the start of `handle_syscall_request_replay()`, after consuming the next trace event:

- **Syscall number mismatch** — trace event says `read` but guest issued `write`
- **TID mismatch** — trace event tid doesn't match the running thread's rr_tid
- **Unexpected EOF** — trace ran out of events but guest is still executing
- **Event kind mismatch** — expecting Complete but got Entry (or vice versa)

#### Error message format

```
RR DIVERGENCE at event #1234:
  Expected: syscall read (nr=0) kind=Complete tid=1
  Actual:   syscall write (nr=1) tid=1
  Syscall args: [0x3, 0x7fff1000, 0x1000, 0x0, 0x0, 0x0]
  Event history (last 10):
    #1224: tid=1 read (nr=0) -> 512
    #1225: tid=1 mmap (nr=9) -> 0x400000
    ...
```

#### Implementation

- **Event history ring buffer**: `RRState` gets `event_history: Mutex<VecDeque<EventSummary>>`
  holding the last 10 consumed events. `EventSummary` stores: event_index, syscall_nr, tid,
  kind, return_value.
- **`check_replay_divergence()`**: New function in `rr.rs` that compares expected vs actual
  and panics with the rich error message on mismatch.
- **`syscall_name()`**: Small helper mapping common syscall numbers to names for readability.
- **Still a panic**: Divergence is unrecoverable. We `eprintln!` the full diagnostic then panic.

## 2. Side-Effect Gap Fixes

### Audit results

Five syscalls have their return values recorded but their output buffers are NOT captured
during recording or injected during replay:

| Syscall | Missing data | Impact |
|---------|-------------|--------|
| `poll` | `revents` in pollfd array | Programs checking poll results see stale data |
| `epoll_wait` | `epoll_event` array | Programs checking epoll results see stale data |
| `recvmsg` | msghdr (name, iovecs, control, flags) | Any recvmsg user diverges |
| `nanosleep` | `remain` timespec on EINTR | Programs retrying after EINTR get wrong remaining time |
| `rt_sigtimedwait` | `siginfo_t` output | Programs inspecting signal info diverge |

### Fixes

#### 2a. `poll`

Add to `capture_side_effects()` and `inject_side_effects()` with same logic as `ppoll`:
read `nfds` from arg1, capture entire `pollfd` array (8 bytes per entry) from arg0.

#### 2b. `epoll_wait`

Add with same logic as `epoll_pwait`: capture `return_value` count of `epoll_event` structs
(12 bytes each) from arg1.

#### 2c. `recvmsg`

Capture all guest-visible output from the `msghdr` at arg1:
- `msghdr` struct (56 bytes on x86_64)
- `msg_name` buffer (up to updated `msg_namelen`)
- iovec scatter buffers (iterate iovecs, read up to total bytes returned)
- `msg_control` buffer (up to updated `msg_controllen`)

Serialize into side-effect data blob. Inject by parsing and writing all components back.

#### 2d. `nanosleep` EINTR

Add to `capture_side_effects_on_error()`: when return is `-EINTR` and arg1 (remain pointer)
is non-null, capture 16-byte `timespec`. Add corresponding inject logic.

#### 2e. `rt_sigtimedwait`

On success (return >= 0) and arg1 non-null, capture 128 bytes (`sizeof(siginfo_t)`) from
arg1. Inject during replay.

## Out of Scope

- **RDTSC/RDTSCP interception** — requires instruction-level trapping, deferred
- **CPUID interception** — same
- **vDSO neutralization** — same
- **Additional ioctl sub-commands** — can be added incrementally as needed
- **File-backed mmap content** — complex, deferred
