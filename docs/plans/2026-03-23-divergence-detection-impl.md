# Divergence Detection & Side-Effect Gap Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add replay divergence detection with rich diagnostics, and fix 5 syscalls with missing side-effect capture to prevent silent replay corruption.

**Architecture:** Divergence detection adds an event history ring buffer to `RRState` and a validation check at every replay event consumption. Side-effect gaps are fixed by adding match arms to the existing `capture_side_effects()` and `inject_side_effects()` functions, following the same patterns already used for similar syscalls (e.g., `ppoll` → `poll`, `epoll_pwait` → `epoll_wait`).

**Tech Stack:** Rust, `#![no_std]` (litebox_shim_linux), litebox_rr crate, cargo nextest

---

### Task 1: Add `syscall_name()` helper and `EventSummary` to `rr.rs`

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs:50-64` (RRState struct), lines ~66-279 (impl RRState)

**Step 1: Add `syscall_name()` helper function**

Add after the `is_synchronous_signal()` function (around line 630) in `litebox_shim_linux/src/rr.rs`:

```rust
/// Human-readable name for common syscall numbers, used in divergence diagnostics.
fn syscall_name(nr: u32) -> &'static str {
    match nr {
        nr::MMAP => "mmap",
        nr::MREMAP => "mremap",
        nr::MUNMAP => "munmap",
        nr::MPROTECT => "mprotect",
        nr::BRK => "brk",
        nr::READ => "read",
        nr::PREAD64 => "pread64",
        nr::READV => "readv",
        nr::WRITE => "write",
        nr::WRITEV => "writev",
        nr::GETRANDOM => "getrandom",
        nr::CLOCK_GETTIME => "clock_gettime",
        nr::GETTIMEOFDAY => "gettimeofday",
        nr::TIME => "time",
        nr::FSTAT => "fstat",
        nr::GETCWD => "getcwd",
        nr::UNAME => "uname",
        nr::PIPE2 => "pipe2",
        nr::GETDENTS64 => "getdents64",
        nr::FUTEX => "futex",
        nr::NANOSLEEP => "nanosleep",
        nr::CLOCK_NANOSLEEP => "clock_nanosleep",
        nr::PPOLL => "ppoll",
        nr::POLL => "poll",
        nr::PSELECT6 => "pselect6",
        nr::EPOLL_PWAIT => "epoll_pwait",
        nr::EPOLL_WAIT => "epoll_wait",
        nr::RECVFROM => "recvfrom",
        nr::RECVMSG => "recvmsg",
        nr::SENDTO => "sendto",
        nr::SENDMSG => "sendmsg",
        nr::CONNECT => "connect",
        nr::ACCEPT => "accept",
        nr::ACCEPT4 => "accept4",
        nr::CLONE => "clone",
        nr::CLONE3 => "clone3",
        nr::EXECVE => "execve",
        nr::EXIT => "exit",
        nr::EXIT_GROUP => "exit_group",
        nr::RT_SIGACTION => "rt_sigaction",
        nr::RT_SIGPROCMASK => "rt_sigprocmask",
        nr::SIGALTSTACK => "sigaltstack",
        nr::RT_SIGRETURN => "rt_sigreturn",
        nr::RT_SIGTIMEDWAIT => "rt_sigtimedwait",
        nr::KILL => "kill",
        nr::TKILL => "tkill",
        nr::TGKILL => "tgkill",
        nr::GETPID => "getpid",
        nr::GETTID => "gettid",
        nr::IOCTL => "ioctl",
        nr::MADVISE => "madvise",
        nr::SYSINFO => "sysinfo",
        nr::SOCKETPAIR => "socketpair",
        nr::GETSOCKOPT => "getsockopt",
        nr::GETSOCKNAME => "getsockname",
        nr::GETPEERNAME => "getpeername",
        nr::CAPGET => "capget",
        _ => "unknown",
    }
}
```

**Step 2: Add `EventSummary` struct and event history ring buffer to `RRState`**

Add a new struct before `RRState`:

```rust
/// Summary of a consumed trace event, stored in the event history ring buffer
/// for divergence diagnostics.
struct EventSummary {
    event_index: u64,
    syscall_nr: u32,
    tid: u32,
    kind: litebox_rr::EventKind,
    result: i64,
}
```

Add to `RRState` struct (line ~50):

```rust
event_history: Mutex<VecDeque<EventSummary>>,
```

Initialize in `RRState::new()` and `RRState::new_replay()`:

```rust
event_history: Mutex::new(VecDeque::with_capacity(16)),
```

Add a method to `impl RRState`:

```rust
/// Record a consumed event in the history ring buffer (max 10 entries).
fn push_event_history(&self, event: &litebox_rr::Event) {
    let mut history = self.event_history.lock();
    if history.len() >= 10 {
        history.pop_front();
    }
    history.push_back(EventSummary {
        event_index: event.event_id,
        syscall_nr: event.syscall_nr,
        tid: event.tid,
        kind: event.kind,
        result: event.result,
    });
}

/// Format the event history for divergence diagnostics.
fn format_event_history(&self) -> alloc::string::String {
    use alloc::fmt::Write;
    let history = self.event_history.lock();
    let mut out = alloc::string::String::new();
    for entry in history.iter() {
        let name = syscall_name(entry.syscall_nr);
        let kind_str = match entry.kind {
            litebox_rr::EventKind::Complete => "",
            litebox_rr::EventKind::Entry => " [ENTRY]",
            litebox_rr::EventKind::Exit => " [EXIT]",
            litebox_rr::EventKind::Signal => " [SIGNAL]",
            litebox_rr::EventKind::Snapshot => " [SNAPSHOT]",
        };
        let _ = writeln!(
            out,
            "    #{}: tid={} {} (nr={}){} -> {}",
            entry.event_index, entry.tid, name, entry.syscall_nr, kind_str, entry.result
        );
    }
    out
}
```

**Step 3: Build and test**

Run: `cargo build --features rr -p litebox_shim_linux`
Expected: compiles cleanly

**Step 4: Run clippy**

Run: `cargo clippy --all-targets --features rr`
Expected: no warnings

**Step 5: Commit**

```
feat(rr): add syscall_name helper and event history ring buffer for divergence diagnostics
```

---

### Task 2: Add divergence detection to replay dispatch

**Files:**
- Modify: `litebox_shim_linux/src/lib.rs:1009-1145` (handle_syscall_request_replay)
- Modify: `litebox_shim_linux/src/rr.rs` (RRState methods)

**Step 1: Add `replay_event_with_history()` method to `RRState`**

This wraps `replay_event()` to also push the consumed event into the history ring buffer, and on divergence, formats a rich error message including syscall args and event history.

```rust
/// Replay an event, recording it in the event history.
/// On divergence, returns a rich error with context.
pub fn replay_event_checked(
    &self,
    actual_syscall_nr: u32,
    actual_tid: u32,
    ctx: &litebox_common_linux::PtRegs,
) -> Result<litebox_rr::Event, alloc::string::String> {
    match self.replay_event(actual_syscall_nr) {
        Ok(event) => {
            self.push_event_history(&event);
            Ok(event)
        }
        Err(rr::ReplayError::Divergence { event_id, expected_syscall_nr, actual_syscall_nr }) => {
            // Read the expected event's kind and tid by peeking (already consumed, use history)
            let history = self.format_event_history();
            let args = format_syscall_args(ctx);
            Err(alloc::format!(
                "RR DIVERGENCE at event #{event_id}:\n\
                 \x20 Expected: syscall {} (nr={expected_syscall_nr})\n\
                 \x20 Actual:   syscall {} (nr={actual_syscall_nr}) tid={actual_tid}\n\
                 \x20 Syscall args: [{args}]\n\
                 \x20 Event history (last 10):\n{history}",
                syscall_name(expected_syscall_nr),
                syscall_name(actual_syscall_nr),
            ))
        }
        Err(rr::ReplayError::EndOfTrace) => {
            let history = self.format_event_history();
            let args = format_syscall_args(ctx);
            Err(alloc::format!(
                "RR DIVERGENCE: unexpected end of trace\n\
                 \x20 Guest issued: syscall {} (nr={actual_syscall_nr}) tid={actual_tid}\n\
                 \x20 Syscall args: [{args}]\n\
                 \x20 Event history (last 10):\n{history}",
                syscall_name(actual_syscall_nr),
            ))
        }
        Err(e) => Err(alloc::format!("RR replay error: {e:?}")),
    }
}
```

Add helper:

```rust
fn format_syscall_args(ctx: &litebox_common_linux::PtRegs) -> alloc::string::String {
    alloc::format!(
        "{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}",
        ctx.syscall_arg(0),
        ctx.syscall_arg(1),
        ctx.syscall_arg(2),
        ctx.syscall_arg(3),
        ctx.syscall_arg(4),
        ctx.syscall_arg(5),
    )
}
```

**Step 2: Replace `replay_event()` calls in `handle_syscall_request_replay()` with `replay_event_checked()`**

In `litebox_shim_linux/src/lib.rs`, replace the 3 `replay_event()` call sites (lines ~1023, ~1056, ~1094, ~1114) with `replay_event_checked()` and update the error handling from `Err(e) => panic!("...")` to `Err(msg) => panic!("{msg}")`.

Note: The ENTRY event consumption (line 1023) should also use checked. The EXIT event (line 1056) should also use checked. The structural path (line 1094) and non-structural path (line 1114) should also use checked.

For each call site, pass the current `syscall_nr`, `self.rr_tid()` as `actual_tid`, and `ctx`.

**Step 3: Build and run existing tests**

Run: `cargo nextest run --features rr -E 'test(rr)'`
Expected: all 12 tests pass (the divergence detection is transparent — it only fires on actual divergence)

**Step 4: Run clippy and fmt**

Run: `cargo fmt --all && cargo clippy --all-targets --features rr`
Expected: clean

**Step 5: Commit**

```
feat(rr): add divergence detection with rich diagnostics to replay dispatch
```

---

### Task 3: Fix `poll` side-effect capture and injection

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs:834-1302` (capture_side_effects), lines 1435-1772 (inject_side_effects)

**Step 1: Add `poll` to `capture_side_effects()`**

Add a new match arm right after the `ppoll` arm (line ~1153). The `poll` syscall has the same arg layout for fds and nfds as `ppoll`:

```rust
// poll(fds, nfds, timeout) -> ready_count
// Same as ppoll: capture entire pollfd array with updated revents.
nr::POLL => {
    let fds_addr = ctx.syscall_arg(0);
    let nfds = ctx.syscall_arg(1);
    read_guest_bytes(
        fds_addr,
        nfds * core::mem::size_of::<litebox_common_linux::Pollfd>(),
    )
}
```

**Step 2: Add `poll` to `inject_side_effects()`**

Add a new match arm right after the `ppoll` arm in inject (line ~1658):

```rust
// poll: write entire pollfd array back to arg0 (same as ppoll)
nr::POLL => {
    let fds_addr = ctx.syscall_arg(0);
    write_guest_bytes(fds_addr, data);
}
```

**Step 3: Build and run tests**

Run: `cargo nextest run --features rr -E 'test(rr)'`
Expected: all tests pass

**Step 4: Commit**

```
fix(rr): capture and inject poll revents side-effect data
```

---

### Task 4: Fix `epoll_wait` side-effect capture and injection

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs` (capture_side_effects, inject_side_effects)

**Step 1: Add `epoll_wait` to `capture_side_effects()`**

Add right after the `epoll_pwait` arm (line ~1180):

```rust
// epoll_wait(epfd, events, maxevents, timeout) -> ready_count
// Same as epoll_pwait: capture ready_count epoll_event structs.
nr::EPOLL_WAIT => {
    let events_addr = ctx.syscall_arg(1);
    read_guest_bytes(
        events_addr,
        return_value * core::mem::size_of::<litebox_common_linux::EpollEvent>(),
    )
}
```

**Step 2: Add `epoll_wait` to `inject_side_effects()`**

Add right after the `epoll_pwait` arm in inject (line ~1679):

```rust
// epoll_wait: events = arg1 (same as epoll_pwait)
nr::EPOLL_WAIT => {
    let events_addr = ctx.syscall_arg(1);
    write_guest_bytes(events_addr, data);
}
```

**Step 3: Build and run tests**

Run: `cargo nextest run --features rr -E 'test(rr)'`
Expected: all tests pass

**Step 4: Commit**

```
fix(rr): capture and inject epoll_wait events side-effect data
```

---

### Task 5: Fix `nanosleep` EINTR side-effect capture

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs:1374-1410` (capture_side_effects_on_error), lines 1435-1772 (inject_side_effects)

**Step 1: Add `nanosleep` to `capture_side_effects_on_error()`**

Add a new match arm inside the function (after the `clock_nanosleep` arm at line ~1393):

```rust
// nanosleep(req, rem) — rem = arg1, written on EINTR
nr::NANOSLEEP if result_signed == Errno::EINTR.as_neg() as isize => {
    let remain_addr = ctx.syscall_arg(1);
    if remain_addr != 0 {
        read_guest_bytes(remain_addr, 16) // sizeof(struct timespec)
    } else {
        Vec::new()
    }
}
```

**Step 2: Add `nanosleep` to `inject_side_effects()`**

Add a match arm in inject:

```rust
// nanosleep: remain = arg1 (on EINTR)
nr::NANOSLEEP => {
    let remain_addr = ctx.syscall_arg(1);
    if remain_addr != 0 {
        write_guest_bytes(remain_addr, data);
    }
}
```

**Step 3: Build and run tests**

Run: `cargo nextest run --features rr -E 'test(rr)'`
Expected: all tests pass

**Step 4: Commit**

```
fix(rr): capture nanosleep remain timespec on EINTR
```

---

### Task 6: Fix `rt_sigtimedwait` side-effect capture

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs` (capture_side_effects, inject_side_effects)

**Step 1: Add `rt_sigtimedwait` to `capture_side_effects()`**

`rt_sigtimedwait(set, info, timeout, sigsetsize)` — `info` is arg1, writes `siginfo_t` (128 bytes) on success.

Add a new match arm:

```rust
// rt_sigtimedwait(set, info, timeout, sigsetsize) -> signal_nr
// info = arg1, sizeof(siginfo_t) = 128
nr::RT_SIGTIMEDWAIT => {
    let info_addr = ctx.syscall_arg(1);
    if info_addr != 0 {
        read_guest_bytes(info_addr, 128) // sizeof(siginfo_t)
    } else {
        Vec::new()
    }
}
```

**Step 2: Add `rt_sigtimedwait` to `inject_side_effects()`**

```rust
// rt_sigtimedwait: info = arg1
nr::RT_SIGTIMEDWAIT => {
    let info_addr = ctx.syscall_arg(1);
    if info_addr != 0 {
        write_guest_bytes(info_addr, data);
    }
}
```

**Step 3: Build and run tests**

Run: `cargo nextest run --features rr -E 'test(rr)'`
Expected: all tests pass

**Step 4: Commit**

```
fix(rr): capture rt_sigtimedwait siginfo_t side-effect data
```

---

### Task 7: Fix `recvmsg` side-effect capture and injection

This is the most complex fix. `recvmsg` writes into a scatter-gather `msghdr` structure.

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs` (capture_side_effects, inject_side_effects, add helpers)

**Step 1: Add `capture_recvmsg_data()` helper**

Add near the existing `capture_readv_data()` helper (line ~1367):

```rust
/// Capture `recvmsg` output: scatter-gather iovec data + updated msghdr fields.
///
/// Serialized format:
/// - `msg_namelen` (4 bytes LE) — updated name length
/// - `msg_name` data (msg_namelen bytes)
/// - `msg_controllen` (8 bytes LE) — updated control length
/// - `msg_control` data (msg_controllen bytes)
/// - `msg_flags` (4 bytes LE)
/// - iovec scatter data (concatenated, total = return_value bytes)
fn capture_recvmsg_data(
    ctx: &litebox_common_linux::PtRegs,
    total_bytes_read: usize,
) -> Vec<u8> {
    #[cfg(target_arch = "x86_64")]
    const IOVEC_SIZE: usize = 16;
    #[cfg(target_arch = "x86")]
    const IOVEC_SIZE: usize = 8;
    const PTR_SIZE: usize = core::mem::size_of::<usize>();

    let msghdr_addr = ctx.syscall_arg(1);
    if msghdr_addr == 0 {
        return Vec::new();
    }

    // Read the full msghdr struct (56 bytes on x86_64, 28 on x86)
    let msghdr_size = core::mem::size_of::<usize>() // msg_name ptr
        + 4  // msg_namelen
        + if PTR_SIZE == 8 { 4 } else { 0 }  // padding on 64-bit
        + PTR_SIZE  // msg_iov ptr
        + PTR_SIZE  // msg_iovlen
        + PTR_SIZE  // msg_control ptr
        + PTR_SIZE  // msg_controllen
        + 4  // msg_flags
        + if PTR_SIZE == 8 { 4 } else { 0 }; // trailing padding on 64-bit

    let msghdr_bytes = read_guest_bytes(msghdr_addr, msghdr_size);
    if msghdr_bytes.len() < msghdr_size {
        return Vec::new();
    }

    let mut result = Vec::new();

    // Parse msghdr fields (all native endian since same-machine capture)
    let mut off = 0;
    let msg_name_ptr = usize::from_ne_bytes(msghdr_bytes[off..off + PTR_SIZE].try_into().unwrap_or([0; 8][..PTR_SIZE].try_into().unwrap()));
    off += PTR_SIZE;
    let msg_namelen = u32::from_ne_bytes(msghdr_bytes[off..off + 4].try_into().unwrap_or([0; 4]));
    off += 4;
    if PTR_SIZE == 8 { off += 4; } // padding
    let msg_iov_ptr = usize::from_ne_bytes(msghdr_bytes[off..off + PTR_SIZE].try_into().unwrap_or([0; 8][..PTR_SIZE].try_into().unwrap()));
    off += PTR_SIZE;
    let msg_iovlen = usize::from_ne_bytes(msghdr_bytes[off..off + PTR_SIZE].try_into().unwrap_or([0; 8][..PTR_SIZE].try_into().unwrap()));
    off += PTR_SIZE;
    let msg_control_ptr = usize::from_ne_bytes(msghdr_bytes[off..off + PTR_SIZE].try_into().unwrap_or([0; 8][..PTR_SIZE].try_into().unwrap()));
    off += PTR_SIZE;
    let msg_controllen_bytes = &msghdr_bytes[off..off + PTR_SIZE];
    let msg_controllen = usize::from_ne_bytes(msg_controllen_bytes.try_into().unwrap_or([0; 8][..PTR_SIZE].try_into().unwrap()));
    off += PTR_SIZE;
    let msg_flags = u32::from_ne_bytes(msghdr_bytes[off..off + 4].try_into().unwrap_or([0; 4]));

    // 1. msg_name data
    result.extend_from_slice(&msg_namelen.to_le_bytes());
    if msg_name_ptr != 0 && msg_namelen > 0 {
        result.extend_from_slice(&read_guest_bytes(msg_name_ptr, msg_namelen as usize));
    }

    // 2. msg_control data
    #[allow(clippy::cast_possible_truncation)]
    let controllen_u64 = msg_controllen as u64;
    result.extend_from_slice(&controllen_u64.to_le_bytes());
    if msg_control_ptr != 0 && msg_controllen > 0 {
        result.extend_from_slice(&read_guest_bytes(msg_control_ptr, msg_controllen));
    }

    // 3. msg_flags
    result.extend_from_slice(&msg_flags.to_le_bytes());

    // 4. iovec scatter data (same approach as capture_readv_data)
    if msg_iov_ptr != 0 && msg_iovlen > 0 && total_bytes_read > 0 {
        let iov_bytes = read_guest_bytes(msg_iov_ptr, msg_iovlen * IOVEC_SIZE);
        let mut remaining = total_bytes_read;
        for i in 0..msg_iovlen {
            if remaining == 0 { break; }
            let iov_off = i * IOVEC_SIZE;

            #[cfg(target_arch = "x86_64")]
            let (base, len) = {
                let base = usize::from_ne_bytes(iov_bytes[iov_off..iov_off + 8].try_into().unwrap_or([0; 8]));
                let len = usize::from_ne_bytes(iov_bytes[iov_off + 8..iov_off + 16].try_into().unwrap_or([0; 8]));
                (base, len)
            };
            #[cfg(target_arch = "x86")]
            let (base, len) = {
                let base = u32::from_ne_bytes(iov_bytes[iov_off..iov_off + 4].try_into().unwrap_or([0; 4])) as usize;
                let len = u32::from_ne_bytes(iov_bytes[iov_off + 4..iov_off + 8].try_into().unwrap_or([0; 4])) as usize;
                (base, len)
            };

            let to_read = len.min(remaining);
            let chunk = read_guest_bytes(base, to_read);
            result.extend_from_slice(&chunk);
            remaining = remaining.saturating_sub(chunk.len());
        }
    }

    result
}
```

**Step 2: Add `recvmsg` to `capture_side_effects()`**

```rust
// recvmsg(sockfd, msg, flags) -> bytes_received
nr::RECVMSG => capture_recvmsg_data(ctx, return_value),
```

**Step 3: Add `inject_recvmsg_data()` helper**

```rust
/// Inject `recvmsg` data back into the guest's msghdr structure.
///
/// Parses the format written by `capture_recvmsg_data()`.
fn inject_recvmsg_data(ctx: &litebox_common_linux::PtRegs, data: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    const IOVEC_SIZE: usize = 16;
    #[cfg(target_arch = "x86")]
    const IOVEC_SIZE: usize = 8;
    const PTR_SIZE: usize = core::mem::size_of::<usize>();

    let msghdr_addr = ctx.syscall_arg(1);
    if msghdr_addr == 0 || data.is_empty() {
        return;
    }

    let mut off = 0;

    // 1. msg_namelen + msg_name data
    if off + 4 > data.len() { return; }
    let msg_namelen = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
    off += 4;

    // Read original msghdr to get pointers
    let msghdr_bytes = read_guest_bytes(msghdr_addr, 56.max(PTR_SIZE * 5 + 12));

    // Parse msg_name ptr from msghdr
    let msg_name_ptr = usize::from_ne_bytes(msghdr_bytes[..PTR_SIZE].try_into().unwrap_or([0; 8][..PTR_SIZE].try_into().unwrap()));

    // Write updated msg_namelen into msghdr (at offset PTR_SIZE)
    write_guest_bytes(msghdr_addr + PTR_SIZE, &msg_namelen.to_ne_bytes());

    if msg_name_ptr != 0 && msg_namelen > 0 {
        let name_end = off + msg_namelen as usize;
        if name_end <= data.len() {
            write_guest_bytes(msg_name_ptr, &data[off..name_end]);
        }
        off = name_end;
    }

    // 2. msg_controllen + msg_control data
    if off + 8 > data.len() { return; }
    let msg_controllen = u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) as usize;
    off += 8;

    // Parse msg_control ptr from msghdr
    let ctrl_ptr_off = PTR_SIZE + 4 + (if PTR_SIZE == 8 { 4 } else { 0 }) + PTR_SIZE + PTR_SIZE;
    let msg_control_ptr = usize::from_ne_bytes(msghdr_bytes[ctrl_ptr_off..ctrl_ptr_off + PTR_SIZE].try_into().unwrap_or([0; 8][..PTR_SIZE].try_into().unwrap()));

    // Write updated msg_controllen into msghdr
    let controllen_off = ctrl_ptr_off + PTR_SIZE;
    write_guest_bytes(msghdr_addr + controllen_off, &msg_controllen.to_ne_bytes());

    if msg_control_ptr != 0 && msg_controllen > 0 {
        let ctrl_end = off + msg_controllen;
        if ctrl_end <= data.len() {
            write_guest_bytes(msg_control_ptr, &data[off..ctrl_end]);
        }
        off = ctrl_end;
    }

    // 3. msg_flags
    if off + 4 > data.len() { return; }
    let msg_flags_bytes = &data[off..off + 4];
    off += 4;

    // Write msg_flags into msghdr
    let flags_off = controllen_off + PTR_SIZE;
    write_guest_bytes(msghdr_addr + flags_off, msg_flags_bytes);

    // 4. iovec scatter data
    let iov_data = &data[off..];
    if iov_data.is_empty() { return; }

    // Parse msg_iov and msg_iovlen from msghdr
    let iov_ptr_off = PTR_SIZE + 4 + (if PTR_SIZE == 8 { 4 } else { 0 });
    let msg_iov_ptr = usize::from_ne_bytes(msghdr_bytes[iov_ptr_off..iov_ptr_off + PTR_SIZE].try_into().unwrap_or([0; 8][..PTR_SIZE].try_into().unwrap()));
    let msg_iovlen = usize::from_ne_bytes(msghdr_bytes[iov_ptr_off + PTR_SIZE..iov_ptr_off + PTR_SIZE * 2].try_into().unwrap_or([0; 8][..PTR_SIZE].try_into().unwrap()));

    if msg_iov_ptr == 0 || msg_iovlen == 0 { return; }

    let iov_bytes = read_guest_bytes(msg_iov_ptr, msg_iovlen * IOVEC_SIZE);
    let mut data_off = 0;
    for i in 0..msg_iovlen {
        if data_off >= iov_data.len() { break; }
        let iov_off = i * IOVEC_SIZE;

        #[cfg(target_arch = "x86_64")]
        let (base, len) = {
            let base = usize::from_ne_bytes(iov_bytes[iov_off..iov_off + 8].try_into().unwrap_or([0; 8]));
            let len = usize::from_ne_bytes(iov_bytes[iov_off + 8..iov_off + 16].try_into().unwrap_or([0; 8]));
            (base, len)
        };
        #[cfg(target_arch = "x86")]
        let (base, len) = {
            let base = u32::from_ne_bytes(iov_bytes[iov_off..iov_off + 4].try_into().unwrap_or([0; 4])) as usize;
            let len = u32::from_ne_bytes(iov_bytes[iov_off + 4..iov_off + 8].try_into().unwrap_or([0; 4])) as usize;
            (base, len)
        };

        let to_write = len.min(iov_data.len() - data_off);
        write_guest_bytes(base, &iov_data[data_off..data_off + to_write]);
        data_off += to_write;
    }
}
```

**Step 4: Add `recvmsg` to `inject_side_effects()`**

```rust
// recvmsg: complex msghdr injection
nr::RECVMSG => {
    inject_recvmsg_data(ctx, data);
}
```

**Step 5: Build and run tests**

Run: `cargo nextest run --features rr -E 'test(rr)'`
Expected: all tests pass

**Step 6: Run clippy and fmt**

Run: `cargo fmt --all && cargo clippy --all-targets --features rr`
Expected: clean

**Step 7: Commit**

```
fix(rr): capture and inject recvmsg msghdr side-effect data
```

---

### Task 8: Final verification — clippy, fmt, full test suite

**Files:** None (verification only)

**Step 1: Run cargo fmt**

Run: `cargo fmt --all --check`
Expected: clean

**Step 2: Run cargo clippy**

Run: `cargo clippy --all-targets --features rr`
Expected: no warnings

**Step 3: Run all RR tests**

Run: `cargo nextest run --features rr -E 'test(rr)'`
Expected: all tests pass (should be 12+)

**Step 4: Run full test suite**

Run: `cargo nextest run --features rr`
Expected: same pass/fail as before (only pre-existing failures)

**Step 5: Commit any cleanup**

If any formatting or clippy fixes were needed.
