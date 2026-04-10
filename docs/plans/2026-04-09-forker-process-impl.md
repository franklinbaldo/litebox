# Forker Process — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the `posix_spawn("/proc/self/exe", "--fork-restore", ...)` path with a forker process that stays single-threaded and forks workers on demand, eliminating `execve`, `openat`, `socket`, `connect`, `memfd_create`, `brk`, `arch_prctl`, and `getrandom` from the post-init syscall surface.

**Architecture:** A dedicated forker process is `fork()`'d from the runner during the single-threaded init window (after platform setup, before any threads start). On `commit_delayed_fork`, the runner sends a `ForkRequest` + `SCM_RIGHTS` fds to the forker over a Unix socketpair. The forker double-forks a worker (for re-parenting via `PR_SET_CHILD_SUBREAPER`), and the worker restores the guest process from the inherited snapshot without needing `execve` or any `openat` calls. The existing `posix_spawn` path is kept as a fallback if the forker is unavailable.

**Tech Stack:** Rust, litebox (sandbox runtime), Unix domain sockets (SCM_RIGHTS), `fork()`, `prctl(PR_SET_CHILD_SUBREAPER)`

**Design Doc:** `docs/plans/2026-04-09-forker-process-design.md`

---

## Task 1: Add ForkerHandle and ForkRequest/ForkResponse Protocol

Define the data structures for communication between the runner and forker process. This is the foundation — everything else builds on it.

**Files:**
- Create: `litebox_platform_linux_userland/src/forker.rs`
- Modify: `litebox_platform_linux_userland/src/lib.rs` (add `mod forker;`)

### Step 1: Create the forker module with protocol types

Create `litebox_platform_linux_userland/src/forker.rs` with:

```rust
//! Forker process: a single-threaded child of the runner that forks
//! workers on demand for fork-restore, eliminating execve/openat from
//! the post-init syscall surface.
//!
//! See `docs/plans/2026-04-09-forker-process-design.md` for the full design.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Handle for the runner to communicate with the forker process.
pub(crate) struct ForkerHandle {
    /// The runner's end of the socketpair.
    sock: std::sync::Mutex<OwnedFd>,
}

/// Stdio binding type for a single fd (0, 1, or 2).
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub(crate) enum StdioBinding {
    /// dup2 from a passed fd (index into the SCM_RIGHTS array).
    FromFdIndex(u8) = 0,
    /// Open /dev/null (read for stdin, write for stdout/stderr).
    DevNull = 1,
    /// Close this fd.
    Close = 2,
    /// Inherit as-is (identity — fd N maps to fd N already).
    Inherit = 3,
}

/// A request from the runner to the forker to create a new worker.
///
/// Serialized as a fixed-size header followed by variable-length specs.
/// All fd references are indices into the SCM_RIGHTS fd array sent
/// alongside the message.
#[derive(Debug)]
pub(crate) struct ForkRequest {
    /// Stdio bindings for fds 0, 1, 2.
    pub stdio: [StdioBinding; 3],
    /// Number of fds in the SCM_RIGHTS array.
    pub num_fds: u16,
    /// Index of the snapshot memfd in the fd array.
    pub snapshot_fd_idx: u8,
    /// Index of the ack pipe (write end) in the fd array.
    pub ack_fd_idx: u8,
    /// Index of the result pipe (write end) in the fd array.
    pub result_fd_idx: u8,
    /// Index of the mux socketpair fd in the fd array, or 0xFF if none.
    pub mux_fd_idx: u8,
    /// Mux stream specs: (stream_id, guest_fd, direction, type, initial_eof).
    pub mux_streams: Vec<(u32, usize, u8, u8, bool)>,
    /// Pipe bridge specs: (guest_fd, host_fd_idx_in_array, is_read).
    pub pipe_bridges: Vec<(usize, u8, bool)>,
    /// Local pipe specs: (write_fd, read_fd, drain_fd_idx_or_0xFF, w_flags, r_flags).
    pub local_pipes: Vec<(usize, usize, u8, u32, u32)>,
}

/// Response from the forker to the runner after a fork request.
#[derive(Debug)]
pub(crate) struct ForkResponse {
    /// Worker PID (grandchild), or negative errno on error.
    pub child_pid: i32,
}

// ── Serialization ─────────────────────────────────────────────────

/// Wire format magic for ForkRequest.
const FORK_REQUEST_MAGIC: [u8; 4] = *b"LBFR";
/// Wire format version.
const FORK_REQUEST_VERSION: u16 = 1;

impl ForkRequest {
    /// Serialize the request into bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&FORK_REQUEST_MAGIC);
        buf.extend_from_slice(&FORK_REQUEST_VERSION.to_le_bytes());
        // stdio bindings (3 bytes)
        for s in &self.stdio {
            buf.push(match s {
                StdioBinding::FromFdIndex(idx) => *idx,
                StdioBinding::DevNull => 0xFE,
                StdioBinding::Close => 0xFD,
                StdioBinding::Inherit => 0xFC,
            });
        }
        buf.extend_from_slice(&self.num_fds.to_le_bytes());
        buf.push(self.snapshot_fd_idx);
        buf.push(self.ack_fd_idx);
        buf.push(self.result_fd_idx);
        buf.push(self.mux_fd_idx);
        // mux_streams count + entries
        buf.extend_from_slice(&(self.mux_streams.len() as u16).to_le_bytes());
        for &(stream_id, guest_fd, dir, stype, initial_eof) in &self.mux_streams {
            buf.extend_from_slice(&stream_id.to_le_bytes());
            buf.extend_from_slice(&(guest_fd as u32).to_le_bytes());
            buf.push(dir);
            buf.push(stype);
            buf.push(if initial_eof { 1 } else { 0 });
        }
        // pipe_bridges count + entries
        buf.extend_from_slice(&(self.pipe_bridges.len() as u16).to_le_bytes());
        for &(guest_fd, host_fd_idx, is_read) in &self.pipe_bridges {
            buf.extend_from_slice(&(guest_fd as u32).to_le_bytes());
            buf.push(host_fd_idx);
            buf.push(if is_read { 1 } else { 0 });
        }
        // local_pipes count + entries
        buf.extend_from_slice(&(self.local_pipes.len() as u16).to_le_bytes());
        for &(write_fd, read_fd, drain_fd_idx, w_flags, r_flags) in &self.local_pipes {
            buf.extend_from_slice(&(write_fd as u32).to_le_bytes());
            buf.extend_from_slice(&(read_fd as u32).to_le_bytes());
            buf.push(drain_fd_idx);
            buf.extend_from_slice(&w_flags.to_le_bytes());
            buf.extend_from_slice(&r_flags.to_le_bytes());
        }
        buf
    }

    /// Deserialize a request from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 14 {
            return Err("ForkRequest too short");
        }
        if data[0..4] != FORK_REQUEST_MAGIC {
            return Err("ForkRequest bad magic");
        }
        let version = u16::from_le_bytes([data[4], data[5]]);
        if version != FORK_REQUEST_VERSION {
            return Err("ForkRequest bad version");
        }
        let stdio = [
            decode_stdio_binding(data[6]),
            decode_stdio_binding(data[7]),
            decode_stdio_binding(data[8]),
        ];
        let num_fds = u16::from_le_bytes([data[9], data[10]]);
        let snapshot_fd_idx = data[11];
        let ack_fd_idx = data[12];
        let result_fd_idx = data[13];
        let mux_fd_idx = data[14];
        let mut off = 15;

        // mux_streams
        if off + 2 > data.len() {
            return Err("truncated mux_streams count");
        }
        let mux_count = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let mut mux_streams = Vec::with_capacity(mux_count);
        for _ in 0..mux_count {
            if off + 11 > data.len() {
                return Err("truncated mux_stream entry");
            }
            let stream_id = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
            let guest_fd = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]) as usize;
            let dir = data[off+8];
            let stype = data[off+9];
            let initial_eof = data[off+10] != 0;
            mux_streams.push((stream_id, guest_fd, dir, stype, initial_eof));
            off += 11;
        }

        // pipe_bridges
        if off + 2 > data.len() {
            return Err("truncated pipe_bridges count");
        }
        let bridge_count = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let mut pipe_bridges = Vec::with_capacity(bridge_count);
        for _ in 0..bridge_count {
            if off + 6 > data.len() {
                return Err("truncated pipe_bridge entry");
            }
            let guest_fd = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) as usize;
            let host_fd_idx = data[off+4];
            let is_read = data[off+5] != 0;
            pipe_bridges.push((guest_fd, host_fd_idx, is_read));
            off += 6;
        }

        // local_pipes
        if off + 2 > data.len() {
            return Err("truncated local_pipes count");
        }
        let pipe_count = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let mut local_pipes = Vec::with_capacity(pipe_count);
        for _ in 0..pipe_count {
            if off + 13 > data.len() {
                return Err("truncated local_pipe entry");
            }
            let write_fd = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) as usize;
            let read_fd = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]) as usize;
            let drain_fd_idx = data[off+8];
            let w_flags = u32::from_le_bytes([data[off+9], data[off+10], data[off+11], data[off+12]]);
            let r_flags = u32::from_le_bytes([data[off+13], data[off+14], data[off+15], data[off+16]]);
            local_pipes.push((write_fd, read_fd, drain_fd_idx, w_flags, r_flags));
            off += 17;
        }

        Ok(Self {
            stdio,
            num_fds,
            snapshot_fd_idx,
            ack_fd_idx,
            result_fd_idx,
            mux_fd_idx,
            mux_streams,
            pipe_bridges,
            local_pipes,
        })
    }
}

fn decode_stdio_binding(b: u8) -> StdioBinding {
    match b {
        0xFE => StdioBinding::DevNull,
        0xFD => StdioBinding::Close,
        0xFC => StdioBinding::Inherit,
        idx => StdioBinding::FromFdIndex(idx),
    }
}

impl ForkResponse {
    pub fn serialize(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(b"LBFP");
        buf[4..8].copy_from_slice(&self.child_pid.to_le_bytes());
        buf
    }

    pub fn deserialize(data: &[u8; 8]) -> Result<Self, &'static str> {
        if &data[0..4] != b"LBFP" {
            return Err("ForkResponse bad magic");
        }
        let child_pid = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        Ok(Self { child_pid })
    }
}
```

### Step 2: Add SCM_RIGHTS send/recv helpers

Append to `forker.rs`:

```rust
// ── SCM_RIGHTS helpers ────────────────────────────────────────────

/// Maximum number of fds we can pass in a single SCM_RIGHTS message.
/// snapshot(1) + ack(1) + result(1) + broker(1) + 9p_memfds(2) + mux(1)
/// + pipe_bridges(N) + drain_memfds(N).  64 should be more than enough.
const MAX_SCMRIGHTS_FDS: usize = 64;

/// Send a ForkRequest message with SCM_RIGHTS fds over a Unix socket.
pub(crate) fn send_fork_request(
    sock: RawFd,
    request: &ForkRequest,
    fds: &[RawFd],
) -> Result<(), i32> {
    let msg_bytes = request.serialize();
    send_msg_with_fds(sock, &msg_bytes, fds)
}

/// Receive a ForkRequest message with SCM_RIGHTS fds from a Unix socket.
pub(crate) fn recv_fork_request(
    sock: RawFd,
) -> Result<(ForkRequest, Vec<OwnedFd>), i32> {
    let mut msg_buf = vec![0u8; 4096];
    let (n, fds) = recv_msg_with_fds(sock, &mut msg_buf)?;
    if n == 0 {
        return Err(-1); // EOF — runner closed the socket
    }
    let req = ForkRequest::deserialize(&msg_buf[..n]).map_err(|_| -1)?;
    Ok((req, fds))
}

/// Send a ForkResponse over a Unix socket (no fds).
pub(crate) fn send_fork_response(sock: RawFd, response: &ForkResponse) -> Result<(), i32> {
    let buf = response.serialize();
    send_msg_with_fds(sock, &buf, &[])
}

/// Receive a ForkResponse from a Unix socket.
pub(crate) fn recv_fork_response(sock: RawFd) -> Result<ForkResponse, i32> {
    let mut buf = [0u8; 8];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    let n = unsafe { libc::recvmsg(sock, &raw mut msg, 0) };
    if n <= 0 {
        return Err(if n == 0 { -1 } else { -std::io::Error::last_os_error().raw_os_error().unwrap_or(1) });
    }
    if (n as usize) < 8 {
        return Err(-1);
    }
    ForkResponse::deserialize(&buf).map_err(|_| -1)
}

/// Low-level: send bytes + fds over a Unix socket using sendmsg + SCM_RIGHTS.
fn send_msg_with_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) -> Result<(), i32> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut _,
        iov_len: data.len(),
    };

    let fd_bytes = fds.len() * std::mem::size_of::<RawFd>();
    let cmsg_space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) as usize };

    // Stack-allocate control buffer (aligned).
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;

    if !fds.is_empty() {
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = cmsg_space;

        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        if cmsg.is_null() {
            return Err(-1);
        }
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as usize;
            let fd_dst = libc::CMSG_DATA(cmsg);
            std::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, fd_dst, fd_bytes);
        }
    }

    let ret = unsafe { libc::sendmsg(sock, &raw const msg, libc::MSG_NOSIGNAL) };
    if ret < 0 {
        return Err(-std::io::Error::last_os_error().raw_os_error().unwrap_or(1));
    }
    Ok(())
}

/// Low-level: receive bytes + fds from a Unix socket using recvmsg + SCM_RIGHTS.
fn recv_msg_with_fds(
    sock: RawFd,
    data_buf: &mut [u8],
) -> Result<(usize, Vec<OwnedFd>), i32> {
    let mut iov = libc::iovec {
        iov_base: data_buf.as_mut_ptr().cast(),
        iov_len: data_buf.len(),
    };

    let cmsg_space = unsafe {
        libc::CMSG_SPACE((MAX_SCMRIGHTS_FDS * std::mem::size_of::<RawFd>()) as u32) as usize
    };
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space;

    let n = unsafe { libc::recvmsg(sock, &raw mut msg, 0) };
    if n < 0 {
        return Err(-std::io::Error::last_os_error().raw_os_error().unwrap_or(1));
    }

    let mut received_fds = Vec::new();
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let fd_bytes = (*cmsg).cmsg_len - libc::CMSG_LEN(0) as usize;
                let num_fds = fd_bytes / std::mem::size_of::<RawFd>();
                let fd_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
                for i in 0..num_fds {
                    let raw_fd = std::ptr::read_unaligned(fd_ptr.add(i));
                    received_fds.push(OwnedFd::from_raw_fd(raw_fd));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
        }
    }

    Ok((n as usize, received_fds))
}
```

### Step 3: Register the module

In `litebox_platform_linux_userland/src/lib.rs`, add the module declaration. Find an appropriate location near the top of the file (after the existing `mod syscall_intercept;` or similar module declarations).

Add:
```rust
pub(crate) mod forker;
```

### Step 4: Build and verify

Run:
```bash
cargo build -p litebox_platform_linux_userland 2>&1
```
Expected: compiles with no errors (module is defined but not yet used — only type definitions).

### Step 5: Commit

```bash
git add litebox_platform_linux_userland/src/forker.rs litebox_platform_linux_userland/src/lib.rs
git commit -m "feat: add forker protocol types and SCM_RIGHTS helpers

Define ForkRequest/ForkResponse wire format, StdioBinding enum,
ForkerHandle struct, and send/recv helpers for Unix socketpair
communication with SCM_RIGHTS fd passing. This is the foundation
for the forker process that will eliminate execve/openat from the
fork-restore path.

See docs/plans/2026-04-09-forker-process-design.md"
```

---

## Task 2: Implement the Forker Process Main Loop

The forker process is the core new component. It's a tight loop: recv request → double-fork → send response.

**Files:**
- Modify: `litebox_platform_linux_userland/src/forker.rs`

### Step 1: Add the forker main loop

Append to `forker.rs`:

```rust
// ── Forker process entry point ────────────────────────────────────

/// Entry point for the forker process.  Called after fork() in the
/// runner's single-threaded init window.
///
/// This function never returns — it loops forever or calls `_exit`.
///
/// # Arguments
/// * `cmd_sock` - The forker's end of the socketpair (runner has the other end).
/// * `dev_null_fd` - Pre-opened `/dev/null` fd for stdio wiring.
/// * `broker_fd` - The broker IPC socket fd (to be closed — forker doesn't use it).
pub(crate) fn forker_main(cmd_sock: RawFd, dev_null_fd: RawFd, broker_fd: Option<RawFd>) -> ! {
    // Close the broker socket — the forker doesn't use it.
    // Workers get their own connections via SCM_RIGHTS.
    if let Some(fd) = broker_fd {
        unsafe { libc::close(fd); }
    }

    loop {
        // 1. Block waiting for a ForkRequest.
        let (req, fds) = match recv_fork_request(cmd_sock) {
            Ok(pair) => pair,
            Err(_) => {
                // Runner closed the socket or error — exit cleanly.
                unsafe { libc::_exit(0); }
            }
        };

        // 2. Create a pipe for the intermediate child to report the
        //    grandchild's PID back to the forker.
        let mut pid_pipe = [0i32; 2];
        if unsafe { libc::pipe2(pid_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            // pipe2 failed — close received fds and report error.
            drop(fds);
            let _ = send_fork_response(cmd_sock, &ForkResponse {
                child_pid: -(std::io::Error::last_os_error().raw_os_error().unwrap_or(1)),
            });
            continue;
        }

        // 3. Double-fork.
        let fork_ret = unsafe { libc::fork() };
        if fork_ret < 0 {
            // fork failed.
            unsafe { libc::close(pid_pipe[0]); libc::close(pid_pipe[1]); }
            drop(fds);
            let _ = send_fork_response(cmd_sock, &ForkResponse {
                child_pid: -(std::io::Error::last_os_error().raw_os_error().unwrap_or(1)),
            });
            continue;
        }

        if fork_ret == 0 {
            // ── Intermediate child ──
            // Close the forker's side of the pid pipe (read end).
            unsafe { libc::close(pid_pipe[0]); }
            // Close the command socket — child doesn't need it.
            unsafe { libc::close(cmd_sock); }

            // Second fork — the actual worker.
            let fork2_ret = unsafe { libc::fork() };
            if fork2_ret < 0 {
                // Second fork failed.  Write -errno to pid pipe.
                let err = -(std::io::Error::last_os_error().raw_os_error().unwrap_or(1));
                let _ = unsafe {
                    libc::write(pid_pipe[1], &err as *const i32 as *const _, 4)
                };
                unsafe { libc::_exit(1); }
            }

            if fork2_ret == 0 {
                // ── Worker (grandchild) ──
                // Close the pid pipe write end — worker doesn't need it.
                unsafe { libc::close(pid_pipe[1]); }

                // Wire stdio from the request, then enter the worker
                // restore path.  This function never returns.
                worker_entry(req, fds, dev_null_fd);
            }

            // ── Intermediate child (parent of worker) ──
            // Write the grandchild PID to the forker, then exit.
            let _ = unsafe {
                libc::write(pid_pipe[1], &fork2_ret as *const i32 as *const _, 4)
            };
            // Close all inherited fds (they belong to the worker now).
            drop(fds);
            unsafe { libc::_exit(0); }
        }

        // ── Forker (parent) ──
        // Close the write end of the pid pipe.
        unsafe { libc::close(pid_pipe[1]); }

        // Close fds that are now owned by the child.
        drop(fds);

        // Reap the intermediate child.
        let mut status: libc::c_int = 0;
        loop {
            let ret = unsafe { libc::waitpid(fork_ret, &raw mut status, 0) };
            if ret != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }

        // Read the grandchild PID from the pid pipe.
        let mut grandchild_pid: i32 = -1;
        let _ = unsafe {
            libc::read(pid_pipe[0], &raw mut grandchild_pid as *mut _ as *mut _, 4)
        };
        unsafe { libc::close(pid_pipe[0]); }

        // Send the response back to the runner.
        let _ = send_fork_response(cmd_sock, &ForkResponse {
            child_pid: grandchild_pid,
        });
    }
}

/// Worker entry point, called in the grandchild after double-fork.
///
/// Wires stdio, then returns to let the caller set up the shim and
/// restore the guest.  This is a placeholder — the actual restore
/// logic will be wired up in Task 4.
fn worker_entry(req: ForkRequest, fds: Vec<OwnedFd>, dev_null_fd: RawFd) -> ! {
    // Wire stdio according to the request.
    for (fd_num, binding) in req.stdio.iter().enumerate() {
        match binding {
            StdioBinding::FromFdIndex(idx) => {
                let src_fd = fds[*idx as usize].as_raw_fd();
                if src_fd != fd_num as RawFd {
                    unsafe { libc::dup2(src_fd, fd_num as RawFd); }
                }
            }
            StdioBinding::DevNull => {
                if dev_null_fd != fd_num as RawFd {
                    unsafe { libc::dup2(dev_null_fd, fd_num as RawFd); }
                }
            }
            StdioBinding::Close => {
                unsafe { libc::close(fd_num as RawFd); }
            }
            StdioBinding::Inherit => {}
        }
    }

    // TODO(Task 4): Extract fds from the array by index, build shim+fs,
    // call fork_restore_and_ack, run_program.
    // For now, just ack failure and exit.
    if let Some(ack_fd) = fds.get(req.ack_fd_idx as usize) {
        let err: i32 = -libc::ENOSYS;
        let _ = unsafe {
            libc::write(ack_fd.as_raw_fd(), &err as *const i32 as *const _, 4)
        };
    }
    unsafe { libc::_exit(1); }
}
```

### Step 2: Build and verify

Run:
```bash
cargo build -p litebox_platform_linux_userland 2>&1
```
Expected: compiles. `forker_main` and `worker_entry` are defined but not called yet.

### Step 3: Commit

```bash
git add litebox_platform_linux_userland/src/forker.rs
git commit -m "feat: implement forker process main loop with double-fork

The forker sits in a recv→double-fork→send loop. It receives
ForkRequests with SCM_RIGHTS fds from the runner, double-forks
a worker (for PR_SET_CHILD_SUBREAPER re-parenting), and sends
back the grandchild PID. Worker entry is a placeholder for now."
```

---

## Task 3: Spawn the Forker from the Runner's Init Path

Modify the runner to fork the forker process during the single-threaded init window, and store the `ForkerHandle` on the platform.

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs` (add `ForkerHandle` field to Platform, spawn logic)
- Modify: `litebox_runner_linux_userland/src/lib.rs` (call forker spawn from `run()`)

### Step 1: Add ForkerHandle field to Platform

In `litebox_platform_linux_userland/src/lib.rs`, add a field to the `LinuxUserland` struct (around line 248, near `worker_processes`):

```rust
    /// Handle for the forker process (if active).
    forker_handle: std::sync::Mutex<Option<forker::ForkerHandle>>,
```

Initialize it in `Platform::with_network()` (around line 821, in the struct literal):

```rust
    forker_handle: std::sync::Mutex::new(None),
```

Also add it to `Platform::new()` if there's a separate constructor (check for both constructors and ensure both initialize the field).

### Step 2: Add `spawn_forker` method on Platform

Add a new public method to `impl LinuxUserland`:

```rust
    /// Spawn the forker process.  Must be called while the runner is
    /// still single-threaded (before any thread creation).
    ///
    /// * `dev_null_fd` — pre-opened `/dev/null` fd (will be inherited by forker).
    ///
    /// Returns `Ok(())` if the forker was spawned, or an error string.
    pub fn spawn_forker(&'static self, dev_null_fd: RawFd) -> Result<(), &'static str> {
        // Get the broker fd (if any) so the forker can close it.
        let broker_fd = self.broker_raw_fd();

        // Create the socketpair.
        let mut fds = [0i32; 2];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } != 0 {
            return Err("socketpair failed");
        }
        let runner_sock = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let forker_sock_raw = fds[1];

        // Set PR_SET_CHILD_SUBREAPER so double-forked workers re-parent
        // to the runner.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err("prctl(PR_SET_CHILD_SUBREAPER) failed");
        }

        // Fork the forker.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err("fork failed");
        }
        if pid == 0 {
            // ── Forker child ──
            // Close the runner's end of the socketpair.
            drop(runner_sock);
            // Clear CLOEXEC on the forker's socket so it survives.
            let flags = unsafe { libc::fcntl(forker_sock_raw, libc::F_GETFD) };
            if flags >= 0 {
                unsafe { libc::fcntl(forker_sock_raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
            }
            // Enter the forker main loop (never returns).
            forker::forker_main(forker_sock_raw, dev_null_fd, broker_fd);
        }

        // ── Runner (parent) ──
        // Close the forker's end.
        unsafe { libc::close(forker_sock_raw); }

        // Store the handle.
        let handle = forker::ForkerHandle::new(runner_sock);
        *self.forker_handle.lock().unwrap() = Some(handle);

        Ok(())
    }
```

### Step 3: Add `broker_raw_fd` helper

Add a helper to extract the broker socket raw fd (needed so the forker can close it):

```rust
    /// Returns the raw fd of the broker IPC socket, if one is connected.
    fn broker_raw_fd(&self) -> Option<RawFd> {
        // network_transport is an enum — check if it's Ipc and extract fd.
        // This requires reading the transport field.
        match &*self.network_transport {
            Some(NetworkTransport::Ipc(fd)) => Some(fd.as_raw_fd()),
            _ => None,
        }
    }
```

Note: You'll need to check how `network_transport` is stored. It's likely behind a `OnceCell` or `Option`. Adjust the pattern match accordingly based on the actual field type (examine `lib.rs` line 805).

### Step 4: Add `ForkerHandle::new` constructor

In `forker.rs`, add:

```rust
impl ForkerHandle {
    pub(crate) fn new(sock: OwnedFd) -> Self {
        Self {
            sock: std::sync::Mutex::new(sock),
        }
    }
}
```

### Step 5: Call from the runner's `run()` function

In `litebox_runner_linux_userland/src/lib.rs`, in the `run()` function, between `register_worker_spawn_flags` (line 458) and `let shim_builder = ...` (line 460), add:

```rust
    // Pre-open /dev/null for the forker to use for stdio wiring.
    let dev_null_fd = unsafe { libc::open(b"/dev/null\0".as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC) };
    if dev_null_fd >= 0 {
        // Spawn the forker process (single-threaded, safe to fork).
        if let Err(e) = platform.spawn_forker(dev_null_fd) {
            eprintln!("warning: failed to spawn forker: {e}; fork-restore will use posix_spawn fallback");
        }
    }
```

### Step 6: Build and verify

Run:
```bash
cargo build -p litebox_runner_linux_userland 2>&1
```
Expected: compiles. The forker is spawned but not yet used (spawn_worker_host_for_fork_restore still uses posix_spawn).

### Step 7: Run existing fork tests to verify no regression

Run:
```bash
cargo test -p litebox_runner_linux_userland --test run -- test_context_switch test_fork_exec_waitpid test_pipe_cross_process test_pipe_vfork_builtin 2>&1
```
Expected: all pass. The forker is spawned but idle — existing posix_spawn path is unchanged.

### Step 8: Commit

```bash
git add litebox_platform_linux_userland/src/forker.rs litebox_platform_linux_userland/src/lib.rs litebox_runner_linux_userland/src/lib.rs
git commit -m "feat: spawn forker process during runner init

Fork the forker process in the single-threaded init window (after
platform setup, before thread creation). Set PR_SET_CHILD_SUBREAPER
for worker re-parenting. The forker is spawned and running but not
yet used — the posix_spawn path remains the active code path."
```

---

## Task 4: Wire spawn_worker_host_for_fork_restore to Use the Forker

Replace the `posix_spawn` call in `spawn_worker_host_for_fork_restore` with a `sendmsg` to the forker, falling back to the existing `posix_spawn` path if the forker is unavailable.

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs`

### Step 1: Add a `try_spawn_via_forker` method

Add a new method that attempts to use the forker for the spawn. This mirrors the signature of the data that `spawn_worker_host_for_fork_restore` currently passes to `posix_spawn`, but sends it via the socketpair instead.

The method should:
1. Lock `self.forker_handle`.
2. If `None`, return `Err` (no forker available — fall back).
3. Build a `ForkRequest` from the stdio bindings, mux_fd, mux_streams, passthrough_fds, local_pipe_pairs.
4. Collect all raw fds into an SCM_RIGHTS array: snapshot_fd, ack_write_fd, result_write_fd, mux_fd (if any), passthrough host fds, drain memfds.
5. Pre-create a broker connection for the worker (call `connect_to_broker_ipc` and/or `connect_nine_p_channel` for 9P fds) and add those fds to the array.
6. Call `send_fork_request`.
7. Call `recv_fork_response` to get the child PID.
8. Return `Ok(child_pid)`.

This is the most complex step. The key challenge is translating the existing `WorkerExecStdioBindings` + `posix_spawn_file_actions` logic into `StdioBinding` + fd index mapping.

### Step 2: Modify `spawn_worker_host_for_fork_restore` to try forker first

At the top of `spawn_worker_host_for_fork_restore` (line 1699, after the spawn guard lock), add:

```rust
        // Try the forker path first (no execve, no openat).
        match self.try_spawn_via_forker(
            snapshot_bytes, &stdio, mux_fd, mux_streams,
            passthrough_fds, local_pipe_pairs,
        ) {
            Ok(pid) => return Ok(pid),
            Err(_) => {
                // Forker unavailable — fall through to posix_spawn.
            }
        }
```

The rest of the function (posix_spawn path) remains as-is for fallback.

### Step 3: Build and verify

Run:
```bash
cargo build -p litebox_runner_linux_userland 2>&1
```

### Step 4: Run fork tests

Run:
```bash
cargo test -p litebox_runner_linux_userland --test run -- test_context_switch test_pipe_vfork_builtin 2>&1
```
Expected: These will use the forker path but worker_entry currently acks with ENOSYS, so they'll fall back to posix_spawn. Both paths should work — verify the tests pass.

Actually, at this point the forker path will fail (worker_entry returns ENOSYS), the ack read returns non-zero, and `spawn_worker_host_for_fork_restore` returns `Err(ack_status)`. This means the fallback posix_spawn won't run for the same request. We need to handle this differently.

**Revised approach:** Don't try_spawn_via_forker yet. First implement the worker restore logic (Task 5), then wire everything up (Task 6).

### Step 3 (revised): Commit the `try_spawn_via_forker` skeleton

Write `try_spawn_via_forker` as a method that always returns `Err(())` for now:

```rust
    fn try_spawn_via_forker<FS>(
        &'static self,
        _snapshot_bytes: &[u8],
        _stdio: &WorkerExecStdioBindings<FS, LinuxUserland>,
        _mux_fd: Option<i32>,
        _mux_streams: &[(u32, usize, u8, u8, bool)],
        _passthrough_fds: &[(usize, i32, bool)],
        _local_pipe_pairs: &[(usize, usize, Vec<u8>, u32, u32)],
    ) -> Result<i32, ()>
    where
        FS: litebox::fs::FileSystem + Send + Sync + 'static,
    {
        // TODO: implement forker-based spawn.
        Err(())
    }
```

### Step 4: Commit

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "feat: add try_spawn_via_forker skeleton (returns Err for now)

Placeholder method on Platform that will attempt to spawn a
fork-restore worker via the forker process. Currently always
falls back to the posix_spawn path."
```

---

## Task 5: Implement Worker Restore Logic

This is the core: make `worker_entry` in `forker.rs` actually restore the guest process and run it, using inherited state instead of re-initializing from scratch.

**Files:**
- Modify: `litebox_platform_linux_userland/src/forker.rs`
- Modify: `litebox_runner_linux_userland/src/lib.rs` (add `run_forked_worker` entry point)

### Step 1: Add `run_forked_worker` to the runner

In `litebox_runner_linux_userland/src/lib.rs`, add a new public function that the worker calls after stdio wiring. This function:
- Reads the snapshot from the inherited memfd
- Uses the inherited platform (global ref)
- Builds filesystem from inherited tar mmap
- Optionally sets up 9P from inherited fds
- Builds the shim
- Calls `fork_restore_and_ack`
- Calls `run_program`

```rust
/// Entry point for a forked worker process (spawned via the forker,
/// not via posix_spawn).  The worker inherits the platform, tar mmap,
/// and signal handlers from the forker.
///
/// This function never returns.
pub fn run_forked_worker(
    snapshot_fd: std::os::fd::OwnedFd,
    ack_fd: i32,
    worker_result_fd: Option<i32>,
    pipe_bridges: Vec<PipeBridgeSpec>,
    mux_fd: Option<i32>,
    mux_streams: Vec<MuxStreamSpec>,
    local_pipes: Vec<LocalPipeSpec>,
    nine_p_fds: Option<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)>,
    nine_p_broker_path: Option<String>,
) -> ! {
    // The platform is inherited (global static set before the forker was forked).
    let platform = litebox_platform_multiplex::platform();

    // Read and deserialize the snapshot.
    let snapshot_data = match read_fork_snapshot_from_fd(snapshot_fd.as_raw_fd()) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("forked worker: failed to read snapshot: {e}");
            let mut ack_file = unsafe { std::fs::File::from_raw_fd(ack_fd) };
            let _ = std::io::Write::write_all(&mut ack_file, &(-1i32).to_le_bytes());
            std::process::exit(1);
        }
    };
    drop(snapshot_fd);

    let snapshot = match litebox_shim_linux::syscalls::fork_snapshot::ForkSnapshot::deserialize(&snapshot_data) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("forked worker: failed to deserialize snapshot: {e}");
            let mut ack_file = unsafe { std::fs::File::from_raw_fd(ack_fd) };
            let _ = std::io::Write::write_all(&mut ack_file, &(-1i32).to_le_bytes());
            std::process::exit(1);
        }
    };

    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    let litebox = shim_builder.litebox();

    // Build filesystem from inherited tar mmap (the tar data is in the
    // platform's static memory — we access it via the same mechanism).
    // For the forked worker, we use EMPTY_TAR_FILE for the tar layer
    // since the actual tar data is already mmap'd and inherited.
    // The platform's cow_regions contain the tar data pointer.
    //
    // Actually, the tar_data is a `&'static [u8]` leaked in the runner's
    // init.  The forker inherits it via fork.  We need to pass it somehow.
    // For now, use EMPTY_TAR_FILE — the 9P broker provides the full FS.
    let tar_data: &'static [u8] = litebox::fs::tar_ro::EMPTY_TAR_FILE;
    // TODO: pass tar_data pointer from runner to forker to worker via
    // a known global or via the ForkRequest message.

    let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem.with_root_privileges(|fs| {
        let mode = litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO;
        let _ = fs.mkdir("/tmp", mode);
    });

    let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
    let default_fs = litebox_shim_linux::default_fs(litebox, in_mem, tar_ro);

    // Set up 9P if fds were provided.
    if let Some((nine_p_tx_fd, nine_p_rx_fd)) = nine_p_fds {
        let (ring_writer, ring_reader) = litebox_common_linux::shmem_ring::ShmemRingPair::open(
            nine_p_tx_fd, nine_p_rx_fd,
        );

        let shim = shim_builder.build();
        let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let net_worker = start_network_worker(&shim, &shutdown);

        let writer = ShmemTransportWriter(ring_writer);
        let reader = ShmemTransportReader(ring_reader);
        let litebox = shim.litebox();
        let msize = 4 * 1024 * 1024u32;
        let (nine_p_fs, mut reader) =
            litebox::fs::nine_p::FileSystem::new(litebox, writer, reader, msize, "root", "/")
                .expect("9P attach failed in forked worker");

        let worker_handle = nine_p_fs.worker_handle();
        let _nine_p_worker = litebox_platform_linux_userland::spawn_host_thread(move || {
            let mut buf = alloc::vec::Vec::with_capacity(msize as usize);
            while worker_handle.poll_responses(&mut reader, &mut buf) {}
        });

        let combined = litebox::fs::layered::FileSystem::new(
            litebox,
            default_fs,
            nine_p_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
        );
        let combined_fs = std::sync::Arc::new(combined);

        let (program, mux_handle) = fork_restore_and_ack(
            &shim, snapshot, combined_fs, ack_fd,
            &pipe_bridges, mux_fd, &mux_streams, &local_pipes,
        ).expect("fork_restore_and_ack failed in forked worker");

        run_program(program, shutdown, net_worker, worker_result_fd, mux_handle);
    } else {
        let initial_file_system = std::sync::Arc::new(default_fs);
        let shim = shim_builder.build();
        let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let net_worker = start_network_worker(&shim, &shutdown);

        let (program, mux_handle) = fork_restore_and_ack(
            &shim, snapshot, initial_file_system, ack_fd,
            &pipe_bridges, mux_fd, &mux_streams, &local_pipes,
        ).expect("fork_restore_and_ack failed in forked worker");

        run_program(program, shutdown, net_worker, worker_result_fd, mux_handle);
    }
}
```

### Step 2: Update `worker_entry` in forker.rs to call `run_forked_worker`

Replace the placeholder `worker_entry` in `forker.rs` with logic that extracts fds from the array by index and calls `run_forked_worker`:

```rust
fn worker_entry(req: ForkRequest, fds: Vec<OwnedFd>, dev_null_fd: RawFd) -> ! {
    // Wire stdio.
    for (fd_num, binding) in req.stdio.iter().enumerate() {
        match binding {
            StdioBinding::FromFdIndex(idx) => {
                let src_fd = fds[*idx as usize].as_raw_fd();
                if src_fd != fd_num as RawFd {
                    unsafe { libc::dup2(src_fd, fd_num as RawFd); }
                }
            }
            StdioBinding::DevNull => {
                if dev_null_fd != fd_num as RawFd {
                    unsafe { libc::dup2(dev_null_fd, fd_num as RawFd); }
                }
            }
            StdioBinding::Close => {
                unsafe { libc::close(fd_num as RawFd); }
            }
            StdioBinding::Inherit => {}
        }
    }

    // Extract fds by index.
    let snapshot_fd = take_fd(&fds, req.snapshot_fd_idx);
    let ack_fd = fds[req.ack_fd_idx as usize].as_raw_fd();
    let result_fd = if req.result_fd_idx != 0xFF {
        Some(fds[req.result_fd_idx as usize].as_raw_fd())
    } else {
        None
    };
    let mux_fd = if req.mux_fd_idx != 0xFF {
        Some(fds[req.mux_fd_idx as usize].as_raw_fd())
    } else {
        None
    };

    // Build PipeBridgeSpec list from the request.
    let pipe_bridges: Vec<_> = req.pipe_bridges.iter().map(|&(guest_fd, host_fd_idx, is_read)| {
        litebox_runner_linux_userland::PipeBridgeSpec {
            guest_fd,
            host_fd: fds[host_fd_idx as usize].as_raw_fd(),
            is_read,
        }
    }).collect();

    // Build MuxStreamSpec list.
    let mux_streams: Vec<_> = req.mux_streams.iter().map(|&(stream_id, guest_fd, dir, stype, initial_eof)| {
        litebox_runner_linux_userland::MuxStreamSpec {
            stream_id,
            guest_fd,
            direction: dir,
            stream_type: stype,
            initial_eof,
        }
    }).collect();

    // Build LocalPipeSpec list.
    let local_pipes: Vec<_> = req.local_pipes.iter().map(|&(write_fd, read_fd, drain_fd_idx, w_flags, r_flags)| {
        let drained = if drain_fd_idx != 0xFF {
            // Read drain data from the memfd.
            read_drain_memfd(&fds[drain_fd_idx as usize])
        } else {
            Vec::new()
        };
        litebox_runner_linux_userland::LocalPipeSpec {
            write_fd,
            read_fd,
            drained,
            w_flags,
            r_flags,
        }
    }).collect();

    // TODO: Extract 9P fds if present.
    let nine_p_fds = None;

    // Forget all OwnedFds to avoid double-close (we extracted raw fds).
    // The worker process owns them now.
    for fd in fds {
        std::mem::forget(fd);
    }

    litebox_runner_linux_userland::run_forked_worker(
        snapshot_fd,
        ack_fd,
        result_fd,
        pipe_bridges,
        mux_fd,
        mux_streams,
        local_pipes,
        nine_p_fds,
        None,
    );
}

fn take_fd(fds: &[OwnedFd], idx: u8) -> OwnedFd {
    // Safety: we're taking ownership.  The original OwnedFd in the Vec
    // will be forgotten later to avoid double-close.
    unsafe { OwnedFd::from_raw_fd(fds[idx as usize].as_raw_fd()) }
}

fn read_drain_memfd(fd: &OwnedFd) -> Vec<u8> {
    use std::io::Read;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) };
    let _ = file.seek(std::io::SeekFrom::Start(0));
    let mut data = Vec::new();
    let _ = file.read_to_end(&mut data);
    // Don't drop — we'll forget later.
    std::mem::forget(file);
    data
}
```

### Step 3: Make necessary types public in the runner

In `litebox_runner_linux_userland/src/lib.rs`, make `PipeBridgeSpec`, `MuxStreamSpec`, `LocalPipeSpec`, `start_network_worker`, `ShmemTransportWriter`, `ShmemTransportReader`, `fork_restore_and_ack`, and `run_program` accessible from the platform crate. These are currently private.

The cleanest approach is to make `run_forked_worker` a function in the runner crate that calls these private functions directly. The platform crate doesn't need to see the internal types.

### Step 4: Build and verify

Run:
```bash
cargo build -p litebox_runner_linux_userland 2>&1
```

### Step 5: Commit

```bash
git add litebox_platform_linux_userland/src/forker.rs litebox_runner_linux_userland/src/lib.rs
git commit -m "feat: implement worker restore logic in forked worker

The worker_entry function in forker.rs now extracts fds from the
SCM_RIGHTS array, builds the PipeBridgeSpec/MuxStreamSpec/LocalPipeSpec
lists, and calls run_forked_worker in the runner crate. The runner's
run_forked_worker uses the inherited platform and tar mmap to build
the shim and filesystem, then calls fork_restore_and_ack + run_program."
```

---

## Task 6: Implement try_spawn_via_forker — The Full Wiring

Now connect everything: translate the posix_spawn arguments into a ForkRequest, send to the forker, handle the response.

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs`

### Step 1: Implement try_spawn_via_forker

Replace the skeleton with the full implementation:

1. Lock `forker_handle`. If `None`, return `Err(())`.
2. Create the snapshot memfd (same as current: `create_worker_fork_snapshot_fd`).
3. Create ack pipe and result pipe (same as current: `create_worker_result_pipe`).
4. Map `WorkerExecStdioBindings` to `StdioBinding` array:
   - `HostStdio { fd }` → `StdioBinding::FromFdIndex(idx)` + add the dup'd fd to the SCM_RIGHTS array
   - `HostPipe { fd }` → same
   - `Close` → `StdioBinding::Close`
   - Everything else (Pipe/Stream/Fs/Inherit) → `StdioBinding::DevNull`
5. Add snapshot_fd, ack_write_fd, result_write_fd to the fd array.
6. If mux_fd is set, add it to the fd array.
7. For each passthrough_fd, add the host fd to the array.
8. For each local_pipe_pair with drain data, create a drain memfd and add it.
9. Pre-create broker connection (if network is active) — call the same `connect_to_broker_ipc` the runner uses. Add the fd to the array. (This is a `socket` + `connect` call, but it happens in the **runner**, not in the worker.)
10. Pre-create 9P channel (if 9P is active) — call `connect_nine_p_channel`. Add the two memfds to the array.
11. Build and send the `ForkRequest`.
12. Receive `ForkResponse`. If `child_pid < 0`, return `Err`.
13. Close write ends of ack/result pipes.
14. Read ack from ack_read_fd (same as current).
15. Register worker in `worker_processes`.
16. Return `Ok(child_pid)`.

### Step 2: Add the forker-first attempt in spawn_worker_host_for_fork_restore

At the top of `spawn_worker_host_for_fork_restore`, after the spawn guard:

```rust
        // Try the forker path first.
        if let Ok(pid) = self.try_spawn_via_forker(
            snapshot_bytes, &stdio, mux_fd, mux_streams,
            passthrough_fds, local_pipe_pairs,
        ) {
            return Ok(pid);
        }
        // Fall through to posix_spawn.
```

### Step 3: Build and verify

```bash
cargo build -p litebox_runner_linux_userland 2>&1
```

### Step 4: Run ALL fork tests

```bash
cargo test -p litebox_runner_linux_userland --test run -- test_context_switch test_fork_exec_waitpid test_pipe_cross_process test_pipe_vfork_builtin test_pipe_cloexec test_pipe_nonpie_exec 2>&1
```
Expected: all pass using the forker path.

### Step 5: Run bash pipe test

```bash
cargo test -p litebox_runner_linux_userland --test run -- test_bash_pipe_cat 2>&1
```
Expected: passes.

### Step 6: Commit

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "feat: wire spawn_worker_host_for_fork_restore to use forker

The forker path is now the primary spawn mechanism for fork-restore
workers. The runner translates WorkerExecStdioBindings into
StdioBinding + fd index mapping, pre-creates broker/9P connections,
packs everything into a ForkRequest + SCM_RIGHTS message, and
sends it to the forker. Falls back to posix_spawn if the forker
is unavailable or if the request fails."
```

---

## Task 7: Verify with strace — Confirm Syscall Elimination

Verify that the forker-spawned worker process no longer makes `execve`, `openat`, `socket`, `connect`, `memfd_create`, `brk`, or `arch_prctl` syscalls.

**Files:**
- None (verification only)

### Step 1: Build release binary

```bash
cargo build --release -p litebox_runner_linux_userland 2>&1
```

### Step 2: Run the fork test under strace

Use the same test setup as before with `/tmp/fork_test.tar`:

```bash
strace -ff -o /tmp/strace_forker \
  timeout 10 \
  target/release/litebox_runner_linux_userland \
    -Z --network-broker /tmp/litebox-broker.sock \
    --initial-files /tmp/fork_test.tar \
    --program-from-tar /fork_test_static 2>&1
```

### Step 3: Identify the worker process PID

Look for the double-forked grandchild — it's the one that reads the snapshot memfd and maps pages at `0x400000`.

```bash
# Find the worker trace file.  It should NOT have execve.
for f in /tmp/strace_forker.*; do
  if grep -q 'mmap.*0x400000' "$f" && ! grep -q 'execve' "$f"; then
    echo "WORKER (no execve): $f"
  fi
done
```

### Step 4: Verify eliminated syscalls

```bash
# The worker trace should NOT contain these:
for syscall in execve openat socket connect memfd_create brk arch_prctl getrandom; do
  count=$(grep -c "^${syscall}" /tmp/strace_forker.WORKER_PID 2>/dev/null || echo 0)
  echo "${syscall}: ${count} calls"
done
```

Expected:
```
execve: 0 calls
openat: 0 calls
socket: 0 calls
connect: 0 calls
memfd_create: 0 calls
brk: 0 calls
arch_prctl: 0 calls
getrandom: 0 calls
```

### Step 5: Commit verification results as a doc update

```bash
# Update the design doc with results
git add docs/plans/2026-04-09-forker-process-design.md
git commit -m "docs: record strace verification of syscall elimination"
```

---

## Task 8: Run Full Test Suite — Regression Check

**Files:**
- None (verification only)

### Step 1: Run all integration tests

```bash
cargo test -p litebox_runner_linux_userland --test run 2>&1
```
Expected: all tests pass.

### Step 2: Run unit tests

```bash
cargo test -p litebox_shim_linux -- fork_snapshot::tests 2>&1
cargo test -p litebox -- fd::tests::test_clone_for_fork 2>&1
```
Expected: all pass.

### Step 3: Run the full workspace build

```bash
cargo build --release 2>&1
```
Expected: clean build.

### Step 4: Test copilot inside litebox (manual)

If the broker is available:
```bash
dev_tools/run_copilot_ipc.sh -- copilot --version
```
Expected: prints version, no crashes.

---

## Summary of Changes

| Task | What | Files |
|------|------|-------|
| 1 | Protocol types + SCM_RIGHTS helpers | `forker.rs` (new), `lib.rs` (mod decl) |
| 2 | Forker main loop (double-fork) | `forker.rs` |
| 3 | Spawn forker from runner init | `lib.rs` (platform), `lib.rs` (runner) |
| 4 | try_spawn_via_forker skeleton | `lib.rs` (platform) |
| 5 | Worker restore logic | `forker.rs`, `lib.rs` (runner) |
| 6 | Full wiring — forker-first spawn | `lib.rs` (platform) |
| 7 | strace verification | (verification only) |
| 8 | Full regression test | (verification only) |
