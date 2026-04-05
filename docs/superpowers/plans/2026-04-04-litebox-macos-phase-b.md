# macOS Shim Phase B: Sockets (AF_UNIX + AF_INET, TCP + UDP) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `litebox_shim_macos` with full socket support: AF_INET (TCP + UDP) via the existing `Network<Platform>` + smoltcp stack, AF_UNIX (stream + datagram) via in-memory ring buffers, `socketpair()`, basic `sendmsg`/`recvmsg`, and macOS-native socket options. Four end-to-end tests validate the implementation.

**Architecture:** AF_INET sockets go through the existing `Network<Platform>` + smoltcp stack (already initialized in `GlobalState`). AF_UNIX sockets use a separate `UnixSocket` type with `VecDeque`-backed `Channel` ring buffers, tracked via a side map in `GlobalState`. All 15 new BSD syscalls are decoded in `litebox_common_macos` and dispatched in the shim. Socket address structs use macOS BSD 4.4 layout (`sin_len` + `sin_family` as `u8` each). Socket options use macOS-specific constant values.

**Tech Stack:** Rust (edition 2024), `litebox` framework (Network, Pipes, FileSystem, fd subsystem), macOS aarch64 BSD ABI, C test programs compiled with `compile_macho_dynamic`.

**Design Spec:** `docs/superpowers/specs/2026-04-04-litebox-macos-phase-b-design.md`

**Test Commands:**
```bash
cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture
cargo clippy -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland -- -D warnings
cargo fmt --check -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland
```

---

## File Structure

### Files to modify

| File | Responsibility |
|------|---------------|
| `litebox_common_macos/src/errno.rs` | Add ~20 socket-related errno constants |
| `litebox_common_macos/src/syscall.rs` | Add 15 new syscall numbers + 15 new `MacosSyscallRequest` variants + decoding match arms |
| `litebox_shim_macos/src/lib.rs` | Add `StrongFd::Network` variant, remove `#[expect(dead_code)]` on `net` field, add `unix_sockets`/`unix_addr_table`/`unix_fd_counter` to `GlobalState` |
| `litebox_shim_macos/src/syscalls/mod.rs` | Add `mod net; mod unix;` declarations and 15 dispatch arms in `do_syscall` |
| `litebox_shim_macos/src/syscalls/file.rs` | Add `StrongFd::Network` arm to `sys_read`/`sys_write`/`sys_close`; handle Unix socket close |
| `litebox_runner_macos_on_macos_userland/tests/loader.rs` | Add 4 new test functions |

### Files to create

| File | Responsibility |
|------|---------------|
| `litebox_shim_macos/src/syscalls/net.rs` | AF_INET socket handlers, socket address structs, socket option mapping, `SocketOptions` struct, dispatch helpers |
| `litebox_shim_macos/src/syscalls/unix.rs` | AF_UNIX: `UnixSocket`, `Channel`, `Backlog`, `UnixAddrTable`, stream/datagram state machines, socketpair |
| `litebox_runner_macos_on_macos_userland/tests/tcp_echo.c` | TCP echo test (threaded server + client) |
| `litebox_runner_macos_on_macos_userland/tests/udp_sendrecv.c` | UDP send/recv test |
| `litebox_runner_macos_on_macos_userland/tests/unix_stream.c` | AF_UNIX stream test (threaded server + client) |
| `litebox_runner_macos_on_macos_userland/tests/socketpair.c` | socketpair bidirectional IPC test |

---

## Task 1: Add socket errno constants

**Files:**
- Modify: `litebox_common_macos/src/errno.rs:44-47` (add 20 new errno variants)

- [ ] **Step 1: Add socket-related errno constants**

In `litebox_common_macos/src/errno.rs`, add these variants to the `Errno` enum. Insert them after the `EAGAIN = 35` line (line 44) and before `ENOTEMPTY = 66` (line 45):

```rust
    EAGAIN = 35,
    EINPROGRESS = 36,
    EALREADY = 37,
    ENOTSOCK = 38,
    EDESTADDRREQ = 39,
    EMSGSIZE = 40,
    EPROTOTYPE = 41,
    ENOPROTOOPT = 42,
    EPROTONOSUPPORT = 43,
    EAFNOSUPPORT = 47,
    EADDRINUSE = 48,
    EADDRNOTAVAIL = 49,
    ENETDOWN = 50,
    ENETUNREACH = 51,
    ECONNRESET = 54,
    ENOBUFS = 55,
    EISCONN = 56,
    ENOTCONN = 57,
    ESHUTDOWN = 58,
    ETIMEDOUT = 60,
    ECONNREFUSED = 61,
    ENOTEMPTY = 66,
    ENOSYS = 78,
    EOPNOTSUPP = 102,
    ENOTSUP = 45,
```

Note: This replaces everything from `EAGAIN` through `ENOTSUP`. The enum variants do not need to be in numeric order (the existing code already has `ENOTEMPTY=66` before `ENOSYS=78` before `ENOTSUP=45`). `ENOPROTOOPT = 42` is also added — it's used when an unrecognized socket option is requested.

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p litebox_common_macos`
Expected: compiles with no errors.

- [ ] **Step 3: Commit**

```bash
git add litebox_common_macos/src/errno.rs
git commit -m "feat(macos): add socket-related errno constants for Phase B"
```

---

## Task 2: Add socket syscall numbers

**Files:**
- Modify: `litebox_common_macos/src/syscall.rs:10-69` (add 15 new `nr::*` constants)

- [ ] **Step 1: Add 15 new syscall number constants**

In `litebox_common_macos/src/syscall.rs`, add these constants inside `pub mod nr { ... }` after the existing `GETDIRENTRIES64` line (line 68):

```rust
    pub const RECVMSG: usize = 27;
    pub const SENDMSG: usize = 28;
    pub const RECVFROM: usize = 29;
    pub const ACCEPT: usize = 30;
    pub const GETPEERNAME: usize = 31;
    pub const GETSOCKNAME: usize = 32;
    pub const SOCKET: usize = 97;
    pub const CONNECT: usize = 98;
    pub const BIND: usize = 104;
    pub const SETSOCKOPT: usize = 105;
    pub const LISTEN: usize = 106;
    pub const GETSOCKOPT: usize = 118;
    pub const SENDTO: usize = 133;
    pub const SHUTDOWN: usize = 134;
    pub const SOCKETPAIR: usize = 135;
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p litebox_common_macos`
Expected: compiles with no errors.

- [ ] **Step 3: Commit**

```bash
git add litebox_common_macos/src/syscall.rs
git commit -m "feat(macos): add 15 socket syscall numbers"
```

---

## Task 3: Add socket syscall request variants and decoding

**Files:**
- Modify: `litebox_common_macos/src/syscall.rs:91-323` (add 15 new `MacosSyscallRequest` variants)
- Modify: `litebox_common_macos/src/syscall.rs:347-548` (add 15 decoding match arms in `try_from_raw`)

- [ ] **Step 1: Add 15 new variants to MacosSyscallRequest enum**

In `litebox_common_macos/src/syscall.rs`, add these variants to the `MacosSyscallRequest` enum, before the `Unknown` variant (currently at line 320):

```rust
    Socket {
        domain: u32,
        sock_type: u32,
        protocol: u32,
    },
    Bind {
        fd: u32,
        addr: u64,
        addrlen: u32,
    },
    Listen {
        fd: u32,
        backlog: u32,
    },
    Accept {
        fd: u32,
        addr: u64,
        addrlen: u64,
    },
    Connect {
        fd: u32,
        addr: u64,
        addrlen: u32,
    },
    Sendto {
        fd: u32,
        buf: u64,
        len: u64,
        flags: u32,
        dest_addr: u64,
        addrlen: u32,
    },
    Recvfrom {
        fd: u32,
        buf: u64,
        len: u64,
        flags: u32,
        src_addr: u64,
        addrlen: u64,
    },
    Sendmsg {
        fd: u32,
        msg: u64,
        flags: u32,
    },
    Recvmsg {
        fd: u32,
        msg: u64,
        flags: u32,
    },
    Shutdown {
        fd: u32,
        how: u32,
    },
    Socketpair {
        domain: u32,
        sock_type: u32,
        protocol: u32,
        sv: u64,
    },
    Setsockopt {
        fd: u32,
        level: u32,
        optname: u32,
        optval: u64,
        optlen: u32,
    },
    Getsockopt {
        fd: u32,
        level: u32,
        optname: u32,
        optval: u64,
        optlen: u64,
    },
    Getsockname {
        fd: u32,
        addr: u64,
        addrlen: u64,
    },
    Getpeername {
        fd: u32,
        addr: u64,
        addrlen: u64,
    },
```

- [ ] **Step 2: Add decoding match arms in try_from_raw**

In the `match nr_raw { ... }` block inside `try_from_raw`, add these arms before the `_ => MacosSyscallRequest::Unknown` catch-all (currently at line 548):

```rust
            nr::SOCKET => MacosSyscallRequest::Socket {
                domain: a0 as u32,
                sock_type: a1 as u32,
                protocol: a2 as u32,
            },
            nr::BIND => MacosSyscallRequest::Bind {
                fd: a0 as u32,
                addr: a1 as u64,
                addrlen: a2 as u32,
            },
            nr::LISTEN => MacosSyscallRequest::Listen {
                fd: a0 as u32,
                backlog: a1 as u32,
            },
            nr::ACCEPT => MacosSyscallRequest::Accept {
                fd: a0 as u32,
                addr: a1 as u64,
                addrlen: a2 as u64,
            },
            nr::CONNECT => MacosSyscallRequest::Connect {
                fd: a0 as u32,
                addr: a1 as u64,
                addrlen: a2 as u32,
            },
            nr::SENDTO => MacosSyscallRequest::Sendto {
                fd: a0 as u32,
                buf: a1 as u64,
                len: a2 as u64,
                flags: a3 as u32,
                dest_addr: a4 as u64,
                addrlen: a5 as u32,
            },
            nr::RECVFROM => MacosSyscallRequest::Recvfrom {
                fd: a0 as u32,
                buf: a1 as u64,
                len: a2 as u64,
                flags: a3 as u32,
                src_addr: a4 as u64,
                addrlen: a5 as u64,
            },
            nr::SENDMSG => MacosSyscallRequest::Sendmsg {
                fd: a0 as u32,
                msg: a1 as u64,
                flags: a2 as u32,
            },
            nr::RECVMSG => MacosSyscallRequest::Recvmsg {
                fd: a0 as u32,
                msg: a1 as u64,
                flags: a2 as u32,
            },
            nr::SHUTDOWN => MacosSyscallRequest::Shutdown {
                fd: a0 as u32,
                how: a1 as u32,
            },
            nr::SOCKETPAIR => MacosSyscallRequest::Socketpair {
                domain: a0 as u32,
                sock_type: a1 as u32,
                protocol: a2 as u32,
                sv: a3 as u64,
            },
            nr::SETSOCKOPT => MacosSyscallRequest::Setsockopt {
                fd: a0 as u32,
                level: a1 as u32,
                optname: a2 as u32,
                optval: a3 as u64,
                optlen: a4 as u32,
            },
            nr::GETSOCKOPT => MacosSyscallRequest::Getsockopt {
                fd: a0 as u32,
                level: a1 as u32,
                optname: a2 as u32,
                optval: a3 as u64,
                optlen: a4 as u64,
            },
            nr::GETSOCKNAME => MacosSyscallRequest::Getsockname {
                fd: a0 as u32,
                addr: a1 as u64,
                addrlen: a2 as u64,
            },
            nr::GETPEERNAME => MacosSyscallRequest::Getpeername {
                fd: a0 as u32,
                addr: a1 as u64,
                addrlen: a2 as u64,
            },
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_common_macos`
Expected: compiles with no errors (new variants are unused for now).

- [ ] **Step 4: Commit**

```bash
git add litebox_common_macos/src/syscall.rs
git commit -m "feat(macos): add 15 socket syscall request variants and decoding"
```

---

## Task 4: Create net.rs with socket address structs, option types, and error mapping

**Files:**
- Create: `litebox_shim_macos/src/syscalls/net.rs`

This task creates the foundational types for the socket implementation. The file will grow in later tasks as syscall handlers are added.

- [ ] **Step 1: Create `litebox_shim_macos/src/syscalls/net.rs` with types**

Create the file with the following content:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AF_INET socket syscall handlers and shared socket types.

use alloc::sync::Arc;
use alloc::vec;
use core::time::Duration;

use litebox::fd::TypedFd;
use litebox::net::{
    CloseBehavior, Network, NetworkProxy, Protocol, ReceiveFlags, SendFlags, TcpOptionData,
    TcpOptionName,
};
use litebox::net::errors::{
    AcceptError, BindError, CloseError, ConnectError, GetTcpOptionError, ListenError,
    LocalAddrError, ReceiveError, RemoteAddrError, SendError, SetTcpOptionError, SocketError,
};
use litebox::net::socket_channel::{
    DatagramSocketChannel, NetworkProxy as NetworkProxyEnum, SocketState, StreamSocketChannel,
};
use litebox_common_macos::errno::Errno;

use crate::{Platform, ShimFS, Task};

// ---------------------------------------------------------------------------
// macOS socket constants
// ---------------------------------------------------------------------------

/// macOS address families.
pub(crate) const AF_UNIX: u32 = 1;
pub(crate) const AF_INET: u32 = 2;

/// macOS socket types.
pub(crate) const SOCK_STREAM: u32 = 1;
pub(crate) const SOCK_DGRAM: u32 = 2;

/// macOS socket option levels.
pub(crate) const SOL_SOCKET: u32 = 0xFFFF;
pub(crate) const IPPROTO_TCP: u32 = 6;
pub(crate) const IPPROTO_IP: u32 = 0;

/// macOS SOL_SOCKET option names.
const SO_REUSEADDR: u32 = 0x0004;
const SO_TYPE: u32 = 0x1008;
const SO_BROADCAST: u32 = 0x0020;
const SO_SNDBUF: u32 = 0x1001;
const SO_RCVBUF: u32 = 0x1002;
const SO_KEEPALIVE: u32 = 0x0008;
const SO_LINGER: u32 = 0x0080;
const SO_LINGER_SEC: u32 = 0x1080;
const SO_RCVTIMEO: u32 = 0x1006;
const SO_SNDTIMEO: u32 = 0x1005;
const SO_ERROR: u32 = 0x1007;

/// macOS IPPROTO_TCP option names.
const TCP_NODELAY: u32 = 0x01;
const TCP_NOPUSH: u32 = 0x04;
const TCP_KEEPALIVE_OPT: u32 = 0x10;
const TCP_KEEPINTVL: u32 = 0x101;
const TCP_KEEPCNT: u32 = 0x102;

/// macOS IPPROTO_IP option names.
const IP_TOS: u32 = 3;

/// Default socket buffer size (matches litebox SOCKET_BUFFER_SIZE).
const SOCKET_BUFFER_SIZE: u32 = 65536 * 4;

/// macOS shutdown(2) `how` values.
const SHUT_RD: u32 = 0;
const SHUT_WR: u32 = 1;
const SHUT_RDWR: u32 = 2;

// ---------------------------------------------------------------------------
// Socket type enum
// ---------------------------------------------------------------------------

/// Socket type (stream or datagram).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SockType {
    Stream,
    Datagram,
}

impl SockType {
    pub(crate) fn try_from_raw(raw: u32) -> Result<Self, Errno> {
        // Mask off any flags in the high bits (macOS doesn't define SOCK_NONBLOCK/SOCK_CLOEXEC,
        // but some programs may pass them anyway).
        match raw & 0xFF {
            SOCK_STREAM => Ok(SockType::Stream),
            SOCK_DGRAM => Ok(SockType::Datagram),
            _ => Err(Errno::EPROTONOSUPPORT),
        }
    }
}

// ---------------------------------------------------------------------------
// Socket option name
// ---------------------------------------------------------------------------

/// Decoded socket option name.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SocketOptionName {
    // SOL_SOCKET
    ReuseAddr,
    Type,
    Broadcast,
    SndBuf,
    RcvBuf,
    KeepAlive,
    Linger,
    LingerSec,
    RcvTimeo,
    SndTimeo,
    Error,
    // IPPROTO_TCP
    TcpNoDelay,
    TcpNoPush,
    TcpKeepAlive,
    TcpKeepIntvl,
    TcpKeepCnt,
    // IPPROTO_IP
    IpTos,
}

impl SocketOptionName {
    /// Decode a (level, optname) pair into a known option, or None if unrecognized.
    pub(crate) fn try_from_raw(level: u32, optname: u32) -> Option<Self> {
        match level {
            SOL_SOCKET => match optname {
                SO_REUSEADDR => Some(Self::ReuseAddr),
                SO_TYPE => Some(Self::Type),
                SO_BROADCAST => Some(Self::Broadcast),
                SO_SNDBUF => Some(Self::SndBuf),
                SO_RCVBUF => Some(Self::RcvBuf),
                SO_KEEPALIVE => Some(Self::KeepAlive),
                SO_LINGER => Some(Self::Linger),
                SO_LINGER_SEC => Some(Self::LingerSec),
                SO_RCVTIMEO => Some(Self::RcvTimeo),
                SO_SNDTIMEO => Some(Self::SndTimeo),
                SO_ERROR => Some(Self::Error),
                _ => None,
            },
            IPPROTO_TCP => match optname {
                TCP_NODELAY => Some(Self::TcpNoDelay),
                TCP_NOPUSH => Some(Self::TcpNoPush),
                TCP_KEEPALIVE_OPT => Some(Self::TcpKeepAlive),
                TCP_KEEPINTVL => Some(Self::TcpKeepIntvl),
                TCP_KEEPCNT => Some(Self::TcpKeepCnt),
                _ => None,
            },
            IPPROTO_IP => match optname {
                IP_TOS => Some(Self::IpTos),
                _ => None,
            },
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Socket options storage
// ---------------------------------------------------------------------------

/// Per-socket option state, shared between inet and unix paths.
#[derive(Default)]
pub(crate) struct SocketOptions {
    pub(crate) reuse_address: bool,
    pub(crate) keep_alive: bool,
    pub(crate) broadcast: bool,
    pub(crate) recv_timeout: Option<Duration>,
    pub(crate) send_timeout: Option<Duration>,
    pub(crate) linger_timeout: Option<Duration>,
}

// ---------------------------------------------------------------------------
// macOS sockaddr structures
// ---------------------------------------------------------------------------

/// macOS `sockaddr_in` (BSD 4.4 style with length prefix).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CSockInetAddr {
    pub(crate) sin_len: u8,
    pub(crate) sin_family: u8,
    pub(crate) sin_port: [u8; 2], // network byte order
    pub(crate) sin_addr: [u8; 4],
    pub(crate) sin_zero: [u8; 8],
}

const UNIX_PATH_MAX: usize = 104;

/// macOS `sockaddr_un` (BSD 4.4 style with length prefix).
#[repr(C)]
#[derive(Clone)]
pub(crate) struct CSockUnixAddr {
    pub(crate) sun_len: u8,
    pub(crate) sun_family: u8,
    pub(crate) sun_path: [u8; UNIX_PATH_MAX],
}

/// A parsed socket address (either inet or unix).
#[derive(Debug, Clone)]
pub(crate) enum SocketAddress {
    Inet(core::net::SocketAddrV4),
    Unix(UnixSocketAddr),
}

/// A Unix socket address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnixSocketAddr {
    /// Named path (e.g., "/tmp/test.sock").
    Path(alloc::string::String),
    /// Unnamed (e.g., from socketpair or unbound socket).
    Unnamed,
}

/// macOS `linger` struct layout.
#[repr(C)]
#[derive(Clone, Copy)]
struct CLinger {
    l_onoff: i32,
    l_linger: i32,
}

/// macOS `timeval` struct layout (used for SO_RCVTIMEO / SO_SNDTIMEO).
#[repr(C)]
#[derive(Clone, Copy)]
struct CTimeval {
    tv_sec: i64,  // __darwin_time_t = long
    tv_usec: i32, // __darwin_suseconds_t = int
}

// ---------------------------------------------------------------------------
// Address read/write helpers
// ---------------------------------------------------------------------------

use litebox_common_linux::mem::{ConstPtr, MutPtr};

/// Read a socket address from guest memory.
pub(crate) fn read_sockaddr_from_user(addr_ptr: u64, addrlen: u32) -> Result<SocketAddress, Errno> {
    if addrlen < 2 {
        return Err(Errno::EINVAL);
    }
    let ptr: ConstPtr<u8> = ConstPtr::from_usize(addr_ptr as usize);

    // Read the family byte (offset 1 on macOS — offset 0 is sin_len/sun_len).
    let family_bytes = ptr.to_owned_slice(2).ok_or(Errno::EFAULT)?;
    let family = family_bytes[1]; // sin_family / sun_family

    match family as u32 {
        AF_INET => {
            if (addrlen as usize) < core::mem::size_of::<CSockInetAddr>() {
                return Err(Errno::EINVAL);
            }
            let raw = ptr
                .to_owned_slice(core::mem::size_of::<CSockInetAddr>())
                .ok_or(Errno::EFAULT)?;
            // Safety: CSockInetAddr is repr(C, packed) and we have enough bytes.
            let sa: CSockInetAddr = unsafe { core::ptr::read_unaligned(raw.as_ptr().cast()) };
            let port = u16::from_be_bytes(sa.sin_port);
            let ip = core::net::Ipv4Addr::from(sa.sin_addr);
            Ok(SocketAddress::Inet(core::net::SocketAddrV4::new(ip, port)))
        }
        AF_UNIX => {
            if (addrlen as usize) < 2 {
                return Err(Errno::EINVAL);
            }
            let path_len = (addrlen as usize).saturating_sub(2).min(UNIX_PATH_MAX);
            if path_len == 0 {
                return Ok(SocketAddress::Unix(UnixSocketAddr::Unnamed));
            }
            // Read the path bytes starting at offset 2.
            let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(addr_ptr as usize + 2);
            let path_bytes = path_ptr.to_owned_slice(path_len).ok_or(Errno::EFAULT)?;
            // Find the null terminator.
            let end = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_len);
            if end == 0 {
                // macOS does not support abstract namespace.
                return Err(Errno::EINVAL);
            }
            let path = core::str::from_utf8(&path_bytes[..end])
                .map_err(|_| Errno::EINVAL)?;
            Ok(SocketAddress::Unix(UnixSocketAddr::Path(
                alloc::string::String::from(path),
            )))
        }
        _ => Err(Errno::EAFNOSUPPORT),
    }
}

/// Write a socket address to guest memory, updating the length pointer.
pub(crate) fn write_sockaddr_inet_to_user(
    endpoint: &core::net::SocketAddr,
    buf_ptr: u64,
    len_ptr: u64,
) -> Result<(), Errno> {
    if buf_ptr == 0 || len_ptr == 0 {
        return Ok(()); // NULL addr — caller doesn't want the address
    }

    let len_mut: MutPtr<u32> = MutPtr::from_usize(len_ptr as usize);
    let buf_len_bytes = len_mut.to_owned_slice(1).ok_or(Errno::EFAULT)?;
    // Read current buffer length (it's a u32 at *len_ptr)
    let buf_len_raw: ConstPtr<u32> = ConstPtr::from_usize(len_ptr as usize);
    let buf_len_val = buf_len_raw.to_owned_slice(1).ok_or(Errno::EFAULT)?;
    let buf_len = buf_len_val[0] as usize;

    let sa_size = core::mem::size_of::<CSockInetAddr>();
    let write_len = buf_len.min(sa_size);

    if let core::net::SocketAddr::V4(v4) = endpoint {
        let sa = CSockInetAddr {
            sin_len: sa_size as u8,
            sin_family: AF_INET as u8,
            sin_port: v4.port().to_be_bytes(),
            sin_addr: v4.ip().octets(),
            sin_zero: [0; 8],
        };

        let sa_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                (&sa as *const CSockInetAddr).cast::<u8>(),
                sa_size,
            )
        };

        let buf_mut: MutPtr<u8> = MutPtr::from_usize(buf_ptr as usize);
        buf_mut
            .copy_from_slice(0, &sa_bytes[..write_len])
            .ok_or(Errno::EFAULT)?;
    }

    // Write back the actual length.
    let len_out: MutPtr<u32> = MutPtr::from_usize(len_ptr as usize);
    len_out
        .copy_from_slice(0, &[sa_size as u32])
        .ok_or(Errno::EFAULT)?;

    Ok(())
}

/// Write a Unix socket address to guest memory.
pub(crate) fn write_sockaddr_unix_to_user(
    addr: &UnixSocketAddr,
    buf_ptr: u64,
    len_ptr: u64,
) -> Result<(), Errno> {
    if buf_ptr == 0 || len_ptr == 0 {
        return Ok(());
    }

    let path_bytes = match addr {
        UnixSocketAddr::Path(p) => p.as_bytes(),
        UnixSocketAddr::Unnamed => &[],
    };

    let sa_len = 2 + path_bytes.len() + 1; // sun_len + sun_family + path + null
    let mut sa_buf = vec![0u8; sa_len.max(2)];
    sa_buf[0] = sa_len as u8; // sun_len
    sa_buf[1] = AF_UNIX as u8; // sun_family
    if !path_bytes.is_empty() {
        sa_buf[2..2 + path_bytes.len()].copy_from_slice(path_bytes);
        // null terminator is already 0 from vec init
    }

    // Read current buffer length.
    let buf_len_raw: ConstPtr<u32> = ConstPtr::from_usize(len_ptr as usize);
    let buf_len_val = buf_len_raw.to_owned_slice(1).ok_or(Errno::EFAULT)?;
    let buf_len = buf_len_val[0] as usize;
    let write_len = buf_len.min(sa_buf.len());

    let buf_mut: MutPtr<u8> = MutPtr::from_usize(buf_ptr as usize);
    buf_mut
        .copy_from_slice(0, &sa_buf[..write_len])
        .ok_or(Errno::EFAULT)?;

    let len_out: MutPtr<u32> = MutPtr::from_usize(len_ptr as usize);
    len_out
        .copy_from_slice(0, &[sa_buf.len() as u32])
        .ok_or(Errno::EFAULT)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Error conversion: litebox net errors -> macOS Errno
// ---------------------------------------------------------------------------

pub(crate) fn socket_error_to_errno(e: SocketError) -> Errno {
    match e {
        SocketError::UnsupportedProtocol(_) => Errno::EPROTONOSUPPORT,
        _ => Errno::EINVAL,
    }
}

pub(crate) fn bind_error_to_errno(e: BindError) -> Errno {
    match e {
        BindError::InvalidFd => Errno::EBADF,
        BindError::UnsupportedAddress(_) => Errno::EAFNOSUPPORT,
        BindError::PortAlreadyInUse(_) => Errno::EADDRINUSE,
        BindError::AlreadyBound => Errno::EINVAL,
        _ => Errno::EINVAL,
    }
}

pub(crate) fn listen_error_to_errno(e: ListenError) -> Errno {
    match e {
        ListenError::InvalidFd => Errno::EBADF,
        ListenError::InvalidAddress => Errno::EINVAL,
        ListenError::InvalidState => Errno::EINVAL,
        ListenError::NoAvailableFreeEphemeralPorts => Errno::EADDRINUSE,
        _ => Errno::EINVAL,
    }
}

pub(crate) fn accept_error_to_errno(e: AcceptError) -> Errno {
    match e {
        AcceptError::InvalidFd => Errno::EBADF,
        AcceptError::NotListening => Errno::EINVAL,
        AcceptError::NoConnectionsReady => Errno::EAGAIN,
        _ => Errno::EINVAL,
    }
}

pub(crate) fn connect_error_to_errno(e: ConnectError) -> Errno {
    match e {
        ConnectError::InvalidFd => Errno::EBADF,
        ConnectError::UnsupportedAddress(_) => Errno::EAFNOSUPPORT,
        ConnectError::PortAllocationFailure(_) => Errno::EADDRINUSE,
        ConnectError::Unaddressable => Errno::EADDRNOTAVAIL,
        ConnectError::InProgress => Errno::EINPROGRESS,
        ConnectError::InvalidState => Errno::ECONNREFUSED,
        _ => Errno::EINVAL,
    }
}

pub(crate) fn send_error_to_errno(e: SendError) -> Errno {
    match e {
        SendError::InvalidFd => Errno::EBADF,
        SendError::SocketInInvalidState => Errno::EPIPE,
        SendError::Unaddressable => Errno::EINVAL,
        SendError::BufferFull => Errno::EAGAIN,
        SendError::PortAllocationFailure(_) => Errno::EADDRINUSE,
        SendError::UnnecessaryDestinationAddress => Errno::EISCONN,
        SendError::DestinationAddressRequired => Errno::EDESTADDRREQ,
        _ => Errno::EINVAL,
    }
}

pub(crate) fn receive_error_to_errno(e: ReceiveError) -> Errno {
    match e {
        ReceiveError::InvalidFd => Errno::EBADF,
        ReceiveError::SocketInInvalidState => Errno::EAGAIN,
        ReceiveError::OperationFinished => Errno::ESHUTDOWN,
        _ => Errno::EINVAL,
    }
}

pub(crate) fn close_error_to_errno(e: CloseError) -> Errno {
    match e {
        CloseError::InvalidFd => Errno::EBADF,
        CloseError::DataPending => Errno::EIO,
        _ => Errno::EIO,
    }
}

pub(crate) fn local_addr_error_to_errno(e: LocalAddrError) -> Errno {
    match e {
        LocalAddrError::InvalidFd => Errno::EBADF,
        _ => Errno::EINVAL,
    }
}

pub(crate) fn remote_addr_error_to_errno(e: RemoteAddrError) -> Errno {
    match e {
        RemoteAddrError::InvalidFd => Errno::EBADF,
        RemoteAddrError::NotConnected => Errno::ENOTCONN,
        _ => Errno::EINVAL,
    }
}

pub(crate) fn set_tcp_option_error_to_errno(e: SetTcpOptionError) -> Errno {
    match e {
        SetTcpOptionError::InvalidFd => Errno::EBADF,
        SetTcpOptionError::NotTcpSocket => Errno::ENOPROTOOPT,
        _ => Errno::EINVAL,
    }
}

pub(crate) fn get_tcp_option_error_to_errno(e: GetTcpOptionError) -> Errno {
    match e {
        GetTcpOptionError::InvalidFd => Errno::EBADF,
        GetTcpOptionError::NotTcpSocket => Errno::ENOPROTOOPT,
        _ => Errno::EINVAL,
    }
}
```

Note: The Network API uses `core::net::SocketAddr` (and `SocketAddrV4`) for addresses, NOT `smoltcp::wire::IpEndpoint`. All address conversions between guest `sockaddr_in` and the Network API should go through `core::net::SocketAddrV4`. The `smoltcp` crate is used internally by the Network layer but not exposed in the public API.

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: may have unused import warnings (that's fine — they'll be used in later tasks). Fix any actual errors. Don't add `mod net;` to `mod.rs` yet — that happens in Task 7.

Actually, don't compile yet — the module isn't wired in. Just validate the file is syntactically correct by checking `cargo check -p litebox_shim_macos` after Task 7 wires it in.

- [ ] **Step 3: Commit**

```bash
git add litebox_shim_macos/src/syscalls/net.rs
git commit -m "feat(macos): add socket address structs, option types, and error mapping"
```

---

## Task 5: Add StrongFd::Network variant and wire into read/write/close

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs:834-850` (add `Network` variant to `StrongFd`, update `from_raw`)
- Modify: `litebox_shim_macos/src/lib.rs:801-802` (remove `#[expect(dead_code)]` on `net` field)
- Modify: `litebox_shim_macos/src/syscalls/file.rs:80-196` (add `Network` arm to `sys_read`, `sys_write`, `sys_close`)

- [ ] **Step 1: Remove dead_code expect from `net` field in GlobalState**

In `litebox_shim_macos/src/lib.rs`, find the `net` field (line 801-802):

```rust
    #[expect(dead_code, reason = "will be used when network syscalls are added")]
    net: litebox::sync::Mutex<Platform, Network<Platform>>,
```

Replace with:

```rust
    /// The network subsystem (AF_INET sockets via smoltcp).
    net: litebox::sync::Mutex<Platform, Network<Platform>>,
```

- [ ] **Step 2: Add `Network` variant to `StrongFd`**

In `litebox_shim_macos/src/lib.rs`, find the `StrongFd` enum (line 834-837):

```rust
enum StrongFd<FS: ShimFS> {
    FileSystem(Arc<TypedFd<FS>>),
    Pipes(Arc<TypedFd<Pipes<Platform>>>),
}
```

Replace with:

```rust
enum StrongFd<FS: ShimFS> {
    FileSystem(Arc<TypedFd<FS>>),
    Pipes(Arc<TypedFd<Pipes<Platform>>>),
    Network(Arc<TypedFd<Network<Platform>>>),
}
```

- [ ] **Step 3: Update `StrongFd::from_raw` to try Network**

In `litebox_shim_macos/src/lib.rs`, find `StrongFd::from_raw` (line 841-850):

```rust
    fn from_raw(rds: &RawDescriptorStorage, fd: usize) -> Result<Self, Errno> {
        if let Ok(fd) = rds.fd_from_raw_integer::<FS>(fd) {
            return Ok(StrongFd::FileSystem(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<Pipes<Platform>>(fd) {
            return Ok(StrongFd::Pipes(fd));
        }
        Err(Errno::EBADF)
    }
```

Replace with:

```rust
    fn from_raw(rds: &RawDescriptorStorage, fd: usize) -> Result<Self, Errno> {
        if let Ok(fd) = rds.fd_from_raw_integer::<FS>(fd) {
            return Ok(StrongFd::FileSystem(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<Pipes<Platform>>(fd) {
            return Ok(StrongFd::Pipes(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<Network<Platform>>(fd) {
            return Ok(StrongFd::Network(fd));
        }
        Err(Errno::EBADF)
    }
```

- [ ] **Step 4: Add Network arm to sys_read**

In `litebox_shim_macos/src/syscalls/file.rs`, find the `sys_read` method's match on `strong_fd` (lines 90-103). After the `Pipes` arm, add:

```rust
            crate::StrongFd::Network(ref typed_fd) => {
                let mut net = self.global.net.lock();
                net.receive(typed_fd, &mut kernel_buf, ReceiveFlags::empty(), None)
                    .map_err(crate::syscalls::net::receive_error_to_errno)?
            }
```

Add the import at the top of `file.rs`:

```rust
use litebox::net::ReceiveFlags;
```

- [ ] **Step 5: Add Network arm to sys_write**

In `litebox_shim_macos/src/syscalls/file.rs`, find the `sys_write` method's match on `strong_fd` (lines 139-152). After the `Pipes` arm, add:

```rust
            crate::StrongFd::Network(ref typed_fd) => {
                let mut net = self.global.net.lock();
                net.send(typed_fd, &data, SendFlags::empty(), None)
                    .map_err(crate::syscalls::net::send_error_to_errno)?
            }
```

Add the import at the top of `file.rs`:

```rust
use litebox::net::SendFlags;
```

- [ ] **Step 6: Add Network arm to sys_close**

In `litebox_shim_macos/src/syscalls/file.rs`, find `sys_close` (lines 160-196). After the pipes `fd_consume_raw_integer` block (lines 190-192), add a network block:

```rust
            if let Ok(typed_fd) = rds.fd_consume_raw_integer::<Network<Platform>>(raw_fd) {
                return self
                    .global
                    .net
                    .lock()
                    .close(&typed_fd, CloseBehavior::GracefulIfNoPendingData)
                    .map_err(crate::syscalls::net::close_error_to_errno);
            }
```

Add the import at the top of `file.rs`:

```rust
use litebox::net::{CloseBehavior, Network};
use crate::Platform;
```

Note: `Platform` should already be in scope via `crate::Platform`. Check if `Network` needs to be imported — it might already be accessible through the existing imports. Adjust as needed.

- [ ] **Step 7: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles with no errors. The `Network` arm in `sys_read`/`sys_write` may warn about unused code until actual network sockets are created.

Note: This task should be done AFTER Task 7 (which adds `mod net;` to `mod.rs`), since the error conversion functions are defined in `net.rs`. If Task 5 is done before Task 7, temporarily use inline error mapping or stub functions. The recommended approach is: do Task 4 first (creates `net.rs`), then Task 7 step 1 (adds `mod net;`), then come back to Task 5.

**Alternative ordering:** If you prefer to keep tasks independent, you can inline the error mapping temporarily:

```rust
// Temporary — replaced when net.rs is wired in:
.map_err(|_| Errno::EIO)
```

- [ ] **Step 8: Commit**

```bash
git add litebox_shim_macos/src/lib.rs litebox_shim_macos/src/syscalls/file.rs
git commit -m "feat(macos): add StrongFd::Network variant, wire into read/write/close"
```

---

## Task 6: Add unix_sockets, unix_addr_table, unix_fd_counter to GlobalState

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs:786-818` (add 3 new fields to `GlobalState`)
- Modify: `litebox_shim_macos/src/lib.rs:250-268` (initialize new fields in `build()`)

- [ ] **Step 1: Add Unix socket fields to GlobalState**

In `litebox_shim_macos/src/lib.rs`, find the `GlobalState` struct (lines 786-818). Add these fields after the `fd_paths` field (line 809):

```rust
    /// Maps virtual fd numbers to Unix socket objects.
    unix_sockets: litebox::sync::RwLock<Platform, BTreeMap<usize, Arc<crate::syscalls::unix::UnixSocket<FS>>>>,
    /// Maps Unix socket paths to their bound entries.
    unix_addr_table: litebox::sync::RwLock<Platform, BTreeMap<alloc::string::String, crate::syscalls::unix::UnixAddrEntry<FS>>>,
    /// Counter for allocating virtual fd numbers for Unix sockets.
    unix_fd_counter: core::sync::atomic::AtomicUsize,
```

- [ ] **Step 2: Initialize new fields in build()**

In `litebox_shim_macos/src/lib.rs`, find the `GlobalState` construction in `build()` (lines 253-268). Add these fields to the struct literal:

```rust
            unix_sockets: litebox::sync::RwLock::new(BTreeMap::new()),
            unix_addr_table: litebox::sync::RwLock::new(BTreeMap::new()),
            unix_fd_counter: core::sync::atomic::AtomicUsize::new(0x1_0000),
```

Note: `unix_fd_counter` starts at `0x1_0000` (65536) to avoid collisions with raw fd numbers from `RawDescriptorStorage` (which allocates from 0 upward). This ensures Unix socket fd numbers never overlap with filesystem/pipe/network fds.

- [ ] **Step 3: Note on compilation**

This task will NOT compile until `crate::syscalls::unix::UnixSocket` and `crate::syscalls::unix::UnixAddrEntry` are defined (Task 13). You have two options:

**Option A (recommended):** Do this task together with Task 13 (which creates `unix.rs`). 

**Option B:** Use placeholder types temporarily:

```rust
    // Placeholder — will be replaced when unix.rs is implemented:
    unix_sockets: litebox::sync::RwLock<Platform, BTreeMap<usize, ()>>,
    unix_addr_table: litebox::sync::RwLock<Platform, BTreeMap<alloc::string::String, ()>>,
```

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/lib.rs
git commit -m "feat(macos): add Unix socket tracking fields to GlobalState"
```

---

## Task 7: Add module declarations and syscall dispatch arms

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/mod.rs:6-10` (add `mod net; mod unix;`)
- Modify: `litebox_shim_macos/src/syscalls/mod.rs:27-205` (add 15 dispatch arms)

- [ ] **Step 1: Add module declarations**

In `litebox_shim_macos/src/syscalls/mod.rs`, add these module declarations after the existing ones (after line 10):

```rust
pub(crate) mod net;
pub(crate) mod unix;
```

- [ ] **Step 2: Add 15 socket dispatch arms to do_syscall**

In `litebox_shim_macos/src/syscalls/mod.rs`, add these arms in the `match request { ... }` block. Add them before the `MacosSyscallRequest::Unknown` arm (currently at line 143):

```rust
            MacosSyscallRequest::Socket {
                domain,
                sock_type,
                protocol,
            } => self.sys_socket(domain, sock_type, protocol),
            MacosSyscallRequest::Bind { fd, addr, addrlen } => {
                self.sys_bind(fd, addr, addrlen).map(|()| 0)
            }
            MacosSyscallRequest::Listen { fd, backlog } => {
                self.sys_listen(fd, backlog).map(|()| 0)
            }
            MacosSyscallRequest::Accept { fd, addr, addrlen } => self.sys_accept(fd, addr, addrlen),
            MacosSyscallRequest::Connect { fd, addr, addrlen } => {
                self.sys_connect(fd, addr, addrlen).map(|()| 0)
            }
            MacosSyscallRequest::Sendto {
                fd,
                buf,
                len,
                flags,
                dest_addr,
                addrlen,
            } => self.sys_sendto(fd, buf, len, flags, dest_addr, addrlen),
            MacosSyscallRequest::Recvfrom {
                fd,
                buf,
                len,
                flags,
                src_addr,
                addrlen,
            } => self.sys_recvfrom(fd, buf, len, flags, src_addr, addrlen),
            MacosSyscallRequest::Sendmsg { fd, msg, flags } => self.sys_sendmsg(fd, msg, flags),
            MacosSyscallRequest::Recvmsg { fd, msg, flags } => self.sys_recvmsg(fd, msg, flags),
            MacosSyscallRequest::Shutdown { fd, how } => self.sys_shutdown(fd, how).map(|()| 0),
            MacosSyscallRequest::Socketpair {
                domain,
                sock_type,
                protocol,
                sv,
            } => self.sys_socketpair(domain, sock_type, protocol, sv).map(|()| 0),
            MacosSyscallRequest::Setsockopt {
                fd,
                level,
                optname,
                optval,
                optlen,
            } => self.sys_setsockopt(fd, level, optname, optval, optlen).map(|()| 0),
            MacosSyscallRequest::Getsockopt {
                fd,
                level,
                optname,
                optval,
                optlen,
            } => self.sys_getsockopt(fd, level, optname, optval, optlen).map(|()| 0),
            MacosSyscallRequest::Getsockname { fd, addr, addrlen } => {
                self.sys_getsockname(fd, addr, addrlen).map(|()| 0)
            }
            MacosSyscallRequest::Getpeername { fd, addr, addrlen } => {
                self.sys_getpeername(fd, addr, addrlen).map(|()| 0)
            }
```

- [ ] **Step 3: Note on compilation**

This task will NOT compile until the `sys_*` methods are defined in `net.rs` and `unix.rs`. This is expected — later tasks will add the handler implementations. Verify by running `cargo check -p litebox_shim_macos` after completing Tasks 8-10 (which add the handler stubs).

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/syscalls/mod.rs
git commit -m "feat(macos): add socket module declarations and syscall dispatch arms"
```

---

## Task 8: Implement AF_INET socket creation (sys_socket)

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/net.rs` (add `sys_socket` and `do_socket_inet`)

- [ ] **Step 1: Add sys_socket and do_socket_inet to net.rs**

Append to `litebox_shim_macos/src/syscalls/net.rs`:

```rust
// ---------------------------------------------------------------------------
// AF_INET socket syscall handlers
// ---------------------------------------------------------------------------

type SocketFd = litebox::net::SocketFd<Platform>;

impl<FS: ShimFS> Task<FS> {
    /// Handle `socket(domain, type, protocol)`.
    pub(crate) fn sys_socket(
        &self,
        domain: u32,
        sock_type: u32,
        _protocol: u32,
    ) -> Result<usize, Errno> {
        let ty = SockType::try_from_raw(sock_type)?;
        match domain {
            AF_UNIX => self.do_socket_unix(ty),
            AF_INET => self.do_socket_inet(ty),
            _ => Err(Errno::EAFNOSUPPORT),
        }
    }

    /// Create an AF_INET socket via the Network subsystem.
    fn do_socket_inet(&self, sock_type: SockType) -> Result<usize, Errno> {
        let protocol = match sock_type {
            SockType::Stream => Protocol::Tcp,
            SockType::Datagram => Protocol::Udp,
        };

        let socket_fd = self
            .global
            .net
            .lock()
            .socket(protocol)
            .map_err(socket_error_to_errno)?;

        // Initialize the NetworkProxy for this socket.
        self.initialize_inet_socket(&socket_fd, sock_type);

        // Store in raw descriptor table and return the integer fd.
        let raw_fd = self
            .global
            .raw_descriptors
            .write()
            .fd_into_raw_integer(socket_fd);
        Ok(raw_fd)
    }

    /// Set up NetworkProxy and metadata for a newly created inet socket.
    fn initialize_inet_socket(
        &self,
        fd: &SocketFd,
        sock_type: SockType,
    ) {
        let proxy = match sock_type {
            SockType::Stream => {
                Arc::new(NetworkProxyEnum::Stream(StreamSocketChannel::new()))
            }
            SockType::Datagram => {
                Arc::new(NetworkProxyEnum::Datagram(DatagramSocketChannel::new()))
            }
        };

        self.global.net.lock().set_socket_proxy(fd, proxy);
    }

    /// Placeholder for AF_UNIX socket creation (implemented in unix.rs, Task 13).
    fn do_socket_unix(&self, _sock_type: SockType) -> Result<usize, Errno> {
        // Will be replaced with actual implementation in Task 13.
        Err(Errno::EAFNOSUPPORT)
    }
}
```

Note: The `do_socket_unix` is a temporary stub. It will be replaced with the real implementation in Task 13 when `unix.rs` is created. The `NetworkProxyEnum` is `litebox::net::socket_channel::NetworkProxy` — adjust the import alias as needed to avoid confusion with local names.

- [ ] **Step 2: Add SocketFd type import if needed**

Make sure the import at the top of `net.rs` includes:

```rust
use litebox::net::socket_channel::{
    DatagramSocketChannel, NetworkProxy as NetworkProxyEnum, SocketState, StreamSocketChannel,
};
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles (possibly with warnings about unused items). If there are import issues with `smoltcp`, check whether `litebox` re-exports the needed types or if `smoltcp` must be added as a direct dependency in `litebox_shim_macos/Cargo.toml`.

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/syscalls/net.rs
git commit -m "feat(macos): implement AF_INET socket creation (sys_socket)"
```

---

## Task 9: Implement AF_INET bind, listen, accept

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/net.rs` (add `sys_bind`, `sys_listen`, `sys_accept`)

- [ ] **Step 1: Add sys_bind**

Append to the `impl<FS: ShimFS> Task<FS>` block in `net.rs`:

```rust
    /// Handle `bind(fd, addr, addrlen)`.
    pub(crate) fn sys_bind(&self, fd: u32, addr: u64, addrlen: u32) -> Result<(), Errno> {
        let sockaddr = read_sockaddr_from_user(addr, addrlen)?;
        match sockaddr {
            SocketAddress::Inet(endpoint) => {
                let rds = self.global.raw_descriptors.read();
                let typed_fd = rds
                    .fd_from_raw_integer::<Network<Platform>>(fd as usize)
                    .map_err(|_| Errno::ENOTSOCK)?;
                self.global
                    .net
                    .lock()
                    .bind(&typed_fd, &core::net::SocketAddr::V4(endpoint))
                    .map_err(bind_error_to_errno)
            }
            SocketAddress::Unix(_unix_addr) => {
                // Delegate to unix.rs (Task 14).
                self.do_bind_unix(fd, _unix_addr)
            }
        }
    }

    /// Placeholder for AF_UNIX bind (implemented in unix.rs).
    fn do_bind_unix(&self, _fd: u32, _addr: UnixSocketAddr) -> Result<(), Errno> {
        Err(Errno::EAFNOSUPPORT) // Stub — replaced in Task 14
    }
```

- [ ] **Step 2: Add sys_listen**

```rust
    /// Handle `listen(fd, backlog)`.
    pub(crate) fn sys_listen(&self, fd: u32, backlog: u32) -> Result<(), Errno> {
        // Try inet first.
        {
            let rds = self.global.raw_descriptors.read();
            if let Ok(typed_fd) = rds.fd_from_raw_integer::<Network<Platform>>(fd as usize) {
                return self
                    .global
                    .net
                    .lock()
                    .listen(&typed_fd, backlog.min(u16::MAX as u32) as u16)
                    .map_err(listen_error_to_errno);
            }
        }
        // Try unix.
        self.do_listen_unix(fd, backlog)
    }

    /// Placeholder for AF_UNIX listen (implemented in unix.rs).
    fn do_listen_unix(&self, _fd: u32, _backlog: u32) -> Result<(), Errno> {
        Err(Errno::ENOTSOCK) // Stub — replaced in Task 14
    }
```

- [ ] **Step 3: Add sys_accept**

```rust
    /// Handle `accept(fd, addr, addrlen)`.
    pub(crate) fn sys_accept(&self, fd: u32, addr: u64, addrlen: u64) -> Result<usize, Errno> {
        // Try inet first.
        {
            let rds = self.global.raw_descriptors.read();
            if let Ok(typed_fd) = rds.fd_from_raw_integer::<Network<Platform>>(fd as usize) {
                drop(rds); // Release read lock before locking net.

                // Prepare a peer address output if the caller wants it.
                let want_peer = addr != 0;
                let mut peer_ep = core::net::SocketAddr::V4(
                    core::net::SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0),
                );
                let peer_arg = if want_peer { Some(&mut peer_ep) } else { None };

                // Accept (non-blocking for now).
                let accepted_fd = match self.global.net.lock().accept(&typed_fd, peer_arg) {
                    Ok(new_fd) => new_fd,
                    Err(AcceptError::NoConnectionsReady) => {
                        // Block until a connection is ready.
                        // TODO: integrate with WaitContext for blocking accept.
                        return Err(Errno::EAGAIN);
                    }
                    Err(e) => return Err(accept_error_to_errno(e)),
                };

                // Initialize the accepted socket's proxy.
                self.initialize_inet_socket(&accepted_fd, SockType::Stream);

                // Write peer address to user memory if requested.
                if want_peer {
                    write_sockaddr_inet_to_user(&peer_ep, addr, addrlen)?;
                }

                // Store in raw descriptor table.
                let raw_fd = self
                    .global
                    .raw_descriptors
                    .write()
                    .fd_into_raw_integer(accepted_fd);
                return Ok(raw_fd);
            }
        }
        // Try unix.
        self.do_accept_unix(fd, addr, addrlen)
    }

    /// Placeholder for AF_UNIX accept (implemented in unix.rs).
    fn do_accept_unix(&self, _fd: u32, _addr: u64, _addrlen: u64) -> Result<usize, Errno> {
        Err(Errno::ENOTSOCK) // Stub — replaced in Task 14
    }
```

- [ ] **Step 4: Add required import**

Make sure `AcceptError` is imported at the top of `net.rs`:

```rust
use litebox::net::errors::AcceptError;
```

(Already in the initial imports from Task 4.)

- [ ] **Step 5: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles with warnings about stub methods.

- [ ] **Step 6: Commit**

```bash
git add litebox_shim_macos/src/syscalls/net.rs
git commit -m "feat(macos): implement AF_INET bind, listen, accept"
```

---

## Task 10: Implement AF_INET connect, sendto, recvfrom

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/net.rs` (add `sys_connect`, `sys_sendto`, `sys_recvfrom`)

- [ ] **Step 1: Add sys_connect**

Append to the `impl<FS: ShimFS> Task<FS>` block in `net.rs`:

```rust
    /// Handle `connect(fd, addr, addrlen)`.
    pub(crate) fn sys_connect(&self, fd: u32, addr: u64, addrlen: u32) -> Result<(), Errno> {
        let sockaddr = read_sockaddr_from_user(addr, addrlen)?;
        match sockaddr {
            SocketAddress::Inet(endpoint) => {
                let rds = self.global.raw_descriptors.read();
                let typed_fd = rds
                    .fd_from_raw_integer::<Network<Platform>>(fd as usize)
                    .map_err(|_| Errno::ENOTSOCK)?;
                drop(rds);
                self.global
                    .net
                    .lock()
                    .connect(&typed_fd, &core::net::SocketAddr::V4(endpoint), false)
                    .map_err(connect_error_to_errno)
            }
            SocketAddress::Unix(_unix_addr) => {
                self.do_connect_unix(fd, _unix_addr)
            }
        }
    }

    /// Placeholder for AF_UNIX connect.
    fn do_connect_unix(&self, _fd: u32, _addr: UnixSocketAddr) -> Result<(), Errno> {
        Err(Errno::EAFNOSUPPORT) // Stub — replaced in Task 14
    }
```

- [ ] **Step 2: Add sys_sendto**

```rust
    /// Handle `sendto(fd, buf, len, flags, dest_addr, addrlen)`.
    pub(crate) fn sys_sendto(
        &self,
        fd: u32,
        buf: u64,
        len: u64,
        flags: u32,
        dest_addr: u64,
        addrlen: u32,
    ) -> Result<usize, Errno> {
        // Read data from guest memory.
        let user_buf: ConstPtr<u8> = ConstPtr::from_usize(buf as usize);
        let data = user_buf
            .to_owned_slice(len as usize)
            .ok_or(Errno::EFAULT)?;

        // Parse destination address if provided.
        let dest = if dest_addr != 0 && addrlen > 0 {
            match read_sockaddr_from_user(dest_addr, addrlen)? {
                SocketAddress::Inet(ep) => Some(core::net::SocketAddr::V4(ep)),
                SocketAddress::Unix(_addr) => {
                    return self.do_sendto_unix(fd, &data, Some(_addr));
                }
            }
        } else {
            None
        };

        // Check if this is a unix socket (connected stream/datagram with no dest_addr).
        {
            let unix_sockets = self.global.unix_sockets.read();
            if unix_sockets.contains_key(&(fd as usize)) {
                drop(unix_sockets);
                return self.do_sendto_unix(fd, &data, None);
            }
        }

        // Try inet.
        let rds = self.global.raw_descriptors.read();
        let typed_fd = rds
            .fd_from_raw_integer::<Network<Platform>>(fd as usize)
            .map_err(|_| Errno::ENOTSOCK)?;
        drop(rds);

        let send_flags = SendFlags::empty(); // macOS send flags are rarely used in practice.
        self.global
            .net
            .lock()
            .send(&typed_fd, &data, send_flags, dest)
            .map_err(send_error_to_errno)
    }

    /// Placeholder for AF_UNIX sendto (with optional destination for unconnected sends).
    fn do_sendto_unix(
        &self,
        _fd: u32,
        _data: &[u8],
        _addr: Option<UnixSocketAddr>,
    ) -> Result<usize, Errno> {
        Err(Errno::EAFNOSUPPORT) // Stub — replaced in Task 14
    }
```

- [ ] **Step 3: Add sys_recvfrom**

```rust
    /// Handle `recvfrom(fd, buf, len, flags, src_addr, addrlen)`.
    pub(crate) fn sys_recvfrom(
        &self,
        fd: u32,
        buf: u64,
        len: u64,
        flags: u32,
        src_addr: u64,
        addrlen: u64,
    ) -> Result<usize, Errno> {
        let buf_len = len as usize;
        let mut kernel_buf = vec![0u8; buf_len];

        // Check if this is a unix socket first.
        {
            let unix_sockets = self.global.unix_sockets.read();
            if unix_sockets.contains_key(&(fd as usize)) {
                drop(unix_sockets);
                return self.do_recvfrom_unix(fd, buf, buf_len, src_addr, addrlen);
            }
        }

        // Try inet.
        let rds = self.global.raw_descriptors.read();
        let typed_fd = rds
            .fd_from_raw_integer::<Network<Platform>>(fd as usize)
            .map_err(|_| Errno::ENOTSOCK)?;
        drop(rds);

        let recv_flags = ReceiveFlags::empty();
        let mut source = if src_addr != 0 {
            Some(None::<core::net::SocketAddr>)
        } else {
            None
        };

        let bytes_read = self
            .global
            .net
            .lock()
            .receive(
                &typed_fd,
                &mut kernel_buf,
                recv_flags,
                source.as_mut(),
            )
            .map_err(receive_error_to_errno)?;

        // Copy data to guest.
        let user_buf: MutPtr<u8> = MutPtr::from_usize(buf as usize);
        user_buf
            .copy_from_slice(0, &kernel_buf[..bytes_read])
            .ok_or(Errno::EFAULT)?;

        // Write source address if requested.
        if let Some(Some(ref ep)) = source {
            write_sockaddr_inet_to_user(ep, src_addr, addrlen)?;
        }

        Ok(bytes_read)
    }

    /// Placeholder for AF_UNIX recvfrom.
    fn do_recvfrom_unix(
        &self,
        _fd: u32,
        _buf: u64,
        _len: usize,
        _src_addr: u64,
        _addrlen: u64,
    ) -> Result<usize, Errno> {
        Err(Errno::EAFNOSUPPORT) // Stub
    }
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`

- [ ] **Step 5: Commit**

```bash
git add litebox_shim_macos/src/syscalls/net.rs
git commit -m "feat(macos): implement AF_INET connect, sendto, recvfrom"
```

---

## Task 11: Implement AF_INET setsockopt, getsockopt

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/net.rs` (add `sys_setsockopt`, `sys_getsockopt`)

- [ ] **Step 1: Add sys_setsockopt**

Append to the `impl<FS: ShimFS> Task<FS>` block in `net.rs`:

```rust
    /// Handle `setsockopt(fd, level, optname, optval, optlen)`.
    pub(crate) fn sys_setsockopt(
        &self,
        fd: u32,
        level: u32,
        optname: u32,
        optval: u64,
        optlen: u32,
    ) -> Result<(), Errno> {
        let opt = SocketOptionName::try_from_raw(level, optname)
            .ok_or(Errno::ENOPROTOOPT)?;

        // Read the option value from guest memory.
        let val_ptr: ConstPtr<u8> = ConstPtr::from_usize(optval as usize);

        // Helper to read a u32 option value.
        let read_u32 = || -> Result<u32, Errno> {
            if optlen < 4 {
                return Err(Errno::EINVAL);
            }
            let bytes = val_ptr.to_owned_slice(4).ok_or(Errno::EFAULT)?;
            Ok(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        };

        // Helper to read a timeval.
        let read_timeval = || -> Result<Option<Duration>, Errno> {
            if optlen < core::mem::size_of::<CTimeval>() as u32 {
                return Err(Errno::EINVAL);
            }
            let bytes = val_ptr
                .to_owned_slice(core::mem::size_of::<CTimeval>())
                .ok_or(Errno::EFAULT)?;
            let tv: CTimeval = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };
            if tv.tv_sec == 0 && tv.tv_usec == 0 {
                Ok(None) // Disable timeout
            } else {
                Ok(Some(Duration::new(
                    tv.tv_sec as u64,
                    tv.tv_usec as u32 * 1000,
                )))
            }
        };

        // Helper to read a linger struct.
        let read_linger = || -> Result<Option<Duration>, Errno> {
            if optlen < core::mem::size_of::<CLinger>() as u32 {
                return Err(Errno::EINVAL);
            }
            let bytes = val_ptr
                .to_owned_slice(core::mem::size_of::<CLinger>())
                .ok_or(Errno::EFAULT)?;
            let lg: CLinger = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };
            if lg.l_onoff == 0 {
                Ok(None)
            } else {
                Ok(Some(Duration::from_secs(lg.l_linger as u64)))
            }
        };

        // Check if this is a unix socket first.
        {
            let unix_sockets = self.global.unix_sockets.read();
            if let Some(unix_sock) = unix_sockets.get(&(fd as usize)) {
                let unix_sock = unix_sock.clone();
                drop(unix_sockets);
                return self.do_setsockopt_unix(&unix_sock, opt, &read_u32, &read_timeval, &read_linger);
            }
        }

        // Inet socket path.
        let rds = self.global.raw_descriptors.read();
        let typed_fd = rds
            .fd_from_raw_integer::<Network<Platform>>(fd as usize)
            .map_err(|_| Errno::ENOTSOCK)?;
        drop(rds);

        match opt {
            SocketOptionName::ReuseAddr => {
                let _val = read_u32()?;
                // smoltcp doesn't enforce address reuse — just accept silently.
                Ok(())
            }
            SocketOptionName::KeepAlive => {
                let val = read_u32()?;
                let keepalive = if val != 0 {
                    Some(Duration::from_secs(7200)) // Default keepalive interval
                } else {
                    None
                };
                self.global
                    .net
                    .lock()
                    .set_tcp_option(&typed_fd, TcpOptionData::KEEPALIVE(keepalive))
                    .map_err(set_tcp_option_error_to_errno)
            }
            SocketOptionName::Broadcast => {
                let _val = read_u32()?;
                // smoltcp doesn't have a broadcast flag — accept silently.
                Ok(())
            }
            SocketOptionName::SndBuf | SocketOptionName::RcvBuf => {
                // Buffer sizes are fixed in smoltcp — silently accept.
                let _val = read_u32()?;
                Ok(())
            }
            SocketOptionName::Linger | SocketOptionName::LingerSec => {
                let _linger = read_linger()?;
                // Store for use during close. For now, accept silently.
                // TODO: store linger state in socket metadata.
                Ok(())
            }
            SocketOptionName::RcvTimeo => {
                let _timeout = read_timeval()?;
                // TODO: store and use during receive.
                Ok(())
            }
            SocketOptionName::SndTimeo => {
                let _timeout = read_timeval()?;
                // TODO: store and use during send.
                Ok(())
            }
            SocketOptionName::TcpNoDelay => {
                let val = read_u32()?;
                self.global
                    .net
                    .lock()
                    .set_tcp_option(&typed_fd, TcpOptionData::NODELAY(val != 0))
                    .map_err(set_tcp_option_error_to_errno)
            }
            SocketOptionName::TcpNoPush => {
                // Inverse of NODELAY (TCP_CORK equivalent).
                let val = read_u32()?;
                self.global
                    .net
                    .lock()
                    .set_tcp_option(&typed_fd, TcpOptionData::NODELAY(val == 0))
                    .map_err(set_tcp_option_error_to_errno)
            }
            SocketOptionName::TcpKeepAlive => {
                let val = read_u32()?;
                let keepalive = if val > 0 {
                    Some(Duration::from_secs(val as u64))
                } else {
                    None
                };
                self.global
                    .net
                    .lock()
                    .set_tcp_option(&typed_fd, TcpOptionData::KEEPALIVE(keepalive))
                    .map_err(set_tcp_option_error_to_errno)
            }
            SocketOptionName::TcpKeepIntvl => {
                // smoltcp doesn't distinguish keepalive interval vs idle — accept silently.
                let _val = read_u32()?;
                Ok(())
            }
            SocketOptionName::TcpKeepCnt => {
                // Not supported by smoltcp — accept silently.
                let _val = read_u32()?;
                Ok(())
            }
            SocketOptionName::IpTos => {
                // Not supported — accept silently.
                let _val = read_u32()?;
                Ok(())
            }
            SocketOptionName::Type | SocketOptionName::Error => {
                // Read-only options.
                Err(Errno::ENOPROTOOPT)
            }
        }
    }

    /// Placeholder for AF_UNIX setsockopt.
    fn do_setsockopt_unix<F1, F2, F3>(
        &self,
        _sock: &crate::syscalls::unix::UnixSocket<FS>,
        _opt: SocketOptionName,
        _read_u32: &F1,
        _read_timeval: &F2,
        _read_linger: &F3,
    ) -> Result<(), Errno> {
        Ok(()) // Stub — most options are silently accepted for unix sockets
    }
```

- [ ] **Step 2: Add sys_getsockopt**

```rust
    /// Handle `getsockopt(fd, level, optname, optval, optlen)`.
    pub(crate) fn sys_getsockopt(
        &self,
        fd: u32,
        level: u32,
        optname: u32,
        optval: u64,
        optlen: u64,
    ) -> Result<(), Errno> {
        let opt = SocketOptionName::try_from_raw(level, optname)
            .ok_or(Errno::ENOPROTOOPT)?;

        let out_ptr: MutPtr<u8> = MutPtr::from_usize(optval as usize);
        let len_ptr: MutPtr<u32> = MutPtr::from_usize(optlen as usize);

        // Helper to write a u32 result.
        let write_u32 = |val: u32| -> Result<(), Errno> {
            let bytes = val.to_ne_bytes();
            out_ptr.copy_from_slice(0, &bytes).ok_or(Errno::EFAULT)?;
            len_ptr.copy_from_slice(0, &4u32.to_ne_bytes()).ok_or(Errno::EFAULT)?;
            Ok(())
        };

        // Try inet.
        let rds = self.global.raw_descriptors.read();
        if let Ok(typed_fd) = rds.fd_from_raw_integer::<Network<Platform>>(fd as usize) {
            drop(rds);
            return match opt {
                SocketOptionName::ReuseAddr => write_u32(0), // Always return 0
                SocketOptionName::Type => {
                    // Return SOCK_STREAM or SOCK_DGRAM.
                    // TODO: store sock_type in metadata. For now, return SOCK_STREAM.
                    write_u32(SOCK_STREAM)
                }
                SocketOptionName::Broadcast => write_u32(0),
                SocketOptionName::SndBuf => write_u32(SOCKET_BUFFER_SIZE),
                SocketOptionName::RcvBuf => write_u32(SOCKET_BUFFER_SIZE),
                SocketOptionName::KeepAlive => write_u32(0),
                SocketOptionName::Error => write_u32(0), // No pending error
                SocketOptionName::Linger | SocketOptionName::LingerSec => {
                    let lg = CLinger {
                        l_onoff: 0,
                        l_linger: 0,
                    };
                    let bytes: &[u8] = unsafe {
                        core::slice::from_raw_parts(
                            (&lg as *const CLinger).cast::<u8>(),
                            core::mem::size_of::<CLinger>(),
                        )
                    };
                    out_ptr.copy_from_slice(0, bytes).ok_or(Errno::EFAULT)?;
                    let size = core::mem::size_of::<CLinger>() as u32;
                    len_ptr.copy_from_slice(0, &size.to_ne_bytes()).ok_or(Errno::EFAULT)?;
                    Ok(())
                }
                SocketOptionName::RcvTimeo | SocketOptionName::SndTimeo => {
                    let tv = CTimeval {
                        tv_sec: 0,
                        tv_usec: 0,
                    };
                    let bytes: &[u8] = unsafe {
                        core::slice::from_raw_parts(
                            (&tv as *const CTimeval).cast::<u8>(),
                            core::mem::size_of::<CTimeval>(),
                        )
                    };
                    out_ptr.copy_from_slice(0, bytes).ok_or(Errno::EFAULT)?;
                    let size = core::mem::size_of::<CTimeval>() as u32;
                    len_ptr.copy_from_slice(0, &size.to_ne_bytes()).ok_or(Errno::EFAULT)?;
                    Ok(())
                }
                SocketOptionName::TcpNoDelay => {
                    match self.global.net.lock().get_tcp_option(&typed_fd, TcpOptionName::NODELAY) {
                        Ok(TcpOptionData::NODELAY(v)) => write_u32(v as u32),
                        _ => write_u32(0),
                    }
                }
                SocketOptionName::TcpNoPush => write_u32(0),
                SocketOptionName::TcpKeepAlive => write_u32(0),
                SocketOptionName::TcpKeepIntvl => write_u32(0),
                SocketOptionName::TcpKeepCnt => write_u32(0),
                SocketOptionName::IpTos => write_u32(0),
            };
        }
        drop(rds);

        // Try unix — most options return defaults.
        {
            let unix_sockets = self.global.unix_sockets.read();
            if unix_sockets.contains_key(&(fd as usize)) {
                return match opt {
                    SocketOptionName::Type => write_u32(SOCK_STREAM), // TODO: actual type
                    SocketOptionName::Error => write_u32(0),
                    SocketOptionName::SndBuf => write_u32(65536),
                    SocketOptionName::RcvBuf => write_u32(65536),
                    _ => write_u32(0),
                };
            }
        }

        Err(Errno::ENOTSOCK)
    }
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/syscalls/net.rs
git commit -m "feat(macos): implement AF_INET setsockopt/getsockopt"
```

---

## Task 12: Implement getsockname, getpeername, shutdown, sendmsg, recvmsg

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/net.rs`

- [ ] **Step 1: Add sys_getsockname**

Append to the `impl<FS: ShimFS> Task<FS>` block:

```rust
    /// Handle `getsockname(fd, addr, addrlen)`.
    pub(crate) fn sys_getsockname(&self, fd: u32, addr: u64, addrlen: u64) -> Result<(), Errno> {
        // Try inet.
        let rds = self.global.raw_descriptors.read();
        if let Ok(typed_fd) = rds.fd_from_raw_integer::<Network<Platform>>(fd as usize) {
            drop(rds);
            let local = self
                .global
                .net
                .lock()
                .get_local_addr(&typed_fd)
                .map_err(local_addr_error_to_errno)?;
            return write_sockaddr_inet_to_user(&local, addr, addrlen);
        }
        drop(rds);

        // Try unix.
        {
            let unix_sockets = self.global.unix_sockets.read();
            if let Some(unix_sock) = unix_sockets.get(&(fd as usize)) {
                let bound_addr = unix_sock.bound_addr();
                drop(unix_sockets);
                return write_sockaddr_unix_to_user(&bound_addr, addr, addrlen);
            }
        }

        Err(Errno::ENOTSOCK)
    }
```

- [ ] **Step 2: Add sys_getpeername**

```rust
    /// Handle `getpeername(fd, addr, addrlen)`.
    pub(crate) fn sys_getpeername(&self, fd: u32, addr: u64, addrlen: u64) -> Result<(), Errno> {
        // Try inet.
        let rds = self.global.raw_descriptors.read();
        if let Ok(typed_fd) = rds.fd_from_raw_integer::<Network<Platform>>(fd as usize) {
            drop(rds);
            let remote = self
                .global
                .net
                .lock()
                .get_remote_addr(&typed_fd)
                .map_err(remote_addr_error_to_errno)?;
            return write_sockaddr_inet_to_user(&remote, addr, addrlen);
        }
        drop(rds);

        // Try unix.
        {
            let unix_sockets = self.global.unix_sockets.read();
            if let Some(unix_sock) = unix_sockets.get(&(fd as usize)) {
                let peer_addr = unix_sock.peer_addr();
                drop(unix_sockets);
                return write_sockaddr_unix_to_user(&peer_addr, addr, addrlen);
            }
        }

        Err(Errno::ENOTSOCK)
    }
```

- [ ] **Step 3: Add sys_shutdown**

```rust
    /// Handle `shutdown(fd, how)`.
    pub(crate) fn sys_shutdown(&self, fd: u32, how: u32) -> Result<(), Errno> {
        // Validate `how` parameter.
        if how > SHUT_RDWR {
            return Err(Errno::EINVAL);
        }

        // Try unix first — unix sockets support proper half-close via Channel shutdown.
        {
            let unix_sockets = self.global.unix_sockets.read();
            if let Some(unix_sock) = unix_sockets.get(&(fd as usize)) {
                let unix_sock = unix_sock.clone();
                drop(unix_sockets);
                return unix_sock.shutdown(how);
            }
        }

        // Try inet.
        // NOTE: The Network API doesn't expose a half-close method directly.
        // For SHUT_RDWR we close the socket. For SHUT_RD/SHUT_WR, we also
        // close (lossy but matches Linux shim behavior which also doesn't
        // implement inet shutdown). A proper fix would require adding
        // shutdown() to the Network API or exposing the NetworkProxy.
        let rds = self.global.raw_descriptors.read();
        if let Ok(typed_fd) = rds.fd_from_raw_integer::<Network<Platform>>(fd as usize) {
            drop(rds);
            return self
                .global
                .net
                .lock()
                .close(&typed_fd, CloseBehavior::Immediate)
                .map_err(close_error_to_errno);
        }
        drop(rds);

        Err(Errno::ENOTSOCK)
    }
```

- [ ] **Step 4: Add sys_sendmsg**

```rust
    /// Handle `sendmsg(fd, msg, flags)`.
    ///
    /// Reads the msghdr from guest memory, gathers data from iov, and dispatches
    /// to sendto. Does not support ancillary data (SCM_RIGHTS).
    pub(crate) fn sys_sendmsg(&self, fd: u32, msg: u64, flags: u32) -> Result<usize, Errno> {
        // macOS msghdr layout (aarch64):
        //   0: msg_name (u64)
        //   8: msg_namelen (u32)
        //  12: _pad0 (u32)
        //  16: msg_iov (u64)
        //  24: msg_iovlen (i32)
        //  28: _pad1 (u32)
        //  32: msg_control (u64)
        //  40: msg_controllen (u32)
        //  44: msg_flags (i32)
        // Total: 48 bytes

        let hdr_ptr: ConstPtr<u8> = ConstPtr::from_usize(msg as usize);
        let hdr_bytes = hdr_ptr.to_owned_slice(48).ok_or(Errno::EFAULT)?;

        let msg_name = u64::from_ne_bytes(hdr_bytes[0..8].try_into().unwrap());
        let msg_namelen = u32::from_ne_bytes(hdr_bytes[8..12].try_into().unwrap());
        let msg_iov = u64::from_ne_bytes(hdr_bytes[16..24].try_into().unwrap());
        let msg_iovlen = i32::from_ne_bytes(hdr_bytes[24..28].try_into().unwrap());
        let msg_controllen = u32::from_ne_bytes(hdr_bytes[40..44].try_into().unwrap());

        // We don't support ancillary data.
        if msg_controllen != 0 {
            return Err(Errno::EOPNOTSUPP);
        }

        // Gather data from iovec array.
        let mut gathered = alloc::vec::Vec::new();
        for i in 0..msg_iovlen as usize {
            // Each iovec is { iov_base: u64, iov_len: u64 } = 16 bytes.
            let iov_ptr: ConstPtr<u8> = ConstPtr::from_usize(msg_iov as usize + i * 16);
            let iov_bytes = iov_ptr.to_owned_slice(16).ok_or(Errno::EFAULT)?;
            let iov_base = u64::from_ne_bytes(iov_bytes[0..8].try_into().unwrap());
            let iov_len = u64::from_ne_bytes(iov_bytes[8..16].try_into().unwrap());

            if iov_len > 0 {
                let data_ptr: ConstPtr<u8> = ConstPtr::from_usize(iov_base as usize);
                let data = data_ptr.to_owned_slice(iov_len as usize).ok_or(Errno::EFAULT)?;
                gathered.extend_from_slice(&data);
            }
        }

        // Dispatch to sendto with gathered data.
        self.sys_sendto(fd, 0, 0, flags, msg_name, msg_namelen)
            .map(|_| gathered.len())
            // Actually, we need to pass the gathered data, not use sys_sendto directly.
            // Let's inline the send logic here instead:
    }
```

Wait — the above approach of calling `sys_sendto` won't work because `sys_sendto` reads the buffer from guest memory. For `sendmsg`, we've already gathered the data into `gathered`. Let me rewrite:

```rust
    /// Handle `sendmsg(fd, msg, flags)`.
    pub(crate) fn sys_sendmsg(&self, fd: u32, msg: u64, _flags: u32) -> Result<usize, Errno> {
        let hdr_ptr: ConstPtr<u8> = ConstPtr::from_usize(msg as usize);
        let hdr_bytes = hdr_ptr.to_owned_slice(48).ok_or(Errno::EFAULT)?;

        let msg_name = u64::from_ne_bytes(hdr_bytes[0..8].try_into().unwrap());
        let msg_namelen = u32::from_ne_bytes(hdr_bytes[8..12].try_into().unwrap());
        let msg_iov = u64::from_ne_bytes(hdr_bytes[16..24].try_into().unwrap());
        let msg_iovlen = i32::from_ne_bytes(hdr_bytes[24..28].try_into().unwrap());
        let msg_controllen = u32::from_ne_bytes(hdr_bytes[40..44].try_into().unwrap());

        if msg_controllen != 0 {
            return Err(Errno::EOPNOTSUPP);
        }

        // Gather data from iovec array.
        let mut gathered = alloc::vec::Vec::new();
        for i in 0..msg_iovlen.max(0) as usize {
            let iov_ptr: ConstPtr<u8> = ConstPtr::from_usize(msg_iov as usize + i * 16);
            let iov_bytes = iov_ptr.to_owned_slice(16).ok_or(Errno::EFAULT)?;
            let iov_base = u64::from_ne_bytes(iov_bytes[0..8].try_into().unwrap());
            let iov_len = u64::from_ne_bytes(iov_bytes[8..16].try_into().unwrap());
            if iov_len > 0 {
                let data_ptr: ConstPtr<u8> = ConstPtr::from_usize(iov_base as usize);
                let data = data_ptr.to_owned_slice(iov_len as usize).ok_or(Errno::EFAULT)?;
                gathered.extend_from_slice(&data);
            }
        }

        // Parse destination address if provided.
        let dest = if msg_name != 0 && msg_namelen > 0 {
            Some(read_sockaddr_from_user(msg_name, msg_namelen)?)
        } else {
            None
        };

        // Dispatch based on socket type.
        // Try inet.
        let rds = self.global.raw_descriptors.read();
        if let Ok(typed_fd) = rds.fd_from_raw_integer::<Network<Platform>>(fd as usize) {
            drop(rds);
            let inet_dest = match dest {
                Some(SocketAddress::Inet(ep)) => Some(core::net::SocketAddr::V4(ep)),
                None => None,
                _ => return Err(Errno::EAFNOSUPPORT),
            };
            return self
                .global
                .net
                .lock()
                .send(&typed_fd, &gathered, SendFlags::empty(), inet_dest)
                .map_err(send_error_to_errno);
        }
        drop(rds);

        // Try unix.
        self.do_sendmsg_unix(fd, &gathered, dest)
    }

    /// Placeholder for AF_UNIX sendmsg.
    fn do_sendmsg_unix(
        &self,
        _fd: u32,
        _data: &[u8],
        _dest: Option<SocketAddress>,
    ) -> Result<usize, Errno> {
        Err(Errno::ENOTSOCK) // Stub
    }
```

- [ ] **Step 5: Add sys_recvmsg**

```rust
    /// Handle `recvmsg(fd, msg, flags)`.
    pub(crate) fn sys_recvmsg(&self, fd: u32, msg: u64, _flags: u32) -> Result<usize, Errno> {
        let hdr_ptr: ConstPtr<u8> = ConstPtr::from_usize(msg as usize);
        let hdr_bytes = hdr_ptr.to_owned_slice(48).ok_or(Errno::EFAULT)?;

        let msg_name = u64::from_ne_bytes(hdr_bytes[0..8].try_into().unwrap());
        let _msg_namelen = u32::from_ne_bytes(hdr_bytes[8..12].try_into().unwrap());
        let msg_iov = u64::from_ne_bytes(hdr_bytes[16..24].try_into().unwrap());
        let msg_iovlen = i32::from_ne_bytes(hdr_bytes[24..28].try_into().unwrap());

        // Calculate total buffer size from iovecs.
        let mut total_len = 0usize;
        let mut iovecs = alloc::vec::Vec::new();
        for i in 0..msg_iovlen.max(0) as usize {
            let iov_ptr: ConstPtr<u8> = ConstPtr::from_usize(msg_iov as usize + i * 16);
            let iov_bytes = iov_ptr.to_owned_slice(16).ok_or(Errno::EFAULT)?;
            let iov_base = u64::from_ne_bytes(iov_bytes[0..8].try_into().unwrap());
            let iov_len = u64::from_ne_bytes(iov_bytes[8..16].try_into().unwrap());
            iovecs.push((iov_base, iov_len as usize));
            total_len += iov_len as usize;
        }

        // Receive into a temporary buffer.
        let mut kernel_buf = vec![0u8; total_len];

        // Try inet.
        let rds = self.global.raw_descriptors.read();
        if let Ok(typed_fd) = rds.fd_from_raw_integer::<Network<Platform>>(fd as usize) {
            drop(rds);
            let mut source = if msg_name != 0 {
                Some(None::<core::net::SocketAddr>)
            } else {
                None
            };

            let bytes_read = self
                .global
                .net
                .lock()
                .receive(&typed_fd, &mut kernel_buf, ReceiveFlags::empty(), source.as_mut())
                .map_err(receive_error_to_errno)?;

            // Scatter into iovecs.
            let mut offset = 0usize;
            for (iov_base, iov_len) in &iovecs {
                if offset >= bytes_read {
                    break;
                }
                let to_copy = (*iov_len).min(bytes_read - offset);
                let dst: MutPtr<u8> = MutPtr::from_usize(*iov_base as usize);
                dst.copy_from_slice(0, &kernel_buf[offset..offset + to_copy])
                    .ok_or(Errno::EFAULT)?;
                offset += to_copy;
            }

            // Write source address if requested.
            if let Some(Some(ref ep)) = source {
                let hdr_mut: MutPtr<u8> = MutPtr::from_usize(msg as usize);
                // Write updated msg_namelen at offset 8.
                let sa_size = core::mem::size_of::<CSockInetAddr>() as u32;
                hdr_mut
                    .copy_from_slice(8, &sa_size.to_ne_bytes())
                    .ok_or(Errno::EFAULT)?;
                write_sockaddr_inet_to_user(ep, msg_name, msg as u64 + 8)?;
            }

            // Write msg_flags = 0 at offset 44.
            let hdr_mut: MutPtr<u8> = MutPtr::from_usize(msg as usize);
            hdr_mut
                .copy_from_slice(40, &0u32.to_ne_bytes()) // msg_controllen = 0
                .ok_or(Errno::EFAULT)?;
            hdr_mut
                .copy_from_slice(44, &0i32.to_ne_bytes()) // msg_flags = 0
                .ok_or(Errno::EFAULT)?;

            return Ok(bytes_read);
        }
        drop(rds);

        // Try unix.
        self.do_recvmsg_unix(fd, &mut kernel_buf, &iovecs, msg)
    }

    /// Placeholder for AF_UNIX recvmsg.
    fn do_recvmsg_unix(
        &self,
        _fd: u32,
        _buf: &mut [u8],
        _iovecs: &[(u64, usize)],
        _msg: u64,
    ) -> Result<usize, Errno> {
        Err(Errno::ENOTSOCK) // Stub
    }
```

- [ ] **Step 6: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`

- [ ] **Step 7: Commit**

```bash
git add litebox_shim_macos/src/syscalls/net.rs
git commit -m "feat(macos): implement getsockname, getpeername, shutdown, sendmsg, recvmsg"
```

---

## Task 13: Create unix.rs with Channel, UnixSocket, and core AF_UNIX types

**Files:**
- Create: `litebox_shim_macos/src/syscalls/unix.rs`

This is the largest single task. It creates the AF_UNIX infrastructure: `Channel` (VecDeque-backed ring buffer), `UnixSocket`, stream/datagram inner types, `Backlog`, and `UnixAddrEntry`.

- [ ] **Step 1: Create `litebox_shim_macos/src/syscalls/unix.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AF_UNIX socket implementation.
//!
//! Uses in-memory ring buffers (`Channel`) for data transfer between connected
//! Unix sockets. Not routed through the smoltcp network stack.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use litebox_common_macos::errno::Errno;

use crate::syscalls::net::{SockType, SocketOptions, UnixSocketAddr, SHUT_RD, SHUT_WR, SHUT_RDWR};
use crate::{Platform, ShimFS, Task};

// ---------------------------------------------------------------------------
// Channel — VecDeque-backed ring buffer for Unix socket data transfer
// ---------------------------------------------------------------------------

/// Default channel buffer capacity (bytes).
const UNIX_BUF_SIZE: usize = 65536;

/// A unidirectional byte channel backed by a `VecDeque`.
pub(crate) struct Channel {
    buf: litebox::sync::Mutex<Platform, ChannelInner>,
}

struct ChannelInner {
    data: VecDeque<u8>,
    capacity: usize,
    /// Writer has been shut down (no more data will be written).
    write_closed: bool,
    /// Reader has been shut down.
    read_closed: bool,
}

impl Channel {
    /// Create a new channel with the given capacity.
    pub(crate) fn new(capacity: usize) -> Self {
        Channel {
            buf: litebox::sync::Mutex::new(ChannelInner {
                data: VecDeque::with_capacity(capacity),
                capacity,
                write_closed: false,
                read_closed: false,
            }),
        }
    }

    /// Try to write data into the channel. Returns bytes written, or error.
    pub(crate) fn try_write(&self, data: &[u8]) -> Result<usize, Errno> {
        let mut inner = self.buf.lock();
        if inner.write_closed {
            return Err(Errno::EPIPE);
        }
        if inner.read_closed {
            return Err(Errno::EPIPE);
        }
        let available = inner.capacity - inner.data.len();
        if available == 0 {
            return Err(Errno::EAGAIN);
        }
        let to_write = data.len().min(available);
        inner.data.extend(&data[..to_write]);
        Ok(to_write)
    }

    /// Try to read data from the channel. Returns bytes read, or error.
    pub(crate) fn try_read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut inner = self.buf.lock();
        if inner.data.is_empty() {
            if inner.write_closed {
                return Ok(0); // EOF
            }
            return Err(Errno::EAGAIN);
        }
        let to_read = buf.len().min(inner.data.len());
        for (i, byte) in inner.data.drain(..to_read).enumerate() {
            buf[i] = byte;
        }
        Ok(to_read)
    }

    /// Shut down the write end.
    pub(crate) fn shutdown_write(&self) {
        self.buf.lock().write_closed = true;
    }

    /// Shut down the read end.
    pub(crate) fn shutdown_read(&self) {
        self.buf.lock().read_closed = true;
    }

    /// Check if the channel has data available for reading.
    pub(crate) fn has_data(&self) -> bool {
        !self.buf.lock().data.is_empty()
    }

    /// Check if the write end is closed.
    pub(crate) fn is_write_closed(&self) -> bool {
        self.buf.lock().write_closed
    }
}

// ---------------------------------------------------------------------------
// Datagram message type for SOCK_DGRAM Unix sockets
// ---------------------------------------------------------------------------

/// A single datagram message.
pub(crate) struct DatagramMessage {
    pub(crate) data: Vec<u8>,
    pub(crate) from: UnixSocketAddr,
}

/// A datagram channel (queue of messages).
pub(crate) struct DatagramChannel {
    queue: litebox::sync::Mutex<Platform, DatagramChannelInner>,
}

struct DatagramChannelInner {
    messages: VecDeque<DatagramMessage>,
    capacity: usize,
    closed: bool,
}

impl DatagramChannel {
    pub(crate) fn new(capacity: usize) -> Self {
        DatagramChannel {
            queue: litebox::sync::Mutex::new(DatagramChannelInner {
                messages: VecDeque::with_capacity(capacity),
                capacity,
                closed: false,
            }),
        }
    }

    pub(crate) fn try_send(&self, msg: DatagramMessage) -> Result<(), Errno> {
        let mut inner = self.queue.lock();
        if inner.closed {
            return Err(Errno::EPIPE);
        }
        if inner.messages.len() >= inner.capacity {
            return Err(Errno::EAGAIN);
        }
        inner.messages.push_back(msg);
        Ok(())
    }

    pub(crate) fn try_recv(&self) -> Result<DatagramMessage, Errno> {
        let mut inner = self.queue.lock();
        match inner.messages.pop_front() {
            Some(msg) => Ok(msg),
            None => {
                if inner.closed {
                    Err(Errno::ESHUTDOWN)
                } else {
                    Err(Errno::EAGAIN)
                }
            }
        }
    }

    pub(crate) fn close(&self) {
        self.queue.lock().closed = true;
    }
}

// ---------------------------------------------------------------------------
// UnixSocket
// ---------------------------------------------------------------------------

/// A Unix domain socket (AF_UNIX).
pub(crate) struct UnixSocket<FS: ShimFS> {
    inner: litebox::sync::Mutex<Platform, UnixSocketInner<FS>>,
    sock_type: SockType,
    bound_addr: litebox::sync::Mutex<Platform, UnixSocketAddr>,
}

enum UnixSocketInner<FS: ShimFS> {
    /// Freshly created, not yet connected or listening.
    Init,
    /// Listening for connections (stream only).
    Listening(Backlog<FS>),
    /// Connected stream socket — has two channels for bidirectional data.
    ConnectedStream {
        /// Channel we read from (peer writes to this).
        rx: Arc<Channel>,
        /// Channel we write to (peer reads from this).
        tx: Arc<Channel>,
        peer_addr: UnixSocketAddr,
    },
    /// Connected datagram socket.
    ConnectedDatagram {
        /// Our receive queue (peer sends to this).
        rx: Arc<DatagramChannel>,
        /// Peer's receive queue (we send to this).
        tx: Arc<DatagramChannel>,
        peer_addr: UnixSocketAddr,
    },
    /// Bound datagram socket (has a receive queue registered in addr table).
    BoundDatagram {
        rx: Arc<DatagramChannel>,
    },
    /// Shut down.
    Closed,
}

impl<FS: ShimFS> UnixSocket<FS> {
    /// Create a new Unix socket.
    pub(crate) fn new(sock_type: SockType) -> Self {
        UnixSocket {
            inner: litebox::sync::Mutex::new(UnixSocketInner::Init),
            sock_type,
            bound_addr: litebox::sync::Mutex::new(UnixSocketAddr::Unnamed),
        }
    }

    /// Get the socket type.
    pub(crate) fn sock_type(&self) -> SockType {
        self.sock_type
    }

    /// Get the bound address.
    pub(crate) fn bound_addr(&self) -> UnixSocketAddr {
        self.bound_addr.lock().clone()
    }

    /// Get the peer address (for connected sockets).
    pub(crate) fn peer_addr(&self) -> UnixSocketAddr {
        let inner = self.inner.lock();
        match &*inner {
            UnixSocketInner::ConnectedStream { peer_addr, .. } => peer_addr.clone(),
            UnixSocketInner::ConnectedDatagram { peer_addr, .. } => peer_addr.clone(),
            _ => UnixSocketAddr::Unnamed,
        }
    }

    /// Write data to a connected stream socket.
    pub(crate) fn write(&self, data: &[u8]) -> Result<usize, Errno> {
        let inner = self.inner.lock();
        match &*inner {
            UnixSocketInner::ConnectedStream { tx, .. } => tx.try_write(data),
            _ => Err(Errno::ENOTCONN),
        }
    }

    /// Read data from a connected stream socket.
    pub(crate) fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let inner = self.inner.lock();
        match &*inner {
            UnixSocketInner::ConnectedStream { rx, .. } => rx.try_read(buf),
            _ => Err(Errno::ENOTCONN),
        }
    }

    /// Shutdown the socket.
    pub(crate) fn shutdown(&self, how: u32) -> Result<(), Errno> {
        let inner = self.inner.lock();
        match &*inner {
            UnixSocketInner::ConnectedStream { rx, tx, .. } => {
                match how {
                    SHUT_RD => rx.shutdown_read(),
                    SHUT_WR => tx.shutdown_write(),
                    SHUT_RDWR => {
                        rx.shutdown_read();
                        tx.shutdown_write();
                    }
                    _ => return Err(Errno::EINVAL),
                }
                Ok(())
            }
            _ => Err(Errno::ENOTCONN),
        }
    }

    /// Bind to an address (sets the bound_addr).
    pub(crate) fn set_bound_addr(&self, addr: UnixSocketAddr) {
        *self.bound_addr.lock() = addr;
    }

    /// Transition to listening state (stream sockets only).
    pub(crate) fn listen(&self, backlog: u32) -> Result<(), Errno> {
        if self.sock_type != SockType::Stream {
            return Err(Errno::EOPNOTSUPP);
        }
        let mut inner = self.inner.lock();
        match &*inner {
            UnixSocketInner::Init => {
                *inner = UnixSocketInner::Listening(Backlog::new(backlog as usize));
                Ok(())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// Try to accept a connection from the backlog (stream sockets only).
    pub(crate) fn try_accept(&self) -> Result<(Arc<Channel>, Arc<Channel>, UnixSocketAddr), Errno> {
        let inner = self.inner.lock();
        match &*inner {
            UnixSocketInner::Listening(backlog) => backlog.try_accept(),
            _ => Err(Errno::EINVAL),
        }
    }

    /// Try to connect to a listening socket.
    /// Pushes a connection entry to the listener's backlog, then transitions
    /// this socket to ConnectedStream.
    pub(crate) fn connect_to_listener(
        &self,
        listener: &UnixSocket<FS>,
        client_addr: UnixSocketAddr,
    ) -> Result<(), Errno> {
        let (client_rx, client_tx) = listener.try_push_to_backlog(client_addr.clone())?;
        let mut inner = self.inner.lock();
        *inner = UnixSocketInner::ConnectedStream {
            rx: client_rx,
            tx: client_tx,
            peer_addr: listener.bound_addr(),
        };
        Ok(())
    }

    /// Try to push a connection to this socket's backlog (called by connect_to_listener).
    /// Returns (client_rx, client_tx) channels for the connecting socket.
    fn try_push_to_backlog(
        &self,
        client_addr: UnixSocketAddr,
    ) -> Result<(Arc<Channel>, Arc<Channel>), Errno> {
        let inner = self.inner.lock();
        match &*inner {
            UnixSocketInner::Listening { backlog } => backlog.try_connect(client_addr),
            _ => Err(Errno::ECONNREFUSED),
        }
    }

    /// Set up as a connected stream socket (used by socketpair and accept).
    pub(crate) fn set_connected_stream(
        &self,
        rx: Arc<Channel>,
        tx: Arc<Channel>,
        peer_addr: UnixSocketAddr,
    ) {
        let mut inner = self.inner.lock();
        *inner = UnixSocketInner::ConnectedStream {
            rx,
            tx,
            peer_addr,
        };
    }

    /// Set up as a connected datagram socket (used by socketpair).
    pub(crate) fn set_connected_datagram(
        &self,
        rx: Arc<DatagramChannel>,
        tx: Arc<DatagramChannel>,
        peer_addr: UnixSocketAddr,
    ) {
        let mut inner = self.inner.lock();
        *inner = UnixSocketInner::ConnectedDatagram {
            rx,
            tx,
            peer_addr,
        };
    }

    /// Set up as a bound datagram socket.
    pub(crate) fn set_bound_datagram(&self, rx: Arc<DatagramChannel>) {
        let mut inner = self.inner.lock();
        *inner = UnixSocketInner::BoundDatagram { rx };
    }

    /// Send a datagram.
    pub(crate) fn send_datagram(&self, data: &[u8], target: &DatagramChannel) -> Result<usize, Errno> {
        let msg = DatagramMessage {
            data: data.to_vec(),
            from: self.bound_addr(),
        };
        target.try_send(msg)?;
        Ok(data.len())
    }

    /// Receive a datagram.
    pub(crate) fn recv_datagram(&self) -> Result<DatagramMessage, Errno> {
        let inner = self.inner.lock();
        match &*inner {
            UnixSocketInner::ConnectedDatagram { rx, .. } => rx.try_recv(),
            UnixSocketInner::BoundDatagram { rx } => rx.try_recv(),
            _ => Err(Errno::ENOTCONN),
        }
    }

    /// Close the socket.
    pub(crate) fn close(&self) {
        let mut inner = self.inner.lock();
        match &*inner {
            UnixSocketInner::ConnectedStream { tx, rx, .. } => {
                tx.shutdown_write();
                rx.shutdown_read();
            }
            UnixSocketInner::ConnectedDatagram { rx, .. } => {
                rx.close();
            }
            UnixSocketInner::BoundDatagram { rx } => {
                rx.close();
            }
            _ => {}
        }
        *inner = UnixSocketInner::Closed;
    }
}

// ---------------------------------------------------------------------------
// Backlog — accept queue for listening stream sockets
// ---------------------------------------------------------------------------

/// Accept queue for a listening Unix stream socket.
pub(crate) struct Backlog<FS: ShimFS> {
    queue: litebox::sync::Mutex<Platform, VecDeque<BacklogEntry>>,
    limit: usize,
    _phantom: core::marker::PhantomData<FS>,
}

/// A pending connection in the backlog.
struct BacklogEntry {
    /// Server-side channel: server reads from this.
    server_rx: Arc<Channel>,
    /// Server-side channel: server writes to this.
    server_tx: Arc<Channel>,
    /// Client's address.
    client_addr: UnixSocketAddr,
}

impl<FS: ShimFS> Backlog<FS> {
    pub(crate) fn new(limit: usize) -> Self {
        Backlog {
            queue: litebox::sync::Mutex::new(VecDeque::with_capacity(limit)),
            limit,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Called by a connecting client. Creates cross-linked channels and pushes
    /// the server-side entry into the queue. Returns (client_rx, client_tx).
    pub(crate) fn try_connect(
        &self,
        client_addr: UnixSocketAddr,
    ) -> Result<(Arc<Channel>, Arc<Channel>), Errno> {
        let mut queue = self.queue.lock();
        if queue.len() >= self.limit {
            return Err(Errno::EAGAIN);
        }

        // Create two channels for bidirectional communication.
        let chan_a = Arc::new(Channel::new(UNIX_BUF_SIZE)); // client writes, server reads
        let chan_b = Arc::new(Channel::new(UNIX_BUF_SIZE)); // server writes, client reads

        queue.push_back(BacklogEntry {
            server_rx: chan_a.clone(), // server reads what client writes
            server_tx: chan_b.clone(), // server writes what client reads
            client_addr,
        });

        // Client: reads from chan_b, writes to chan_a
        Ok((chan_b, chan_a))
    }

    /// Called by accept(). Pops the next pending connection.
    /// Returns (server_rx, server_tx, client_addr).
    pub(crate) fn try_accept(&self) -> Result<(Arc<Channel>, Arc<Channel>, UnixSocketAddr), Errno> {
        let mut queue = self.queue.lock();
        match queue.pop_front() {
            Some(entry) => Ok((entry.server_rx, entry.server_tx, entry.client_addr)),
            None => Err(Errno::EAGAIN),
        }
    }
}

// ---------------------------------------------------------------------------
// UnixAddrEntry — what's stored in the address table
// ---------------------------------------------------------------------------

/// Entry in the Unix socket address table.
pub(crate) enum UnixAddrEntry<FS: ShimFS> {
    /// A listening stream socket (contains Backlog inside).
    /// We store the whole socket so connect() can call try_push_to_backlog().
    StreamListener(Arc<UnixSocket<FS>>),
    /// A bound datagram socket's receive queue.
    DatagramReceiver(Arc<DatagramChannel>),
}
```

- [ ] **Step 2: Verify the file is syntactically valid**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles (the module is already declared in `mod.rs` from Task 7). There may be warnings about unused types — that's expected.

- [ ] **Step 3: Commit**

```bash
git add litebox_shim_macos/src/syscalls/unix.rs
git commit -m "feat(macos): add Channel, UnixSocket, Backlog, and AF_UNIX core types"
```

---

## Task 14: Implement AF_UNIX socket, bind, listen, accept, connect

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/net.rs` (replace stub methods with real AF_UNIX implementations)
- Modify: `litebox_shim_macos/src/syscalls/unix.rs` (may add helper methods)
- Modify: `litebox_shim_macos/src/lib.rs` (finalize GlobalState unix fields from Task 6)

This task replaces the `do_socket_unix`, `do_bind_unix`, `do_listen_unix`, `do_accept_unix`, `do_connect_unix` stubs in `net.rs` with real implementations that use the `UnixSocket` types from `unix.rs`.

- [ ] **Step 1: Replace `do_socket_unix` stub**

In `net.rs`, replace the `do_socket_unix` method:

```rust
    fn do_socket_unix(&self, sock_type: SockType) -> Result<usize, Errno> {
        let socket = Arc::new(crate::syscalls::unix::UnixSocket::new(sock_type));
        let fd = self
            .global
            .unix_fd_counter
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.global.unix_sockets.write().insert(fd, socket);
        Ok(fd)
    }
```

- [ ] **Step 2: Replace `do_bind_unix` stub**

```rust
    fn do_bind_unix(&self, fd: u32, addr: UnixSocketAddr) -> Result<(), Errno> {
        let unix_sockets = self.global.unix_sockets.read();
        let socket = unix_sockets
            .get(&(fd as usize))
            .ok_or(Errno::ENOTSOCK)?
            .clone();
        drop(unix_sockets);

        match &addr {
            UnixSocketAddr::Path(path) => {
                // Check if address is already in use.
                let addr_table = self.global.unix_addr_table.read();
                if addr_table.contains_key(path) {
                    return Err(Errno::EADDRINUSE);
                }
                drop(addr_table);

                socket.set_bound_addr(addr.clone());

                // For datagram sockets, register in addr table immediately.
                if socket.sock_type() == SockType::Datagram {
                    let rx = Arc::new(crate::syscalls::unix::DatagramChannel::new(64));
                    socket.set_bound_datagram(rx.clone());
                    self.global.unix_addr_table.write().insert(
                        path.clone(),
                        crate::syscalls::unix::UnixAddrEntry::DatagramReceiver(rx),
                    );
                }

                Ok(())
            }
            UnixSocketAddr::Unnamed => Err(Errno::EINVAL),
        }
    }
```

- [ ] **Step 3: Replace `do_listen_unix` stub**

```rust
    fn do_listen_unix(&self, fd: u32, backlog: u32) -> Result<(), Errno> {
        let unix_sockets = self.global.unix_sockets.read();
        let socket = unix_sockets
            .get(&(fd as usize))
            .ok_or(Errno::ENOTSOCK)?
            .clone();
        drop(unix_sockets);

        socket.listen(backlog)?;

        // Register the socket in the address table so connect() can find it.
        let bound_addr = socket.bound_addr();
        if let UnixSocketAddr::Path(ref path) = bound_addr {
            self.global.unix_addr_table.write().insert(
                path.clone(),
                crate::syscalls::unix::UnixAddrEntry::StreamListener(socket),
            );
        }

        Ok(())
    }
```

- [ ] **Step 4: Replace `do_accept_unix` stub**

```rust
    fn do_accept_unix(&self, fd: u32, addr: u64, addrlen: u64) -> Result<usize, Errno> {
        let unix_sockets = self.global.unix_sockets.read();
        let socket = unix_sockets
            .get(&(fd as usize))
            .ok_or(Errno::ENOTSOCK)?
            .clone();
        drop(unix_sockets);

        let (server_rx, server_tx, client_addr) = socket.try_accept()?;

        // Create the accepted socket.
        let accepted = Arc::new(crate::syscalls::unix::UnixSocket::<FS>::new(SockType::Stream));
        accepted.set_connected_stream(server_rx, server_tx, client_addr.clone());

        // Allocate fd and register.
        let accepted_fd = self
            .global
            .unix_fd_counter
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.global.unix_sockets.write().insert(accepted_fd, accepted);

        // Write client address back to user memory if requested.
        write_sockaddr_unix_to_user(&client_addr, addr, addrlen)?;

        Ok(accepted_fd)
    }
```

- [ ] **Step 5: Replace `do_connect_unix` stub**

```rust
    fn do_connect_unix(&self, fd: u32, addr: UnixSocketAddr) -> Result<(), Errno> {
        let path = match &addr {
            UnixSocketAddr::Path(p) => p.clone(),
            UnixSocketAddr::Unnamed => return Err(Errno::EINVAL),
        };

        let unix_sockets = self.global.unix_sockets.read();
        let client_socket = unix_sockets
            .get(&(fd as usize))
            .ok_or(Errno::ENOTSOCK)?
            .clone();
        drop(unix_sockets);

        // Find the target in the address table.
        let addr_table = self.global.unix_addr_table.read();
        let entry = addr_table.get(&path).ok_or(Errno::ECONNREFUSED)?;

        match entry {
            crate::syscalls::unix::UnixAddrEntry::StreamListener(listener_socket) => {
                let listener_socket = listener_socket.clone();
                drop(addr_table);
                let client_addr = client_socket.bound_addr();
                client_socket.connect_to_listener(&listener_socket, client_addr)?;
                Ok(())
            }
            crate::syscalls::unix::UnixAddrEntry::DatagramReceiver(rx) => {
                let rx = rx.clone();
                drop(addr_table);
                // For datagram connect, store the target for future sends.
                let my_rx = Arc::new(crate::syscalls::unix::DatagramChannel::new(64));
                client_socket.set_connected_datagram(my_rx, rx, addr);
                Ok(())
            }
        }
    }
```

- [ ] **Step 6: Replace Unix sendto/recvfrom stubs**

```rust
    fn do_sendto_unix(
        &self,
        fd: u32,
        data: &[u8],
        _addr: Option<UnixSocketAddr>,
    ) -> Result<usize, Errno> {
        let unix_sockets = self.global.unix_sockets.read();
        let socket = unix_sockets
            .get(&(fd as usize))
            .ok_or(Errno::ENOTSOCK)?
            .clone();
        drop(unix_sockets);
        socket.write(data)
    }

    fn do_recvfrom_unix(
        &self,
        fd: u32,
        buf: u64,
        len: usize,
        src_addr: u64,
        addrlen: u64,
    ) -> Result<usize, Errno> {
        let unix_sockets = self.global.unix_sockets.read();
        let socket = unix_sockets
            .get(&(fd as usize))
            .ok_or(Errno::ENOTSOCK)?
            .clone();
        drop(unix_sockets);

        let mut kernel_buf = alloc::vec![0u8; len];
        let bytes_read = socket.read(&mut kernel_buf)?;

        let user_buf: MutPtr<u8> = MutPtr::from_usize(buf as usize);
        user_buf
            .copy_from_slice(0, &kernel_buf[..bytes_read])
            .ok_or(Errno::EFAULT)?;

        // Unix sockets don't typically report source address for stream.
        // For datagram, we'd need to track it. Write unnamed for now.
        if src_addr != 0 {
            write_sockaddr_unix_to_user(&UnixSocketAddr::Unnamed, src_addr, addrlen)?;
        }

        Ok(bytes_read)
    }
```

- [ ] **Step 7: Add Unix socket close to sys_close in file.rs**

In `litebox_shim_macos/src/syscalls/file.rs`, in the `sys_close` method, after the Network `fd_consume_raw_integer` block, add:

```rust
        // Try Unix socket.
        {
            let mut unix_sockets = self.global.unix_sockets.write();
            if let Some(socket) = unix_sockets.remove(&raw_fd) {
                // Remove from address table if bound.
                let bound = socket.bound_addr();
                if let crate::syscalls::net::UnixSocketAddr::Path(ref path) = bound {
                    self.global.unix_addr_table.write().remove(path);
                }
                socket.close();
                return Ok(());
            }
        }
```

- [ ] **Step 8: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`

- [ ] **Step 9: Commit**

```bash
git add litebox_shim_macos/src/syscalls/net.rs litebox_shim_macos/src/syscalls/unix.rs litebox_shim_macos/src/syscalls/file.rs
git commit -m "feat(macos): implement AF_UNIX socket, bind, listen, accept, connect"
```

---

## Task 15: Implement socketpair

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/net.rs` (add `sys_socketpair`)

- [ ] **Step 1: Add sys_socketpair**

Append to the `impl<FS: ShimFS> Task<FS>` block in `net.rs`:

```rust
    /// Handle `socketpair(domain, type, protocol, sv)`.
    pub(crate) fn sys_socketpair(
        &self,
        domain: u32,
        sock_type: u32,
        _protocol: u32,
        sv: u64,
    ) -> Result<(), Errno> {
        if domain != AF_UNIX {
            return Err(Errno::EAFNOSUPPORT);
        }

        let ty = SockType::try_from_raw(sock_type)?;

        let sock_a = Arc::new(crate::syscalls::unix::UnixSocket::<FS>::new(ty));
        let sock_b = Arc::new(crate::syscalls::unix::UnixSocket::<FS>::new(ty));

        match ty {
            SockType::Stream => {
                let chan_a = Arc::new(crate::syscalls::unix::Channel::new(65536));
                let chan_b = Arc::new(crate::syscalls::unix::Channel::new(65536));

                // A reads from chan_a, writes to chan_b
                // B reads from chan_b, writes to chan_a
                sock_a.set_connected_stream(chan_a.clone(), chan_b.clone(), UnixSocketAddr::Unnamed);
                sock_b.set_connected_stream(chan_b, chan_a, UnixSocketAddr::Unnamed);
            }
            SockType::Datagram => {
                let dg_a = Arc::new(crate::syscalls::unix::DatagramChannel::new(64));
                let dg_b = Arc::new(crate::syscalls::unix::DatagramChannel::new(64));

                sock_a.set_connected_datagram(dg_a.clone(), dg_b.clone(), UnixSocketAddr::Unnamed);
                sock_b.set_connected_datagram(dg_b, dg_a, UnixSocketAddr::Unnamed);
            }
        }

        let fd_a = self
            .global
            .unix_fd_counter
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let fd_b = self
            .global
            .unix_fd_counter
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        self.global.unix_sockets.write().insert(fd_a, sock_a);
        self.global.unix_sockets.write().insert(fd_b, sock_b);

        // Write fd pair to guest memory: sv[0] = fd_a, sv[1] = fd_b.
        let sv_ptr: MutPtr<u32> = MutPtr::from_usize(sv as usize);
        // macOS socketpair writes two int values (i32).
        let fds = [fd_a as u32, fd_b as u32];
        sv_ptr
            .copy_from_slice(0, &fds)
            .ok_or(Errno::EFAULT)?;

        Ok(())
    }
```

Note: The `sv_ptr.copy_from_slice` needs to write two `i32`/`u32` values. Adjust the pointer type based on what `MutPtr` supports. If `MutPtr<u32>` doesn't have `copy_from_slice`, use `MutPtr<u8>` and write raw bytes:

```rust
        let sv_ptr: MutPtr<u8> = MutPtr::from_usize(sv as usize);
        let mut sv_bytes = [0u8; 8];
        sv_bytes[0..4].copy_from_slice(&(fd_a as u32).to_ne_bytes());
        sv_bytes[4..8].copy_from_slice(&(fd_b as u32).to_ne_bytes());
        sv_ptr.copy_from_slice(0, &sv_bytes).ok_or(Errno::EFAULT)?;
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`

- [ ] **Step 3: Commit**

```bash
git add litebox_shim_macos/src/syscalls/net.rs
git commit -m "feat(macos): implement socketpair for AF_UNIX"
```

---

## Task 16: TCP echo test

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/tcp_echo.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

**Depends on:** Tasks 1-12 (all AF_INET functionality)

- [ ] **Step 1: Create tcp_echo.c**

Create `litebox_runner_macos_on_macos_userland/tests/tcp_echo.c`:

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: TCP echo — server thread accepts a connection, echoes data back.
// Uses threads: server binds to 127.0.0.1:0, getsockname() to discover port,
// client connects and sends "hello tcp", verifies echoed data.
// Exit codes: 0 = success, 1-20 = specific failure step.

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

// Shared state: the port assigned by bind()
static volatile int g_port = 0;
static volatile int g_server_ready = 0;

static void *server_thread(void *arg) {
    (void)arg;

    // Create server socket
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) _exit(1);

    // Allow address reuse
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind to 127.0.0.1:0 (auto-assign port)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(0x7f000001); // 127.0.0.1

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) _exit(2);

    // Discover assigned port
    struct sockaddr_in bound_addr;
    socklen_t bound_len = sizeof(bound_addr);
    if (getsockname(sfd, (struct sockaddr *)&bound_addr, &bound_len) != 0) _exit(3);
    g_port = ntohs(bound_addr.sin_port);

    if (listen(sfd, 5) != 0) _exit(4);

    // Signal client
    g_server_ready = 1;

    // Accept one connection
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int cfd = accept(sfd, (struct sockaddr *)&client_addr, &client_len);
    if (cfd < 0) _exit(5);

    // Echo loop: read then write back
    char buf[128];
    ssize_t n = recv(cfd, buf, sizeof(buf), 0);
    if (n <= 0) _exit(6);

    ssize_t sent = send(cfd, buf, (size_t)n, 0);
    if (sent != n) _exit(7);

    close(cfd);
    close(sfd);
    return NULL;
}

int main(void) {
    pthread_t srv;
    if (pthread_create(&srv, NULL, server_thread, NULL) != 0) _exit(10);

    // Wait for server to be ready
    while (!g_server_ready) {
        usleep(1000); // 1ms
    }

    // Create client socket
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) _exit(11);

    // Connect to server
    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_len = sizeof(srv_addr);
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons((uint16_t)g_port);
    srv_addr.sin_addr.s_addr = htonl(0x7f000001);

    if (connect(cfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) != 0) _exit(12);

    // Send data
    const char *msg = "hello tcp";
    ssize_t msg_len = (ssize_t)strlen(msg);
    ssize_t sent = send(cfd, msg, (size_t)msg_len, 0);
    if (sent != msg_len) _exit(13);

    // Receive echoed data
    char buf[128];
    ssize_t n = recv(cfd, buf, sizeof(buf), 0);
    if (n != msg_len) _exit(14);
    if (memcmp(buf, msg, (size_t)n) != 0) _exit(15);

    close(cfd);

    // Wait for server thread to finish
    pthread_join(srv, NULL);

    _exit(0);
}
```

- [ ] **Step 2: Add test_tcp_echo to loader.rs**

In `litebox_runner_macos_on_macos_userland/tests/loader.rs`, append:

```rust
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_tcp_echo() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/tcp_echo.c", "tcp_echo");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/tcp_echo"],
        &cache_result,
        "tcp_echo",
    );
    assert_eq!(
        exit_code, 0,
        "tcp_echo test failed with exit code {exit_code}"
    );
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_runner_macos_on_macos_userland --tests`
Expected: compiles.

- [ ] **Step 4: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_tcp_echo -- --nocapture`
Expected: test passes (exit code 0).

- [ ] **Step 5: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/tcp_echo.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add TCP echo end-to-end test"
```

---

## Task 17: UDP send/recv test

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/udp_sendrecv.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

**Depends on:** Tasks 1-12 (all AF_INET functionality)

- [ ] **Step 1: Create udp_sendrecv.c**

Create `litebox_runner_macos_on_macos_userland/tests/udp_sendrecv.c`:

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: UDP send/recv — two sockets, sendto/recvfrom with address verification.
// Single-process: receiver binds to 127.0.0.1:0, sender uses sendto(),
// receiver uses recvfrom() and verifies data + source address.
// Exit codes: 0 = success, 1-10 = specific failure step.

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    // Create receiver socket
    int rfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rfd < 0) _exit(1);

    // Bind receiver to 127.0.0.1:0
    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_len = sizeof(recv_addr);
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = 0;
    recv_addr.sin_addr.s_addr = htonl(0x7f000001);

    if (bind(rfd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) != 0) _exit(2);

    // Discover assigned port
    struct sockaddr_in bound_addr;
    socklen_t bound_len = sizeof(bound_addr);
    if (getsockname(rfd, (struct sockaddr *)&bound_addr, &bound_len) != 0) _exit(3);

    // Create sender socket
    int sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd < 0) _exit(4);

    // Send data to receiver
    const char *msg = "hello udp";
    ssize_t msg_len = (ssize_t)strlen(msg);
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_len = sizeof(dest_addr);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = bound_addr.sin_port; // already in network order
    dest_addr.sin_addr.s_addr = htonl(0x7f000001);

    ssize_t sent = sendto(sfd, msg, (size_t)msg_len, 0,
                          (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sent != msg_len) _exit(5);

    // Receive data
    char buf[128];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t n = recvfrom(rfd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from_addr, &from_len);
    if (n != msg_len) _exit(6);
    if (memcmp(buf, msg, (size_t)n) != 0) _exit(7);

    // Verify source address is 127.0.0.1
    if (from_addr.sin_addr.s_addr != htonl(0x7f000001)) _exit(8);

    close(sfd);
    close(rfd);

    _exit(0);
}
```

- [ ] **Step 2: Add test_udp_sendrecv to loader.rs**

In `litebox_runner_macos_on_macos_userland/tests/loader.rs`, append:

```rust
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_udp_sendrecv() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/udp_sendrecv.c", "udp_sendrecv");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/udp_sendrecv"],
        &cache_result,
        "udp_sendrecv",
    );
    assert_eq!(
        exit_code, 0,
        "udp_sendrecv test failed with exit code {exit_code}"
    );
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_runner_macos_on_macos_userland --tests`
Expected: compiles.

- [ ] **Step 4: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_udp_sendrecv -- --nocapture`
Expected: test passes (exit code 0).

- [ ] **Step 5: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/udp_sendrecv.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add UDP sendrecv end-to-end test"
```

---

## Task 18: Unix stream test

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/unix_stream.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

**Depends on:** Tasks 13-14 (AF_UNIX socket, bind, listen, accept, connect)

- [ ] **Step 1: Create unix_stream.c**

Create `litebox_runner_macos_on_macos_userland/tests/unix_stream.c`:

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: AF_UNIX stream — server thread accepts a connection, echoes data back.
// Uses threads: server binds to /tmp/litebox_test.sock, client connects,
// sends "hello unix", verifies echoed data.
// Exit codes: 0 = success, 1-20 = specific failure step.

#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#define SOCK_PATH "/tmp/litebox_test.sock"

static volatile int g_server_ready = 0;

static void *server_thread(void *arg) {
    (void)arg;

    // Create server socket
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) _exit(1);

    // Remove any stale socket file
    unlink(SOCK_PATH);

    // Bind to path
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_len = sizeof(addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) _exit(2);
    if (listen(sfd, 5) != 0) _exit(3);

    // Signal client
    g_server_ready = 1;

    // Accept one connection
    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);
    int cfd = accept(sfd, (struct sockaddr *)&client_addr, &client_len);
    if (cfd < 0) _exit(4);

    // Echo: read then write back
    char buf[128];
    ssize_t n = recv(cfd, buf, sizeof(buf), 0);
    if (n <= 0) _exit(5);

    ssize_t sent = send(cfd, buf, (size_t)n, 0);
    if (sent != n) _exit(6);

    close(cfd);
    close(sfd);
    unlink(SOCK_PATH);
    return NULL;
}

int main(void) {
    pthread_t srv;
    if (pthread_create(&srv, NULL, server_thread, NULL) != 0) _exit(10);

    // Wait for server to be ready
    while (!g_server_ready) {
        usleep(1000);
    }

    // Create client socket
    int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cfd < 0) _exit(11);

    // Connect to server
    struct sockaddr_un srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sun_len = sizeof(srv_addr);
    srv_addr.sun_family = AF_UNIX;
    strncpy(srv_addr.sun_path, SOCK_PATH, sizeof(srv_addr.sun_path) - 1);

    if (connect(cfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) != 0) _exit(12);

    // Send data
    const char *msg = "hello unix";
    ssize_t msg_len = (ssize_t)strlen(msg);
    ssize_t sent = send(cfd, msg, (size_t)msg_len, 0);
    if (sent != msg_len) _exit(13);

    // Receive echoed data
    char buf[128];
    ssize_t n = recv(cfd, buf, sizeof(buf), 0);
    if (n != msg_len) _exit(14);
    if (memcmp(buf, msg, (size_t)n) != 0) _exit(15);

    close(cfd);

    // Wait for server thread
    pthread_join(srv, NULL);

    _exit(0);
}
```

- [ ] **Step 2: Add test_unix_stream to loader.rs**

In `litebox_runner_macos_on_macos_userland/tests/loader.rs`, append:

```rust
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_unix_stream() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/unix_stream.c", "unix_stream");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/unix_stream"],
        &cache_result,
        "unix_stream",
    );
    assert_eq!(
        exit_code, 0,
        "unix_stream test failed with exit code {exit_code}"
    );
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_runner_macos_on_macos_userland --tests`
Expected: compiles.

- [ ] **Step 4: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_unix_stream -- --nocapture`
Expected: test passes (exit code 0).

- [ ] **Step 5: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/unix_stream.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add AF_UNIX stream end-to-end test"
```

---

## Task 19: Socketpair test

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/socketpair.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

**Depends on:** Task 15 (socketpair implementation)

- [ ] **Step 1: Create socketpair.c**

Create `litebox_runner_macos_on_macos_userland/tests/socketpair.c`:

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: socketpair() — create connected AF_UNIX pair, bidirectional data exchange.
// Creates a pair, writes "hello pair" to sv[0], reads from sv[1] and verifies,
// then writes "reply" to sv[1], reads from sv[0] and verifies.
// Exit codes: 0 = success, 1-10 = specific failure step.

#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) _exit(1);

    // Write "hello pair" to sv[0]
    const char *msg1 = "hello pair";
    ssize_t msg1_len = (ssize_t)strlen(msg1);
    ssize_t sent = write(sv[0], msg1, (size_t)msg1_len);
    if (sent != msg1_len) _exit(2);

    // Read from sv[1]
    char buf[128];
    ssize_t n = read(sv[1], buf, sizeof(buf));
    if (n != msg1_len) _exit(3);
    if (memcmp(buf, msg1, (size_t)n) != 0) _exit(4);

    // Write "reply" to sv[1]
    const char *msg2 = "reply";
    ssize_t msg2_len = (ssize_t)strlen(msg2);
    sent = write(sv[1], msg2, (size_t)msg2_len);
    if (sent != msg2_len) _exit(5);

    // Read from sv[0]
    n = read(sv[0], buf, sizeof(buf));
    if (n != msg2_len) _exit(6);
    if (memcmp(buf, msg2, (size_t)n) != 0) _exit(7);

    close(sv[0]);
    close(sv[1]);

    _exit(0);
}
```

- [ ] **Step 2: Add test_socketpair to loader.rs**

In `litebox_runner_macos_on_macos_userland/tests/loader.rs`, append:

```rust
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_socketpair() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/socketpair.c", "socketpair_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/socketpair_test"],
        &cache_result,
        "socketpair_test",
    );
    assert_eq!(
        exit_code, 0,
        "socketpair test failed with exit code {exit_code}"
    );
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_runner_macos_on_macos_userland --tests`
Expected: compiles.

- [ ] **Step 4: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_socketpair -- --nocapture`
Expected: test passes (exit code 0).

- [ ] **Step 5: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/socketpair.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add socketpair end-to-end test"
```

---

## Task 20: Final verification — all tests pass + clippy clean

**Files:** None (verification only)

**Depends on:** Tasks 1-19

- [ ] **Step 1: Run all tests**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Expected: All tests pass (existing Phase A tests + 4 new: test_tcp_echo, test_udp_sendrecv, test_unix_stream, test_socketpair).

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland -- -D warnings`
Expected: No warnings or errors.

- [ ] **Step 3: Run fmt check**

Run: `cargo fmt --check -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland`
Expected: No formatting issues.

- [ ] **Step 4: Fix any issues found**

If any test fails, clippy warning, or fmt issue is found, fix it and re-run the checks.

- [ ] **Step 5: Final commit (if fixes were needed)**

```bash
git add -A
git commit -m "fix(macos): address Phase B final verification issues"
```
