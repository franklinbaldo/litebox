# macOS Shim Phase B: Sockets (AF_UNIX + AF_INET, TCP + UDP)

## Goal

Extend `litebox_shim_macos` with full socket support:

1. **AF_INET sockets** — TCP and UDP over the existing `Network<Platform>` + smoltcp stack
2. **AF_UNIX sockets** — Stream and datagram via a separate `UnixSocket` type with in-memory buffers
3. **socketpair()** — Connected AF_UNIX socket pairs for IPC
4. **sendmsg/recvmsg** — Structured message I/O (data only, no SCM_RIGHTS)
5. **Full socket options** — Match the Linux shim's supported set, mapped to macOS constants

This is Phase B of a three-phase plan:
- **Phase A** (complete): FD dispatch + pipes + filesystem + thread exit
- **Phase B** (this spec): Sockets (AF_UNIX + AF_INET)
- **Phase C** (future): Process lifecycle (fork/exec/waitpid) + I/O multiplexing (select/poll/kqueue)

## Approach

**macOS-Native Adaptation** of the proven Linux shim architecture:

- Follow the same high-level structure: separate `UnixSocket` type for AF_UNIX, `Network<Platform>` for AF_INET
- Use macOS-native struct layouts (`sin_len` + `sin_family` as `u8` each, `sun_path[104]`, etc.)
- Use macOS BSD syscall numbers and socket option constants (which differ significantly from Linux)
- Skip Linux-only features (epoll integration, /proc/net, SO_PEERCRED)
- Map Linux-isms to macOS equivalents (TCP_CORK → TCP_NOPUSH, TCP_KEEPIDLE → TCP_KEEPALIVE)

The `litebox` crate already provides `Network<Platform>` with socket/bind/listen/accept/connect/send/receive/close — all platform-generic using smoltcp. The macOS shim's `GlobalState` already initializes `Network` (currently marked `#[expect(dead_code)]`). We wire it up.

## 1. StrongFd Extension

### Current state

```rust
enum StrongFd<FS: ShimFS> {
    FileSystem(Arc<TypedFd<FS>>),
    Pipes(Arc<TypedFd<Pipes<Platform>>>),
}
```

### New variants

```rust
enum StrongFd<FS: ShimFS> {
    FileSystem(Arc<TypedFd<FS>>),
    Pipes(Arc<TypedFd<Pipes<Platform>>>),
    Network(Arc<TypedFd<Network<Platform>>>),
    // Unix sockets use a separate Descriptor enum (see section 5)
}
```

`StrongFd::from_raw()` gains a third try-branch for `Network`. The `#[expect(dead_code)]` on `GlobalState.net` is removed.

### Affected existing syscalls

| Syscall | Change |
|---------|--------|
| `sys_read` | Add `StrongFd::Network` arm → `net.receive()` |
| `sys_write` | Add `StrongFd::Network` arm → `net.send()` |
| `sys_close` | Add Network subsystem try-branch; also handle Unix socket close |
| `sys_dup2` | Works at `DescriptorEntry` level — subsystem-agnostic, no change needed |
| `sys_fcntl` | Network/Unix FDs: `F_GETFL`/`F_SETFL` work, `F_GETPATH` returns `EBADF` |

## 2. macOS Socket Address Structures

macOS uses BSD 4.4-style sockaddr with a length prefix. These differ from Linux:

### `CSockInetAddr` (macOS `sockaddr_in`)

```rust
#[repr(C, packed)]
struct CSockInetAddr {
    sin_len: u8,        // 1 byte — struct length (always 16)
    sin_family: u8,     // 1 byte — AF_INET (2)
    sin_port: u16,      // 2 bytes — port in network byte order
    sin_addr: [u8; 4],  // 4 bytes — IPv4 address
    sin_zero: [u8; 8],  // 8 bytes — padding
}
// Total: 16 bytes (same as Linux, different field widths)
```

### `CSockUnixAddr` (macOS `sockaddr_un`)

```rust
const UNIX_PATH_MAX: usize = 104;  // macOS: 104 (Linux: 108)

#[repr(C)]
struct CSockUnixAddr {
    sun_len: u8,                     // 1 byte — struct length
    sun_family: u8,                  // 1 byte — AF_UNIX (1)
    sun_path: [u8; UNIX_PATH_MAX],   // 104 bytes — path
}
// Total: 106 bytes (Linux: 110)
```

### Address reading/writing helpers

```rust
enum SocketAddress {
    Inet(SocketAddr),           // smoltcp-compatible
    Unix(UnixSocketAddr),       // local representation
}

fn read_sockaddr_from_user(memory: &GuestMemory, addr: usize, len: usize)
    -> Result<SocketAddress, Errno>;

fn write_sockaddr_to_user(memory: &GuestMemory, addr: SocketAddress,
    buf: usize, len_ptr: usize) -> Result<(), Errno>;
```

`read_sockaddr_from_user` reads the `sin_family`/`sun_family` byte (offset 1, since offset 0 is the length prefix) to determine AF_INET vs AF_UNIX, then parses the appropriate struct. `write_sockaddr_to_user` serializes back to macOS format, including setting the `sin_len`/`sun_len` field.

## 3. AF_INET Socket Implementation

AF_INET sockets go through the existing `Network<Platform>` + smoltcp stack. The pattern follows the Linux shim's `net.rs`.

### Socket creation

```rust
fn do_socket_inet(&self, sock_type: SockType) -> Result<usize, Errno> {
    let protocol = match sock_type {
        SockType::Stream => Protocol::Tcp,
        SockType::Datagram => Protocol::Udp,
        _ => return Err(Errno::EPROTONOSUPPORT),
    };
    let raw_fd = self.global.net.lock().socket(protocol)?;
    // raw_fd is stored in Network's internal descriptor table
    // StrongFd::Network resolves it via rds.fd_from_raw_integer::<Network<Platform>>()
    Ok(raw_fd)
}
```

### NetworkProxy initialization

After `socket()`, create a `NetworkProxy` for the fd (following `initialize_socket` in Linux shim):

```rust
fn initialize_socket(&self, raw_fd: usize, sock_type: SockType)
    -> Result<NetworkProxy<Platform>, Errno>
{
    match sock_type {
        SockType::Stream => {
            let channel = StreamSocketChannel::new(/* ... */);
            Ok(NetworkProxy::Stream(channel))
        }
        SockType::Datagram => {
            let channel = DatagramSocketChannel::new(/* ... */);
            Ok(NetworkProxy::Datagram(channel))
        }
        _ => Err(Errno::EPROTONOSUPPORT),
    }
}
```

### Syscall handlers (AF_INET path)

| Handler | Core operation |
|---------|---------------|
| `sys_bind` | `net.bind(fd, addr)` |
| `sys_listen` | `net.listen(fd, backlog)` |
| `sys_accept` | `net.accept(fd)` → new fd + peer addr |
| `sys_connect` | `net.connect(fd, addr)` |
| `sys_sendto` | `net.send(fd, data, dest_addr)` |
| `sys_recvfrom` | `net.receive(fd, buf)` → (bytes_read, source_addr) |
| `sys_getsockname` | `net.local_addr(fd)` → write to user |
| `sys_getpeername` | `net.peer_addr(fd)` → write to user |
| `sys_shutdown` | `net.shutdown(fd, how)` |

All go through `Network<Platform>` which handles the smoltcp state machine internally.

### Close

`close_socket` for AF_INET checks `SO_LINGER`: if set, attempts graceful close with timeout; otherwise immediate close via `net.close(fd)`.

## 4. Socket Options

macOS uses completely different constant values from Linux. We define a macOS-specific option mapping.

### macOS socket option constants

**Levels:**

| Level | macOS value | Linux value |
|-------|-------------|-------------|
| `SOL_SOCKET` | 0xFFFF (65535) | 1 |
| `IPPROTO_TCP` | 6 | 6 |
| `IPPROTO_IP` | 0 | 0 |

**SOL_SOCKET options:**

| Option | macOS value | Linux value | Implementation |
|--------|-------------|-------------|----------------|
| `SO_REUSEADDR` | 0x0004 | 2 | Store in `SocketOptions.reuse_address` |
| `SO_TYPE` | 0x1008 | 3 | Return socket type (get only, set returns ENOPROTOOPT) |
| `SO_BROADCAST` | 0x0020 | 6 | Store in `SocketOptions.broadcast` |
| `SO_SNDBUF` | 0x1001 | 7 | Get: return `SOCKET_BUFFER_SIZE`; Set: return EOPNOTSUPP |
| `SO_RCVBUF` | 0x1002 | 8 | Get: return `SOCKET_BUFFER_SIZE`; Set: return EOPNOTSUPP |
| `SO_KEEPALIVE` | 0x0008 | 9 | Set TCP keepalive via `set_tcp_option(KEEPALIVE)` |
| `SO_LINGER` | 0x0080 | 13 | Store linger timeout (used during close) |
| `SO_RCVTIMEO` | 0x1006 | 20 | Store recv timeout (used in receive) |
| `SO_SNDTIMEO` | 0x1005 | 21 | Store send timeout (used in sendto) |
| `SO_ERROR` | 0x1007 | 4 | Return pending socket error |

**Note:** macOS also defines `SO_LINGER_SEC` (0x1080) which uses seconds instead of ticks. Guest programs compiled with macOS headers under `_POSIX_C_SOURCE` may use 0x1080. We support both — they both set/get the same linger timeout in seconds.

**IPPROTO_TCP options:**

| Option | macOS value | Linux value | Implementation |
|--------|-------------|-------------|----------------|
| `TCP_NODELAY` | 0x01 | 1 | `set_tcp_option(NODELAY)` / `get_tcp_option(NODELAY)` |
| `TCP_NOPUSH` | 0x04 | N/A (TCP_CORK=3) | Emulate as inverse of NODELAY (same as Linux's TCP_CORK) |
| `TCP_KEEPALIVE` | 0x10 | N/A (TCP_KEEPIDLE=4) | `set_tcp_option(KEEPALIVE(Some(Duration)))` |
| `TCP_KEEPINTVL` | 0x101 | 5 | `set_tcp_option(KEEPALIVE(Some(Duration)))` |
| `TCP_KEEPCNT` | 0x102 | 6 | Return EOPNOTSUPP (same as Linux shim) |
| `TCP_CONGESTION` | N/A | 13 | Not available on macOS — return ENOPROTOOPT |

**IPPROTO_IP options:**

| Option | macOS value | Linux value | Implementation |
|--------|-------------|-------------|----------------|
| `IP_TOS` | 3 | 1 | Return EOPNOTSUPP (same as Linux shim) |

### SocketOptionName enum

```rust
enum SocketOptionLevel {
    Socket,     // SOL_SOCKET (0xFFFF)
    Tcp,        // IPPROTO_TCP (6)
    Ip,         // IPPROTO_IP (0)
}

enum SocketOptionName {
    // SOL_SOCKET
    ReuseAddr, Type, Broadcast, SndBuf, RcvBuf,
    KeepAlive, Linger, LingerSec, RcvTimeo, SndTimeo, Error,
    // IPPROTO_TCP
    TcpNoDelay, TcpNoPush, TcpKeepAlive, TcpKeepIntvl, TcpKeepCnt,
    // IPPROTO_IP
    IpTos,
}

impl SocketOptionName {
    fn try_from(level: u32, optname: u32) -> Option<Self> { /* ... */ }
}
```

### SocketOptions struct

```rust
struct SocketOptions {
    reuse_address: bool,
    keep_alive: bool,
    broadcast: bool,
    recv_timeout: Option<Duration>,
    send_timeout: Option<Duration>,
    linger_timeout: Option<Duration>,
}
```

Shared between inet and unix socket paths (same as Linux shim).

## 5. AF_UNIX Socket Implementation

AF_UNIX sockets use a separate `UnixSocket` type — they do not go through the smoltcp network stack. Data flows through in-memory ring buffers (`Channel` from the `channel` module).

### Descriptor model

Unix sockets are tracked via a side map in `GlobalState`, since the macOS shim uses `RawDescriptorStorage` directly (no separate file descriptor table like the Linux shim's `Descriptor` enum):

```rust
// In GlobalState:
unix_sockets: RwLock<BTreeMap<usize, Arc<UnixSocket<FS>>>>,
unix_fd_counter: AtomicUsize,  // allocates virtual fd numbers for Unix sockets
```

The key is a virtual fd number allocated from `unix_fd_counter`. Socket syscalls check `unix_sockets` first (for AF_UNIX operations), then fall through to `StrongFd::from_raw()` for AF_INET/FS/Pipes. `sys_close` checks and removes from `unix_sockets` if the fd is found there.

This is simpler than introducing a full `Descriptor` enum and integrates cleanly with the existing macOS shim architecture.

### UnixSocket structure

```rust
struct UnixSocket<FS: ShimFS> {
    inner: UnixSocketInner<FS>,
    status: AtomicU32,              // OFlags (RDWR, NONBLOCK)
    options: Mutex<SocketOptions>,
}

enum UnixSocketInner<FS: ShimFS> {
    Stream(UnixStream<FS>),
    Datagram(UnixDatagram<FS>),
}
```

### UnixStream state machine

```
Init ──bind()──► Bound ──listen()──► Listen ──accept()──► (new Connected socket)
  │                                      ▲
  └──connect()──► Connected              │
                                    try_connect() pushes
                                    to Backlog queue
```

States:
- **Init**: Freshly created. Can `bind()`, `listen()`, or `connect()`.
- **Bound**: Has a path in the address table. Can `listen()`.
- **Listen**: Has a `Backlog` (bounded `VecDeque` of connected streams). Can `accept()`.
- **Connected**: Has a pair of cross-linked ring buffer channels. Can `send()`/`recv()`.

### Backlog (accept queue)

```rust
struct Backlog<FS: ShimFS> {
    addr: Arc<UnixBoundSocketAddr<FS>>,
    limit: u16,                                        // from listen(backlog)
    sockets: Mutex<Option<VecDeque<UnixConnectedStream<FS>>>>,
    pollee: Pollee<Platform>,                          // for waking accept()
}
```

`connect()` calls `backlog.try_connect()`:
1. If queue is full → `EAGAIN` (caller retries with blocking)
2. Create a pair of cross-linked `UnixConnectedStream` instances
3. Push server-side stream into the `VecDeque`
4. Notify the pollee (`Events::IN`) to wake `accept()`
5. Return client-side stream

`accept()` calls `backlog.try_accept()`:
1. Pop front of `VecDeque`
2. If empty → `EAGAIN` (caller retries with blocking)
3. Wrap in new `UnixSocket` (Connected state)
4. Return new fd

### Channel (ring buffer)

Each connected pair shares two `Channel` instances (from the existing `channel` module in the Linux shim, or re-implemented):

```
Socket A                          Socket B
┌─────────┐   Channel 1          ┌─────────┐
│ send ────┼──► [ring buf] ──────┼─► recv  │
│          │                      │          │
│ recv ◄───┼──── [ring buf] ◄────┼── send  │
└─────────┘   Channel 2          └─────────┘
```

Buffer capacity: `UNIX_BUF_SIZE = 65536` bytes per channel.

### UnixDatagram

Datagram sockets are simpler:
- No connection state machine (no listen/accept)
- `bind()` registers in address table with a write-end of a `Channel<DatagramMessage>`
- `connect()` looks up the target in the address table, stores write-end
- `sendto(addr)` looks up the target each time (if not connected)
- Messages are atomic — each send/recv operates on complete datagrams

### UnixAddrTable

```rust
type UnixAddrTable<FS> = BTreeMap<UnixSocketAddrKey, UnixEntry<FS>>;

enum UnixSocketAddrKey {
    Path(String),
    // No abstract namespace on macOS (Linux-only feature)
}

enum UnixEntry<FS: ShimFS> {
    Stream(Arc<Backlog<FS>>),
    Datagram(WriteEnd<DatagramMessage>),
}
```

Stored in `GlobalState`:
```rust
unix_addr_table: RwLock<UnixAddrTable<FS>>,
```

**Note:** macOS does not support the abstract namespace for Unix sockets (a Linux-only feature). All Unix socket addresses are filesystem paths.

## 6. socketpair()

`socketpair(AF_UNIX, type, 0, sv)` creates a connected pair of AF_UNIX sockets.

For `SOCK_STREAM`:
1. Create two `Channel` instances
2. Cross-wire: socket A reads from channel 1, writes to channel 2; socket B reads from channel 2, writes to channel 1
3. Both sockets start in Connected state with `UnixSocketAddr::Unnamed`
4. Allocate two fd numbers, write to `sv[0]` and `sv[1]` in guest memory

For `SOCK_DGRAM`: same cross-wiring but with `DatagramMessage` channels.

Only `AF_UNIX` is supported for `socketpair`. `AF_INET` returns `EOPNOTSUPP`.

## 7. sendmsg / recvmsg

Basic structured message I/O. No SCM_RIGHTS (fd passing) support.

### macOS msghdr layout

```rust
#[repr(C)]
struct UserMsgHdr {
    msg_name: u64,       // *mut sockaddr
    msg_namelen: u32,    // sockaddr length
    _pad0: u32,          // padding for alignment
    msg_iov: u64,        // *mut iovec
    msg_iovlen: i32,     // number of iovecs
    _pad1: u32,          // padding
    msg_control: u64,    // *mut cmsghdr (ancillary data)
    msg_controllen: u32, // ancillary data length
    msg_flags: i32,      // flags
}
```

**Note:** The macOS `msghdr` uses `int` for `msg_iovlen` (not `size_t` like Linux on 64-bit). Verify exact layout against macOS headers during implementation.

### sendmsg implementation

1. Read `UserMsgHdr` from guest memory
2. If `msg_controllen != 0` → return `EOPNOTSUPP` (no ancillary data support)
3. Gather data from `msg_iov` scatter array
4. If `msg_name` is set, parse destination address
5. Dispatch to inet `sendto()` or unix `sendto()` with gathered data

### recvmsg implementation

1. Read `UserMsgHdr` from guest memory
2. Receive data into a temporary buffer
3. Scatter into `msg_iov` buffers
4. If `msg_name` is set, write source address
5. Write updated `msg_namelen` and `msg_flags` back to guest memory

## 8. New Syscalls

### BSD syscall numbers

| BSD # | Name | Direction |
|-------|------|-----------|
| 27 | `recvmsg` | ← data |
| 28 | `sendmsg` | → data |
| 29 | `recvfrom` | ← data |
| 30 | `accept` | ← new fd |
| 31 | `getpeername` | ← addr |
| 32 | `getsockname` | ← addr |
| 97 | `socket` | → new fd |
| 98 | `connect` | → |
| 104 | `bind` | → |
| 105 | `setsockopt` | → |
| 106 | `listen` | → |
| 118 | `getsockopt` | ← value |
| 133 | `sendto` | → data |
| 134 | `shutdown` | → |
| 135 | `socketpair` | → two fds |

Total: 15 new syscall variants.

### MacosSyscallRequest variants

```rust
// In litebox_common_macos/src/syscall.rs

Socket { domain: u32, sock_type: u32, protocol: u32 },
Bind { fd: u32, addr: u64, addrlen: u32 },
Listen { fd: u32, backlog: u32 },
Accept { fd: u32, addr: u64, addrlen: u64 },
Connect { fd: u32, addr: u64, addrlen: u32 },
Sendto { fd: u32, buf: u64, len: u64, flags: u32, dest_addr: u64, addrlen: u32 },
Recvfrom { fd: u32, buf: u64, len: u64, flags: u32, src_addr: u64, addrlen: u64 },
Sendmsg { fd: u32, msg: u64, flags: u32 },
Recvmsg { fd: u32, msg: u64, flags: u32 },
Shutdown { fd: u32, how: u32 },
Socketpair { domain: u32, sock_type: u32, protocol: u32, sv: u64 },
Setsockopt { fd: u32, level: u32, optname: u32, optval: u64, optlen: u32 },
Getsockopt { fd: u32, level: u32, optname: u32, optval: u64, optlen: u64 },
Getsockname { fd: u32, addr: u64, addrlen: u64 },
Getpeername { fd: u32, addr: u64, addrlen: u64 },
```

### New errno constants needed

Add to `litebox_common_macos/src/errno.rs`:

| Errno | macOS value | Usage |
|-------|-------------|-------|
| `EADDRINUSE` | 48 | bind: address already in use |
| `EADDRNOTAVAIL` | 49 | bind: address not available |
| `ENETUNREACH` | 51 | connect: network unreachable |
| `ECONNRESET` | 54 | recv: connection reset by peer |
| `ENOBUFS` | 55 | send: no buffer space |
| `EISCONN` | 56 | connect: already connected |
| `ENOTCONN` | 57 | send/recv: not connected |
| `ESHUTDOWN` | 58 | send: socket shut down |
| `ETIMEDOUT` | 60 | connect: timed out |
| `ECONNREFUSED` | 61 | connect: connection refused |
| `ENETDOWN` | 50 | network is down |
| `ENOTSOCK` | 38 | not a socket |
| `EAFNOSUPPORT` | 47 | address family not supported |
| `EPROTONOSUPPORT` | 43 | protocol not supported |
| `EOPNOTSUPP` | 102 | operation not supported |
| `EPROTOTYPE` | 41 | protocol wrong type for socket |
| `EMSGSIZE` | 40 | message too long |
| `EDESTADDRREQ` | 39 | destination address required |
| `EALREADY` | 37 | operation already in progress |
| `EINPROGRESS` | 36 | operation now in progress |

## 9. Socket Dispatch Pattern

All socket syscalls use a dual-dispatch pattern to handle AF_INET vs AF_UNIX:

```rust
fn with_socket<R>(
    &self,
    sockfd: u32,
    inet_op: impl FnOnce(&SocketFd<Platform>) -> Result<R, Errno>,
    unix_op: impl FnOnce(Arc<UnixSocket<FS>>) -> Result<R, Errno>,
) -> Result<R, Errno> {
    // Try Network subsystem first (AF_INET)
    if let Ok(fd) = rds.fd_from_raw_integer::<Network<Platform>>(sockfd as usize) {
        return inet_op(/* ... */);
    }
    // Try Unix socket table
    if let Some(unix_sock) = self.unix_sockets.read().get(&(sockfd as usize)) {
        return unix_op(unix_sock.clone());
    }
    Err(Errno::ENOTSOCK)
}
```

### sys_socket dispatch

```rust
fn sys_socket(&self, domain: u32, sock_type: u32, _protocol: u32) -> Result<usize, Errno> {
    let ty = SockType::try_from(sock_type & 0xFF)?;  // mask off SOCK_NONBLOCK/CLOEXEC flags
    match domain {
        1 => self.do_socket_unix(ty),      // AF_UNIX
        2 => self.do_socket_inet(ty),      // AF_INET
        _ => Err(Errno::EAFNOSUPPORT),
    }
}
```

**SOCK_NONBLOCK / SOCK_CLOEXEC:** macOS does not define these flags. Guest programs compiled against macOS headers will not use them. If encountered (from a non-native guest), we can mask them off and apply via fcntl semantics, but this should not arise in practice.

## 10. Tests

Four focused test programs, each verifying behavior through exit code:

### test_tcp_echo (`tcp_echo.c`)

Single-process TCP echo test using threads:
1. Server thread: `socket()` → `bind(127.0.0.1:0)` → `listen()` → `accept()` → `recv()` → `send()` → `close()`
2. Client thread: `socket()` → `connect()` → `send("hello tcp")` → `recv()` → verify echoed data → `close()`
3. Use `getsockname()` after bind to discover assigned port (port 0 = auto-assign)
4. Exit 0 on success, nonzero on failure at each step

### test_udp_sendrecv (`udp_sendrecv.c`)

Single-process UDP test:
1. Create two UDP sockets (sender and receiver)
2. Receiver: `bind(127.0.0.1:0)` → `getsockname()` to get assigned port
3. Sender: `sendto(receiver_addr, "hello udp")`
4. Receiver: `recvfrom()` → verify data and source address
5. Exit 0 on success

### test_unix_stream (`unix_stream.c`)

AF_UNIX stream test using threads:
1. Server thread: `socket(AF_UNIX)` → `bind("/tmp/test.sock")` → `listen()` → `accept()` → `recv()` → `send()` → `close()`
2. Client thread: `socket(AF_UNIX)` → `connect("/tmp/test.sock")` → `send("hello unix")` → `recv()` → verify → `close()`
3. Clean up: `unlink("/tmp/test.sock")`
4. Exit 0 on success

### test_socketpair (`socketpair.c`)

socketpair IPC test:
1. `socketpair(AF_UNIX, SOCK_STREAM, 0, sv)`
2. Write "hello pair" to `sv[0]`
3. Read from `sv[1]`, verify data matches
4. Write "reply" to `sv[1]`
5. Read from `sv[0]`, verify reply
6. Close both ends
7. Exit 0 on success

## 11. Files Modified

| File | Changes |
|------|---------|
| `litebox_common_macos/src/syscall.rs` | Add 15 new `nr::*` constants, 15 new `MacosSyscallRequest` variants, decoding match arms |
| `litebox_common_macos/src/errno.rs` | Add ~20 new socket-related errno constants |
| `litebox_shim_macos/src/lib.rs` | Add `StrongFd::Network` variant; remove `#[expect(dead_code)]` from `net` field; add `unix_addr_table` and `unix_sockets` to `GlobalState` |
| `litebox_shim_macos/src/syscalls/mod.rs` | Add dispatch arms for all 15 socket syscalls |
| `litebox_shim_macos/src/syscalls/file.rs` | Add `StrongFd::Network` arm to `sys_read`/`sys_write`/`sys_close`; handle Unix socket close |
| `litebox_shim_macos/src/syscalls/net.rs` | **New file.** AF_INET socket handlers: sys_socket, sys_bind, sys_listen, sys_accept, sys_connect, sys_sendto, sys_recvfrom, sys_sendmsg, sys_recvmsg, sys_setsockopt, sys_getsockopt, sys_getsockname, sys_getpeername, sys_shutdown, sys_socketpair. Socket address parsing. Socket option name mapping. SocketOptions struct. `with_socket` dispatch helper. |
| `litebox_shim_macos/src/syscalls/unix.rs` | **New file.** AF_UNIX socket handlers: UnixSocket, UnixStream, UnixDatagram, UnixConnectedStream, Backlog, UnixAddrTable, Channel (or reuse from litebox crate if available). Stream state machine. Datagram send/recv. socketpair connected-pair creation. |

## 12. Files Created

| File | Purpose |
|------|---------|
| `litebox_shim_macos/src/syscalls/net.rs` | AF_INET socket + socket option + dispatch logic |
| `litebox_shim_macos/src/syscalls/unix.rs` | AF_UNIX socket implementation |
| `litebox_runner_macos_on_macos_userland/tests/tcp_echo.c` | TCP echo test |
| `litebox_runner_macos_on_macos_userland/tests/udp_sendrecv.c` | UDP send/recv test |
| `litebox_runner_macos_on_macos_userland/tests/unix_stream.c` | AF_UNIX stream test |
| `litebox_runner_macos_on_macos_userland/tests/socketpair.c` | socketpair IPC test |

## 13. Implementation Order

Recommended task ordering for the implementation plan:

1. **Errno constants** — add all socket-related errnos to `errno.rs`
2. **Syscall numbers + request variants** — add 15 syscalls to `syscall.rs`
3. **Socket address structs** — `CSockInetAddr`, `CSockUnixAddr`, `SocketAddress`, read/write helpers
4. **SocketOptions + SocketOptionName** — option struct and macOS constant mapping
5. **StrongFd::Network** — add variant, update `from_raw`, wire into read/write/close
6. **AF_INET socket creation** — `sys_socket(AF_INET)`, `NetworkProxy` init
7. **AF_INET bind/listen/accept** — server path
8. **AF_INET connect/send/recv** — client path + sendto/recvfrom
9. **AF_INET setsockopt/getsockopt** — option handling
10. **AF_INET getsockname/getpeername/shutdown** — remaining inet syscalls
11. **TCP echo test** — validate AF_INET TCP path end-to-end
12. **UDP sendrecv test** — validate AF_INET UDP path
13. **UnixSocket + Channel** — core AF_UNIX types and ring buffer
14. **AF_UNIX stream** — connect/accept/send/recv with backlog
15. **AF_UNIX datagram** — bind/sendto/recvfrom
16. **AF_UNIX address table** — path-based address resolution
17. **Unix stream test** — validate AF_UNIX stream path
18. **socketpair** — connected pair creation
19. **socketpair test** — validate socketpair
20. **sendmsg/recvmsg** — structured message I/O for both inet and unix
21. **Dispatch wiring + close** — ensure all 15 syscalls dispatched, Unix socket close
22. **Clippy + fmt cleanup** — final pass

## 14. Test Commands

```bash
# Run all macOS tests
cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture

# Run specific socket tests
cargo test -p litebox_runner_macos_on_macos_userland test_tcp_echo -- --nocapture
cargo test -p litebox_runner_macos_on_macos_userland test_udp_sendrecv -- --nocapture
cargo test -p litebox_runner_macos_on_macos_userland test_unix_stream -- --nocapture
cargo test -p litebox_runner_macos_on_macos_userland test_socketpair -- --nocapture

# Clippy and fmt
cargo clippy -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland -- -D warnings
cargo fmt --check -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland
```

## 15. Risks and Open Questions

1. **Channel module**: The Linux shim has a `channel.rs` with ring buffer (`ringbuf::HeapRb`) in `litebox_shim_linux` — not directly shareable. The macOS shim will implement its own `Channel` type in `unix.rs` following the same ring buffer pattern. If the `ringbuf` crate is already a dependency of the workspace, reuse it; otherwise use `VecDeque` as the backing store (simpler, adequate for in-process IPC).

2. **WaitContext for blocking sockets**: Blocking `accept()`, `connect()`, `recv()` require `WaitContext` for event-driven wakeup. Phase A added `WaitState` — verify it integrates with the `Pollee`/`Poller` mechanism used by both `Network` and `UnixSocket`.

3. **Port auto-assignment**: `bind(port=0)` relies on `LocalPortAllocator` in the `litebox` crate. Verify it works correctly for the macOS shim's `Network` instance.

4. **msghdr layout verification**: The macOS `msghdr` struct layout should be verified against actual macOS headers during implementation. Field sizes and padding may differ from what's documented here.

5. **SO_LINGER vs SO_LINGER_SEC**: macOS has two linger options (0x0080 and 0x1080). Most programs use `SO_LINGER_SEC` when compiled with POSIX settings. We handle both.
