# Fork Listening TCP Socket Support - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable nginx's master/worker fork pattern by snapshotting and restoring listening TCP sockets across the fork boundary.

**Architecture:** The fork snapshot currently rejects `FdClass::NetworkSocket` at the reject gate in `snapshot_fd_table()`. We need to: (1) add a public API on `Network` to query listening socket state, (2) capture that state in the snapshot data model, (3) accept listening sockets through the reject gate, (4) restore them in the child worker process. The scope is **listening TCP sockets only** — the nginx pattern where master binds+listens, forks workers that inherit the fd and call `accept()`.

**Tech Stack:** Rust, litebox (sandbox runtime), smoltcp (userspace TCP/IP), litebox_shim_linux (syscall interception layer)

---

## Task 1: Add `get_listening_socket_info()` to `Network`

The `TcpServerSpecific` struct (and its fields `ip_listen_endpoint` and `backlog`) are private to the `litebox` crate. The snapshot code in `litebox_shim_linux` cannot access them. We need a new public method on `Network` that returns the listening state for a socket fd.

**Files:**
- Modify: `litebox/src/net/mod.rs`

### Step 1: Define the return type and add the method

Add a new public struct and method to `litebox/src/net/mod.rs`. Place the struct near the other public types (after `Protocol` enum around line 59), and the method on the `impl Network` block.

```rust
// Add near line 59 (after Protocol enum):

/// Information about a listening TCP socket, used for fork snapshot/restore.
#[derive(Debug, Clone)]
pub struct ListeningSocketInfo {
    /// The IPv4 address the socket is bound to, or `None` for INADDR_ANY.
    pub bind_addr: Option<core::net::Ipv4Addr>,
    /// The port the socket is listening on.
    pub port: u16,
    /// The listen backlog.
    pub backlog: u16,
}
```

```rust
// Add as a method on `impl Network<Platform>`, after `get_remote_addr` (after line ~1175):

/// Returns the listening socket info for a TCP server socket, or `None`
/// if the socket is not a listening TCP socket.  Used by the fork
/// snapshot path to capture enough state to reconstruct the socket in
/// the child.
pub fn get_listening_socket_info(
    &self,
    fd: &SocketFd<Platform>,
) -> Option<ListeningSocketInfo> {
    let descriptor_table = self.litebox.descriptor_table();
    let table_entry = descriptor_table.get_entry_mut(fd)?;
    let socket_handle = &table_entry.entry;
    match &socket_handle.specific {
        ProtocolSpecific::Tcp(tcp) => {
            let server = tcp.server_socket.as_ref()?;
            let backlog = server.backlog?;
            let bind_addr = server
                .ip_listen_endpoint
                .addr
                .map(|a| match a {
                    smoltcp::wire::IpAddress::Ipv4(v4) => core::net::Ipv4Addr::from(v4.0),
                });
            Some(ListeningSocketInfo {
                bind_addr,
                port: server.ip_listen_endpoint.port,
                backlog,
            })
        }
        _ => None,
    }
}
```

### Step 2: Verify it compiles

Run: `cargo build --package litebox -j$(nproc)`
Expected: Compiles with no errors (maybe some warnings about dead code, that's fine).

### Step 3: Commit

```bash
git add litebox/src/net/mod.rs
git commit -m "feat(net): add get_listening_socket_info() for fork snapshot support"
```

---

## Task 2: Add `ListeningSocketSnapshot` to the fork snapshot data model

We need to capture the listening socket state per-fd in the snapshot, serialize it, and deserialize it.

**Files:**
- Modify: `litebox_shim_linux/src/syscalls/fork_snapshot.rs`

### Step 1: Add the snapshot struct

Add `ListeningSocketSnapshot` after `FdMetadataSnapshot` (around line 238):

```rust
/// Snapshot of a listening TCP socket's state for fork restore.
///
/// Captures the bind address, port, and backlog so the child process
/// can reconstruct an equivalent listening socket via socket+bind+listen.
#[derive(Debug, Clone)]
pub struct ListeningSocketSnapshot {
    /// IPv4 bind address octets.  `[0,0,0,0]` means INADDR_ANY.
    pub bind_addr: [u8; 4],
    /// TCP port the socket is listening on.
    pub port: u16,
    /// Listen backlog.
    pub backlog: u16,
}
```

### Step 2: Add the field to `FdEntrySnapshot`

Add an optional `listening_socket` field to `FdEntrySnapshot` (line ~196):

```rust
pub struct FdEntrySnapshot {
    // ... existing fields ...
    /// For listening TCP sockets: the socket state needed for restore.
    pub listening_socket: Option<ListeningSocketSnapshot>,
}
```

### Step 3: Update `FdEntrySnapshot::write` serialization

In the `write` method (line ~946), add after `self.metadata.write(w);`:

```rust
match &self.listening_socket {
    Some(ls) => {
        w.write_bool(true);
        w.write_bytes_fixed(&ls.bind_addr);
        w.write_u16(ls.port);
        w.write_u16(ls.backlog);
    }
    None => {
        w.write_bool(false);
    }
}
```

Note: `SnapshotWriter` may not have `write_bytes_fixed` or `write_u16`. Check available methods. If not, use `w.write_u32(u32::from_be_bytes(ls.bind_addr))` for the address and `w.write_u32(ls.port as u32)` / `w.write_u32(ls.backlog as u32)` for the 16-bit values. Adapt based on the available writer API.

### Step 4: Update `FdEntrySnapshot::read` deserialization

In the `read` method (line ~955), add after `metadata: FdMetadataSnapshot::read(r)?,`:

```rust
listening_socket: if r.read_bool()? {
    let addr_u32 = r.read_u32()?;
    Some(ListeningSocketSnapshot {
        bind_addr: addr_u32.to_be_bytes(),
        port: r.read_u32()? as u16,
        backlog: r.read_u32()? as u16,
    })
} else {
    None
},
```

### Step 5: Verify it compiles

Run: `cargo build --package litebox_shim_linux -j$(nproc)`
Expected: Compiles (may need to add `listening_socket: None` to any existing construction site of `FdEntrySnapshot`).

### Step 6: Commit

```bash
git add litebox_shim_linux/src/syscalls/fork_snapshot.rs
git commit -m "feat(fork): add ListeningSocketSnapshot to fork data model"
```

---

## Task 3: Accept listening sockets in the reject gate & capture state

Modify `snapshot_fd_table()` to (a) accept `NetworkSocket` fds that are listening, and (b) capture their listening state in the snapshot.

**Files:**
- Modify: `litebox_shim_linux/src/syscalls/process.rs` (function `snapshot_fd_table`, lines ~6160-6374)

### Step 1: Capture listening socket info during classification

At lines 6229-6232, where `NetworkSocket` is classified, also query the listening state:

```rust
} else if let Ok(fd) =
    rds.fd_from_raw_integer::<litebox::net::Network<crate::Platform>>(raw_fd)
{
    // Probe listening state for fork snapshot.
    let listen_info = self.global.net.lock().get_listening_socket_info(&fd);
    (FdClass::NetworkSocket, Some(fd.object_id()), None, None, listen_info)
}
```

This requires changing the tuple type to include a 5th element. **Alternatively**, capture the listening info separately after classification, to minimize tuple changes. The cleaner approach: add a separate `let listening_info = ...;` variable after the classification block (after line 6263), conditioned on `class == FdClass::NetworkSocket`.

**Cleaner approach** — after line 6263 (after the classification block), add:

```rust
// For NetworkSocket fds, probe listening state for fork snapshot.
let listening_socket = if subsystem_class == FdClass::NetworkSocket {
    if let Ok(fd) =
        rds.fd_from_raw_integer::<litebox::net::Network<crate::Platform>>(raw_fd)
    {
        let info = self.global.net.lock().get_listening_socket_info(&fd);
        info.map(|i| super::fork_snapshot::ListeningSocketSnapshot {
            bind_addr: i.bind_addr.map_or([0, 0, 0, 0], |a| a.octets()),
            port: i.port,
            backlog: i.backlog,
        })
    } else {
        None
    }
} else {
    None
};
```

### Step 2: Accept listening NetworkSocket in the reject gate

At lines 6282-6298, add a new match arm for listening NetworkSocket:

```rust
match class {
    FdClass::StdioFd | FdClass::Pipe => {}
    FdClass::NetworkSocket if listening_socket.is_some() => {
        // Listening TCP socket — accepted for fork snapshot.
    }
    // ... rest of existing arms ...
}
```

### Step 3: Include `listening_socket` in the `FdEntrySnapshot`

At line 6339, where `FdEntrySnapshot` is constructed, add the field:

```rust
entries.push(FdEntrySnapshot {
    fd: raw_fd,
    class,
    fd_flags: 0,
    status_flags: fs_status_flags,
    object_id: object_id.map_or(0, litebox::fd::DescriptorObjectId::as_u64),
    metadata: terminal_meta.unwrap_or_default(),
    listening_socket,  // NEW
});
```

### Step 4: Verify it compiles

Run: `cargo build --package litebox_shim_linux -j$(nproc)`
Expected: Compiles without errors.

### Step 5: Commit

```bash
git add litebox_shim_linux/src/syscalls/process.rs
git commit -m "feat(fork): accept listening TCP sockets in snapshot and capture state"
```

---

## Task 4: Restore listening sockets in the child process

Add a restore code path in `restore_process()` that reconstructs listening TCP sockets from the snapshot.

**Files:**
- Modify: `litebox_shim_linux/src/lib.rs` (function `restore_process`, around lines 948-1071)

### Step 1: Add restore block for NetworkSocket entries

After the existing FilesystemFd restore blocks (after line 1071, before `// --- 11. Build credentials.`), add a new block:

```rust
// Restore listening TCP sockets from fork snapshot.
{
    use syscalls::fork_snapshot::FdClass;

    for entry in &fd_table.entries {
        if entry.class != FdClass::NetworkSocket {
            continue;
        }
        let Some(ref ls) = entry.listening_socket else {
            // Non-listening network socket — currently unsupported for restore.
            // This should have been rejected at the snapshot gate.
            continue;
        };

        // Reconstruct the listening socket: socket() + bind() + listen().
        let bind_ip = core::net::Ipv4Addr::from(ls.bind_addr);
        let bind_addr = core::net::SocketAddr::V4(
            core::net::SocketAddrV4::new(bind_ip, ls.port),
        );

        // Create a new TCP socket.
        let socket_fd = {
            let mut net = self.global.net.lock();
            let fd = net
                .socket(litebox::net::Protocol::Tcp)
                .expect("failed to create TCP socket for fork restore");
            // Bind to the captured address.
            net.bind(&fd, bind_addr)
                .expect("failed to bind TCP socket for fork restore");
            // Start listening with the captured backlog.
            net.listen(&fd, ls.backlog)
                .expect("failed to listen on TCP socket for fork restore");
            fd
        };

        // Initialize the socket in the shim layer (sets up proxy, metadata).
        use syscalls::net::{SockFlags, SockType};
        let _ = self.global.initialize_socket(
            &socket_fd,
            SockType::Stream,
            SockFlags::empty(),
        );

        // Place it at the correct fd slot.
        let mut rds = child_files.raw_descriptor_store.write();
        let success = rds.fd_into_specific_raw_integer(socket_fd, entry.fd);
        debug_assert!(
            success,
            "fd slot {} occupied during network socket restore",
            entry.fd
        );
        drop(rds);
    }
}
```

### Step 2: Verify it compiles

Run: `cargo build --package litebox_shim_linux -j$(nproc)`
Expected: Compiles without errors. There may be import issues (e.g. `SockFlags`, `SockType` visibility) — resolve as needed.

### Step 3: Commit

```bash
git add litebox_shim_linux/src/lib.rs
git commit -m "feat(fork): restore listening TCP sockets in child process"
```

---

## Task 5: Update nginx config for multi-process mode and test

Change the nginx config to use `master_process on` and test that nginx workers can accept connections.

**Files:**
- Modify: `litebox_runner_linux_userland/tests/net/nginx.conf`
- Modify: `litebox_runner_linux_userland/tests/run.rs` (test function)

### Step 1: Create a fork-enabled nginx config

Create a new config file or modify the existing one. The key changes:
- Remove `master_process off;`
- Set `worker_processes 2;` (or leave as 1 initially for simpler testing)

```nginx
# nginx configuration for litebox fork integration test.
master_process on;
daemon off;
worker_processes 2;
pid /tmp/nginx.pid;
error_log stderr info;

events {
    worker_connections 64;
}

http {
    access_log off;
    client_body_temp_path /tmp/nginx_client_body;
    proxy_temp_path /tmp/nginx_proxy;
    fastcgi_temp_path /tmp/nginx_fastcgi;
    uwsgi_temp_path /tmp/nginx_uwsgi;
    scgi_temp_path /tmp/nginx_scgi;

    server {
        listen 10.0.0.2:8080;

        location / {
            return 200 'hello from litebox nginx\n';
            default_type text/plain;
        }
    }
}
```

### Step 2: Run the test

Run:
```bash
cargo test --package litebox_runner_linux_userland --test run --release -- test_nginx_with_wrk --exact --nocapture
```
Expected: nginx starts, forks worker processes that inherit the listening socket, wrk can make requests successfully.

### Step 3: If the test passes, commit

```bash
git add litebox_runner_linux_userland/tests/net/nginx.conf
git commit -m "feat(nginx): enable master_process on for fork+socket test"
```

---

## Task 6: Run benchmarks and compare

Run wrk benchmarks comparing single-process vs multi-process nginx under litebox.

### Step 1: Run multi-process benchmark

```bash
cargo test --package litebox_runner_linux_userland --test run --release -- test_nginx_with_wrk --exact --nocapture
```

### Step 2: Document results

Compare against the earlier single-process numbers:
- 2t/10c/5s: 41,817 req/s (single-process)
- 4t/50c/10s: 27,321 req/s (single-process)

---

## Potential Issues and Mitigations

1. **Lock ordering in snapshot**: Acquiring `self.global.net.lock()` while holding the descriptor table lock. Check that existing code (e.g., `getsockname`) uses the same ordering. If not, drop the dt/rds locks temporarily, acquire net lock, then re-acquire dt/rds. Alternative: capture network info in a separate pass over the fd list.

2. **Port allocation conflict**: In the child, calling `bind()` may fail if the port allocator thinks the port is already in use (since it's a global singleton). The child worker has a fresh `Network` instance (created during runner init), so the port allocator should be empty. Verify this is the case.

3. **Socket proxy initialization**: The restore path calls `initialize_socket()` which sets up the proxy. Ensure the proxy is correctly wired so that the worker's event loop can dispatch `accept()` events to the restored socket.

4. **`getsockname` on restored listening socket**: Verify that after restore, `getsockname` returns the correct address (not 0.0.0.0:0). The fix may require using `get_local_addr` on the backlog sockets rather than the main handle, or fixing `get_local_addr` to check the server_socket's endpoint.

5. **epoll on listening socket**: nginx uses epoll to wait for accept events. If the child also needs epoll support for the listening fd, that's a separate (likely larger) piece of work. Check if nginx workers use epoll or blocking accept.
