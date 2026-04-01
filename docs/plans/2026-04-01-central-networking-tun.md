# Central Networking: TUN Device + Socket I/O Routing — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable networking in the micro/central architecture by implementing a TUN device for `CentralPlatform` and routing socket I/O syscalls through central's shim (smoltcp virtual network stack) instead of broken local execution.

**Architecture:** `CentralPlatform` gains a TUN fd field and implements `IPInterfaceProvider` (read/write raw IP packets). A network worker thread in central drives smoltcp ↔ TUN packet flow. Socket I/O syscalls (`sendto`/`recvfrom`/`sendmsg`/`recvmsg`) are removed from `needs_local_exec()` and routed through the shim with shmem-based buffer marshaling (same pattern as file read/write). The shim's existing smoltcp stack handles the virtual networking — no new networking code needed.

**Tech Stack:** Rust, `libc` for TUN ioctl, smoltcp 0.12.0 (existing), shmem data region for buffer transfer.

**Current state of networking:** Socket management syscalls (`socket`/`bind`/`listen`/`accept`/`connect`/`setsockopt`/`getsockopt`) already route through central's shim. Socket I/O (`sendto`/`recvfrom`/`sendmsg`/`recvmsg`) is marked `needs_local_exec()` but micro has no match arms for them → returns `-ENOSYS`. The smoltcp stack exists and works but `perform_network_interaction()` is never called in central, and `CentralPlatform::IPInterfaceProvider` is `unimplemented!()`.

---

## Task 1: Add TUN fd to `CentralPlatform` and implement `IPInterfaceProvider`

**Files:**
- Modify: `litebox_platform_central/src/lib.rs` (lines 23-54)
- Modify: `litebox_platform_central/Cargo.toml`

**Step 1: Add `std::os::fd` imports and make `CentralPlatform` hold a TUN fd**

Change the struct from a unit struct to:

```rust
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::RwLock;

/// The central server platform.
///
/// Implements [`litebox::platform::Provider`] for use in a server (host-side)
/// process that communicates with a guest over IPC.
///
/// If a TUN device name is provided at construction time, networking is
/// enabled via the kernel TUN interface. Otherwise, networking panics.
#[derive(Debug)]
pub struct CentralPlatform {
    tun_fd: RwLock<Option<OwnedFd>>,
}
```

Add a constructor:

```rust
impl CentralPlatform {
    /// Create a new central platform.
    ///
    /// If `tun_device_name` is `Some("tunN")`, opens `/dev/net/tun` with
    /// `IFF_TUN | IFF_NO_PI` and stores the fd for `IPInterfaceProvider`.
    /// If `None`, networking calls will panic.
    pub fn new(tun_device_name: Option<&str>) -> Self {
        let tun_fd = tun_device_name.map(|name| {
            // Open /dev/net/tun
            let fd = unsafe {
                libc::open(
                    c"/dev/net/tun".as_ptr(),
                    libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            assert!(fd >= 0, "failed to open /dev/net/tun: {}", std::io::Error::last_os_error());

            // TUNSETIFF ioctl
            const IFF_TUN: libc::c_short = 0x0001;
            const IFF_NO_PI: libc::c_short = 0x1000;

            #[repr(C)]
            struct Ifreq {
                ifr_name: [libc::c_char; libc::IFNAMSIZ],
                ifr_flags: libc::c_short,
                _pad: [u8; 22],
            }

            let mut ifreq = Ifreq {
                ifr_name: [0; libc::IFNAMSIZ],
                ifr_flags: IFF_TUN | IFF_NO_PI,
                _pad: [0; 22],
            };
            assert!(name.len() < libc::IFNAMSIZ, "TUN device name too long");
            for (i, b) in name.bytes().enumerate() {
                ifreq.ifr_name[i] = b as libc::c_char;
            }

            // TUNSETIFF = _IOW('T', 202, int) = 0x400454CA
            let ret = unsafe { libc::ioctl(fd, 0x400454CA, &raw const ifreq) };
            assert!(ret >= 0, "TUNSETIFF failed: {}", std::io::Error::last_os_error());

            unsafe { OwnedFd::from_raw_fd(fd) }
        });

        Self {
            tun_fd: RwLock::new(tun_fd),
        }
    }
}
```

**Step 2: Implement `IPInterfaceProvider`**

Replace the `unimplemented!()` stubs:

```rust
impl litebox::platform::IPInterfaceProvider for CentralPlatform {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        let guard = self.tun_fd.read().unwrap();
        let fd = guard.as_ref().expect("networking not enabled (no TUN device)");
        let ret = unsafe {
            libc::write(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len())
        };
        assert!(ret >= 0, "TUN write failed: {}", std::io::Error::last_os_error());
        Ok(())
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        let guard = self.tun_fd.read().unwrap();
        let fd = guard.as_ref().expect("networking not enabled (no TUN device)");
        let ret = unsafe {
            libc::read(fd.as_raw_fd(), packet.as_mut_ptr().cast(), packet.len())
        };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                return Err(litebox::platform::ReceiveError::WouldBlock);
            }
            panic!("TUN read failed: {}", std::io::Error::last_os_error());
        }
        Ok(ret as usize)
    }
}
```

**Step 3: Add a `wait_on_tun` method** (needed by network worker thread):

```rust
impl CentralPlatform {
    // ... (new() from above)

    /// Block until the TUN device has data available, or timeout expires.
    ///
    /// Used by the network worker thread to avoid spinning when no packets
    /// are arriving.
    pub fn wait_on_tun(&self, timeout: Option<core::time::Duration>) {
        let guard = self.tun_fd.read().unwrap();
        let Some(fd) = guard.as_ref() else { return };
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = timeout.map_or(-1, |t| {
            i32::try_from(t.as_millis()).unwrap_or(i32::MAX)
        });
        unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
    }
}
```

**Step 4: Update Cargo.toml** if needed — `libc` is already a dependency. No changes needed. But `std::os::fd::OwnedFd` requires `std` (already used).

**Step 5: Update `litebox_central/src/main.rs`** to pass a TUN device name:

Change line 55 from:
```rust
let platform: &'static Platform = Box::leak(Box::new(CentralPlatform));
```
to:
```rust
let platform: &'static Platform = Box::leak(Box::new(CentralPlatform::new(Some("tun0"))));
```

Note: The TUN device name should eventually come from CLI args. For now, hardcode `"tun0"`. We'll add `--tun-device` arg later.

**Step 6: Build and verify**

```bash
cargo build -p litebox_platform_central
cargo build -p litebox_central
cargo clippy -p litebox_central
```

Expected: builds clean, clippy clean.

**Step 7: Commit**

```bash
git add litebox_platform_central/src/lib.rs litebox_central/src/main.rs
git commit -m "central: implement IPInterfaceProvider with TUN device support"
```

---

## Task 2: Add network worker thread to central

**Files:**
- Modify: `litebox_central/src/main.rs` (add network worker spawn before server.run())

**Step 1: Spawn network worker thread**

After `let shim = std::sync::Arc::new(shim);` (line 116) and before the server creation, add:

```rust
// Spawn a network worker thread to drive smoltcp ↔ TUN packet flow.
// This mirrors the pattern in litebox_runner_linux_userland.
let net_shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
let net_worker = {
    let shim = shim.clone();
    let shutdown = net_shutdown.clone();
    std::thread::Builder::new()
        .name("net-worker".into())
        .spawn(move || {
            const DEFAULT_TIMEOUT: core::time::Duration =
                core::time::Duration::from_micros(100);
            const MAX_TIMEOUT: core::time::Duration =
                core::time::Duration::from_millis(1);

            while !shutdown.load(core::sync::atomic::Ordering::Relaxed) {
                let timeout = loop {
                    match shim.perform_network_interaction() {
                        litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {}
                        litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                            break timeout;
                        }
                    }
                };
                platform.wait_on_tun(
                    Some(timeout.unwrap_or(DEFAULT_TIMEOUT).min(MAX_TIMEOUT)),
                );
            }
            // Final flush
            while shim
                .perform_network_interaction()
                .call_again_immediately()
            {}
        })
        .expect("failed to spawn network worker thread")
};
```

After `server.run()`, add shutdown + join:

```rust
let result = server.run();
net_shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
let _ = net_worker.join();
result
```

Note: `platform` must be accessible from the closure. Since it's `&'static Platform`, it can be captured directly.

**Step 2: Build and verify**

```bash
cargo build -p litebox_central
cargo clippy -p litebox_central
```

**Step 3: Commit**

```bash
git add litebox_central/src/main.rs
git commit -m "central: spawn network worker thread for smoltcp ↔ TUN packet flow"
```

---

## Task 3: Route `recvfrom` through central's shim (data-producing)

**Files:**
- Modify: `litebox_central/src/server.rs` — remove `SYS_recvfrom` from `needs_local_exec()`, add to `is_data_producing_io()`, handle in `handle_data_producing_io()`
- Modify: `litebox_micro/src/local_exec.rs` — add `SYS_recvfrom` handler for the HAS_DATA path

The shim's `sys_recvfrom` signature (from `litebox_shim_linux/src/syscalls/net.rs:1435`):
```rust
pub(crate) fn sys_recvfrom(
    &self,
    fd: i32,        // args[0]
    buf: MutPtr<u8>, // args[1] — we rewrite to shmem
    len: usize,      // args[2]
    flags: ReceiveFlags, // args[3]
    addr: Option<MutPtr<u8>>, // args[4] — source addr output
    addrlen: MutPtr<u32>,     // args[5] — source addr length output
) -> Result<usize, Errno>
```

**Key challenge:** `recvfrom` writes both data AND a sockaddr. The shim's `sys_recvfrom` uses a 4096-byte stack buffer internally (line 1449), then copies to the MutPtr. We need both outputs in shmem.

**Approach:** Rewrite `buf` (args[1]) to shmem data region offset 0. Rewrite `addr` (args[4]) to shmem just after the data buffer. Rewrite `addrlen` (args[5]) to shmem after the sockaddr area. The shim writes results there, and we return all of it via HAS_DATA.

**Step 1: Remove `SYS_recvfrom` from `needs_local_exec()`**

In `server.rs` line 747, remove `libc::SYS_recvfrom` from the match.

**Step 2: Add `SYS_recvfrom` to `is_data_producing_io()`**

Add `| libc::SYS_recvfrom` to the match in `is_data_producing_io()`.

**Step 3: Add recvfrom handling in `handle_data_producing_io()`**

In the match block inside `handle_data_producing_io()`, add:

```rust
libc::SYS_recvfrom => {
    // recvfrom(fd, buf, len, flags, src_addr, addrlen)
    // Layout in shmem data region:
    //   [0..len): receive buffer
    //   [len..len+128): sockaddr output space
    //   [len+128..len+132): addrlen (u32)
    let len = entry.args[2] as usize;
    let capped = len.min(data_region.len() - 256);

    // Rewrite buf pointer to shmem
    regs.rsi = data_ptr;
    regs.rdx = capped;

    // If src_addr is requested (args[4] != 0), point to shmem after buffer
    let has_addr = entry.args[4] != 0;
    if has_addr {
        let addr_offset = capped;
        let addrlen_offset = capped + 128;
        regs.r8 = data_ptr + addr_offset;
        regs.r9 = data_ptr + addrlen_offset;
        // Initialize addrlen to 128 (max sockaddr size)
        let addrlen_ptr = &mut data_region[addrlen_offset..addrlen_offset + 4];
        addrlen_ptr.copy_from_slice(&128u32.to_ne_bytes());
    } else {
        regs.r8 = 0; // NULL src_addr
        regs.r9 = 0; // NULL addrlen
    }

    cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
    if cq.result >= 0 {
        // data_len encodes: received bytes + sockaddr area
        let result_len = if has_addr {
            capped + 128 + 4 // buffer area + sockaddr + addrlen
        } else {
            cq.result as u32
        };
        cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
        cq.data_offset = 0;
        cq.data_len = result_len as u32;
    }
}
```

Wait — this is getting complex. The shim's `sys_recvfrom` is called via PtRegs dispatch which decodes args differently. Let me re-examine how the shim dispatch works in central.

**Important architectural note:** The shim's `dispatch_syscall` (in `litebox_shim_linux/src/lib.rs`) decodes PtRegs into typed arguments. For `SYS_recvfrom`, it decodes `args[1]` as `MutPtr<u8>` (which in central is `GuestMutPtr<u8>` — a raw address). So if we point `regs.rsi` at the shmem data region address, the `GuestMutPtr` will have that address and its `copy_from_slice`/`mutate_subslice_with` will write directly to shmem. This should work because `GuestMutPtr` just does raw pointer writes (see `litebox_platform_central/src/lib.rs:324`).

Similarly for `addr` (args[4], `MutPtr<u8>`) and `addrlen` (args[5], `MutPtr<u32>`).

So the approach is correct: rewrite the pointer args in PtRegs to point at shmem, dispatch through the shim, shim writes to shmem, return HAS_DATA to micro.

**Step 4: Add `SYS_recvfrom` handler in micro's `local_exec.rs`**

```rust
nr if nr == libc::SYS_recvfrom as u32 => {
    if cq.flags & cq_flags::HAS_DATA != 0 {
        // Central routed recvfrom through the shim's smoltcp stack.
        // Data region layout:
        //   [0..N): received data (N = cq.result)
        //   If guest requested src_addr:
        //     [capped..capped+128): sockaddr
        //     [capped+128..capped+132): addrlen (u32)
        let guest_buf = args[1] as *mut u8;
        let recv_len = cq.result as usize;

        // Copy received data to guest buffer
        if !ring_base.is_null() && recv_len > 0 {
            let data_src = ring_base
                .add(layout.data_region_offset)
                .add(cq.data_offset as usize);
            core::ptr::copy_nonoverlapping(data_src, guest_buf, recv_len);
        }

        // Copy sockaddr if requested
        let guest_addr = args[4] as *mut u8;
        let guest_addrlen = args[5] as *mut u32;
        if guest_addr != core::ptr::null_mut() && !ring_base.is_null() {
            let capped = args[2] as usize; // original len arg
            let capped = capped.min((cq.data_len as usize).saturating_sub(132));
            let addr_src = ring_base
                .add(layout.data_region_offset)
                .add(capped);
            let addrlen_src = ring_base
                .add(layout.data_region_offset)
                .add(capped + 128);
            let addrlen = u32::from_ne_bytes(
                core::slice::from_raw_parts(addrlen_src, 4)
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            if addrlen > 0 && addrlen <= 128 {
                core::ptr::copy_nonoverlapping(addr_src, guest_addr, addrlen as usize);
            }
            if !guest_addrlen.is_null() {
                guest_addrlen.write(addrlen);
            }
        }

        cq.result
    } else {
        cq.result // error or zero-length
    }
}
```

**Step 5: Build and test**

```bash
cargo build --release -p litebox_micro -p litebox_launcher
cargo build --release -p litebox_central
cargo clippy -p litebox -p litebox_shim_linux -p litebox_micro -p litebox_launcher
cargo clippy -p litebox_central
```

**Step 6: Commit**

```bash
git add litebox_central/src/server.rs litebox_micro/src/local_exec.rs
git commit -m "central: route recvfrom through shim's smoltcp stack via shmem"
```

---

## Task 4: Route `sendto` through central's shim (data-consuming + addr)

**Files:**
- Modify: `litebox_central/src/server.rs` — remove `SYS_sendto` from `needs_local_exec()`, handle in `handle_data_consuming_io()` or add a new handler
- Modify: `litebox_micro/src/handler.rs` — ensure micro copies sendto buffer + sockaddr to shmem

**Step 1: Remove `SYS_sendto` from `needs_local_exec()`**

**Step 2: Add sendto data marshaling in micro's `handler.rs`**

The existing `copy_write_data_to_data_region` handles `write`/`pwrite64`. We need it to also handle `sendto`. Add `SYS_sendto` to `write_data_arg_info()`:

```rust
fn write_data_arg_info(syscall_nr: u32) -> Option<(usize, usize)> {
    match i64::from(syscall_nr) {
        libc::SYS_write | libc::SYS_pwrite64 => Some((1, 2)),
        libc::SYS_sendto => Some((1, 2)), // sendto(fd, buf, len, flags, addr, addrlen)
        _ => None,
    }
}
```

For the sockaddr (args[4]), copy it to the pathname zone (reusing that per-thread 4096-byte slot). Add `SYS_sendto` to `pathname_arg_index()`:

Actually, the sockaddr isn't a pathname — it's a fixed-size struct. But the pathname zone has 4096 bytes per thread, which is more than enough for a sockaddr (max 128 bytes). We can repurpose `copy_pathname_to_data_region` or add a new function.

Better approach: copy the sockaddr to the pathname slot. Add to `pathname_arg_index`:
- But `pathname_arg_index` reads a NUL-terminated C string, and sockaddr isn't NUL-terminated.

So we need a **new copy function** for sockaddr:

```rust
/// Copy sockaddr from guest memory to the shmem pathname zone for sendto/connect.
///
/// Layout in pathname zone: [sockaddr bytes: addrlen]
/// Sets entry.data_offset/data_len to encode the sockaddr location.
fn copy_sockaddr_to_data_region(
    entry: &mut SqEntry,
    args: &SyscallArgs,
    syscall_nr: u32,
    ring_base: *mut u8,
    layout: &SharedRingLayout,
) {
    let (addr_idx, addrlen_idx) = match i64::from(syscall_nr) {
        libc::SYS_sendto => (4, 5),
        _ => return,
    };

    let addr = args.args[addr_idx] as *const u8;
    let addrlen = args.args[addrlen_idx] as usize;

    if addr.is_null() || addrlen == 0 {
        return;
    }

    // Use per-thread pathname slot for sockaddr (4096 bytes available)
    let thread_offset = entry.thread_slot as usize * PATHNAME_REGION_SIZE;
    let copy_len = addrlen.min(PATHNAME_REGION_SIZE);

    unsafe {
        let dst = ring_base
            .add(layout.data_region_offset)
            .add(thread_offset);
        core::ptr::copy_nonoverlapping(addr, dst, copy_len);
    }

    // Encode sockaddr info in a way central can decode.
    // We'll use the upper 16 bits of data_len for sockaddr length.
    // Or better: store sockaddr info separately.
    // Actually, since data_offset/data_len are already used for the write buffer,
    // we need another mechanism. Let's use the args themselves:
    // Rewrite args[4] to encode the shmem offset instead of the guest pointer.
    // Central knows to read from shmem at that offset.
}
```

Hmm, this is getting complex. Simpler approach: **pack the sockaddr into the write-data zone alongside the send buffer**.

Layout in write-data zone for sendto:
```
[send_data: len bytes][sockaddr: addrlen bytes]
```

Set `entry.data_len = len + addrlen`. Central knows `len` from args[2] and `addrlen` from args[5], so it can split them.

**Step 3: Handle sendto in central's server.rs**

Add sendto to `is_data_consuming_io()` and handle in `handle_data_consuming_io()`:

```rust
libc::SYS_sendto => {
    // sendto(fd, buf, len, flags, addr, addrlen)
    let send_len = entry.args[2] as usize;
    let addrlen = entry.args[5] as usize;

    // Data region layout: [send_data: send_len][sockaddr: addrlen]
    // Rewrite buf pointer
    regs.rsi = buf_ptr; // points to send data
    regs.rdx = send_len.min(len);

    // Rewrite addr pointer if present
    if entry.args[4] != 0 && addrlen > 0 {
        let addr_ptr = buf_ptr + send_len.min(len);
        regs.r8 = addr_ptr;
        regs.r9 = addrlen;
    }

    cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
}
```

**Step 4: Build, clippy, test**

**Step 5: Commit**

```bash
git commit -m "central: route sendto through shim's smoltcp stack via shmem"
```

---

## Task 5: Route `sendmsg` and `recvmsg` through central's shim

**Files:**
- Modify: `litebox_central/src/server.rs`
- Modify: `litebox_micro/src/handler.rs`
- Modify: `litebox_micro/src/local_exec.rs`

These are the most complex socket I/O syscalls due to `msghdr` containing iovec arrays, control messages, and sockaddr. The approach:

**For `sendmsg(fd, msghdr*, flags)`:**
- Micro reads the `msghdr` struct from guest memory
- Gathers all iovec data into a flat buffer in the write-data zone
- Copies sockaddr (if any) after the data
- Packs a simplified header at the start: `[msg_namelen: u32][data_len: u32][name: msg_namelen][data: data_len]`
- Central unpacks and dispatches through the shim

**For `recvmsg(fd, msghdr*, flags)`:**
- Central dispatches through shim, receives data + sockaddr
- Packs results into shmem data region
- Micro copies back to guest's msghdr, iovecs, and sockaddr

Implementation detail: The shim has `sys_sendmsg` and `sys_recvmsg` which use `MsgHdrConst`/`MsgHdrMut` types to read/write msghdr. These types use `ConstPtr`/`MutPtr` for the iovec and sockaddr pointers. In central, these become `GuestConstPtr`/`GuestMutPtr` which do raw pointer reads/writes.

**Approach:** Create a marshaled representation in shmem:
- Micro builds a flat buffer: `[4-byte name_len][4-byte total_data_len][name bytes][data bytes]`
- Rewrites args[1] (msghdr pointer) to point at a synthetic msghdr in shmem that has rewritten iovec/sockaddr pointers

This is complex enough that it may be better to implement as a **custom dispatch path** in central (not through the generic shim PtRegs dispatch) that directly calls `do_sendto`/`do_recvfrom` with the deserialized data.

**Note:** This task is optional for initial nginx support — nginx primarily uses `read`/`write`/`sendfile` on connected sockets, not `sendmsg`/`recvmsg`. We can defer this if simpler socket I/O works.

---

## Task 6: Route `read`/`write` on socket fds through central

**Files:**
- Modify: `litebox_central/src/server.rs` — verify `read`/`write` already dispatch correctly for socket fds

**Key insight:** `read(fd, buf, len)` and `write(fd, buf, len)` already go through `is_data_producing_io()` and `is_data_consuming_io()`. The shim dispatches these to the task, which calls `sys_read`/`sys_write`, which looks up the fd in the fd table. If the fd is a socket, it dispatches through the socket read/write path.

This should **already work** — when the guest does `read(socket_fd, ...)`, central redirects the buffer to shmem, dispatches through shim, shim reads from the socket channel into shmem, returns HAS_DATA.

Verify this works by testing with a simple TCP connection.

---

## Task 7: TUN device setup (host-side network configuration)

**Files:**
- Modify: `litebox_launcher/src/central.rs` — add TUN device setup before spawning central

The TUN device needs host-side configuration:
1. Assign IP address: `ip addr add 10.0.0.1/24 dev tun0`
2. Bring interface up: `ip link set tun0 up`
3. Enable IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward`
4. NAT: `iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE`

These can be done either:
- In the launcher before spawning central
- In central's startup
- In a setup script

For now, add a helper function in the launcher or document the manual setup.

**Note:** TUN device creation requires `CAP_NET_ADMIN` or root. The launcher already runs as root for other reasons.

---

## Task 8: Add `--tun-device` CLI arg to central

**Files:**
- Modify: `litebox_central/src/main.rs` — add arg to Args struct
- Modify: `litebox_launcher/src/central.rs` — pass arg when spawning central

**Step 1: Add arg**

```rust
#[derive(Parser)]
struct Args {
    // ... existing args ...

    /// TUN device name for networking (e.g., "tun0"). If not provided,
    /// networking is disabled.
    #[arg(long)]
    tun_device: Option<String>,
}
```

**Step 2: Pass to CentralPlatform::new()**

```rust
let platform: &'static Platform = Box::leak(Box::new(
    CentralPlatform::new(args.tun_device.as_deref()),
));
```

**Step 3: Conditionally spawn network worker**

Only spawn the network worker thread if TUN is configured:

```rust
let net_worker = if args.tun_device.is_some() {
    // ... spawn thread ...
    Some(handle)
} else {
    None
};
```

---

## Task 9: End-to-end test with a simple TCP connection

**Manual test procedure:**

1. Set up TUN device:
```bash
ip tuntap add mode tun dev tun0
ip addr add 10.0.0.1/24 dev tun0
ip link set tun0 up
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE
```

2. Build everything:
```bash
cargo build --release -p litebox_micro -p litebox_launcher
cargo build --release -p litebox_central
```

3. Create a simple test program or use `wget`/`curl` from the rootfs:
```bash
# In the litebox guest (via the launcher)
wget http://example.com -O /dev/null
```

Or start with something simpler like a DNS query or TCP connect.

---

## Implementation Notes

### What's already working (no changes needed):
- `socket()`, `bind()`, `listen()`, `accept4()`, `connect()` — already go through central's shim
- `setsockopt()`, `getsockopt()`, `getsockname()`, `getpeername()` — same
- `close()` on socket fds — dual-dispatch (shim first, EBADF fallback)
- smoltcp virtual network stack with TCP/UDP support
- Socket ring buffer channels (smoltcp ↔ application data)
- `read()`/`write()` on socket fds — should already work via data-producing/consuming I/O

### What needs to be added:
- `CentralPlatform` TUN fd + `IPInterfaceProvider` (Task 1)
- Network worker thread (Task 2)
- `recvfrom` routing (Task 3)
- `sendto` routing (Task 4)
- `sendmsg`/`recvmsg` routing (Task 5, can defer)
- TUN host config (Task 7)
- CLI arg (Task 8)

### Syscall gaps for nginx (separate from networking, implement later):
- `sendfile()` — needs new shim implementation
- `shutdown()` — needs shim implementation
- `epoll_ctl` with `EPOLL_CTL_MOD` — needs shim fix
- `setsid()` / `setpgid()` — needs central implementation
- `fchmod()` / `fchown()` / `rename()` — needs shim + VFS work
- SIGCHLD delivery on child exit — needs central signaling
