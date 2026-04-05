// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in a central
//! server process context (e.g., micro-LiteBox).
//!
//! This platform uses standard library primitives and Linux futexes, and stubs
//! out functionality that is not applicable to a server-side host process (raw
//! IP networking, guest memory pointers).

use core::ops::RangeBounds;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::time::Duration;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::RwLock;

use litebox::platform::{
    ImmediatelyWokenUp, Punchthrough, PunchthroughProvider, PunchthroughToken, RawConstPointer,
    RawMutPointer, UnblockedOrTimedOut,
};
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

// ---------------------------------------------------------------------------
// TUN constants and helpers
// ---------------------------------------------------------------------------

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;

/// `TUNSETIFF` ioctl number: `_IOW('T', 202, int)` = `0x400454CA`.
const TUNSETIFF: libc::c_ulong = 0x400454CA;

/// `TUNSETQUEUE` ioctl number: `_IOW('T', 217, int)` = `0x400454D9`.
/// Used with `IFF_DETACH_QUEUE` / `IFF_ATTACH_QUEUE` to control which queues
/// actively receive packets from the kernel.
const TUNSETQUEUE: libc::c_ulong = 0x400454D9;

/// Flag for `TUNSETQUEUE`: detach a queue so it stops receiving packets.
const IFF_DETACH_QUEUE: libc::c_short = 0x0400;

#[repr(C)]
struct Ifreq {
    ifr_name: [libc::c_char; 16],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

/// The central server platform.
///
/// Implements [`litebox::platform::Provider`] for use in a server (host-side)
/// process that communicates with a guest over IPC. Optionally holds a TUN
/// device file descriptor for raw IP networking.
#[derive(Debug)]
pub struct CentralPlatform {
    /// The TUN device name (needed to open additional queues on fork).
    tun_device_name: Option<String>,
    /// TUN queue file descriptors. Queue 0 is created at startup;
    /// additional queues are created via `open_new_queue()` on fork.
    tun_queues: RwLock<Vec<OwnedFd>>,
    /// When `true`, page management operations (`allocate_pages`,
    /// `deallocate_pages`, `update_permissions`) skip real syscalls and
    /// return success immediately. Used to let the shim's `PageManager`
    /// track VMA metadata without creating real pages in central's address
    /// space ("phantom pages").
    phantom_mode: AtomicBool,
}

impl CentralPlatform {
    /// Create a new `CentralPlatform`, optionally opening a TUN device.
    ///
    /// If `tun_device_name` is `Some`, the named TUN device is opened via
    /// `/dev/net/tun` and configured with `TUNSETIFF`. If `None`, no TUN
    /// device is created and IP networking calls will panic.
    ///
    /// # Panics
    ///
    /// Panics if the TUN device cannot be opened or configured (e.g.,
    /// `/dev/net/tun` does not exist, or the `TUNSETIFF` ioctl fails).
    /// Also panics if the device name is 16 bytes or longer.
    pub fn new(tun_device_name: Option<&str>) -> Self {
        let tun_fd = tun_device_name.map(|name| {
            // Open /dev/net/tun
            let fd = unsafe {
                libc::open(
                    c"/dev/net/tun".as_ptr(),
                    libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            assert!(
                fd >= 0,
                "failed to open /dev/net/tun: {}",
                std::io::Error::last_os_error()
            );

            // TUNSETIFF ioctl
            let mut ifreq = Ifreq {
                ifr_name: [0; 16],
                ifr_flags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
                _pad: [0; 22],
            };
            assert!(name.len() < 16, "TUN device name too long");
            for (i, b) in name.bytes().enumerate() {
                ifreq.ifr_name[i] = b.cast_signed();
            }

            let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &raw const ifreq) };
            assert!(
                ret >= 0,
                "TUNSETIFF failed: {}",
                std::io::Error::last_os_error()
            );

            // Host-side network configuration for the TUN device
            eprintln!("configuring TUN device {name}...");

            eprintln!("  ip addr add 10.0.0.1/24 dev {name}");
            let status = std::process::Command::new("ip")
                .args(["addr", "add", "10.0.0.1/24", "dev", name])
                .status()
                .expect("failed to run `ip addr add`");
            assert!(status.success(), "`ip addr add` failed: {status}");

            eprintln!("  ip link set {name} up");
            let status = std::process::Command::new("ip")
                .args(["link", "set", name, "up"])
                .status()
                .expect("failed to run `ip link set`");
            assert!(status.success(), "`ip link set` failed: {status}");

            eprintln!("  enabling ip_forward");
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
                .expect("failed to enable ip_forward");

            eprintln!("  iptables MASQUERADE for 10.0.0.0/24");
            let check = std::process::Command::new("iptables")
                .args([
                    "-t",
                    "nat",
                    "-C",
                    "POSTROUTING",
                    "-s",
                    "10.0.0.0/24",
                    "-j",
                    "MASQUERADE",
                ])
                .output()
                .expect("failed to run `iptables -C`");
            if !check.status.success() {
                let status = std::process::Command::new("iptables")
                    .args([
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        "-s",
                        "10.0.0.0/24",
                        "-j",
                        "MASQUERADE",
                    ])
                    .status()
                    .expect("failed to run `iptables -A`");
                assert!(status.success(), "`iptables -A` failed: {status}");
            }

            eprintln!("TUN device {name} configured");

            unsafe { OwnedFd::from_raw_fd(fd) }
        });

        Self {
            tun_device_name: tun_device_name.map(String::from),
            tun_queues: RwLock::new(if let Some(fd) = tun_fd {
                vec![fd]
            } else {
                vec![]
            }),
            phantom_mode: AtomicBool::new(false),
        }
    }

    /// Returns `true` if a TUN device was configured at startup.
    pub fn has_tun(&self) -> bool {
        self.tun_device_name.is_some()
    }

    /// Open an additional file descriptor to the same TUN device.
    ///
    /// Called when a worker is forked. Returns the queue index.
    ///
    /// # Panics
    ///
    /// Panics if no TUN device was configured at startup, if `/dev/net/tun`
    /// cannot be opened, or if the `TUNSETIFF` ioctl fails.
    pub fn open_new_queue(&self) -> usize {
        let name = self
            .tun_device_name
            .as_deref()
            .expect("cannot open TUN queue: no TUN device configured");

        let fd = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        assert!(
            fd >= 0,
            "failed to open /dev/net/tun for new queue: {}",
            std::io::Error::last_os_error()
        );

        let mut ifreq = Ifreq {
            ifr_name: [0; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
            _pad: [0; 22],
        };
        assert!(name.len() < 16, "TUN device name too long");
        for (i, b) in name.bytes().enumerate() {
            ifreq.ifr_name[i] = b.cast_signed();
        }

        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &raw const ifreq) };
        assert!(
            ret >= 0,
            "TUNSETIFF failed for new queue: {}",
            std::io::Error::last_os_error()
        );

        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut queues = self.tun_queues.write().unwrap();
        let idx = queues.len();
        queues.push(owned);
        idx
    }

    /// Detach a TUN queue so the kernel stops routing packets to it.
    ///
    /// After detaching, the queue fd remains open (other state may reference
    /// its index) but `read()` will never return data because the kernel no
    /// longer delivers packets to it. This is used to remove the master
    /// process's queue after forking workers, so that all incoming traffic is
    /// directed exclusively to worker queues.
    ///
    /// Returns `true` if the queue was detached, `false` if it was already
    /// detached (the ioctl returned `EINVAL`).
    ///
    /// # Panics
    ///
    /// Panics if the queue index is out of bounds or the ioctl fails with an
    /// error other than `EINVAL`.
    pub fn try_detach_queue(&self, queue: usize) -> bool {
        let raw_fd = {
            let guard = self.tun_queues.read().unwrap();
            guard[queue].as_raw_fd()
        };
        let ifreq = Ifreq {
            ifr_name: [0; 16],
            ifr_flags: IFF_DETACH_QUEUE,
            _pad: [0; 22],
        };
        let ret = unsafe { libc::ioctl(raw_fd, TUNSETQUEUE, &raw const ifreq) };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EINVAL {
                // Already detached — this is expected on subsequent forks.
                return false;
            }
            panic!(
                "TUNSETQUEUE(DETACH) failed for queue {queue}: {}",
                std::io::Error::last_os_error()
            );
        }
        true
    }

    /// Send an IP packet via a specific TUN queue.
    ///
    /// # Panics
    ///
    /// Panics if the queue index is out of bounds or the write fails.
    pub fn send_ip_packet_on_queue(&self, queue: usize, packet: &[u8]) {
        let raw_fd = {
            let guard = self.tun_queues.read().unwrap();
            guard[queue].as_raw_fd()
        };
        let ret = unsafe { libc::write(raw_fd, packet.as_ptr().cast(), packet.len()) };
        assert!(
            ret >= 0,
            "TUN queue {queue} write failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// Receive an IP packet from a specific TUN queue.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiveError::WouldBlock`](litebox::platform::ReceiveError::WouldBlock)
    /// if no data is available (non-blocking).
    ///
    /// # Panics
    ///
    /// Panics if the queue index is out of bounds or an unexpected read error
    /// occurs.
    pub fn receive_ip_packet_on_queue(
        &self,
        queue: usize,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        let raw_fd = {
            let guard = self.tun_queues.read().unwrap();
            guard[queue].as_raw_fd()
        };
        let ret = unsafe { libc::read(raw_fd, packet.as_mut_ptr().cast(), packet.len()) };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                return Err(litebox::platform::ReceiveError::WouldBlock);
            }
            panic!(
                "TUN queue {queue} read failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let size = ret.cast_unsigned();
        Ok(size)
    }

    /// Block until a specific TUN queue has data to read, or the timeout
    /// expires.
    ///
    /// Returns immediately if the queue index is out of bounds.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn wait_on_tun_queue(&self, queue: usize, timeout: Option<Duration>) {
        let raw_fd = {
            let guard = self.tun_queues.read().unwrap();
            if queue >= guard.len() {
                return;
            }
            guard[queue].as_raw_fd()
        };
        let mut pfd = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = timeout.map_or(-1, |t| {
            let ms = t.as_millis();
            let ms = if ms == 0 && !t.is_zero() { 1 } else { ms };
            i32::try_from(ms).unwrap_or(i32::MAX)
        });
        unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
    }

    /// Block until the TUN device has data to read, or the timeout expires.
    ///
    /// Delegates to queue 0. Returns immediately if no TUN device is
    /// configured.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn wait_on_tun(&self, timeout: Option<Duration>) {
        self.wait_on_tun_queue(0, timeout);
    }
}

// ---------------------------------------------------------------------------
// Thread-local TUN queue routing
// ---------------------------------------------------------------------------

std::thread_local! {
    /// The TUN queue index that the current thread should use for
    /// [`IPInterfaceProvider`] send/receive operations.
    static CURRENT_TUN_QUEUE: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

impl CentralPlatform {
    /// Set the TUN queue index for the current thread.
    ///
    /// All subsequent [`IPInterfaceProvider`] calls on this thread will route
    /// through the specified queue.
    ///
    /// # Panics
    ///
    /// No immediate panic, but subsequent `IPInterfaceProvider` calls will
    /// panic if `queue` is out of bounds for the TUN device's queue list.
    pub fn set_current_tun_queue(queue: usize) {
        CURRENT_TUN_QUEUE.set(queue);
    }
}

// ---------------------------------------------------------------------------
// Task 2: DebugLogProvider and IPInterfaceProvider
// ---------------------------------------------------------------------------

impl litebox::platform::DebugLogProvider for CentralPlatform {
    fn debug_log_print(&self, msg: &str) {
        eprint!("{msg}");
    }
}

impl litebox::platform::IPInterfaceProvider for CentralPlatform {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        self.send_ip_packet_on_queue(CURRENT_TUN_QUEUE.get(), packet);
        Ok(())
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        self.receive_ip_packet_on_queue(CURRENT_TUN_QUEUE.get(), packet)
    }
}

// ---------------------------------------------------------------------------
// Task 3: TimeProvider
// ---------------------------------------------------------------------------

/// A monotonic instant backed by [`std::time::Instant`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CentralInstant(std::time::Instant);

impl litebox::platform::Instant for CentralInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.0.checked_duration_since(earlier.0)
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(CentralInstant)
    }
}

/// A wall-clock time backed by [`std::time::SystemTime`].
pub struct CentralSystemTime(std::time::SystemTime);

impl litebox::platform::SystemTime for CentralSystemTime {
    const UNIX_EPOCH: Self = CentralSystemTime(std::time::SystemTime::UNIX_EPOCH);

    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration> {
        self.0.duration_since(earlier.0).map_err(|e| e.duration())
    }
}

impl litebox::platform::TimeProvider for CentralPlatform {
    type Instant = CentralInstant;
    type SystemTime = CentralSystemTime;

    fn now(&self) -> Self::Instant {
        CentralInstant(std::time::Instant::now())
    }

    fn current_time(&self) -> Self::SystemTime {
        CentralSystemTime(std::time::SystemTime::now())
    }
}

// ---------------------------------------------------------------------------
// Task 4: RawMutexProvider (Linux futex-based)
// ---------------------------------------------------------------------------

/// A raw mutex backed by a Linux futex.
pub struct CentralRawMutex {
    futex: AtomicU32,
}

impl CentralRawMutex {
    /// Perform a futex WAIT: if `*futex == val`, sleep until woken.
    fn futex_wait(&self, val: u32, timeout: Option<Duration>) -> libc::c_long {
        let timeout_ptr = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs().cast_signed(),
            tv_nsec: i64::from(d.subsec_nanos()),
        });
        let timeout_arg: *const libc::timespec = match &timeout_ptr {
            Some(ts) => ts,
            None => core::ptr::null(),
        };
        // SAFETY: The futex pointer is valid for the lifetime of `self`, and
        // the timeout pointer is either null or points to a valid timespec on
        // the stack.
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                &raw const self.futex,
                libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                val,
                timeout_arg,
            )
        }
    }

    /// Perform a futex WAKE: wake up to `n` waiters.
    fn futex_wake(&self, n: i32) -> libc::c_long {
        // SAFETY: The futex pointer is valid for the lifetime of `self`.
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                &raw const self.futex,
                libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                n,
            )
        }
    }
}

impl litebox::platform::RawMutex for CentralRawMutex {
    const INIT: Self = Self {
        futex: AtomicU32::new(0),
    };

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.futex
    }

    fn wake_many(&self, n: usize) -> usize {
        let n = i32::try_from(n).unwrap_or(i32::MAX);
        let ret = self.futex_wake(n);
        debug_assert!(ret >= 0, "futex WAKE failed: {ret}");
        usize::try_from(ret).expect("futex WAKE returned negative count")
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        let ret = self.futex_wait(val, None);
        if ret == 0 {
            return Ok(());
        }
        let errno = unsafe { *libc::__errno_location() };
        match errno {
            libc::EINTR | libc::EAGAIN => {
                // EINTR: interrupted by signal (treat as woken)
                // EAGAIN: value changed before we slept
                if errno == libc::EAGAIN {
                    Err(ImmediatelyWokenUp)
                } else {
                    Ok(())
                }
            }
            _ => panic!("unexpected futex WAIT errno: {errno}"),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        time: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        let ret = self.futex_wait(val, Some(time));
        if ret == 0 {
            return Ok(UnblockedOrTimedOut::Unblocked);
        }
        let errno = unsafe { *libc::__errno_location() };
        match errno {
            libc::EINTR => Ok(UnblockedOrTimedOut::Unblocked),
            libc::EAGAIN => Err(ImmediatelyWokenUp),
            libc::ETIMEDOUT => Ok(UnblockedOrTimedOut::TimedOut),
            _ => panic!("unexpected futex WAIT errno: {errno}"),
        }
    }
}

impl litebox::platform::RawMutexProvider for CentralPlatform {
    type RawMutex = CentralRawMutex;
}

// ---------------------------------------------------------------------------
// Task 5: RawPointerProvider (stub)
// ---------------------------------------------------------------------------

/// A stub read-only guest pointer for the central platform.
///
/// Since the central platform runs in a separate address space from the guest,
/// direct pointer access is not meaningful. All dereference operations are
/// unimplemented.
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct GuestConstPtr<T: Sized> {
    addr: usize,
    _marker: core::marker::PhantomData<*const T>,
}

impl<T> Clone for GuestConstPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for GuestConstPtr<T> {}

impl<T> core::fmt::Debug for GuestConstPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GuestConstPtr").field(&self.addr).finish()
    }
}

impl<T: FromBytes> RawConstPointer<T> for GuestConstPtr<T> {
    fn as_usize(&self) -> usize {
        self.addr
    }

    fn from_usize(addr: usize) -> Self {
        Self {
            addr,
            _marker: core::marker::PhantomData,
        }
    }

    fn read_at_offset(self, count: isize) -> Option<T> {
        if self.addr == 0 {
            return None;
        }
        unsafe { Some((self.addr as *const T).offset(count).read_unaligned()) }
    }

    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        if self.addr == 0 {
            return None;
        }
        let src = self.addr as *const T;
        let mut vec = alloc::vec::Vec::with_capacity(len);
        for i in 0..len {
            vec.push(unsafe { src.add(i).read_unaligned() });
        }
        Some(vec.into_boxed_slice())
    }
}

/// A stub read-write guest pointer for the central platform.
///
/// See [`GuestConstPtr`] for details.
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct GuestMutPtr<T: Sized> {
    addr: usize,
    _marker: core::marker::PhantomData<*const T>,
}

impl<T> Clone for GuestMutPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for GuestMutPtr<T> {}

impl<T> core::fmt::Debug for GuestMutPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GuestMutPtr").field(&self.addr).finish()
    }
}

impl<T: FromBytes> RawConstPointer<T> for GuestMutPtr<T> {
    fn as_usize(&self) -> usize {
        self.addr
    }

    fn from_usize(addr: usize) -> Self {
        Self {
            addr,
            _marker: core::marker::PhantomData,
        }
    }

    fn read_at_offset(self, count: isize) -> Option<T> {
        if self.addr == 0 {
            return None;
        }
        unsafe { Some((self.addr as *const T).offset(count).read_unaligned()) }
    }

    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        if self.addr == 0 {
            return None;
        }
        let src = self.addr as *const T;
        let mut vec = alloc::vec::Vec::with_capacity(len);
        for i in 0..len {
            vec.push(unsafe { src.add(i).read_unaligned() });
        }
        Some(vec.into_boxed_slice())
    }
}

impl<T: FromBytes + IntoBytes> RawMutPointer<T> for GuestMutPtr<T> {
    fn write_at_offset(self, count: isize, value: T) -> Option<()> {
        if self.addr == 0 {
            return None;
        }
        unsafe { (self.addr as *mut T).offset(count).write_unaligned(value) };
        Some(())
    }

    fn mutate_subslice_with<R>(
        self,
        range: impl RangeBounds<isize>,
        f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R> {
        if self.addr == 0 {
            return None;
        }
        let start = match range.start_bound() {
            core::ops::Bound::Included(&s) => s,
            core::ops::Bound::Excluded(&s) => s.checked_add(1)?,
            core::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            core::ops::Bound::Included(&e) => e.checked_add(1)?,
            core::ops::Bound::Excluded(&e) => e,
            core::ops::Bound::Unbounded => return None,
        };
        let len = (end - start).cast_unsigned();
        let slice =
            unsafe { core::slice::from_raw_parts_mut((self.addr as *mut T).offset(start), len) };
        Some(f(slice))
    }
}

impl litebox::platform::RawPointerProvider for CentralPlatform {
    type RawConstPointer<T: FromBytes> = GuestConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = GuestMutPtr<T>;
}

// ---------------------------------------------------------------------------
// Task 6: PunchthroughProvider and Provider
// ---------------------------------------------------------------------------

/// A punchthrough token wrapping [`litebox_common_linux::PunchthroughSyscall`].
///
/// The central platform emulates FS base register operations using a
/// thread-local variable rather than hardware registers, since it does not
/// run guest code directly.
pub struct CentralPunchthroughToken<'a> {
    punchthrough: litebox_common_linux::PunchthroughSyscall<'a, CentralPlatform>,
}

std::thread_local! {
    /// Emulated FS base register value for the current thread.
    static GUEST_FSBASE: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

impl<'a> PunchthroughToken for CentralPunchthroughToken<'a> {
    type Punchthrough = litebox_common_linux::PunchthroughSyscall<'a, CentralPlatform>;

    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    > {
        match self.punchthrough {
            #[cfg(target_arch = "x86_64")]
            litebox_common_linux::PunchthroughSyscall::SetFsBase { addr } => {
                GUEST_FSBASE.set(addr);
                Ok(0)
            }
            #[cfg(target_arch = "x86_64")]
            litebox_common_linux::PunchthroughSyscall::GetFsBase => Ok(GUEST_FSBASE.get()),
            #[cfg(target_arch = "x86")]
            litebox_common_linux::PunchthroughSyscall::SetThreadArea { .. } => {
                Err(litebox::platform::PunchthroughError::Unimplemented(
                    "SetThreadArea is not supported on the central platform",
                ))
            }
        }
    }
}

impl PunchthroughProvider for CentralPlatform {
    type PunchthroughToken<'a> = CentralPunchthroughToken<'a>;

    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
        Some(CentralPunchthroughToken { punchthrough })
    }
}

impl litebox::platform::Provider for CentralPlatform {}

// ---------------------------------------------------------------------------
// Task 7-8: Additional traits required by litebox_shim_linux
// ---------------------------------------------------------------------------

/// Error returned when CentralPlatform cannot spawn threads.
///
/// The central platform does not support direct thread spawning; the guest
/// manages its own threads via IPC.
#[derive(Debug)]
pub struct CentralThreadSpawnError;

impl core::fmt::Display for CentralThreadSpawnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CentralPlatform does not support thread spawning")
    }
}

impl core::error::Error for CentralThreadSpawnError {}

impl litebox::platform::ThreadProvider for CentralPlatform {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = CentralThreadSpawnError;
    type ThreadHandle = ();

    unsafe fn spawn_thread(
        &self,
        _ctx: &Self::ExecutionContext,
        _init_thread: alloc::boxed::Box<
            dyn litebox::shim::InitThread<ExecutionContext = Self::ExecutionContext>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        Err(CentralThreadSpawnError)
    }

    fn current_thread(&self) -> Self::ThreadHandle {}

    fn interrupt_thread(&self, _thread: &Self::ThreadHandle) {
        // No-op: the central platform does not run guest code directly.
    }
}

impl litebox::platform::StdioProvider for CentralPlatform {
    fn read_from_stdin(&self, _buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        Err(litebox::platform::StdioReadError::Closed)
    }

    fn write_to(
        &self,
        _stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        use std::io::Write;
        std::io::stderr().write_all(buf).ok();
        Ok(buf.len())
    }

    fn is_a_tty(&self, _stream: litebox::platform::StdioStream) -> bool {
        false
    }
}

impl litebox::platform::PageManagementProvider<4096> for CentralPlatform {
    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: litebox::platform::page_mgmt::FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        use litebox::platform::page_mgmt::{AllocationError, FixedAddressBehavior};

        if self.phantom_mode.load(Ordering::Acquire) {
            return Ok(GuestMutPtr::from_usize(suggested_range.start));
        }

        let mut flags: libc::c_int = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        match fixed_address_behavior {
            FixedAddressBehavior::Hint => {}
            FixedAddressBehavior::Replace => flags |= libc::MAP_FIXED,
            FixedAddressBehavior::NoReplace => flags |= libc::MAP_FIXED_NOREPLACE,
        }
        if can_grow_down {
            flags |= libc::MAP_GROWSDOWN;
        }
        if populate_pages_immediately {
            flags |= libc::MAP_POPULATE;
        }

        let prot = prot_flags(initial_permissions);

        // SAFETY: mmap with MAP_ANONYMOUS and fd=-1 is a safe operation.
        let ret = unsafe {
            libc::mmap(
                suggested_range.start as *mut libc::c_void,
                suggested_range.len(),
                prot,
                flags,
                -1,
                0,
            )
        };

        if ret == libc::MAP_FAILED {
            let errno = unsafe { *libc::__errno_location() };
            return Err(match errno {
                libc::ENOMEM => AllocationError::OutOfMemory,
                libc::EEXIST => AllocationError::AddressInUse,
                _ => panic!("unhandled mmap error: {errno}"),
            });
        }

        Ok(GuestMutPtr::from_usize(ret as usize))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        if self.phantom_mode.load(Ordering::Acquire) {
            return Ok(());
        }

        // SAFETY: Caller guarantees the pages are not in active use.
        let ret = unsafe { libc::munmap(range.start as *mut libc::c_void, range.len()) };
        if ret != 0 {
            return Err(litebox::platform::page_mgmt::DeallocationError::AlreadyUnallocated);
        }
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        if self.phantom_mode.load(Ordering::Acquire) {
            return Ok(());
        }

        let prot = prot_flags(new_permissions);
        // SAFETY: Caller guarantees the permissions don't conflict with active usage.
        let ret = unsafe { libc::mprotect(range.start as *mut libc::c_void, range.len(), prot) };
        if ret != 0 {
            return Err(litebox::platform::page_mgmt::PermissionUpdateError::Unallocated);
        }
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        core::iter::empty()
    }
}

/// RAII guard that enables phantom mode on a `CentralPlatform` for its
/// lifetime. When dropped, phantom mode is disabled.
pub struct PhantomModeGuard<'a> {
    platform: &'a CentralPlatform,
}

impl<'a> PhantomModeGuard<'a> {
    /// Enable phantom mode on `platform` for the duration of this guard.
    pub fn new(platform: &'a CentralPlatform) -> Self {
        platform.phantom_mode.store(true, Ordering::Release);
        Self { platform }
    }
}

impl Drop for PhantomModeGuard<'_> {
    fn drop(&mut self) {
        self.platform.phantom_mode.store(false, Ordering::Release);
    }
}

/// Convert [`MemoryRegionPermissions`] to libc `PROT_*` flags.
fn prot_flags(perms: litebox::platform::page_mgmt::MemoryRegionPermissions) -> libc::c_int {
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
    let mut prot: libc::c_int = libc::PROT_NONE;
    if perms.contains(MemoryRegionPermissions::READ) {
        prot |= libc::PROT_READ;
    }
    if perms.contains(MemoryRegionPermissions::WRITE) {
        prot |= libc::PROT_WRITE;
    }
    if perms.contains(MemoryRegionPermissions::EXEC) {
        prot |= libc::PROT_EXEC;
    }
    prot
}

impl litebox::platform::SystemInfoProvider for CentralPlatform {
    fn get_syscall_entry_point(&self) -> usize {
        // The central platform does not run guest code directly; the syscall
        // entry point is not meaningful. Return 0 as a sentinel.
        0
    }

    fn get_vdso_address(&self) -> Option<usize> {
        // No VDSO in the central platform — the guest does not share our
        // address space.
        None
    }
}

impl litebox::platform::CrngProvider for CentralPlatform {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

/// A timer handle backed by POSIX `timer_create` / `timer_settime`.
pub struct CentralTimerHandle(libc::timer_t);

// SAFETY: `timer_t` is an opaque kernel handle safe to send across threads.
unsafe impl Send for CentralTimerHandle {}
// SAFETY: `timer_settime` and `timer_delete` are thread-safe for distinct timers.
unsafe impl Sync for CentralTimerHandle {}

impl Drop for CentralTimerHandle {
    fn drop(&mut self) {
        // SAFETY: We own the timer and it will not be used after drop.
        unsafe {
            libc::timer_delete(self.0);
        }
    }
}

impl litebox::platform::TimerHandle for CentralTimerHandle {
    fn set_timer(&self, duration: Duration) {
        let its = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: duration.as_secs().cast_signed(),
                tv_nsec: i64::from(duration.subsec_nanos()),
            },
        };
        // SAFETY: Valid timer id and itimerspec on the stack.
        let ret = unsafe { libc::timer_settime(self.0, 0, &raw const its, core::ptr::null_mut()) };
        assert!(
            ret == 0,
            "timer_settime failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

impl litebox::platform::TimerProvider for CentralPlatform {
    type TimerHandle = CentralTimerHandle;
    type Signal = litebox_common_linux::signal::Signal;

    fn create_timer(
        &self,
        signal: Self::Signal,
    ) -> Result<Self::TimerHandle, litebox::platform::TimerCreationError> {
        let mut sev: libc::sigevent = unsafe { core::mem::zeroed() };
        sev.sigev_notify = libc::SIGEV_SIGNAL;
        sev.sigev_signo = libc::SIGALRM;
        sev.sigev_value.sival_ptr = signal.as_i32() as *mut libc::c_void;

        let mut timer_id: libc::timer_t = core::ptr::null_mut();
        // SAFETY: Passing valid pointers to timer_create.
        let ret =
            unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &raw mut sev, &raw mut timer_id) };
        assert!(
            ret == 0,
            "timer_create failed: {}",
            std::io::Error::last_os_error()
        );

        Ok(CentralTimerHandle(timer_id))
    }
}

impl litebox::platform::SignalProvider for CentralPlatform {
    type Signal = litebox_common_linux::signal::Signal;

    // Uses the default no-op implementation of take_pending_signals.
}

std::thread_local! {
    static CENTRAL_TLS: core::cell::Cell<*mut ()> = const { core::cell::Cell::new(core::ptr::null_mut()) };
}

// SAFETY: The thread-local cell ensures that get/replace operate on per-thread
// storage, and null_mut is returned when no value has been set.
unsafe impl litebox::platform::ThreadLocalStorageProvider for CentralPlatform {
    fn get_thread_local_storage() -> *mut () {
        CENTRAL_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        CENTRAL_TLS.replace(value)
    }

    fn clear_guest_thread_local_storage() {
        // No-op: the central platform does not have hardware TLS state to clear.
    }
}

/// Dummy `VmapManager`.
///
/// The central platform does not support `vmap` / `vunmap` (kernel-level
/// operations). The default trait methods return `UnsupportedOperation`.
impl litebox_common_linux::vmap::VmapManager<4096> for CentralPlatform {}

/// Dummy `VmemPageFaultHandler`.
///
/// Page faults are handled transparently by the host Linux kernel for the
/// central platform. This implementation satisfies the trait bounds required
/// by `PageManager::handle_page_fault`.
impl litebox::mm::linux::VmemPageFaultHandler for CentralPlatform {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for central platform")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for central platform")
    }
}

#[cfg(test)]
mod guest_ptr_tests {
    use super::*;
    use litebox::platform::{RawConstPointer, RawMutPointer};

    #[test]
    fn guest_const_ptr_read_at_offset() {
        let values: [u64; 3] = [42, 99, 7];
        let ptr = GuestConstPtr::<u64>::from_usize(values.as_ptr() as usize);
        assert_eq!(ptr.read_at_offset(0), Some(42));
        assert_eq!(ptr.read_at_offset(1), Some(99));
        assert_eq!(ptr.read_at_offset(2), Some(7));
    }

    #[test]
    fn guest_const_ptr_to_owned_slice() {
        let values: [u32; 4] = [1, 2, 3, 4];
        let ptr = GuestConstPtr::<u32>::from_usize(values.as_ptr() as usize);
        let slice = ptr.to_owned_slice(4).unwrap();
        assert_eq!(&*slice, &[1, 2, 3, 4]);
    }

    #[test]
    fn guest_const_ptr_null_returns_none() {
        let ptr = GuestConstPtr::<u64>::from_usize(0);
        assert_eq!(ptr.read_at_offset(0), None);
        assert!(ptr.to_owned_slice(1).is_none());
    }

    #[test]
    fn guest_mut_ptr_read_at_offset() {
        let mut values: [u64; 2] = [10, 20];
        let ptr = GuestMutPtr::<u64>::from_usize(values.as_mut_ptr() as usize);
        assert_eq!(RawConstPointer::read_at_offset(ptr, 0), Some(10));
        assert_eq!(RawConstPointer::read_at_offset(ptr, 1), Some(20));
    }

    #[test]
    fn guest_mut_ptr_to_owned_slice() {
        let mut values: [u8; 3] = [0xAA, 0xBB, 0xCC];
        let ptr = GuestMutPtr::<u8>::from_usize(values.as_mut_ptr() as usize);
        let slice = RawConstPointer::to_owned_slice(ptr, 3).unwrap();
        assert_eq!(&*slice, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn guest_mut_ptr_write_at_offset() {
        let mut values: [u64; 2] = [0, 0];
        let ptr = GuestMutPtr::<u64>::from_usize(values.as_mut_ptr() as usize);
        assert_eq!(ptr.write_at_offset(0, 42), Some(()));
        assert_eq!(ptr.write_at_offset(1, 99), Some(()));
        assert_eq!(values, [42, 99]);
    }

    #[test]
    fn guest_mut_ptr_mutate_subslice_with() {
        let mut values: [u8; 4] = [0; 4];
        let ptr = GuestMutPtr::<u8>::from_usize(values.as_mut_ptr() as usize);
        let result = ptr.mutate_subslice_with(1..3, |slice| {
            slice[0] = 0xAA;
            slice[1] = 0xBB;
            42
        });
        assert_eq!(result, Some(42));
        assert_eq!(values, [0, 0xAA, 0xBB, 0]);
    }

    #[test]
    fn guest_mut_ptr_null_returns_none() {
        let ptr = GuestMutPtr::<u64>::from_usize(0);
        assert_eq!(ptr.write_at_offset(0, 42), None);
        assert_eq!(ptr.mutate_subslice_with(0..1, |_| 0), None);
    }
}
