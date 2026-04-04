// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Network proxy — terminates guest TCP/UDP via smoltcp and bridges to host sockets.
//!
//! # Architecture
//!
//! ```text
//! Guest <-IPC-> [broker smoltcp] <-relay-> host TCP/UDP sockets
//! ```
//!
//! The broker runs its own smoltcp instance with `set_any_ip(true)`. Before each
//! smoltcp poll, incoming packets are staged and inspected. TCP SYN packets
//! trigger on-demand creation of listen sockets so smoltcp can complete the
//! handshake. Once a connection is ESTABLISHED, a host-side `TcpStream` is
//! opened and data is relayed bidirectionally.

mod device;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::sock_compat::{
    self, AsRawSock, IpcListener, IpcStream, POLLIN, POLLOUT, PollFd, RawSock,
};

use smoltcp::iface::SocketHandle;
use smoltcp::wire::Ipv4Address;
use tracing::{debug, info, warn};

use device::DEVICE_MTU;

/// Broker IP address (gateway from the guest's perspective).
const BROKER_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
/// Broker IP as std Ipv4Addr.
const BROKER_IPV4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Maximum concurrent TCP flows.
const MAX_CONNECTIONS: usize = 1024;

/// smoltcp socket buffer size (64 KB — broker relays immediately).
const SOCKET_BUFFER_SIZE: usize = 65536;

/// UDP flow idle timeout before garbage collection.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// IPC handshake magic bytes.
const HANDSHAKE_MAGIC: &[u8; 4] = b"LBNP";

/// Handshake protocol version.
const HANDSHAKE_VERSION: u16 = 1;

/// Full TCP 4-tuple identifying a unique connection.
/// (guest_src_ip, guest_src_port, dst_ip, dst_port)
#[allow(dead_code)]
type TcpFlowKey = ([u8; 4], u16, [u8; 4], u16);

/// State for an active TCP bridge between smoltcp and a host socket.
#[allow(dead_code)]
struct TcpBridge {
    smoltcp_handle: SocketHandle,
    host_stream: std::net::TcpStream,
    dest: SocketAddr,
    /// Whether the host side has reached EOF.
    host_eof: bool,
}

/// A TCP connection in the process of connecting to the host (non-blocking).
/// The smoltcp listen socket is NOT created until the host connect succeeds,
/// so guest connect() only succeeds after the real host connection is ready.
#[allow(dead_code)]
struct PendingConnect {
    /// Full 4-tuple so parallel connections to the same server are distinguished.
    flow_key: TcpFlowKey,
    dest: SocketAddr,
    /// Connecting stream.
    stream: IpcStream,
    /// When the connect was initiated (for timeout).
    started: Instant,
}

/// A newly accepted connection waiting for transport classification.
/// Drained opportunistically each event-loop iteration with zero blocking.
#[allow(dead_code)]
struct PendingHandshake {
    stream: Option<IpcStream>,
    raw_socket: RawSock,
    handshake: [u8; 8],
    got: usize,
    deadline: Instant,
}

/// Timeout for the LB9P handshake on an accepted connection.
const HANDSHAKE_ACCEPT_TIMEOUT: Duration = Duration::from_millis(100);

/// Maximum total time to receive direct shared-memory 9P upgrade metadata.
#[cfg(windows)]
const LB9P_RING_UPGRADE_TIMEOUT: Duration = Duration::from_secs(2);

/// Hard cap on concurrent background direct 9P ring-upgrade workers.
#[cfg(any(unix, windows))]
const MAX_CONCURRENT_LB9P_RING_UPGRADES: usize = 32;

/// Number of currently active background direct 9P ring-upgrade workers.
#[cfg(any(unix, windows))]
static ACTIVE_LB9P_RING_UPGRADES: AtomicUsize = AtomicUsize::new(0);

/// Maximum concurrently active extra LBNP proxy sessions accepted from the
/// listener while an initial session is already running.
const MAX_ADDITIONAL_LBNP_SESSIONS: usize = 32;

/// Maximum accepted-but-not-yet-classified listener sockets kept in the
/// pending handshake queue at once.
const MAX_PENDING_ACCEPTED_HANDSHAKES: usize = 32;

/// Timeout for non-blocking host TCP connect.
const HOST_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

struct LbnpSessionPermit {
    session_slots: Arc<AtomicUsize>,
}

impl Drop for LbnpSessionPermit {
    fn drop(&mut self) {
        self.session_slots.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_lbnp_session_permit(session_slots: &Arc<AtomicUsize>) -> Option<LbnpSessionPermit> {
    loop {
        let active = session_slots.load(Ordering::Acquire);
        if active >= MAX_ADDITIONAL_LBNP_SESSIONS {
            return None;
        }
        if session_slots
            .compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(LbnpSessionPermit {
                session_slots: Arc::clone(session_slots),
            });
        }
    }
}

/// Extract the raw socket descriptor from any std socket type.
fn raw_socket<T: AsRawSock>(socket: &T) -> RawSock {
    socket.as_raw_sock()
}

/// Key for a UDP flow: (src_ip, src_port, dst_ip, dst_port).
#[allow(dead_code)]
type UdpFlowKey = ([u8; 4], u16, [u8; 4], u16);

/// State for a UDP flow (guest<->host datagram relay, bypassing smoltcp).
#[allow(dead_code)]
struct UdpFlow {
    /// Host-side UDP socket bound to an ephemeral port.
    host_socket: UdpSocket,
    /// Guest source IP (for constructing reply packets).
    guest_src_ip: [u8; 4],
    /// Guest source port.
    guest_src_port: u16,
    /// Destination IP the guest was sending to.
    dest_ip: [u8; 4],
    /// Destination port.
    dest_port: u16,
    /// Last activity timestamp for GC.
    last_activity: Instant,
}

// ---------------------------------------------------------------------------
// SCM_RIGHTS fd receiving (Unix only)
// ---------------------------------------------------------------------------

/// Receive two file descriptors from an IPC stream via `SCM_RIGHTS`.
///
/// The runner sends the shared-memory ring buffer fds immediately after the
/// `LB9P` magic bytes. This function performs a blocking `recvmsg` to receive
/// a single dummy byte plus the ancillary `SCM_RIGHTS` message carrying two
/// file descriptors (tx_fd, rx_fd from the creator's perspective).
#[cfg(unix)]
fn recv_ring_fds(
    stream: &IpcStream,
) -> Result<(std::os::unix::io::OwnedFd, std::os::unix::io::OwnedFd), std::io::Error> {
    use std::os::unix::io::FromRawFd;

    // Control message buffer: large enough for SCM_RIGHTS with 2 fds.
    // Use a union to guarantee the buffer is aligned for `cmsghdr`.
    // `CMSG_FIRSTHDR` / `CMSG_NXTHDR` return `*mut cmsghdr` pointing into
    // this buffer, so it must satisfy `cmsghdr`'s alignment requirement.
    #[allow(clippy::cast_possible_truncation)] // 2 * 4 = 8 always fits u32
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE((2 * size_of::<i32>()) as u32) as usize };
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
    }

    let raw_fd = stream.raw();

    // Make the socket blocking with a receive timeout for the fd-receive step.
    // A timeout prevents this recvmsg from blocking the event loop indefinitely
    // if the runner stalls after sending the marker byte.
    // SAFETY: `raw_fd` is a valid open file descriptor.
    unsafe {
        let flags = libc::fcntl(raw_fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(raw_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        libc::setsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Buffer for the dummy data byte.
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr().cast(),
        iov_len: 1,
    };

    let mut cmsg_buf = CmsgBuf {
        buf: [0u8; CMSG_SPACE],
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: accessing the `buf` field of a zero-initialised union is safe.
    msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
    #[allow(clippy::cast_possible_truncation)]
    {
        msg.msg_controllen = CMSG_SPACE as _;
    }

    // SAFETY: `raw_fd` is a valid socket, `msg` points to properly initialised
    // buffers, and the control-message buffer is large enough for 2 fds.
    let n = unsafe { libc::recvmsg(raw_fd, &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed before ring fds received",
        ));
    }
    if n != 1 || dummy[0] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected LB9P transport marker",
        ));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SCM_RIGHTS control data was truncated",
        ));
    }

    // Walk the control messages looking for SCM_RIGHTS.
    // SAFETY: `msg` was filled by a successful `recvmsg`; iterating with
    // `CMSG_FIRSTHDR`/`CMSG_NXTHDR` is the standard way to walk ancillary
    // data.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is a valid pointer returned by CMSG_FIRSTHDR/CMSG_NXTHDR.
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
            // SAFETY: the kernel placed the fd array right after the cmsghdr.
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
            if (hdr.cmsg_len as usize) < header_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed SCM_RIGHTS message",
                ));
            }
            let fd_count = ((hdr.cmsg_len as usize) - header_len) / size_of::<i32>();
            if fd_count != 2 {
                for i in 0..fd_count {
                    // SAFETY: `data_ptr` points to `fd_count` consecutive `i32`
                    // values written by the kernel for this SCM_RIGHTS message.
                    let leaked_fd =
                        unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>().add(i)) };
                    // SAFETY: these fds were opened in this process by recvmsg;
                    // close any unexpected extras before returning an error.
                    unsafe {
                        libc::close(leaked_fd);
                    }
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected exactly 2 fds in SCM_RIGHTS, got {fd_count}"),
                ));
            }
            // SAFETY: `data_ptr` points to at least 2 consecutive `i32` values
            // written by the kernel.
            let tx_raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>()) };
            let rx_raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>().add(1)) };
            // SAFETY: these are valid open fds received via SCM_RIGHTS.
            let tx_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(tx_raw) };
            let rx_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(rx_raw) };
            return Ok((tx_fd, rx_fd));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "no SCM_RIGHTS message received with ring fds",
    ))
}

#[cfg(any(unix, windows))]
const LB9P_RING_ACK: u8 = b'K';

#[cfg(unix)]
const LB9P_RING_MARKER: u8 = 0;

#[cfg(windows)]
const LB9P_RING_MARKER: u8 = litebox_common_windows::shmem_ring::TRANSPORT_MARKER;

#[cfg(windows)]
fn recv_ring_connection_info(
    stream: &mut IpcStream,
) -> Result<litebox_common_windows::shmem_ring::RingConnectionInfo, std::io::Error> {
    use std::io::Read as _;

    stream.set_nonblocking(false)?;
    let mut payload = [0u8; 1 + litebox_common_windows::shmem_ring::CONNECTION_INFO_SIZE];
    let deadline = Instant::now() + LB9P_RING_UPGRADE_TIMEOUT;
    let mut got = 0usize;
    while got < payload.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out receiving Windows ring metadata",
            ));
        }

        let timeout = if remaining < Duration::from_millis(1) {
            Duration::from_millis(1)
        } else {
            remaining
        };
        stream.set_read_timeout(Some(timeout))?;

        match stream.read(&mut payload[got..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before Windows ring metadata was complete",
                ));
            }
            Ok(n) => got += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }

    if payload[0] != LB9P_RING_MARKER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected LB9P transport marker",
        ));
    }

    let info_bytes: &[u8; litebox_common_windows::shmem_ring::CONNECTION_INFO_SIZE] = payload[1..]
        .try_into()
        .expect("fixed-size ring metadata payload");
    litebox_common_windows::shmem_ring::RingConnectionInfo::decode(info_bytes).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid Windows ring metadata: {err}"),
        )
    })
}

#[cfg(any(unix, windows))]
fn ack_ring_connection(stream: &mut IpcStream) {
    stream.set_nonblocking(false).ok();
    use std::io::Write as _;
    let _ = stream.write_all(&[LB9P_RING_ACK]);
}

#[cfg(unix)]
fn handle_shared_memory_lb9p_connection(stream: &mut IpcStream, ring_spawner: RingServiceSpawner) {
    match recv_ring_fds(stream) {
        Ok((tx_fd, rx_fd)) => {
            match litebox_common_linux::shmem_ring::ShmemRingPair::open(tx_fd, rx_fd) {
                Ok((writer, reader)) => {
                    ack_ring_connection(stream);
                    ring_spawner(writer, reader);
                    info!("direct 9P channel connected (shared memory)");
                }
                Err(e) => {
                    warn!("failed to open ring pair: {e}");
                }
            }
        }
        Err(e) => {
            warn!("failed to receive ring fds: {e}");
        }
    }
}

#[cfg(windows)]
fn handle_shared_memory_lb9p_connection(stream: &mut IpcStream, ring_spawner: RingServiceSpawner) {
    match recv_ring_connection_info(stream) {
        Ok(info) => match litebox_common_windows::shmem_ring::ShmemRingPair::open(&info) {
            Ok((writer, reader)) => {
                ack_ring_connection(stream);
                ring_spawner(writer, reader);
                info!("direct 9P channel connected (shared memory)");
            }
            Err(e) => {
                warn!("failed to open Windows ring pair: {e}");
            }
        },
        Err(e) => {
            warn!("failed to receive Windows ring metadata: {e}");
        }
    }
}

#[cfg(any(unix, windows))]
struct RingUpgradePermit;

#[cfg(any(unix, windows))]
impl RingUpgradePermit {
    fn acquire() -> Option<Self> {
        loop {
            let current = ACTIVE_LB9P_RING_UPGRADES.load(Ordering::Acquire);
            if current >= MAX_CONCURRENT_LB9P_RING_UPGRADES {
                return None;
            }
            if ACTIVE_LB9P_RING_UPGRADES
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Self);
            }
        }
    }
}

#[cfg(any(unix, windows))]
impl Drop for RingUpgradePermit {
    fn drop(&mut self) {
        ACTIVE_LB9P_RING_UPGRADES.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(any(unix, windows))]
fn spawn_shared_memory_lb9p_connection(stream: IpcStream, ring_spawner: RingServiceSpawner) {
    let Some(permit) = RingUpgradePermit::acquire() else {
        warn!("dropping LB9P ring upgrade connection: too many concurrent background upgrades");
        return;
    };

    if let Err(e) = std::thread::Builder::new()
        .name("lb9p-ring-upgrade".into())
        .spawn(move || {
            let _permit = permit;
            let mut stream = stream;
            handle_shared_memory_lb9p_connection(&mut stream, ring_spawner);
        })
    {
        warn!("failed to spawn LB9P ring upgrade thread: {e}");
    }
}

// ---------------------------------------------------------------------------
// Local service registry — broker-internal services on BROKER_IP
// ---------------------------------------------------------------------------

/// Factory that spawns a service handler on a bidirectional byte stream.
///
/// The handler runs in a separate thread. The returned `JoinHandle` is kept
/// so the proxy can detect service exit.
pub type ServiceSpawner =
    Box<dyn Fn(std::net::TcpStream) -> std::thread::JoinHandle<()> + Send + Sync>;

/// Factory that spawns a service handler on a shared-memory ring buffer pair.
///
/// Used for direct IPC connections (LB9P handshake) where the runner upgrades
/// the control stream to a platform-specific shared-memory transport. The
/// handler runs in a separate thread.
#[cfg(any(unix, windows))]
pub type RingServiceSpawner = std::sync::Arc<
    dyn Fn(
            crate::nine_p::transport::ShmemRingWriter,
            crate::nine_p::transport::ShmemRingReader,
        ) -> std::thread::JoinHandle<()>
        + Send
        + Sync,
>;

/// Registry of broker-internal services keyed by TCP port.
///
/// When a guest connects to `BROKER_IP:<port>`, the proxy looks up this
/// registry. If a service is registered, the connection is handled
/// in-process via a loopback TCP pair instead of opening a host TCP socket.
///
/// On Unix and Windows, services may also be registered with a ring spawner
/// for direct shared-memory IPC via the `LB9P` handshake path.
pub struct LocalServiceRegistry {
    services: HashMap<u16, ServiceSpawner>,
    #[cfg(any(unix, windows))]
    ring_services: HashMap<u16, RingServiceSpawner>,
}

impl Default for LocalServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            #[cfg(any(unix, windows))]
            ring_services: HashMap::new(),
        }
    }

    /// Register a service on the given port. The `spawner` is called with one
    /// end of a loopback TCP pair; the other end is relayed to the smoltcp TCP
    /// socket.
    pub fn register(&mut self, port: u16, spawner: ServiceSpawner) {
        self.services.insert(port, spawner);
    }

    /// Register a shared-memory ring spawner for the given port.
    ///
    /// When a direct IPC connection (LB9P) arrives, the proxy receives
    /// platform-specific ring metadata and calls this spawner with the
    /// resulting ring writer/reader pair.
    #[cfg(any(unix, windows))]
    pub fn register_ring(&mut self, port: u16, spawner: RingServiceSpawner) {
        self.ring_services.insert(port, spawner);
    }

    fn get(&self, port: u16) -> Option<&ServiceSpawner> {
        self.services.get(&port)
    }

    #[cfg(any(unix, windows))]
    fn get_ring(&self, port: u16) -> Option<RingServiceSpawner> {
        self.ring_services.get(&port).cloned()
    }
}

/// State for a TCP bridge to a broker-internal (local) service.
/// Analogous to `TcpBridge` but the "host side" is a loopback TCP stream
/// connected to an in-process service thread.
#[allow(dead_code)]
struct LocalBridge {
    smoltcp_handle: SocketHandle,
    /// Our end of the loopback pair — the service thread owns the other end.
    stream: std::net::TcpStream,
    dest_port: u16,
    host_eof: bool,
    _thread: std::thread::JoinHandle<()>,
}

/// Run the network proxy event loop.
///
/// `ipc_fd` is one end of an IPC stream connected to the runner.
/// This function takes ownership and runs until the IPC connection closes.
///
/// If `magic_prefix` is `Some`, the caller (e.g. [`accept_ipc_client`]) has
/// already read and validated the 4-byte `LBNP` magic from the fd.  The
/// handshake then only reads the remaining 4 bytes (version + MTU).
///
/// If `local_services` is provided, connections to `BROKER_IP:<port>` are
/// handled in-process by the registered service instead of proxied to the host.
///
/// If `accept_listener` is provided, the event loop also accepts new IPC
/// connections on it. Additional `LBNP` clients are handed off to their own
/// proxy sessions, while a connection sending `LB9P` magic is dispatched to the
/// first registered local service (port 5640 / 9P) as a direct byte-stream
/// channel, bypassing smoltcp entirely.
///
/// If `handshake_done` is true, the caller (e.g. [`accept_ipc_client`]) has
/// already completed the full LBNP handshake on the fd.
pub fn run(
    ipc_fd: IpcStream,
    handshake_done: bool,
    local_services: Option<LocalServiceRegistry>,
    accept_listener: Option<&IpcListener>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_with_session_slots(
        ipc_fd,
        handshake_done,
        local_services,
        accept_listener,
        Arc::new(AtomicUsize::new(0)),
    )
}

pub fn run_with_session_slots(
    ipc_fd: IpcStream,
    handshake_done: bool,
    local_services: Option<LocalServiceRegistry>,
    accept_listener: Option<&IpcListener>,
    session_slots: Arc<AtomicUsize>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_inner(
        ipc_fd,
        handshake_done,
        Arc::new(local_services.unwrap_or_default()),
        accept_listener,
        session_slots,
    )
}

fn run_inner(
    _ipc_fd: IpcStream,
    _handshake_done: bool,
    _local_services: Arc<LocalServiceRegistry>,
    _accept_listener: Option<&IpcListener>,
    _session_slots: Arc<AtomicUsize>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Full event loop implementation added in the next PR.
    todo!("net_proxy event loop")
}

/// Accept the IPC network-proxy client from `listener`.
///
/// Loops until a connection either:
/// - completes the full LBNP handshake and returns `Ok(Some(stream))`, or
/// - is recognized as a direct local `LB9P` service connection and handled
///   inline, returning `Ok(None)` so the caller can keep listening.
///
/// Connections that are slow, send wrong magic/version/MTU, or close early are
/// dropped so a stray local client cannot monopolize the listener.
///
/// Returns an error if no valid client arrives within `overall_timeout`. Pass
/// `None` to wait indefinitely.
pub fn accept_ipc_client(
    listener: &IpcListener,
    local_services: Option<&LocalServiceRegistry>,
    overall_timeout: Option<Duration>,
) -> Result<Option<IpcStream>, Box<dyn std::error::Error>> {
    let deadline = overall_timeout.map(|d| Instant::now() + d);
    let per_client_timeout = Duration::from_secs(2);

    loop {
        if deadline.is_some_and(|dl| Instant::now() >= dl) {
            return Err("no valid LBNP client connected within timeout".into());
        }

        // Non-blocking accept.
        let stream = match listener.accept() {
            Ok(Some(stream)) => stream,
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                return Err(format!("listener accept error: {e}").into());
            }
        };

        stream.set_nonblocking(true).ok();
        let raw_socket = stream.raw();

        // Read the 4-byte magic prefix first so we can distinguish LBNP from
        // direct LB9P local-service connections.
        let client_deadline = Instant::now() + per_client_timeout;
        let mut buf = [0u8; 8];
        let mut got = 0usize;
        let magic_ok = loop {
            if Instant::now() >= client_deadline {
                break false;
            }
            let remaining_ms = client_deadline
                .saturating_duration_since(Instant::now())
                .as_millis();
            let mut rpfd = PollFd {
                fd: raw_socket,
                events: POLLIN,
                revents: 0,
            };
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let ret = sock_compat::poll_fds(
                std::slice::from_mut(&mut rpfd),
                remaining_ms.min(100) as i32,
            );
            if ret <= 0 {
                continue;
            }
            let n = sock_compat::recv_nb(raw_socket, &mut buf[got..4], 0);
            if n > 0 {
                #[allow(clippy::cast_sign_loss)]
                {
                    got += n as usize;
                }
                if got == 4 {
                    break true;
                }
            } else if n == 0 {
                break false; // peer closed
            } else {
                let err = sock_compat::last_socket_error();
                if !sock_compat::is_would_block(err) {
                    break false;
                }
            }
        };

        if !magic_ok || got < 4 {
            debug!("rejected connection: only got {got}/4 magic bytes");
            continue;
        }

        if &buf[0..4] == b"LB9P" {
            let Some(local_services) = local_services else {
                debug!("rejected connection: LB9P client arrived with no local services available");
                continue;
            };

            #[cfg(any(unix, windows))]
            {
                if local_services.get_ring(5640).is_some() {
                    let mut marker = [0u8; 1];
                    let marker_ready = loop {
                        match stream.peek(&mut marker) {
                            Ok(0) => {
                                if Instant::now() >= client_deadline {
                                    break false;
                                }
                                let remaining_ms = client_deadline
                                    .saturating_duration_since(Instant::now())
                                    .as_millis();
                                let mut rpfd = PollFd {
                                    fd: raw_socket,
                                    events: POLLIN,
                                    revents: 0,
                                };
                                #[allow(
                                    clippy::cast_possible_truncation,
                                    clippy::cast_possible_wrap
                                )]
                                let ret = sock_compat::poll_fds(
                                    std::slice::from_mut(&mut rpfd),
                                    remaining_ms.min(100) as i32,
                                );
                                if ret <= 0 {
                                    continue;
                                }
                            }
                            Ok(_) => break true,
                            Err(e) => {
                                warn!("failed to classify LB9P transport: {e}");
                                break false;
                            }
                        }
                    };

                    if !marker_ready {
                        debug!("rejected LB9P connection: timed out waiting for transport marker");
                        continue;
                    }

                    if marker[0] == LB9P_RING_MARKER {
                        let Some(ring_spawner) = local_services.get_ring(5640) else {
                            warn!("LB9P ring marker received but no ring service registered");
                            continue;
                        };
                        spawn_shared_memory_lb9p_connection(stream, ring_spawner);
                        return Ok(None);
                    }
                }
            }

            if let Some(spawner) = local_services.get(5640) {
                let stream = sock_compat::into_blocking_tcp_stream(stream);
                spawner(stream);
                info!("direct 9P channel connected");
            } else {
                warn!("LB9P connection but no 9P service registered");
            }
            return Ok(None);
        }

        if &buf[0..4] != HANDSHAKE_MAGIC {
            debug!("rejected connection: wrong magic {:02x?}", &buf[0..4]);
            continue;
        }

        // Read the remaining 4 bytes of the LBNP handshake:
        // version(2) + MTU(2).
        let ok = loop {
            if Instant::now() >= client_deadline {
                break false;
            }
            let remaining_ms = client_deadline
                .saturating_duration_since(Instant::now())
                .as_millis();
            let mut rpfd = PollFd {
                fd: raw_socket,
                events: POLLIN,
                revents: 0,
            };
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let ret = sock_compat::poll_fds(
                std::slice::from_mut(&mut rpfd),
                remaining_ms.min(100) as i32,
            );
            if ret <= 0 {
                continue;
            }
            let n = sock_compat::recv_nb(raw_socket, &mut buf[got..], 0);
            if n > 0 {
                #[allow(clippy::cast_sign_loss)]
                {
                    got += n as usize;
                }
                if got == 8 {
                    break true;
                }
            } else if n == 0 {
                break false; // peer closed
            } else {
                let err = sock_compat::last_socket_error();
                if !sock_compat::is_would_block(err) {
                    break false;
                }
            }
        };

        if !ok || got < 8 {
            debug!("rejected connection: only got {got}/8 LBNP handshake bytes");
            continue;
        }

        let version = u16::from_le_bytes([buf[4], buf[5]]);
        let mtu = u16::from_le_bytes([buf[6], buf[7]]);
        #[allow(clippy::cast_possible_truncation)]
        let our_mtu = DEVICE_MTU as u16;
        if version != HANDSHAKE_VERSION {
            debug!("rejected connection: version {version} != {HANDSHAKE_VERSION}");
            continue;
        }
        if mtu != our_mtu {
            debug!("rejected connection: MTU {mtu} != {our_mtu}");
            continue;
        }

        // Send handshake response.
        let mut response = [0u8; 8];
        response[0..4].copy_from_slice(HANDSHAKE_MAGIC);
        response[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
        response[6..8].copy_from_slice(&our_mtu.to_le_bytes());

        let mut sent = 0usize;
        let send_deadline = Instant::now() + per_client_timeout;
        let send_ok = loop {
            if Instant::now() >= send_deadline {
                break false;
            }
            let n = sock_compat::send_nb(raw_socket, &response[sent..], 0);
            if n > 0 {
                #[allow(clippy::cast_sign_loss)]
                {
                    sent += n as usize;
                }
                if sent == 8 {
                    break true;
                }
            } else if n == 0 {
                break false;
            } else {
                let err = sock_compat::last_socket_error();
                if sock_compat::is_would_block(err) {
                    let mut wpfd = PollFd {
                        fd: raw_socket,
                        events: POLLOUT,
                        revents: 0,
                    };
                    sock_compat::poll_fds(std::slice::from_mut(&mut wpfd), 100);
                    continue;
                }
                break false;
            }
        };

        if !send_ok {
            debug!("rejected connection: failed to send handshake response");
            continue;
        }

        info!(
            version,
            mtu, "accepted valid LBNP client, handshake complete"
        );
        return Ok(Some(stream));
    }
}

/// Perform the IPC handshake (broker side).
///
/// Reads all 8 bytes (magic + version + MTU), validates, and sends the
/// response.  Used only by the `--network-proxy-fd` path where the runner
/// passes the fd directly.
fn perform_handshake(fd: &IpcStream) -> Result<(), Box<dyn std::error::Error>> {
    // Wait for handshake with 10s timeout.
    let mut pfd = PollFd {
        fd: fd.raw(),
        events: POLLIN,
        revents: 0,
    };
    let ret = sock_compat::poll_fds(std::slice::from_mut(&mut pfd), 10_000);
    if ret <= 0 {
        return Err("IPC handshake timeout".into());
    }

    // Read handshake: magic (4) + version (2) + MTU (2) = 8 bytes.
    // Handles would-block/short reads on non-blocking sockets.
    let mut buf = [0u8; 8];
    let mut read = 0;
    let deadline = Instant::now() + Duration::from_secs(10);
    while read < 8 {
        let ret = sock_compat::recv_nb(fd.raw(), &mut buf[read..], 0);
        if ret > 0 {
            #[allow(clippy::cast_sign_loss)]
            {
                read += ret as usize;
            }
        } else if ret == 0 {
            return Err("IPC handshake: peer closed".into());
        } else {
            let err = sock_compat::last_socket_error();
            if sock_compat::is_would_block(err) {
                if Instant::now() > deadline {
                    return Err("IPC handshake read timeout".into());
                }
                let mut rpfd = PollFd {
                    fd: fd.raw(),
                    events: POLLIN,
                    revents: 0,
                };
                sock_compat::poll_fds(std::slice::from_mut(&mut rpfd), 100);
                continue;
            }
            return Err(format!("IPC handshake read failed: errno {err}").into());
        }
    }

    validate_handshake_request(&buf)?;
    send_handshake_response(fd)
}

fn validate_handshake_request(buf: &[u8; 8]) -> Result<(), Box<dyn std::error::Error>> {
    if &buf[0..4] != HANDSHAKE_MAGIC {
        return Err(format!(
            "IPC handshake: bad magic {:02x?}, expected {:02x?}",
            &buf[0..4],
            HANDSHAKE_MAGIC
        )
        .into());
    }

    let version = u16::from_le_bytes([buf[4], buf[5]]);
    let mtu = u16::from_le_bytes([buf[6], buf[7]]);
    info!(version, mtu, "IPC handshake received");

    if version != HANDSHAKE_VERSION {
        return Err(format!(
            "IPC handshake: unsupported version {version}, expected {HANDSHAKE_VERSION}"
        )
        .into());
    }

    #[allow(clippy::cast_possible_truncation)]
    let our_mtu = DEVICE_MTU as u16;
    if mtu != our_mtu {
        return Err(
            format!("IPC handshake: MTU mismatch — peer sent {mtu}, we expect {our_mtu}").into(),
        );
    }
    Ok(())
}

fn send_handshake_response(fd: &IpcStream) -> Result<(), Box<dyn std::error::Error>> {
    // Send handshake response (retry on would-block).
    #[allow(clippy::cast_possible_truncation)]
    let response_mtu = DEVICE_MTU as u16;
    let mut response = [0u8; 8];
    response[0..4].copy_from_slice(HANDSHAKE_MAGIC);
    response[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
    response[6..8].copy_from_slice(&response_mtu.to_le_bytes());

    let mut sent = 0usize;
    while sent < 8 {
        let ret = sock_compat::send_nb(fd.raw(), &response[sent..], 0);
        if ret > 0 {
            #[allow(clippy::cast_sign_loss)]
            {
                sent += ret as usize;
            }
        } else if ret == 0 {
            return Err("IPC handshake response: peer closed".into());
        } else {
            let err = sock_compat::last_socket_error();
            if sock_compat::is_would_block(err) {
                let mut wpfd = PollFd {
                    fd: fd.raw(),
                    events: POLLOUT,
                    revents: 0,
                };
                sock_compat::poll_fds(std::slice::from_mut(&mut wpfd), 100);
                continue;
            }
            return Err(format!("IPC handshake response send failed: errno {err}").into());
        }
    }

    Ok(())
}
