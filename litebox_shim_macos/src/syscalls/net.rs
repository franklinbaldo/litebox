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

use crate::{ConstPtr, MutPtr};

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
