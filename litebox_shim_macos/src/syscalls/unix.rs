// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AF_UNIX socket implementation.
//!
//! Uses in-memory ring buffers (`Channel`) for data transfer between connected
//! Unix sockets. Not routed through the smoltcp network stack.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use litebox_common_macos::errno::Errno;

use crate::syscalls::net::{SockType, SocketOptions, UnixSocketAddr, SHUT_RD, SHUT_WR, SHUT_RDWR};
use crate::{Platform, ShimFS, Task};

// ---------------------------------------------------------------------------
// Channel â VecDeque-backed ring buffer for Unix socket data transfer
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
    /// Connected stream socket â has two channels for bidirectional data.
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
            UnixSocketInner::Listening(backlog) => backlog.try_connect(client_addr),
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
// Backlog â accept queue for listening stream sockets
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
// UnixAddrEntry â what's stored in the address table
// ---------------------------------------------------------------------------

/// Entry in the Unix socket address table.
pub(crate) enum UnixAddrEntry<FS: ShimFS> {
    /// A listening stream socket (contains Backlog inside).
    /// We store the whole socket so connect() can call try_push_to_backlog().
    StreamListener(Arc<UnixSocket<FS>>),
    /// A bound datagram socket's receive queue.
    DatagramReceiver(Arc<DatagramChannel>),
}
