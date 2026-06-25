// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-domain-socket broker channel for hosted userland deployments.
//!
//! This module deliberately uses `std` because Unix-domain sockets and `std::io`
//! framing are hosted userland concerns. Portable broker interfaces live in the
//! no_std protocol, local, core, and host crates.

use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use litebox_broker_protocol::channel::{
    HostControlChannel, HostReceive, LocalControlChannel, PeerCredential,
};
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerRequest, BrokerResponse,
};
use litebox_broker_protocol::wire::{
    WireError, decode_handshake_request, decode_handshake_response, decode_request,
    decode_response, encode_handshake_request, encode_handshake_response, encode_request,
    encode_response,
};

const MAX_FRAME_LEN: usize = 64 * 1024;

/// Local-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamLocalControlChannel {
    stream: UnixStream,
    setup_deadline: Option<Instant>,
}

impl UnixStreamLocalControlChannel {
    /// Creates a local control channel from an already-connected Unix stream.
    pub const fn from_connected(stream: UnixStream) -> Self {
        Self {
            stream,
            setup_deadline: None,
        }
    }

    /// Connects to a userland broker Unix socket.
    pub fn connect(path: impl AsRef<Path>) -> IoResult<Self> {
        UnixStream::connect(path).map(Self::from_connected)
    }

    /// Connects to a userland broker Unix socket with a deadline for setup I/O.
    pub fn connect_with_setup_deadline(
        path: impl AsRef<Path>,
        deadline: Instant,
    ) -> IoResult<Self> {
        connect_unix_stream_with_deadline(path.as_ref(), deadline).map(|stream| Self {
            stream,
            setup_deadline: Some(deadline),
        })
    }
}

/// Host-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamHostControlChannel {
    stream: UnixStream,
}

impl UnixStreamHostControlChannel {
    /// Creates a host control channel from an accepted Unix stream.
    pub const fn from_accepted(stream: UnixStream) -> Self {
        Self { stream }
    }
}

impl LocalControlChannel for UnixStreamLocalControlChannel {
    type Error = Error;

    fn send_handshake_request(&mut self, request: &BrokerHandshakeRequest) -> IoResult<()> {
        let frame = encode_handshake_request(request.clone());
        write_frame_with_deadline(&mut self.stream, &frame, self.setup_deadline)
    }

    fn recv_handshake_response(&mut self) -> IoResult<Option<BrokerHandshakeResponse>> {
        let frame = read_frame_with_deadline(&mut self.stream, self.setup_deadline)?;
        if self.setup_deadline.take().is_some() {
            self.stream.set_read_timeout(None)?;
            self.stream.set_write_timeout(None)?;
        }
        match frame {
            Some(frame) => decode_handshake_response(&frame)
                .map(Some)
                .map_err(wire_error),
            None => Ok(None),
        }
    }

    fn send_request(&mut self, request: &BrokerRequest) -> IoResult<()> {
        let frame = encode_request(request.clone());
        write_frame_with_deadline(&mut self.stream, &frame, None)
    }

    fn recv_response(&mut self) -> IoResult<Option<BrokerResponse>> {
        match read_frame_with_deadline(&mut self.stream, None)? {
            Some(frame) => decode_response(&frame).map(Some).map_err(wire_error),
            None => Ok(None),
        }
    }
}

impl HostControlChannel for UnixStreamHostControlChannel {
    type Error = Error;

    fn peer_credential(&self) -> IoResult<PeerCredential> {
        // TODO(broker): replace the PoC placeholder with Unix peer credential extraction
        // before this channel is used as an authenticated deployment boundary.
        Ok(PeerCredential::Unauthenticated)
    }

    fn recv_handshake_request(&mut self) -> IoResult<HostReceive<BrokerHandshakeRequest>> {
        let Some(frame) = read_frame_with_deadline(&mut self.stream, None)? else {
            return Ok(HostReceive::PeerClosed);
        };
        match decode_handshake_request(&frame) {
            Ok(request) => Ok(HostReceive::Message(request)),
            Err(WireError::WrongMessagePhase) => Ok(HostReceive::ProtocolViolation),
            Err(error) => Err(wire_error(error)),
        }
    }

    fn send_handshake_response(&mut self, response: &BrokerHandshakeResponse) -> IoResult<()> {
        write_frame_with_deadline(
            &mut self.stream,
            &encode_handshake_response(response.clone()),
            None,
        )
    }

    fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        let Some(frame) = read_frame_with_deadline(&mut self.stream, None)? else {
            return Ok(HostReceive::PeerClosed);
        };
        match decode_request(&frame) {
            Ok(request) => Ok(HostReceive::Message(request)),
            Err(WireError::WrongMessagePhase) => Ok(HostReceive::ProtocolViolation),
            Err(error) => Err(wire_error(error)),
        }
    }

    fn send_response(&mut self, response: &BrokerResponse) -> IoResult<()> {
        write_frame_with_deadline(&mut self.stream, &encode_response(response.clone()), None)
    }
}

fn read_frame_with_deadline(
    stream: &mut UnixStream,
    deadline: Option<Instant>,
) -> IoResult<Option<Vec<u8>>> {
    let mut len_buf = [0; 4];
    let mut read = 0;
    while read < len_buf.len() {
        refresh_stream_io_deadline(stream, deadline)?;
        match stream.read(&mut len_buf[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => return Err(invalid_data("truncated broker frame length")),
            Ok(len) => read += len,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_LEN {
        return Err(invalid_data("invalid broker frame length"));
    }

    let mut frame = vec![0; len];
    let mut read = 0;
    while read < frame.len() {
        refresh_stream_io_deadline(stream, deadline)?;
        match stream.read(&mut frame[read..]) {
            Ok(0) => return Err(invalid_data("truncated broker frame")),
            Ok(len) => read += len,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Some(frame))
}

fn write_frame_with_deadline(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Option<Instant>,
) -> IoResult<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
        return Err(invalid_data("invalid broker frame length"));
    }
    let len = u32::try_from(frame.len()).map_err(|_| invalid_data("broker frame too large"))?;
    write_all_with_deadline(stream, &len.to_le_bytes(), deadline)?;
    write_all_with_deadline(stream, frame, deadline)
}

fn write_all_with_deadline(
    stream: &mut UnixStream,
    mut buffer: &[u8],
    deadline: Option<Instant>,
) -> IoResult<()> {
    while !buffer.is_empty() {
        refresh_stream_io_deadline(stream, deadline)?;
        match stream.write(buffer) {
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "failed to write broker frame",
                ));
            }
            Ok(written) => buffer = &buffer[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn connect_unix_stream_with_deadline(path: &Path, deadline: Instant) -> IoResult<UnixStream> {
    let (addr, addr_len) = unix_socket_addr(path)?;
    _ = io_timeout_for_deadline(deadline)?;
    let stream = new_nonblocking_unix_stream()?;

    loop {
        // SAFETY: `stream` owns a valid AF_UNIX stream socket, and `addr`/`addr_len`
        // describe a live sockaddr_un built from `path` for the duration of this call.
        let result = unsafe {
            libc::connect(
                stream.as_raw_fd(),
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                addr_len,
            )
        };
        if result == 0 {
            set_fd_blocking(stream.as_raw_fd())?;
            return Ok(UnixStream::from(stream));
        }

        let error = Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            _ = io_timeout_for_deadline(deadline)?;
            continue;
        }
        if error
            .raw_os_error()
            .is_some_and(|code| code == libc::EISCONN)
        {
            set_fd_blocking(stream.as_raw_fd())?;
            return Ok(UnixStream::from(stream));
        }
        if error.raw_os_error().is_some_and(connect_in_progress_error) {
            wait_for_connect(stream.as_raw_fd(), deadline)?;
            set_fd_blocking(stream.as_raw_fd())?;
            return Ok(UnixStream::from(stream));
        }
        return Err(error);
    }
}

fn unix_socket_addr(path: &Path) -> IoResult<(libc::sockaddr_un, libc::socklen_t)> {
    let path = path.as_os_str().as_bytes();
    if path.contains(&0) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "broker socket path contains NUL byte",
        ));
    }

    // SAFETY: `sockaddr_un` is a plain C socket address type; all-zero is a
    // valid initialized value before setting the address family and path.
    let mut addr = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    addr.sun_family =
        libc::sa_family_t::try_from(libc::AF_UNIX).expect("AF_UNIX fits in libc::sa_family_t");
    if path.len() >= addr.sun_path.len() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "broker socket path is too long",
        ));
    }

    // SAFETY: `path.len() < addr.sun_path.len()` above, so the copy stays
    // within `sun_path`; `sockaddr_un` was zeroed, leaving the required NUL.
    unsafe {
        std::ptr::copy_nonoverlapping(
            path.as_ptr(),
            addr.sun_path.as_mut_ptr().cast::<u8>(),
            path.len(),
        );
    }

    let addr_len =
        libc::socklen_t::try_from(std::mem::size_of::<libc::sa_family_t>() + path.len() + 1)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "broker socket path is too long"))?;
    Ok((addr, addr_len))
}

fn new_nonblocking_unix_stream() -> IoResult<OwnedFd> {
    let socket_type = libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
    // SAFETY: `socket` is called with constant AF_UNIX/SOCK_STREAM parameters
    // and returns either a new owned file descriptor or -1 with errno set.
    let fd = unsafe { libc::socket(libc::AF_UNIX, socket_type, 0) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }

    // SAFETY: `fd` was returned by `socket` above and is uniquely owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn wait_for_connect(fd: RawFd, deadline: Instant) -> IoResult<()> {
    loop {
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let timeout = poll_timeout_for_deadline(deadline)?;
        // SAFETY: `pollfd` points to one initialized pollfd entry that remains
        // valid for the duration of the call.
        let result = unsafe { libc::poll(std::ptr::addr_of_mut!(pollfd), 1, timeout) };
        if result == 0 {
            return Err(Error::new(
                ErrorKind::TimedOut,
                "broker connect deadline expired",
            ));
        }
        if result < 0 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }

        match socket_error(fd)? {
            0 => return Ok(()),
            code if connect_in_progress_error(code) => {}
            code => return Err(Error::from_raw_os_error(code)),
        }
    }
}

fn poll_timeout_for_deadline(deadline: Instant) -> IoResult<i32> {
    let timeout = io_timeout_for_deadline(deadline)?;
    let max = u128::from(u32::try_from(i32::MAX).expect("i32::MAX fits in u32"));
    let millis = timeout.as_millis().clamp(1, max);
    Ok(i32::try_from(millis).expect("poll timeout is clamped to i32::MAX"))
}

fn socket_error(fd: RawFd) -> IoResult<i32> {
    let mut error = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of_val(&error))
        .expect("SO_ERROR length fits in libc::socklen_t");
    // SAFETY: `error` and `len` are valid out-pointers for SO_ERROR on `fd`.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            std::ptr::addr_of_mut!(error).cast::<libc::c_void>(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if result < 0 {
        return Err(Error::last_os_error());
    }
    Ok(error)
}

fn set_fd_blocking(fd: RawFd) -> IoResult<()> {
    // SAFETY: `fcntl` does not take ownership of `fd`; F_GETFL reads the status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: `fcntl` does not take ownership of `fd`; F_SETFL updates only
    // descriptor status flags and preserves all flags except O_NONBLOCK.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    if result < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

fn connect_in_progress_error(code: i32) -> bool {
    code == libc::EINPROGRESS
        || code == libc::EALREADY
        || code == libc::EAGAIN
        || code == libc::EWOULDBLOCK
}

fn refresh_stream_io_deadline(stream: &UnixStream, deadline: Option<Instant>) -> IoResult<()> {
    if let Some(deadline) = deadline {
        let timeout = io_timeout_for_deadline(deadline)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
    }
    Ok(())
}

fn io_timeout_for_deadline(deadline: Instant) -> IoResult<Duration> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|timeout| !timeout.is_zero())
        .ok_or_else(|| Error::new(ErrorKind::TimedOut, "broker I/O deadline expired"))?;
    Ok(timeout)
}

fn invalid_data(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn wire_error(error: WireError) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("invalid broker wire message: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn frame_round_trip() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        write_frame_with_deadline(&mut writer, &[1, 2, 3], None).unwrap();

        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap()
                .unwrap(),
            [1, 2, 3]
        );
    }

    #[test]
    fn clean_eof_before_frame_is_close() {
        let (writer, mut reader) = UnixStream::pair().unwrap();
        drop(writer);

        assert!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn malformed_frames_are_invalid() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&[1, 0]).unwrap();
        drop(writer);
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&0u32.to_le_bytes()).unwrap();
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .write_all(&u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_le_bytes())
            .unwrap();
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&4u32.to_le_bytes()).unwrap();
        writer.write_all(&[1, 2]).unwrap();
        drop(writer);
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn local_connect_setup_deadline_applies_before_connect() {
        let path = temporary_socket_path("expired-connect");
        let deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("test deadline should be representable");
        let Err(error) =
            UnixStreamLocalControlChannel::connect_with_setup_deadline(&path, deadline)
        else {
            panic!("connect unexpectedly succeeded after setup deadline");
        };
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn local_connect_setup_deadline_returns_blocking_stream() {
        let path = temporary_socket_path("blocking-connect");
        let listener = UnixListener::bind(&path).unwrap();

        let mut local = UnixStreamLocalControlChannel::connect_with_setup_deadline(
            &path,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let (host_stream, _) = listener.accept().unwrap();
        let mut host = UnixStreamHostControlChannel::from_accepted(host_stream);

        local
            .send_handshake_request(&BrokerHandshakeRequest {
                protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        assert_eq!(
            host.recv_handshake_request().unwrap(),
            HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            })
        );

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn local_handshake_read_setup_deadline_is_wall_clock() {
        let (mut host_stream, local_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamLocalControlChannel {
            stream: local_stream,
            setup_deadline: Some(Instant::now() + Duration::from_millis(50)),
        };

        let reader = std::thread::spawn(move || channel.recv_handshake_response().unwrap_err());
        host_stream.write_all(&8u32.to_le_bytes()).unwrap();
        for _ in 0..8 {
            std::thread::sleep(Duration::from_millis(20));
            if host_stream.write_all(&[0]).is_err() {
                break;
            }
        }

        let error = reader.join().expect("timeout reader panicked");
        assert!(
            matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "unexpected timeout error kind: {error:?}"
        );
    }

    #[test]
    fn host_reports_wrong_phase_request_frames_as_protocol_violations() {
        let (mut peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamHostControlChannel::from_accepted(host_stream);
        write_frame_with_deadline(
            &mut peer_stream,
            &encode_request(BrokerRequest::Event(
                litebox_broker_protocol::message::EventRequest::Create(
                    litebox_broker_protocol::event::CreateEventRequest { initial_count: 0 },
                ),
            )),
            None,
        )
        .unwrap();
        assert_eq!(
            channel.recv_handshake_request().unwrap(),
            HostReceive::ProtocolViolation
        );

        let (mut peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamHostControlChannel::from_accepted(host_stream);
        write_frame_with_deadline(
            &mut peer_stream,
            &encode_handshake_request(BrokerHandshakeRequest {
                protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            }),
            None,
        )
        .unwrap();
        assert_eq!(
            channel.recv_request().unwrap(),
            HostReceive::ProtocolViolation
        );
    }

    fn temporary_socket_path(name: &str) -> std::path::PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "litebox-broker-transport-{name}-{}-{now}.sock",
            std::process::id()
        ))
    }
}
