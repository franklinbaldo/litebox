// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-domain-socket broker channel for hosted userland deployments.
//!
//! This module deliberately uses `std` because Unix-domain sockets and `std::io`
//! framing are hosted userland concerns. Portable broker interfaces live in the
//! no_std protocol, local, core, and host crates.

use std::io::{Error, ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use crate::shared_memory::MemfdSharedMemory;
use litebox_broker_protocol::channel::{
    ControlResponse, HostControlChannel, HostNotificationChannel, HostReceive, LocalControlChannel,
    LocalNotificationChannel, PeerCredential,
};
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse,
};
use litebox_broker_protocol::wire::{
    WireError, decode_handshake_request, decode_handshake_response, decode_notification,
    decode_request, decode_response, encode_handshake_request, encode_handshake_response,
    encode_notification, encode_request, encode_response,
};

const MAX_FRAME_LEN: usize = 64 * 1024;
const RESPONSE_ATTACHMENT_NONE: u8 = 0;
const RESPONSE_ATTACHMENT_SHARED_MEMORY: u8 = 1;
const SHARED_MEMORY_MARKER: u8 = 0xa5;
/// Local-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamLocalControlChannel {
    stream: UnixStream,
    setup_deadline: Option<Instant>,
}

/// Independently owned handle for interrupting local control-channel I/O.
pub struct UnixStreamLocalControlCancellation {
    stream: UnixStream,
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
    ///
    /// TODO: `UnixStream` does not expose a connect timeout, so this
    /// deadline currently covers setup I/O after the initial connect
    /// succeeds, but not a blocking connect call.
    pub fn connect_with_setup_deadline(
        path: impl AsRef<Path>,
        deadline: Instant,
    ) -> IoResult<Self> {
        UnixStream::connect(path).map(|stream| Self {
            stream,
            setup_deadline: Some(deadline),
        })
    }

    /// Creates a handle that can interrupt pending control-channel I/O.
    pub fn cancellation_handle(&self) -> IoResult<UnixStreamLocalControlCancellation> {
        self.stream
            .try_clone()
            .map(|stream| UnixStreamLocalControlCancellation { stream })
    }
}

impl UnixStreamLocalControlCancellation {
    /// Shuts down the control stream, unblocking pending reads or writes.
    pub fn cancel(&self) -> IoResult<()> {
        match self.stream.shutdown(Shutdown::Both) {
            Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
            result => result,
        }
    }
}

impl Drop for UnixStreamLocalControlChannel {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// Host-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamHostControlChannel {
    stream: UnixStream,
}

/// Local-side Unix-domain-socket notification channel for the hosted userland POC.
pub struct UnixStreamLocalNotificationChannel {
    stream: UnixStream,
}

/// Host-side Unix-domain-socket notification channel for the hosted userland POC.
pub struct UnixStreamHostNotificationChannel {
    stream: UnixStream,
}

impl UnixStreamHostControlChannel {
    /// Creates a host control channel from an accepted Unix stream.
    pub const fn from_accepted(stream: UnixStream) -> Self {
        Self { stream }
    }
}

impl UnixStreamLocalNotificationChannel {
    /// Creates a local notification channel from an already-connected Unix stream.
    pub const fn from_connected(stream: UnixStream) -> Self {
        Self { stream }
    }

    /// Connects to a userland broker Unix notification socket.
    pub fn connect(path: impl AsRef<Path>) -> IoResult<Self> {
        UnixStream::connect(path).map(Self::from_connected)
    }
}

impl UnixStreamHostNotificationChannel {
    /// Creates a host notification channel from an accepted Unix stream.
    pub const fn from_accepted(stream: UnixStream) -> Self {
        Self { stream }
    }
}

impl LocalControlChannel for UnixStreamLocalControlChannel {
    type Error = Error;
    type SharedMemory = MemfdSharedMemory;

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

    fn recv_response(&mut self) -> IoResult<Option<ControlResponse<Self::SharedMemory>>> {
        match read_frame_with_deadline(&mut self.stream, None)? {
            Some(frame) => {
                let Some((&attachment, response_frame)) = frame.split_first() else {
                    return Err(invalid_data("missing broker response attachment tag"));
                };
                let response = decode_response(response_frame).map_err(wire_error)?;
                let shared_memory = match attachment {
                    RESPONSE_ATTACHMENT_NONE => None,
                    RESPONSE_ATTACHMENT_SHARED_MEMORY => Some(MemfdSharedMemory::from_received_fd(
                        receive_fd(&self.stream)?,
                    )?),
                    _ => return Err(invalid_data("invalid broker response attachment tag")),
                };
                Ok(Some(ControlResponse {
                    response,
                    shared_memory,
                }))
            }
            None => Ok(None),
        }
    }
}

impl HostControlChannel for UnixStreamHostControlChannel {
    type Error = Error;
    type SharedMemory = MemfdSharedMemory;

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

    fn create_shared_memory(&mut self, length: usize) -> IoResult<Option<Self::SharedMemory>> {
        MemfdSharedMemory::create(length).map(Some)
    }

    fn send_response(
        &mut self,
        response: &BrokerResponse,
        shared_memory: Option<&Self::SharedMemory>,
    ) -> IoResult<()> {
        let encoded_response = encode_response(response.clone());
        let mut frame = Vec::with_capacity(encoded_response.len() + 1);
        frame.push(if shared_memory.is_some() {
            RESPONSE_ATTACHMENT_SHARED_MEMORY
        } else {
            RESPONSE_ATTACHMENT_NONE
        });
        frame.extend_from_slice(&encoded_response);
        write_frame_with_deadline(&mut self.stream, &frame, None)?;
        if let Some(shared_memory) = shared_memory {
            send_fd(&self.stream, shared_memory.as_fd())?;
        }
        Ok(())
    }
}

impl LocalNotificationChannel for UnixStreamLocalNotificationChannel {
    type Error = Error;

    fn recv_notification(&mut self) -> IoResult<Option<BrokerNotification>> {
        match read_frame_with_deadline(&mut self.stream, None)? {
            Some(frame) => decode_notification(&frame).map(Some).map_err(wire_error),
            None => Ok(None),
        }
    }
}

impl HostNotificationChannel for UnixStreamHostNotificationChannel {
    type Error = Error;

    fn send_notification(&mut self, notification: &BrokerNotification) -> IoResult<()> {
        write_frame_with_deadline(
            &mut self.stream,
            &encode_notification(notification.clone()),
            None,
        )
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

fn send_fd(stream: &UnixStream, fd: BorrowedFd<'_>) -> IoResult<()> {
    let marker = [SHARED_MEMORY_MARKER];
    let io = [IoSlice::new(&marker)];
    let fds = [fd];
    let mut control_space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut control_space);
    assert!(
        control.push(SendAncillaryMessage::ScmRights(&fds)),
        "SCM_RIGHTS control buffer is correctly sized"
    );

    loop {
        match rustix::net::sendmsg(stream, &io, &mut control, SendFlags::empty()) {
            Ok(1) => return Ok(()),
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "failed to send shared-memory descriptor",
                ));
            }
            Ok(_) => {
                return Err(invalid_data(
                    "shared-memory descriptor marker was oversized",
                ));
            }
            Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_fd(stream: &UnixStream) -> IoResult<OwnedFd> {
    let mut marker = [0];
    let mut io = [IoSliceMut::new(&mut marker)];
    let mut control_space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = RecvAncillaryBuffer::new(&mut control_space);

    let received = loop {
        match rustix::net::recvmsg(stream, &mut io, &mut control, RecvFlags::CMSG_CLOEXEC) {
            Ok(received) => break received,
            Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    };
    if received.bytes == 0 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "broker closed before shared-memory descriptor",
        ));
    }
    let mut received_fds = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(fds) = message {
            received_fds.extend(fds);
        }
    }
    if received.flags.contains(ReturnFlags::CTRUNC) || received_fds.len() != 1 {
        return Err(invalid_data(
            "shared-memory response must contain exactly one descriptor",
        ));
    }
    if received.bytes != 1 || marker[0] != SHARED_MEMORY_MARKER {
        return Err(invalid_data("invalid shared-memory descriptor marker"));
    }
    Ok(received_fds
        .pop()
        .expect("exactly one descriptor was checked"))
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
    use litebox_broker_protocol::message::PipeResponse;
    use litebox_broker_protocol::pipe::CreatePipeResponse;
    use litebox_broker_protocol::shared_memory::SharedMemory;
    use rustix::io::FdFlags;

    const TEST_SHARED_MEMORY_REGION_SIZE: usize = 32 * 1024;
    const TEST_SHARED_MEMORY_SIZE: usize = TEST_SHARED_MEMORY_REGION_SIZE * 2;

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
    fn shared_memory_response_transfers_sealed_memfd() {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut local = UnixStreamLocalControlChannel::from_connected(local_stream);
        let mut host = UnixStreamHostControlChannel::from_accepted(host_stream);
        let host_memory = host
            .create_shared_memory(TEST_SHARED_MEMORY_SIZE)
            .unwrap()
            .unwrap();
        host_memory.write(0, &[1, 2, 3]).unwrap();
        let response = BrokerResponse::Pipe(PipeResponse::Create(CreatePipeResponse {
            read_handle: litebox_broker_protocol::ObjectHandle(1),
            write_handle: litebox_broker_protocol::ObjectHandle(2),
        }));

        host.send_response(&response, Some(&host_memory)).unwrap();
        let received = local.recv_response().unwrap().unwrap();

        assert_eq!(received.response, response);
        let local_memory = received.shared_memory.unwrap();
        let mut data = [0; 3];
        local_memory.read(0, &mut data).unwrap();
        assert_eq!(data, [1, 2, 3]);
        local_memory
            .write(TEST_SHARED_MEMORY_REGION_SIZE, &[4, 5, 6])
            .unwrap();
        host_memory
            .read(TEST_SHARED_MEMORY_REGION_SIZE, &mut data)
            .unwrap();
        assert_eq!(data, [4, 5, 6]);
        let descriptor_flags = rustix::io::fcntl_getfd(local_memory.as_fd()).unwrap();
        assert!(descriptor_flags.contains(FdFlags::CLOEXEC));
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
    fn local_handshake_response_read_setup_deadline_is_wall_clock() {
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
    fn local_control_cancellation_unblocks_response_read() {
        let (local_stream, _host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamLocalControlChannel::from_connected(local_stream);
        let cancellation = channel.cancellation_handle().unwrap();
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let reader_completed = completed.clone();
        let reader = std::thread::spawn(move || {
            started_sender.send(()).unwrap();
            result_sender.send(channel.recv_response()).unwrap();
            reader_completed.store(true, std::sync::atomic::Ordering::Release);
        });

        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!completed.load(std::sync::atomic::Ordering::Acquire));
        cancellation.cancel().unwrap();

        assert!(result_receiver.recv_timeout(Duration::from_secs(1)).is_ok());
        reader.join().unwrap();
    }

    #[test]
    fn dropping_local_control_closes_connection_with_cancellation_clone() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let channel = UnixStreamLocalControlChannel::from_connected(local_stream);
        let _cancellation = channel.cancellation_handle().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        drop(channel);

        let mut byte = [0];
        assert_eq!(host_stream.read(&mut byte).unwrap(), 0);
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

    #[test]
    fn notification_frame_round_trip() {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut local = UnixStreamLocalNotificationChannel::from_connected(local_stream);
        let mut host = UnixStreamHostNotificationChannel::from_accepted(host_stream);
        let notification = BrokerNotification::Readiness(
            litebox_broker_protocol::message::ReadinessNotification {
                handle: litebox_broker_protocol::ObjectHandle(7),
                readiness: litebox_broker_protocol::readiness::ReadinessFlags::READ,
            },
        );

        host.send_notification(&notification).unwrap();

        assert_eq!(local.recv_notification().unwrap(), Some(notification));
    }
}
