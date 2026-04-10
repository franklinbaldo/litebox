// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Forker protocol types and SCM_RIGHTS helpers.
//!
//! The forker process sits between the runner and the worker, eliminating
//! `execve`/`openat` from the fork-restore path. Communication happens over a
//! Unix socketpair using a simple wire protocol with file-descriptor passing
//! via `SCM_RIGHTS`.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Mutex;

/// Maximum number of file descriptors in a single `SCM_RIGHTS` message.
pub const MAX_SCMRIGHTS_FDS: usize = 64;

/// Callback that the runner registers for forked workers.
/// Called in the grandchild after stdio wiring, with the request + fds.
static WORKER_CALLBACK: std::sync::OnceLock<fn(ForkRequest, Vec<OwnedFd>, RawFd) -> !> =
    std::sync::OnceLock::new();

/// Register the worker callback function.
///
/// The runner calls this before spawning the forker so that forked workers
/// can call back into the runner crate for restore logic.
pub fn set_worker_callback(f: fn(ForkRequest, Vec<OwnedFd>, RawFd) -> !) {
    WORKER_CALLBACK.set(f).ok();
}

/// Magic bytes identifying a [`ForkRequest`] on the wire.
const FORK_REQUEST_MAGIC: [u8; 4] = *b"LBFR";

/// Wire-format version for [`ForkRequest`].
const FORK_REQUEST_VERSION: u16 = 2;

/// Magic bytes identifying a [`ForkResponse`] on the wire.
const FORK_RESPONSE_MAGIC: [u8; 4] = *b"LBFP";

// ---------------------------------------------------------------------------
// ForkerHandle
// ---------------------------------------------------------------------------

/// The runner's end of the socketpair to the forker process.
pub struct ForkerHandle {
    pub(crate) sock: Mutex<OwnedFd>,
}

impl ForkerHandle {
    /// Wrap a connected socket into a `ForkerHandle`.
    pub fn new(sock: OwnedFd) -> Self {
        Self {
            sock: Mutex::new(sock),
        }
    }
}

// ---------------------------------------------------------------------------
// StdioBinding
// ---------------------------------------------------------------------------

/// How to wire a single stdio fd (0, 1, or 2) in the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioBinding {
    /// `dup2` from the fd at this index in the SCM_RIGHTS array.
    FromFdIndex(u8),
    /// Open `/dev/null` (actually dup2 from an inherited `/dev/null` fd).
    DevNull,
    /// Close this fd.
    Close,
    /// Leave the fd as-is.
    Inherit,
}

impl StdioBinding {
    /// Wire encoding: tag byte followed by optional payload.
    fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            StdioBinding::FromFdIndex(idx) => {
                out.push(0);
                out.push(*idx);
            }
            StdioBinding::DevNull => out.push(1),
            StdioBinding::Close => out.push(2),
            StdioBinding::Inherit => out.push(3),
        }
    }

    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, &'static str> {
        if *pos >= data.len() {
            return Err("StdioBinding: unexpected end of data");
        }
        let tag = data[*pos];
        *pos += 1;
        match tag {
            0 => {
                if *pos >= data.len() {
                    return Err("StdioBinding::FromFdIndex: missing index");
                }
                let idx = data[*pos];
                *pos += 1;
                Ok(StdioBinding::FromFdIndex(idx))
            }
            1 => Ok(StdioBinding::DevNull),
            2 => Ok(StdioBinding::Close),
            3 => Ok(StdioBinding::Inherit),
            _ => Err("StdioBinding: unknown tag"),
        }
    }
}

// ---------------------------------------------------------------------------
// ForkRequestKind
// ---------------------------------------------------------------------------

/// The kind of work the forked worker should perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkRequestKind {
    /// Restore from a ForkSnapshot memfd (existing fork-restore path).
    ForkRestore = 0,
    /// Boot a new shim and load a non-PIE binary from exec image memfd(s).
    WorkerExec = 1,
}

// ---------------------------------------------------------------------------
// ForkRequest
// ---------------------------------------------------------------------------

/// Serializable request from the runner to the forker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkRequest {
    /// The kind of work this forked worker should perform.
    pub kind: ForkRequestKind,
    /// Stdio bindings for fds 0, 1, 2.
    pub stdio: [StdioBinding; 3],
    /// Number of fds in the accompanying SCM_RIGHTS message.
    pub num_fds: u16,
    /// Index into the SCM_RIGHTS array for the snapshot fd (0xFF = none).
    pub snapshot_fd_idx: u8,
    /// Index for the acknowledgement fd (0xFF = none).
    pub ack_fd_idx: u8,
    /// Index for the result fd (0xFF = none).
    pub result_fd_idx: u8,
    /// Index for the mux fd (0xFF = none).
    pub mux_fd_idx: u8,
    /// Index for the exec image fd (0xFF = none).
    pub exec_image_fd_idx: u8,
    /// Index for the interpreter image fd (0xFF = none).
    pub interp_image_fd_idx: u8,
    /// Mux stream descriptors: (stream_id, guest_fd, direction, type, initial_eof).
    pub mux_streams: Vec<(u32, usize, u8, u8, bool)>,
    /// Pipe bridge descriptors: (guest_fd, host_fd_idx_in_array, is_read).
    pub pipe_bridges: Vec<(usize, u8, bool)>,
    /// Local pipe descriptors: (write_fd, read_fd, drain_fd_idx_or_0xFF, w_flags, r_flags).
    pub local_pipes: Vec<(usize, usize, u8, u32, u32)>,
}

impl ForkRequest {
    /// Serialize into wire format.
    ///
    /// Wire layout:
    /// - magic "LBFR" (4 bytes)
    /// - version u16 LE (2 bytes)
    /// - stdio bindings (variable)
    /// - num_fds u16 LE
    /// - snapshot_fd_idx, ack_fd_idx, result_fd_idx, mux_fd_idx (4 bytes)
    /// - mux_streams count u32 LE, then each entry
    /// - pipe_bridges count u32 LE, then each entry
    /// - local_pipes count u32 LE, then each entry
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Header
        out.extend_from_slice(&FORK_REQUEST_MAGIC);
        out.extend_from_slice(&FORK_REQUEST_VERSION.to_le_bytes());

        // Kind
        out.push(self.kind as u8);

        // Stdio bindings
        for binding in &self.stdio {
            binding.serialize(&mut out);
        }

        // Fd info
        out.extend_from_slice(&self.num_fds.to_le_bytes());
        out.push(self.snapshot_fd_idx);
        out.push(self.ack_fd_idx);
        out.push(self.result_fd_idx);
        out.push(self.mux_fd_idx);
        out.push(self.exec_image_fd_idx);
        out.push(self.interp_image_fd_idx);

        // Mux streams
        #[allow(clippy::cast_possible_truncation)]
        let mux_count = self.mux_streams.len() as u32;
        out.extend_from_slice(&mux_count.to_le_bytes());
        for &(stream_id, guest_fd, direction, ty, initial_eof) in &self.mux_streams {
            out.extend_from_slice(&stream_id.to_le_bytes());
            out.extend_from_slice(&(guest_fd as u64).to_le_bytes());
            out.push(direction);
            out.push(ty);
            out.push(if initial_eof { 1 } else { 0 });
        }

        // Pipe bridges
        #[allow(clippy::cast_possible_truncation)]
        let bridge_count = self.pipe_bridges.len() as u32;
        out.extend_from_slice(&bridge_count.to_le_bytes());
        for &(guest_fd, host_fd_idx, is_read) in &self.pipe_bridges {
            out.extend_from_slice(&(guest_fd as u64).to_le_bytes());
            out.push(host_fd_idx);
            out.push(if is_read { 1 } else { 0 });
        }

        // Local pipes
        #[allow(clippy::cast_possible_truncation)]
        let pipe_count = self.local_pipes.len() as u32;
        out.extend_from_slice(&pipe_count.to_le_bytes());
        for &(write_fd, read_fd, drain_fd_idx, w_flags, r_flags) in &self.local_pipes {
            out.extend_from_slice(&(write_fd as u64).to_le_bytes());
            out.extend_from_slice(&(read_fd as u64).to_le_bytes());
            out.push(drain_fd_idx);
            out.extend_from_slice(&w_flags.to_le_bytes());
            out.extend_from_slice(&r_flags.to_le_bytes());
        }

        out
    }

    /// Deserialize from wire format.
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        let mut pos = 0;

        // Magic
        if data.len() < 6 {
            return Err("ForkRequest: data too short for header");
        }
        if data[0..4] != FORK_REQUEST_MAGIC {
            return Err("ForkRequest: bad magic");
        }
        pos += 4;

        // Version
        let version = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        if version != FORK_REQUEST_VERSION {
            return Err("ForkRequest: unsupported version");
        }

        // Kind
        if pos >= data.len() {
            return Err("ForkRequest: truncated kind");
        }
        let kind = match data[pos] {
            0 => ForkRequestKind::ForkRestore,
            1 => ForkRequestKind::WorkerExec,
            _ => return Err("ForkRequest: unknown kind"),
        };
        pos += 1;

        // Stdio
        let mut stdio = [StdioBinding::Close; 3];
        for binding in &mut stdio {
            *binding = StdioBinding::deserialize(data, &mut pos)?;
        }

        // num_fds
        if pos + 2 > data.len() {
            return Err("ForkRequest: truncated num_fds");
        }
        let num_fds = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // fd indices
        if pos + 6 > data.len() {
            return Err("ForkRequest: truncated fd indices");
        }
        let snapshot_fd_idx = data[pos];
        let ack_fd_idx = data[pos + 1];
        let result_fd_idx = data[pos + 2];
        let mux_fd_idx = data[pos + 3];
        let exec_image_fd_idx = data[pos + 4];
        let interp_image_fd_idx = data[pos + 5];
        pos += 6;

        // Mux streams
        if pos + 4 > data.len() {
            return Err("ForkRequest: truncated mux_streams count");
        }
        let mux_count =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        let mut mux_streams = Vec::with_capacity(mux_count);
        for _ in 0..mux_count {
            if pos + 15 > data.len() {
                return Err("ForkRequest: truncated mux_stream entry");
            }
            let stream_id =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
            let guest_fd = u64::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]) as usize;
            pos += 8;
            let direction = data[pos];
            pos += 1;
            let ty = data[pos];
            pos += 1;
            let initial_eof = data[pos] != 0;
            pos += 1;
            mux_streams.push((stream_id, guest_fd, direction, ty, initial_eof));
        }

        // Pipe bridges
        if pos + 4 > data.len() {
            return Err("ForkRequest: truncated pipe_bridges count");
        }
        let bridge_count =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        let mut pipe_bridges = Vec::with_capacity(bridge_count);
        for _ in 0..bridge_count {
            if pos + 10 > data.len() {
                return Err("ForkRequest: truncated pipe_bridge entry");
            }
            let guest_fd = u64::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]) as usize;
            pos += 8;
            let host_fd_idx = data[pos];
            pos += 1;
            let is_read = data[pos] != 0;
            pos += 1;
            pipe_bridges.push((guest_fd, host_fd_idx, is_read));
        }

        // Local pipes
        if pos + 4 > data.len() {
            return Err("ForkRequest: truncated local_pipes count");
        }
        let pipe_count =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        let mut local_pipes = Vec::with_capacity(pipe_count);
        for _ in 0..pipe_count {
            if pos + 25 > data.len() {
                return Err("ForkRequest: truncated local_pipe entry");
            }
            let write_fd = u64::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]) as usize;
            pos += 8;
            let read_fd = u64::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]) as usize;
            pos += 8;
            let drain_fd_idx = data[pos];
            pos += 1;
            let w_flags =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
            let r_flags =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
            local_pipes.push((write_fd, read_fd, drain_fd_idx, w_flags, r_flags));
        }

        Ok(ForkRequest {
            kind,
            stdio,
            num_fds,
            snapshot_fd_idx,
            ack_fd_idx,
            result_fd_idx,
            mux_fd_idx,
            exec_image_fd_idx,
            interp_image_fd_idx,
            mux_streams,
            pipe_bridges,
            local_pipes,
        })
    }
}

// ---------------------------------------------------------------------------
// ForkResponse
// ---------------------------------------------------------------------------

/// Fixed 8-byte response from the forker to the runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkResponse {
    /// PID of the child process (negative on error).
    pub child_pid: i32,
}

impl ForkResponse {
    /// Serialize to an 8-byte wire representation.
    pub fn serialize(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&FORK_RESPONSE_MAGIC);
        buf[4..8].copy_from_slice(&self.child_pid.to_le_bytes());
        buf
    }

    /// Deserialize from an 8-byte wire representation.
    pub fn deserialize(data: &[u8; 8]) -> Result<Self, &'static str> {
        if data[0..4] != FORK_RESPONSE_MAGIC {
            return Err("ForkResponse: bad magic");
        }
        let child_pid = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        Ok(ForkResponse { child_pid })
    }
}

// ---------------------------------------------------------------------------
// SCM_RIGHTS helpers
// ---------------------------------------------------------------------------

/// Send a data buffer along with file descriptors over a Unix socket using `SCM_RIGHTS`.
///
/// # Safety
///
/// `sock` must be a valid, connected Unix-domain socket file descriptor.
/// All entries in `fds` must be valid, open file descriptors.
pub fn send_msg_with_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) -> Result<(), i32> {
    assert!(fds.len() <= MAX_SCMRIGHTS_FDS);

    let fd_payload_size = fds.len() * size_of::<RawFd>();

    // SAFETY: CMSG_SPACE with a valid payload size returns the correct buffer size.
    #[allow(clippy::cast_possible_truncation)]
    let cmsg_space = unsafe { libc::CMSG_SPACE(fd_payload_size as u32) as usize };

    // Guarantees the control-message buffer is aligned for `cmsghdr`.
    #[repr(C)]
    struct AlignedBuf {
        _align: [libc::cmsghdr; 0],
        buf: [u8; 1024], // Large enough for MAX_SCMRIGHTS_FDS fds
    }

    let mut cmsg_buf = AlignedBuf {
        _align: [],
        buf: [0u8; 1024],
    };
    assert!(cmsg_space <= cmsg_buf.buf.len());

    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };

    // SAFETY: zeroing msghdr is safe; all-zero is a valid representation.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;

    if !fds.is_empty() {
        msg.msg_control = cmsg_buf.buf.as_mut_ptr().cast();
        #[allow(clippy::cast_possible_truncation)]
        {
            msg.msg_controllen = cmsg_space as _;
        }

        // SAFETY: `msg` has a properly sized and aligned control buffer.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            if cmsg.is_null() {
                return Err(libc::EINVAL);
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            #[allow(clippy::cast_possible_truncation)]
            {
                (*cmsg).cmsg_len = libc::CMSG_LEN(fd_payload_size as u32) as _;
            }
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(cmsg),
                fd_payload_size,
            );
        }
    }

    // SAFETY: `sock` is a valid connected Unix socket, `msg` is fully initialised.
    let ret = unsafe { libc::sendmsg(sock, &raw const msg, libc::MSG_NOSIGNAL) };
    if ret < 0 {
        // SAFETY: reading thread-local errno immediately after a failed syscall.
        let errno = unsafe { *libc::__errno_location() };
        return Err(errno);
    }
    if ret as usize != data.len() {
        return Err(libc::EIO);
    }

    Ok(())
}

/// Receive a data buffer and any accompanying file descriptors from a Unix socket.
///
/// Returns `(bytes_read, received_fds)`.
///
/// # Safety
///
/// `sock` must be a valid, connected Unix-domain socket file descriptor.
/// `data_buf` must have sufficient capacity for the expected message.
pub fn recv_msg_with_fds(sock: RawFd, data_buf: &mut [u8]) -> Result<(usize, Vec<OwnedFd>), i32> {
    // SAFETY: CMSG_SPACE with a valid payload size returns the correct buffer size.
    #[allow(clippy::cast_possible_truncation)]
    let cmsg_space =
        unsafe { libc::CMSG_SPACE((MAX_SCMRIGHTS_FDS * size_of::<RawFd>()) as u32) as usize };

    #[repr(C)]
    struct AlignedBuf {
        _align: [libc::cmsghdr; 0],
        buf: [u8; 1024],
    }

    let mut cmsg_buf = AlignedBuf {
        _align: [],
        buf: [0u8; 1024],
    };
    assert!(cmsg_space <= cmsg_buf.buf.len());

    let mut iov = libc::iovec {
        iov_base: data_buf.as_mut_ptr().cast(),
        iov_len: data_buf.len(),
    };

    // SAFETY: zeroing msghdr is safe; all-zero is a valid representation.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.buf.as_mut_ptr().cast();
    #[allow(clippy::cast_possible_truncation)]
    {
        msg.msg_controllen = cmsg_space as _;
    }

    // SAFETY: `sock` is a valid socket, `msg` is fully initialised.
    let ret = unsafe { libc::recvmsg(sock, &raw mut msg, 0) };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(errno);
    }
    if ret == 0 {
        return Err(libc::ECONNRESET);
    }

    let bytes_read = ret as usize;

    // Extract fds from ancillary data.
    let mut received_fds = Vec::new();
    // SAFETY: iterating through the cmsg chain using the standard CMSG macros.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg);
                let data_len = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let num_fds = data_len / size_of::<RawFd>();
                for i in 0..num_fds {
                    let mut raw_fd: RawFd = 0;
                    std::ptr::copy_nonoverlapping(
                        data_ptr.add(i * size_of::<RawFd>()),
                        (&raw mut raw_fd).cast::<u8>(),
                        size_of::<RawFd>(),
                    );
                    // SAFETY: the fd was just received via SCM_RIGHTS and is valid.
                    received_fds.push(OwnedFd::from_raw_fd(raw_fd));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
        }
    }

    Ok((bytes_read, received_fds))
}

/// Send a [`ForkRequest`] with accompanying file descriptors over a Unix socket.
pub fn send_fork_request(sock: RawFd, request: &ForkRequest, fds: &[RawFd]) -> Result<(), i32> {
    let data = request.serialize();
    send_msg_with_fds(sock, &data, fds)
}

/// Receive a [`ForkRequest`] and its accompanying file descriptors from a Unix socket.
pub fn recv_fork_request(sock: RawFd) -> Result<(ForkRequest, Vec<OwnedFd>), i32> {
    // 64 KiB should be more than enough for any reasonable ForkRequest.
    let mut buf = vec![0u8; 65536];
    let (n, fds) = recv_msg_with_fds(sock, &mut buf)?;
    let request = ForkRequest::deserialize(&buf[..n]).map_err(|_| libc::EPROTO)?;
    Ok((request, fds))
}

/// Send a [`ForkResponse`] over a Unix socket (no ancillary fds).
pub fn send_fork_response(sock: RawFd, response: &ForkResponse) -> Result<(), i32> {
    let data = response.serialize();
    send_msg_with_fds(sock, &data, &[])
}

/// Receive a [`ForkResponse`] from a Unix socket.
pub fn recv_fork_response(sock: RawFd) -> Result<ForkResponse, i32> {
    let mut buf = [0u8; 8];
    let (n, _fds) = recv_msg_with_fds(sock, &mut buf)?;
    if n != 8 {
        return Err(libc::EPROTO);
    }
    ForkResponse::deserialize(&buf).map_err(|_| libc::EPROTO)
}

// ---------------------------------------------------------------------------
// Forker process main loop
// ---------------------------------------------------------------------------

/// Entry point for the forker process.
///
/// Called after `fork()` in the runner's single-threaded init window.
/// The forker sits in a loop, receiving fork requests over `cmd_sock`,
/// performing a double-fork to create orphaned worker processes, and
/// sending the grandchild PID back to the runner.
///
/// # Safety
///
/// - `cmd_sock` must be a valid, connected Unix-domain socket fd.
/// - `dev_null_fd` must be a valid fd open to `/dev/null`.
/// - `broker_fd`, if `Some`, must be a valid fd (it will be closed immediately).
///
/// This function never returns.
pub fn forker_main(cmd_sock: RawFd, dev_null_fd: RawFd, broker_fd: Option<RawFd>) -> ! {
    // The forker doesn't use the broker socket — workers get their own via SCM_RIGHTS.
    if let Some(fd) = broker_fd {
        // SAFETY: `fd` is a valid open fd that we own.
        unsafe {
            libc::close(fd);
        }
    }

    // Install the host-level seccomp sandbox before processing any requests.
    // Workers inherit this filter via fork(), so they are also sandboxed.
    // This filter does NOT allow execve -- the main security win.
    crate::sandbox_seccomp::install_forker_sandbox_filter();

    loop {
        // Block waiting for a fork request + fds from the runner.
        let (req, fds) = match recv_fork_request(cmd_sock) {
            Ok(pair) => pair,
            Err(_) => {
                // EOF or error — runner closed the socket, exit cleanly.
                // SAFETY: _exit is always safe to call.
                unsafe {
                    libc::_exit(0);
                }
            }
        };

        // Create a pipe for the intermediate child to report the grandchild PID.
        let mut pid_pipe = [0i32; 2];
        // SAFETY: pipe2 with a valid array and O_CLOEXEC is safe.
        if unsafe { libc::pipe2(pid_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            // pipe2 failed — report error to the runner.
            let errno = unsafe { *libc::__errno_location() };
            drop(fds);
            let _ = send_fork_response(cmd_sock, &ForkResponse { child_pid: -errno });
            continue;
        }
        let pid_pipe_read = pid_pipe[0];
        let pid_pipe_write = pid_pipe[1];

        // SAFETY: fork() in a single-threaded process is safe.
        let first_pid = unsafe { libc::fork() };

        if first_pid < 0 {
            // First fork failed.
            let errno = unsafe { *libc::__errno_location() };
            // SAFETY: closing valid pipe fds.
            unsafe {
                libc::close(pid_pipe_read);
                libc::close(pid_pipe_write);
            }
            drop(fds);
            let _ = send_fork_response(cmd_sock, &ForkResponse { child_pid: -errno });
            continue;
        }

        if first_pid > 0 {
            // ── Parent (forker) ──
            // Close write end of pid_pipe — only the intermediate child writes.
            // SAFETY: valid fd from pipe2.
            unsafe {
                libc::close(pid_pipe_write);
            }
            // Close the received fds — the forker doesn't need them, the
            // grandchild inherited them via fork().
            drop(fds);

            // Reap the intermediate child (it exits immediately).
            // SAFETY: first_pid is a valid child PID.
            unsafe {
                let mut status: i32 = 0;
                loop {
                    let ret = libc::waitpid(first_pid, &raw mut status, 0);
                    if ret >= 0 || *libc::__errno_location() != libc::EINTR {
                        break;
                    }
                }
            }

            // Read grandchild PID (or negative errno) from the pid pipe.
            let mut grandchild_pid: i32 = 0;
            // SAFETY: reading sizeof(i32) bytes into a valid i32 from a valid pipe fd.
            let n = unsafe {
                libc::read(
                    pid_pipe_read,
                    (&raw mut grandchild_pid).cast::<libc::c_void>(),
                    std::mem::size_of::<i32>(),
                )
            };
            // SAFETY: closing a valid fd.
            unsafe {
                libc::close(pid_pipe_read);
            }

            let child_pid = if n == std::mem::size_of::<i32>() as isize {
                // If the intermediate child wrote a negative value, it's -errno
                // from a failed second fork.
                grandchild_pid
            } else {
                // Pipe read failed — shouldn't happen but report as EIO.
                -(libc::EIO)
            };

            let _ = send_fork_response(cmd_sock, &ForkResponse { child_pid });
            continue;
        }

        // ── Intermediate child (first_pid == 0) ──
        // Close read end of pid_pipe — only the parent reads.
        // SAFETY: valid fd from pipe2.
        unsafe {
            libc::close(pid_pipe_read);
        }
        // Close the command socket — only the forker parent uses it.
        // SAFETY: valid fd.
        unsafe {
            libc::close(cmd_sock);
        }

        // Second fork to create the grandchild (actual worker).
        // SAFETY: single-threaded process (intermediate child just forked).
        let second_pid = unsafe { libc::fork() };

        if second_pid < 0 {
            // Second fork failed — write negative errno to pid_pipe, exit.
            let errno = unsafe { *libc::__errno_location() };
            let neg_errno = -errno;
            // SAFETY: writing sizeof(i32) bytes from a valid i32 to a valid pipe fd.
            unsafe {
                libc::write(
                    pid_pipe_write,
                    (&raw const neg_errno).cast::<libc::c_void>(),
                    std::mem::size_of::<i32>(),
                );
                libc::close(pid_pipe_write);
            }
            drop(fds);
            // SAFETY: _exit is always safe.
            unsafe {
                libc::_exit(1);
            }
        }

        if second_pid == 0 {
            // ── Grandchild (worker) ──
            // Close pid_pipe write end — only the intermediate parent uses it.
            // SAFETY: valid fd from pipe2.
            unsafe {
                libc::close(pid_pipe_write);
            }
            // Hand off to the worker entry point (never returns).
            worker_entry(req, fds, dev_null_fd);
        }

        // ── Intermediate parent (second_pid > 0) ──
        // Write the grandchild PID to the pid pipe for the forker to read.
        // SAFETY: writing sizeof(i32) bytes from a valid i32 to a valid pipe fd.
        unsafe {
            libc::write(
                pid_pipe_write,
                (&raw const second_pid).cast::<libc::c_void>(),
                std::mem::size_of::<i32>(),
            );
            libc::close(pid_pipe_write);
        }
        // Drop the received fds — the grandchild inherited them.
        drop(fds);
        // SAFETY: _exit is always safe.
        unsafe {
            libc::_exit(0);
        }
    }
}

/// Worker entry point.
///
/// Wires stdio according to the request, then calls the registered worker
/// callback (set by the runner via [`set_worker_callback`]) to restore guest
/// state and resume execution.
///
/// If no callback is registered, writes `ENOSYS` to the ack fd and exits.
///
/// This function never returns.
pub fn worker_entry(req: ForkRequest, fds: Vec<OwnedFd>, dev_null_fd: RawFd) -> ! {
    // Wire stdio according to req.stdio.
    for (target_fd, binding) in req.stdio.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let target_fd = target_fd as i32;
        match binding {
            StdioBinding::FromFdIndex(idx) => {
                let idx = *idx as usize;
                if idx < fds.len() {
                    // SAFETY: both fds are valid.
                    unsafe {
                        libc::dup2(fds[idx].as_raw_fd(), target_fd);
                    }
                }
            }
            StdioBinding::DevNull => {
                // SAFETY: dev_null_fd and target_fd are valid fds.
                unsafe {
                    libc::dup2(dev_null_fd, target_fd);
                }
            }
            StdioBinding::Close => {
                // SAFETY: target_fd is a valid stdio fd number.
                unsafe {
                    libc::close(target_fd);
                }
            }
            StdioBinding::Inherit => {
                // Leave the fd as-is.
            }
        }
    }

    // Call the registered worker callback (runner's restore logic).
    if let Some(cb) = WORKER_CALLBACK.get() {
        cb(req, fds, dev_null_fd);
        // cb is -> !, so this is unreachable.
    }

    // Fallback if no callback registered: write ENOSYS to ack fd and exit.
    let ack_fd_idx = req.ack_fd_idx as usize;
    if ack_fd_idx < fds.len() {
        let enosys: i32 = -(libc::ENOSYS);
        // SAFETY: writing sizeof(i32) bytes to a valid fd.
        unsafe {
            libc::write(
                fds[ack_fd_idx].as_raw_fd(),
                (&raw const enosys).cast::<libc::c_void>(),
                std::mem::size_of::<i32>(),
            );
        }
    }

    // SAFETY: _exit is always safe.
    unsafe {
        libc::_exit(1);
    }
}

// ---------------------------------------------------------------------------
// WorkerExecParams
// ---------------------------------------------------------------------------

// Magic and version for WorkerExecParams
const WORKER_EXEC_PARAMS_MAGIC: [u8; 4] = *b"LBWE";
const WORKER_EXEC_PARAMS_VERSION: u16 = 1;

/// Parameters for a worker-exec request, serialized into a memfd.
///
/// Carries the guest identity, arguments, environment, and infrastructure
/// configuration that the worker child needs to boot a new shim and load
/// the non-PIE binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerExecParams {
    /// The resolved binary path (load path for the shim loader).
    pub guest_binary_path: String,
    /// Original guest argv (argv[0] may differ from guest_binary_path for symlinks).
    pub argv: Vec<String>,
    /// Guest environment variables (KEY=VALUE strings).
    pub envp: Vec<String>,
    /// Guest working directory.
    pub cwd: String,
    /// Guest PID.
    pub guest_pid: i32,
    /// Guest parent PID.
    pub guest_ppid: i32,
    /// Guest UID.
    pub guest_uid: u32,
    /// Guest effective UID.
    pub guest_euid: u32,
    /// Guest GID.
    pub guest_gid: u32,
    /// Guest effective GID.
    pub guest_egid: u32,
    /// Path to the interpreter binary (for dynamically-linked non-PIE).
    pub interp_path: Option<String>,
    /// Infrastructure flags forwarded from the runner.
    /// Flat list of (key, optional_value) pairs, e.g. [("--nine-p-broker", Some("/path"))].
    pub infra_flags: Vec<(String, Option<String>)>,
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn read_string(data: &[u8], pos: &mut usize) -> Result<String, &'static str> {
    if *pos + 4 > data.len() {
        return Err("WorkerExecParams: truncated string length");
    }
    let len =
        u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]) as usize;
    *pos += 4;
    if *pos + len > data.len() {
        return Err("WorkerExecParams: truncated string data");
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len])
        .map_err(|_| "WorkerExecParams: invalid UTF-8")?;
    *pos += len;
    Ok(s.to_string())
}

impl WorkerExecParams {
    /// Serialize into wire format.
    ///
    /// Wire layout:
    /// - magic "LBWE" (4 bytes)
    /// - version u16 LE (2 bytes)
    /// - guest_binary_path: u32 len + bytes
    /// - argv_count u32 LE | for each: u32 len + bytes
    /// - envp_count u32 LE | for each: u32 len + bytes
    /// - cwd: u32 len + bytes
    /// - guest_pid i32 LE | guest_ppid i32 LE
    /// - guest_uid u32 LE | guest_euid u32 LE | guest_gid u32 LE | guest_egid u32 LE
    /// - has_interp u8 (0 or 1) | if 1: u32 len + bytes
    /// - infra_flags_count u32 LE | for each: key (u32 len + bytes) | has_value u8 | if 1: value (u32 len + bytes)
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Header
        out.extend_from_slice(&WORKER_EXEC_PARAMS_MAGIC);
        out.extend_from_slice(&WORKER_EXEC_PARAMS_VERSION.to_le_bytes());

        // guest_binary_path
        write_string(&mut out, &self.guest_binary_path);

        // argv
        #[allow(clippy::cast_possible_truncation)]
        let argv_count = self.argv.len() as u32;
        out.extend_from_slice(&argv_count.to_le_bytes());
        for arg in &self.argv {
            write_string(&mut out, arg);
        }

        // envp
        #[allow(clippy::cast_possible_truncation)]
        let envp_count = self.envp.len() as u32;
        out.extend_from_slice(&envp_count.to_le_bytes());
        for env in &self.envp {
            write_string(&mut out, env);
        }

        // cwd
        write_string(&mut out, &self.cwd);

        // guest identity
        out.extend_from_slice(&self.guest_pid.to_le_bytes());
        out.extend_from_slice(&self.guest_ppid.to_le_bytes());
        out.extend_from_slice(&self.guest_uid.to_le_bytes());
        out.extend_from_slice(&self.guest_euid.to_le_bytes());
        out.extend_from_slice(&self.guest_gid.to_le_bytes());
        out.extend_from_slice(&self.guest_egid.to_le_bytes());

        // interp_path
        match &self.interp_path {
            None => out.push(0),
            Some(path) => {
                out.push(1);
                write_string(&mut out, path);
            }
        }

        // infra_flags
        #[allow(clippy::cast_possible_truncation)]
        let flags_count = self.infra_flags.len() as u32;
        out.extend_from_slice(&flags_count.to_le_bytes());
        for (key, value) in &self.infra_flags {
            write_string(&mut out, key);
            match value {
                None => out.push(0),
                Some(v) => {
                    out.push(1);
                    write_string(&mut out, v);
                }
            }
        }

        out
    }

    /// Deserialize from wire format.
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        let mut pos = 0;

        // Magic
        if data.len() < 6 {
            return Err("WorkerExecParams: data too short for header");
        }
        if data[0..4] != WORKER_EXEC_PARAMS_MAGIC {
            return Err("WorkerExecParams: bad magic");
        }
        pos += 4;

        // Version
        let version = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        if version != WORKER_EXEC_PARAMS_VERSION {
            return Err("WorkerExecParams: unsupported version");
        }

        // guest_binary_path
        let guest_binary_path = read_string(data, &mut pos)?;

        // argv
        if pos + 4 > data.len() {
            return Err("WorkerExecParams: truncated argv count");
        }
        let argv_count =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        let mut argv = Vec::with_capacity(argv_count);
        for _ in 0..argv_count {
            argv.push(read_string(data, &mut pos)?);
        }

        // envp
        if pos + 4 > data.len() {
            return Err("WorkerExecParams: truncated envp count");
        }
        let envp_count =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        let mut envp = Vec::with_capacity(envp_count);
        for _ in 0..envp_count {
            envp.push(read_string(data, &mut pos)?);
        }

        // cwd
        let cwd = read_string(data, &mut pos)?;

        // guest identity
        if pos + 24 > data.len() {
            return Err("WorkerExecParams: truncated guest identity");
        }
        let guest_pid =
            i32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let guest_ppid =
            i32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let guest_uid =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let guest_euid =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let guest_gid =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let guest_egid =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // interp_path
        if pos >= data.len() {
            return Err("WorkerExecParams: truncated interp_path flag");
        }
        let has_interp = data[pos];
        pos += 1;
        let interp_path = if has_interp != 0 {
            Some(read_string(data, &mut pos)?)
        } else {
            None
        };

        // infra_flags
        if pos + 4 > data.len() {
            return Err("WorkerExecParams: truncated infra_flags count");
        }
        let flags_count =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        let mut infra_flags = Vec::with_capacity(flags_count);
        for _ in 0..flags_count {
            let key = read_string(data, &mut pos)?;
            if pos >= data.len() {
                return Err("WorkerExecParams: truncated infra_flag value flag");
            }
            let has_value = data[pos];
            pos += 1;
            let value = if has_value != 0 {
                Some(read_string(data, &mut pos)?)
            } else {
                None
            };
            infra_flags.push((key, value));
        }

        Ok(WorkerExecParams {
            guest_binary_path,
            argv,
            envp,
            cwd,
            guest_pid,
            guest_ppid,
            guest_uid,
            guest_euid,
            guest_gid,
            guest_egid,
            interp_path,
            infra_flags,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn fork_request_round_trip_minimal() {
        let req = ForkRequest {
            kind: ForkRequestKind::ForkRestore,
            stdio: [
                StdioBinding::Inherit,
                StdioBinding::DevNull,
                StdioBinding::Close,
            ],
            num_fds: 0,
            snapshot_fd_idx: 0xFF,
            ack_fd_idx: 0xFF,
            result_fd_idx: 0xFF,
            mux_fd_idx: 0xFF,
            exec_image_fd_idx: 0xFF,
            interp_image_fd_idx: 0xFF,
            mux_streams: vec![],
            pipe_bridges: vec![],
            local_pipes: vec![],
        };

        let data = req.serialize();
        let decoded = ForkRequest::deserialize(&data).expect("deserialize should succeed");
        assert_eq!(req, decoded);
    }

    #[test]
    fn fork_request_round_trip_full() {
        let req = ForkRequest {
            kind: ForkRequestKind::ForkRestore,
            stdio: [
                StdioBinding::FromFdIndex(3),
                StdioBinding::FromFdIndex(4),
                StdioBinding::DevNull,
            ],
            num_fds: 10,
            snapshot_fd_idx: 0,
            ack_fd_idx: 1,
            result_fd_idx: 2,
            mux_fd_idx: 3,
            exec_image_fd_idx: 0xFF,
            interp_image_fd_idx: 0xFF,
            mux_streams: vec![(100, 5, 0, 1, false), (200, 6, 1, 2, true)],
            pipe_bridges: vec![(7, 4, true), (8, 5, false)],
            local_pipes: vec![(10, 11, 0xFF, 0x1234, 0x5678), (20, 21, 6, 0, 0)],
        };

        let data = req.serialize();
        let decoded = ForkRequest::deserialize(&data).expect("deserialize should succeed");
        assert_eq!(req, decoded);
    }

    #[test]
    fn fork_request_bad_magic() {
        let mut data = ForkRequest {
            kind: ForkRequestKind::ForkRestore,
            stdio: [StdioBinding::Inherit; 3],
            num_fds: 0,
            snapshot_fd_idx: 0xFF,
            ack_fd_idx: 0xFF,
            result_fd_idx: 0xFF,
            mux_fd_idx: 0xFF,
            exec_image_fd_idx: 0xFF,
            interp_image_fd_idx: 0xFF,
            mux_streams: vec![],
            pipe_bridges: vec![],
            local_pipes: vec![],
        }
        .serialize();

        data[0] = b'X';
        assert!(ForkRequest::deserialize(&data).is_err());
    }

    #[test]
    fn fork_request_bad_version() {
        let mut data = ForkRequest {
            kind: ForkRequestKind::ForkRestore,
            stdio: [StdioBinding::Inherit; 3],
            num_fds: 0,
            snapshot_fd_idx: 0xFF,
            ack_fd_idx: 0xFF,
            result_fd_idx: 0xFF,
            mux_fd_idx: 0xFF,
            exec_image_fd_idx: 0xFF,
            interp_image_fd_idx: 0xFF,
            mux_streams: vec![],
            pipe_bridges: vec![],
            local_pipes: vec![],
        }
        .serialize();

        // Set version to 99
        data[4] = 99;
        data[5] = 0;
        assert!(ForkRequest::deserialize(&data).is_err());
    }

    #[test]
    fn fork_request_truncated() {
        assert!(ForkRequest::deserialize(&[]).is_err());
        assert!(ForkRequest::deserialize(b"LBF").is_err());
        assert!(ForkRequest::deserialize(b"LBFR\x01").is_err());
    }

    #[test]
    fn fork_response_round_trip() {
        let resp = ForkResponse { child_pid: 12345 };
        let data = resp.serialize();
        let decoded = ForkResponse::deserialize(&data).expect("deserialize should succeed");
        assert_eq!(resp, decoded);
    }

    #[test]
    fn fork_response_negative_pid() {
        let resp = ForkResponse { child_pid: -1 };
        let data = resp.serialize();
        let decoded = ForkResponse::deserialize(&data).expect("deserialize should succeed");
        assert_eq!(resp, decoded);
        assert_eq!(decoded.child_pid, -1);
    }

    #[test]
    fn fork_response_bad_magic() {
        let data = [b'X', b'B', b'F', b'P', 0, 0, 0, 0];
        assert!(ForkResponse::deserialize(&data).is_err());
    }

    #[test]
    fn stdio_binding_all_variants() {
        // Test each variant serializes and deserializes correctly.
        let variants = [
            StdioBinding::FromFdIndex(0),
            StdioBinding::FromFdIndex(42),
            StdioBinding::FromFdIndex(255),
            StdioBinding::DevNull,
            StdioBinding::Close,
            StdioBinding::Inherit,
        ];

        for &variant in &variants {
            let mut buf = Vec::new();
            variant.serialize(&mut buf);
            let mut pos = 0;
            let decoded =
                StdioBinding::deserialize(&buf, &mut pos).expect("deserialize should succeed");
            assert_eq!(variant, decoded);
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn fork_request_large_collections() {
        let req = ForkRequest {
            kind: ForkRequestKind::ForkRestore,
            stdio: [
                StdioBinding::FromFdIndex(1),
                StdioBinding::Close,
                StdioBinding::Inherit,
            ],
            num_fds: 64,
            snapshot_fd_idx: 0,
            ack_fd_idx: 1,
            result_fd_idx: 2,
            mux_fd_idx: 3,
            exec_image_fd_idx: 0xFF,
            interp_image_fd_idx: 0xFF,
            mux_streams: (0..20)
                .map(|i| (i, i as usize * 10, (i % 2) as u8, (i % 3) as u8, i % 2 == 0))
                .collect(),
            pipe_bridges: (0..10)
                .map(|i| (i as usize * 5, i as u8, i % 2 == 0))
                .collect(),
            local_pipes: (0..5)
                .map(|i| (i as usize, i as usize + 100, i as u8, i * 0x100, i * 0x200))
                .collect(),
        };

        let data = req.serialize();
        let decoded = ForkRequest::deserialize(&data).expect("deserialize should succeed");
        assert_eq!(req, decoded);
    }

    #[test]
    fn scm_rights_send_recv_via_socketpair() {
        // Create a socketpair and test sending/receiving ForkRequest + fds.
        let mut sv = [0i32; 2];
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0, "socketpair failed");

        let sock_a = unsafe { OwnedFd::from_raw_fd(sv[0]) };
        let sock_b = unsafe { OwnedFd::from_raw_fd(sv[1]) };

        let req = ForkRequest {
            kind: ForkRequestKind::ForkRestore,
            stdio: [
                StdioBinding::Inherit,
                StdioBinding::DevNull,
                StdioBinding::Close,
            ],
            num_fds: 2,
            snapshot_fd_idx: 0,
            ack_fd_idx: 1,
            result_fd_idx: 0xFF,
            mux_fd_idx: 0xFF,
            exec_image_fd_idx: 0xFF,
            interp_image_fd_idx: 0xFF,
            mux_streams: vec![(1, 3, 0, 1, false)],
            pipe_bridges: vec![],
            local_pipes: vec![],
        };

        // Create two pipes to use as test fds to send.
        let mut pipe_fds = [0i32; 2];
        let ret = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe failed");

        // Send the request with the pipe fds.
        send_fork_request(sock_a.as_raw_fd(), &req, &pipe_fds).expect("send should succeed");

        // Close our copies of the pipe fds (they've been sent).
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }

        // Receive on the other end.
        let (decoded_req, received_fds) =
            recv_fork_request(sock_b.as_raw_fd()).expect("recv should succeed");

        assert_eq!(req, decoded_req);
        assert_eq!(received_fds.len(), 2);
    }

    #[test]
    fn scm_rights_fork_response_round_trip() {
        let mut sv = [0i32; 2];
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0, "socketpair failed");

        let sock_a = unsafe { OwnedFd::from_raw_fd(sv[0]) };
        let sock_b = unsafe { OwnedFd::from_raw_fd(sv[1]) };

        let resp = ForkResponse { child_pid: 42 };
        send_fork_response(sock_a.as_raw_fd(), &resp).expect("send should succeed");

        let decoded = recv_fork_response(sock_b.as_raw_fd()).expect("recv should succeed");
        assert_eq!(resp, decoded);
    }

    #[test]
    fn fork_request_round_trip_worker_exec() {
        let req = ForkRequest {
            kind: ForkRequestKind::WorkerExec,
            stdio: [
                StdioBinding::Inherit,
                StdioBinding::Inherit,
                StdioBinding::Inherit,
            ],
            num_fds: 4,
            snapshot_fd_idx: 0, // metadata memfd
            ack_fd_idx: 0xFF,
            result_fd_idx: 1,
            mux_fd_idx: 0xFF,
            exec_image_fd_idx: 2,
            interp_image_fd_idx: 3,
            mux_streams: vec![],
            pipe_bridges: vec![],
            local_pipes: vec![],
        };
        let data = req.serialize();
        let decoded = ForkRequest::deserialize(&data).expect("deserialize");
        assert_eq!(req, decoded);
    }

    #[test]
    fn worker_exec_params_round_trip_minimal() {
        let params = WorkerExecParams {
            guest_binary_path: "/usr/bin/echo".to_string(),
            argv: vec!["echo".to_string(), "hello".to_string()],
            envp: vec!["PATH=/bin".to_string()],
            cwd: "/".to_string(),
            guest_pid: 42,
            guest_ppid: 1,
            guest_uid: 1000,
            guest_euid: 1000,
            guest_gid: 1000,
            guest_egid: 1000,
            interp_path: None,
            infra_flags: vec![],
        };
        let data = params.serialize();
        let decoded = WorkerExecParams::deserialize(&data).unwrap();
        assert_eq!(params, decoded);
    }

    #[test]
    fn worker_exec_params_round_trip_full() {
        let params = WorkerExecParams {
            guest_binary_path: "/usr/bin/node".to_string(),
            argv: vec!["node".to_string(), "index.js".to_string()],
            envp: vec!["PATH=/bin".to_string(), "HOME=/root".to_string()],
            cwd: "/app".to_string(),
            guest_pid: 100,
            guest_ppid: 1,
            guest_uid: 0,
            guest_euid: 0,
            guest_gid: 0,
            guest_egid: 0,
            interp_path: Some("/lib64/ld-linux-x86-64.so.2".to_string()),
            infra_flags: vec![
                (
                    "--nine-p-broker".to_string(),
                    Some("/tmp/broker.sock".to_string()),
                ),
                ("--program-from-tar".to_string(), None),
            ],
        };
        let data = params.serialize();
        let decoded = WorkerExecParams::deserialize(&data).unwrap();
        assert_eq!(params, decoded);
    }

    #[test]
    fn worker_exec_params_empty_strings() {
        let params = WorkerExecParams {
            guest_binary_path: "".to_string(),
            argv: vec![],
            envp: vec![],
            cwd: "".to_string(),
            guest_pid: 0,
            guest_ppid: 0,
            guest_uid: 0,
            guest_euid: 0,
            guest_gid: 0,
            guest_egid: 0,
            interp_path: None,
            infra_flags: vec![],
        };
        let data = params.serialize();
        let decoded = WorkerExecParams::deserialize(&data).unwrap();
        assert_eq!(params, decoded);
    }

    #[test]
    fn worker_exec_params_bad_magic() {
        let mut data = WorkerExecParams {
            guest_binary_path: "/bin/ls".to_string(),
            argv: vec!["ls".to_string()],
            envp: vec![],
            cwd: "/".to_string(),
            guest_pid: 1,
            guest_ppid: 0,
            guest_uid: 0,
            guest_euid: 0,
            guest_gid: 0,
            guest_egid: 0,
            interp_path: None,
            infra_flags: vec![],
        }
        .serialize();
        data[0] = b'X';
        assert!(WorkerExecParams::deserialize(&data).is_err());
    }

    #[test]
    fn worker_exec_params_truncated() {
        assert!(WorkerExecParams::deserialize(&[]).is_err());
        assert!(WorkerExecParams::deserialize(b"LBWE").is_err());
    }
}
