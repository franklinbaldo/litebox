//! Record-and-replay support for the Linux shim.
//!
//! When enabled via the `rr` feature, syscall execution can be recorded to a
//! trace buffer or replayed from a previously recorded trace.

use alloc::vec::Vec;
use litebox_rr::{Event, Recorder, ReplayError, Replayer, TraceArch};

use litebox::platform::{RawConstPointer as _, RawMutPointer as _};

use crate::{MutPtr, Platform};

type Mutex<T> = litebox::sync::Mutex<Platform, T>;

/// The record-replay operating mode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RRMode {
    /// No recording or replaying. Normal execution.
    Off,
    /// Record syscall results and side-effect data.
    Record,
    /// Replay from a previously recorded trace.
    Replay,
}

/// Returns the current target architecture as a [`TraceArch`].
fn current_arch() -> TraceArch {
    #[cfg(target_arch = "x86_64")]
    {
        TraceArch::X86_64
    }
    #[cfg(target_arch = "x86")]
    {
        TraceArch::X86
    }
}

/// Record-replay state attached to a `GlobalState`.
pub struct RRState {
    mode: RRMode,
    /// Only present in Record mode.
    recorder: Option<Mutex<Recorder>>,
    /// Only present in Replay mode.
    replayer: Option<Mutex<Replayer>>,
}

impl RRState {
    /// Create a new RR state in the given mode.
    ///
    /// # Panics
    ///
    /// Panics if called with `RRMode::Replay`. Use [`RRState::new_replay`]
    /// instead.
    pub fn new(mode: RRMode) -> Self {
        match mode {
            RRMode::Off => Self {
                mode,
                recorder: None,
                replayer: None,
            },
            RRMode::Record => Self {
                mode,
                recorder: Some(Mutex::new(Recorder::new(current_arch()))),
                replayer: None,
            },
            RRMode::Replay => {
                panic!("use RRState::new_replay() for replay mode");
            }
        }
    }

    /// Create a new RR state for replay from the given trace data.
    pub fn new_replay(trace_data: Vec<u8>) -> Result<Self, ReplayError> {
        let replayer = Replayer::from_bytes(trace_data)?;
        Ok(Self {
            mode: RRMode::Replay,
            recorder: None,
            replayer: Some(Mutex::new(replayer)),
        })
    }

    /// Return the current mode.
    pub fn mode(&self) -> RRMode {
        self.mode
    }

    /// Record a syscall event during recording mode.
    ///
    /// `syscall_nr` is the raw Linux syscall number.
    /// `result` is the return value (positive = success, negative = -errno).
    /// `data` is the side-effect data (bytes written to guest buffers).
    pub fn record_event(&self, syscall_nr: u32, result: i64, data: Vec<u8>) {
        if let Some(ref recorder) = self.recorder {
            recorder.lock().record(syscall_nr, result, data);
        }
    }

    /// Get the next replay event, validating the syscall number matches.
    pub fn replay_event(&self, actual_syscall_nr: u32) -> Result<Event, ReplayError> {
        if let Some(ref replayer) = self.replayer {
            replayer.lock().expect_event(actual_syscall_nr)
        } else {
            Err(ReplayError::EndOfTrace)
        }
    }

    /// Finish recording and return the trace bytes. Consumes the RR state.
    pub fn finish_recording(mut self) -> Option<Vec<u8>> {
        // We own `self`, so we can get a &mut to the Mutex and extract
        // the Recorder without needing to lock.
        self.recorder
            .as_mut()
            .map(|r| core::mem::replace(r.get_mut(), Recorder::new(current_arch())).finish())
    }
}

// ---------------------------------------------------------------------------
// Helpers for extracting syscall metadata from PtRegs
// ---------------------------------------------------------------------------

/// Extract the raw syscall number from the register context.
#[allow(clippy::cast_possible_truncation)]
pub fn get_syscall_nr(ctx: &litebox_common_linux::PtRegs) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        ctx.orig_rax as u32
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.orig_eax as u32
    }
}

/// Write the syscall return value into the register context.
pub fn set_return_value(ctx: &mut litebox_common_linux::PtRegs, value: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        ctx.rax = value;
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.eax = value;
    }
}

// ---------------------------------------------------------------------------
// Side-effect capture (recording) and injection (replay)
// ---------------------------------------------------------------------------

/// Syscall numbers on x86_64 that write to guest memory and whose side-effect
/// bytes we need to capture.
///
/// We use the `syscalls::Sysno` crate to stay platform-correct.
#[allow(clippy::cast_sign_loss)]
mod nr {
    use syscalls::Sysno;

    pub const READ: u32 = Sysno::read.id() as u32;
    pub const PREAD64: u32 = Sysno::pread64.id() as u32;
    pub const GETRANDOM: u32 = Sysno::getrandom.id() as u32;
    pub const CLOCK_GETTIME: u32 = Sysno::clock_gettime.id() as u32;
    pub const GETTIMEOFDAY: u32 = Sysno::gettimeofday.id() as u32;
    pub const FSTAT: u32 = Sysno::fstat.id() as u32;
    #[cfg(target_arch = "x86_64")]
    pub const STAT: u32 = Sysno::stat.id() as u32;
    #[cfg(target_arch = "x86_64")]
    pub const LSTAT: u32 = Sysno::lstat.id() as u32;
    pub const GETCWD: u32 = Sysno::getcwd.id() as u32;
    #[cfg(target_arch = "x86_64")]
    pub const READLINK: u32 = Sysno::readlink.id() as u32;
    pub const UNAME: u32 = Sysno::uname.id() as u32;
    pub const PIPE2: u32 = Sysno::pipe2.id() as u32;
    pub const SYSINFO: u32 = Sysno::sysinfo.id() as u32;
    pub const GETDENTS64: u32 = Sysno::getdents64.id() as u32;
    pub const READLINKAT: u32 = Sysno::readlinkat.id() as u32;
    pub const READV: u32 = Sysno::readv.id() as u32;
    #[cfg(target_arch = "x86_64")]
    pub const NEWFSTATAT: u32 = Sysno::newfstatat.id() as u32;
    #[cfg(target_arch = "x86")]
    pub const FSTATAT64: u32 = Sysno::fstatat64.id() as u32;
    pub const TIME: u32 = Sysno::time.id() as u32;
}

/// Read `len` bytes from guest memory at the given address.
/// Returns an empty `Vec` on failure (null pointer, etc.).
fn read_guest_bytes(addr: usize, len: usize) -> Vec<u8> {
    if addr == 0 || len == 0 {
        return Vec::new();
    }
    let ptr: MutPtr<u8> = MutPtr::from_usize(addr);
    ptr.to_owned_slice(len)
        .map(<[u8]>::into_vec)
        .unwrap_or_default()
}

/// Write `data` bytes into guest memory at the given address.
fn write_guest_bytes(addr: usize, data: &[u8]) {
    if addr == 0 || data.is_empty() {
        return;
    }
    let ptr: MutPtr<u8> = MutPtr::from_usize(addr);
    let _ = ptr.copy_from_slice(0, data);
}

/// After a syscall completes successfully during recording, capture any
/// side-effect bytes that were written to guest memory.
///
/// `syscall_nr`: raw Linux syscall number
/// `ctx`: register state (contains the original arguments)
/// `return_value`: the raw return value (usize)
pub fn capture_side_effects(
    syscall_nr: u32,
    ctx: &litebox_common_linux::PtRegs,
    return_value: usize,
) -> Vec<u8> {
    // If the return value looks like a negative errno (high bit set on 64-bit),
    // the syscall failed, so there are no side-effects to capture.
    let result_signed = return_value.cast_signed();
    if result_signed < 0 {
        return Vec::new();
    }

    match syscall_nr {
        // read(fd, buf, count) -> bytes_read
        // buf = arg1, bytes_read = return_value
        nr::READ => {
            let buf_addr = ctx.syscall_arg(1);
            read_guest_bytes(buf_addr, return_value)
        }

        // pread64(fd, buf, count, offset) -> bytes_read
        nr::PREAD64 => {
            let buf_addr = ctx.syscall_arg(1);
            read_guest_bytes(buf_addr, return_value)
        }

        // getrandom(buf, count, flags) -> bytes_read
        nr::GETRANDOM => {
            let buf_addr = ctx.syscall_arg(0);
            read_guest_bytes(buf_addr, return_value)
        }

        // clock_gettime(clockid, tp) -> 0
        // tp = arg1, size = sizeof(timespec) = 16 on both x86 and x86_64
        nr::CLOCK_GETTIME => {
            let tp_addr = ctx.syscall_arg(1);
            read_guest_bytes(tp_addr, 16)
        }

        // gettimeofday(tv, tz) -> 0
        // tv = arg0, size = sizeof(timeval) = 16 on x86_64, 8 on x86
        nr::GETTIMEOFDAY => {
            let tv_addr = ctx.syscall_arg(0);
            #[cfg(target_arch = "x86_64")]
            let size = 16;
            #[cfg(target_arch = "x86")]
            let size = 8;
            read_guest_bytes(tv_addr, size)
        }

        // fstat(fd, buf) -> 0
        // buf = arg1, size = sizeof(struct stat)
        nr::FSTAT => {
            let buf_addr = ctx.syscall_arg(1);
            read_guest_bytes(
                buf_addr,
                core::mem::size_of::<litebox_common_linux::FileStat>(),
            )
        }

        // stat(pathname, buf) -> 0
        #[cfg(target_arch = "x86_64")]
        nr::STAT => {
            let buf_addr = ctx.syscall_arg(1);
            read_guest_bytes(
                buf_addr,
                core::mem::size_of::<litebox_common_linux::FileStat>(),
            )
        }

        // lstat(pathname, buf) -> 0
        #[cfg(target_arch = "x86_64")]
        nr::LSTAT => {
            let buf_addr = ctx.syscall_arg(1);
            read_guest_bytes(
                buf_addr,
                core::mem::size_of::<litebox_common_linux::FileStat>(),
            )
        }

        // newfstatat(dirfd, pathname, buf, flags) -> 0
        // buf = arg2
        #[cfg(target_arch = "x86_64")]
        nr::NEWFSTATAT => {
            let buf_addr = ctx.syscall_arg(2);
            read_guest_bytes(
                buf_addr,
                core::mem::size_of::<litebox_common_linux::FileStat>(),
            )
        }

        // fstatat64 on x86 — buf = arg2
        #[cfg(target_arch = "x86")]
        nr::FSTATAT64 => {
            let buf_addr = ctx.syscall_arg(2);
            read_guest_bytes(
                buf_addr,
                core::mem::size_of::<litebox_common_linux::FileStat>(),
            )
        }

        // getcwd(buf, size) -> bytes_written (including NUL)
        nr::GETCWD => {
            let buf_addr = ctx.syscall_arg(0);
            read_guest_bytes(buf_addr, return_value)
        }

        // readlink(pathname, buf, bufsiz) -> bytes_read
        #[cfg(target_arch = "x86_64")]
        nr::READLINK => {
            let buf_addr = ctx.syscall_arg(1);
            read_guest_bytes(buf_addr, return_value)
        }

        // readlinkat(dirfd, pathname, buf, bufsiz) -> bytes_read
        // buf = arg2
        nr::READLINKAT => {
            let buf_addr = ctx.syscall_arg(2);
            read_guest_bytes(buf_addr, return_value)
        }

        // uname(buf) -> 0
        // buf = arg0, size = sizeof(struct utsname) = 390
        nr::UNAME => {
            let buf_addr = ctx.syscall_arg(0);
            read_guest_bytes(buf_addr, 390)
        }

        // pipe2(pipefd, flags) -> 0
        // pipefd = arg0, size = 8 (two i32s)
        nr::PIPE2 => {
            let pipefd_addr = ctx.syscall_arg(0);
            read_guest_bytes(pipefd_addr, 8)
        }

        // sysinfo(info) -> 0
        // info = arg0
        nr::SYSINFO => {
            let buf_addr = ctx.syscall_arg(0);
            // sizeof(struct sysinfo) = 112 on x86_64
            #[cfg(target_arch = "x86_64")]
            let size = 112;
            #[cfg(target_arch = "x86")]
            let size = 64;
            read_guest_bytes(buf_addr, size)
        }

        // getdents64(fd, dirp, count) -> bytes_read
        // dirp = arg1
        nr::GETDENTS64 => {
            let dirp_addr = ctx.syscall_arg(1);
            read_guest_bytes(dirp_addr, return_value)
        }

        // readv(fd, iov, iovcnt) -> bytes_read
        // The data is scattered across iovec buffers. For MVP, we capture
        // the total bytes by reading each iovec base/len pair and concatenating.
        nr::READV => capture_readv_data(ctx, return_value),

        // time(tloc) -> seconds since epoch
        // tloc = arg0, if non-null writes a time_t (8 bytes on x86_64, 4 on x86)
        nr::TIME => {
            let tloc_addr = ctx.syscall_arg(0);
            if tloc_addr != 0 {
                #[cfg(target_arch = "x86_64")]
                let size = 8;
                #[cfg(target_arch = "x86")]
                let size = 4;
                read_guest_bytes(tloc_addr, size)
            } else {
                Vec::new()
            }
        }

        // No side-effect data for other syscalls.
        _ => Vec::new(),
    }
}

/// Capture data written by `readv`. The iovec array is at arg1 with iovcnt at
/// arg2. We read each iovec's base/len from guest memory and concatenate the
/// data, up to `total_bytes_read`.
fn capture_readv_data(ctx: &litebox_common_linux::PtRegs, total_bytes_read: usize) -> Vec<u8> {
    // sizeof(struct iovec) = 16 on x86_64 (ptr + size_t), 8 on x86
    #[cfg(target_arch = "x86_64")]
    const IOVEC_SIZE: usize = 16;
    #[cfg(target_arch = "x86")]
    const IOVEC_SIZE: usize = 8;

    let iov_addr = ctx.syscall_arg(1);
    let iovcnt = ctx.syscall_arg(2);

    if iov_addr == 0 || iovcnt == 0 || total_bytes_read == 0 {
        return Vec::new();
    }

    let iov_bytes = read_guest_bytes(iov_addr, iovcnt * IOVEC_SIZE);
    if iov_bytes.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(total_bytes_read);
    let mut remaining = total_bytes_read;

    for i in 0..iovcnt {
        if remaining == 0 {
            break;
        }
        let offset = i * IOVEC_SIZE;

        #[cfg(target_arch = "x86_64")]
        let (base, len) = {
            let base =
                usize::from_ne_bytes(iov_bytes[offset..offset + 8].try_into().unwrap_or([0; 8]));
            let len = usize::from_ne_bytes(
                iov_bytes[offset + 8..offset + 16]
                    .try_into()
                    .unwrap_or([0; 8]),
            );
            (base, len)
        };

        #[cfg(target_arch = "x86")]
        let (base, len) = {
            let base =
                u32::from_ne_bytes(iov_bytes[offset..offset + 4].try_into().unwrap_or([0; 4]))
                    as usize;
            let len = u32::from_ne_bytes(
                iov_bytes[offset + 4..offset + 8]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;
            (base, len)
        };

        let to_read = len.min(remaining);
        let chunk = read_guest_bytes(base, to_read);
        result.extend_from_slice(&chunk);
        remaining = remaining.saturating_sub(chunk.len());
    }

    result
}

/// During replay, inject the recorded side-effect data back into guest memory.
///
/// `syscall_nr`: raw Linux syscall number
/// `ctx`: register state (contains the original arguments)
/// `data`: the recorded side-effect bytes
pub fn inject_side_effects(syscall_nr: u32, ctx: &litebox_common_linux::PtRegs, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    match syscall_nr {
        // read / pread64: buf = arg1
        nr::READ | nr::PREAD64 => {
            let buf_addr = ctx.syscall_arg(1);
            write_guest_bytes(buf_addr, data);
        }

        // getrandom: buf = arg0
        nr::GETRANDOM => {
            let buf_addr = ctx.syscall_arg(0);
            write_guest_bytes(buf_addr, data);
        }

        // clock_gettime: tp = arg1
        nr::CLOCK_GETTIME => {
            let tp_addr = ctx.syscall_arg(1);
            write_guest_bytes(tp_addr, data);
        }

        // gettimeofday: tv = arg0
        nr::GETTIMEOFDAY => {
            let tv_addr = ctx.syscall_arg(0);
            write_guest_bytes(tv_addr, data);
        }

        // fstat: buf = arg1
        nr::FSTAT => {
            let buf_addr = ctx.syscall_arg(1);
            write_guest_bytes(buf_addr, data);
        }

        // stat: buf = arg1
        #[cfg(target_arch = "x86_64")]
        nr::STAT => {
            let buf_addr = ctx.syscall_arg(1);
            write_guest_bytes(buf_addr, data);
        }

        // lstat: buf = arg1
        #[cfg(target_arch = "x86_64")]
        nr::LSTAT => {
            let buf_addr = ctx.syscall_arg(1);
            write_guest_bytes(buf_addr, data);
        }

        // newfstatat: buf = arg2
        #[cfg(target_arch = "x86_64")]
        nr::NEWFSTATAT => {
            let buf_addr = ctx.syscall_arg(2);
            write_guest_bytes(buf_addr, data);
        }

        // fstatat64: buf = arg2
        #[cfg(target_arch = "x86")]
        nr::FSTATAT64 => {
            let buf_addr = ctx.syscall_arg(2);
            write_guest_bytes(buf_addr, data);
        }

        // getcwd: buf = arg0
        nr::GETCWD => {
            let buf_addr = ctx.syscall_arg(0);
            write_guest_bytes(buf_addr, data);
        }

        // readlink: buf = arg1
        #[cfg(target_arch = "x86_64")]
        nr::READLINK => {
            let buf_addr = ctx.syscall_arg(1);
            write_guest_bytes(buf_addr, data);
        }

        // readlinkat: buf = arg2
        nr::READLINKAT => {
            let buf_addr = ctx.syscall_arg(2);
            write_guest_bytes(buf_addr, data);
        }

        // uname: buf = arg0
        nr::UNAME => {
            let buf_addr = ctx.syscall_arg(0);
            write_guest_bytes(buf_addr, data);
        }

        // pipe2: pipefd = arg0
        nr::PIPE2 => {
            let pipefd_addr = ctx.syscall_arg(0);
            write_guest_bytes(pipefd_addr, data);
        }

        // sysinfo: info = arg0
        nr::SYSINFO => {
            let buf_addr = ctx.syscall_arg(0);
            write_guest_bytes(buf_addr, data);
        }

        // getdents64: dirp = arg1
        nr::GETDENTS64 => {
            let dirp_addr = ctx.syscall_arg(1);
            write_guest_bytes(dirp_addr, data);
        }

        // readv: scatter into iovec buffers
        nr::READV => inject_readv_data(ctx, data),

        // time: tloc = arg0
        nr::TIME => {
            let tloc_addr = ctx.syscall_arg(0);
            if tloc_addr != 0 {
                write_guest_bytes(tloc_addr, data);
            }
        }

        _ => {}
    }
}

/// Inject readv data back into the guest's iovec buffers.
fn inject_readv_data(ctx: &litebox_common_linux::PtRegs, data: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    const IOVEC_SIZE: usize = 16;
    #[cfg(target_arch = "x86")]
    const IOVEC_SIZE: usize = 8;

    let iov_addr = ctx.syscall_arg(1);
    let iovcnt = ctx.syscall_arg(2);

    if iov_addr == 0 || iovcnt == 0 || data.is_empty() {
        return;
    }

    let iov_bytes = read_guest_bytes(iov_addr, iovcnt * IOVEC_SIZE);
    if iov_bytes.is_empty() {
        return;
    }

    let mut written = 0usize;

    for i in 0..iovcnt {
        if written >= data.len() {
            break;
        }
        let offset = i * IOVEC_SIZE;

        #[cfg(target_arch = "x86_64")]
        let (base, len) = {
            let base =
                usize::from_ne_bytes(iov_bytes[offset..offset + 8].try_into().unwrap_or([0; 8]));
            let len = usize::from_ne_bytes(
                iov_bytes[offset + 8..offset + 16]
                    .try_into()
                    .unwrap_or([0; 8]),
            );
            (base, len)
        };

        #[cfg(target_arch = "x86")]
        let (base, len) = {
            let base =
                u32::from_ne_bytes(iov_bytes[offset..offset + 4].try_into().unwrap_or([0; 4]))
                    as usize;
            let len = u32::from_ne_bytes(
                iov_bytes[offset + 4..offset + 8]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;
            (base, len)
        };

        let to_write = len.min(data.len() - written);
        write_guest_bytes(base, &data[written..written + to_write]);
        written += to_write;
    }
}
