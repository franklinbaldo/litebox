// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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

    /// Take the recorded trace data without consuming the RR state.
    ///
    /// Returns `None` if not in recording mode. After this call the
    /// recorder is replaced with a fresh one (so subsequent syscalls
    /// would start a new, empty trace).
    pub fn take_trace(&self) -> Option<Vec<u8>> {
        self.recorder.as_ref().map(|r| {
            let mut guard = r.lock();
            core::mem::replace(&mut *guard, Recorder::new(current_arch())).finish()
        })
    }

    /// Record a signal delivery event during recording mode.
    ///
    /// `signal_nr` is the signal number (e.g., 14 for SIGALRM).
    /// `siginfo_bytes` is the raw `Siginfo` struct serialized as bytes.
    pub fn record_signal(&self, signal_nr: i32, siginfo_bytes: Vec<u8>) {
        if let Some(ref recorder) = self.recorder {
            recorder.lock().record(
                litebox_rr::SIGNAL_DELIVERY_NR,
                i64::from(signal_nr),
                siginfo_bytes,
            );
        }
    }

    /// During replay, check if the next trace event is a signal delivery.
    pub fn peek_is_signal(&self) -> bool {
        self.replayer
            .as_ref()
            .is_some_and(|r| r.lock().peek_event_nr() == Some(litebox_rr::SIGNAL_DELIVERY_NR))
    }

    /// During replay, consume the next signal event from the trace.
    /// Returns `(signal_nr, siginfo_bytes)`.
    pub fn replay_signal(&self) -> Result<(i32, Vec<u8>), litebox_rr::ReplayError> {
        if let Some(ref replayer) = self.replayer {
            let event = replayer
                .lock()
                .expect_event(litebox_rr::SIGNAL_DELIVERY_NR)?;
            #[allow(clippy::cast_possible_truncation)]
            let signal_nr = event.result as i32;
            Ok((signal_nr, event.data))
        } else {
            Err(litebox_rr::ReplayError::EndOfTrace)
        }
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

/// Syscall number constants derived from the `syscalls` crate.
#[allow(clippy::cast_sign_loss)]
mod nr {
    use syscalls::Sysno;

    // --- Structural syscalls (execute during replay) ---
    pub const MMAP: u32 = Sysno::mmap.id() as u32;
    pub const MREMAP: u32 = Sysno::mremap.id() as u32;
    pub const MUNMAP: u32 = Sysno::munmap.id() as u32;
    pub const MPROTECT: u32 = Sysno::mprotect.id() as u32;
    pub const BRK: u32 = Sysno::brk.id() as u32;
    pub const MADVISE: u32 = Sysno::madvise.id() as u32;
    pub const EXIT: u32 = Sysno::exit.id() as u32;
    pub const EXIT_GROUP: u32 = Sysno::exit_group.id() as u32;
    pub const CLONE: u32 = Sysno::clone.id() as u32;
    pub const CLONE3: u32 = Sysno::clone3.id() as u32;
    pub const EXECVE: u32 = Sysno::execve.id() as u32;
    pub const RT_SIGRETURN: u32 = Sysno::rt_sigreturn.id() as u32;
    #[cfg(target_arch = "x86")]
    pub const SIGRETURN: u32 = Sysno::sigreturn.id() as u32;
    #[cfg(target_arch = "x86_64")]
    pub const ARCH_PRCTL: u32 = Sysno::arch_prctl.id() as u32;
    #[cfg(target_arch = "x86")]
    pub const SET_THREAD_AREA: u32 = Sysno::set_thread_area.id() as u32;

    // --- Syscalls with side-effect data (write to guest memory) ---
    pub const READ: u32 = Sysno::read.id() as u32;
    pub const PREAD64: u32 = Sysno::pread64.id() as u32;
    pub const READV: u32 = Sysno::readv.id() as u32;
    pub const GETRANDOM: u32 = Sysno::getrandom.id() as u32;
    pub const CLOCK_GETTIME: u32 = Sysno::clock_gettime.id() as u32;
    pub const GETTIMEOFDAY: u32 = Sysno::gettimeofday.id() as u32;
    pub const TIME: u32 = Sysno::time.id() as u32;
    pub const FSTAT: u32 = Sysno::fstat.id() as u32;
    #[cfg(target_arch = "x86_64")]
    pub const STAT: u32 = Sysno::stat.id() as u32;
    #[cfg(target_arch = "x86_64")]
    pub const LSTAT: u32 = Sysno::lstat.id() as u32;
    #[cfg(target_arch = "x86_64")]
    pub const NEWFSTATAT: u32 = Sysno::newfstatat.id() as u32;
    #[cfg(target_arch = "x86")]
    pub const FSTATAT64: u32 = Sysno::fstatat64.id() as u32;
    pub const GETCWD: u32 = Sysno::getcwd.id() as u32;
    #[cfg(target_arch = "x86_64")]
    pub const READLINK: u32 = Sysno::readlink.id() as u32;
    pub const READLINKAT: u32 = Sysno::readlinkat.id() as u32;
    pub const UNAME: u32 = Sysno::uname.id() as u32;
    pub const PIPE2: u32 = Sysno::pipe2.id() as u32;
    pub const SYSINFO: u32 = Sysno::sysinfo.id() as u32;
    pub const GETDENTS64: u32 = Sysno::getdents64.id() as u32;

    // Signal-related (structural: modify signal handler/mask state, deliver
    // signals internally). kill/tkill/tgkill must execute because they queue
    // signals via send_signal() into LiteBox's internal pending set — this is
    // not captured by the host signal recording path.
    pub const RT_SIGPROCMASK: u32 = Sysno::rt_sigprocmask.id() as u32;
    pub const RT_SIGACTION: u32 = Sysno::rt_sigaction.id() as u32;
    pub const SIGALTSTACK: u32 = Sysno::sigaltstack.id() as u32;
    pub const KILL: u32 = Sysno::kill.id() as u32;
    pub const TKILL: u32 = Sysno::tkill.id() as u32;
    pub const TGKILL: u32 = Sysno::tgkill.id() as u32;

    // Process identity — must be structural so kill/tgkill see consistent
    // pid/tid values (otherwise replay pid/tid mismatch causes ESRCH).
    pub const GETPID: u32 = Sysno::getpid.id() as u32;
    pub const GETTID: u32 = Sysno::gettid.id() as u32;
    pub const GETPPID: u32 = Sysno::getppid.id() as u32;
    pub const GETUID: u32 = Sysno::getuid.id() as u32;
    pub const GETGID: u32 = Sysno::getgid.id() as u32;
    pub const GETEUID: u32 = Sysno::geteuid.id() as u32;
    pub const GETEGID: u32 = Sysno::getegid.id() as u32;

    // Process info
    pub const GETRLIMIT: u32 = Sysno::getrlimit.id() as u32;
    pub const PRLIMIT64: u32 = Sysno::prlimit64.id() as u32;
    pub const PRCTL: u32 = Sysno::prctl.id() as u32;
    pub const SCHED_GETAFFINITY: u32 = Sysno::sched_getaffinity.id() as u32;
    pub const CLOCK_GETRES: u32 = Sysno::clock_getres.id() as u32;
    pub const CLOCK_NANOSLEEP: u32 = Sysno::clock_nanosleep.id() as u32;
    pub const GET_ROBUST_LIST: u32 = Sysno::get_robust_list.id() as u32;

    // Blocking I/O
    pub const PPOLL: u32 = Sysno::ppoll.id() as u32;
    pub const PSELECT6: u32 = Sysno::pselect6.id() as u32;
    pub const EPOLL_PWAIT: u32 = Sysno::epoll_pwait.id() as u32;

    // Network
    pub const RECVFROM: u32 = Sysno::recvfrom.id() as u32;
    pub const ACCEPT: u32 = Sysno::accept.id() as u32;
    pub const ACCEPT4: u32 = Sysno::accept4.id() as u32;
    pub const GETSOCKOPT: u32 = Sysno::getsockopt.id() as u32;
    pub const GETSOCKNAME: u32 = Sysno::getsockname.id() as u32;
    pub const GETPEERNAME: u32 = Sysno::getpeername.id() as u32;
    pub const SOCKETPAIR: u32 = Sysno::socketpair.id() as u32;

    // ioctl
    pub const IOCTL: u32 = Sysno::ioctl.id() as u32;

    // Misc
    pub const CAPGET: u32 = Sysno::capget.id() as u32;
}

/// Returns `true` if the signal is synchronous (caused deterministically by
/// an instruction) and does not need recording. These signals will re-trigger
/// naturally during replay from the same faulting instruction.
pub fn is_synchronous_signal(signal: litebox_common_linux::signal::Signal) -> bool {
    use litebox_common_linux::signal::Signal;
    matches!(
        signal,
        Signal::SIGSEGV | Signal::SIGBUS | Signal::SIGFPE | Signal::SIGILL | Signal::SIGTRAP
    )
}

/// Returns `true` if this syscall is structural and must execute even during
/// replay. These syscalls modify process memory layout, CPU register state,
/// or lifecycle state that cannot be captured as simple return-value +
/// side-effect bytes.
///
/// All other syscalls are replayed from trace (return value + side-effect
/// data injected, actual implementation skipped).
pub fn is_structural(syscall_nr: u32) -> bool {
    matches!(
        syscall_nr,
        // Memory layout
        nr::MMAP
            | nr::MREMAP
            | nr::MUNMAP
            | nr::MPROTECT
            | nr::BRK
            | nr::MADVISE
            // Process lifecycle
            | nr::EXIT
            | nr::EXIT_GROUP
            | nr::CLONE
            | nr::CLONE3
            | nr::EXECVE
            | nr::RT_SIGRETURN
            // Signal infrastructure — handlers, masks, and delivery must be
            // in place during replay. kill/tkill/tgkill queue signals via
            // LiteBox's internal send_signal(), not through host signals, so
            // they must execute to produce the signal.
            | nr::RT_SIGACTION
            | nr::RT_SIGPROCMASK
            | nr::SIGALTSTACK
            | nr::KILL
            | nr::TKILL
            | nr::TGKILL
            // Process identity — must return live values so kill/tgkill
            // see consistent pid/tid during replay.
            | nr::GETPID
            | nr::GETTID
            | nr::GETPPID
            | nr::GETUID
            | nr::GETGID
            | nr::GETEUID
            | nr::GETEGID
    ) || is_structural_arch(syscall_nr)
}

#[cfg(target_arch = "x86_64")]
fn is_structural_arch(syscall_nr: u32) -> bool {
    // arch_prctl(ARCH_SET_FS/ARCH_SET_GS) modifies CPU segment registers
    // via a punchthrough syscall. Must execute during replay for TLS to work.
    // We mark the entire arch_prctl as structural since ARCH_GET_FS also
    // executes harmlessly (reads FS base and writes to guest memory).
    matches!(syscall_nr, nr::ARCH_PRCTL)
}

#[cfg(target_arch = "x86")]
fn is_structural_arch(syscall_nr: u32) -> bool {
    // sigreturn: restores signal frame.
    // set_thread_area: modifies GDT entry for TLS via punchthrough.
    matches!(syscall_nr, nr::SIGRETURN | nr::SET_THREAD_AREA)
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
    let result_signed = return_value.cast_signed();

    // Some syscalls write to guest memory even on error. Handle them first.
    if result_signed < 0 {
        return capture_side_effects_on_error(syscall_nr, ctx, result_signed);
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

        // -----------------------------------------------------------
        // Signal syscalls
        // -----------------------------------------------------------

        // rt_sigprocmask(how, set, oldset, sigsetsize) -> 0
        // oldset = arg2, sizeof(SigSet) = 8
        nr::RT_SIGPROCMASK => {
            let oldset_addr = ctx.syscall_arg(2);
            if oldset_addr != 0 {
                read_guest_bytes(oldset_addr, 8)
            } else {
                Vec::new()
            }
        }

        // rt_sigaction(signum, act, oldact, sigsetsize) -> 0
        // oldact = arg2
        nr::RT_SIGACTION => {
            let oldact_addr = ctx.syscall_arg(2);
            if oldact_addr != 0 {
                read_guest_bytes(
                    oldact_addr,
                    core::mem::size_of::<litebox_common_linux::signal::SigAction>(),
                )
            } else {
                Vec::new()
            }
        }

        // sigaltstack(ss, old_ss) -> 0
        // old_ss = arg1
        nr::SIGALTSTACK => {
            let old_ss_addr = ctx.syscall_arg(1);
            if old_ss_addr != 0 {
                read_guest_bytes(
                    old_ss_addr,
                    core::mem::size_of::<litebox_common_linux::signal::SigAltStack>(),
                )
            } else {
                Vec::new()
            }
        }

        // -----------------------------------------------------------
        // Process info syscalls
        // -----------------------------------------------------------

        // getrlimit(resource, rlim) -> 0
        // rlim = arg1, sizeof(Rlimit) = 2 * sizeof(usize)
        nr::GETRLIMIT => {
            let rlim_addr = ctx.syscall_arg(1);
            read_guest_bytes(
                rlim_addr,
                core::mem::size_of::<litebox_common_linux::Rlimit>(),
            )
        }

        // prlimit64(pid, resource, new_limit, old_limit) -> 0
        // old_limit = arg3, sizeof(Rlimit64) = 16
        nr::PRLIMIT64 => {
            let old_limit_addr = ctx.syscall_arg(3);
            if old_limit_addr != 0 {
                read_guest_bytes(
                    old_limit_addr,
                    core::mem::size_of::<litebox_common_linux::Rlimit64>(),
                )
            } else {
                Vec::new()
            }
        }

        // prctl(option, arg2, ...) -> varies
        // PR_GET_NAME (option=16): writes 16 bytes (TASK_COMM_LEN) at arg2
        nr::PRCTL => {
            let option = ctx.syscall_arg(0);
            if option == 16 {
                // PR_GET_NAME
                let name_addr = ctx.syscall_arg(1);
                read_guest_bytes(name_addr, litebox_common_linux::TASK_COMM_LEN)
            } else {
                Vec::new()
            }
        }

        // arch_prctl(option, addr) -> 0
        // ARCH_GET_FS (0x1003): writes sizeof(usize) at addr (arg1)
        nr::ARCH_PRCTL => {
            let option = ctx.syscall_arg(0);
            if option == 0x1003 {
                // ARCH_GET_FS
                let addr = ctx.syscall_arg(1);
                read_guest_bytes(addr, core::mem::size_of::<usize>())
            } else {
                Vec::new()
            }
        }

        // sched_getaffinity(pid, cpusetsize, mask) -> bytes_written
        // mask = arg2, size = return_value
        nr::SCHED_GETAFFINITY => {
            let mask_addr = ctx.syscall_arg(2);
            read_guest_bytes(mask_addr, return_value)
        }

        // clock_getres(clockid, res) -> 0
        // res = arg1, sizeof(timespec) = 16
        nr::CLOCK_GETRES => {
            let res_addr = ctx.syscall_arg(1);
            if res_addr != 0 {
                read_guest_bytes(res_addr, 16)
            } else {
                Vec::new()
            }
        }

        // clock_nanosleep: side-effects on success are empty (return 0).
        // Side-effects on EINTR are handled in capture_side_effects_on_error.
        nr::CLOCK_NANOSLEEP => Vec::new(),

        // get_robust_list(pid, head_ptr, len_ptr) -> 0
        // head_ptr = arg1 (writes a pointer), len_ptr = arg2 (writes a usize)
        // We concatenate: [head_ptr bytes] + [len bytes]
        nr::GET_ROBUST_LIST => {
            let head_ptr_addr = ctx.syscall_arg(1);
            let len_ptr_addr = ctx.syscall_arg(2);
            let ptr_size = core::mem::size_of::<usize>();
            let mut data = read_guest_bytes(head_ptr_addr, ptr_size);
            data.extend_from_slice(&read_guest_bytes(len_ptr_addr, ptr_size));
            data
        }

        // -----------------------------------------------------------
        // Blocking I/O
        // -----------------------------------------------------------

        // ppoll(fds, nfds, timeout, sigmask, sigsetsize) -> ready_count
        // Writes revents field in each pollfd. Capture entire pollfd array.
        // sizeof(Pollfd) = 8, revents at offset 6 within each.
        nr::PPOLL => {
            let fds_addr = ctx.syscall_arg(0);
            let nfds = ctx.syscall_arg(1);
            read_guest_bytes(
                fds_addr,
                nfds * core::mem::size_of::<litebox_common_linux::Pollfd>(),
            )
        }

        // pselect6(nfds, readfds, writefds, exceptfds, timeout, sigsetpack) -> ready_count
        // Each fd_set is ceil(nfds / bits_per_usize) * sizeof(usize) bytes.
        // Concatenate: [readfds] + [writefds] + [exceptfds] (skip null ones).
        nr::PSELECT6 => {
            let nfds = ctx.syscall_arg(0);
            let bits_per_usize = core::mem::size_of::<usize>() * 8;
            let fd_set_bytes = nfds.div_ceil(bits_per_usize) * core::mem::size_of::<usize>();
            let mut data = Vec::new();
            for arg_idx in 1..=3 {
                let addr = ctx.syscall_arg(arg_idx);
                if addr != 0 {
                    data.extend_from_slice(&read_guest_bytes(addr, fd_set_bytes));
                }
            }
            data
        }

        // epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize) -> ready_count
        // events = arg1, sizeof(EpollEvent) = 12 (packed)
        nr::EPOLL_PWAIT => {
            let events_addr = ctx.syscall_arg(1);
            read_guest_bytes(
                events_addr,
                return_value * core::mem::size_of::<litebox_common_linux::EpollEvent>(),
            )
        }

        // -----------------------------------------------------------
        // Network syscalls
        // -----------------------------------------------------------

        // recvfrom(sockfd, buf, len, flags, addr, addrlen) -> bytes_read
        // buf = arg1, addr = arg4, addrlen = arg5
        nr::RECVFROM => {
            let buf_addr = ctx.syscall_arg(1);
            let mut data = read_guest_bytes(buf_addr, return_value);
            // Capture source address if provided.
            capture_sockaddr(ctx.syscall_arg(4), ctx.syscall_arg(5), &mut data);
            data
        }

        // accept(sockfd, addr, addrlen) / accept4(sockfd, addr, addrlen, flags)
        // addr = arg1, addrlen = arg2
        nr::ACCEPT | nr::ACCEPT4 => {
            let mut data = Vec::new();
            capture_sockaddr(ctx.syscall_arg(1), ctx.syscall_arg(2), &mut data);
            data
        }

        // getsockopt(sockfd, level, optname, optval, optlen) -> 0
        // optval = arg3, optlen = arg4 (in/out u32)
        nr::GETSOCKOPT => {
            let optlen_addr = ctx.syscall_arg(4);
            let optlen_bytes = read_guest_bytes(optlen_addr, 4);
            if optlen_bytes.len() == 4 {
                let optlen =
                    u32::from_ne_bytes(optlen_bytes[..4].try_into().unwrap_or([0; 4])) as usize;
                let optval_addr = ctx.syscall_arg(3);
                let mut data = read_guest_bytes(optval_addr, optlen);
                data.extend_from_slice(&optlen_bytes);
                data
            } else {
                Vec::new()
            }
        }

        // getsockname(sockfd, addr, addrlen) -> 0
        nr::GETSOCKNAME => {
            let mut data = Vec::new();
            capture_sockaddr(ctx.syscall_arg(1), ctx.syscall_arg(2), &mut data);
            data
        }

        // getpeername(sockfd, addr, addrlen) -> 0
        nr::GETPEERNAME => {
            let mut data = Vec::new();
            capture_sockaddr(ctx.syscall_arg(1), ctx.syscall_arg(2), &mut data);
            data
        }

        // socketpair(domain, type, protocol, sv) -> 0
        // sv = arg3, 8 bytes (two i32s)
        nr::SOCKETPAIR => {
            let sv_addr = ctx.syscall_arg(3);
            read_guest_bytes(sv_addr, 8)
        }

        // -----------------------------------------------------------
        // ioctl sub-commands
        // -----------------------------------------------------------

        // ioctl(fd, request, arg) -> 0
        nr::IOCTL => {
            let request = ctx.syscall_arg(1);
            #[allow(clippy::cast_possible_truncation)]
            let request_u32 = request as u32;
            match request_u32 {
                // TCGETS: writes Termios at arg2
                litebox_common_linux::TCGETS => {
                    let buf_addr = ctx.syscall_arg(2);
                    read_guest_bytes(
                        buf_addr,
                        core::mem::size_of::<litebox_common_linux::Termios>(),
                    )
                }
                // TIOCGWINSZ: writes Winsize at arg2
                litebox_common_linux::TIOCGWINSZ => {
                    let buf_addr = ctx.syscall_arg(2);
                    read_guest_bytes(
                        buf_addr,
                        core::mem::size_of::<litebox_common_linux::Winsize>(),
                    )
                }
                _ => Vec::new(),
            }
        }

        // -----------------------------------------------------------
        // Misc
        // -----------------------------------------------------------

        // capget(header, data) -> 0
        // header = arg0, data = arg1
        // Data size depends on header.version (12 for v1, 24 for v2/v3).
        nr::CAPGET => {
            let header_addr = ctx.syscall_arg(0);
            let data_addr = ctx.syscall_arg(1);
            let header_bytes = read_guest_bytes(
                header_addr,
                core::mem::size_of::<litebox_common_linux::CapHeader>(),
            );
            if data_addr == 0 || header_bytes.len() < 4 {
                return Vec::new();
            }
            let version = u32::from_ne_bytes(header_bytes[..4].try_into().unwrap_or([0; 4]));
            let cap_data_size = core::mem::size_of::<litebox_common_linux::CapData>();
            let data_count = match version {
                0x1998_0330 => 1,               // VERSION_1
                0x2007_1026 | 0x2008_0522 => 2, // VERSION_2, VERSION_3
                _ => return Vec::new(),
            };
            read_guest_bytes(data_addr, cap_data_size * data_count)
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

/// Capture side-effect bytes for syscalls that write to guest memory on error.
///
/// Most syscalls only write on success. The exceptions handled here:
/// - `clock_nanosleep`: writes `remain` on `-EINTR` (relative mode only)
/// - `sigaltstack`: writes `old_ss` even on `-EPERM`
fn capture_side_effects_on_error(
    syscall_nr: u32,
    ctx: &litebox_common_linux::PtRegs,
    result_signed: isize,
) -> Vec<u8> {
    use litebox_common_linux::errno::Errno;

    match syscall_nr {
        // clock_nanosleep: writes remain on EINTR if flags != TIMER_ABSTIME (1).
        // remain = arg3
        nr::CLOCK_NANOSLEEP if result_signed == Errno::EINTR.as_neg() as isize => {
            let flags = ctx.syscall_arg(1);
            let remain_addr = ctx.syscall_arg(3);
            if flags & 1 == 0 && remain_addr != 0 {
                // Relative mode, remain was written.
                read_guest_bytes(remain_addr, 16) // sizeof(timespec)
            } else {
                Vec::new()
            }
        }

        // sigaltstack: writes old_ss even when returning EPERM.
        nr::SIGALTSTACK if result_signed == Errno::EPERM.as_neg() as isize => {
            let old_ss_addr = ctx.syscall_arg(1);
            if old_ss_addr != 0 {
                read_guest_bytes(
                    old_ss_addr,
                    core::mem::size_of::<litebox_common_linux::signal::SigAltStack>(),
                )
            } else {
                Vec::new()
            }
        }

        _ => Vec::new(),
    }
}

/// Capture a sockaddr + addrlen pair written by network syscalls.
///
/// Reads the `addrlen` output (4 bytes at `addrlen_addr`), then reads
/// that many bytes from `addr_addr`. Appends all bytes to `out`:
/// `[addr bytes (addrlen)] + [addrlen bytes (4)]`.
fn capture_sockaddr(addr_addr: usize, addrlen_addr: usize, out: &mut Vec<u8>) {
    if addr_addr == 0 || addrlen_addr == 0 {
        return;
    }
    let addrlen_bytes = read_guest_bytes(addrlen_addr, 4);
    if addrlen_bytes.len() < 4 {
        return;
    }
    let addrlen = u32::from_ne_bytes(addrlen_bytes[..4].try_into().unwrap_or([0; 4])) as usize;
    out.extend_from_slice(&read_guest_bytes(addr_addr, addrlen));
    out.extend_from_slice(&addrlen_bytes);
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

        // -----------------------------------------------------------
        // Signal syscalls
        // -----------------------------------------------------------

        // rt_sigprocmask: oldset = arg2
        nr::RT_SIGPROCMASK => {
            let oldset_addr = ctx.syscall_arg(2);
            if oldset_addr != 0 {
                write_guest_bytes(oldset_addr, data);
            }
        }

        // rt_sigaction: oldact = arg2
        nr::RT_SIGACTION => {
            let oldact_addr = ctx.syscall_arg(2);
            if oldact_addr != 0 {
                write_guest_bytes(oldact_addr, data);
            }
        }

        // sigaltstack: old_ss = arg1
        nr::SIGALTSTACK => {
            let old_ss_addr = ctx.syscall_arg(1);
            if old_ss_addr != 0 {
                write_guest_bytes(old_ss_addr, data);
            }
        }

        // -----------------------------------------------------------
        // Process info syscalls
        // -----------------------------------------------------------

        // getrlimit: rlim = arg1
        nr::GETRLIMIT => {
            let rlim_addr = ctx.syscall_arg(1);
            write_guest_bytes(rlim_addr, data);
        }

        // prlimit64: old_limit = arg3
        nr::PRLIMIT64 => {
            let old_limit_addr = ctx.syscall_arg(3);
            if old_limit_addr != 0 {
                write_guest_bytes(old_limit_addr, data);
            }
        }

        // prctl: PR_GET_NAME writes at arg1
        nr::PRCTL => {
            let option = ctx.syscall_arg(0);
            if option == 16 {
                let name_addr = ctx.syscall_arg(1);
                write_guest_bytes(name_addr, data);
            }
        }

        // arch_prctl: ARCH_GET_FS writes at arg1
        nr::ARCH_PRCTL => {
            let option = ctx.syscall_arg(0);
            if option == 0x1003 {
                let addr = ctx.syscall_arg(1);
                write_guest_bytes(addr, data);
            }
        }

        // sched_getaffinity: mask = arg2
        nr::SCHED_GETAFFINITY => {
            let mask_addr = ctx.syscall_arg(2);
            write_guest_bytes(mask_addr, data);
        }

        // clock_getres: res = arg1
        nr::CLOCK_GETRES => {
            let res_addr = ctx.syscall_arg(1);
            if res_addr != 0 {
                write_guest_bytes(res_addr, data);
            }
        }

        // clock_nanosleep: remain = arg3 (on EINTR, relative mode)
        nr::CLOCK_NANOSLEEP => {
            let remain_addr = ctx.syscall_arg(3);
            if remain_addr != 0 {
                write_guest_bytes(remain_addr, data);
            }
        }

        // get_robust_list: data = [head_ptr bytes] + [len bytes]
        nr::GET_ROBUST_LIST => {
            let ptr_size = core::mem::size_of::<usize>();
            if data.len() >= ptr_size * 2 {
                let head_ptr_addr = ctx.syscall_arg(1);
                let len_ptr_addr = ctx.syscall_arg(2);
                write_guest_bytes(head_ptr_addr, &data[..ptr_size]);
                write_guest_bytes(len_ptr_addr, &data[ptr_size..ptr_size * 2]);
            }
        }

        // -----------------------------------------------------------
        // Blocking I/O
        // -----------------------------------------------------------

        // ppoll: write entire pollfd array back to arg0
        nr::PPOLL => {
            let fds_addr = ctx.syscall_arg(0);
            write_guest_bytes(fds_addr, data);
        }

        // pselect6: data = [readfds] + [writefds] + [exceptfds] (concatenated)
        nr::PSELECT6 => {
            let nfds = ctx.syscall_arg(0);
            let bits_per_usize = core::mem::size_of::<usize>() * 8;
            let fd_set_bytes = nfds.div_ceil(bits_per_usize) * core::mem::size_of::<usize>();
            let mut offset = 0;
            for arg_idx in 1..=3 {
                let addr = ctx.syscall_arg(arg_idx);
                if addr != 0 && offset + fd_set_bytes <= data.len() {
                    write_guest_bytes(addr, &data[offset..offset + fd_set_bytes]);
                    offset += fd_set_bytes;
                }
            }
        }

        // epoll_pwait: events = arg1
        nr::EPOLL_PWAIT => {
            let events_addr = ctx.syscall_arg(1);
            write_guest_bytes(events_addr, data);
        }

        // -----------------------------------------------------------
        // Network syscalls
        // -----------------------------------------------------------

        // recvfrom: data = [buf bytes] + [addr bytes] + [addrlen (4)]
        nr::RECVFROM => {
            let buf_addr = ctx.syscall_arg(1);
            let addr_addr = ctx.syscall_arg(4);
            let addrlen_addr = ctx.syscall_arg(5);
            // The buf portion length is return_value, which we can infer:
            // total data = buf_bytes + addr_bytes + addrlen(4).
            // But we can compute it: if addr_addr != 0, last 4 bytes are addrlen,
            // and the addrlen value tells us the addr size, remainder is buf.
            if addr_addr != 0 && addrlen_addr != 0 && data.len() >= 4 {
                inject_sockaddr_from_tail(addr_addr, addrlen_addr, data, buf_addr);
            } else {
                write_guest_bytes(buf_addr, data);
            }
        }

        // accept / accept4: data = [addr bytes] + [addrlen (4)]
        nr::ACCEPT | nr::ACCEPT4 => {
            let addr_addr = ctx.syscall_arg(1);
            let addrlen_addr = ctx.syscall_arg(2);
            if addr_addr != 0 && addrlen_addr != 0 {
                inject_sockaddr(addr_addr, addrlen_addr, data);
            }
        }

        // getsockopt: data = [optval bytes] + [optlen (4)]
        nr::GETSOCKOPT => {
            if data.len() >= 4 {
                let optval_addr = ctx.syscall_arg(3);
                let optlen_addr = ctx.syscall_arg(4);
                let optlen_bytes = &data[data.len() - 4..];
                let optval_bytes = &data[..data.len() - 4];
                write_guest_bytes(optval_addr, optval_bytes);
                write_guest_bytes(optlen_addr, optlen_bytes);
            }
        }

        // getsockname: data = [addr bytes] + [addrlen (4)]
        nr::GETSOCKNAME => {
            let addr_addr = ctx.syscall_arg(1);
            let addrlen_addr = ctx.syscall_arg(2);
            inject_sockaddr(addr_addr, addrlen_addr, data);
        }

        // getpeername: data = [addr bytes] + [addrlen (4)]
        nr::GETPEERNAME => {
            let addr_addr = ctx.syscall_arg(1);
            let addrlen_addr = ctx.syscall_arg(2);
            inject_sockaddr(addr_addr, addrlen_addr, data);
        }

        // socketpair: sv = arg3
        nr::SOCKETPAIR => {
            let sv_addr = ctx.syscall_arg(3);
            write_guest_bytes(sv_addr, data);
        }

        // -----------------------------------------------------------
        // ioctl sub-commands
        // -----------------------------------------------------------
        nr::IOCTL => {
            let request = ctx.syscall_arg(1);
            #[allow(clippy::cast_possible_truncation)]
            let request_u32 = request as u32;
            match request_u32 {
                litebox_common_linux::TCGETS | litebox_common_linux::TIOCGWINSZ => {
                    let buf_addr = ctx.syscall_arg(2);
                    write_guest_bytes(buf_addr, data);
                }
                _ => {}
            }
        }

        // -----------------------------------------------------------
        // Misc
        // -----------------------------------------------------------

        // capget: data at arg1
        nr::CAPGET => {
            let data_addr = ctx.syscall_arg(1);
            if data_addr != 0 {
                write_guest_bytes(data_addr, data);
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

/// Inject a sockaddr + addrlen pair from recorded data.
///
/// The data layout is `[addr bytes (addrlen)] + [addrlen bytes (4)]`.
fn inject_sockaddr(addr_addr: usize, addrlen_addr: usize, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let addrlen_bytes = &data[data.len() - 4..];
    let addr_bytes = &data[..data.len() - 4];
    write_guest_bytes(addr_addr, addr_bytes);
    write_guest_bytes(addrlen_addr, addrlen_bytes);
}

/// For recvfrom: data layout is `[buf bytes] + [addr bytes] + [addrlen (4)]`.
///
/// The last 4 bytes are the addrlen value, which tells us the addr size.
/// Everything before `addr + addrlen` is the buf data.
fn inject_sockaddr_from_tail(addr_addr: usize, addrlen_addr: usize, data: &[u8], buf_addr: usize) {
    // Last 4 bytes = addrlen value
    let addrlen_bytes = &data[data.len() - 4..];
    let addrlen = u32::from_ne_bytes(addrlen_bytes[..4].try_into().unwrap_or([0; 4])) as usize;

    // The sockaddr data is right before the addrlen bytes
    if data.len() < 4 + addrlen {
        // Fallback: just write everything as buf
        write_guest_bytes(buf_addr, data);
        return;
    }
    let addr_start = data.len() - 4 - addrlen;
    let buf_bytes = &data[..addr_start];
    let addr_bytes = &data[addr_start..data.len() - 4];

    write_guest_bytes(buf_addr, buf_bytes);
    write_guest_bytes(addr_addr, addr_bytes);
    write_guest_bytes(addrlen_addr, addrlen_bytes);
}
