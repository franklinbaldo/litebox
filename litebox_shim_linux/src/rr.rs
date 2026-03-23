// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Record-and-replay support for the Linux shim.
//!
//! When enabled via the `rr` feature, syscall execution can be recorded to a
//! trace buffer or replayed from a previously recorded trace.

use alloc::collections::BTreeSet;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use litebox_rr::{Event, EventKind, Recorder, ReplayError, Replayer, TraceArch, TraceMetadata};

use litebox::mm::linux::VmFlags;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};

use crate::{MutPtr, Platform};

type Mutex<T> = litebox::sync::Mutex<Platform, T>;

/// Public re-exports of syscall number constants needed by the dispatch logic
/// in `lib.rs`.
pub mod nr_pub {
    pub use super::nr::{EXECVE, EXIT, EXIT_GROUP, MMAP};
}

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

/// Summary of a consumed trace event, stored in the event history ring buffer
/// for divergence diagnostics.
struct EventSummary {
    event_index: u64,
    syscall_nr: u32,
    tid: u32,
    kind: litebox_rr::EventKind,
    result: i64,
}

/// Record-replay state attached to a `GlobalState`.
pub struct RRState {
    mode: RRMode,
    /// Only present in Record mode.
    recorder: Option<Mutex<Recorder>>,
    /// Only present in Replay mode.
    replayer: Option<Mutex<Replayer>>,
    /// Serializes thread execution. Present in Record and Replay modes.
    coordinator: Option<RunCoordinator>,
    /// When true, write/writev to stdout/stderr are executed on the host
    /// during replay so that program output is visible.
    replay_stdout: bool,
    /// Guest virtual address of the rewriter trampoline page from the most
    /// recent `load_program()` call. Used to capture execve snapshots.
    last_trampoline_start: core::sync::atomic::AtomicUsize,
    /// Ring buffer of recently consumed trace events for divergence diagnostics.
    event_history: Mutex<VecDeque<EventSummary>>,
}

impl RRState {
    /// Create a new RR state in the given mode.
    ///
    /// For `Record` mode, a [`RunCoordinator`] is created but no threads
    /// are registered yet — call
    /// [`RunCoordinator::register_initial_thread`] from the main thread
    /// before dispatching any syscalls.
    ///
    /// # Panics
    ///
    /// Panics if called with `RRMode::Replay`. Use [`RRState::new_replay`]
    /// instead.
    pub fn new(mode: RRMode, metadata: Option<TraceMetadata>) -> Self {
        match mode {
            RRMode::Off => Self {
                mode,
                recorder: None,
                replayer: None,
                coordinator: None,
                replay_stdout: false,
                last_trampoline_start: core::sync::atomic::AtomicUsize::new(0),
                event_history: Mutex::new(VecDeque::with_capacity(16)),
            },
            RRMode::Record => Self {
                mode,
                recorder: Some(Mutex::new(Recorder::new(current_arch(), metadata))),
                replayer: None,
                coordinator: Some(RunCoordinator::new()),
                replay_stdout: false,
                last_trampoline_start: core::sync::atomic::AtomicUsize::new(0),
                event_history: Mutex::new(VecDeque::with_capacity(16)),
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
            coordinator: Some(RunCoordinator::new()),
            replay_stdout: false,
            last_trampoline_start: core::sync::atomic::AtomicUsize::new(0),
            event_history: Mutex::new(VecDeque::with_capacity(16)),
        })
    }

    /// Return the current mode.
    pub fn mode(&self) -> RRMode {
        self.mode
    }

    /// Enable or disable stdout/stderr replay output.
    pub fn set_replay_stdout(&mut self, enabled: bool) {
        self.replay_stdout = enabled;
    }

    /// Returns `true` if stdout/stderr writes should be executed during replay.
    pub fn replay_stdout(&self) -> bool {
        self.replay_stdout
    }

    /// Store the trampoline start address from the most recent `load_program()`.
    pub fn set_last_trampoline_start(&self, addr: usize) {
        self.last_trampoline_start
            .store(addr, core::sync::atomic::Ordering::Relaxed);
    }

    /// Retrieve the trampoline start address from the most recent `load_program()`.
    pub fn last_trampoline_start(&self) -> usize {
        self.last_trampoline_start
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Return a reference to the run coordinator.
    ///
    /// Returns `None` when RR is disabled (`RRMode::Off`).
    pub fn coordinator(&self) -> Option<&RunCoordinator> {
        self.coordinator.as_ref()
    }

    /// Record a syscall event during recording mode.
    ///
    /// `syscall_nr` is the raw Linux syscall number.
    /// `result` is the return value (positive = success, negative = -errno).
    /// `data` is the side-effect data (bytes written to guest buffers).
    /// `tid` identifies the thread that produced this event.
    /// `kind` indicates whether the event is a complete syscall, blocking
    /// entry/exit, or signal delivery.
    pub fn record_event(
        &self,
        syscall_nr: u32,
        result: i64,
        data: Vec<u8>,
        tid: u32,
        kind: EventKind,
    ) {
        if let Some(ref recorder) = self.recorder {
            recorder.lock().record(syscall_nr, result, data, tid, kind);
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
            .map(|r| core::mem::replace(r.get_mut(), Recorder::new(current_arch(), None)).finish())
    }

    /// Take the recorded trace data without consuming the RR state.
    ///
    /// Returns `None` if not in recording mode. After this call the
    /// recorder is replaced with a fresh one (so subsequent syscalls
    /// would start a new, empty trace).
    pub fn take_trace(&self) -> Option<Vec<u8>> {
        self.recorder.as_ref().map(|r| {
            let mut guard = r.lock();
            core::mem::replace(&mut *guard, Recorder::new(current_arch(), None)).finish()
        })
    }

    /// Record a signal delivery event during recording mode.
    ///
    /// `signal_nr` is the signal number (e.g., 14 for SIGALRM).
    /// `siginfo_bytes` is the raw `Siginfo` struct serialized as bytes.
    /// `tid` identifies the thread that received the signal.
    pub fn record_signal(&self, signal_nr: i32, siginfo_bytes: Vec<u8>, tid: u32) {
        if let Some(ref recorder) = self.recorder {
            recorder.lock().record(
                litebox_rr::SIGNAL_DELIVERY_NR,
                i64::from(signal_nr),
                siginfo_bytes,
                tid,
                EventKind::Signal,
            );
        }
    }

    /// During replay, check if the next trace event is a signal delivery.
    pub fn peek_is_signal(&self) -> bool {
        self.replayer
            .as_ref()
            .is_some_and(|r| r.lock().peek_event_nr() == Some(litebox_rr::SIGNAL_DELIVERY_NR))
    }

    /// During replay, peek at the result field of the next trace event
    /// without consuming it. Returns `None` if the trace is exhausted.
    pub fn peek_event_result(&self) -> Option<i64> {
        self.replayer
            .as_ref()
            .and_then(|r| r.lock().peek_event_result())
    }

    /// During replay, peek at the `tid` field of the next trace event
    /// without consuming it. Returns `None` if the trace is exhausted.
    pub fn peek_event_tid(&self) -> Option<u32> {
        self.replayer
            .as_ref()
            .and_then(|r| r.lock().peek_event_tid())
    }

    /// During replay, peek at the `kind` field of the next trace event
    /// without consuming it. Returns `None` if the trace is exhausted.
    pub fn peek_event_kind(&self) -> Option<EventKind> {
        self.replayer
            .as_ref()
            .and_then(|r| r.lock().peek_event_kind())
    }

    /// During replay, peek at the `data_len` field of the next trace event
    /// without consuming it. Returns `None` if the trace is exhausted.
    pub fn peek_event_data_len(&self) -> Option<u32> {
        self.replayer
            .as_ref()
            .and_then(|r| r.lock().peek_event_data_len())
    }

    /// Records a memory snapshot event during recording.
    ///
    /// `snapshot_data` is the serialized memory snapshot.
    /// `tid` is the RR-normalized thread id.
    pub fn record_snapshot(&self, snapshot_data: Vec<u8>, tid: u32) {
        if let Some(ref recorder) = self.recorder {
            recorder.lock().record_snapshot(snapshot_data, tid);
        }
    }

    /// Returns `true` if the next replay event is a memory snapshot.
    pub fn peek_is_snapshot(&self) -> bool {
        self.replayer
            .as_ref()
            .is_some_and(|r| r.lock().peek_is_snapshot())
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

    /// Wrapper around [`replay_event()`] that also pushes the consumed event
    /// into the history ring buffer and, on divergence, formats a rich error
    /// message including syscall names, register arguments, and recent history.
    pub fn replay_event_checked(
        &self,
        actual_syscall_nr: u32,
        actual_tid: u32,
        ctx: &litebox_common_linux::PtRegs,
    ) -> Result<Event, alloc::string::String> {
        match self.replay_event(actual_syscall_nr) {
            Ok(event) => {
                self.push_event_history(&event);
                Ok(event)
            }
            Err(ReplayError::Divergence {
                event_id,
                expected_syscall_nr,
                actual_syscall_nr,
            }) => Err(alloc::format!(
                "RR DIVERGENCE at event #{event_id}:\n\
                 \x20 Expected: syscall {} (nr={expected_syscall_nr})\n\
                 \x20 Actual:   syscall {} (nr={actual_syscall_nr}) tid={actual_tid}\n\
                 \x20 Syscall args: [{}]\n\
                 \x20 Event history (last 10):\n{}",
                syscall_name(expected_syscall_nr),
                syscall_name(actual_syscall_nr),
                format_syscall_args(ctx),
                self.format_event_history(),
            )),
            Err(ReplayError::EndOfTrace) => Err(alloc::format!(
                "RR unexpected end of trace:\n\
                 \x20 Actual: syscall {} (nr={actual_syscall_nr}) tid={actual_tid}\n\
                 \x20 Syscall args: [{}]\n\
                 \x20 Event history (last 10):\n{}",
                syscall_name(actual_syscall_nr),
                format_syscall_args(ctx),
                self.format_event_history(),
            )),
            Err(e) => Err(alloc::format!("RR replay error: {e:?}")),
        }
    }

    /// Record a consumed event in the history ring buffer (max 10 entries).
    fn push_event_history(&self, event: &litebox_rr::Event) {
        let mut history = self.event_history.lock();
        if history.len() >= 10 {
            history.pop_front();
        }
        history.push_back(EventSummary {
            event_index: event.event_id,
            syscall_nr: event.syscall_nr,
            tid: event.tid,
            kind: event.kind,
            result: event.result,
        });
    }

    /// Format the event history for divergence diagnostics.
    fn format_event_history(&self) -> alloc::string::String {
        use alloc::fmt::Write;
        let history = self.event_history.lock();
        let mut out = alloc::string::String::new();
        for entry in history.iter() {
            let name = syscall_name(entry.syscall_nr);
            let kind_str = match entry.kind {
                litebox_rr::EventKind::Complete => "",
                litebox_rr::EventKind::Entry => " [ENTRY]",
                litebox_rr::EventKind::Exit => " [EXIT]",
                litebox_rr::EventKind::Signal => " [SIGNAL]",
                litebox_rr::EventKind::Snapshot => " [SNAPSHOT]",
            };
            let _ = writeln!(
                out,
                "    #{}: tid={} {} (nr={}){} -> {}",
                entry.event_index, entry.tid, name, entry.syscall_nr, kind_str, entry.result
            );
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Run coordinator — serializes guest thread execution
// ---------------------------------------------------------------------------

/// Serializes guest thread execution so only one thread runs at a time.
///
/// During recording, any runnable thread may be granted the token.
/// During replay, only the thread matching the next trace event's tid
/// is granted the token.
pub struct RunCoordinator {
    inner: Mutex<CoordinatorInner>,
}

struct CoordinatorInner {
    /// TID of the thread currently holding the run token, or 0 if idle.
    current_tid: i32,
    /// Threads that are runnable (waiting for the token).
    runnable: BTreeSet<i32>,
    /// Threads that are blocked inside a syscall (released the token).
    blocked: BTreeSet<i32>,
    /// When true, all threads should exit.
    shutdown: bool,
}

impl Default for RunCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl RunCoordinator {
    /// Create a new empty coordinator. No threads are registered yet.
    /// Call [`register_initial_thread`] to add and grant the first thread.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CoordinatorInner {
                current_tid: 0,
                runnable: BTreeSet::new(),
                blocked: BTreeSet::new(),
                shutdown: false,
            }),
        }
    }

    /// Register and grant the token to the initial (main) thread.
    /// Must be called exactly once before any other thread operations.
    ///
    /// # Panics
    ///
    /// Panics if a thread already holds the token.
    pub fn register_initial_thread(&self, tid: i32) {
        let mut inner = self.inner.lock();
        assert_eq!(
            inner.current_tid, 0,
            "register_initial_thread: token already held"
        );
        inner.runnable.insert(tid);
        inner.current_tid = tid;
    }

    /// Register a new thread as runnable. It will not run until granted
    /// the token.
    pub fn register_thread(&self, tid: i32) {
        let mut inner = self.inner.lock();
        inner.runnable.insert(tid);
    }

    /// Remove a thread from all sets (on exit).
    pub fn remove_thread(&self, tid: i32) {
        let mut inner = self.inner.lock();
        inner.runnable.remove(&tid);
        inner.blocked.remove(&tid);
        if inner.current_tid == tid {
            inner.current_tid = 0;
        }
    }

    /// Release the run token after a syscall completes. The caller must
    /// hold the token (current_tid == tid).
    ///
    /// # Panics
    ///
    /// Panics if `tid` does not match the current token holder.
    pub fn release_token(&self, tid: i32) {
        let mut inner = self.inner.lock();
        assert_eq!(inner.current_tid, tid, "release_token: tid mismatch");
        inner.current_tid = 0;
    }

    /// Wait until this thread is granted the run token.
    /// Returns false if the coordinator has been shut down.
    pub fn acquire_token(&self, tid: i32) -> bool {
        loop {
            {
                let inner = self.inner.lock();
                if inner.shutdown {
                    return false;
                }
                if inner.current_tid == tid {
                    return true;
                }
            }
            // Spin-wait: hint the CPU that we're in a busy loop.
            // In the litebox no_std context there is no condvar available,
            // so spin_loop is the best we can do.
            core::hint::spin_loop();
        }
    }

    /// Grant the token to a specific thread (used by replay coordinator).
    ///
    /// # Panics
    ///
    /// Panics if another thread already holds the token.
    pub fn grant_token(&self, tid: i32) {
        let mut inner = self.inner.lock();
        assert_eq!(inner.current_tid, 0, "grant_token: token already held");
        inner.current_tid = tid;
    }

    /// Pick the next runnable thread and grant it the token.
    /// Used during recording (any runnable thread is fine).
    /// Returns the tid that was granted, or 0 if no threads are runnable.
    ///
    /// # Panics
    ///
    /// Panics if another thread already holds the token.
    pub fn grant_next_runnable(&self) -> i32 {
        let mut inner = self.inner.lock();
        assert_eq!(inner.current_tid, 0, "grant_next: token already held");
        if let Some(&tid) = inner.runnable.iter().next() {
            inner.current_tid = tid;
            tid
        } else {
            0
        }
    }

    /// Try to grant the token to the next runnable thread, but only if
    /// no thread currently holds the token. This is a no-op if a thread
    /// already has the token or no threads are runnable.
    ///
    /// Returns the tid that was granted, or 0 if nothing was done.
    pub fn try_grant_next_runnable(&self) -> i32 {
        let mut inner = self.inner.lock();
        if inner.current_tid != 0 {
            return 0;
        }
        if let Some(&tid) = inner.runnable.iter().next() {
            inner.current_tid = tid;
            tid
        } else {
            0
        }
    }

    /// Move a thread from runnable to blocked (entering a blocking syscall).
    ///
    /// # Panics
    ///
    /// Panics if `tid` does not match the current token holder.
    pub fn enter_blocking(&self, tid: i32) {
        let mut inner = self.inner.lock();
        assert_eq!(inner.current_tid, tid, "enter_blocking: not token holder");
        inner.runnable.remove(&tid);
        inner.blocked.insert(tid);
        inner.current_tid = 0;
    }

    /// Move a thread from blocked to runnable (woke up from blocking syscall).
    pub fn exit_blocking(&self, tid: i32) {
        let mut inner = self.inner.lock();
        inner.blocked.remove(&tid);
        inner.runnable.insert(tid);
    }

    /// Signal all threads to shut down.
    pub fn shutdown(&self) {
        let mut inner = self.inner.lock();
        inner.shutdown = true;
    }

    /// Check if shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.inner.lock().shutdown
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
    pub const RECVMSG: u32 = Sysno::recvmsg.id() as u32;
    pub const SENDTO: u32 = Sysno::sendto.id() as u32;
    pub const SENDMSG: u32 = Sysno::sendmsg.id() as u32;
    pub const CONNECT: u32 = Sysno::connect.id() as u32;
    pub const ACCEPT: u32 = Sysno::accept.id() as u32;
    pub const ACCEPT4: u32 = Sysno::accept4.id() as u32;
    pub const GETSOCKOPT: u32 = Sysno::getsockopt.id() as u32;
    pub const GETSOCKNAME: u32 = Sysno::getsockname.id() as u32;
    pub const GETPEERNAME: u32 = Sysno::getpeername.id() as u32;
    pub const SOCKETPAIR: u32 = Sysno::socketpair.id() as u32;

    // Blocking
    pub const FUTEX: u32 = Sysno::futex.id() as u32;
    pub const NANOSLEEP: u32 = Sysno::nanosleep.id() as u32;
    pub const WRITE: u32 = Sysno::write.id() as u32;
    pub const WRITEV: u32 = Sysno::writev.id() as u32;
    pub const POLL: u32 = Sysno::poll.id() as u32;
    pub const EPOLL_WAIT: u32 = Sysno::epoll_wait.id() as u32;
    pub const RT_SIGTIMEDWAIT: u32 = Sysno::rt_sigtimedwait.id() as u32;

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

/// Human-readable name for common syscall numbers, used in divergence diagnostics.
pub fn syscall_name(nr: u32) -> &'static str {
    match nr {
        nr::MMAP => "mmap",
        nr::MREMAP => "mremap",
        nr::MUNMAP => "munmap",
        nr::MPROTECT => "mprotect",
        nr::BRK => "brk",
        nr::READ => "read",
        nr::PREAD64 => "pread64",
        nr::READV => "readv",
        nr::WRITE => "write",
        nr::WRITEV => "writev",
        nr::GETRANDOM => "getrandom",
        nr::CLOCK_GETTIME => "clock_gettime",
        nr::GETTIMEOFDAY => "gettimeofday",
        nr::TIME => "time",
        nr::FSTAT => "fstat",
        nr::GETCWD => "getcwd",
        nr::UNAME => "uname",
        nr::PIPE2 => "pipe2",
        nr::GETDENTS64 => "getdents64",
        nr::FUTEX => "futex",
        nr::NANOSLEEP => "nanosleep",
        nr::CLOCK_NANOSLEEP => "clock_nanosleep",
        nr::PPOLL => "ppoll",
        nr::POLL => "poll",
        nr::PSELECT6 => "pselect6",
        nr::EPOLL_PWAIT => "epoll_pwait",
        nr::EPOLL_WAIT => "epoll_wait",
        nr::RECVFROM => "recvfrom",
        nr::RECVMSG => "recvmsg",
        nr::SENDTO => "sendto",
        nr::SENDMSG => "sendmsg",
        nr::CONNECT => "connect",
        nr::ACCEPT => "accept",
        nr::ACCEPT4 => "accept4",
        nr::CLONE => "clone",
        nr::CLONE3 => "clone3",
        nr::EXECVE => "execve",
        nr::EXIT => "exit",
        nr::EXIT_GROUP => "exit_group",
        nr::RT_SIGACTION => "rt_sigaction",
        nr::RT_SIGPROCMASK => "rt_sigprocmask",
        nr::SIGALTSTACK => "sigaltstack",
        nr::RT_SIGRETURN => "rt_sigreturn",
        nr::RT_SIGTIMEDWAIT => "rt_sigtimedwait",
        nr::KILL => "kill",
        nr::TKILL => "tkill",
        nr::TGKILL => "tgkill",
        nr::GETPID => "getpid",
        nr::GETTID => "gettid",
        nr::IOCTL => "ioctl",
        nr::MADVISE => "madvise",
        nr::SYSINFO => "sysinfo",
        nr::SOCKETPAIR => "socketpair",
        nr::GETSOCKOPT => "getsockopt",
        nr::GETSOCKNAME => "getsockname",
        nr::GETPEERNAME => "getpeername",
        nr::CAPGET => "capget",
        _ => "unknown",
    }
}

fn format_syscall_args(ctx: &litebox_common_linux::PtRegs) -> alloc::string::String {
    alloc::format!(
        "{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}",
        ctx.syscall_arg(0),
        ctx.syscall_arg(1),
        ctx.syscall_arg(2),
        ctx.syscall_arg(3),
        ctx.syscall_arg(4),
        ctx.syscall_arg(5),
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

/// Returns `true` if this syscall may block the calling thread.
///
/// During recording, blocking syscalls produce an ENTRY event (token released)
/// and an EXIT event (token reacquired, result captured). This allows other
/// threads to run while one thread is blocked in a syscall like `futex_wait`
/// or `nanosleep`.
pub fn is_potentially_blocking(syscall_nr: u32) -> bool {
    matches!(
        syscall_nr,
        nr::FUTEX
            | nr::NANOSLEEP
            | nr::CLOCK_NANOSLEEP
            | nr::READ
            | nr::READV
            | nr::WRITE
            | nr::WRITEV
            | nr::RECVFROM
            | nr::RECVMSG
            | nr::SENDTO
            | nr::SENDMSG
            | nr::POLL
            | nr::PPOLL
            | nr::PSELECT6
            | nr::EPOLL_WAIT
            | nr::EPOLL_PWAIT
            | nr::ACCEPT
            | nr::ACCEPT4
            | nr::CONNECT
            | nr::RT_SIGTIMEDWAIT
    )
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

/// During replay with `--rr-replay-stdout`, execute `write`/`writev` on the
/// host for stdout (fd 1) and stderr (fd 2) so that program output is visible.
///
/// The return value still comes from the trace — this only performs the I/O
/// side effect.
///
/// # Panics
///
/// Does not panic.
pub fn maybe_replay_stdio_write(
    syscall_nr: u32,
    ctx: &litebox_common_linux::PtRegs,
    replay_stdout: bool,
) {
    if !replay_stdout {
        return;
    }

    let fd = ctx.syscall_arg(0);
    // Only replay writes to stdout (1) or stderr (2).
    if fd != 1 && fd != 2 {
        return;
    }

    match syscall_nr {
        nr::WRITE => {
            let buf_addr = ctx.syscall_arg(1);
            let count = ctx.syscall_arg(2);
            let buf = read_guest_bytes(buf_addr, count);
            if !buf.is_empty() {
                // SAFETY: buf points to a valid slice from read_guest_bytes,
                // fd is 1 or 2 (stdout/stderr), which are valid host fds.
                unsafe {
                    syscalls::raw::syscall3(
                        syscalls::Sysno::write,
                        fd,
                        buf.as_ptr() as usize,
                        buf.len(),
                    );
                }
            }
        }
        nr::WRITEV => {
            let iov_addr = ctx.syscall_arg(1);
            let iovcnt = ctx.syscall_arg(2);
            // Each iovec is { base: *const u8, len: usize } = 2 * size_of::<usize>() bytes.
            let iovec_size = 2 * core::mem::size_of::<usize>();
            let iov_bytes = read_guest_bytes(iov_addr, iovcnt * iovec_size);
            if iov_bytes.is_empty() {
                return;
            }
            for i in 0..iovcnt {
                let offset = i * iovec_size;
                if offset + iovec_size > iov_bytes.len() {
                    break;
                }
                let base = usize::from_ne_bytes(
                    iov_bytes[offset..offset + core::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap_or([0; core::mem::size_of::<usize>()]),
                );
                let len = usize::from_ne_bytes(
                    iov_bytes[offset + core::mem::size_of::<usize>()..offset + iovec_size]
                        .try_into()
                        .unwrap_or([0; core::mem::size_of::<usize>()]),
                );
                let buf = read_guest_bytes(base, len);
                if !buf.is_empty() {
                    // SAFETY: buf points to a valid slice from read_guest_bytes,
                    // fd is 1 or 2 (stdout/stderr), which are valid host fds.
                    unsafe {
                        syscalls::raw::syscall3(
                            syscalls::Sysno::write,
                            fd,
                            buf.as_ptr() as usize,
                            buf.len(),
                        );
                    }
                }
            }
        }
        _ => {}
    }
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

        // rt_sigtimedwait(set, info, timeout, sigsetsize) -> signal_nr
        // info = arg1, sizeof(siginfo_t) = 128
        nr::RT_SIGTIMEDWAIT => {
            let info_addr = ctx.syscall_arg(1);
            if info_addr != 0 {
                read_guest_bytes(info_addr, 128) // sizeof(siginfo_t)
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

        // poll(fds, nfds, timeout) -> ready_count
        // Same as ppoll: capture entire pollfd array with updated revents.
        nr::POLL => {
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

        // epoll_wait(epfd, events, maxevents, timeout) -> ready_count
        // Same as epoll_pwait: capture ready_count epoll_event structs.
        nr::EPOLL_WAIT => {
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

        // recvmsg(sockfd, msg, flags) -> bytes_received
        nr::RECVMSG => capture_recvmsg_data(ctx, return_value),

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

        // mmap(addr, len, prot, flags, fd, offset) -> mapped_addr
        // For file-backed mmaps (MAP_ANONYMOUS not set), capture the mapped
        // memory contents so the trace is self-contained. During replay, the
        // fd may be a phantom (the corresponding open was non-structural and
        // never actually executed), so we convert the mmap to anonymous and
        // inject the captured data.
        nr::MMAP => {
            let flags = ctx.syscall_arg(3);
            // MAP_ANONYMOUS = 0x20
            let is_anonymous = flags & 0x20 != 0;
            if !is_anonymous && return_value != 0 {
                let len = ctx.syscall_arg(1);
                read_guest_bytes(return_value, len)
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

/// Capture `recvmsg` output: scatter-gather iovec data + updated msghdr fields.
///
/// Serialized format:
/// - `msg_namelen` (4 bytes LE) — updated name length
/// - `msg_name` data (`msg_namelen` bytes)
/// - `msg_controllen` (8 bytes LE) — updated control length
/// - `msg_control` data (`msg_controllen` bytes)
/// - `msg_flags` (4 bytes LE)
/// - iovec scatter data (concatenated, total = `return_value` bytes)
fn capture_recvmsg_data(ctx: &litebox_common_linux::PtRegs, total_bytes_read: usize) -> Vec<u8> {
    #[cfg(target_arch = "x86_64")]
    const IOVEC_SIZE: usize = 16;
    #[cfg(target_arch = "x86")]
    const IOVEC_SIZE: usize = 8;
    const PTR_SIZE: usize = core::mem::size_of::<usize>();
    // msghdr is 56 bytes on x86_64, 28 on x86
    #[cfg(target_arch = "x86_64")]
    const MSGHDR_SIZE: usize = 56;
    #[cfg(target_arch = "x86")]
    const MSGHDR_SIZE: usize = 28;

    let msghdr_addr = ctx.syscall_arg(1);
    if msghdr_addr == 0 {
        return Vec::new();
    }

    let msghdr_bytes = read_guest_bytes(msghdr_addr, MSGHDR_SIZE);
    if msghdr_bytes.len() < MSGHDR_SIZE {
        return Vec::new();
    }

    let mut result = Vec::new();

    // Parse msghdr fields (native endian — same machine capture)
    let mut off = 0;

    // msg_name: ptr at offset 0
    let msg_name_ptr = usize::from_ne_bytes(
        msghdr_bytes[off..off + PTR_SIZE]
            .try_into()
            .unwrap_or([0u8; PTR_SIZE]),
    );
    off += PTR_SIZE;

    // msg_namelen: u32 at offset PTR_SIZE
    let msg_namelen = u32::from_ne_bytes(msghdr_bytes[off..off + 4].try_into().unwrap_or([0u8; 4]));
    off += 4;

    // padding on x86_64
    #[cfg(target_arch = "x86_64")]
    {
        off += 4;
    }

    // msg_iov: ptr
    let msg_iov_ptr = usize::from_ne_bytes(
        msghdr_bytes[off..off + PTR_SIZE]
            .try_into()
            .unwrap_or([0u8; PTR_SIZE]),
    );
    off += PTR_SIZE;

    // msg_iovlen: usize
    let msg_iovlen = usize::from_ne_bytes(
        msghdr_bytes[off..off + PTR_SIZE]
            .try_into()
            .unwrap_or([0u8; PTR_SIZE]),
    );
    off += PTR_SIZE;

    // msg_control: ptr
    let msg_control_ptr = usize::from_ne_bytes(
        msghdr_bytes[off..off + PTR_SIZE]
            .try_into()
            .unwrap_or([0u8; PTR_SIZE]),
    );
    off += PTR_SIZE;

    // msg_controllen: usize
    let msg_controllen = usize::from_ne_bytes(
        msghdr_bytes[off..off + PTR_SIZE]
            .try_into()
            .unwrap_or([0u8; PTR_SIZE]),
    );
    off += PTR_SIZE;

    // msg_flags: i32 (4 bytes)
    let msg_flags = u32::from_ne_bytes(msghdr_bytes[off..off + 4].try_into().unwrap_or([0u8; 4]));

    // 1. Serialize msg_name
    result.extend_from_slice(&msg_namelen.to_le_bytes());
    if msg_name_ptr != 0 && msg_namelen > 0 {
        result.extend_from_slice(&read_guest_bytes(msg_name_ptr, msg_namelen as usize));
    }

    // 2. Serialize msg_control
    #[allow(clippy::cast_possible_truncation)]
    let controllen_u64 = msg_controllen as u64;
    result.extend_from_slice(&controllen_u64.to_le_bytes());
    if msg_control_ptr != 0 && msg_controllen > 0 {
        result.extend_from_slice(&read_guest_bytes(msg_control_ptr, msg_controllen));
    }

    // 3. Serialize msg_flags
    result.extend_from_slice(&msg_flags.to_le_bytes());

    // 4. Serialize iovec scatter data (same approach as capture_readv_data)
    if msg_iov_ptr != 0 && msg_iovlen > 0 && total_bytes_read > 0 {
        let iov_bytes = read_guest_bytes(msg_iov_ptr, msg_iovlen * IOVEC_SIZE);
        let mut remaining = total_bytes_read;
        for i in 0..msg_iovlen {
            if remaining == 0 {
                break;
            }
            let iov_off = i * IOVEC_SIZE;
            if iov_off + IOVEC_SIZE > iov_bytes.len() {
                break;
            }

            #[cfg(target_arch = "x86_64")]
            let (base, len) = {
                let base = usize::from_ne_bytes(
                    iov_bytes[iov_off..iov_off + 8]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                );
                let len = usize::from_ne_bytes(
                    iov_bytes[iov_off + 8..iov_off + 16]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                );
                (base, len)
            };

            #[cfg(target_arch = "x86")]
            let (base, len) = {
                let base = u32::from_ne_bytes(
                    iov_bytes[iov_off..iov_off + 4]
                        .try_into()
                        .unwrap_or([0u8; 4]),
                ) as usize;
                let len = u32::from_ne_bytes(
                    iov_bytes[iov_off + 4..iov_off + 8]
                        .try_into()
                        .unwrap_or([0u8; 4]),
                ) as usize;
                (base, len)
            };

            let to_read = len.min(remaining);
            let chunk = read_guest_bytes(base, to_read);
            result.extend_from_slice(&chunk);
            remaining = remaining.saturating_sub(chunk.len());
        }
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

        // nanosleep(req, rem) — rem = arg1, written on EINTR
        nr::NANOSLEEP if result_signed == Errno::EINTR.as_neg() as isize => {
            let remain_addr = ctx.syscall_arg(1);
            if remain_addr != 0 {
                read_guest_bytes(remain_addr, 16) // sizeof(struct timespec)
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

        // rt_sigtimedwait: info = arg1
        nr::RT_SIGTIMEDWAIT => {
            let info_addr = ctx.syscall_arg(1);
            if info_addr != 0 {
                write_guest_bytes(info_addr, data);
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

        // nanosleep: remain = arg1 (on EINTR)
        nr::NANOSLEEP => {
            let remain_addr = ctx.syscall_arg(1);
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

        // poll: write entire pollfd array back to arg0 (same as ppoll)
        nr::POLL => {
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

        // epoll_wait: events = arg1 (same as epoll_pwait)
        nr::EPOLL_WAIT => {
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

        // recvmsg: complex msghdr injection
        nr::RECVMSG => inject_recvmsg_data(ctx, data),

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

/// Inject `recvmsg` data back into the guest's msghdr structure.
///
/// Parses the format written by `capture_recvmsg_data()`.
fn inject_recvmsg_data(ctx: &litebox_common_linux::PtRegs, data: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    const IOVEC_SIZE: usize = 16;
    #[cfg(target_arch = "x86")]
    const IOVEC_SIZE: usize = 8;
    const PTR_SIZE: usize = core::mem::size_of::<usize>();
    #[cfg(target_arch = "x86_64")]
    const MSGHDR_SIZE: usize = 56;
    #[cfg(target_arch = "x86")]
    const MSGHDR_SIZE: usize = 28;

    let msghdr_addr = ctx.syscall_arg(1);
    if msghdr_addr == 0 || data.is_empty() {
        return;
    }

    // Read the original msghdr to get pointers
    let msghdr_bytes = read_guest_bytes(msghdr_addr, MSGHDR_SIZE);
    if msghdr_bytes.len() < MSGHDR_SIZE {
        return;
    }

    // Parse pointers from msghdr
    let msg_name_ptr = usize::from_ne_bytes(
        msghdr_bytes[..PTR_SIZE]
            .try_into()
            .unwrap_or([0u8; PTR_SIZE]),
    );

    let mut hdr_off = PTR_SIZE + 4; // skip name ptr + namelen
    #[cfg(target_arch = "x86_64")]
    {
        hdr_off += 4;
    } // padding

    let msg_iov_ptr = usize::from_ne_bytes(
        msghdr_bytes[hdr_off..hdr_off + PTR_SIZE]
            .try_into()
            .unwrap_or([0u8; PTR_SIZE]),
    );
    hdr_off += PTR_SIZE;

    let msg_iovlen = usize::from_ne_bytes(
        msghdr_bytes[hdr_off..hdr_off + PTR_SIZE]
            .try_into()
            .unwrap_or([0u8; PTR_SIZE]),
    );
    hdr_off += PTR_SIZE;

    let msg_control_ptr = usize::from_ne_bytes(
        msghdr_bytes[hdr_off..hdr_off + PTR_SIZE]
            .try_into()
            .unwrap_or([0u8; PTR_SIZE]),
    );

    // Now parse the serialized data blob
    let mut off = 0;

    // 1. msg_namelen + msg_name data
    if off + 4 > data.len() {
        return;
    }
    let msg_namelen = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0u8; 4]));
    off += 4;

    // Write updated msg_namelen into msghdr (at offset PTR_SIZE in the struct)
    write_guest_bytes(msghdr_addr + PTR_SIZE, &msg_namelen.to_ne_bytes());

    if msg_name_ptr != 0 && msg_namelen > 0 {
        let name_end = off + msg_namelen as usize;
        if name_end <= data.len() {
            write_guest_bytes(msg_name_ptr, &data[off..name_end]);
        }
        off = name_end;
    }

    // 2. msg_controllen + msg_control data
    if off + 8 > data.len() {
        return;
    }
    #[allow(clippy::cast_possible_truncation)]
    let msg_controllen =
        u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0u8; 8])) as usize;
    off += 8;

    // Write updated msg_controllen into msghdr
    // controllen is at: PTR_SIZE(name) + 4(namelen) + pad + PTR_SIZE(iov) + PTR_SIZE(iovlen) + PTR_SIZE(control)
    let controllen_offset =
        PTR_SIZE + 4 + if PTR_SIZE == 8 { 4 } else { 0 } + PTR_SIZE + PTR_SIZE + PTR_SIZE;
    write_guest_bytes(
        msghdr_addr + controllen_offset,
        &msg_controllen.to_ne_bytes(),
    );

    if msg_control_ptr != 0 && msg_controllen > 0 {
        let ctrl_end = off + msg_controllen;
        if ctrl_end <= data.len() {
            write_guest_bytes(msg_control_ptr, &data[off..ctrl_end]);
        }
        off = ctrl_end;
    }

    // 3. msg_flags
    if off + 4 > data.len() {
        return;
    }
    let msg_flags_bytes = &data[off..off + 4];
    off += 4;

    // Write msg_flags into msghdr
    // flags is at: controllen_offset + PTR_SIZE(controllen)
    let flags_offset = controllen_offset + PTR_SIZE;
    write_guest_bytes(msghdr_addr + flags_offset, msg_flags_bytes);

    // 4. iovec scatter data
    let iov_data = &data[off..];
    if iov_data.is_empty() || msg_iov_ptr == 0 || msg_iovlen == 0 {
        return;
    }

    let iov_bytes = read_guest_bytes(msg_iov_ptr, msg_iovlen * IOVEC_SIZE);
    let mut data_off = 0;
    for i in 0..msg_iovlen {
        if data_off >= iov_data.len() {
            break;
        }
        let iov_off = i * IOVEC_SIZE;
        if iov_off + IOVEC_SIZE > iov_bytes.len() {
            break;
        }

        #[cfg(target_arch = "x86_64")]
        let (base, len) = {
            let base = usize::from_ne_bytes(
                iov_bytes[iov_off..iov_off + 8]
                    .try_into()
                    .unwrap_or([0u8; 8]),
            );
            let len = usize::from_ne_bytes(
                iov_bytes[iov_off + 8..iov_off + 16]
                    .try_into()
                    .unwrap_or([0u8; 8]),
            );
            (base, len)
        };

        #[cfg(target_arch = "x86")]
        let (base, len) = {
            let base = u32::from_ne_bytes(
                iov_bytes[iov_off..iov_off + 4]
                    .try_into()
                    .unwrap_or([0u8; 4]),
            ) as usize;
            let len = u32::from_ne_bytes(
                iov_bytes[iov_off + 4..iov_off + 8]
                    .try_into()
                    .unwrap_or([0u8; 4]),
            ) as usize;
            (base, len)
        };

        let to_write = len.min(iov_data.len() - data_off);
        write_guest_bytes(base, &iov_data[data_off..data_off + to_write]);
        data_off += to_write;
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

// ---------------------------------------------------------------------------
// Replay address determinism for mmap
// ---------------------------------------------------------------------------

/// During replay, patch the register context for an `mmap` syscall so that the
/// mapping lands at the same address as during recording. If the recorded
/// result is a valid address (non-negative), we set `addr = recorded_address`
/// and add `MAP_FIXED` to the flags.
///
/// Returns `true` if the context was patched, `false` if it was left unchanged
/// (e.g., the recorded call returned an error).
pub fn patch_mmap_for_replay(ctx: &mut litebox_common_linux::PtRegs, recorded_result: i64) -> bool {
    // Negative result means the mmap failed during recording; don't force
    // an address.
    if recorded_result < 0 {
        return false;
    }

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let recorded_addr = recorded_result as usize;
    if recorded_addr == 0 {
        return false;
    }

    // Patch addr (arg0) to the recorded address.
    #[cfg(target_arch = "x86_64")]
    {
        ctx.rdi = recorded_addr;
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.ebx = recorded_addr;
    }

    // Patch flags (arg3) to include MAP_FIXED and remove MAP_FIXED_NOREPLACE.
    // MAP_FIXED = 0x10, MAP_FIXED_NOREPLACE = 0x100000
    #[cfg(target_arch = "x86_64")]
    {
        ctx.r10 = (ctx.r10 | 0x10) & !0x10_0000;
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.esi = (ctx.esi | 0x10) & !0x10_0000;
    }

    true
}

/// During replay of a file-backed mmap, convert it to an anonymous mapping.
/// This is called when the trace event has non-empty data (captured file
/// contents). The caller must inject the captured data after the mmap
/// executes.
///
/// Patches:
/// - prot (arg2): sets to `PROT_READ | PROT_WRITE` (0x3) so we can inject
///   data after mapping without creating unsupported RWX pages
/// - flags (arg3): adds `MAP_ANONYMOUS` (0x20)
/// - fd (arg4): sets to `-1` (ignored for anonymous mappings)
/// - offset (arg5): sets to `0`
///
/// Returns the original prot value so the caller can mprotect back.
pub fn patch_mmap_to_anonymous(ctx: &mut litebox_common_linux::PtRegs) -> usize {
    // PROT_READ | PROT_WRITE = 0x3, MAP_ANONYMOUS = 0x20
    #[cfg(target_arch = "x86_64")]
    {
        let original_prot = ctx.rdx;
        ctx.rdx = 0x3; // PROT_READ | PROT_WRITE (not OR — avoids RWX)
        ctx.r10 |= 0x20;
        ctx.r8 = usize::MAX; // fd = -1
        ctx.r9 = 0; // offset = 0
        original_prot
    }
    #[cfg(target_arch = "x86")]
    {
        let original_prot = ctx.edx;
        ctx.edx = 0x3; // PROT_READ | PROT_WRITE (not OR — avoids RWX)
        ctx.esi |= 0x20;
        ctx.edi = usize::MAX; // fd = -1
        ctx.ebp = 0; // offset = 0
        original_prot
    }
}

/// During replay, inject captured file contents into a file-backed mmap that
/// was converted to anonymous. Writes `data` into guest memory at
/// `mapped_addr`.
pub fn inject_mmap_file_data(mapped_addr: usize, data: &[u8]) {
    write_guest_bytes(mapped_addr, data);
}

// ---------------------------------------------------------------------------
// Memory snapshot capture and restore
// ---------------------------------------------------------------------------

/// Captures a memory snapshot: all VMAs + contents + brk + entry/stack +
/// trampoline address.
///
/// `mappings` is the list of `(range, flags)` from `PageManager::mappings()`.
/// `brk` is the current program break.
/// `entry_point` and `stack_top` come from `ElfLoadInfo`.
/// `trampoline_start` is the guest virtual address where the rewriter
/// trampoline page begins (0 if none).
///
/// Returns serialized snapshot bytes.
#[allow(clippy::cast_possible_truncation)]
pub fn capture_memory_snapshot(
    mappings: &[(core::ops::Range<usize>, VmFlags)],
    brk: usize,
    entry_point: usize,
    stack_top: usize,
    trampoline_start: usize,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let num_vmas = mappings.len() as u32;
    buf.extend_from_slice(&num_vmas.to_le_bytes());

    for (range, flags) in mappings {
        let start = range.start as u64;
        let end = range.end as u64;
        let len = range.end.saturating_sub(range.start);
        buf.extend_from_slice(&start.to_le_bytes());
        buf.extend_from_slice(&end.to_le_bytes());
        buf.extend_from_slice(&flags.bits().to_le_bytes());

        let data = read_guest_bytes(range.start, len);
        let data_len = data.len() as u64;
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&data);
    }

    buf.extend_from_slice(&(brk as u64).to_le_bytes());
    buf.extend_from_slice(&(entry_point as u64).to_le_bytes());
    buf.extend_from_slice(&(stack_top as u64).to_le_bytes());
    buf.extend_from_slice(&(trampoline_start as u64).to_le_bytes());
    buf
}

/// Parsed VMA from a memory snapshot.
pub struct SnapshotVma {
    pub start: usize,
    pub end: usize,
    pub flags: VmFlags,
    pub data: Vec<u8>,
}

/// Result of deserializing a memory snapshot.
pub struct ParsedSnapshot {
    pub vmas: Vec<SnapshotVma>,
    pub brk: usize,
    pub entry_point: usize,
    pub stack_top: usize,
    /// Guest virtual address of the rewriter trampoline page (0 if none).
    pub trampoline_start: usize,
}

/// Deserializes a memory snapshot from bytes.
///
/// # Panics
///
/// Panics if the data is malformed (truncated or inconsistent).
#[allow(clippy::cast_possible_truncation)]
pub fn parse_memory_snapshot(data: &[u8]) -> ParsedSnapshot {
    let mut offset = 0;

    let num_vmas = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    let mut vmas = Vec::with_capacity(num_vmas);
    for _ in 0..num_vmas {
        let start = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;
        let end = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;
        let flags_bits = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let data_len = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;
        let vma_data = data[offset..offset + data_len].to_vec();
        offset += data_len;

        let flags = VmFlags::from_bits_truncate(flags_bits);
        vmas.push(SnapshotVma {
            start,
            end,
            flags,
            data: vma_data,
        });
    }

    let brk = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;
    let entry_point = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;
    let stack_top = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;
    let trampoline_start = if offset + 8 <= data.len() {
        u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as usize
    } else {
        0
    };

    ParsedSnapshot {
        vmas,
        brk,
        entry_point,
        stack_top,
        trampoline_start,
    }
}
