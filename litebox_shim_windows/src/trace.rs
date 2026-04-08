// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Lightweight, always-on syscall/exception trace logger.
//!
//! Each thread owns a fixed-size ring buffer ([`TraceRing`]) that records the
//! last [`TRACE_RING_SIZE`] events. Recording is lock-free, allocation-free,
//! and performs no I/O. On process exit (or non-zero thread exit) the buffer
//! is dumped to stderr in chronological order.

/// Number of entries in each per-thread ring buffer.
/// 4096 entries captures a full run of typical test programs.
pub(crate) const TRACE_RING_SIZE: usize = 4096;

/// Discriminant for trace entries.
#[repr(u8)]
#[derive(Clone, Copy)]
pub(crate) enum TraceKind {
    SyscallEntry = 0,
    SyscallExit = 1,
    ExceptionForward = 2,
    GuardPageFault = 3,
    DemandCommit = 4,
    ThreadCreate = 5,
    ThreadExit = 6,
    NullFixup = 7,
    /// Memory operation with dereferenced values: base, size, protect/type.
    MemOp = 8,
    /// Explicit terminate request observed in the shim.
    ExitRequest = 9,
    /// Ad-hoc fault-site probe payload.
    Probe = 10,
}

impl TraceKind {
    fn as_str(self) -> &'static str {
        match self {
            TraceKind::SyscallEntry => "SYSCALL_ENTRY",
            TraceKind::SyscallExit => "SYSCALL_EXIT ",
            TraceKind::ExceptionForward => "EXC_FORWARD  ",
            TraceKind::GuardPageFault => "GUARD_FAULT  ",
            TraceKind::DemandCommit => "DEMAND_COMMIT",
            TraceKind::ThreadCreate => "THREAD_CREATE",
            TraceKind::ThreadExit => "THREAD_EXIT  ",
            TraceKind::NullFixup => "NULL_FIXUP   ",
            TraceKind::MemOp => "MEM_OP       ",
            TraceKind::ExitRequest => "EXIT_REQUEST ",
            TraceKind::Probe => "PROBE        ",
        }
    }
}

/// A single trace event.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct TraceEntry {
    /// Monotonic per-thread sequence counter.
    pub seq: u64,
    /// Shim-internal thread ID.
    pub tid: u32,
    /// Entry type.
    pub kind: TraceKind,
    /// Syscall number or exception code.
    pub code: u32,
    /// Up to 3 key arguments/values.
    pub arg0: usize,
    pub arg1: usize,
    pub arg2: usize,
}

const EMPTY_ENTRY: TraceEntry = TraceEntry {
    seq: 0,
    tid: 0,
    kind: TraceKind::SyscallEntry,
    code: 0,
    arg0: 0,
    arg1: 0,
    arg2: 0,
};

/// Per-thread ring buffer for trace entries.
pub(crate) struct TraceRing {
    entries: [TraceEntry; TRACE_RING_SIZE],
    /// Next write position (wraps at `TRACE_RING_SIZE`).
    head: usize,
    /// Monotonic per-thread sequence counter.
    seq: u64,
    /// Thread ID that owns this ring.
    tid: u32,
}

impl TraceRing {
    /// Create a new, empty ring buffer for the given thread.
    pub(crate) fn new(tid: u32) -> Self {
        #[allow(clippy::large_stack_arrays)]
        Self {
            entries: [EMPTY_ENTRY; TRACE_RING_SIZE],
            head: 0,
            seq: 0,
            tid,
        }
    }

    /// Record a trace event. This is the hot path — no allocation, no I/O,
    /// no locks.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub(crate) fn record(
        &mut self,
        kind: TraceKind,
        code: u32,
        arg0: usize,
        arg1: usize,
        arg2: usize,
    ) {
        self.seq += 1;
        let idx = self.head;
        self.entries[idx] = TraceEntry {
            seq: self.seq,
            tid: self.tid,
            kind,
            code,
            arg0,
            arg1,
            arg2,
        };
        self.head = (idx + 1) % TRACE_RING_SIZE;
    }

    /// Dump the ring buffer contents to stderr in chronological order.
    ///
    /// Entries are printed oldest-first. Empty entries (seq == 0) are skipped.
    pub(crate) fn dump(&self) {
        use litebox::platform::{StdioOutStream, StdioProvider as _};
        let platform = litebox_platform_multiplex::platform();

        let _ = platform.write_to(
            StdioOutStream::Stderr,
            alloc::format!(
                "[trace] === Thread {} trace dump ({} entries max) ===\n",
                self.tid,
                TRACE_RING_SIZE
            )
            .as_bytes(),
        );

        // Walk from head (oldest) to head-1 (newest), skipping empty entries.
        for i in 0..TRACE_RING_SIZE {
            let idx = (self.head + i) % TRACE_RING_SIZE;
            let e = &self.entries[idx];
            if e.seq == 0 {
                continue;
            }
            let line = alloc::format!(
                "[trace] seq={:<6} tid={} {} nr=0x{:X} arg0=0x{:X} arg1=0x{:X} arg2=0x{:X}\n",
                e.seq,
                e.tid,
                e.kind.as_str(),
                e.code,
                e.arg0,
                e.arg1,
                e.arg2,
            );
            let _ = platform.write_to(StdioOutStream::Stderr, line.as_bytes());
        }

        let _ = platform.write_to(StdioOutStream::Stderr, b"[trace] === End trace dump ===\n");
    }
}
