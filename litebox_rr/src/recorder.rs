// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Recorder — accumulates syscall events into an in-memory trace buffer.

use crate::trace::{
    Event, EventKind, TRACE_MAGIC, TRACE_VERSION, TraceArch, TraceHeader, TraceMetadata,
};
use alloc::vec::Vec;

/// Records syscall events into an in-memory byte buffer.
///
/// Usage:
/// 1. Create with `Recorder::new(arch, metadata)`
/// 2. Call `record(syscall_nr, result, data)` for each syscall
/// 3. Call `finish()` to get the complete trace bytes
pub struct Recorder {
    /// Serialized trace bytes (header + events)
    buffer: Vec<u8>,
    /// Next event ID to assign
    next_event_id: u64,
}

impl Recorder {
    /// Create a new recorder for the given architecture and optional metadata.
    /// Immediately writes the trace header to the buffer.
    ///
    /// If `metadata` is `None`, a default empty metadata block is used (v3
    /// headers always include metadata).
    pub fn new(arch: TraceArch, metadata: Option<TraceMetadata>) -> Self {
        let metadata = metadata.unwrap_or_else(|| TraceMetadata {
            program_path: alloc::string::String::new(),
            argv: alloc::vec![],
            envp: alloc::vec![],
            initial_files_path: None,
            program_from_tar: false,
        });
        let header = TraceHeader {
            magic: TRACE_MAGIC,
            version: TRACE_VERSION,
            arch,
            metadata: Some(metadata),
        };
        let buffer = header.to_bytes();
        Self {
            buffer,
            next_event_id: 0,
        }
    }

    /// Record a syscall event.
    ///
    /// `data` is the side-effect bytes (empty if none). `tid` identifies the
    /// thread that produced this event. `kind` indicates whether the event is a
    /// complete syscall, a blocking entry/exit pair, or a signal delivery.
    pub fn record(
        &mut self,
        syscall_nr: u32,
        result: i64,
        data: Vec<u8>,
        tid: u32,
        kind: EventKind,
    ) {
        let event = Event {
            event_id: self.next_event_id,
            syscall_nr,
            result,
            data,
            tid,
            kind,
        };
        self.buffer.extend_from_slice(&event.to_bytes());
        self.next_event_id += 1;
    }

    /// Record a syscall event with default `tid=0` and `kind=Complete`.
    /// Convenience for single-threaded recording.
    pub fn record_simple(&mut self, syscall_nr: u32, result: i64, data: Vec<u8>) {
        self.record(syscall_nr, result, data, 0, EventKind::Complete);
    }

    /// Records a memory snapshot event (used after execve or initial program load).
    ///
    /// `snapshot_data` contains the serialized memory snapshot (VMAs + contents + registers).
    /// `tid` is the thread that performed the execve.
    pub fn record_snapshot(&mut self, snapshot_data: Vec<u8>, tid: u32) {
        self.record(
            crate::trace::EXECVE_SNAPSHOT_NR,
            0,
            snapshot_data,
            tid,
            EventKind::Snapshot,
        );
    }

    /// Return the number of events recorded so far.
    pub fn event_count(&self) -> u64 {
        self.next_event_id
    }

    /// Consume the recorder and return the complete trace bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recorder_empty() {
        let recorder = Recorder::new(TraceArch::X86_64, None);
        assert_eq!(recorder.event_count(), 0);
        let bytes = recorder.finish();
        // Should contain only the header
        let (header, consumed) = TraceHeader::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(header.magic, TRACE_MAGIC);
        assert_eq!(header.version, TRACE_VERSION);
        assert_eq!(header.arch, TraceArch::X86_64);
    }

    #[test]
    fn test_recorder_records_events() {
        let mut recorder = Recorder::new(TraceArch::X86, None);
        recorder.record(0, 5, alloc::vec![1, 2, 3, 4, 5], 0, EventKind::Complete);
        recorder.record(1, -1, alloc::vec![], 0, EventKind::Complete);
        recorder.record(60, 0, alloc::vec![0xAB], 0, EventKind::Complete);

        let bytes = recorder.finish();

        // Parse header
        let (header, mut offset) = TraceHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.arch, TraceArch::X86);

        // Parse event 0
        let (ev0, consumed) = Event::from_bytes(&bytes[offset..]).unwrap();
        offset += consumed;
        assert_eq!(ev0.event_id, 0);
        assert_eq!(ev0.syscall_nr, 0);
        assert_eq!(ev0.result, 5);
        assert_eq!(ev0.data, alloc::vec![1, 2, 3, 4, 5]);
        assert_eq!(ev0.tid, 0);
        assert_eq!(ev0.kind, EventKind::Complete);

        // Parse event 1
        let (ev1, consumed) = Event::from_bytes(&bytes[offset..]).unwrap();
        offset += consumed;
        assert_eq!(ev1.event_id, 1);
        assert_eq!(ev1.syscall_nr, 1);
        assert_eq!(ev1.result, -1);
        assert!(ev1.data.is_empty());

        // Parse event 2
        let (ev2, consumed) = Event::from_bytes(&bytes[offset..]).unwrap();
        offset += consumed;
        assert_eq!(ev2.event_id, 2);
        assert_eq!(ev2.syscall_nr, 60);
        assert_eq!(ev2.result, 0);
        assert_eq!(ev2.data, alloc::vec![0xAB]);

        // No more data
        assert_eq!(offset, bytes.len());
    }

    #[test]
    fn test_recorder_event_count() {
        let mut recorder = Recorder::new(TraceArch::X86_64, None);
        assert_eq!(recorder.event_count(), 0);
        recorder.record(0, 0, alloc::vec![], 0, EventKind::Complete);
        assert_eq!(recorder.event_count(), 1);
        recorder.record(1, 0, alloc::vec![], 0, EventKind::Complete);
        assert_eq!(recorder.event_count(), 2);
        recorder.record(2, 0, alloc::vec![], 0, EventKind::Complete);
        assert_eq!(recorder.event_count(), 3);
    }

    #[test]
    fn test_record_snapshot() {
        use crate::Replayer;
        use crate::trace::EXECVE_SNAPSHOT_NR;

        let mut rec = Recorder::new(TraceArch::X86_64, None);
        rec.record_snapshot(alloc::vec![10, 20, 30], 1);
        let trace = rec.finish();
        let mut rep = Replayer::from_bytes(trace).unwrap();
        let event = rep.next_event().unwrap();
        assert_eq!(event.syscall_nr, EXECVE_SNAPSHOT_NR);
        assert_eq!(event.kind, EventKind::Snapshot);
        assert_eq!(event.data, alloc::vec![10, 20, 30]);
        assert_eq!(event.tid, 1);
        assert_eq!(event.result, 0);
    }
}
