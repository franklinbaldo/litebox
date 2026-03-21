// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Recorder — accumulates syscall events into an in-memory trace buffer.

use crate::trace::{Event, TRACE_MAGIC, TRACE_VERSION, TraceArch, TraceHeader};
use alloc::vec::Vec;

/// Records syscall events into an in-memory byte buffer.
///
/// Usage:
/// 1. Create with `Recorder::new(arch)`
/// 2. Call `record(syscall_nr, result, data)` for each syscall
/// 3. Call `finish()` to get the complete trace bytes
pub struct Recorder {
    /// Serialized trace bytes (header + events)
    buffer: Vec<u8>,
    /// Next event ID to assign
    next_event_id: u64,
}

impl Recorder {
    /// Create a new recorder for the given architecture.
    /// Immediately writes the trace header to the buffer.
    pub fn new(arch: TraceArch) -> Self {
        let header = TraceHeader {
            magic: TRACE_MAGIC,
            version: TRACE_VERSION,
            arch,
        };
        let buffer = header.to_bytes();
        Self {
            buffer,
            next_event_id: 0,
        }
    }

    /// Record a syscall event. `data` is the side-effect bytes (empty if none).
    pub fn record(&mut self, syscall_nr: u32, result: i64, data: Vec<u8>) {
        let event = Event {
            event_id: self.next_event_id,
            syscall_nr,
            result,
            data,
        };
        self.buffer.extend_from_slice(&event.to_bytes());
        self.next_event_id += 1;
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
        let recorder = Recorder::new(TraceArch::X86_64);
        assert_eq!(recorder.event_count(), 0);
        let bytes = recorder.finish();
        // Should contain only the header (9 bytes)
        let (header, consumed) = TraceHeader::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(header.magic, TRACE_MAGIC);
        assert_eq!(header.version, TRACE_VERSION);
        assert_eq!(header.arch, TraceArch::X86_64);
    }

    #[test]
    fn test_recorder_records_events() {
        let mut recorder = Recorder::new(TraceArch::X86);
        recorder.record(0, 5, alloc::vec![1, 2, 3, 4, 5]);
        recorder.record(1, -1, alloc::vec![]);
        recorder.record(60, 0, alloc::vec![0xAB]);

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
        let mut recorder = Recorder::new(TraceArch::X86_64);
        assert_eq!(recorder.event_count(), 0);
        recorder.record(0, 0, alloc::vec![]);
        assert_eq!(recorder.event_count(), 1);
        recorder.record(1, 0, alloc::vec![]);
        assert_eq!(recorder.event_count(), 2);
        recorder.record(2, 0, alloc::vec![]);
        assert_eq!(recorder.event_count(), 3);
    }
}
