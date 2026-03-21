// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Replayer — reads syscall events sequentially from a trace buffer.

use crate::trace::{Event, TraceArch, TraceError, TraceHeader};
use alloc::vec::Vec;

/// Error during replay.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplayError {
    /// Trace format error.
    Trace(TraceError),
    /// Reached end of trace (no more events).
    EndOfTrace,
    /// The guest made a different syscall than expected.
    Divergence {
        event_id: u64,
        expected_syscall_nr: u32,
        actual_syscall_nr: u32,
    },
}

impl From<TraceError> for ReplayError {
    fn from(e: TraceError) -> Self {
        Self::Trace(e)
    }
}

/// Reads events sequentially from an in-memory trace buffer.
///
/// Usage:
/// 1. Create with `Replayer::from_bytes(trace_data)`
/// 2. Call `next_event()` for each syscall to get the recorded event
/// 3. Optionally call `expect_event(syscall_nr)` to validate + advance
#[derive(Debug)]
pub struct Replayer {
    /// The complete trace data.
    data: Vec<u8>,
    /// Current read offset into `data`.
    offset: usize,
    /// Architecture from the trace header.
    arch: TraceArch,
    /// Number of events consumed so far.
    events_consumed: u64,
}

impl Replayer {
    /// Parse the trace header and create a replayer.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, ReplayError> {
        let (header, consumed) = TraceHeader::from_bytes(&data)?;
        Ok(Self {
            data,
            offset: consumed,
            arch: header.arch,
            events_consumed: 0,
        })
    }

    /// Return the architecture from the trace header.
    pub fn arch(&self) -> TraceArch {
        self.arch
    }

    /// Return the number of events consumed so far.
    pub fn events_consumed(&self) -> u64 {
        self.events_consumed
    }

    /// Read and return the next event without validation.
    pub fn next_event(&mut self) -> Result<Event, ReplayError> {
        if self.offset >= self.data.len() {
            return Err(ReplayError::EndOfTrace);
        }
        let (event, consumed) = Event::from_bytes(&self.data[self.offset..])?;
        self.offset += consumed;
        self.events_consumed += 1;
        Ok(event)
    }

    /// Read the next event and verify it matches the expected syscall number.
    /// Returns the event if it matches, or `ReplayError::Divergence` if not.
    pub fn expect_event(&mut self, actual_syscall_nr: u32) -> Result<Event, ReplayError> {
        let event = self.next_event()?;
        if event.syscall_nr != actual_syscall_nr {
            return Err(ReplayError::Divergence {
                event_id: event.event_id,
                expected_syscall_nr: event.syscall_nr,
                actual_syscall_nr,
            });
        }
        Ok(event)
    }

    /// Return true if there are no more events.
    pub fn is_exhausted(&self) -> bool {
        self.offset >= self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::Recorder;

    #[test]
    fn test_replayer_roundtrip() {
        let mut recorder = Recorder::new(TraceArch::X86_64);
        recorder.record(0, 5, alloc::vec![1, 2, 3, 4, 5]);
        recorder.record(1, -1, alloc::vec![]);
        recorder.record(60, 0, alloc::vec![0xAB]);
        let bytes = recorder.finish();

        let mut replayer = Replayer::from_bytes(bytes).unwrap();
        assert_eq!(replayer.arch(), TraceArch::X86_64);
        assert_eq!(replayer.events_consumed(), 0);

        let ev0 = replayer.next_event().unwrap();
        assert_eq!(ev0.event_id, 0);
        assert_eq!(ev0.syscall_nr, 0);
        assert_eq!(ev0.result, 5);
        assert_eq!(ev0.data, alloc::vec![1, 2, 3, 4, 5]);
        assert_eq!(replayer.events_consumed(), 1);

        let ev1 = replayer.next_event().unwrap();
        assert_eq!(ev1.event_id, 1);
        assert_eq!(ev1.syscall_nr, 1);
        assert_eq!(ev1.result, -1);
        assert!(ev1.data.is_empty());
        assert_eq!(replayer.events_consumed(), 2);

        let ev2 = replayer.next_event().unwrap();
        assert_eq!(ev2.event_id, 2);
        assert_eq!(ev2.syscall_nr, 60);
        assert_eq!(ev2.result, 0);
        assert_eq!(ev2.data, alloc::vec![0xAB]);
        assert_eq!(replayer.events_consumed(), 3);

        assert!(replayer.is_exhausted());
    }

    #[test]
    fn test_replayer_end_of_trace() {
        let mut recorder = Recorder::new(TraceArch::X86_64);
        recorder.record(0, 0, alloc::vec![]);
        let bytes = recorder.finish();

        let mut replayer = Replayer::from_bytes(bytes).unwrap();
        // Consume the one event
        let _ = replayer.next_event().unwrap();
        // Next should be EndOfTrace
        assert_eq!(replayer.next_event(), Err(ReplayError::EndOfTrace));
        assert!(replayer.is_exhausted());
    }

    #[test]
    fn test_replayer_divergence() {
        let mut recorder = Recorder::new(TraceArch::X86_64);
        recorder.record(42, 0, alloc::vec![]);
        let bytes = recorder.finish();

        let mut replayer = Replayer::from_bytes(bytes).unwrap();
        // Expect syscall 99, but trace has syscall 42
        let err = replayer.expect_event(99).unwrap_err();
        assert_eq!(
            err,
            ReplayError::Divergence {
                event_id: 0,
                expected_syscall_nr: 42,
                actual_syscall_nr: 99,
            }
        );
    }

    #[test]
    fn test_replayer_invalid_data() {
        let garbage = alloc::vec![0xFF, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE];
        let err = Replayer::from_bytes(garbage).unwrap_err();
        match err {
            ReplayError::Trace(_) => {} // Expected: some TraceError variant
            other => panic!("expected Trace error, got {:?}", other),
        }
    }
}
