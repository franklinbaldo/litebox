// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Replayer — reads syscall events sequentially from a trace buffer.

use crate::trace::{Event, EventKind, TraceArch, TraceError, TraceHeader, TraceMetadata};
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
    /// Trace format version from the header.
    version: u32,
    /// Number of events consumed so far.
    events_consumed: u64,
    /// Optional program metadata (v3+).
    metadata: Option<TraceMetadata>,
}

impl Replayer {
    /// Parse the trace header and create a replayer.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, ReplayError> {
        let (header, consumed) = TraceHeader::from_bytes(&data)?;
        Ok(Self {
            data,
            offset: consumed,
            arch: header.arch,
            version: header.version,
            events_consumed: 0,
            metadata: header.metadata,
        })
    }

    /// Return the architecture from the trace header.
    pub fn arch(&self) -> TraceArch {
        self.arch
    }

    /// Return the trace format version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Return a reference to the trace metadata, if present (v3+).
    pub fn metadata(&self) -> Option<&TraceMetadata> {
        self.metadata.as_ref()
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

    /// Peek at the `syscall_nr` of the next event without consuming it.
    /// Returns `None` if the trace is exhausted.
    ///
    /// # Panics
    ///
    /// Panics if the underlying slice conversion fails (should not happen when
    /// the bounds check above succeeds).
    pub fn peek_event_nr(&self) -> Option<u32> {
        if self.offset >= self.data.len() {
            return None;
        }
        // syscall_nr is at bytes [8..12] within the event (after event_id).
        let start = self.offset + 8;
        if start + 4 > self.data.len() {
            return None;
        }
        Some(u32::from_le_bytes(
            self.data[start..start + 4].try_into().unwrap(),
        ))
    }

    /// Peek at the `result` field of the next event without consuming it.
    /// Returns `None` if the trace is exhausted.
    ///
    /// # Panics
    ///
    /// Panics if the underlying slice conversion fails (should not happen when
    /// the bounds check above succeeds).
    pub fn peek_event_result(&self) -> Option<i64> {
        if self.offset >= self.data.len() {
            return None;
        }
        // result is at bytes [12..20] within the event (after event_id + syscall_nr).
        let start = self.offset + 12;
        if start + 8 > self.data.len() {
            return None;
        }
        Some(i64::from_le_bytes(
            self.data[start..start + 8].try_into().unwrap(),
        ))
    }

    /// Peek at the `tid` field of the next event without consuming it.
    /// Returns `None` if the trace is exhausted.
    ///
    /// # Panics
    ///
    /// Panics if the underlying slice conversion fails (should not happen when
    /// the bounds check above succeeds).
    pub fn peek_event_tid(&self) -> Option<u32> {
        if self.offset >= self.data.len() {
            return None;
        }
        // tid is at bytes [24..28] within the v2 event.
        let start = self.offset + 24;
        if start + 4 > self.data.len() {
            return None;
        }
        Some(u32::from_le_bytes(
            self.data[start..start + 4].try_into().unwrap(),
        ))
    }

    /// Peek at the `kind` field of the next event without consuming it.
    /// Returns `None` if the trace is exhausted.
    pub fn peek_event_kind(&self) -> Option<EventKind> {
        if self.offset >= self.data.len() {
            return None;
        }
        // kind is at byte [28] within the v2 event.
        let start = self.offset + 28;
        if start >= self.data.len() {
            return None;
        }
        EventKind::from_byte(self.data[start])
    }

    /// Returns `true` if the next event is a memory snapshot event.
    pub fn peek_is_snapshot(&self) -> bool {
        self.peek_event_nr() == Some(crate::trace::EXECVE_SNAPSHOT_NR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::Recorder;
    use crate::trace::EventKind;

    #[test]
    fn test_replayer_roundtrip() {
        let mut recorder = Recorder::new(TraceArch::X86_64, None);
        recorder.record(0, 5, alloc::vec![1, 2, 3, 4, 5], 0, EventKind::Complete);
        recorder.record(1, -1, alloc::vec![], 0, EventKind::Complete);
        recorder.record(60, 0, alloc::vec![0xAB], 0, EventKind::Complete);
        let bytes = recorder.finish();

        let mut replayer = Replayer::from_bytes(bytes).unwrap();
        assert_eq!(replayer.arch(), TraceArch::X86_64);
        assert_eq!(replayer.events_consumed(), 0);

        let ev0 = replayer.next_event().unwrap();
        assert_eq!(ev0.event_id, 0);
        assert_eq!(ev0.syscall_nr, 0);
        assert_eq!(ev0.result, 5);
        assert_eq!(ev0.data, alloc::vec![1, 2, 3, 4, 5]);
        assert_eq!(ev0.tid, 0);
        assert_eq!(ev0.kind, EventKind::Complete);
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
        let mut recorder = Recorder::new(TraceArch::X86_64, None);
        recorder.record(0, 0, alloc::vec![], 0, EventKind::Complete);
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
        let mut recorder = Recorder::new(TraceArch::X86_64, None);
        recorder.record(42, 0, alloc::vec![], 0, EventKind::Complete);
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
    fn test_replayer_peek_event_nr() {
        let mut recorder = Recorder::new(TraceArch::X86_64, None);
        recorder.record(42, 0, alloc::vec![], 0, EventKind::Complete);
        recorder.record(
            crate::SIGNAL_DELIVERY_NR,
            14,
            alloc::vec![0xAA; 128],
            0,
            EventKind::Signal,
        );
        recorder.record(99, 1, alloc::vec![], 0, EventKind::Complete);
        let bytes = recorder.finish();

        let mut replayer = Replayer::from_bytes(bytes).unwrap();

        // Peek should show 42 without consuming
        assert_eq!(replayer.peek_event_nr(), Some(42));
        assert_eq!(replayer.peek_event_nr(), Some(42)); // idempotent
        let _ = replayer.next_event().unwrap(); // consume

        // Peek should show signal sentinel
        assert_eq!(replayer.peek_event_nr(), Some(crate::SIGNAL_DELIVERY_NR));
        let _ = replayer.next_event().unwrap(); // consume

        // Peek should show 99
        assert_eq!(replayer.peek_event_nr(), Some(99));
        let _ = replayer.next_event().unwrap(); // consume

        // Exhausted
        assert_eq!(replayer.peek_event_nr(), None);
    }

    #[test]
    fn test_replayer_peek_event_result() {
        let mut recorder = Recorder::new(TraceArch::X86_64, None);
        recorder.record(9, 0x7f00_0000_0000, alloc::vec![], 0, EventKind::Complete); // mmap success
        recorder.record(9, -12, alloc::vec![], 0, EventKind::Complete); // mmap ENOMEM (-12)
        let bytes = recorder.finish();

        let mut replayer = Replayer::from_bytes(bytes).unwrap();

        // Peek result of first event: 0x7f00_0000_0000
        assert_eq!(replayer.peek_event_result(), Some(0x7f00_0000_0000));
        assert_eq!(replayer.peek_event_result(), Some(0x7f00_0000_0000)); // idempotent
        let _ = replayer.next_event().unwrap(); // consume

        // Peek result of second event: -12
        assert_eq!(replayer.peek_event_result(), Some(-12));
        let _ = replayer.next_event().unwrap(); // consume

        // Exhausted
        assert_eq!(replayer.peek_event_result(), None);
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

    #[test]
    fn test_replayer_peek_event_tid() {
        let mut recorder = Recorder::new(TraceArch::X86_64, None);
        recorder.record(0, 0, alloc::vec![], 1, EventKind::Complete);
        recorder.record(202, 0, alloc::vec![], 42, EventKind::Entry);
        recorder.record(202, 0, alloc::vec![], 42, EventKind::Exit);
        let bytes = recorder.finish();

        let mut replayer = Replayer::from_bytes(bytes).unwrap();

        assert_eq!(replayer.peek_event_tid(), Some(1));
        assert_eq!(replayer.peek_event_tid(), Some(1)); // idempotent
        let _ = replayer.next_event().unwrap();

        assert_eq!(replayer.peek_event_tid(), Some(42));
        let _ = replayer.next_event().unwrap();

        assert_eq!(replayer.peek_event_tid(), Some(42));
        let _ = replayer.next_event().unwrap();

        assert_eq!(replayer.peek_event_tid(), None);
    }

    #[test]
    fn test_replayer_peek_event_kind() {
        let mut recorder = Recorder::new(TraceArch::X86_64, None);
        recorder.record(0, 0, alloc::vec![], 0, EventKind::Complete);
        recorder.record(202, 0, alloc::vec![], 0, EventKind::Entry);
        recorder.record(202, 0, alloc::vec![], 0, EventKind::Exit);
        recorder.record(
            crate::SIGNAL_DELIVERY_NR,
            14,
            alloc::vec![],
            0,
            EventKind::Signal,
        );
        let bytes = recorder.finish();

        let mut replayer = Replayer::from_bytes(bytes).unwrap();

        assert_eq!(replayer.peek_event_kind(), Some(EventKind::Complete));
        let _ = replayer.next_event().unwrap();

        assert_eq!(replayer.peek_event_kind(), Some(EventKind::Entry));
        let _ = replayer.next_event().unwrap();

        assert_eq!(replayer.peek_event_kind(), Some(EventKind::Exit));
        let _ = replayer.next_event().unwrap();

        assert_eq!(replayer.peek_event_kind(), Some(EventKind::Signal));
        let _ = replayer.next_event().unwrap();

        assert_eq!(replayer.peek_event_kind(), None);
    }

    #[test]
    fn test_replayer_version() {
        let recorder = Recorder::new(TraceArch::X86_64, None);
        let bytes = recorder.finish();
        let replayer = Replayer::from_bytes(bytes).unwrap();
        assert_eq!(replayer.version(), 4);
    }

    #[test]
    fn test_recorder_with_metadata() {
        let meta = TraceMetadata {
            program_path: alloc::string::String::from("/usr/bin/hello"),
            argv: alloc::vec![
                alloc::string::String::from("hello"),
                alloc::string::String::from("--world"),
            ],
            envp: alloc::vec![
                alloc::string::String::from("PATH=/usr/bin"),
                alloc::string::String::from("HOME=/root"),
            ],
            initial_files_path: Some(alloc::string::String::from("/tmp/rootfs.tar")),
            program_from_tar: true,
        };

        // Record with metadata
        let mut recorder = Recorder::new(TraceArch::X86_64, Some(meta.clone()));
        recorder.record(0, 42, alloc::vec![1, 2, 3], 0, EventKind::Complete);
        let bytes = recorder.finish();

        // Replay and verify metadata comes back
        let mut replayer = Replayer::from_bytes(bytes).unwrap();
        assert_eq!(replayer.version(), 4);
        assert_eq!(replayer.arch(), TraceArch::X86_64);

        let got_meta = replayer.metadata().expect("metadata should be present");
        assert_eq!(*got_meta, meta);
        assert_eq!(got_meta.program_path, "/usr/bin/hello");
        assert_eq!(got_meta.argv.len(), 2);
        assert_eq!(got_meta.envp.len(), 2);
        assert!(got_meta.program_from_tar);
        assert_eq!(
            got_meta.initial_files_path.as_deref(),
            Some("/tmp/rootfs.tar")
        );

        // Events should still be readable
        let ev = replayer.next_event().unwrap();
        assert_eq!(ev.event_id, 0);
        assert_eq!(ev.syscall_nr, 0);
        assert_eq!(ev.result, 42);
        assert_eq!(ev.data, alloc::vec![1, 2, 3]);
        assert!(replayer.is_exhausted());
    }

    #[test]
    fn test_peek_is_snapshot() {
        use crate::Recorder;

        let mut rec = Recorder::new(TraceArch::X86_64, None);
        rec.record_simple(1, 0, alloc::vec![]);
        rec.record_snapshot(alloc::vec![1, 2, 3], 1);
        let trace = rec.finish();

        let mut rep = Replayer::from_bytes(trace).unwrap();
        assert!(!rep.peek_is_snapshot());
        let _ = rep.next_event().unwrap();
        assert!(rep.peek_is_snapshot());
        let snap = rep.next_event().unwrap();
        assert_eq!(snap.kind, EventKind::Snapshot);
    }
}
