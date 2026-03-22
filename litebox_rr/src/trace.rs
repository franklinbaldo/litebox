// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Core trace format types and binary serialization.
//!
//! The trace format uses a simple TLV (type-length-value) encoding with
//! little-endian byte order for all multi-byte integers.

use alloc::string::String;
use alloc::vec::Vec;

/// Magic bytes for the trace file header: "LBRR" in ASCII.
pub const TRACE_MAGIC: [u8; 4] = *b"LBRR";

/// Current trace format version.
pub const TRACE_VERSION: u32 = 4;

/// Sentinel syscall number used for signal delivery events in the trace.
/// This is well outside the range of real Linux syscall numbers.
pub const SIGNAL_DELIVERY_NR: u32 = 0xFFFF_FFFE;

/// Sentinel syscall number used for execve snapshot events in the trace.
/// This is well outside the range of real Linux syscall numbers.
pub const EXECVE_SNAPSHOT_NR: u32 = 0xFFFF_FFFD;

/// The kind of a trace event.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum EventKind {
    /// Non-blocking syscall completed in a single event.
    Complete = 0,
    /// Blocking syscall entered; run token released. `result` field is unused.
    Entry = 1,
    /// Blocking syscall resumed; run token reacquired. `result` + side-effects captured.
    Exit = 2,
    /// Async signal delivery event.
    Signal = 3,
    /// Memory snapshot event (used after execve or initial program load).
    Snapshot = 4,
}

impl EventKind {
    /// Convert a raw byte to an [`EventKind`].
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Complete),
            1 => Some(Self::Entry),
            2 => Some(Self::Exit),
            3 => Some(Self::Signal),
            4 => Some(Self::Snapshot),
            _ => None,
        }
    }
}

/// Errors that can occur when decoding trace data.
#[derive(Debug, Clone, PartialEq)]
pub enum TraceError {
    /// Not enough bytes to decode.
    UnexpectedEof,
    /// Magic bytes don't match.
    InvalidMagic,
    /// Unsupported version.
    UnsupportedVersion(u32),
    /// Invalid architecture byte.
    InvalidArch(u8),
    /// Invalid event kind byte.
    InvalidEventKind(u8),
    /// Invalid or corrupt metadata block.
    InvalidMetadata,
}

/// Target architecture recorded in the trace header.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TraceArch {
    /// 32-bit x86.
    X86 = 0,
    /// 64-bit x86.
    X86_64 = 1,
}

impl TraceArch {
    /// Convert a raw byte to a [`TraceArch`], returning an error for unknown
    /// values.
    fn from_byte(b: u8) -> Result<Self, TraceError> {
        match b {
            0 => Ok(Self::X86),
            1 => Ok(Self::X86_64),
            _ => Err(TraceError::InvalidArch(b)),
        }
    }
}

/// Metadata about the traced program, stored in the trace header (v3+).
///
/// This captures enough information to reproduce the original execution
/// environment: the program binary, its arguments, environment variables,
/// and optional initial filesystem snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceMetadata {
    /// Path to the guest program binary.
    pub program_path: String,
    /// Command-line arguments (argv).
    pub argv: Vec<String>,
    /// Environment variables (envp).
    pub envp: Vec<String>,
    /// Optional path to the initial filesystem tar archive.
    pub initial_files_path: Option<String>,
    /// Whether the program binary was extracted from the tar archive.
    pub program_from_tar: bool,
}

impl TraceMetadata {
    /// Serialize this metadata to bytes.
    ///
    /// Wire format:
    /// ```text
    /// u32 LE  total_len        (byte count of everything after this u32)
    /// u32 LE  program_path_len
    /// [u8]    program_path     (UTF-8)
    /// u32 LE  argc
    /// for each arg:
    ///   u32 LE  arg_len
    ///   [u8]    arg
    /// u32 LE  envc
    /// for each env:
    ///   u32 LE  env_len
    ///   [u8]    env
    /// u8      flags             (bit 0 = program_from_tar, bit 1 = has_initial_files)
    /// if has_initial_files:
    ///   u32 LE  initial_files_path_len
    ///   [u8]    initial_files_path
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if any string length or the total payload size exceeds
    /// [`u32::MAX`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Build the payload (everything after total_len).
        let mut payload = Vec::new();

        // program_path
        let pp = self.program_path.as_bytes();
        let pp_len: u32 = pp
            .len()
            .try_into()
            .expect("program_path length exceeds u32::MAX");
        payload.extend_from_slice(&pp_len.to_le_bytes());
        payload.extend_from_slice(pp);

        // argv
        let argc: u32 = self.argv.len().try_into().expect("argc exceeds u32::MAX");
        payload.extend_from_slice(&argc.to_le_bytes());
        for arg in &self.argv {
            let ab = arg.as_bytes();
            let al: u32 = ab.len().try_into().expect("arg length exceeds u32::MAX");
            payload.extend_from_slice(&al.to_le_bytes());
            payload.extend_from_slice(ab);
        }

        // envp
        let envc: u32 = self.envp.len().try_into().expect("envc exceeds u32::MAX");
        payload.extend_from_slice(&envc.to_le_bytes());
        for env in &self.envp {
            let eb = env.as_bytes();
            let el: u32 = eb.len().try_into().expect("env length exceeds u32::MAX");
            payload.extend_from_slice(&el.to_le_bytes());
            payload.extend_from_slice(eb);
        }

        // flags
        let mut flags: u8 = 0;
        if self.program_from_tar {
            flags |= 0x01;
        }
        if self.initial_files_path.is_some() {
            flags |= 0x02;
        }
        payload.push(flags);

        // initial_files_path (if present)
        if let Some(ref ifp) = self.initial_files_path {
            let ib = ifp.as_bytes();
            let il: u32 = ib
                .len()
                .try_into()
                .expect("initial_files_path length exceeds u32::MAX");
            payload.extend_from_slice(&il.to_le_bytes());
            payload.extend_from_slice(ib);
        }

        // Prepend total_len
        let total_len: u32 = payload
            .len()
            .try_into()
            .expect("metadata payload size exceeds u32::MAX");
        let mut buf = Vec::with_capacity(4 + payload.len());
        buf.extend_from_slice(&total_len.to_le_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    /// Deserialize metadata from `data`, returning the metadata and the number
    /// of bytes consumed.
    ///
    /// # Panics
    ///
    /// This method does not panic. All slice indexing is guarded by length
    /// checks that return [`TraceError::InvalidMetadata`] or
    /// [`TraceError::UnexpectedEof`] on invalid input.
    #[allow(clippy::similar_names)] // argc/argv, envc/envp are natural names
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), TraceError> {
        if data.len() < 4 {
            return Err(TraceError::UnexpectedEof);
        }
        let total_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let total_consumed = 4 + total_len;
        if data.len() < total_consumed {
            return Err(TraceError::UnexpectedEof);
        }

        let payload = &data[4..total_consumed];
        let mut pos = 0;

        // Helper: read a u32 LE from payload
        let read_u32 = |pos: &mut usize| -> Result<u32, TraceError> {
            if *pos + 4 > payload.len() {
                return Err(TraceError::InvalidMetadata);
            }
            let val = u32::from_le_bytes(payload[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            Ok(val)
        };

        // Helper: read a UTF-8 string of known length from payload
        let read_string = |pos: &mut usize, len: usize| -> Result<String, TraceError> {
            if *pos + len > payload.len() {
                return Err(TraceError::InvalidMetadata);
            }
            let s = core::str::from_utf8(&payload[*pos..*pos + len])
                .map_err(|_| TraceError::InvalidMetadata)?;
            *pos += len;
            Ok(String::from(s))
        };

        // program_path
        let pp_len = read_u32(&mut pos)? as usize;
        let program_path = read_string(&mut pos, pp_len)?;

        // argv
        let argc = read_u32(&mut pos)? as usize;
        let mut argv = Vec::with_capacity(argc);
        for _ in 0..argc {
            let al = read_u32(&mut pos)? as usize;
            argv.push(read_string(&mut pos, al)?);
        }

        // envp
        let envc = read_u32(&mut pos)? as usize;
        let mut envp = Vec::with_capacity(envc);
        for _ in 0..envc {
            let el = read_u32(&mut pos)? as usize;
            envp.push(read_string(&mut pos, el)?);
        }

        // flags
        if pos >= payload.len() {
            return Err(TraceError::InvalidMetadata);
        }
        let flags = payload[pos];
        pos += 1;
        let program_from_tar = flags & 0x01 != 0;
        let has_initial_files = flags & 0x02 != 0;

        // initial_files_path
        let initial_files_path = if has_initial_files {
            let il = read_u32(&mut pos)? as usize;
            Some(read_string(&mut pos, il)?)
        } else {
            None
        };

        Ok((
            Self {
                program_path,
                argv,
                envp,
                initial_files_path,
                program_from_tar,
            },
            total_consumed,
        ))
    }
}

/// Header written at the start of every trace.
///
/// Wire format (v1/v2: 9 bytes, v3: 9 bytes + metadata block):
/// ```text
/// [0..4]  magic:   [u8; 4]
/// [4..8]  version: u32 LE
/// [8]     arch:    u8
/// -- v3 only: --
/// [9..]   metadata (see [`TraceMetadata::to_bytes`])
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TraceHeader {
    /// Magic bytes (must be [`TRACE_MAGIC`]).
    pub magic: [u8; 4],
    /// Format version.
    pub version: u32,
    /// Target architecture.
    pub arch: TraceArch,
    /// Optional program metadata (v3+).
    pub metadata: Option<TraceMetadata>,
}

/// Size of a serialized [`TraceHeader`] in bytes.
const TRACE_HEADER_SIZE: usize = 9;

impl TraceHeader {
    /// Serialize this header to bytes.
    ///
    /// For v3 headers, metadata is always serialized after the fixed 9-byte
    /// portion.
    ///
    /// # Panics
    ///
    /// Panics if `version >= 3` and `metadata` is `None`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TRACE_HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.push(self.arch as u8);

        if self.version >= 3 {
            let meta = self.metadata.as_ref().expect("v3 header requires metadata");
            buf.extend_from_slice(&meta.to_bytes());
        }

        buf
    }

    /// Deserialize a header from `data`, returning the header and the number of
    /// bytes consumed.
    ///
    /// Accepts v1, v2 (no metadata), and v3 (metadata follows fixed header).
    ///
    /// # Panics
    ///
    /// This method does not panic. All slice indexing is guarded by a length
    /// check that returns [`TraceError::UnexpectedEof`] on short input.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), TraceError> {
        if data.len() < TRACE_HEADER_SIZE {
            return Err(TraceError::UnexpectedEof);
        }

        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        if magic != TRACE_MAGIC {
            return Err(TraceError::InvalidMagic);
        }

        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version == 0 || version > TRACE_VERSION {
            return Err(TraceError::UnsupportedVersion(version));
        }

        let arch = TraceArch::from_byte(data[8])?;

        let mut consumed = TRACE_HEADER_SIZE;
        let metadata = if version >= 3 {
            let (meta, meta_consumed) = TraceMetadata::from_bytes(&data[consumed..])?;
            consumed += meta_consumed;
            Some(meta)
        } else {
            None
        };

        Ok((
            Self {
                magic,
                version,
                arch,
                metadata,
            },
            consumed,
        ))
    }
}

/// A single recorded syscall event.
///
/// Wire format (32 + `data_len` bytes):
/// ```text
/// [0..8]              event_id:   u64 LE
/// [8..12]             syscall_nr: u32 LE
/// [12..20]            result:     i64 LE
/// [20..24]            data_len:   u32 LE
/// [24..28]            tid:        u32 LE
/// [28]                kind:       u8
/// [29..32]            pad:        [u8; 3] (zero)
/// [32..32+data_len]   data:       [u8]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Monotonically increasing event counter.
    pub event_id: u64,
    /// Linux syscall number.
    pub syscall_nr: u32,
    /// Syscall return value. Positive = success, negative = -errno.
    pub result: i64,
    /// Side-effect data written to guest memory by this syscall (e.g., bytes
    /// from `read()`). Empty for syscalls that don't produce output data.
    pub data: Vec<u8>,
    /// Thread ID of the thread that produced this event.
    pub tid: u32,
    /// Kind of event (complete, entry, exit, signal).
    pub kind: EventKind,
}

/// Size of the fixed portion of a serialized [`Event`] (excluding variable-length data).
const EVENT_FIXED_SIZE: usize = 32;

impl Event {
    /// Serialize this event to bytes.
    ///
    /// # Panics
    ///
    /// Panics if `self.data.len()` exceeds [`u32::MAX`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let data_len: u32 = self
            .data
            .len()
            .try_into()
            .expect("event data length exceeds u32::MAX");
        let mut buf = Vec::with_capacity(EVENT_FIXED_SIZE + self.data.len());
        buf.extend_from_slice(&self.event_id.to_le_bytes());
        buf.extend_from_slice(&self.syscall_nr.to_le_bytes());
        buf.extend_from_slice(&self.result.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&self.tid.to_le_bytes());
        buf.push(self.kind as u8);
        buf.extend_from_slice(&[0u8; 3]); // padding
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserialize an event from `data`, returning the event and the number of
    /// bytes consumed.
    ///
    /// # Panics
    ///
    /// This method does not panic. All slice indexing is guarded by length
    /// checks that return [`TraceError::UnexpectedEof`] on short input.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), TraceError> {
        if data.len() < EVENT_FIXED_SIZE {
            return Err(TraceError::UnexpectedEof);
        }

        let event_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let syscall_nr = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let result = i64::from_le_bytes(data[12..20].try_into().unwrap());
        let data_len = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;
        let tid = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let kind = EventKind::from_byte(data[28]).ok_or(TraceError::InvalidEventKind(data[28]))?;
        // bytes [29..32] are padding, skip them

        let total = EVENT_FIXED_SIZE + data_len;
        if data.len() < total {
            return Err(TraceError::UnexpectedEof);
        }

        let payload = data[EVENT_FIXED_SIZE..total].to_vec();

        Ok((
            Self {
                event_id,
                syscall_nr,
                result,
                data: payload,
                tid,
                kind,
            },
            total,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a sample metadata for tests.
    fn sample_metadata() -> TraceMetadata {
        TraceMetadata {
            program_path: String::from("/usr/bin/hello"),
            argv: alloc::vec![String::from("hello"), String::from("--world")],
            envp: alloc::vec![String::from("PATH=/usr/bin"), String::from("HOME=/root")],
            initial_files_path: Some(String::from("/tmp/rootfs.tar")),
            program_from_tar: true,
        }
    }

    #[test]
    fn test_header_roundtrip() {
        // v3 requires metadata, so test with metadata present
        let header = TraceHeader {
            magic: TRACE_MAGIC,
            version: TRACE_VERSION,
            arch: TraceArch::X86_64,
            metadata: Some(TraceMetadata {
                program_path: String::from("/bin/test"),
                argv: alloc::vec![],
                envp: alloc::vec![],
                initial_files_path: None,
                program_from_tar: false,
            }),
        };
        let bytes = header.to_bytes();
        let (decoded, consumed) = TraceHeader::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_event_roundtrip() {
        let event = Event {
            event_id: 42,
            syscall_nr: 0,
            result: 5,
            data: alloc::vec![1, 2, 3, 4, 5],
            tid: 0,
            kind: EventKind::Complete,
        };
        let bytes = event.to_bytes();
        let (decoded, consumed) = Event::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, EVENT_FIXED_SIZE + 5);
        assert_eq!(decoded, event);
    }

    #[test]
    fn test_event_roundtrip_no_data() {
        let event = Event {
            event_id: 1,
            syscall_nr: 60,
            result: 0,
            data: alloc::vec![],
            tid: 0,
            kind: EventKind::Complete,
        };
        let bytes = event.to_bytes();
        let (decoded, consumed) = Event::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, EVENT_FIXED_SIZE);
        assert_eq!(decoded, event);
    }

    #[test]
    fn test_header_invalid_magic() {
        let mut bytes = TraceHeader {
            magic: TRACE_MAGIC,
            version: TRACE_VERSION,
            arch: TraceArch::X86_64,
            metadata: Some(TraceMetadata {
                program_path: String::from("/bin/x"),
                argv: alloc::vec![],
                envp: alloc::vec![],
                initial_files_path: None,
                program_from_tar: false,
            }),
        }
        .to_bytes();
        // Corrupt the magic bytes.
        bytes[0] = b'X';
        let err = TraceHeader::from_bytes(&bytes).unwrap_err();
        assert_eq!(err, TraceError::InvalidMagic);
    }

    #[test]
    fn test_header_eof() {
        let bytes = [0u8; 4]; // Too short for a header.
        let err = TraceHeader::from_bytes(&bytes).unwrap_err();
        assert_eq!(err, TraceError::UnexpectedEof);
    }

    #[test]
    fn test_event_kind_roundtrip() {
        for (byte, expected) in [
            (0u8, EventKind::Complete),
            (1, EventKind::Entry),
            (2, EventKind::Exit),
            (3, EventKind::Signal),
        ] {
            assert_eq!(EventKind::from_byte(byte), Some(expected));
        }
        assert_eq!(EventKind::from_byte(4), Some(EventKind::Snapshot));
        assert_eq!(EventKind::from_byte(5), None);
        assert_eq!(EventKind::from_byte(255), None);
    }

    #[test]
    fn test_event_with_tid_and_kind() {
        let event = Event {
            event_id: 10,
            syscall_nr: 202, // futex
            result: 0,
            data: alloc::vec![],
            tid: 42,
            kind: EventKind::Entry,
        };
        let bytes = event.to_bytes();
        let (decoded, consumed) = Event::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, EVENT_FIXED_SIZE);
        assert_eq!(decoded.tid, 42);
        assert_eq!(decoded.kind, EventKind::Entry);
        assert_eq!(decoded, event);
    }

    // -- TraceMetadata tests --

    #[test]
    fn test_metadata_roundtrip() {
        let meta = sample_metadata();
        let bytes = meta.to_bytes();
        let (decoded, consumed) = TraceMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, meta);
    }

    #[test]
    fn test_metadata_empty_roundtrip() {
        let meta = TraceMetadata {
            program_path: String::new(),
            argv: alloc::vec![],
            envp: alloc::vec![],
            initial_files_path: None,
            program_from_tar: false,
        };
        let bytes = meta.to_bytes();
        let (decoded, consumed) = TraceMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, meta);
    }

    #[test]
    fn test_metadata_program_from_tar() {
        let meta = TraceMetadata {
            program_path: String::from("/app/main"),
            argv: alloc::vec![String::from("/app/main")],
            envp: alloc::vec![],
            initial_files_path: Some(String::from("/data/fs.tar")),
            program_from_tar: true,
        };
        let bytes = meta.to_bytes();
        let (decoded, consumed) = TraceMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, meta);
        assert!(decoded.program_from_tar);
        assert_eq!(decoded.initial_files_path.as_deref(), Some("/data/fs.tar"));
    }

    // -- TraceHeader v3/v2 tests --

    #[test]
    fn test_header_v3_with_metadata_roundtrip() {
        let meta = sample_metadata();
        let header = TraceHeader {
            magic: TRACE_MAGIC,
            version: 3,
            arch: TraceArch::X86_64,
            metadata: Some(meta.clone()),
        };
        let bytes = header.to_bytes();
        let (decoded, consumed) = TraceHeader::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.version, 3);
        assert_eq!(decoded.metadata, Some(meta));
    }

    #[test]
    fn test_header_v2_no_metadata() {
        // Manually build a v2 header (9 bytes, no metadata)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TRACE_MAGIC);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.push(TraceArch::X86_64 as u8);

        let (decoded, consumed) = TraceHeader::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, TRACE_HEADER_SIZE);
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.arch, TraceArch::X86_64);
        assert_eq!(decoded.metadata, None);
    }

    #[test]
    fn test_snapshot_event_kind_roundtrip() {
        assert_eq!(EventKind::from_byte(4), Some(EventKind::Snapshot));
    }

    #[test]
    fn test_snapshot_event_roundtrip() {
        let snapshot_data = alloc::vec![1, 2, 3, 4, 5];
        let event = Event {
            event_id: 42,
            syscall_nr: EXECVE_SNAPSHOT_NR,
            result: 0,
            data: snapshot_data.clone(),
            tid: 1,
            kind: EventKind::Snapshot,
        };
        let bytes = event.to_bytes();
        let (decoded, consumed) = Event::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, event);
    }
}
