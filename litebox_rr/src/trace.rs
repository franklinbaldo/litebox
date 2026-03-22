// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Core trace format types and binary serialization.
//!
//! The trace format uses a simple TLV (type-length-value) encoding with
//! little-endian byte order for all multi-byte integers.

use alloc::vec::Vec;

/// Magic bytes for the trace file header: "LBRR" in ASCII.
pub const TRACE_MAGIC: [u8; 4] = *b"LBRR";

/// Current trace format version.
pub const TRACE_VERSION: u32 = 1;

/// Sentinel syscall number used for signal delivery events in the trace.
/// This is well outside the range of real Linux syscall numbers.
pub const SIGNAL_DELIVERY_NR: u32 = 0xFFFF_FFFE;

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

/// Header written at the start of every trace.
///
/// Wire format (9 bytes):
/// ```text
/// [0..4]  magic:   [u8; 4]
/// [4..8]  version: u32 LE
/// [8]     arch:    u8
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TraceHeader {
    /// Magic bytes (must be [`TRACE_MAGIC`]).
    pub magic: [u8; 4],
    /// Format version.
    pub version: u32,
    /// Target architecture.
    pub arch: TraceArch,
}

/// Size of a serialized [`TraceHeader`] in bytes.
const TRACE_HEADER_SIZE: usize = 9;

impl TraceHeader {
    /// Serialize this header to bytes.
    ///
    /// # Panics
    ///
    /// This method does not panic.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TRACE_HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.push(self.arch as u8);
        buf
    }

    /// Deserialize a header from `data`, returning the header and the number of
    /// bytes consumed.
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
        if version != TRACE_VERSION {
            return Err(TraceError::UnsupportedVersion(version));
        }

        let arch = TraceArch::from_byte(data[8])?;

        Ok((
            Self {
                magic,
                version,
                arch,
            },
            TRACE_HEADER_SIZE,
        ))
    }
}

/// A single recorded syscall event.
///
/// Wire format (24 + `data_len` bytes):
/// ```text
/// [0..8]              event_id:   u64 LE
/// [8..12]             syscall_nr: u32 LE
/// [12..20]            result:     i64 LE
/// [20..24]            data_len:   u32 LE
/// [24..24+data_len]   data:       [u8]
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
}

/// Size of the fixed portion of a serialized [`Event`] (excluding variable-length data).
const EVENT_FIXED_SIZE: usize = 24;

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
            },
            total,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = TraceHeader {
            magic: TRACE_MAGIC,
            version: TRACE_VERSION,
            arch: TraceArch::X86_64,
        };
        let bytes = header.to_bytes();
        let (decoded, consumed) = TraceHeader::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, TRACE_HEADER_SIZE);
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_event_roundtrip() {
        let event = Event {
            event_id: 42,
            syscall_nr: 0,
            result: 5,
            data: alloc::vec![1, 2, 3, 4, 5],
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
}
