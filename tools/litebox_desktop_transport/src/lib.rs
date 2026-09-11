//! Portable framing primitives for the LiteBox `desktop_fd_v1` contract.
//!
//! This crate intentionally has no SDL, window-system, audio or OS dependencies.
//! A host or guest supplies the two dedicated byte streams. The caller owns the
//! process/FD setup and may connect these streams to LiteBox pipes later.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::{Condvar, Mutex};

pub const MAGIC: [u8; 4] = *b"LBDF";
pub const VERSION: u16 = 1;
pub const HANDSHAKE_SIZE: usize = 12;
pub const FRAME_HEADER_SIZE: usize = 4;
pub const DEFAULT_MAX_MESSAGE: u32 = 16 * 1024 * 1024;
pub const DEFAULT_QUEUE_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handshake {
    pub version: u16,
    pub max_message: u32,
    pub flags: u16,
}

impl Handshake {
    pub fn new(max_message: u32, flags: u16) -> Result<Self, ProtocolError> {
        if max_message == 0 || max_message > DEFAULT_MAX_MESSAGE {
            return Err(ProtocolError::InvalidLimit);
        }
        Ok(Self {
            version: VERSION,
            max_message,
            flags,
        })
    }

    pub fn encode(self) -> [u8; HANDSHAKE_SIZE] {
        let mut out = [0; HANDSHAKE_SIZE];
        out[..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..10].copy_from_slice(&self.max_message.to_le_bytes());
        out[10..12].copy_from_slice(&self.flags.to_le_bytes());
        out
    }

    pub fn decode(bytes: [u8; HANDSHAKE_SIZE]) -> Result<Self, ProtocolError> {
        if bytes[..4] != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let max_message = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        if max_message == 0 || max_message > DEFAULT_MAX_MESSAGE {
            return Err(ProtocolError::InvalidLimit);
        }
        Ok(Self {
            version,
            max_message,
            flags: u16::from_le_bytes([bytes[10], bytes[11]]),
        })
    }
}

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    BadMagic,
    UnsupportedVersion(u16),
    InvalidLimit,
    MessageTooLarge(usize),
    Truncated,
    Closed,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::BadMagic => f.write_str("invalid desktop transport magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported desktop transport version {v}"),
            Self::InvalidLimit => f.write_str("invalid desktop transport message limit"),
            Self::MessageTooLarge(n) => write!(f, "message is too large: {n} bytes"),
            Self::Truncated => f.write_str("stream ended in a partial frame"),
            Self::Closed => f.write_str("transport is closed"),
        }
    }
}

impl std::error::Error for ProtocolError {}
impl From<io::Error> for ProtocolError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Synchronous framed endpoint over a dedicated reader and writer.
pub struct Framed<R, W> {
    reader: R,
    writer: W,
    max_message: u32,
    handshaken: bool,
    closed: bool,
}

impl<R: Read, W: Write> Framed<R, W> {
    pub fn new(reader: R, writer: W, max_message: u32) -> Result<Self, ProtocolError> {
        if max_message == 0 || max_message > DEFAULT_MAX_MESSAGE {
            return Err(ProtocolError::InvalidLimit);
        }
        Ok(Self {
            reader,
            writer,
            max_message,
            handshaken: false,
            closed: false,
        })
    }

    /// Write our handshake and read the peer handshake. Both endpoints must call this.
    pub fn handshake(&mut self, flags: u16) -> Result<u32, ProtocolError> {
        if self.closed {
            return Err(ProtocolError::Closed);
        }
        let ours = Handshake::new(self.max_message, flags)?;
        self.writer.write_all(&ours.encode())?;
        self.writer.flush()?;
        let mut bytes = [0; HANDSHAKE_SIZE];
        read_exact_state(&mut self.reader, &mut bytes, false)?;
        let peer = Handshake::decode(bytes)?;
        self.max_message = self.max_message.min(peer.max_message);
        self.handshaken = true;
        Ok(self.max_message)
    }

    pub fn send(&mut self, message: &[u8]) -> Result<(), ProtocolError> {
        if self.closed || !self.handshaken {
            return Err(ProtocolError::Closed);
        }
        if message.len() > self.max_message as usize {
            return Err(ProtocolError::MessageTooLarge(message.len()));
        }
        let length = (message.len() as u32).to_le_bytes();
        self.writer.write_all(&length)?;
        self.writer.write_all(message)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Returns `Ok(None)` only when EOF occurs at a frame boundary.
    pub fn recv(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        if self.closed || !self.handshaken {
            return Err(ProtocolError::Closed);
        }
        let mut header = [0; FRAME_HEADER_SIZE];
        if !read_exact_state(&mut self.reader, &mut header, true)? {
            return Ok(None);
        }
        let length = u32::from_le_bytes(header) as usize;
        if length > self.max_message as usize {
            return Err(ProtocolError::MessageTooLarge(length));
        }
        let mut body = vec![0; length];
        read_exact_state(&mut self.reader, &mut body, false)?;
        Ok(Some(body))
    }

    pub fn close(&mut self) -> Result<(), ProtocolError> {
        if !self.closed {
            self.writer.flush()?;
            self.closed = true;
        }
        Ok(())
    }
}

fn read_exact_state<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    allow_clean_eof: bool,
) -> Result<bool, ProtocolError> {
    let mut offset = 0;
    while offset < buffer.len() {
        match reader.read(&mut buffer[offset..]) {
            Ok(0) if offset == 0 && allow_clean_eof => return Ok(false),
            Ok(0) => return Err(ProtocolError::Truncated),
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

/// A bounded, blocking queue used between UI/audio producers and transport writers.
pub struct BoundedQueue<T> {
    state: Mutex<QueueState<T>>,
    available: Condvar,
    space: Condvar,
}
struct QueueState<T> {
    values: VecDeque<T>,
    capacity: usize,
    closed: bool,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> Result<Self, ProtocolError> {
        if capacity == 0 {
            return Err(ProtocolError::InvalidLimit);
        }
        Ok(Self {
            state: Mutex::new(QueueState {
                values: VecDeque::new(),
                capacity,
                closed: false,
            }),
            available: Condvar::new(),
            space: Condvar::new(),
        })
    }

    pub fn push(&self, value: T) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::Closed)?;
        while state.values.len() == state.capacity && !state.closed {
            state = self.space.wait(state).map_err(|_| ProtocolError::Closed)?;
        }
        if state.closed {
            return Err(ProtocolError::Closed);
        }
        state.values.push_back(value);
        self.available.notify_one();
        Ok(())
    }

    /// Attempts to enqueue without waiting. A full or closed queue returns `Closed`.
    pub fn try_push(&self, value: T) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::Closed)?;
        if state.closed || state.values.len() == state.capacity {
            return Err(ProtocolError::Closed);
        }
        state.values.push_back(value);
        self.available.notify_one();
        Ok(())
    }

    pub fn pop(&self) -> Result<Option<T>, ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::Closed)?;
        loop {
            if let Some(value) = state.values.pop_front() {
                self.space.notify_one();
                return Ok(Some(value));
            }
            if state.closed {
                return Ok(None);
            }
            state = self
                .available
                .wait(state)
                .map_err(|_| ProtocolError::Closed)?;
        }
    }

    pub fn close(&self) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::Closed)?;
        state.closed = true;
        self.available.notify_all();
        self.space.notify_all();
        Ok(())
    }
    pub fn len(&self) -> Result<usize, ProtocolError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| ProtocolError::Closed)?
            .values
            .len())
    }
    pub fn is_empty(&self) -> Result<bool, ProtocolError> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Fragmented {
        data: Cursor<Vec<u8>>,
        chunk: usize,
    }
    impl Read for Fragmented {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.chunk.min(out.len());
            self.data.read(&mut out[..n])
        }
    }
    #[test]
    fn handshake_round_trip_and_limit() {
        let h = Handshake::new(1024, 7).unwrap();
        assert_eq!(Handshake::decode(h.encode()).unwrap(), h);
        assert!(matches!(
            Handshake::new(0, 0),
            Err(ProtocolError::InvalidLimit)
        ));
    }
    #[test]
    fn fragmented_frames_and_eof_are_distinct() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(3u32).to_le_bytes());
        bytes.extend_from_slice(b"abc");
        let mut f = Framed::new(
            Fragmented {
                data: Cursor::new(bytes),
                chunk: 1,
            },
            Vec::<u8>::new(),
            64,
        )
        .unwrap();
        f.handshaken = true;
        assert_eq!(f.recv().unwrap(), Some(b"abc".to_vec()));
        assert_eq!(f.recv().unwrap(), None);
        let mut truncated = Framed::new(
            Fragmented {
                data: Cursor::new(vec![4, 0, 0, 0, b'x']),
                chunk: 1,
            },
            Vec::<u8>::new(),
            64,
        )
        .unwrap();
        truncated.handshaken = true;
        assert!(matches!(truncated.recv(), Err(ProtocolError::Truncated)));
    }
    #[test]
    fn bounded_queue_applies_limit_and_shutdown() {
        let queue = BoundedQueue::new(1).unwrap();
        queue.try_push(1).unwrap();
        assert!(queue.try_push(2).is_err());
        assert_eq!(queue.pop().unwrap(), Some(1));
        queue.close().unwrap();
        assert_eq!(queue.pop().unwrap(), None);
        assert!(queue.push(3).is_err());
    }
}
