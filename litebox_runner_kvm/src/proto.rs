// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The wire protocol of the virtio message channel.
//!
//! virtio-console is a **byte stream**. It does not preserve message
//! boundaries, so framing is ours to provide:
//!
//! ```text
//! [u32 len][u16 version][u16 opcode][payload...]
//! ```
//!
//! `len` counts everything *after itself* -- version, opcode and payload --
//! so a reader takes four bytes, then exactly `len` more. **Every integer in
//! this protocol is little-endian**, matching the only architectures either
//! end runs on and matching what Python's `struct` `<` prefix produces.
//!
//! `version` and `opcode` are separate fields for a reason. Today the payload
//! carries [`UteeParamOwned`]-shaped parameters; a future cut may want to
//! carry `OpteeMsgArgs` instead. That is a *new opcode*, not a new meaning for
//! an existing one, and `version` exists so that a genuinely incompatible
//! reshaping of the framing is rejected outright rather than misparsed. An
//! unknown version is [`Error::UnknownVersion`], never a best-effort attempt
//! at the payload.
//!
//! [`UteeParamOwned`]: litebox_common_optee::UteeParamOwned
//!
//! # This parses untrusted input
//!
//! Everything decoded here arrives from outside the guest. The decoder is
//! therefore written as a cursor ([`Reader`]) whose every accessor checks the
//! requested length against what remains *before* reading it, and which has no
//! path that can panic, over-read, or allocate on an attacker's word alone:
//!
//! - the frame length is checked against [`MAX_FRAME_LEN`] before a buffer of
//!   that size is ever contemplated;
//! - every length-prefixed byte string is checked against the bytes actually
//!   remaining in the frame before it is allocated, so a 4 GiB length in a
//!   12-byte frame is a clean [`Error::Truncated`];
//! - the parameter count is checked against [`MAX_PARAMS`], which is
//!   `UteeParams::TEE_NUM_PARAMS`;
//! - unknown opcodes and unknown parameter tags are rejected by name.
//!
//! # Why this module is dependency-free
//!
//! Nothing here refers to `litebox_common_optee`, or to anything else in the
//! tree. It uses `core` and `alloc` only. That is what makes it compilable --
//! and so testable -- on the host, which the rest of this crate is not: see
//! `dev_tests/tests/kvm_proto.rs`, which includes this file as a module and
//! runs the `#[cfg(test)]` tests below against the host target. The conversion
//! to and from `UteeParamOwned` lives in [`crate::ta`], where it costs nothing
//! and keeps this file portable.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// The only protocol version this build speaks.
pub const VERSION: u16 = 1;

/// Largest frame accepted or produced, counting the four length bytes.
///
/// 1 MiB. The guest heap is a few hundred megabytes and a frame is buffered
/// whole, so an unbounded length would be a trivial remote exhaustion; a TA
/// parameter set that does not fit in a megabyte is not something this cut
/// supports anyway.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Maximum number of parameters in a request or response.
///
/// `UteeParams::TEE_NUM_PARAMS`, restated here rather than imported so this
/// module stays dependency-free. `crate::ta` asserts the two agree.
pub const MAX_PARAMS: usize = 4;

/// Bytes of framing that precede the payload: `len`, `version`, `opcode`.
pub const HEADER_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// Why a frame could not be decoded.
///
/// Every variant carries the numbers that produced it: a framing error with no
/// values in it cannot be acted on from a log line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The buffer ended in the middle of a field.
    Truncated { needed: usize, remaining: usize },
    /// The frame's declared length exceeds [`MAX_FRAME_LEN`].
    TooLong { declared: usize },
    /// The frame's declared length is too small to hold even the version and
    /// opcode.
    TooShort { declared: usize },
    /// The version field is not [`VERSION`].
    UnknownVersion { version: u16 },
    /// The opcode field names no known operation.
    UnknownOpcode { opcode: u16 },
    /// A parameter's tag byte names no known parameter kind.
    UnknownParamTag { tag: u8 },
    /// More parameters than [`MAX_PARAMS`].
    TooManyParams { count: usize },
    /// Bytes were left over after the frame was fully decoded. A decoder that
    /// silently ignored a tail would accept two different encodings of the
    /// same message, which is exactly the ambiguity framing exists to remove.
    TrailingBytes { remaining: usize },
    /// A string field was not valid UTF-8.
    NotUtf8,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Truncated { needed, remaining } => {
                write!(f, "truncated: needed {needed} bytes, {remaining} remain")
            }
            Self::TooLong { declared } => write!(
                f,
                "frame declares {declared} bytes, over the {MAX_FRAME_LEN}-byte limit"
            ),
            Self::TooShort { declared } => {
                write!(
                    f,
                    "frame declares {declared} bytes, under the 4-byte header"
                )
            }
            Self::UnknownVersion { version } => {
                write!(
                    f,
                    "unknown protocol version {version} (this build speaks {VERSION})"
                )
            }
            Self::UnknownOpcode { opcode } => write!(f, "unknown opcode {opcode}"),
            Self::UnknownParamTag { tag } => write!(f, "unknown parameter tag {tag}"),
            Self::TooManyParams { count } => {
                write!(f, "{count} parameters, at most {MAX_PARAMS} are allowed")
            }
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} bytes left over after the frame")
            }
            Self::NotUtf8 => f.write_str("a string field is not valid UTF-8"),
        }
    }
}

// ---------------------------------------------------------------------------
// Opcodes.
// ---------------------------------------------------------------------------

/// What a frame asks for, or says.
///
/// The first three mirror `TaEntryFunc` in
/// `litebox_runner_optee_on_linux_userland/src/tests.rs`, which is the model
/// this channel copies. [`Shutdown`] and [`Response`] are this protocol's own.
///
/// [`Shutdown`]: Opcode::Shutdown
/// [`Response`]: Opcode::Response
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Opcode {
    /// Acquire a session, load ldelf and the TA, and enter its `OpenSession`
    /// entry point.
    OpenSession = 1,
    /// Enter the TA's `InvokeCommand` entry point with a command id.
    InvokeCommand = 2,
    /// Enter the TA's `CloseSession` entry point.
    CloseSession = 3,
    /// Leave the request loop and exit the guest successfully. Without this
    /// the guest could only be ended by its host's timeout.
    Shutdown = 4,
    /// A reply. Only ever sent guest to host.
    Response = 5,
}

impl Opcode {
    fn from_raw(raw: u16) -> Result<Self, Error> {
        match raw {
            1 => Ok(Self::OpenSession),
            2 => Ok(Self::InvokeCommand),
            3 => Ok(Self::CloseSession),
            4 => Ok(Self::Shutdown),
            5 => Ok(Self::Response),
            opcode => Err(Error::UnknownOpcode { opcode }),
        }
    }
}

// ---------------------------------------------------------------------------
// Parameters.
// ---------------------------------------------------------------------------

/// A single TA parameter, mirroring `UteeParamOwned`.
///
/// The encoding is a tag byte followed by the variant's fields. Two shapes of
/// asymmetry were possible and both were rejected in favour of one encoding
/// per variant used in both directions:
///
/// - `ValueOutput` carries its two `u64`s even on a request, where they are
///   zero. The alternative -- omit them on the request -- makes the decoder's
///   behaviour depend on which direction the frame is travelling, which is a
///   second protocol hiding inside the first.
/// - `MemrefOutput` carries both `buffer_size` and a length-prefixed byte
///   string. On a request the string is empty and `buffer_size` says how much
///   room the TA is given; on a response the string is what the TA wrote. This
///   is what "memref outputs carry a size on request and bytes on response"
///   means concretely.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Param {
    /// An unused parameter slot.
    None,
    ValueInput {
        value_a: u64,
        value_b: u64,
    },
    ValueOutput {
        value_a: u64,
        value_b: u64,
    },
    ValueInout {
        value_a: u64,
        value_b: u64,
    },
    MemrefInput {
        data: Box<[u8]>,
    },
    MemrefOutput {
        buffer_size: u64,
        data: Box<[u8]>,
    },
    MemrefInout {
        buffer_size: u64,
        data: Box<[u8]>,
    },
}

/// Parameter tag bytes. Fixed by the wire format, so they are named rather
/// than derived from the enum's discriminants, which a reordering could move.
mod tag {
    pub const NONE: u8 = 0;
    pub const VALUE_INPUT: u8 = 1;
    pub const VALUE_OUTPUT: u8 = 2;
    pub const VALUE_INOUT: u8 = 3;
    pub const MEMREF_INPUT: u8 = 4;
    pub const MEMREF_OUTPUT: u8 = 5;
    pub const MEMREF_INOUT: u8 = 6;
}

impl Param {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::None => out.push(tag::NONE),
            Self::ValueInput { value_a, value_b } => {
                out.push(tag::VALUE_INPUT);
                out.extend_from_slice(&value_a.to_le_bytes());
                out.extend_from_slice(&value_b.to_le_bytes());
            }
            Self::ValueOutput { value_a, value_b } => {
                out.push(tag::VALUE_OUTPUT);
                out.extend_from_slice(&value_a.to_le_bytes());
                out.extend_from_slice(&value_b.to_le_bytes());
            }
            Self::ValueInout { value_a, value_b } => {
                out.push(tag::VALUE_INOUT);
                out.extend_from_slice(&value_a.to_le_bytes());
                out.extend_from_slice(&value_b.to_le_bytes());
            }
            Self::MemrefInput { data } => {
                out.push(tag::MEMREF_INPUT);
                put_bytes(out, data);
            }
            Self::MemrefOutput { buffer_size, data } => {
                out.push(tag::MEMREF_OUTPUT);
                out.extend_from_slice(&buffer_size.to_le_bytes());
                put_bytes(out, data);
            }
            Self::MemrefInout { buffer_size, data } => {
                out.push(tag::MEMREF_INOUT);
                out.extend_from_slice(&buffer_size.to_le_bytes());
                put_bytes(out, data);
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        let tag = r.u8()?;
        match tag {
            tag::NONE => Ok(Self::None),
            tag::VALUE_INPUT => Ok(Self::ValueInput {
                value_a: r.u64()?,
                value_b: r.u64()?,
            }),
            tag::VALUE_OUTPUT => Ok(Self::ValueOutput {
                value_a: r.u64()?,
                value_b: r.u64()?,
            }),
            tag::VALUE_INOUT => Ok(Self::ValueInout {
                value_a: r.u64()?,
                value_b: r.u64()?,
            }),
            tag::MEMREF_INPUT => Ok(Self::MemrefInput { data: r.bytes()? }),
            tag::MEMREF_OUTPUT => Ok(Self::MemrefOutput {
                buffer_size: r.u64()?,
                data: r.bytes()?,
            }),
            tag::MEMREF_INOUT => Ok(Self::MemrefInout {
                buffer_size: r.u64()?,
                data: r.bytes()?,
            }),
            tag => Err(Error::UnknownParamTag { tag }),
        }
    }
}

// ---------------------------------------------------------------------------
// Messages.
// ---------------------------------------------------------------------------

/// A request, host to guest.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Request {
    pub opcode: Opcode,
    /// The TA command id. Meaningful only for [`Opcode::InvokeCommand`];
    /// carried unconditionally so every request has one shape.
    pub cmd_id: u32,
    pub params: Vec<Param>,
}

/// A reply, guest to host.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Response {
    /// Zero on success. Non-zero means the *runner* failed before or around
    /// the TA -- a bad opcode, no session, a load failure.
    pub status: u32,
    /// The TA's own return code, taken from `%rax` on return from ring 3.
    /// Zero when no TA ran.
    pub ta_return: u32,
    /// The parameters as the TA left them, read back out of its `UteeParams`.
    pub params: Vec<Param>,
    /// Human-readable detail. Empty on success. This is what makes a failure
    /// diagnosable from the client's output rather than only from the guest's
    /// serial log.
    pub message: String,
}

/// Status code for a request the runner refused before any TA ran.
pub const STATUS_OK: u32 = 0;
/// Status code for any runner-side failure. Deliberately one value: the
/// detail lives in [`Response::message`], and inventing a code space that
/// neither end switches on would be ceremony.
pub const STATUS_ERROR: u32 = 1;

impl Request {
    /// Encodes the request as a complete frame, length prefix included.
    ///
    /// # Panics
    ///
    /// Panics if the encoded frame would exceed [`MAX_FRAME_LEN`]. This is a
    /// local programming error -- the guest never encodes a request -- and the
    /// only requests this crate builds are in its own tests.
    pub fn encode(&self) -> Vec<u8> {
        // `Shutdown` carries nothing, so it is encoded as nothing. The
        // alternative -- emit the cmd_id and an empty parameter list anyway --
        // would make the encoder and the decoder disagree about what a
        // shutdown frame is.
        if self.opcode == Opcode::Shutdown {
            return frame(self.opcode, &[]);
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.cmd_id.to_le_bytes());
        put_params(&mut payload, &self.params);
        frame(self.opcode, &payload)
    }

    /// Decodes a complete frame, length prefix included.
    pub fn decode(frame: &[u8]) -> Result<Self, Error> {
        let (opcode, mut r) = open_frame(frame)?;
        if opcode == Opcode::Response {
            return Err(Error::UnknownOpcode {
                opcode: Opcode::Response as u16,
            });
        }
        // `Shutdown` carries nothing at all. Requiring an empty payload rather
        // than skipping whatever is there keeps the "no trailing bytes" rule
        // uniform.
        if opcode == Opcode::Shutdown {
            r.finish()?;
            return Ok(Self {
                opcode,
                cmd_id: 0,
                params: Vec::new(),
            });
        }
        let cmd_id = r.u32()?;
        let params = get_params(&mut r)?;
        r.finish()?;
        Ok(Self {
            opcode,
            cmd_id,
            params,
        })
    }
}

impl Response {
    /// A successful reply carrying the TA's return code and output parameters.
    pub fn ok(ta_return: u32, params: Vec<Param>) -> Self {
        Self {
            status: STATUS_OK,
            ta_return,
            params,
            message: String::new(),
        }
    }

    /// A failure reply. `message` is what went wrong.
    pub fn error(message: String) -> Self {
        Self {
            status: STATUS_ERROR,
            ta_return: 0,
            params: Vec::new(),
            message,
        }
    }

    /// Encodes the response as a complete frame, length prefix included.
    ///
    /// # Panics
    ///
    /// Panics if the encoded frame would exceed [`MAX_FRAME_LEN`]. The guest
    /// builds these itself, out of at most four parameters whose memrefs it
    /// bounded when it accepted the request, so this is a local invariant.
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.status.to_le_bytes());
        payload.extend_from_slice(&self.ta_return.to_le_bytes());
        put_params(&mut payload, &self.params);
        put_bytes(&mut payload, self.message.as_bytes());
        frame(Opcode::Response, &payload)
    }

    /// Decodes a complete frame, length prefix included.
    pub fn decode(frame: &[u8]) -> Result<Self, Error> {
        let (opcode, mut r) = open_frame(frame)?;
        if opcode != Opcode::Response {
            return Err(Error::UnknownOpcode {
                opcode: opcode as u16,
            });
        }
        let status = r.u32()?;
        let ta_return = r.u32()?;
        let params = get_params(&mut r)?;
        let message = r.string()?;
        r.finish()?;
        Ok(Self {
            status,
            ta_return,
            params,
            message,
        })
    }
}

// ---------------------------------------------------------------------------
// Framing.
// ---------------------------------------------------------------------------

/// How many more bytes are needed to complete the frame that starts at the
/// front of `buf`, or `None` if the frame is already complete.
///
/// This is the function a stream reader loops on: virtio-console delivers
/// arbitrary fragments, so "have I got a whole message yet" has to be
/// answerable from a prefix. A buffer shorter than the length prefix needs at
/// least the rest of the prefix.
///
/// # Errors
///
/// [`Error::TooLong`] or [`Error::TooShort`] if the declared length is out of
/// range -- which is knowable, and worth failing on, before the frame is
/// complete. Waiting for a 4 GiB "frame" to arrive is the bug this prevents.
pub fn bytes_needed(buf: &[u8]) -> Result<Option<usize>, Error> {
    if buf.len() < 4 {
        return Ok(Some(4 - buf.len()));
    }
    let total = frame_len(buf)?;
    Ok((buf.len() < total).then(|| total - buf.len()))
}

/// The total size of the frame whose length prefix is at the front of `buf`,
/// validated against both bounds.
fn frame_len(buf: &[u8]) -> Result<usize, Error> {
    let mut prefix = [0_u8; 4];
    prefix.copy_from_slice(buf.get(..4).ok_or(Error::Truncated {
        needed: 4,
        remaining: buf.len(),
    })?);
    let declared = u32::from_le_bytes(prefix) as usize;
    // The declared length counts the version and the opcode, so it cannot be
    // smaller than those four bytes.
    if declared < 4 {
        return Err(Error::TooShort { declared });
    }
    let total = declared.saturating_add(4);
    if total > MAX_FRAME_LEN {
        return Err(Error::TooLong { declared });
    }
    Ok(total)
}

/// Validates a complete frame's header and returns its opcode and a reader
/// positioned at the payload.
fn open_frame(buf: &[u8]) -> Result<(Opcode, Reader<'_>), Error> {
    let total = frame_len(buf)?;
    let body = buf.get(..total).ok_or(Error::Truncated {
        needed: total,
        remaining: buf.len(),
    })?;
    // Anything past the declared length is a second frame, not this one's
    // business; callers hand whole frames in, so a longer buffer is a caller
    // bug and is reported rather than ignored.
    if buf.len() != total {
        return Err(Error::TrailingBytes {
            remaining: buf.len() - total,
        });
    }
    let mut r = Reader::new(&body[4..]);
    let version = r.u16()?;
    if version != VERSION {
        return Err(Error::UnknownVersion { version });
    }
    let opcode = Opcode::from_raw(r.u16()?)?;
    Ok((opcode, r))
}

/// Wraps `payload` in the length prefix, version and opcode.
fn frame(opcode: Opcode, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() + 4;
    assert!(
        len + 4 <= MAX_FRAME_LEN,
        "encoded frame is {} bytes, over the {MAX_FRAME_LEN}-byte limit",
        len + 4
    );
    let mut out = Vec::with_capacity(len + 4);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the assertion above bounds `len` by MAX_FRAME_LEN, which is far below u32::MAX"
    )]
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(opcode as u16).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Appends a length-prefixed byte string.
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    assert!(
        bytes.len() <= MAX_FRAME_LEN,
        "byte string of {} bytes cannot be framed",
        bytes.len()
    );
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the assertion above bounds the length by MAX_FRAME_LEN"
    )]
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Appends a count-prefixed parameter list.
fn put_params(out: &mut Vec<u8>, params: &[Param]) {
    assert!(
        params.len() <= MAX_PARAMS,
        "{} parameters, at most {MAX_PARAMS} are allowed",
        params.len()
    );
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the assertion above bounds the count by MAX_PARAMS, which is 4"
    )]
    out.push(params.len() as u8);
    for param in params {
        param.encode(out);
    }
}

/// Decodes a count-prefixed parameter list, bounding the count before
/// allocating for it.
fn get_params(r: &mut Reader<'_>) -> Result<Vec<Param>, Error> {
    let count = r.u8()? as usize;
    if count > MAX_PARAMS {
        return Err(Error::TooManyParams { count });
    }
    let mut params = Vec::with_capacity(count);
    for _ in 0..count {
        params.push(Param::decode(r)?);
    }
    Ok(params)
}

// ---------------------------------------------------------------------------
// The bounds-checking cursor.
// ---------------------------------------------------------------------------

/// A read cursor over a frame's payload.
///
/// The single place bounds are checked. Each accessor takes what it needs from
/// the front and shortens the remaining slice, and every one of them goes
/// through [`Reader::take`], so there is exactly one length check to review
/// rather than one per field.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self { rest }
    }

    /// Takes `n` bytes, or fails without consuming anything.
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(Error::Truncated {
            needed: n,
            remaining: self.rest.len(),
        })?;
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let mut b = [0_u8; 2];
        b.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(b))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let mut b = [0_u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let mut b = [0_u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    /// Reads a length-prefixed byte string.
    ///
    /// The length is checked against what actually remains *before* the
    /// allocation, so a declared length of `u32::MAX` costs nothing.
    fn bytes(&mut self) -> Result<Box<[u8]>, Error> {
        let len = self.u32()? as usize;
        Ok(Box::from(self.take(len)?))
    }

    /// Reads a length-prefixed UTF-8 string.
    fn string(&mut self) -> Result<String, Error> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        core::str::from_utf8(bytes)
            .map(String::from)
            .map_err(|_| Error::NotUtf8)
    }

    /// Asserts the payload was consumed exactly.
    fn finish(&self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingBytes {
                remaining: self.rest.len(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests.
//
// Pure functions, so unlike almost everything else in this crate these run on
// the host. See the module comment for how.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn all_params() -> Vec<Param> {
        vec![
            Param::None,
            Param::ValueInput {
                value_a: 0x0123_4567_89AB_CDEF,
                value_b: 1,
            },
            Param::ValueOutput {
                value_a: 0,
                value_b: u64::MAX,
            },
            Param::ValueInout {
                value_a: 100,
                value_b: 0,
            },
        ]
    }

    #[test]
    fn request_round_trips_for_every_opcode() {
        for opcode in [
            Opcode::OpenSession,
            Opcode::InvokeCommand,
            Opcode::CloseSession,
        ] {
            let request = Request {
                opcode,
                cmd_id: 7,
                params: all_params(),
            };
            let encoded = request.encode();
            assert_eq!(Request::decode(&encoded), Ok(request), "opcode {opcode:?}");
        }
    }

    #[test]
    fn shutdown_round_trips_and_carries_nothing() {
        let request = Request {
            opcode: Opcode::Shutdown,
            cmd_id: 0,
            params: Vec::new(),
        };
        let encoded = request.encode();
        // The header alone: no cmd_id, no parameter count.
        assert_eq!(encoded.len(), HEADER_LEN);
        assert_eq!(Request::decode(&encoded), Ok(request));
        // And a shutdown frame with a payload glued on is rejected rather
        // than silently accepted.
        let mut padded = encoded.clone();
        padded[0] += 1;
        padded.push(0);
        assert_eq!(
            Request::decode(&padded),
            Err(Error::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn every_param_variant_round_trips() {
        for param in [
            Param::None,
            Param::ValueInput {
                value_a: 1,
                value_b: 2,
            },
            Param::ValueOutput {
                value_a: 3,
                value_b: 4,
            },
            Param::ValueInout {
                value_a: 5,
                value_b: 6,
            },
            Param::MemrefInput {
                data: Box::from(&b"hello"[..]),
            },
            Param::MemrefOutput {
                buffer_size: 64,
                data: Box::from(&[][..]),
            },
            Param::MemrefOutput {
                buffer_size: 64,
                data: Box::from(&b"written by the TA"[..]),
            },
            Param::MemrefInout {
                buffer_size: 16,
                data: Box::from(&b"in and out"[..]),
            },
        ] {
            let request = Request {
                opcode: Opcode::InvokeCommand,
                cmd_id: 0,
                params: vec![param.clone()],
            };
            let encoded = request.encode();
            assert_eq!(
                Request::decode(&encoded).map(|r| r.params),
                Ok(vec![param.clone()]),
                "param {param:?}"
            );
        }
    }

    #[test]
    fn response_round_trips() {
        let response = Response::ok(
            0,
            vec![Param::ValueInout {
                value_a: 100,
                value_b: 200,
            }],
        );
        assert_eq!(Response::decode(&response.encode()), Ok(response));

        let failure = Response::error(String::from("no session is open"));
        assert_eq!(Response::decode(&failure.encode()), Ok(failure));
    }

    #[test]
    fn a_response_is_not_a_request_and_vice_versa() {
        let response = Response::ok(0, Vec::new());
        assert!(matches!(
            Request::decode(&response.encode()),
            Err(Error::UnknownOpcode { opcode: 5 })
        ));
        let request = Request {
            opcode: Opcode::CloseSession,
            cmd_id: 0,
            params: Vec::new(),
        };
        assert!(matches!(
            Response::decode(&request.encode()),
            Err(Error::UnknownOpcode { opcode: 3 })
        ));
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_panic() {
        let encoded = Request {
            opcode: Opcode::InvokeCommand,
            cmd_id: 9,
            params: all_params(),
        }
        .encode();
        for cut in 0..encoded.len() {
            assert!(
                Request::decode(&encoded[..cut]).is_err(),
                "a {cut}-byte prefix decoded as a whole frame"
            );
        }
        assert!(Request::decode(&encoded).is_ok());
    }

    #[test]
    fn a_length_larger_than_the_buffer_is_truncated() {
        let mut encoded = Request {
            opcode: Opcode::CloseSession,
            cmd_id: 0,
            params: Vec::new(),
        }
        .encode();
        encoded[..4].copy_from_slice(&1000_u32.to_le_bytes());
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::Truncated {
                needed: 1004,
                remaining: encoded.len()
            })
        );
        assert_eq!(bytes_needed(&encoded), Ok(Some(1004 - encoded.len())));
    }

    #[test]
    fn a_length_over_the_maximum_is_rejected_without_allocating() {
        let mut encoded = Request {
            opcode: Opcode::CloseSession,
            cmd_id: 0,
            params: Vec::new(),
        }
        .encode();
        encoded[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::TooLong {
                declared: u32::MAX as usize
            })
        );
        // And a stream reader learns this from the four-byte prefix alone,
        // rather than waiting for 4 GiB that will never arrive.
        assert_eq!(
            bytes_needed(&encoded[..4]),
            Err(Error::TooLong {
                declared: u32::MAX as usize
            })
        );
    }

    #[test]
    fn a_length_under_the_header_is_rejected() {
        let encoded = [3_u8, 0, 0, 0, 1, 0, 1, 0];
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::TooShort { declared: 3 })
        );
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut encoded = Request {
            opcode: Opcode::OpenSession,
            cmd_id: 0,
            params: Vec::new(),
        }
        .encode();
        encoded[4..6].copy_from_slice(&99_u16.to_le_bytes());
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::UnknownVersion { version: 99 })
        );
    }

    #[test]
    fn an_unknown_opcode_is_rejected() {
        let mut encoded = Request {
            opcode: Opcode::OpenSession,
            cmd_id: 0,
            params: Vec::new(),
        }
        .encode();
        encoded[6..8].copy_from_slice(&4242_u16.to_le_bytes());
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::UnknownOpcode { opcode: 4242 })
        );
    }

    #[test]
    fn an_unknown_param_tag_is_rejected() {
        let mut encoded = Request {
            opcode: Opcode::InvokeCommand,
            cmd_id: 0,
            params: vec![Param::None],
        }
        .encode();
        // ... len, version, opcode, cmd_id, count, tag.
        let tag_index = encoded.len() - 1;
        encoded[tag_index] = 200;
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::UnknownParamTag { tag: 200 })
        );
    }

    #[test]
    fn too_many_params_is_rejected_before_allocating() {
        let mut encoded = Request {
            opcode: Opcode::InvokeCommand,
            cmd_id: 0,
            params: Vec::new(),
        }
        .encode();
        // The count byte is the last one, and claiming 255 parameters must not
        // reserve room for them.
        let count_index = encoded.len() - 1;
        encoded[count_index] = 255;
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::TooManyParams { count: 255 })
        );
    }

    #[test]
    fn a_memref_length_larger_than_the_frame_is_truncated() {
        let mut encoded = Request {
            opcode: Opcode::InvokeCommand,
            cmd_id: 0,
            params: vec![Param::MemrefInput {
                data: Box::from(&b"abcd"[..]),
            }],
        }
        .encode();
        // Overwrite the memref's own length prefix -- the last four bytes
        // before the data -- with something enormous. The frame's `len` is
        // untouched, so this is the "inner length lies" case.
        let data_len_index = encoded.len() - 8;
        encoded[data_len_index..data_len_index + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::Truncated {
                needed: u32::MAX as usize,
                remaining: 4
            })
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = Request {
            opcode: Opcode::CloseSession,
            cmd_id: 0,
            params: Vec::new(),
        }
        .encode();
        encoded.push(0);
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn bytes_needed_walks_a_stream() {
        let encoded = Request {
            opcode: Opcode::InvokeCommand,
            cmd_id: 1,
            params: all_params(),
        }
        .encode();
        assert_eq!(bytes_needed(&[]), Ok(Some(4)));
        assert_eq!(bytes_needed(&encoded[..2]), Ok(Some(2)));
        for cut in 4..encoded.len() {
            assert_eq!(bytes_needed(&encoded[..cut]), Ok(Some(encoded.len() - cut)));
        }
        assert_eq!(bytes_needed(&encoded), Ok(None));
    }

    #[test]
    fn a_non_utf8_message_is_rejected() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&STATUS_ERROR.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        put_params(&mut payload, &[]);
        put_bytes(&mut payload, &[0xFF, 0xFE]);
        let encoded = frame(Opcode::Response, &payload);
        assert_eq!(Response::decode(&encoded), Err(Error::NotUtf8));
    }
}
