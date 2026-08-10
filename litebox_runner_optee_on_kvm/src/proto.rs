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
///
/// Binaries do **not** raise this. `kmpp-ta.elf` is 2.5 MB, which would have
/// forced this constant to at least 4 MiB had a binary been sent in one
/// frame -- and this constant does not only bound binaries. It also bounds
/// every memref parameter, the accumulated receive buffer in
/// [`crate::ta::Channel`], and the clamp `crate::ta::read_user_bytes` applies
/// to a length a *TA* left in its `UteeParams`. Raising it to accommodate one
/// message type would silently loosen the bound on all of those. So binaries
/// are chunked instead ([`Opcode::LoadBinary`]) and get their own, separately
/// justified bound, [`MAX_BINARY_LEN`].
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Largest binary the guest will accept over [`Opcode::LoadBinary`].
///
/// 8 MiB. The largest artifact in the tree today is `kmpp-ta.elf` at 2.5 MB,
/// so this is roughly a 3x headroom; it is also under 2% of the guest's ~495
/// MB heap, and two of them (ldelf and the TA) are held at once. The declared
/// total is checked against this **before** the receiving buffer is reserved,
/// so a peer that announces a 4 GiB binary costs nothing.
pub const MAX_BINARY_LEN: usize = 8 * 1024 * 1024;

/// Maximum number of parameters in a request or response.
///
/// `UteeParams::TEE_NUM_PARAMS`, restated here rather than imported so this
/// module stays dependency-free. `crate::ta` asserts the two agree.
pub const MAX_PARAMS: usize = 4;

/// Bytes a response spends on framing rather than on payload, worst case.
///
/// Frame header and length prefix (8), `status` (4), `ta_return` (4), the
/// parameter count (1), and per parameter a tag, a `buffer_size` and a length
/// prefix (13 x [`MAX_PARAMS`]), plus the message's length prefix (4).
const RESPONSE_OVERHEAD: usize = 8 + 4 + 4 + 1 + 13 * MAX_PARAMS + 4;

/// Largest `Response::message` that will be framed; longer ones are truncated.
///
/// A message is diagnostic text, so losing the tail of an unusually long one
/// costs nothing, and bounding it here is what lets the memref budget below be
/// a constant rather than something that depends on the message.
pub const MAX_MESSAGE_LEN: usize = 8 * 1024;

/// Total bytes of memref payload a single response may carry, across *all* its
/// parameters.
///
/// This is a whole-response budget, deliberately, because the thing it has to
/// keep inside [`MAX_FRAME_LEN`] is the whole response. A per-parameter clamp
/// does not: there are up to [`MAX_PARAMS`] memrefs, so four parameters each
/// clamped to a megabyte sum to four, and the frame assertion then fires on a
/// response the guest built itself.
///
/// The value is [`MAX_FRAME_LEN`] less everything that is not memref bytes, so
/// a response that respects it cannot fail to frame. It reserves room for a
/// full-length message *and* four full parameters at once, which no single
/// response uses -- a success carries no message and an error carries no
/// parameters -- so the reservation is slack rather than a real reduction.
pub const MAX_RESPONSE_MEMREF_BYTES: usize = MAX_FRAME_LEN - RESPONSE_OVERHEAD - MAX_MESSAGE_LEN;

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
    /// A [`Opcode::LoadBinary`] frame named no known [`BinaryTarget`].
    UnknownBinaryTarget { target: u8 },
    /// A [`Opcode::LoadBinary`] frame declared a total size over
    /// [`MAX_BINARY_LEN`].
    BinaryTooLong { total_len: usize },
    /// A [`Opcode::LoadBinary`] chunk does not fit inside the total it
    /// declares. Caught in the decoder rather than in the guest, because
    /// `offset + len > total_len` is a statement about the *frame*, and
    /// letting it through would leave every consumer to re-derive the same
    /// check.
    BinaryChunkOutOfRange {
        offset: usize,
        chunk_len: usize,
        total_len: usize,
    },
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
            Self::UnknownBinaryTarget { target } => {
                write!(f, "unknown binary target {target}")
            }
            Self::BinaryTooLong { total_len } => write!(
                f,
                "binary declares {total_len} bytes, over the {MAX_BINARY_LEN}-byte limit"
            ),
            Self::BinaryChunkOutOfRange {
                offset,
                chunk_len,
                total_len,
            } => write!(
                f,
                "chunk of {chunk_len} bytes at offset {offset} does not fit in {total_len} bytes"
            ),
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
    /// Deliver one chunk of `ldelf` or of the TA. See [`LoadChunk`].
    LoadBinary = 6,
}

impl Opcode {
    fn from_raw(raw: u16) -> Result<Self, Error> {
        match raw {
            1 => Ok(Self::OpenSession),
            2 => Ok(Self::InvokeCommand),
            3 => Ok(Self::CloseSession),
            4 => Ok(Self::Shutdown),
            5 => Ok(Self::Response),
            6 => Ok(Self::LoadBinary),
            opcode => Err(Error::UnknownOpcode { opcode }),
        }
    }
}

// ---------------------------------------------------------------------------
// Binary loading.
// ---------------------------------------------------------------------------

/// Which of the two binaries a [`LoadChunk`] belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum BinaryTarget {
    /// OP-TEE's user-mode loader.
    Ldelf = 1,
    /// The trusted application ldelf will map.
    Ta = 2,
}

impl BinaryTarget {
    fn from_raw(raw: u8) -> Result<Self, Error> {
        match raw {
            1 => Ok(Self::Ldelf),
            2 => Ok(Self::Ta),
            target => Err(Error::UnknownBinaryTarget { target }),
        }
    }

    /// The name used in log lines and error messages.
    ///
    /// `allow` rather than `expect`: this file is compiled twice, once into
    /// the guest -- where `ta.rs` calls this -- and once into
    /// `dev_tests/tests/kvm_proto.rs`, which exercises the codec only. It is
    /// genuinely dead in the second, and `expect` would then fire in the first.
    #[allow(
        dead_code,
        reason = "used by ta.rs in the guest build, not by the codec tests"
    )]
    pub fn name(self) -> &'static str {
        match self {
            Self::Ldelf => "ldelf",
            Self::Ta => "the TA",
        }
    }
}

/// One slice of a binary being shipped into the guest.
///
/// Binaries are *chunked* rather than sent whole; see [`MAX_FRAME_LEN`] for
/// why. Every chunk restates `total_len` so that the receiver can size its
/// buffer from the first frame it sees and can reject a peer that changes its
/// mind mid-transfer, and carries an explicit `offset` so that a lost or
/// reordered chunk is a detected error rather than a silently corrupt ELF.
/// The transfer is append-only: the guest requires `offset` to equal exactly
/// what it already holds.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoadChunk {
    pub target: BinaryTarget,
    /// The size of the whole binary, repeated in every chunk.
    pub total_len: usize,
    /// Where `data` belongs within it.
    pub offset: usize,
    pub data: Box<[u8]>,
}

impl LoadChunk {
    /// True when this chunk ends the binary.
    pub fn is_last(&self) -> bool {
        self.offset + self.data.len() == self.total_len
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
///
/// # Invariant
///
/// `load.is_some()` exactly when `opcode == Opcode::LoadBinary`. [`decode`]
/// establishes it and [`encode`] asserts it, so no consumer has to check
/// both.
///
/// [`decode`]: Request::decode
/// [`encode`]: Request::encode
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Request {
    pub opcode: Opcode,
    /// The TA command id. Meaningful only for [`Opcode::InvokeCommand`];
    /// carried unconditionally so every request has one shape.
    pub cmd_id: u32,
    pub params: Vec<Param>,
    /// The binary chunk, for [`Opcode::LoadBinary`] and nothing else.
    pub load: Option<LoadChunk>,
}

impl Request {
    /// A request that carries no binary: everything except
    /// [`Opcode::LoadBinary`].
    pub fn simple(opcode: Opcode, cmd_id: u32, params: Vec<Param>) -> Self {
        Self {
            opcode,
            cmd_id,
            params,
            load: None,
        }
    }

    /// A [`Opcode::LoadBinary`] request.
    pub fn load(chunk: LoadChunk) -> Self {
        Self {
            opcode: Opcode::LoadBinary,
            cmd_id: 0,
            params: Vec::new(),
            load: Some(chunk),
        }
    }
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
        assert_eq!(
            self.load.is_some(),
            self.opcode == Opcode::LoadBinary,
            "a request carries a binary chunk exactly when its opcode is LoadBinary"
        );
        if let Some(chunk) = self.load.as_ref() {
            assert!(
                chunk.total_len <= MAX_BINARY_LEN,
                "binary of {} bytes is over the {MAX_BINARY_LEN}-byte limit",
                chunk.total_len
            );
            assert!(
                chunk.offset + chunk.data.len() <= chunk.total_len,
                "chunk of {} bytes at offset {} does not fit in {} bytes",
                chunk.data.len(),
                chunk.offset,
                chunk.total_len
            );
            let mut payload = Vec::with_capacity(chunk.data.len() + 16);
            payload.push(chunk.target as u8);
            payload.extend_from_slice(
                &u32::try_from(chunk.total_len)
                    .expect("bounded above")
                    .to_le_bytes(),
            );
            payload.extend_from_slice(
                &u32::try_from(chunk.offset)
                    .expect("bounded above")
                    .to_le_bytes(),
            );
            put_bytes(&mut payload, &chunk.data);
            return frame(self.opcode, &payload);
        }
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
        if opcode == Opcode::LoadBinary {
            let target = BinaryTarget::from_raw(r.u8()?)?;
            let total_len = r.u32()? as usize;
            // Bounded before `bytes()` below is allowed to allocate anything,
            // and before the guest sizes a buffer from it.
            if total_len > MAX_BINARY_LEN {
                return Err(Error::BinaryTooLong { total_len });
            }
            let offset = r.u32()? as usize;
            let data = r.bytes()?;
            if offset.saturating_add(data.len()) > total_len {
                return Err(Error::BinaryChunkOutOfRange {
                    offset,
                    chunk_len: data.len(),
                    total_len,
                });
            }
            r.finish()?;
            return Ok(Self::load(LoadChunk {
                target,
                total_len,
                offset,
                data,
            }));
        }
        // `Shutdown` carries nothing at all. Requiring an empty payload rather
        // than skipping whatever is there keeps the "no trailing bytes" rule
        // uniform.
        if opcode == Opcode::Shutdown {
            r.finish()?;
            return Ok(Self::simple(opcode, 0, Vec::new()));
        }
        let cmd_id = r.u32()?;
        let params = get_params(&mut r)?;
        r.finish()?;
        Ok(Self::simple(opcode, cmd_id, params))
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
    /// Panics if the encoded frame would exceed [`MAX_FRAME_LEN`]. That is a
    /// local invariant, and the two things that could break it are both closed
    /// here: the memref bytes are budgeted across the whole response by
    /// [`MAX_RESPONSE_MEMREF_BYTES`] when `crate::ta` collects them, and the
    /// message is truncated to [`MAX_MESSAGE_LEN`] just below. The budget
    /// leaves room for both at once, so the sum cannot reach the limit.
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.status.to_le_bytes());
        payload.extend_from_slice(&self.ta_return.to_le_bytes());
        put_params(&mut payload, &self.params);
        // Truncated rather than asserted on: a message is diagnostic text, and
        // a response that cannot be sent tells the client nothing at all,
        // which is strictly worse than one whose explanation is cut short.
        put_bytes(&mut payload, truncate_message(&self.message).as_bytes());
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
/// `None` means "at least one whole frame is present", not "exactly one". A
/// caller that then hands the whole buffer to [`Request::decode`] is wrong
/// whenever a read delivered two frames; use [`complete_frame_len`], which
/// says where the first one ends.
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

/// The length of the complete frame at the front of `buf`, or `None` if `buf`
/// does not yet hold a whole one.
///
/// This is what a stream reader actually needs, and the difference from
/// [`bytes_needed`] is the whole point. A byte stream has no message
/// boundaries: one read can deliver half a frame, or a frame and a half, or
/// three frames. `bytes_needed` answers "is there a frame here", which is not
/// enough to consume one -- consuming the *buffer* rather than the *frame*
/// discards whatever followed it, and the next read then starts in the middle
/// of a frame and never recovers, because a length-prefixed format has no
/// resynchronisation point.
///
/// Returning the length instead lets the caller split, decode the front and
/// keep the remainder. Everything past `total` belongs to the next frame and
/// is not looked at here, not even to validate it: it may still be partial.
///
/// # Errors
///
/// As [`bytes_needed`].
pub fn complete_frame_len(buf: &[u8]) -> Result<Option<usize>, Error> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let total = frame_len(buf)?;
    Ok((buf.len() >= total).then_some(total))
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

/// Truncates a message to [`MAX_MESSAGE_LEN`], on a character boundary.
///
/// Splitting a `str` mid-character would not compile as a slice, so the cut
/// walks back to the nearest boundary. At most three bytes are given up.
fn truncate_message(message: &str) -> &str {
    if message.len() <= MAX_MESSAGE_LEN {
        return message;
    }
    let mut end = MAX_MESSAGE_LEN;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    &message[..end]
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
            let request = Request::simple(opcode, 7, all_params());
            let encoded = request.encode();
            assert_eq!(Request::decode(&encoded), Ok(request), "opcode {opcode:?}");
        }
    }

    #[test]
    fn shutdown_round_trips_and_carries_nothing() {
        let request = Request::simple(Opcode::Shutdown, 0, Vec::new());
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
            let request = Request::simple(Opcode::InvokeCommand, 0, vec![param.clone()]);
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
        let request = Request::simple(Opcode::CloseSession, 0, Vec::new());
        assert!(matches!(
            Response::decode(&request.encode()),
            Err(Error::UnknownOpcode { opcode: 3 })
        ));
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_panic() {
        let encoded = Request::simple(Opcode::InvokeCommand, 9, all_params()).encode();
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
        let mut encoded = Request::simple(Opcode::CloseSession, 0, Vec::new()).encode();
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
        let mut encoded = Request::simple(Opcode::CloseSession, 0, Vec::new()).encode();
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
        let mut encoded = Request::simple(Opcode::OpenSession, 0, Vec::new()).encode();
        encoded[4..6].copy_from_slice(&99_u16.to_le_bytes());
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::UnknownVersion { version: 99 })
        );
    }

    #[test]
    fn an_unknown_opcode_is_rejected() {
        let mut encoded = Request::simple(Opcode::OpenSession, 0, Vec::new()).encode();
        encoded[6..8].copy_from_slice(&4242_u16.to_le_bytes());
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::UnknownOpcode { opcode: 4242 })
        );
    }

    #[test]
    fn an_unknown_param_tag_is_rejected() {
        let mut encoded = Request::simple(Opcode::InvokeCommand, 0, vec![Param::None]).encode();
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
        let mut encoded = Request::simple(Opcode::InvokeCommand, 0, Vec::new()).encode();
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
        let mut encoded = Request::simple(
            Opcode::InvokeCommand,
            0,
            vec![Param::MemrefInput {
                data: Box::from(&b"abcd"[..]),
            }],
        )
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
        let mut encoded = Request::simple(Opcode::CloseSession, 0, Vec::new()).encode();
        encoded.push(0);
        assert_eq!(
            Request::decode(&encoded),
            Err(Error::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn bytes_needed_walks_a_stream() {
        let encoded = Request::simple(Opcode::InvokeCommand, 1, all_params()).encode();
        assert_eq!(bytes_needed(&[]), Ok(Some(4)));
        assert_eq!(bytes_needed(&encoded[..2]), Ok(Some(2)));
        for cut in 4..encoded.len() {
            assert_eq!(bytes_needed(&encoded[..cut]), Ok(Some(encoded.len() - cut)));
        }
        assert_eq!(bytes_needed(&encoded), Ok(None));
    }

    // -----------------------------------------------------------------
    // Binary loading.
    // -----------------------------------------------------------------

    /// Builds a `LoadBinary` frame from raw field values, bypassing the
    /// encoder's own assertions. Several of the tests below need to produce
    /// frames the encoder would refuse to build.
    fn load_frame(target: u8, total_len: u32, offset: u32, data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(target);
        payload.extend_from_slice(&total_len.to_le_bytes());
        payload.extend_from_slice(&offset.to_le_bytes());
        put_bytes(&mut payload, data);
        frame(Opcode::LoadBinary, &payload)
    }

    #[test]
    fn a_load_chunk_round_trips_for_every_target() {
        for target in [BinaryTarget::Ldelf, BinaryTarget::Ta] {
            let request = Request::load(LoadChunk {
                target,
                total_len: 10,
                offset: 4,
                data: Box::from(&b"abcdef"[..]),
            });
            let encoded = request.encode();
            assert_eq!(Request::decode(&encoded), Ok(request), "target {target:?}");
        }
    }

    #[test]
    fn a_load_request_carries_no_params_and_others_carry_no_chunk() {
        let load = Request::decode(
            &Request::load(LoadChunk {
                target: BinaryTarget::Ta,
                total_len: 1,
                offset: 0,
                data: Box::from(&b"x"[..]),
            })
            .encode(),
        )
        .expect("a well-formed load frame");
        assert!(load.params.is_empty());
        assert_eq!(load.cmd_id, 0);
        assert!(load.load.is_some());
        assert!(load.load.expect("just checked").is_last());

        let other = Request::decode(&Request::simple(Opcode::CloseSession, 0, Vec::new()).encode())
            .expect("a well-formed close frame");
        assert_eq!(other.load, None);
    }

    #[test]
    fn a_chunk_that_does_not_end_the_binary_is_not_the_last() {
        let chunk = LoadChunk {
            target: BinaryTarget::Ldelf,
            total_len: 100,
            offset: 0,
            data: Box::from(&b"abcd"[..]),
        };
        assert!(!chunk.is_last());
    }

    #[test]
    fn an_unknown_binary_target_is_rejected() {
        assert_eq!(
            Request::decode(&load_frame(9, 4, 0, b"abcd")),
            Err(Error::UnknownBinaryTarget { target: 9 })
        );
    }

    /// The oversized case: a declared total over [`MAX_BINARY_LEN`] is
    /// refused on the strength of the four bytes that declare it, before the
    /// receiver reserves anything.
    #[test]
    fn an_oversized_binary_is_rejected_before_allocating() {
        let over = u32::try_from(MAX_BINARY_LEN).expect("MAX_BINARY_LEN fits in a u32") + 1;
        assert_eq!(
            Request::decode(&load_frame(1, over, 0, b"abcd")),
            Err(Error::BinaryTooLong {
                total_len: over as usize
            })
        );
        // And the largest permitted total is still accepted, so the bound is
        // exactly where it claims to be rather than one out.
        let at_limit = u32::try_from(MAX_BINARY_LEN).expect("fits");
        assert!(Request::decode(&load_frame(1, at_limit, 0, b"abcd")).is_ok());
    }

    /// A chunk that claims to sit past the end of the binary it belongs to.
    #[test]
    fn a_chunk_outside_the_declared_total_is_rejected() {
        assert_eq!(
            Request::decode(&load_frame(2, 10, 8, b"abcd")),
            Err(Error::BinaryChunkOutOfRange {
                offset: 8,
                chunk_len: 4,
                total_len: 10,
            })
        );
        // An offset near u32::MAX must not wrap into the valid range.
        assert_eq!(
            Request::decode(&load_frame(2, 10, u32::MAX, b"")),
            Err(Error::BinaryChunkOutOfRange {
                offset: u32::MAX as usize,
                chunk_len: 0,
                total_len: 10,
            })
        );
    }

    /// The truncated case: every prefix of a load frame is an error, never a
    /// panic and never a partial accept.
    #[test]
    fn a_truncated_load_frame_is_an_error_not_a_panic() {
        let encoded = Request::load(LoadChunk {
            target: BinaryTarget::Ta,
            total_len: 2048,
            offset: 1024,
            data: Box::from(&[0x5A_u8; 1024][..]),
        })
        .encode();
        for cut in 0..encoded.len() {
            assert!(
                Request::decode(&encoded[..cut]).is_err(),
                "a {cut}-byte prefix of a load frame decoded as a whole frame"
            );
        }
        assert!(Request::decode(&encoded).is_ok());
    }

    /// The chunk's own length prefix is checked against the bytes actually
    /// present, not against what it claims.
    #[test]
    fn a_chunk_length_larger_than_the_frame_is_truncated() {
        let mut encoded = load_frame(1, 4096, 0, b"abcd");
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

    /// A whole binary can be reassembled from chunks that each fit a frame,
    /// which is the point of chunking at all: 2.5 MB of `kmpp-ta.elf` crosses
    /// the wire without [`MAX_FRAME_LEN`] moving.
    #[test]
    fn chunks_reassemble_a_binary_larger_than_a_frame() {
        const TOTAL: usize = 2_500_000;
        const CHUNK: usize = 256 * 1024;
        // A compile-time check, not a runtime one: both operands are consts, so
        // this states the premise of the test rather than testing anything.
        const _: () = assert!(TOTAL > MAX_FRAME_LEN);

        let source: Vec<u8> = (0..TOTAL)
            .map(|i| u8::try_from(i % 251).expect("i % 251 is at most 250"))
            .collect();
        let mut received = Vec::new();
        for (index, piece) in source.chunks(CHUNK).enumerate() {
            let encoded = Request::load(LoadChunk {
                target: BinaryTarget::Ta,
                total_len: TOTAL,
                offset: index * CHUNK,
                data: Box::from(piece),
            })
            .encode();
            assert!(encoded.len() <= MAX_FRAME_LEN);
            let chunk = Request::decode(&encoded)
                .expect("a chunk this end built")
                .load
                .expect("a load frame carries a chunk");
            assert_eq!(chunk.offset, received.len());
            received.extend_from_slice(&chunk.data);
            assert_eq!(chunk.is_last(), received.len() == TOTAL);
        }
        assert_eq!(received, source);
    }

    /// A response that spends the whole memref budget across the maximum
    /// number of parameters still frames. This is the coherence property the
    /// budget exists for: the old per-parameter clamp let four memrefs of
    /// `MAX_FRAME_LEN` each be collected, and the frame assertion then killed
    /// the guest on a response it had built itself.
    #[test]
    fn a_response_spending_the_whole_memref_budget_frames() {
        let share = MAX_RESPONSE_MEMREF_BYTES / MAX_PARAMS;
        let params: Vec<Param> = (0..MAX_PARAMS)
            .map(|_| Param::MemrefOutput {
                buffer_size: share as u64,
                data: vec![0xAB; share].into_boxed_slice(),
            })
            .collect();
        let encoded = Response::ok(0, params).encode();
        assert!(
            encoded.len() <= MAX_FRAME_LEN,
            "{} bytes exceeds the {MAX_FRAME_LEN}-byte frame limit",
            encoded.len()
        );
        // And it survives the round trip, so the budget bounds a response that
        // is actually usable rather than merely one that encodes.
        let decoded = Response::decode(&encoded).expect("a response this end built");
        assert_eq!(decoded.params.len(), MAX_PARAMS);
    }

    /// The budget leaves room for a full-length message alongside a full set
    /// of parameters, which is what makes it safe to reason about the two
    /// independently.
    #[test]
    fn the_budget_and_a_full_message_fit_together() {
        let share = MAX_RESPONSE_MEMREF_BYTES / MAX_PARAMS;
        let params: Vec<Param> = (0..MAX_PARAMS)
            .map(|_| Param::MemrefInout {
                buffer_size: share as u64,
                data: vec![0x5A; share].into_boxed_slice(),
            })
            .collect();
        let response = Response {
            status: STATUS_OK,
            ta_return: 0,
            params,
            message: "m".repeat(MAX_MESSAGE_LEN),
        };
        assert!(response.encode().len() <= MAX_FRAME_LEN);
    }

    /// An over-long message is truncated rather than asserted on: a response
    /// that cannot be sent tells the client nothing, which is worse than one
    /// whose explanation is cut short.
    #[test]
    fn an_over_long_message_is_truncated() {
        let response = Response::error("x".repeat(MAX_MESSAGE_LEN * 3));
        let decoded = Response::decode(&response.encode()).expect("a truncated message still fits");
        assert_eq!(decoded.message.len(), MAX_MESSAGE_LEN);
    }

    /// Truncation lands on a character boundary, so a multi-byte character
    /// straddling the cut is dropped whole rather than split.
    #[test]
    fn truncation_respects_character_boundaries() {
        // 'é' is two bytes, so a limit that is odd cuts one of them in half.
        let message = "é".repeat(MAX_MESSAGE_LEN);
        let truncated = truncate_message(&message);
        assert!(truncated.len() <= MAX_MESSAGE_LEN);
        assert!(message.starts_with(truncated));
        // Every character survived whole.
        assert!(truncated.chars().all(|c| c == 'é'));
    }

    #[test]
    fn a_short_message_is_left_alone() {
        assert_eq!(truncate_message("brief"), "brief");
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
    // -----------------------------------------------------------------------
    // Stream framing.
    //
    // The channel is a byte stream with no message boundaries, so these tests
    // are about the *reader*, not about any one frame. `drain` below is
    // `Channel::recv`'s inner loop with the transport removed: it holds a
    // `pending` buffer, asks the codec where the first whole frame ends, splits
    // there and keeps the remainder. Everything the real loop adds is I/O.
    // -----------------------------------------------------------------------

    /// Decode every whole frame at the front of `pending`, consuming exactly
    /// those bytes and leaving the rest. Mirrors `ta::Channel::recv`.
    fn drain(pending: &mut Vec<u8>) -> Result<Vec<Request>, Error> {
        let mut out = Vec::new();
        while let Some(total) = complete_frame_len(pending)? {
            let rest = pending.split_off(total);
            let frame = core::mem::replace(pending, rest);
            out.push(Request::decode(&frame)?);
        }
        Ok(out)
    }

    #[test]
    fn a_complete_frame_reports_its_own_length() {
        let encoded = Request::simple(Opcode::CloseSession, 0, Vec::new()).encode();
        assert_eq!(complete_frame_len(&encoded), Ok(Some(encoded.len())));
    }

    #[test]
    fn a_partial_frame_is_not_a_frame_yet() {
        let encoded = Request::simple(Opcode::InvokeCommand, 9, all_params()).encode();
        for cut in 0..encoded.len() {
            assert_eq!(
                complete_frame_len(&encoded[..cut]),
                Ok(None),
                "a {cut}-byte prefix was reported as a whole frame"
            );
        }
    }

    /// The bug this pair of functions exists to fix: `bytes_needed` cannot
    /// distinguish one frame from two, so a caller that consumed the whole
    /// buffer on `Ok(None)` fed the decoder a frame and a half.
    #[test]
    fn two_frames_in_one_read_are_two_frames() {
        let first = Request::simple(Opcode::OpenSession, 0, Vec::new()).encode();
        let second = Request::simple(Opcode::InvokeCommand, 7, all_params()).encode();
        let mut pending = first.clone();
        pending.extend_from_slice(&second);

        // What the old reader saw, and why it went wrong: "no more bytes
        // needed", followed by a decode of the whole buffer.
        assert_eq!(bytes_needed(&pending), Ok(None));
        assert_eq!(
            Request::decode(&pending),
            Err(Error::TrailingBytes {
                remaining: second.len()
            })
        );

        // What it sees now.
        assert_eq!(complete_frame_len(&pending), Ok(Some(first.len())));
        let decoded = drain(&mut pending).expect("both frames decode");
        assert!(pending.is_empty(), "bytes were left over");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].opcode, Opcode::OpenSession);
        assert_eq!(decoded[1].opcode, Opcode::InvokeCommand);
        assert_eq!(decoded[1].cmd_id, 7);
        assert_eq!(decoded[1].params, all_params());
    }

    /// A frame and a *fragment*: the second frame's tail has not arrived. The
    /// first must still be delivered, and not one byte of the second consumed.
    #[test]
    fn a_frame_and_a_half_yields_the_frame_and_keeps_the_half() {
        let first = Request::simple(Opcode::OpenSession, 0, Vec::new()).encode();
        let second = Request::simple(Opcode::InvokeCommand, 7, all_params()).encode();
        for half in 1..second.len() {
            let mut pending = first.clone();
            pending.extend_from_slice(&second[..half]);

            let decoded = drain(&mut pending).expect("the first frame decodes");
            assert_eq!(decoded.len(), 1, "with {half} bytes of the second frame");
            assert_eq!(decoded[0].opcode, Opcode::OpenSession);
            assert_eq!(
                pending,
                second[..half],
                "the {half}-byte fragment of the second frame was not kept intact"
            );

            // And once the rest arrives, the second frame decodes too.
            pending.extend_from_slice(&second[half..]);
            let decoded = drain(&mut pending).expect("the second frame decodes");
            assert!(pending.is_empty());
            assert_eq!(decoded.len(), 1);
            assert_eq!(decoded[0].cmd_id, 7);
        }
    }

    /// The general case: an arbitrary run of frames delivered in fixed-size
    /// chunks, for every chunk size. One byte at a time is the worst case a
    /// virtio console can actually produce; larger chunks put several frames in
    /// one delivery.
    #[test]
    fn a_run_of_frames_survives_any_chunking() {
        let requests = [
            Request::simple(Opcode::OpenSession, 0, Vec::new()),
            Request::simple(Opcode::InvokeCommand, 1, all_params()),
            Request::simple(Opcode::InvokeCommand, 2, Vec::new()),
            Request::simple(Opcode::CloseSession, 0, Vec::new()),
        ];
        let mut stream = Vec::new();
        for request in &requests {
            stream.extend_from_slice(&request.encode());
        }

        for chunk_size in 1..=stream.len() {
            let mut pending = Vec::new();
            let mut decoded = Vec::new();
            for chunk in stream.chunks(chunk_size) {
                pending.extend_from_slice(chunk);
                decoded.extend(drain(&mut pending).expect("every frame decodes"));
            }
            assert!(
                pending.is_empty(),
                "{} bytes left over at chunk size {chunk_size}",
                pending.len()
            );
            assert_eq!(decoded.len(), requests.len(), "at chunk size {chunk_size}");
            for (got, want) in decoded.iter().zip(requests.iter()) {
                assert_eq!(got.opcode, want.opcode, "at chunk size {chunk_size}");
                assert_eq!(got.cmd_id, want.cmd_id, "at chunk size {chunk_size}");
                assert_eq!(got.params, want.params, "at chunk size {chunk_size}");
            }
        }
    }

    /// An absurd declared length is still rejected from the prefix alone,
    /// rather than waited out. This is the property `bytes_needed` had and
    /// `complete_frame_len` must not lose.
    #[test]
    fn an_absurd_declared_length_is_rejected_before_the_frame_completes() {
        let mut encoded = Request::simple(Opcode::CloseSession, 0, Vec::new()).encode();
        encoded[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            complete_frame_len(&encoded),
            Err(Error::TooLong {
                declared: u32::MAX as usize
            })
        );
        // ... and a declared length shorter than the header it counts.
        encoded[..4].copy_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            complete_frame_len(&encoded),
            Err(Error::TooShort { declared: 3 })
        );
    }

    /// Fewer than four bytes is not an error, it is "not yet": the declared
    /// length is not even readable, so nothing can be judged about it.
    #[test]
    fn a_buffer_shorter_than_the_length_prefix_is_pending_not_broken() {
        for len in 0..4 {
            assert_eq!(complete_frame_len(&[0xFF_u8; 4][..len]), Ok(None));
        }
    }
}
