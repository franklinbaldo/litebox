// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Loading and running an OP-TEE trusted application.
//!
//! This is modelled on `litebox_runner_optee_on_linux_userland`, **not** on
//! `litebox_runner_lvbs`. The LVBS runner is reactive: VTL0 makes vtlcalls
//! into VTL1 and the runner services them. On a plain KVM guest there is no
//! VTL0, so the runner has to drive the shim itself.
//!
//! There are two ways to drive it, and which one runs depends on whether QEMU
//! was given a virtio device:
//!
//! - [`serve`], when there is one. Requests arrive over the virtio message
//!   channel and the runner services them, which is the point of the whole
//!   exercise: an external client decides what the TA does.
//! - [`run`], when there is not. The embedded open/close sequence, unchanged.
//!   `scripts/run.sh` and the CI boot test have no virtio device on their
//!   QEMU lines, and neither should have to.
//!
//! The sequence each performs is OP-TEE's own. `ldelf` is OP-TEE's user-mode
//! loader: it is entered first, in ring 3, and it is what actually maps the
//! TA. Only once it has returned does the TA's own entry point exist to be
//! called, which is why there are two distinct ring-3 entries below
//! (`run_thread_ref` for ldelf, then `reenter_thread_ref` per TA entry-point
//! invocation).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use litebox::platform::RawConstPointer as _;
use litebox::platform::common_providers::userspace_pointers::ValidateAccess as _;
use litebox::utils::TruncateExt as _;
use litebox_common_linux::PtRegs;
use litebox_common_optee::{
    TeeIdentity, TeeLogin, TeeParamType, TeeUuid, UteeEntryFunc, UteeParamOwned, UteeParams,
};
use litebox_platform_lvbs::{LvbsValidateAccess, reenter_thread_ref, run_thread_ref};
use litebox_shim_optee::session::session_manager;
use litebox_shim_optee::{LoadedProgram, OpteeShim, OpteeShimBuilder, UserConstPtr};

use crate::proto::{self, Opcode, Param, Request, Response};
use crate::virtio::{self, queue::Dma};

/// OP-TEE's user-mode loader, which runs before the TA and maps it.
static LDELF: &[u8] =
    include_bytes!("../../litebox_runner_optee_on_linux_userland/tests/ldelf.elf");

/// The TA itself. `hello-ta` is the simplest one in the tree, which is what we
/// want for the first ring-3 execution this platform has ever performed.
///
/// Still embedded rather than shipped over the wire. Moving binaries across
/// the channel is a later cut; nothing about the framing forbids it.
static TA: &[u8] =
    include_bytes!("../../litebox_runner_optee_on_linux_userland/tests/hello-ta.elf");

/// Loads and runs the TA, opening and then closing one session.
///
/// This is the path taken when there is no virtio device, and it is unchanged
/// from before the channel existed.
///
/// # Panics
///
/// Panics on any failure. There is no caller that could do anything better
/// with an error, and a KVM guest that cannot run its TA has nothing else to
/// do; panicking routes through the runner's panic handler, which ends QEMU
/// with the failure status.
pub fn run() {
    let shim = build_shim();

    let session_token = session_manager()
        .try_acquire_open_session_token()
        .expect("no open-session token available");
    let session_id = session_token
        .session_id()
        .expect("open-session token carries no session id");
    log::info!("ta         session id {session_id}");

    let ta_uuid = ta_uuid();
    let loaded_program = shim
        .load_ldelf(LDELF, ta_uuid, Some(TA))
        .unwrap_or_else(|e| panic!("failed to load ldelf: {e:?}"));
    let entrypoints = loaded_program
        .entrypoints
        .as_ref()
        .expect("load_ldelf returned no entrypoints");
    log::info!(
        "ta         ldelf loaded, params at {:?}",
        loaded_program.params_address
    );

    // First ring-3 entry on this platform. ldelf runs and maps the TA.
    log::info!("ta         entering ldelf in ring 3...");
    // SAFETY: the context is the initial one `load_ldelf` installed in the
    // task, which is what `run_thread_ref` expects; `PtRegs::default()` is the
    // scratch buffer the platform fills in, exactly as the userland runner
    // passes it.
    unsafe {
        run_thread_ref(entrypoints, &mut PtRegs::default());
    }
    log::info!("ta         ldelf returned");

    // ldelf has now created the first USER-accessible mappings this kernel has
    // ever had, so SMAP enforcement is finally testable. See `check_smap`.
    check_smap();

    for (name, func_id) in [
        ("OpenSession", UteeEntryFunc::OpenSession),
        ("CloseSession", UteeEntryFunc::CloseSession),
    ] {
        // An OP-TEE TA entry point is (re)started with a fresh stack each
        // time; the parameters live at a fixed address in that stack, which
        // `load_ta_context` rewrites per call.
        let params = [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS];
        entrypoints
            .load_ta_context(params.as_slice(), session_id, func_id as u32, None)
            .unwrap_or_else(|e| panic!("failed to load TA context for {name}: {e:?}"));
        log::info!("ta         entering TA {name} in ring 3...");
        // SAFETY: `load_ta_context` just installed the initial state for this
        // entry point; `reenter_thread_ref` is the paired call for a task that
        // has already run once (ldelf).
        unsafe {
            reenter_thread_ref(entrypoints, &mut PtRegs::default());
        }
        log::info!("ta         TA {name} returned");
    }

    log::info!("ta         open/close session completed");
}

/// Builds the OP-TEE shim.
fn build_shim() -> OpteeShim {
    let shim_builder = OpteeShimBuilder::new();
    // Held only for the side effect of constructing the `LiteBox`; `build`
    // takes ownership of it. Mirrors the userland runner.
    let _litebox = shim_builder.litebox();
    let shim = shim_builder.build();
    log::info!("ta         shim built");
    shim
}

/// The UUID in the TA's own `.ta_head` section.
///
/// `load_ldelf` rejects the binary with `InvalidUuid` if the UUID it is given
/// disagrees. Reading it out of the binary rather than hard-coding it means
/// swapping `hello-ta` for another TA needs no edit here, and means the value
/// cannot silently drift from the artifact. (The userland runner's default
/// path passes `TeeUuid::default()`; that evidently only ever ran against a
/// nil-UUID TA.)
///
/// # Panics
///
/// Panics if the embedded TA has no parseable `.ta_head`, which is a fact
/// about the build, not about anything a client did.
fn ta_uuid() -> TeeUuid {
    let ta_uuid = litebox_common_optee::parse_ta_head(TA)
        .expect("hello-ta.elf has no parseable .ta_head section")
        .uuid;
    let node = ta_uuid.clock_seq_and_node;
    log::info!(
        "ta         uuid {:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        ta_uuid.time_low,
        ta_uuid.time_mid,
        ta_uuid.time_hi_and_version,
        node[0],
        node[1],
        node[2],
        node[3],
        node[4],
        node[5],
        node[6],
        node[7],
    );
    ta_uuid
}

// ---------------------------------------------------------------------------
// The request loop.
// ---------------------------------------------------------------------------

/// How long [`serve`] waits for a request before giving up, in nanoseconds.
///
/// Two minutes.
///
/// Blocking forever would be defensible for a server, and it is what a real
/// one would do. It is the wrong choice here. This guest runs under CI, where
/// the only thing that could end an indefinite wait is the harness's own
/// `timeout`, which reports status 124 -- indistinguishable from a triple
/// fault, a hang in the queue code, or a genuinely absent client, and costing
/// the full timeout every time. A deadline the *guest* owns turns "no client
/// ever spoke to me" into a specific, immediate, non-zero failure with a log
/// line naming the cause.
///
/// Two minutes rather than something tight because the wait spans the client's
/// whole think time, including its own connect retry, and under TCG the guest
/// is the slow part of the system. It is far longer than any legitimate gap
/// and far shorter than a CI job's patience.
const REQUEST_TIMEOUT_NANOS: u64 = 120 * 1_000_000_000;

/// Size of the channel's receive and transmit buffers.
///
/// One page. Frames larger than this are still handled -- [`Channel::recv`]
/// reassembles a frame from as many buffer-fuls as it takes -- so this is a
/// throughput choice, not a limit. The limit is [`proto::MAX_FRAME_LEN`].
const CHANNEL_BUF_SIZE: usize = 4096;

/// A framed message channel over the virtio console's byte stream.
///
/// The console does not preserve message boundaries: a 40-byte frame may
/// arrive as 40 one-byte completions, and two frames may arrive in one. So
/// received bytes are accumulated and [`proto::bytes_needed`] is asked, after
/// every completion, whether a whole frame is present yet.
struct Channel {
    console: virtio::Console,
    rx: Dma,
    tx: Dma,
    /// Bytes received but not yet consumed by a decoded frame.
    pending: Vec<u8>,
}

/// Why the channel could not carry a message.
///
/// Distinct from [`proto::Error`]: a decode failure is the client's fault and
/// is answered with an error response, whereas these end the loop.
enum ChannelError {
    /// No request arrived within [`REQUEST_TIMEOUT_NANOS`].
    Timeout,
    /// The device never returned a transmitted descriptor.
    TransmitStalled,
    /// The peer's frame was malformed. Reported to the peer where it can be,
    /// and always logged.
    Protocol(proto::Error),
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Timeout => write!(
                f,
                "no request arrived within {} seconds",
                REQUEST_TIMEOUT_NANOS / 1_000_000_000
            ),
            Self::TransmitStalled => f.write_str("the device never completed a transmit"),
            Self::Protocol(error) => write!(f, "malformed frame: {error}"),
        }
    }
}

impl Channel {
    fn new(console: virtio::Console) -> Self {
        Self {
            console,
            rx: Dma::alloc(CHANNEL_BUF_SIZE as u64),
            tx: Dma::alloc(CHANNEL_BUF_SIZE as u64),
            pending: Vec::new(),
        }
    }

    /// Reads bytes until a whole frame is present, and decodes it.
    fn recv(&mut self) -> Result<Request, ChannelError> {
        loop {
            // Ask the codec whether what we already hold is a frame. This is
            // asked *before* reading, because a previous completion may have
            // delivered two frames at once and the second is already here.
            match proto::bytes_needed(&self.pending) {
                Ok(None) => {
                    let frame = core::mem::take(&mut self.pending);
                    return Request::decode(&frame).map_err(ChannelError::Protocol);
                }
                // A declared length that is absurd is knowable from the
                // four-byte prefix, so it is rejected now rather than waited
                // out. This is the difference between a clean error and a
                // hang on a frame that will never complete.
                Err(error) => return Err(ChannelError::Protocol(error)),
                Ok(Some(_)) => {}
            }

            let capacity = u32::try_from(CHANNEL_BUF_SIZE).expect("small buffer");
            let Some(len) =
                self.console
                    .receive_deadline(&mut self.rx, capacity, REQUEST_TIMEOUT_NANOS)
            else {
                return Err(ChannelError::Timeout);
            };
            let len = (len as usize).min(CHANNEL_BUF_SIZE);
            let mut bytes = [0_u8; CHANNEL_BUF_SIZE];
            self.rx.read_into(&mut bytes, len);
            // The accumulated buffer is bounded by the same maximum the codec
            // enforces, so a peer that streams megabytes without ever
            // completing a frame cannot exhaust the heap. In practice
            // `bytes_needed` rejects the oversized length first; this is the
            // belt to that's braces.
            if self.pending.len() + len > proto::MAX_FRAME_LEN {
                return Err(ChannelError::Protocol(proto::Error::TooLong {
                    declared: self.pending.len() + len,
                }));
            }
            self.pending.extend_from_slice(&bytes[..len]);
        }
    }

    /// Sends a response, in as many buffer-fuls as it takes.
    fn send(&mut self, response: &Response) -> Result<(), ChannelError> {
        let frame = response.encode();
        for chunk in frame.chunks(CHANNEL_BUF_SIZE) {
            self.tx.fill(chunk, CHANNEL_BUF_SIZE);
            let len = u32::try_from(chunk.len()).expect("chunk is at most one page");
            if !self.console.send_blocking(&self.tx, len) {
                return Err(ChannelError::TransmitStalled);
            }
        }
        Ok(())
    }
}

/// The TA state a session owns between an `OpenSession` and its
/// `CloseSession`.
struct Session {
    id: u32,
    loaded: LoadedProgram,
}

/// Services requests from the virtio message channel until the client asks to
/// shut down.
///
/// Returns normally on [`Opcode::Shutdown`], so the caller finishes the boot
/// the same way the no-device path does -- through `check_nx_is_enforced`,
/// which is what makes a successful run's ending identical either way.
///
/// # Panics
///
/// Panics if the channel itself fails: a timeout waiting for a request, a
/// transmit the device never completes, or a frame this end cannot even parse
/// a length out of. None of those can be answered over the channel that just
/// broke, and a guest that quietly continued would be reported by CI as a
/// timeout rather than as the specific failure it is.
pub fn serve(console: virtio::Console) {
    // The wire format's parameter bound and OP-TEE's must agree, or a
    // four-parameter request would be accepted and then silently truncated.
    // `proto` names its own constant so that it stays dependency-free; this is
    // where the two are tied together.
    const _: () = assert!(proto::MAX_PARAMS == UteeParams::TEE_NUM_PARAMS);

    let shim = build_shim();
    let mut channel = Channel::new(console);
    let mut session: Option<Session> = None;
    let mut ldelf_has_run = false;

    log::info!("channel    serving requests");
    loop {
        let request = match channel.recv() {
            Ok(request) => request,
            Err(ChannelError::Protocol(error)) => {
                // Answerable: the framing was legible enough to know the peer
                // is still there. Tell it what was wrong and carry on.
                log::warn!("channel    rejecting a frame: {error}");
                let response = Response::error(format!("malformed frame: {error}"));
                if let Err(fatal) = channel.send(&response) {
                    panic!("channel: {fatal}");
                }
                // The stream is out of sync after a bad frame -- there is no
                // resynchronisation point in a length-prefixed format -- so
                // the pending bytes are dropped rather than reparsed forever.
                channel.pending.clear();
                continue;
            }
            Err(fatal) => panic!("channel: {fatal}"),
        };

        log::info!(
            "channel    request {:?} cmd_id {} with {} parameter(s)",
            request.opcode,
            request.cmd_id,
            request.params.len()
        );

        if request.opcode == Opcode::Shutdown {
            log::info!("channel    shutdown requested");
            let response = Response::ok(0, Vec::new());
            if let Err(fatal) = channel.send(&response) {
                panic!("channel: {fatal}");
            }
            return;
        }

        let response = service(&shim, &request, &mut session, &mut ldelf_has_run);
        match response.status {
            proto::STATUS_OK => log::info!(
                "channel    response ok, TA returned {:#010X}, {} parameter(s)",
                response.ta_return,
                response.params.len()
            ),
            _ => log::warn!("channel    response error: {}", response.message),
        }
        if let Err(fatal) = channel.send(&response) {
            panic!("channel: {fatal}");
        }
    }
}

/// Performs one request against the shim.
///
/// Every failure here is a [`Response`], never a panic: a client that asks for
/// something impossible must get an answer saying so, not a dead guest. The
/// panics that remain are about the build (`ta_uuid`) or about the channel,
/// not about the request.
fn service(
    shim: &OpteeShim,
    request: &Request,
    session: &mut Option<Session>,
    ldelf_has_run: &mut bool,
) -> Response {
    let params = match to_utee_params(&request.params) {
        Ok(params) => params,
        Err(message) => return Response::error(message),
    };

    match request.opcode {
        Opcode::OpenSession => {
            if session.is_some() {
                return Response::error(String::from(
                    "a session is already open; close it before opening another",
                ));
            }
            match open_session(shim, &params, ldelf_has_run) {
                Ok((new_session, response)) => {
                    *session = Some(new_session);
                    response
                }
                Err(message) => Response::error(message),
            }
        }
        Opcode::InvokeCommand | Opcode::CloseSession => {
            let Some(open) = session.as_ref() else {
                return Response::error(String::from("no session is open"));
            };
            let (func_id, cmd_id) = if request.opcode == Opcode::InvokeCommand {
                (UteeEntryFunc::InvokeCommand, Some(request.cmd_id))
            } else {
                (UteeEntryFunc::CloseSession, None)
            };
            let result = enter_ta(&open.loaded, open.id, func_id, cmd_id, &params);
            // The session is over whether or not the TA liked being closed.
            if request.opcode == Opcode::CloseSession {
                *session = None;
            }
            match result {
                Ok(response) => response,
                Err(message) => Response::error(message),
            }
        }
        // `serve` handles Shutdown and LoadBinary before they get here, and
        // `Request::decode` refuses to produce a Response opcode at all.
        Opcode::Shutdown | Opcode::LoadBinary | Opcode::Response => {
            Response::error(format!("opcode {:?} is not a request", request.opcode))
        }
    }
}

/// Acquires a session, loads ldelf and the TA, and enters the TA's
/// `OpenSession` entry point.
fn open_session(
    shim: &OpteeShim,
    params: &[UteeParamOwned],
    ldelf_has_run: &mut bool,
) -> Result<(Session, Response), String> {
    let mut token = session_manager()
        .try_acquire_open_session_token()
        .map_err(|e| format!("no open-session token available: {e:?}"))?;
    let session_id = token
        .session_id()
        .ok_or_else(|| String::from("open-session token carries no session id"))?;

    // The client identity a real REE client would present. `hello-ta` does not
    // inspect it; a TA that did would see the same default the userland
    // runner's JSON path uses when the file names none.
    session_manager().set_session_client_identity(
        session_id,
        Some(TeeIdentity {
            login: TeeLogin::User,
            uuid: TeeUuid::NIL,
        }),
    );

    let loaded = shim
        .load_ldelf(LDELF, ta_uuid(), Some(TA))
        .map_err(|e| format!("failed to load ldelf: {e:?}"))?;
    let entrypoints = loaded
        .entrypoints
        .as_ref()
        .ok_or_else(|| String::from("load_ldelf returned no entrypoints"))?;
    log::info!(
        "ta         session {session_id}, ldelf loaded, params at {:?}",
        loaded.params_address
    );

    log::info!("ta         entering ldelf in ring 3...");
    let mut ctx = PtRegs::default();
    // SAFETY: the context is the initial one `load_ldelf` installed in the
    // task, which is what `run_thread_ref` expects.
    unsafe {
        run_thread_ref(entrypoints, &mut ctx);
    }
    if ctx.rax != 0 {
        return Err(format!("ldelf exited with {:#x}", ctx.rax));
    }
    log::info!("ta         ldelf returned");

    // ldelf has now created the first USER-accessible mappings this kernel has
    // ever had, so SMAP enforcement is finally testable -- once. Repeating it
    // per session would say nothing new and would cost a fault each time.
    if !*ldelf_has_run {
        *ldelf_has_run = true;
        check_smap();
    }

    // The session outlives this call, so disarm the token: its drop must not
    // recycle the id or clear the client identity.
    token.disarm();

    let response = enter_ta(
        &loaded,
        session_id,
        UteeEntryFunc::OpenSession,
        None,
        params,
    )?;
    Ok((
        Session {
            id: session_id,
            loaded,
        },
        response,
    ))
}

/// The name of an entry point, for logging. `UteeEntryFunc` has no `Debug`.
fn entry_name(func_id: UteeEntryFunc) -> &'static str {
    match func_id {
        UteeEntryFunc::OpenSession => "OpenSession",
        UteeEntryFunc::CloseSession => "CloseSession",
        UteeEntryFunc::InvokeCommand => "InvokeCommand",
        UteeEntryFunc::Unknown => "unknown",
    }
}

/// Loads a TA context and enters the named entry point in ring 3, then reads
/// back what the TA left in its `UteeParams`.
fn enter_ta(
    loaded: &LoadedProgram,
    session_id: u32,
    func_id: UteeEntryFunc,
    cmd_id: Option<u32>,
    params: &[UteeParamOwned],
) -> Result<Response, String> {
    let entrypoints = loaded
        .entrypoints
        .as_ref()
        .ok_or_else(|| String::from("the loaded program has no entrypoints"))?;

    // An OP-TEE TA entry point is (re)started with a fresh stack each time;
    // the parameters live at a fixed address in that stack, which
    // `load_ta_context` rewrites per call.
    entrypoints
        .load_ta_context(params, session_id, func_id as u32, cmd_id)
        .map_err(|e| format!("failed to load TA context: {e:?}"))?;

    let name = entry_name(func_id);
    log::info!("ta         entering TA {name} in ring 3...");
    let mut ctx = PtRegs::default();
    // SAFETY: `load_ta_context` just installed the initial state for this
    // entry point; `reenter_thread_ref` is the paired call for a task that has
    // already run once (ldelf).
    unsafe {
        reenter_thread_ref(entrypoints, &mut ctx);
    }
    let ta_return: u32 = ctx.rax.trunc();
    log::info!("ta         TA {name} returned {ta_return:#010X}");

    // The TA stores its results in the `UteeParams` structure and in the
    // buffers it refers to, both of which live in *user* memory.
    let out = match loaded.params_address {
        Some(address) => read_ta_params(address)?,
        None => Vec::new(),
    };
    Ok(Response::ok(ta_return, out))
}

/// Reads the TA's `UteeParams` back out of user memory.
///
/// The parameter *types* are taken from what the TA left behind rather than
/// from what the request asked for, mirroring `handle_ta_command_output` in
/// the userland runner: it is the TA that decides what it wrote.
fn read_ta_params(params_address: usize) -> Result<Vec<Param>, String> {
    let params = UserConstPtr::<UteeParams>::from_usize(params_address)
        .read_at_offset(0)
        .ok_or_else(|| format!("could not read UteeParams at {params_address:#x}"))?;

    let mut out = Vec::with_capacity(UteeParams::TEE_NUM_PARAMS);
    for index in 0..UteeParams::TEE_NUM_PARAMS {
        let param_type = params
            .get_type(index)
            .map_err(|e| format!("parameter {index} has an unknown type: {e:?}"))?;
        let values = params.get_values(index).ok().flatten();
        let Some((value_a, value_b)) = values else {
            out.push(Param::None);
            continue;
        };
        out.push(match param_type {
            TeeParamType::None => Param::None,
            TeeParamType::ValueInput => Param::ValueInput { value_a, value_b },
            TeeParamType::ValueOutput => Param::ValueOutput { value_a, value_b },
            TeeParamType::ValueInout => Param::ValueInout { value_a, value_b },
            // For a memref the two values are the user address and the length
            // the TA left there, so the bytes have to be copied out of user
            // memory before the answer can carry them.
            TeeParamType::MemrefInput => Param::MemrefInput {
                data: read_user_bytes(value_a, value_b),
            },
            TeeParamType::MemrefOutput => Param::MemrefOutput {
                buffer_size: value_b,
                data: read_user_bytes(value_a, value_b),
            },
            TeeParamType::MemrefInout => Param::MemrefInout {
                buffer_size: value_b,
                data: read_user_bytes(value_a, value_b),
            },
        });
    }
    Ok(out)
}

/// Copies `len` bytes out of the TA's address space.
///
/// A read that fails yields no bytes rather than an error: the parameter is
/// still worth reporting, and a memref the TA left pointing nowhere is its
/// business, not a reason to fail the whole request. `to_owned_slice`
/// validates the range and brackets the copy in `stac`/`clac`, so a bad
/// address is `None` rather than a fault.
///
/// The length is clamped to the frame budget for the same reason every other
/// length in this path is bounded: `value_b` comes from a TA, and a TA that
/// left `u64::MAX` there must not become an allocation.
fn read_user_bytes(addr: u64, len: u64) -> Box<[u8]> {
    let len = usize::try_from(len)
        .unwrap_or(usize::MAX)
        .min(proto::MAX_FRAME_LEN);
    if len == 0 {
        return Box::from(&[][..]);
    }
    UserConstPtr::<u8>::from_usize(addr.trunc())
        .to_owned_slice(len)
        .unwrap_or_else(|| Box::from(&[][..]))
}

/// Converts the wire's parameters into the shim's, padding to
/// `TEE_NUM_PARAMS`.
///
/// `UteeParamOwned` owns its bytes, which is why memrefs need no machinery
/// here at all: a `MemrefInput` is the decoded byte string moved into the
/// variant, and there is no shared memory anywhere in the picture. That
/// ownership is the whole reason this protocol carries `UteeParamOwned` rather
/// than `OpteeMsgArgs`; see the plan.
fn to_utee_params(params: &[Param]) -> Result<Vec<UteeParamOwned>, String> {
    if params.len() > UteeParamOwned::TEE_NUM_PARAMS {
        return Err(format!(
            "{} parameters, at most {} are allowed",
            params.len(),
            UteeParamOwned::TEE_NUM_PARAMS
        ));
    }
    let mut out = Vec::with_capacity(UteeParamOwned::TEE_NUM_PARAMS);
    for param in params {
        out.push(match param {
            Param::None => UteeParamOwned::None,
            Param::ValueInput { value_a, value_b } => UteeParamOwned::ValueInput {
                value_a: *value_a,
                value_b: *value_b,
            },
            Param::ValueOutput { .. } => UteeParamOwned::ValueOutput,
            Param::ValueInout { value_a, value_b } => UteeParamOwned::ValueInout {
                value_a: *value_a,
                value_b: *value_b,
            },
            Param::MemrefInput { data } => UteeParamOwned::MemrefInput { data: data.clone() },
            Param::MemrefOutput { buffer_size, .. } => UteeParamOwned::MemrefOutput {
                buffer_size: usize::try_from(*buffer_size)
                    .map_err(|_| "memref buffer_size does not fit in a usize".to_string())?,
            },
            Param::MemrefInout { buffer_size, data } => {
                let buffer_size = usize::try_from(*buffer_size)
                    .map_err(|_| "memref buffer_size does not fit in a usize".to_string())?;
                if buffer_size < data.len() {
                    return Err(format!(
                        "memref buffer_size {buffer_size} is smaller than its {} bytes of data",
                        data.len()
                    ));
                }
                UteeParamOwned::MemrefInout {
                    data: data.clone(),
                    buffer_size,
                }
            }
        });
    }
    out.resize(UteeParamOwned::TEE_NUM_PARAMS, UteeParamOwned::None);
    Ok(out)
}

/// Confirms that SMAP is actually enforced, which `check_cpu_state` could not.
///
/// `enable_smep_smap` sets CR4.SMAP during bring-up, but at that point there
/// was nothing to test it against: every page in
/// existence had the USER bit clear, and inventing a user mapping for the test
/// would only have proved that the test's own mapping worked. ldelf has now
/// created real ones, so this is the first honest opportunity.
///
/// Three things are checked, in increasing strength:
///
/// 1. that a TA page really does have the USER bit set (a page-table walk, so
///    this is a fact about the hardware structures, not about an intention);
/// 2. that a supervisor read of it *faults* with SMAP on -- this is the
///    enforcement claim;
/// 3. that the same read *succeeds* between `stac` and `clac` -- without this
///    the fault in (2) could just as well have been an unmapped page.
fn check_smap() {
    let Some(user_va) = crate::first_user_page() else {
        log::error!("smap       no USER-accessible page found after ldelf ran; check skipped");
        return;
    };

    let t = crate::walk(user_va).expect("the user page vanished between walks");
    log::info!("smap       user page va {user_va:#018X} -> {t}");

    // 2. A supervisor read with SMAP on. Recovered through the exception
    //    table, so a failure to fault is reported rather than hanging.
    let probe = user_va as *const u64;
    // SAFETY: the read is expected to fault; `read_u64_fallible` registers it
    // in `.ex_table` so the fault is recovered rather than propagating.
    let with_smap = unsafe { litebox::mm::exception_table::read_u64_fallible(probe) };
    assert!(
        with_smap.is_err(),
        "a supervisor read of user page {user_va:#018X} succeeded with CR4.SMAP set: \
         SMAP is not enforced"
    );
    log::info!("smap       supervisor read faulted as expected (SMAP enforced)");

    // 3. The same read inside `with_user_memory_access`, which brackets it
    //    with `stac`/`clac`.
    let with_ac = LvbsValidateAccess::with_user_memory_access(|| {
        // SAFETY: as above, and inside `stac`/`clac` it is expected to
        // succeed; the fallible form is kept so a surprise fault is reported
        // rather than fatal.
        unsafe { litebox::mm::exception_table::read_u64_fallible(probe) }
    });
    let Ok(v) = with_ac else {
        panic!(
            "a supervisor read of user page {user_va:#018X} faulted even inside \
             stac/clac: the fault in step 2 was not SMAP"
        )
    };
    log::info!("smap       read inside stac/clac succeeded, value {v:#018X}");
}
