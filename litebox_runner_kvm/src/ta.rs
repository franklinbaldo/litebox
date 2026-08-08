// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Loading and running an OP-TEE trusted application.
//!
//! This is modelled on `litebox_runner_optee_on_linux_userland`'s
//! `run_ta_with_default_commands`, **not** on `litebox_runner_lvbs`. The LVBS
//! runner is reactive: VTL0 makes vtlcalls into VTL1 and the runner services
//! them. On a plain KVM guest there is no VTL0, nobody will ever call in, and
//! so the runner has to drive the shim itself.
//!
//! The sequence is OP-TEE's own. `ldelf` is OP-TEE's user-mode loader: it is
//! entered first, in ring 3, and it is what actually maps the TA. Only once it
//! has returned does the TA's own entry point exist to be called, which is why
//! there are two distinct ring-3 entries below (`run_thread_ref` for ldelf,
//! then `reenter_thread_ref` per TA entry-point invocation).

use litebox::platform::common_providers::userspace_pointers::ValidateAccess as _;
use litebox_common_linux::PtRegs;
use litebox_common_optee::{UteeEntryFunc, UteeParamOwned};
use litebox_platform_lvbs::{LvbsValidateAccess, reenter_thread_ref, run_thread_ref};
use litebox_shim_optee::{OpteeShimBuilder, session::session_manager};

/// OP-TEE's user-mode loader, which runs before the TA and maps it.
static LDELF: &[u8] =
    include_bytes!("../../litebox_runner_optee_on_linux_userland/tests/ldelf.elf");

/// The TA itself. `hello-ta` is the simplest one in the tree, which is what we
/// want for the first ring-3 execution this platform has ever performed.
static TA: &[u8] =
    include_bytes!("../../litebox_runner_optee_on_linux_userland/tests/hello-ta.elf");

/// Loads and runs the TA, opening and then closing one session.
///
/// # Panics
///
/// Panics on any failure. There is no caller that could do anything better
/// with an error, and a KVM guest that cannot run its TA has nothing else to
/// do; panicking routes through the runner's panic handler, which ends QEMU
/// with the failure status.
pub fn run() {
    let shim_builder = OpteeShimBuilder::new();
    // Held only for the side effect of constructing the `LiteBox`; `build`
    // takes ownership of it. Mirrors the userland runner.
    let _litebox = shim_builder.litebox();
    let shim = shim_builder.build();
    log::info!("ta         shim built");

    let session_token = session_manager()
        .try_acquire_open_session_token()
        .expect("no open-session token available");
    let session_id = session_token
        .session_id()
        .expect("open-session token carries no session id");
    log::info!("ta         session id {session_id}");

    // The UUID must be the one in the TA's own `.ta_head` section:
    // `load_ldelf` rejects the binary with `InvalidUuid` if it disagrees.
    // Reading it out of the binary rather than hard-coding it means swapping
    // `hello-ta` for another TA needs no edit here, and means the value cannot
    // silently drift from the artifact. (The userland runner passes
    // `TeeUuid::default()`; that path evidently only ever ran against a
    // nil-UUID TA.)
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

/// Confirms that SMAP is actually enforced, which Task 7 could not.
///
/// Task 7 set CR4.SMAP but had nothing to test it against: every page in
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
