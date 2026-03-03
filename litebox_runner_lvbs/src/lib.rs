// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use core::{ops::Neg, panic::PanicInfo};
use litebox::{
    mm::linux::PAGE_SIZE,
    platform::GuestExecutionProvider,
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::errno::Errno;
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArgs, OpteeRpcArgs, OpteeSmcArgs, OpteeSmcResult,
    OpteeSmcReturnCode, TeeOrigin, TeeResult, UteeEntryFunc, UteeParams, optee_msg_args_total_size,
};
use litebox_platform_lvbs::{
    arch::{gdt, get_core_id, instrs::hlt_loop, interrupts},
    debug_serial_println,
    host::{bootparam::get_vtl1_memory_info, per_cpu_variables::allocate_per_cpu_variables},
    mm::MemoryProvider,
    mshv::{
        NUM_VTLCALL_PARAMS, VsmFunction, hvcall,
        vsm::vsm_dispatch,
        vsm_intercept::raise_vtl0_gp_fault,
        vtl_switch::{vtl_switch, vtl_switch_init},
        vtl1_mem_layout::{
            VSM_SK_PTE_PAGES_COUNT, VTL1_INIT_HEAP_SIZE, VTL1_INIT_HEAP_START_PAGE,
            VTL1_PML4E_PAGE, VTL1_PRE_POPULATED_MEMORY_SIZE, VTL1_PTE_0_PAGE, VTL1_REMAP_PDE_PAGE,
            VTL1_REMAP_PDPT_PAGE, get_heap_start_address, get_rela_end_address,
            get_rela_start_address, get_text_end_address, get_text_start_address,
        },
    },
    serial_println,
};
use litebox_platform_multiplex::Platform;
use litebox_shim_optee::msg_handler::{
    decode_ta_request, handle_optee_msg_args, handle_optee_smc_args, update_optee_msg_args,
};
use litebox_shim_optee::session::{
    MAX_TA_INSTANCES, SessionIdGuard, SessionManager, TaInstance, allocate_session_id,
};
use litebox_shim_optee::{NormalWorldConstPtr, NormalWorldMutPtr};
use once_cell::race::OnceBox;
use spin::mutex::SpinMutex;

/// # Panics
///
/// Panics if it failed to enable Hyper-V hypercall
pub fn init() -> Option<&'static Platform> {
    let mut ret: Option<&'static Platform> = None;

    if get_core_id() == 0 {
        if let Ok((start, size)) = get_vtl1_memory_info() {
            let vtl1_start = x86_64::PhysAddr::new(start);
            let vtl1_end = x86_64::PhysAddr::new(start + size);

            // Add a small range of mapped memory to the global allocator for populating the base page table.
            // `VTL1_INIT_HEAP_START_PAGE` and `VTL1_INIT_HEP_SIZE` specify a physical address range which is
            // not used by the VTL1 kernel.
            let mem_fill_start =
                TruncateExt::<usize>::truncate(Platform::pa_to_va(vtl1_start).as_u64())
                    + VTL1_INIT_HEAP_START_PAGE * PAGE_SIZE;
            let mem_fill_size = VTL1_INIT_HEAP_SIZE;
            unsafe {
                Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
            }
            debug_serial_println!(
                "heap: seed init region (pages {}..+{:#x}): VA {:#x}, size {:#x}",
                VTL1_INIT_HEAP_START_PAGE,
                mem_fill_size,
                mem_fill_start,
                mem_fill_size
            );

            // Add remaining mapped but non-used memory pages (between `get_heap_start_address()` and
            // the end of the Phase 1 high-canonical mapping) to the global allocator.
            //
            // Phase 1 maps `VTL1_REMAP_PTE_COUNT * 2 MiB` = 16 MiB of high-canonical
            // memory, which equals the full pre-populated region. We must NOT hand
            // out addresses beyond that boundary because they are unmapped until
            // `Platform::new()` builds the base page table covering all 128 MiB.
            // The full VTL1 range is added after `Platform::new()` completes.
            //
            // After two-phase relocation, `get_heap_start_address()` returns a
            // high-canonical VA. Use it directly for the allocator.
            let heap_va = get_heap_start_address();
            let mem_fill_start: usize = heap_va.truncate();
            let heap_phys = Platform::va_to_pa(x86_64::VirtAddr::new(heap_va)).as_u64();
            let heap_offset: usize = TruncateExt::<usize>::truncate(heap_phys - start);
            let mem_fill_size = VTL1_PRE_POPULATED_MEMORY_SIZE - heap_offset;
            unsafe {
                Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
            }
            debug_serial_println!(
                "heap: add pre-populated region (_heap_start..Phase 1 end): VA {:#x}, size {:#x}",
                mem_fill_start,
                mem_fill_size
            );

            // Text section boundaries. These are used by the platform to mark
            // code pages executable and everything else NO_EXECUTE (DEP).
            // After two-phase relocation, linker symbols return
            // high-canonical VAs; convert to PA for the page table mapper.
            let text_phys_start =
                Platform::va_to_pa(x86_64::VirtAddr::new(get_text_start_address()));
            let text_phys_end = Platform::va_to_pa(x86_64::VirtAddr::new(get_text_end_address()));

            // Reclaim .rela.dyn section memory now that relocations have been applied
            // and we're running at high-canonical addresses.
            // After two-phase relocation, `get_rela_start/end_address()` return
            // high-canonical VAs. Use directly for the allocator.
            let rela_va = get_rela_start_address();
            let rela_size: usize = (get_rela_end_address() - rela_va).truncate();
            if rela_size > 0 {
                let rela_virt: usize = rela_va.truncate();
                unsafe {
                    Platform::mem_fill_pages(rela_virt, rela_size);
                }
                debug_serial_println!(
                    "heap: reclaim .rela.dyn section: VA {:#x}, size {:#x}",
                    rela_virt,
                    rela_size
                );
            }

            let platform = Platform::new(vtl1_start, vtl1_end, text_phys_start, text_phys_end);
            ret = Some(platform);
            litebox_platform_multiplex::set_platform(platform);

            // Reclaim Phase 1 / VTL0 page table frames now that Platform::new()
            // has loaded a fresh base page table covering all VTL1 memory.
            // These physical pages are no longer referenced by CR3.
            {
                // Reclaim pages 2–12 (PML4, PDPT, PDE, 8 PTE pages)
                let early_pt_pa = vtl1_start + (VTL1_PML4E_PAGE * PAGE_SIZE) as u64;
                let early_pt_start: usize =
                    TruncateExt::<usize>::truncate(Platform::pa_to_va(early_pt_pa).as_u64());
                let early_pt_size: usize =
                    (VTL1_PTE_0_PAGE + VSM_SK_PTE_PAGES_COUNT - VTL1_PML4E_PAGE) * PAGE_SIZE;
                // Safety: the early page table frames are no longer referenced
                // (CR3 now points to the Phase 2 base page table).
                unsafe {
                    Platform::mem_fill_pages(early_pt_start, early_pt_size);
                }
                debug_serial_println!(
                    "heap: reclaim early page table frames (pages {}..{}): VA {:#x}, size {:#x}",
                    VTL1_PML4E_PAGE,
                    VTL1_PML4E_PAGE + (early_pt_size / PAGE_SIZE),
                    early_pt_start,
                    early_pt_size
                );

                // Reclaim Phase 1 PDPT and PDE pages
                let remap_pt_pa = vtl1_start + (VTL1_REMAP_PDPT_PAGE * PAGE_SIZE) as u64;
                let remap_pt_start: usize =
                    TruncateExt::<usize>::truncate(Platform::pa_to_va(remap_pt_pa).as_u64());
                let remap_pt_size: usize =
                    (VTL1_REMAP_PDE_PAGE - VTL1_REMAP_PDPT_PAGE + 1) * PAGE_SIZE;
                unsafe {
                    Platform::mem_fill_pages(remap_pt_start, remap_pt_size);
                }
                debug_serial_println!(
                    "heap: reclaim Phase 1 remap PT frames (pages {}..{}): VA {:#x}, size {:#x}",
                    VTL1_REMAP_PDPT_PAGE,
                    VTL1_REMAP_PDE_PAGE + 1,
                    remap_pt_start,
                    remap_pt_size
                );
            }

            // Add the rest of the VTL1 memory to the global allocator once they are mapped to the base page table.
            let mem_fill_start = mem_fill_start + mem_fill_size;
            let mem_fill_size = TruncateExt::<usize>::truncate(
                size - (mem_fill_start as u64 - Platform::pa_to_va(vtl1_start).as_u64()),
            );
            unsafe {
                Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
            }
            debug_serial_println!(
                "heap: add remaining VTL1 memory (post Phase 2): VA {:#x}, size {:#x}",
                mem_fill_start,
                mem_fill_size
            );

            allocate_per_cpu_variables();
        } else {
            panic!("Failed to get memory info");
        }
    }

    if let Err(e) = hvcall::init() {
        panic!("Err: {:?}", e);
    }
    gdt::init();
    interrupts::init_idt();
    x86_64::instructions::interrupts::enable();
    Platform::enable_syscall_support();

    ret
}

pub fn run(platform: Option<&'static Platform>) -> ! {
    vtl_switch_init(platform);

    let mut return_value: Option<i64> = None;
    loop {
        let params = vtl_switch(return_value);
        return_value = Some(vtlcall_dispatch(&params));
    }
}

/// Dispatch VTL call based on the function ID in params[0] and return the result.
///
/// VTL call is with up to four u64 parameters and returns an i64 result.
/// The first parameter (params[0]) is the VSM function ID to identify the requested service.
/// The remaining parameters (params[1] to params[3]) are function-specific arguments.
///
/// TODO: Consider unified interface signature and naming
/// VTL call is Hyper-V specific. However, in general, there is no fundamental difference
/// between VTL call and TrustZone SMC call, TDX TDCALL, etc.
fn vtlcall_dispatch(params: &[u64; NUM_VTLCALL_PARAMS]) -> i64 {
    let func_id: u32 = params[0].truncate();
    let Ok(func_id) = VsmFunction::try_from(func_id) else {
        return Errno::EINVAL.as_neg().into();
    };
    match func_id {
        VsmFunction::OpteeMessage => {
            let smc_args_pfn = params[1];
            optee_smc_handler_entry(smc_args_pfn)
        }
        _ => vsm_dispatch(func_id, &params[1..]),
    }
}

/// An entry point function to handle OP-TEE SMC call.
fn optee_smc_handler_entry(smc_args_pfn: u64) -> i64 {
    match optee_smc_handler_entry_inner(smc_args_pfn) {
        Ok(res) => res,
        Err(e) => e.as_neg().into(),
    }
}

fn optee_smc_handler_entry_inner(
    smc_args_pfn: u64,
) -> Result<i64, litebox_common_linux::errno::Errno> {
    let smc_args_pfn: usize = smc_args_pfn.truncate();
    let smc_args_addr = smc_args_pfn << litebox_platform_lvbs::mshv::vtl1_mem_layout::PAGE_SHIFT;
    let smc_args_updated = optee_smc_handler(smc_args_addr);

    // Write back the SMC arguments page to normal world memory.
    // All OP-TEE return codes (success or error) are delivered via smc_args.args[0].
    let mut smc_args_ptr = NormalWorldMutPtr::<OpteeSmcArgs, PAGE_SIZE>::with_usize(smc_args_addr)
        .map_err(|_| litebox_common_linux::errno::Errno::EINVAL)?;
    // SAFETY: The SMC args are written back to normal world memory.
    unsafe { smc_args_ptr.write_at_offset(0, smc_args_updated) }
        .map_err(|_| litebox_common_linux::errno::Errno::EFAULT)?;
    Ok(0)
}

/// Get the global session manager.
fn session_manager() -> &'static SessionManager {
    static SESSION_MANAGER: OnceBox<SessionManager> = OnceBox::new();
    SESSION_MANAGER.get_or_init(|| Box::new(SessionManager::new()))
}

/// Maps [`AddressSpaceError`](litebox::platform::address_space::AddressSpaceError) to the most
/// appropriate OP-TEE SMC return code.
fn address_space_error_to_smc(
    err: litebox::platform::address_space::AddressSpaceError,
) -> OpteeSmcReturnCode {
    use litebox::platform::address_space::AddressSpaceError;
    match err {
        AddressSpaceError::NoSpace => OpteeSmcReturnCode::ENomem,
        AddressSpaceError::InvalidId => OpteeSmcReturnCode::EBadCmd,
        AddressSpaceError::Busy => OpteeSmcReturnCode::EBusy,
        AddressSpaceError::NotSupported => OpteeSmcReturnCode::ENotAvail,
        _ => OpteeSmcReturnCode::EBadCmd,
    }
}

/// Creates a new address space for a TA instance.
#[inline]
fn create_ta_address_space() -> Result<usize, OpteeSmcReturnCode> {
    use litebox::platform::AddressSpaceProvider;
    litebox_platform_multiplex::platform()
        .create_address_space()
        .map_err(address_space_error_to_smc)
}

/// Destroys a TA's address space.
///
/// Must be called AFTER switching away from the TA's address space
/// (i.e., outside `with_address_space` scope).
#[inline]
fn destroy_ta_address_space(as_id: usize) -> Result<(), OpteeSmcReturnCode> {
    use litebox::platform::AddressSpaceProvider;
    litebox_platform_multiplex::platform()
        .destroy_address_space(as_id)
        .map_err(address_space_error_to_smc)
}

/// Executes `f` within the given TA address space, restoring the base
/// page table on return (even on panic).
#[inline]
fn with_ta_address_space<R>(as_id: usize, f: impl FnOnce() -> R) -> Result<R, OpteeSmcReturnCode> {
    use litebox::platform::AddressSpaceProvider;
    litebox_platform_multiplex::platform()
        .with_address_space(as_id, f)
        .map_err(address_space_error_to_smc)
}

/// Tears down a TA's memory mappings and address space.
///
/// 1. Switch to the TA's address space
/// 2. Release user-space memory mappings
/// 3. Restore the base page table (via RAII guard)
/// 4. Destroy the address space
///
/// # Safety
///
/// The caller must ensure that no references to user-space memory mapped by
/// this task's page table are held after this call.
unsafe fn teardown_ta_address_space(shim: &litebox_shim_optee::OpteeShim, as_id: usize) {
    // release_user_mappings must run inside with_ta_address_space because it
    // unmaps pages in the TA's active page table.
    let _ = with_ta_address_space(as_id, || {
        // Safety: caller guarantees no references will be held afterwards.
        unsafe { shim.release_user_mappings() };
    });
    // Now the base PT is restored by the RAII guard; safe to destroy.
    let _ = destroy_ta_address_space(as_id);
}

/// Handler for OP-TEE SMC calls.
///
/// This function processes SMC calls from the normal world (VTL0) and dispatches them
/// to the appropriate handlers based on the command type.
///
/// For TA requests (OpenSession, InvokeCommand, CloseSession), it uses `decode_ta_request`
/// to extract the TA request information and load/run it using `OpteeShim`.
///
/// OpenSession for multi-instance TA creates:
/// - A new address space for memory isolation
/// - A new TA instance with its own state
/// - An entry in the global session map
///
/// OpenSession for single-instance TA reuses existing TA instance if available,
/// otherwise creates a new one.
///
/// InvokeCommand looks up the session and enters its address space.
/// CloseSession removes the session and cleans up its address space if no more sessions use it.
///
/// Before returning to VTL0, `with_ta_address_space` restores the base page table via RAII.
///
/// # Panics
///
/// Panics if `loaded_program.entrypoints` is `None` when attempting to run the TA.
/// This should not happen in normal operation as `entrypoints` is always `Some` after
/// loading.
///
/// # Return Value
///
/// This function always returns `OpteeSmcArgs` with the result code in `args[0]`.
/// The OP-TEE driver expects all return codes (success or error) to be delivered via
/// `smc_args.args[0]`.
fn optee_smc_handler(smc_args_addr: usize) -> OpteeSmcArgs {
    use OpteeMessageCommand::{CloseSession, InvokeCommand, OpenSession};

    // Helper to create error response when we don't read smc_args from the normal world yet
    let make_error_response = |code: OpteeSmcReturnCode| -> OpteeSmcArgs {
        let mut args = OpteeSmcArgs::default();
        args.set_return_code(code);
        args
    };

    let Ok(mut smc_args_ptr) =
        NormalWorldConstPtr::<OpteeSmcArgs, PAGE_SIZE>::with_usize(smc_args_addr)
    else {
        return make_error_response(OpteeSmcReturnCode::EBadAddr);
    };
    // SAFETY: The SMC args are read from normal world memory into an owned copy.
    let Ok(mut smc_args) = (unsafe { smc_args_ptr.read_at_offset(0) }) else {
        return make_error_response(OpteeSmcReturnCode::EBadAddr);
    };
    let Ok(msg_args_phys_addr) = smc_args.optee_msg_args_phys_addr() else {
        smc_args.set_return_code(OpteeSmcReturnCode::EBadAddr);
        return *smc_args;
    };
    let Ok(smc_result) = handle_optee_smc_args(&mut smc_args) else {
        smc_args.set_return_code(OpteeSmcReturnCode::EBadCmd);
        return *smc_args;
    };
    if let OpteeSmcResult::CallWithArg {
        msg_args,
        rpc_args: _,
    } = smc_result
    {
        let mut msg_args = *msg_args;
        debug_serial_println!("OP-TEE SMC with MsgArgs Command: {:?}", msg_args.cmd);
        let result = match msg_args.cmd {
            OpenSession => handle_open_session(&mut msg_args, msg_args_phys_addr),
            InvokeCommand => handle_invoke_command(&mut msg_args, msg_args_phys_addr),
            CloseSession => handle_close_session(&mut msg_args, msg_args_phys_addr),
            _ => {
                let r = handle_optee_msg_args(&msg_args);
                if r.is_ok() {
                    msg_args.ret = TeeResult::Success;
                } else {
                    msg_args.ret = TeeResult::BadParameters;
                }
                msg_args.ret_origin = TeeOrigin::Tee;
                let _ = write_non_ta_msg_args_to_normal_world(&msg_args, msg_args_phys_addr);
                r
            }
        };

        if let Err(e) = result {
            smc_args.set_return_code(e);
        } else {
            smc_args.set_return_code(OpteeSmcReturnCode::Ok);
        }
        *smc_args
    } else {
        smc_result.into()
    }
}

/// Handle OpenSession command.
///
/// For multi-instance TAs, creates a new address space and loads ldelf/TA into it.
/// For single-instance TAs (TA_FLAG_SINGLE_INSTANCE), reuses existing TA instance.
///
/// On success, the session is registered and msg_args is updated with the session ID.
/// On failure (including TA returning error), msg_args is updated with the error code
/// and appropriate cleanup is performed (address space teardown for new instances,
/// instance cleanup for TARGET_DEAD on single-instance TAs with no other sessions).
fn handle_open_session(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
) -> Result<(), OpteeSmcReturnCode> {
    let ta_req_info = decode_ta_request(msg_args).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;
    if ta_req_info.entry_func != UteeEntryFunc::OpenSession {
        return Err(OpteeSmcReturnCode::EBadCmd);
    }

    let ta_uuid = ta_req_info.uuid.ok_or(OpteeSmcReturnCode::EBadCmd)?;
    let client_identity = ta_req_info.client_identity;
    let params = &ta_req_info.params;

    if let Some(existing) = session_manager().get_single_instance(&ta_uuid) {
        // Try to reuse existing single-instance TA, or create a new instance
        // If the TA is busy (lock held), return EThreadLimit - driver will wait and retry
        open_session_single_instance(
            msg_args,
            msg_args_phys_addr,
            existing,
            params,
            ta_uuid,
            &ta_req_info,
        )
    } else {
        open_session_new_instance(
            msg_args,
            msg_args_phys_addr,
            params,
            ta_uuid,
            client_identity,
            &ta_req_info,
        )
    }
}

/// Open a new session on an existing single-instance TA.
///
/// Returns `Err(OpteeSmcReturnCode::EThreadLimit)` if the TA instance is currently in use.
/// The Linux driver will wait and retry automatically.
///
/// If the TA's OpenSession entry point returns an error, the session is not registered.
/// For cleanup semantics, see OP-TEE OS `tee_ta_open_session()` in `tee_ta_manager.c`.
#[allow(clippy::type_complexity)]
fn open_session_single_instance(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
    instance_arc: Arc<SpinMutex<TaInstance>>,
    params: &[litebox_common_optee::UteeParamOwned],
    ta_uuid: litebox_common_optee::TeeUuid,
    ta_req_info: &litebox_shim_optee::msg_handler::TaRequestInfo<PAGE_SIZE>,
) -> Result<(), OpteeSmcReturnCode> {
    // Use try_lock to avoid spinning - return EThreadLimit if TA is in use
    // The Linux driver will handle this by waiting and retrying
    let instance = instance_arc
        .try_lock()
        .ok_or(OpteeSmcReturnCode::EThreadLimit)?;

    // Allocate session ID BEFORE calling load_ta_context so TA gets correct ID.
    // Use SessionIdGuard to ensure the ID is recycled on any error path
    // (before it is registered with the session manager).
    let session_id_guard =
        SessionIdGuard::new(allocate_session_id().ok_or(OpteeSmcReturnCode::EBusy)?);
    // Safe to unwrap: guard was just created with Some(id).
    let runner_session_id = session_id_guard.id().unwrap();

    debug_serial_println!(
        "Reusing single-instance TA: uuid={:?}, as_id={}, session_id={}",
        ta_uuid,
        instance.address_space_id,
        runner_session_id
    );

    let as_id = instance.address_space_id;
    let ta_flags = instance.loaded_program.ta_flags;

    // Run the TA's OpenSession entry point inside its address space.
    // write_msg_args_to_normal_world must be called inside the address space
    // because update_optee_msg_args dereferences TA memref addresses.
    let return_code = with_ta_address_space(as_id, || {
        // Safety: we are inside the TA's address space scope.
        let reuse_result = unsafe {
            instance
                .shim
                .reenter_open_session(&instance.loaded_program, params, runner_session_id)
        }
        .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

        let return_code = reuse_result.return_code;
        write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            return_code,
            if return_code == TeeResult::Success {
                Some(runner_session_id)
            } else {
                None
            },
            reuse_result.ta_params.as_ref(),
            Some(ta_req_info),
        )?;

        Ok::<_, OpteeSmcReturnCode>(return_code)
    })??;

    // Drop the lock before potential cleanup
    drop(instance);

    // Per OP-TEE OS: if OpenSession fails, don't register the session
    // Reference: tee_ta_open_session() in tee_ta_manager.c
    if return_code != TeeResult::Success {
        debug_serial_println!(
            "OpenSession failed on single-instance TA: return_code={:?}",
            return_code
        );

        // For single-instance TAs, only clean up on TARGET_DEAD (panic).
        // Regular errors (access denied, bad params, etc.) don't mean the TA is dead -
        // it can still serve future OpenSession requests from other clients.
        if return_code == TeeResult::TargetDead {
            // Check if any other sessions are using this instance by counting sessions
            // in the session map that reference this TA instance.
            let session_count = session_manager()
                .sessions()
                .count_sessions_for_instance(&instance_arc);

            if session_count == 0 {
                debug_serial_println!(
                    "Single-instance TA panicked with no other sessions, cleaning up"
                );

                session_manager().remove_single_instance(&ta_uuid);

                // Safety: We are about to tear down this TA instance;
                // no references to user-space memory will be held afterwards.
                unsafe { teardown_ta_address_space(&instance_arc.lock().shim, as_id) };

                // TODO: Per OP-TEE OS semantics, if the TA has INSTANCE_KEEP_ALIVE but not
                // INSTANCE_KEEP_CRASHED, we should respawn the TA here instead of just
                // cleaning it up. Currently we always clean up on panic.

                return Ok(());
            }
        }

        return Ok(());
    }

    // Success: register session and disarm the guard (ownership transfers to session map)
    // Safe to unwrap: guard has not been disarmed yet.
    let runner_session_id = session_id_guard.disarm().unwrap();
    session_manager().register_session(runner_session_id, instance_arc.clone(), ta_uuid, ta_flags);

    debug_serial_println!(
        "OpenSession complete on single-instance TA: session_id={}",
        runner_session_id
    );

    Ok(())
}

/// Create a new TA instance for a session.
///
/// If ldelf loading or OpenSession entry point fails, the address space is torn down.
/// Per OP-TEE OS semantics: if OpenSession returns non-success, cleanup happens.
fn open_session_new_instance(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
    params: &[litebox_common_optee::UteeParamOwned],
    ta_uuid: litebox_common_optee::TeeUuid,
    client_identity: Option<litebox_common_optee::TeeIdentity>,
    ta_req_info: &litebox_shim_optee::msg_handler::TaRequestInfo<PAGE_SIZE>,
) -> Result<(), OpteeSmcReturnCode> {
    // Check TA instance limit
    // TODO: consider better resource management strategy
    if session_manager().instance_count() >= MAX_TA_INSTANCES {
        debug_serial_println!("TA instance limit reached ({} instances)", MAX_TA_INSTANCES);
        return Err(OpteeSmcReturnCode::ENomem);
    }

    // Create a new address space for the TA
    let as_id = create_ta_address_space()?;

    debug_serial_println!("Created address space ID: {}", as_id);

    // Allocate session ID before loading - return EBusy to normal world if exhausted
    let runner_session_id = allocate_session_id().ok_or_else(|| {
        let _ = destroy_ta_address_space(as_id);
        OpteeSmcReturnCode::EBusy
    })?;

    // Create shim and run the TA lifecycle inside the address space.
    // write_msg_args_to_normal_world must be called inside the address space
    // because update_optee_msg_args dereferences TA memref addresses.
    let shim = litebox_shim_optee::OpteeShimBuilder::new().build();

    let result = with_ta_address_space(as_id, || {
        // Safety: we are inside the TA's address space scope.
        let shim_result = unsafe {
            shim.run_open_session(
                LDELF_BINARY,
                ta_uuid,
                Some(TA_BINARY),
                client_identity,
                runner_session_id,
                params,
            )
        };

        match shim_result {
            Ok(open_result) => {
                debug_serial_println!(
                    "TA flags: {:?}, single_instance={}",
                    open_result.ta_flags,
                    open_result.ta_flags.is_single_instance()
                );
                write_msg_args_to_normal_world(
                    msg_args,
                    msg_args_phys_addr,
                    TeeResult::Success,
                    Some(runner_session_id),
                    open_result.ta_params.as_ref(),
                    Some(ta_req_info),
                )?;
                Ok(Some(open_result))
            }
            Err(litebox_shim_optee::OpenSessionError::LdelfFailed(return_code)) => {
                debug_serial_println!(
                    "ldelf/TA_CreateEntryPoint failed: return_code={:?}",
                    return_code
                );
                write_msg_args_to_normal_world(
                    msg_args,
                    msg_args_phys_addr,
                    return_code,
                    None,
                    None,
                    Some(ta_req_info),
                )?;
                Ok(None)
            }
            Err(litebox_shim_optee::OpenSessionError::TaOpenSessionFailed {
                return_code,
                ta_params,
            }) => {
                debug_serial_println!(
                    "OpenSession failed on new instance: return_code={:?}",
                    return_code
                );
                write_msg_args_to_normal_world(
                    msg_args,
                    msg_args_phys_addr,
                    return_code,
                    None,
                    ta_params.as_ref(),
                    Some(ta_req_info),
                )?;
                Ok(None)
            }
            Err(litebox_shim_optee::OpenSessionError::LoadFailed(_)) => {
                Err(OpteeSmcReturnCode::ENomem)
            }
            Err(
                litebox_shim_optee::OpenSessionError::NoEntrypoints
                | litebox_shim_optee::OpenSessionError::ContextLoadFailed
                | litebox_shim_optee::OpenSessionError::ParamsReadFailed,
            ) => Err(OpteeSmcReturnCode::EBadCmd),
        }
    })?;

    // Outside address space scope: only session registration and cleanup
    // (no TA user-space memory access needed).
    match result {
        Ok(Some(open_result)) => {
            let instance = Arc::new(SpinMutex::new(TaInstance {
                shim,
                loaded_program: open_result.loaded_program,
                address_space_id: as_id,
            }));

            if open_result.ta_flags.is_single_instance() {
                session_manager().cache_single_instance(ta_uuid, instance.clone());
            }

            session_manager().register_session(
                runner_session_id,
                instance.clone(),
                ta_uuid,
                open_result.ta_flags,
            );

            debug_serial_println!(
                "OpenSession complete on new instance: session_id={}",
                runner_session_id
            );
            Ok(())
        }
        Ok(None) => {
            // Error response already written; destroy AS.
            // Shim released user mappings on all error paths (see OpenSessionError doc).
            let _ = destroy_ta_address_space(as_id);
            Ok(())
        }
        Err(e) => {
            // Internal error; no VTL0 response written.
            // Shim released user mappings on all error paths (see OpenSessionError doc).
            let _ = destroy_ta_address_space(as_id);
            Err(e)
        }
    }
}

/// Handle InvokeCommand.
///
/// Looks up the session by ID, enters its address space, and runs the command.
///
/// Per OP-TEE OS semantics: if the TA panics (returns TARGET_DEAD), the session
/// should be cleaned up. For single-instance TAs with no other sessions, the
/// entire instance is destroyed.
fn handle_invoke_command(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
) -> Result<(), OpteeSmcReturnCode> {
    let ta_req_info = decode_ta_request(msg_args).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;
    if ta_req_info.entry_func != UteeEntryFunc::InvokeCommand {
        return Err(OpteeSmcReturnCode::EBadCmd);
    }
    let cmd_id = ta_req_info.cmd_id;
    let params = &ta_req_info.params;
    let session_id = ta_req_info.session;

    // Get the session entry from the session map (need full entry for potential cleanup)
    let session_entry = session_manager()
        .get_session_entry(session_id)
        .ok_or(OpteeSmcReturnCode::EBadCmd)?;
    // Use try_lock to avoid spinning - return EThreadLimit if TA is in use
    // The Linux driver will handle this by waiting and retrying
    let Some(instance) = session_entry.instance.try_lock() else {
        return Err(OpteeSmcReturnCode::EThreadLimit);
    };

    let as_id = instance.address_space_id;

    debug_serial_println!(
        "InvokeCommand: session_id={}, as_id={}, cmd_id={}",
        session_id,
        as_id,
        cmd_id
    );

    // Run the TA command inside its address space.
    // write_msg_args_to_normal_world must be called inside because it reads TA user memory.
    let return_code = with_ta_address_space(as_id, || {
        // Safety: we are inside the TA's address space scope.
        let result = unsafe {
            instance.shim.run_invoke_command(
                &instance.loaded_program,
                params.as_slice(),
                session_id,
                cmd_id,
            )
        }
        .map_err(|e| match e {
            litebox_shim_optee::InvokeCommandError::ParamsReadFailed => {
                OpteeSmcReturnCode::EBadAddr
            }
            _ => OpteeSmcReturnCode::EBadCmd,
        })?;

        let return_code = result.return_code;
        write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            return_code,
            None,
            result.ta_params.as_ref(),
            Some(&ta_req_info),
        )?;

        Ok::<_, OpteeSmcReturnCode>(return_code)
    })??;

    // Per OP-TEE OS: if TA panics (TARGET_DEAD), clean up the session/instance
    // Reference: tee_ta_invoke_command() in tee_ta_manager.c
    if return_code == TeeResult::TargetDead {
        debug_serial_println!(
            "InvokeCommand: TA panicked (TARGET_DEAD), session_id={}",
            session_id
        );

        let ta_uuid = session_entry.ta_uuid;
        let ta_flags = session_entry.ta_flags;
        let instance_arc = session_entry.instance.clone();

        // Drop the instance lock before cleanup
        drop(instance);

        // Remove the session from the map
        session_manager().unregister_session(session_id);

        // Check if this was the last session using the TA instance by counting
        // remaining sessions that reference this instance.
        let remaining_sessions = session_manager()
            .sessions()
            .count_sessions_for_instance(&instance_arc);
        let is_last_session = remaining_sessions == 0;

        if is_last_session {
            // Clear single-instance cache if applicable
            if ta_flags.is_single_instance() {
                session_manager().remove_single_instance(&ta_uuid);
            }

            // Safety: We are about to tear down this TA instance;
            // no references to user-space memory will be held afterwards.
            unsafe { teardown_ta_address_space(&instance_arc.lock().shim, as_id) };
            debug_serial_println!(
                "InvokeCommand: cleaned up dead TA instance, as_id={}",
                as_id
            );

            // TODO: Per OP-TEE OS semantics, if the TA has INSTANCE_KEEP_ALIVE but not
            // INSTANCE_KEEP_CRASHED, we should respawn the TA here instead of just
            // cleaning it up. Currently we always clean up on panic.
        }

        return Ok(());
    }

    Ok(())
}

/// Handle CloseSession command.
///
/// Looks up the session, enters the TA to call TA_CloseSessionEntryPoint,
/// then removes the session from the map. For single-instance TAs, the TA
/// is only destroyed when the last session closes.
fn handle_close_session(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
) -> Result<(), OpteeSmcReturnCode> {
    let ta_req_info = decode_ta_request(msg_args).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;
    if ta_req_info.entry_func != UteeEntryFunc::CloseSession {
        return Err(OpteeSmcReturnCode::EBadCmd);
    }
    let session_id = ta_req_info.session;

    debug_serial_println!("CloseSession: session_id={}", session_id);

    // Get the session entry from the session map
    let session_entry = session_manager()
        .get_session_entry(session_id)
        .ok_or(OpteeSmcReturnCode::EBadCmd)?;
    // Use try_lock to avoid spinning - return EThreadLimit if TA is in use
    // The Linux driver will handle this by waiting and retrying
    let Some(instance) = session_entry.instance.try_lock() else {
        return Err(OpteeSmcReturnCode::EThreadLimit);
    };

    let as_id = instance.address_space_id;

    // Run CloseSession entry point inside the TA's address space.
    // write_msg_args_to_normal_world must be called inside because it reads TA user memory.
    with_ta_address_space(as_id, || {
        // Load TA context for CloseSession (no params, no cmd_id) - pass actual session_id
        instance
            .loaded_program
            .entrypoints
            .as_ref()
            .unwrap()
            .load_ta_context(
                &[],
                Some(session_id),
                UteeEntryFunc::CloseSession as u32,
                None,
            )
            .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

        // Run the TA entry function (TA_CloseSessionEntryPoint)
        let mut ctx = litebox_common_linux::PtRegs::default();
        unsafe {
            litebox_platform_multiplex::platform().reenter_thread(
                instance.loaded_program.entrypoints.as_ref().unwrap(),
                &mut ctx,
            );
        }

        // CloseSession always succeeds (TA_CloseSessionEntryPoint returns void)
        write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            TeeResult::Success,
            None,
            None,
            None,
        )?;

        Ok::<_, OpteeSmcReturnCode>(())
    })??;

    // Clone the instance Arc before dropping the lock for later cleanup check
    let instance_arc = session_entry.instance.clone();

    // Drop the instance lock before removing from map
    drop(instance);

    // Remove the session entry from the map
    let removed_entry = session_manager().unregister_session(session_id);

    // Check if this was the last session using the TA instance by counting
    // remaining sessions that reference this instance.
    let remaining_sessions = session_manager()
        .sessions()
        .count_sessions_for_instance(&instance_arc);

    // If this was the last session using the TA instance, clean up (unless keep_alive is set)
    if remaining_sessions == 0 {
        if let Some(entry) = removed_entry {
            // If this is a single-instance TA with keep_alive flag, don't remove it from memory.
            // Note: keep_alive is only meaningful for single-instance TAs.
            if entry.ta_flags.is_single_instance() && entry.ta_flags.is_keep_alive() {
                debug_serial_println!(
                    "CloseSession complete: session_id={}, TA kept alive (INSTANCE_KEEP_ALIVE flag)",
                    session_id
                );
                return Ok(());
            }

            // Clear single-instance cache if this was a single-instance TA
            if entry.ta_flags.is_single_instance() {
                session_manager().remove_single_instance(&entry.ta_uuid);
            }

            let instance = entry.instance.lock();
            let as_id = instance.address_space_id;

            // Safety: We are about to tear down this TA instance;
            // no references to user-space memory will be held afterwards.
            unsafe { teardown_ta_address_space(&instance.shim, as_id) };

            // Drop the instance to release shim/loaded_program resources
            drop(instance);
            drop(entry);

            debug_serial_println!(
                "CloseSession complete: deleted as_id={} (last session)",
                as_id
            );
        }
    } else {
        debug_serial_println!(
            "CloseSession complete: session_id={}, other sessions remaining on TA",
            session_id
        );
    }

    Ok(())
}

/// Update msg_args with return values and write back to normal world memory.
///
/// Serializes `OpteeMsgArgs` into a contiguous byte blob and writes it to
/// the VTL0 physical address.
///
/// Per OP-TEE OS semantics:
/// - `TeeOrigin::Tee` is used when the error comes from TEE itself (panic/TARGET_DEAD)
/// - `TeeOrigin::TrustedApp` is used when the error comes from the TA
///
/// # Security Note
///
/// This function may access TA userspace memory via `update_optee_msg_args`
/// to copy out memref output parameters. It must be called **inside**
/// `with_ta_address_space` scope when `ta_params` contains memref outputs,
/// otherwise the userspace memory references become invalid.
///
/// # Panics
///
/// Debug-panics if called while the base page table is active (i.e., not in
/// a TA context) and `ta_params` is `Some`.
#[inline]
fn write_msg_args_to_normal_world(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
    return_code: TeeResult,
    session_id: Option<u32>,
    ta_params: Option<&UteeParams>,
    ta_req_info: Option<&litebox_shim_optee::msg_handler::TaRequestInfo<PAGE_SIZE>>,
) -> Result<(), OpteeSmcReturnCode> {
    // Ensure we're on a task page table when TA params need to be read.
    // Note: uses LVBS-specific `page_table_manager()` directly — this is acceptable
    // because this function is part of the LVBS runner (not portable to other platforms).
    if ta_params.is_some() {
        debug_assert!(
            !litebox_platform_multiplex::platform()
                .page_table_manager()
                .is_base_page_table_active(),
            "write_msg_args_to_normal_world called with ta_params on base page table"
        );
    }
    // Per OP-TEE: origin is TEE only if panicked (TARGET_DEAD), otherwise TrustedApp
    let origin = if return_code == TeeResult::TargetDead {
        TeeOrigin::Tee
    } else {
        TeeOrigin::TrustedApp
    };
    update_optee_msg_args(
        return_code,
        origin,
        session_id,
        ta_params,
        ta_req_info,
        msg_args,
    )?;

    let msg_args_size = optee_msg_args_total_size(msg_args.num_params);
    let mut blob = vec![0u8; msg_args_size];
    msg_args.serialize(&mut blob)?;

    let mut ptr = NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
        msg_args_phys_addr.truncate(),
        msg_args_size,
    )?;
    // SAFETY: Writing msg_args back to normal world memory at a valid physical address.
    // The blob contains the serialized variable-length optee_msg_arg structure(s).
    unsafe { ptr.write_slice_at_offset(0, &blob) }?;
    Ok(())
}

/// Write back `OpteeMsgArgs` for non-TA commands (e.g., RegisterShm, UnregisterShm) that
/// don't require TA userspace memory access.
///
/// Unlike [`write_msg_args_to_normal_world`], this function does not access TA userspace
/// memory and can be called from the base page table context. It simply serializes the
/// msg_args (which should already have `ret` / `ret_origin` set by the caller) back to
/// the normal world physical address.
#[inline]
fn write_non_ta_msg_args_to_normal_world(
    msg_args: &OpteeMsgArgs,
    msg_args_phys_addr: u64,
) -> Result<(), OpteeSmcReturnCode> {
    let msg_args_size = optee_msg_args_total_size(msg_args.num_params);
    let mut blob = vec![0u8; msg_args_size];
    msg_args.serialize(&mut blob)?;

    let mut ptr = NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
        msg_args_phys_addr.truncate(),
        msg_args_size,
    )?;
    // SAFETY: Writing msg_args back to normal world memory at a valid physical address.
    // The blob contains the serialized variable-length optee_msg_arg structure(s).
    unsafe { ptr.write_slice_at_offset(0, &blob) }?;
    Ok(())
}

/// Write `OpteeRpcArgs` to the normal world. Its write address is determined by
/// `msg_args_phys_addr` and the size of `OpteeMsgArgs`.
///
/// Unlike [`write_msg_args_to_normal_world`], this function does not access TA userspace
/// memory and can be called from the base page table context. It simply serializes the
/// rpc_args and writes it to the normal world physical address.
#[expect(dead_code)]
#[inline]
fn write_rpc_args_to_normal_world(
    msg_args: &OpteeMsgArgs,
    msg_args_phys_addr: u64,
    rpc_args: &OpteeRpcArgs,
) -> Result<(), OpteeSmcReturnCode> {
    let msg_args_size = optee_msg_args_total_size(msg_args.num_params);

    let rpc_args_size = optee_msg_args_total_size(rpc_args.num_params);
    let mut blob = vec![0u8; rpc_args_size];
    rpc_args.serialize(&mut blob)?;

    let rpc_pa: usize =
        <u64 as litebox::utils::TruncateExt<usize>>::truncate(msg_args_phys_addr) + msg_args_size; // RPC args are placed right after the main msg_args blob
    let mut ptr = NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(rpc_pa, rpc_args_size)?;
    // SAFETY: Writing rpc_args back to normal world memory at a valid physical address.
    // The blob contains the serialized variable-length optee_msg_arg structure(s).
    unsafe { ptr.write_slice_at_offset(0, &blob) }?;
    Ok(())
}

// use include_bytes! to include ldelf and (KMPP) TA binaries
const LDELF_BINARY: &[u8] = &[0u8; 0];
const TA_BINARY: &[u8] = &[0u8; 0];

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    match raise_vtl0_gp_fault() {
        Ok(result) => vtl_switch(Some(result.reinterpret_as_signed())),
        Err(err) => vtl_switch(Some((err as u32).reinterpret_as_signed().neg().into())),
    };
    // We assume that once this VTL1 kernel panics, we don't try to resume its execution.
    // This is because, after the panic, the kernel is in an undefined state.
    // Switch back to VTL0, do crash dump, and reboot the machine.
    hlt_loop()
}
