// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT thread creation and termination syscall handlers.

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::handle_table::{NtObject, ThreadObject};
use crate::NtShimEntrypoints;
use litebox::platform::{RawConstPointer as _, RawPointerProvider, ThreadProvider as _};
use litebox_common_windows::ntstatus::NtStatus;

use super::NtSyscallArgs;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn set_guest_teb_base(value: u64) {
    litebox_platform_windows_userland::WindowsUserland::set_guest_teb_base(value);
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn set_guest_va_range(start: usize, end: usize) {
    litebox_platform_windows_userland::WindowsUserland::set_guest_va_range(start..end);
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn set_guest_teb_base(_value: u64) {}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn set_guest_va_range(_start: usize, _end: usize) {}

/// Sentinel return address pushed onto child thread stacks. When the start
/// routine returns, RIP becomes this value and faults. The exception handler
/// recognises this specific address as a clean thread exit (using RAX as exit
/// code) rather than a real crash. This value is in the null guard region
/// (first 64 KB) but distinct from 0, so it won't be confused with a null
/// function-pointer dereference.
pub(crate) const THREAD_EXIT_SENTINEL: usize = 0xDEAD;
const WIN64_SHADOW_SPACE_SIZE: usize = 0x20;

fn initial_child_thread_rsp(stack_top: usize) -> usize {
    stack_top - WIN64_SHADOW_SPACE_SIZE - core::mem::size_of::<usize>()
}

// NtCreateThreadEx signature (simplified):
//   NTSTATUS NtCreateThreadEx(
//     OUT PHANDLE ThreadHandle,           // arg0 (r10)
//     IN ACCESS_MASK DesiredAccess,        // arg1 (rdx)
//     IN POBJECT_ATTRIBUTES ObjectAttributes, // arg2 (r8)
//     IN HANDLE ProcessHandle,             // arg3 (r9)
//     IN PVOID StartRoutine,               // [rsp+0x28]
//     IN PVOID Argument,                   // [rsp+0x30]
//     IN ULONG CreateFlags,                // [rsp+0x38]
//     IN SIZE_T ZeroBits,                  // [rsp+0x40]
//     IN SIZE_T StackSize,                 // [rsp+0x48]
//     IN SIZE_T MaximumStackSize,          // [rsp+0x50]
//     IN PPS_ATTRIBUTE_LIST AttributeList  // [rsp+0x58]
//   );

/// NtCreateThreadEx — create a new guest thread.
///
/// Allocates a new TEB, guest stack, sets up the execution context, and
/// spawns a platform thread via `ThreadProvider::spawn_thread`. The child
/// thread gets its own `NtShimEntrypoints` instance with shared process
/// state but independent handle table (seeded with stdio handles).
pub(crate) fn nt_create_thread_ex<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    shim: &NtShimEntrypoints<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_va = args.arg0;
    if handle_out_va != 0
        && !crate::is_addr_range_writable(handle_out_va, core::mem::size_of::<usize>())
    {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    // Read stack arguments from guest stack via fallible helpers.
    // start_routine is critical — a NULL entry point would crash the sandbox.
    let Some(start_routine) = crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28)
    else {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    };
    if start_routine == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }
    let argument = crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let create_flags =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);
    let _zero_bits =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x40).unwrap_or(0);
    let stack_size =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x48).unwrap_or(0);
    let _max_stack_size =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x50).unwrap_or(0);

    let unsupported_flags = create_flags & !0x1;
    if unsupported_flags != 0 {
        log_unimplemented!("NtCreateThreadEx: unsupported create_flags=0x{create_flags:X}");
        return NtStatus::STATUS_NOT_IMPLEMENTED;
    }
    let initial_suspend_count = u32::from((create_flags & 0x1) != 0);

    // Allocate a thread ID.
    let tid = {
        let mut id = shim.shared.next_thread_id.lock();
        let val = *id;
        *id = val + crate::peb_teb::SYNTHETIC_THREAD_ID_INCREMENT;
        val
    };

    // Allocate guest stack for the new thread.
    let actual_stack_size = if stack_size == 0 {
        1024 * 1024 // 1 MiB default
    } else {
        (stack_size + 0xFFF) & !0xFFF
    };

    let pm = &shim.shared.process_state.pm;
    let nz_stack_size =
        litebox::mm::linux::NonZeroPageSize::<{ crate::PAGE_SIZE }>::new(actual_stack_size)
            .expect("stack size must be page-aligned");
    let stack_base_ptr = unsafe {
        pm.create_writable_pages(
            None,
            nz_stack_size,
            litebox::mm::linux::CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    };
    let stack_base = match stack_base_ptr {
        Ok(ptr) => ptr.as_usize(),
        Err(_) => return NtStatus::STATUS_NO_MEMORY,
    };
    let stack_top = stack_base + actual_stack_size;
    let cleanup_stack = |stack_base: usize| {
        let stack_ptr = <litebox_platform_multiplex::Platform as RawPointerProvider>::RawMutPointer::<
            u8,
        >::from_usize(stack_base);
        let _ = unsafe { pm.remove_pages(stack_ptr, actual_stack_size) };
    };

    // Allocate a new TEB for the child thread (two pages — 8KB).
    let nz_teb_size = litebox::mm::linux::NonZeroPageSize::<{ crate::PAGE_SIZE }>::new(0x2000)
        .expect("TEB size must be page-aligned");
    let teb_ptr = unsafe {
        pm.create_writable_pages(
            None,
            nz_teb_size,
            litebox::mm::linux::CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    };
    let child_teb_va = match teb_ptr {
        Ok(ptr) => ptr.as_usize(),
        Err(_) => {
            cleanup_stack(stack_base);
            return NtStatus::STATUS_NO_MEMORY;
        }
    };
    let cleanup_stack_and_teb = || {
        let teb_ptr = <litebox_platform_multiplex::Platform as RawPointerProvider>::RawMutPointer::<
            u8,
        >::from_usize(child_teb_va);
        let _ = unsafe { pm.remove_pages(teb_ptr, 0x2000) };
        cleanup_stack(stack_base);
    };

    // Create the thread object once the child TEB VA is known.
    let thread_obj = Arc::new(ThreadObject::new(tid, initial_suspend_count, child_teb_va));
    let Some(parent_init) = &shim.init_state else {
        log_unimplemented!("NtCreateThreadEx: no parent init state");
        cleanup_stack_and_teb();
        return NtStatus::STATUS_UNSUCCESSFUL;
    };

    // Initialize the child TEB from scratch.
    //
    // In real Windows, ntoskrnl creates a **fresh, zeroed** TEB for each new
    // thread and only populates a handful of fields (NtTib, ClientId, PEB
    // pointer, stack limits).  The previous approach of copying the parent
    // TEB wholesale carried over stale per-thread state (heap FLS affinity
    // data, activation context stacks, LFH per-thread slots, etc.) that
    // ntdll never expects to be pre-populated for a new thread.  This caused
    // STATUS_HEAP_CORRUPTION (0xC0000374) when a second child thread's
    // LdrpInitializeThread found corrupted heap metadata left over from the
    // first child thread's exit path.
    //
    // Following the syscall-boundary principle: do what the kernel does —
    // zero-init the TEB and set only the fields the kernel sets.
    let parent_teb_va = parent_init.teb_va;
    unsafe {
        // Start from a clean slate — zero the entire TEB (2 pages).
        core::ptr::write_bytes(child_teb_va as *mut u8, 0, 0x2000);

        // NtTib.ExceptionList = -1 (no SEH chain)
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::EXCEPTION_LIST) as *mut u64,
            u64::MAX,
        );
        // NtTib.StackBase
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::STACK_BASE) as *mut usize,
            stack_top,
        );
        // NtTib.StackLimit
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::STACK_LIMIT) as *mut usize,
            stack_base,
        );
        // NtTib.Self = pointer to TEB itself
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::SELF) as *mut usize,
            child_teb_va,
        );
        // ClientId.UniqueProcess — same as parent
        if parent_teb_va != 0 {
            let parent_pid: u64 = core::ptr::read(
                (parent_teb_va + crate::peb_teb::teb_offsets::CLIENT_ID_PROCESS) as *const u64,
            );
            core::ptr::write(
                (child_teb_va + crate::peb_teb::teb_offsets::CLIENT_ID_PROCESS) as *mut u64,
                parent_pid,
            );
        }
        // ClientId.UniqueThread — new thread ID
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::CLIENT_ID_THREAD) as *mut u64,
            u64::from(tid),
        );
        // ProcessEnvironmentBlock — same as parent
        if parent_teb_va != 0 {
            let peb_ptr: u64 = core::ptr::read(
                (parent_teb_va + crate::peb_teb::teb_offsets::PEB_PTR) as *const u64,
            );
            core::ptr::write(
                (child_teb_va + crate::peb_teb::teb_offsets::PEB_PTR) as *mut u64,
                peb_ptr,
            );
        }
        // DeallocationStack = base of the stack allocation
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::DEALLOCATION_STACK) as *mut usize,
            stack_base,
        );
        // GuaranteedStackBytes — minimum stack guarantee (default 4KB)
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::GUARANTEED_STACK_BYTES) as *mut u64,
            0x1000,
        );
    }
    // All per-thread state (TLS, FLS, heap FLS, activation context, etc.)
    // is left as zero — LdrpInitializeThread will initialise these fields
    // from scratch, exactly as it does for kernel-created threads.

    // Allocate per-thread implicit TLS (TEB+0x58) from PE TLS templates.
    //
    // IMPORTANT: Only do this when the child thread does NOT enter through
    // LdrInitializeThunk.  When LdrInitializeThunk is available, ntdll's
    // LdrpInitializeThread will call LdrpAllocateTlsEntry which allocates
    // TLS from the process heap via RtlAllocateHeap.  If we pre-allocate
    // TLS from the PageManager, the pointer ends up in TEB+0x58 and ntdll's
    // thread-exit path (LdrpReleaseTlsEntry) will later try to free it
    // with RtlFreeHeap — passing a non-heap pointer corrupts the heap and
    // causes STATUS_HEAP_CORRUPTION (0xC0000374) in surviving threads.
    //
    // The fallback path (no LdrInitializeThunk) still needs our allocation
    // because ntdll won't run its full init sequence.
    let use_ldr_init_thunk =
        parent_init.ldr_init_thunk_va != 0 && parent_init.rtl_user_thread_start_va != 0;
    if !use_ldr_init_thunk {
        if let Some(templates) = shim.shared.tls_templates.get() {
            if !templates.is_empty() {
                crate::allocate_child_thread_tls(
                    &shim.shared.process_state.pm,
                    child_teb_va,
                    templates,
                );
            }
        }
    }

    // Set up the child thread's stack and initial entry point.
    //
    // When LdrInitializeThunk is available, child threads enter through the
    // full ntdll loader path (LdrInitializeThunk → LdrpInitialize →
    // LdrpInitializeThread → DLL_THREAD_ATTACH → NtContinue) just like real
    // Windows.  A CONTEXT structure on the stack describes the post-init
    // state (RIP=RtlUserThreadStart, RCX=StartRoutine, RDX=Parameter).
    //
    // When LdrInitializeThunk is not available, fall back to the old path:
    // enter directly at RtlUserThreadStart (or the start routine itself).
    let (child_effective_stack_top, child_entry_point, child_initial_rcx, child_initial_rdx) =
        if use_ldr_init_thunk {
            // Build a CONTEXT on the child's stack, mirroring how the runner
            // sets up the main thread for LdrInitializeThunk.
            const CONTEXT_SIZE: usize = 0x4D0;
            const CONTEXT_FULL: u32 = 0x10_000B;

            // Place the sentinel return address at the very top of the stack.
            // RtlUserThreadStart will eventually return to this address,
            // triggering the clean thread-exit path.
            let sentinel_rsp = initial_child_thread_rsp(stack_top);
            unsafe {
                core::ptr::write(sentinel_rsp as *mut usize, THREAD_EXIT_SENTINEL);
            }

            // Place CONTEXT below the sentinel+shadow area (16-byte aligned).
            let context_va = (sentinel_rsp - CONTEXT_SIZE) & !0xF;

            // Zero the CONTEXT region and fill key fields.
            unsafe {
                core::ptr::write_bytes(context_va as *mut u8, 0, CONTEXT_SIZE);
            }
            let ctx = context_va;
            let default_fp = litebox_common_linux::FpRegs::default();
            unsafe {
                // ContextFlags at +0x30: CONTEXT_FULL
                core::ptr::write_unaligned((ctx + 0x30) as *mut u32, CONTEXT_FULL);
                // EFlags at +0x44: IF + reserved bit 1
                core::ptr::write_unaligned((ctx + 0x44) as *mut u32, 0x202);
                // SegCs at +0x38: user-mode 64-bit CS
                core::ptr::write_unaligned((ctx + 0x38) as *mut u16, 0x33);
                // SegSs at +0x42: user-mode SS
                core::ptr::write_unaligned((ctx + 0x42) as *mut u16, 0x2B);
                // Rcx at +0x80: first param to RtlUserThreadStart = StartRoutine
                core::ptr::write_unaligned((ctx + 0x80) as *mut u64, start_routine as u64);
                // Rdx at +0x88: second param = thread parameter
                core::ptr::write_unaligned((ctx + 0x88) as *mut u64, argument as u64);
                // Rsp at +0x98: stack for RtlUserThreadStart (after NtContinue).
                // NtContinue doesn't push a return address, so bias RSP by +8
                // to maintain the Windows x64 RSP%16==8 alignment invariant.
                let post_init_rsp = sentinel_rsp as u64;
                core::ptr::write_unaligned((ctx + 0x98) as *mut u64, post_init_rsp);
                // Rip at +0xF8: RtlUserThreadStart
                core::ptr::write_unaligned(
                    (ctx + 0xF8) as *mut u64,
                    parent_init.rtl_user_thread_start_va as u64,
                );
                // MxCsr at +0x34 and FltSave at +0x100: default FP/SIMD state.
                core::ptr::copy_nonoverlapping(
                    default_fp.data[24..28].as_ptr(),
                    (ctx + 0x34) as *mut u8,
                    4,
                );
                core::ptr::copy_nonoverlapping(
                    default_fp.data.as_ptr(),
                    (ctx + 0x100) as *mut u8,
                    512,
                );
            }

            // LdrInitializeThunk's own stack frame: below the CONTEXT with
            // shadow space for the Win64 calling convention.
            let ldr_rsp = context_va - 0x28;

            // Find ntdll base address from the module list.
            let ntdll_base = parent_init
                .module_bases
                .iter()
                .find(|m| {
                    m.name.eq_ignore_ascii_case("ntdll.dll") || m.name.eq_ignore_ascii_case("ntdll")
                })
                .map_or(0, |m| m.base_address);

            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtCreateThreadEx child LdrInitializeThunk: ctx=0x{context_va:X} \
                     ldr_rsp=0x{ldr_rsp:X} ntdll=0x{ntdll_base:X} \
                     RtlUTS=0x{:X} start=0x{start_routine:X} arg=0x{argument:X} \
                     stack_top=0x{stack_top:X} sentinel_rsp=0x{sentinel_rsp:X} \
                     ldr_init_thunk=0x{:X}\n",
                    parent_init.rtl_user_thread_start_va,
                    parent_init.ldr_init_thunk_va,
                ));
            }

            (
                ldr_rsp,
                parent_init.ldr_init_thunk_va,
                context_va,
                ntdll_base,
            )
        } else {
            // Fallback: enter through RtlUserThreadStart or directly.
            let rsp = initial_child_thread_rsp(stack_top);
            unsafe {
                core::ptr::write(rsp as *mut usize, THREAD_EXIT_SENTINEL);
            }
            if parent_init.rtl_user_thread_start_va != 0 {
                (
                    rsp,
                    parent_init.rtl_user_thread_start_va,
                    start_routine,
                    argument,
                )
            } else {
                (rsp, start_routine, argument, 0)
            }
        };

    // Build a minimal execution context. The child's EnterShim::init() will
    // override RIP, RSP, and RCX before guest entry.
    let child_ctx = litebox_common_linux::ExecutionContext::default();

    // Create the child's shim entrypoints — shares all process-wide state.
    let child_shim = NtShimEntrypoints::new_for_child_thread(
        Arc::clone(&shim.shared),
        Arc::clone(&thread_obj),
        tid,
        parent_init,
        child_entry_point,
        child_effective_stack_top,
        child_teb_va,
        child_initial_rcx,
        child_initial_rdx,
    );

    // Wrap in InitThread for the platform.
    let init_args = Box::new(NtChildThreadInit {
        child_shim,
        child_teb_va,
        guest_va_start: parent_init.guest_va_start,
        guest_va_end: parent_init.guest_va_end,
    });

    // Spawn the thread.
    let platform = litebox_platform_multiplex::platform();
    shim.shared
        .threads_by_id
        .lock()
        .insert(tid, Arc::clone(&thread_obj));
    if unsafe { platform.spawn_thread(&child_ctx, init_args) }.is_err() {
        shim.shared.threads_by_id.lock().remove(&tid);
        cleanup_stack_and_teb();
        log_unimplemented!("NtCreateThreadEx: spawn_thread failed");
        return NtStatus::STATUS_NO_MEMORY;
    }

    // Thread spawned successfully — now insert handle into the shared table.
    // This is deferred so that error paths above don't leave a dangling handle
    // for a thread that never started.
    shim.trace(
        crate::TraceKind::ThreadCreate,
        tid as u32,
        start_routine,
        0,
        0,
    );
    let handle = shim
        .shared
        .handles
        .lock()
        .insert(NtObject::Thread(Arc::clone(&thread_obj)));

    // Write the handle to the caller's output.
    if handle_out_va != 0
        && !crate::try_write_guest_value_unaligned::<usize>(handle_out_va, handle as usize)
    {
        let _ = shim.shared.handles.lock().close(handle);
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    #[cfg(all(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtCreateThreadEx -> handle=0x{handle:X} tid={} start=0x{:X} arg=0x{:X} teb=0x{:X} suspended={}\n",
            tid,
            start_routine,
            argument,
            child_teb_va,
            initial_suspend_count != 0,
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// InitThread implementation for child NT threads.
///
/// Carries the fully-configured child `NtShimEntrypoints` and the child TEB VA.
/// When `init()` is called on the new host thread, it sets the FS base (guest
/// TEB base) and returns the child shim as the `EnterShim` for the thread's
/// execution loop.
struct NtChildThreadInit<FS: crate::NtShimFS> {
    child_shim: NtShimEntrypoints<FS>,
    child_teb_va: usize,
    guest_va_start: usize,
    guest_va_end: usize,
}

// Safety: NtShimEntrypoints fields are all Send+Sync (Mutex, Arc, Atomic).
// ThreadObject is Arc-wrapped. child_teb_va is a plain usize.
unsafe impl<FS: crate::NtShimFS> Send for NtChildThreadInit<FS> {}

impl<FS: crate::NtShimFS> litebox::shim::InitThread for NtChildThreadInit<FS> {
    type ExecutionContext = litebox_common_linux::ExecutionContext;

    fn init(
        self: alloc::boxed::Box<Self>,
    ) -> alloc::boxed::Box<dyn litebox::shim::EnterShim<ExecutionContext = Self::ExecutionContext>>
    {
        // Set FS base for this host thread to point to the child TEB.
        // This must happen on the new thread (TLS is per-thread).
        set_guest_va_range(self.guest_va_start, self.guest_va_end);
        set_guest_teb_base(self.child_teb_va as u64);

        if let Some(thread_obj) = self.child_shim.thread_obj.as_ref() {
            thread_obj.wait_until_resumed(&self.child_shim.wait_cx());
        }

        // Return the child's shim entrypoints. Its init() will set RIP, RSP,
        // and RCX correctly for child thread entry.
        Box::new(self.child_shim)
    }
}

/// NtTerminateThread — terminate the current thread.
///
/// Returns (status, should_terminate). When should_terminate is true, the
/// platform will exit the thread's execution loop.
pub(crate) fn nt_terminate_thread(ctx: &mut super::super::ExecutionContext) -> (NtStatus, bool) {
    let _args = NtSyscallArgs::from_ctx(ctx);
    // args.arg0 = handle (-2 = current thread)
    // args.arg1 = exit code

    // For now, only support terminating the current thread.
    (NtStatus::STATUS_SUCCESS, true)
}

/// Spawn a worker factory thread — kernel-initiated thread creation.
///
/// This is the kernel's mechanism for spawning threads on behalf of a worker
/// factory (`NtSetInformationWorkerFactory(ThreadMinimum)`). The thread starts
/// at `start_routine(start_parameter)` and goes through the full
/// `LdrInitializeThunk` → `RtlUserThreadStart` path, just like
/// `NtCreateThreadEx`.
///
/// Returns `Ok(thread_id)` on success or `Err(NtStatus)` on failure.
pub(crate) fn spawn_worker_factory_thread<FS: crate::NtShimFS>(
    shim: &NtShimEntrypoints<FS>,
    start_routine: usize,
    start_parameter: usize,
) -> Result<u32, NtStatus> {
    if start_routine == 0 {
        return Err(NtStatus::STATUS_INVALID_PARAMETER);
    }

    let Some(parent_init) = &shim.init_state else {
        return Err(NtStatus::STATUS_UNSUCCESSFUL);
    };

    // Allocate thread ID.
    let tid = {
        let mut id = shim.shared.next_thread_id.lock();
        let val = *id;
        *id = val + crate::peb_teb::SYNTHETIC_THREAD_ID_INCREMENT;
        val
    };

    // Allocate stack (1 MiB default, matching NtCreateThreadEx).
    let actual_stack_size: usize = 1024 * 1024;
    let pm = &shim.shared.process_state.pm;
    let nz_stack_size =
        litebox::mm::linux::NonZeroPageSize::<{ crate::PAGE_SIZE }>::new(actual_stack_size)
            .expect("stack size must be page-aligned");
    let stack_base_ptr = unsafe {
        pm.create_writable_pages(
            None,
            nz_stack_size,
            litebox::mm::linux::CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    };
    let stack_base = match stack_base_ptr {
        Ok(ptr) => ptr.as_usize(),
        Err(_) => return Err(NtStatus::STATUS_NO_MEMORY),
    };
    let stack_top = stack_base + actual_stack_size;
    let cleanup_stack = || {
        let stack_ptr = <litebox_platform_multiplex::Platform as RawPointerProvider>::RawMutPointer::<
            u8,
        >::from_usize(stack_base);
        let _ = unsafe { pm.remove_pages(stack_ptr, actual_stack_size) };
    };

    // Allocate TEB (2 pages).
    let nz_teb_size = litebox::mm::linux::NonZeroPageSize::<{ crate::PAGE_SIZE }>::new(0x2000)
        .expect("TEB size must be page-aligned");
    let teb_ptr = unsafe {
        pm.create_writable_pages(
            None,
            nz_teb_size,
            litebox::mm::linux::CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    };
    let child_teb_va = match teb_ptr {
        Ok(ptr) => ptr.as_usize(),
        Err(_) => {
            cleanup_stack();
            return Err(NtStatus::STATUS_NO_MEMORY);
        }
    };
    let cleanup_stack_and_teb = || {
        let teb_ptr = <litebox_platform_multiplex::Platform as RawPointerProvider>::RawMutPointer::<
            u8,
        >::from_usize(child_teb_va);
        let _ = unsafe { pm.remove_pages(teb_ptr, 0x2000) };
        cleanup_stack();
    };

    // Initialize TEB from scratch — same as NtCreateThreadEx.
    let parent_teb_va = parent_init.teb_va;
    unsafe {
        core::ptr::write_bytes(child_teb_va as *mut u8, 0, 0x2000);

        // NtTib.ExceptionList = -1
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::EXCEPTION_LIST) as *mut u64,
            u64::MAX,
        );
        // NtTib.StackBase
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::STACK_BASE) as *mut usize,
            stack_top,
        );
        // NtTib.StackLimit
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::STACK_LIMIT) as *mut usize,
            stack_base,
        );
        // NtTib.Self
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::SELF) as *mut usize,
            child_teb_va,
        );
        // ClientId.UniqueProcess
        if parent_teb_va != 0 {
            let parent_pid: u64 = core::ptr::read(
                (parent_teb_va + crate::peb_teb::teb_offsets::CLIENT_ID_PROCESS) as *const u64,
            );
            core::ptr::write(
                (child_teb_va + crate::peb_teb::teb_offsets::CLIENT_ID_PROCESS) as *mut u64,
                parent_pid,
            );
        }
        // ClientId.UniqueThread
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::CLIENT_ID_THREAD) as *mut u64,
            u64::from(tid),
        );
        // ProcessEnvironmentBlock
        if parent_teb_va != 0 {
            let peb_ptr: u64 = core::ptr::read(
                (parent_teb_va + crate::peb_teb::teb_offsets::PEB_PTR) as *const u64,
            );
            core::ptr::write(
                (child_teb_va + crate::peb_teb::teb_offsets::PEB_PTR) as *mut u64,
                peb_ptr,
            );
        }
        // DeallocationStack
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::DEALLOCATION_STACK) as *mut usize,
            stack_base,
        );
        // GuaranteedStackBytes
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::GUARANTEED_STACK_BYTES) as *mut u64,
            0x1000,
        );
    }

    // Set up entry point — use LdrInitializeThunk path if available.
    let use_ldr_init_thunk =
        parent_init.ldr_init_thunk_va != 0 && parent_init.rtl_user_thread_start_va != 0;

    let (child_effective_stack_top, child_entry_point, child_initial_rcx, child_initial_rdx) =
        if use_ldr_init_thunk {
            const CONTEXT_SIZE: usize = 0x4D0;
            const CONTEXT_FULL: u32 = 0x10_000B;

            let sentinel_rsp = initial_child_thread_rsp(stack_top);
            unsafe {
                core::ptr::write(sentinel_rsp as *mut usize, THREAD_EXIT_SENTINEL);
            }

            let context_va = (sentinel_rsp - CONTEXT_SIZE) & !0xF;
            let default_fp = litebox_common_linux::FpRegs::default();
            unsafe {
                core::ptr::write_bytes(context_va as *mut u8, 0, CONTEXT_SIZE);
                core::ptr::write_unaligned((context_va + 0x30) as *mut u32, CONTEXT_FULL);
                core::ptr::write_unaligned((context_va + 0x44) as *mut u32, 0x202);
                core::ptr::write_unaligned((context_va + 0x38) as *mut u16, 0x33);
                core::ptr::write_unaligned((context_va + 0x42) as *mut u16, 0x2B);
                // Rcx = StartRoutine
                core::ptr::write_unaligned((context_va + 0x80) as *mut u64, start_routine as u64);
                // Rdx = StartParameter
                core::ptr::write_unaligned((context_va + 0x88) as *mut u64, start_parameter as u64);
                // Rsp
                let post_init_rsp = sentinel_rsp as u64;
                core::ptr::write_unaligned((context_va + 0x98) as *mut u64, post_init_rsp);
                // Rip = RtlUserThreadStart
                core::ptr::write_unaligned(
                    (context_va + 0xF8) as *mut u64,
                    parent_init.rtl_user_thread_start_va as u64,
                );
                // FP/SIMD state
                core::ptr::copy_nonoverlapping(
                    default_fp.data[24..28].as_ptr(),
                    (context_va + 0x34) as *mut u8,
                    4,
                );
                core::ptr::copy_nonoverlapping(
                    default_fp.data.as_ptr(),
                    (context_va + 0x100) as *mut u8,
                    512,
                );
            }

            let ldr_rsp = context_va - 0x28;
            let ntdll_base = parent_init
                .module_bases
                .iter()
                .find(|m| {
                    m.name.eq_ignore_ascii_case("ntdll.dll") || m.name.eq_ignore_ascii_case("ntdll")
                })
                .map_or(0, |m| m.base_address);

            (
                ldr_rsp,
                parent_init.ldr_init_thunk_va,
                context_va,
                ntdll_base,
            )
        } else {
            let rsp = initial_child_thread_rsp(stack_top);
            unsafe {
                core::ptr::write(rsp as *mut usize, THREAD_EXIT_SENTINEL);
            }
            if parent_init.rtl_user_thread_start_va != 0 {
                (
                    rsp,
                    parent_init.rtl_user_thread_start_va,
                    start_routine,
                    start_parameter,
                )
            } else {
                (rsp, start_routine, start_parameter, 0)
            }
        };

    // Create ThreadObject and child shim.
    let thread_obj = Arc::new(ThreadObject::new(tid, 0, child_teb_va));
    let child_shim = NtShimEntrypoints::new_for_child_thread(
        Arc::clone(&shim.shared),
        Arc::clone(&thread_obj),
        tid,
        parent_init,
        child_entry_point,
        child_effective_stack_top,
        child_teb_va,
        child_initial_rcx,
        child_initial_rdx,
    );

    let child_ctx = litebox_common_linux::ExecutionContext::default();
    let init_args = Box::new(NtChildThreadInit {
        child_shim,
        child_teb_va,
        guest_va_start: parent_init.guest_va_start,
        guest_va_end: parent_init.guest_va_end,
    });

    // Spawn the thread.
    let platform = litebox_platform_multiplex::platform();
    shim.shared
        .threads_by_id
        .lock()
        .insert(tid, Arc::clone(&thread_obj));
    if unsafe { platform.spawn_thread(&child_ctx, init_args) }.is_err() {
        shim.shared.threads_by_id.lock().remove(&tid);
        cleanup_stack_and_teb();
        return Err(NtStatus::STATUS_NO_MEMORY);
    }

    // Insert thread handle (no user-mode handle needed, but the thread object
    // should be in the handle table for NtWaitForSingleObject etc.).
    shim.shared
        .handles
        .lock()
        .insert(NtObject::Thread(Arc::clone(&thread_obj)));

    {
        #[cfg(any(debug_assertions, feature = "trace_debug"))]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: spawn_worker_factory_thread -> tid={} start=0x{:X} param=0x{:X} teb=0x{:X}\n",
                tid, start_routine, start_parameter, child_teb_va,
            ));
        }
    }

    Ok(tid)
}

#[cfg(test)]
mod tests {
    use super::initial_child_thread_rsp;

    #[test]
    fn initial_child_thread_rsp_leaves_win64_shadow_space() {
        let stack_top = 0x1000usize;
        let rsp = initial_child_thread_rsp(stack_top);

        assert_eq!(rsp, 0xFD8);
        assert_eq!(rsp % 16, 8);
        assert!(rsp + 0x28 <= stack_top);
    }
}
