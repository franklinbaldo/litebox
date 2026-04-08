// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Minimal headless Win32k handlers for USER32/GDI initialization.
//!
//! The goal here is not to implement Win32k. We only provide enough for the
//! guest's real `win32u.dll` stubs to stay inside the NT shim so USER32/GDI
//! initialization does not fall through to host win32k callbacks.

use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
use litebox::platform::RawConstPointer as _;
use litebox_common_windows::ntstatus::NtStatus;
use litebox_common_windows::pe_parser::PeParsedFile;

use crate::{NtProcessState, PAGE_SIZE};

use super::NtSyscallArgs;

const STUB_PREFIX: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
const CFG_CHECK: [u8; 8] = [0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01];
const SYSCALL_TAIL: [u8; 5] = [0x75, 0x03, 0x0F, 0x05, 0xC3];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Win32kSyscallId {
    NtUserGetThreadState,
    NtUserProcessConnect,
    NtUserGetDpiForCurrentProcess,
    NtUserSetProcessDpiAwarenessContext,
    NtUserDisableProcessWindowFiltering,
    NtUserSetProcessMousewheelRoutingMode,
    NtUserLoadUserApiHook,
    NtUserRegisterWindowMessage,
    NtUserGetSystemMetrics,
    NtGdiInit,
    NtGdiInit2,
}

pub(crate) struct Win32kSyscallMap {
    table: Vec<Option<Win32kSyscallId>>,
}

impl Win32kSyscallMap {
    pub(crate) fn from_pairs(pairs: &[(u32, Win32kSyscallId)]) -> Self {
        let max_nr = pairs.iter().map(|(nr, _)| *nr).max().unwrap_or(0) as usize;
        let mut table = alloc::vec![None; max_nr + 1];
        for &(nr, id) in pairs {
            table[nr as usize] = Some(id);
        }
        Self { table }
    }

    #[inline]
    pub(crate) fn lookup(&self, raw_nr: u32) -> Option<Win32kSyscallId> {
        self.table.get(raw_nr as usize).copied().flatten()
    }
}

pub(crate) fn build_win32k_syscall_map(parsed: &PeParsedFile, pe_data: &[u8]) -> Win32kSyscallMap {
    let mut pairs = Vec::new();

    for export in parsed.exports(pe_data) {
        let Some(name) = export.name else {
            continue;
        };
        let Some(id) = name_to_win32k_syscall_id(name) else {
            continue;
        };
        if export.forwarder.is_some() {
            continue;
        }
        let Some(raw_nr) = read_win32k_stub_number(parsed, pe_data, export.rva) else {
            continue;
        };
        pairs.push((raw_nr, id));
    }

    Win32kSyscallMap::from_pairs(&pairs)
}

fn name_to_win32k_syscall_id(name: &str) -> Option<Win32kSyscallId> {
    let id = match name {
        "NtUserGetThreadState" => Win32kSyscallId::NtUserGetThreadState,
        "NtUserProcessConnect" => Win32kSyscallId::NtUserProcessConnect,
        "NtUserGetDpiForCurrentProcess" => Win32kSyscallId::NtUserGetDpiForCurrentProcess,
        "NtUserSetProcessDpiAwarenessContext" => {
            Win32kSyscallId::NtUserSetProcessDpiAwarenessContext
        }
        "NtUserDisableProcessWindowFiltering" => {
            Win32kSyscallId::NtUserDisableProcessWindowFiltering
        }
        "NtUserSetProcessMousewheelRoutingMode" => {
            Win32kSyscallId::NtUserSetProcessMousewheelRoutingMode
        }
        "NtUserLoadUserApiHook" => Win32kSyscallId::NtUserLoadUserApiHook,
        "NtUserRegisterWindowMessage" => Win32kSyscallId::NtUserRegisterWindowMessage,
        "NtUserGetSystemMetrics" => Win32kSyscallId::NtUserGetSystemMetrics,
        "NtGdiInit" => Win32kSyscallId::NtGdiInit,
        "NtGdiInit2" => Win32kSyscallId::NtGdiInit2,
        _ => return None,
    };
    Some(id)
}

fn read_win32k_stub_number(parsed: &PeParsedFile, pe_data: &[u8], rva: u32) -> Option<u32> {
    let off = parsed.rva_to_file_offset(rva)?;
    let stub = pe_data.get(off..off + 21)?;
    if stub[0..4] != STUB_PREFIX || stub[8..16] != CFG_CHECK || stub[16..21] != SYSCALL_TAIL {
        return None;
    }
    Some(u32::from_le_bytes(stub[4..8].try_into().ok()?))
}

fn alloc_zeroed_user_region(
    process_state: &Arc<NtProcessState>,
    size: usize,
) -> Result<usize, NtStatus> {
    let Some(nz_size) = NonZeroPageSize::<PAGE_SIZE>::new(size) else {
        return Err(NtStatus::STATUS_NO_MEMORY);
    };

    let ptr = unsafe {
        process_state.pm.create_writable_pages(
            None,
            nz_size,
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    }
    .map_err(|_| NtStatus::STATUS_NO_MEMORY)?;

    let base = ptr.as_usize();
    process_state.track_section_view(base, size);
    Ok(base)
}

fn alloc_zeroed_user_page(process_state: &Arc<NtProcessState>) -> Result<usize, NtStatus> {
    alloc_zeroed_user_region(process_state, PAGE_SIZE)
}

fn ensure_user_thread_ready(
    process_state: &Arc<NtProcessState>,
    teb_va: usize,
) -> Result<(), NtStatus> {
    const WIN32_CLIENT_BASE_SIZE: usize = PAGE_SIZE * 2;
    const WIN32_CLIENT_DATA_OFFSET: usize = 0x10E0;
    const WIN32_CLIENT_BOUND: u32 = 0x0600;
    const WIN32_CLIENT_HINTS: u64 = 0x0000_0000_0409_0409;
    const WIN32_CLIENT_CACHE_18: u64 = 0x0000_0000_0003_6380;
    const WIN32_CLIENT_CACHE_20: u64 = 0x0000_0000_0000_8D10;
    const WIN32_CLIENT_CACHE_28: u64 = 0x0000_0000_0003_6380;
    const WIN32_CLIENT_CACHE_38: u64 = 0x0000_0000_0005_03B6;
    const WIN32_CLIENT_CACHE_48: u64 = 0x0008_0000_0000_0000;
    const WIN32_CLIENT_CACHE_58: u64 = 0x0000_0000_0000_0039;
    const WIN32_CLIENT_DATA_QWORD0: u64 = 0x0000_0000_0001_000C;
    const WIN32_CLIENT_DATA_QWORD8: u64 = WIN32_CLIENT_DATA_OFFSET as u64;

    if teb_va == 0 {
        return Err(NtStatus::STATUS_UNSUCCESSFUL);
    }

    let thread_info_addr = teb_va + crate::peb_teb::teb_offsets::WIN32_THREAD_INFO;
    let client_ptr_addr = teb_va + crate::peb_teb::teb_offsets::WIN32_CLIENT_INFO_PTR20;
    let client_base_addr = teb_va + crate::peb_teb::teb_offsets::WIN32_CLIENT_INFO_PTR28;

    let (existing_thread_info, existing_client_ptr, existing_client_base) = unsafe {
        // SAFETY: `teb_va` is the current thread's guest TEB base and points to a
        // writable user allocation that the shim owns for the lifetime of the thread.
        (
            core::ptr::read(thread_info_addr as *const u64),
            core::ptr::read(client_ptr_addr as *const u64),
            core::ptr::read(client_base_addr as *const u64),
        )
    };

    if existing_thread_info != 0 && existing_client_ptr != 0 && existing_client_base != 0 {
        return Ok(());
    }

    let thread_info_va = alloc_zeroed_user_page(process_state)?;
    let client_info_va = alloc_zeroed_user_page(process_state)?;
    let client_base_va = alloc_zeroed_user_region(process_state, WIN32_CLIENT_BASE_SIZE)?;

    unsafe {
        // SAFETY: The TEB and newly allocated USER pages belong to the current guest
        // process. USER32 only reads these fields after `NtUserGetThreadState(0xE)`
        // reports readiness, so seeding them here is the shim-owned lazy-init point.
        core::ptr::write(thread_info_addr as *mut u64, thread_info_va as u64);
        core::ptr::write(
            (teb_va + crate::peb_teb::teb_offsets::WIN32_CLIENT_INFO_QWORD0) as *mut u64,
            8,
        );
        core::ptr::write(
            (teb_va + crate::peb_teb::teb_offsets::WIN32_CLIENT_INFO_DWORD10) as *mut u32,
            WIN32_CLIENT_BOUND,
        );
        core::ptr::write(
            (teb_va + crate::peb_teb::teb_offsets::WIN32_CLIENT_INFO_DWORD14) as *mut u32,
            0,
        );
        core::ptr::write(
            (teb_va + crate::peb_teb::teb_offsets::WIN32_CLIENT_INFO_DWORD18) as *mut u32,
            0,
        );
        core::ptr::write(
            (teb_va + crate::peb_teb::teb_offsets::WIN32_CLIENT_INFO_DWORD1C) as *mut u32,
            0,
        );
        core::ptr::write(client_ptr_addr as *mut u64, client_info_va as u64);
        core::ptr::write(client_base_addr as *mut u64, client_base_va as u64);
        core::ptr::write(
            (teb_va + crate::peb_teb::teb_offsets::WIN32_CLIENT_INFO_DWORD38) as *mut u32,
            0,
        );
        core::ptr::write(
            (teb_va + crate::peb_teb::teb_offsets::WIN32_CLIENT_INFO_QWORD90) as *mut u64,
            WIN32_CLIENT_HINTS,
        );

        core::ptr::write(client_info_va as *mut u32, 4);
        core::ptr::write(
            (client_info_va + 0x08) as *mut u64,
            WIN32_CLIENT_DATA_OFFSET as u64,
        );
        core::ptr::write((client_info_va + 0x10) as *mut u32, 0);
        core::ptr::write((client_info_va + 0x18) as *mut u64, WIN32_CLIENT_CACHE_18);
        core::ptr::write((client_info_va + 0x20) as *mut u64, WIN32_CLIENT_CACHE_20);
        core::ptr::write((client_info_va + 0x28) as *mut u64, WIN32_CLIENT_CACHE_28);
        core::ptr::write((client_info_va + 0x38) as *mut u64, WIN32_CLIENT_CACHE_38);
        core::ptr::write((client_info_va + 0x40) as *mut u64, 1);
        core::ptr::write((client_info_va + 0x48) as *mut u64, WIN32_CLIENT_CACHE_48);
        core::ptr::write((client_info_va + 0x58) as *mut u64, WIN32_CLIENT_CACHE_58);

        // USER32/GDI helper wrappers treat `client_base + *(client_info+0x8)` as a
        // tiny metadata record, so seed the non-pointer scalars they probe there.
        core::ptr::write(
            client_base_va.wrapping_add(WIN32_CLIENT_DATA_OFFSET) as *mut u64,
            WIN32_CLIENT_DATA_QWORD0,
        );
        core::ptr::write(
            client_base_va.wrapping_add(WIN32_CLIENT_DATA_OFFSET + 0x08) as *mut u64,
            WIN32_CLIENT_DATA_QWORD8,
        );
    }

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: seeded USER thread state teb=0x{teb_va:X} win32_thread=0x{thread_info_va:X} \
client_info=0x{client_info_va:X} client_base=0x{client_base_va:X}\n",
        ));
    }

    Ok(())
}

/// `NtUserGetThreadState` gates parts of USER32 initialization.
///
/// The current guest USER32 path uses selector `0xE` as a lazy "Win32 thread
/// state is initialized" probe. Returning `1` is not enough: USER32
/// immediately starts reading `TEB.Win32ThreadInfo` and `TEB.Win32ClientInfo`.
pub(crate) fn nt_user_get_thread_state(
    ctx: &mut crate::ExecutionContext,
    process_state: &Arc<NtProcessState>,
    teb_va: usize,
) -> NtStatus {
    const THREAD_STATE_USER_READY: u32 = 0xE;

    let args = NtSyscallArgs::from_ctx(ctx);
    let selector = args.arg0 as u32;
    let (value, status) = match selector {
        THREAD_STATE_USER_READY => match ensure_user_thread_ready(process_state, teb_va) {
            Ok(()) => (1usize, NtStatus::STATUS_SUCCESS),
            Err(status) => (0usize, status),
        },
        _ => (0usize, NtStatus::STATUS_SUCCESS),
    };

    ctx.regs.rax = value;

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtUserGetThreadState(selector=0x{selector:X}) -> 0x{value:X}\n",
        ));
    }

    status
}

/// `NtUserProcessConnect` establishes the guest USER32 shared-info view.
pub(crate) fn nt_user_process_connect(
    ctx: &mut crate::ExecutionContext,
    process_state: &Arc<NtProcessState>,
) -> NtStatus {
    const USER_CONNECT_MIN_SIZE: usize = 0x20;

    let args = NtSyscallArgs::from_ctx(ctx);
    let user_connect_ptr = args.arg1;
    let user_connect_size = args.arg2;

    if user_connect_ptr == 0 || user_connect_size < USER_CONNECT_MIN_SIZE {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let shared_info_va = match alloc_zeroed_user_page(process_state) {
        Ok(va) => va,
        Err(status) => return status,
    };

    unsafe {
        core::ptr::write_bytes(user_connect_ptr as *mut u8, 0, user_connect_size);

        let buf = user_connect_ptr as *mut u64;
        core::ptr::write(buf, 0x0600);
        core::ptr::write(buf.add(1), shared_info_va as u64);
        core::ptr::write(buf.add(2), shared_info_va as u64);
        core::ptr::write(buf.add(3), shared_info_va as u64);

        let shared_info = shared_info_va as *mut u64;
        core::ptr::write(shared_info.add(1), (shared_info_va + 0x100) as u64);
    }

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtUserProcessConnect shared_info=0x{shared_info_va:X}\n",
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// `NtUserGetDpiForCurrentProcess` reports the process DPI used by USER32's
/// awareness helpers. A headless console sandbox behaves like the default
/// 96-DPI environment.
pub(crate) fn nt_user_get_dpi_for_current_process(ctx: &mut crate::ExecutionContext) -> NtStatus {
    const DEFAULT_PROCESS_DPI: usize = 96;

    ctx.regs.rax = DEFAULT_PROCESS_DPI;

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtUserGetDpiForCurrentProcess -> {DEFAULT_PROCESS_DPI}\n",
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// `NtUserSetProcessDpiAwarenessContext` applies USER32's normalized
/// awareness context. In the headless sandbox USER32 caches the chosen context
/// in user mode, so reporting success is sufficient.
pub(crate) fn nt_user_set_process_dpi_awareness_context(
    ctx: &mut crate::ExecutionContext,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let context = args.arg0 as isize;
    ctx.regs.rax = 1;

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtUserSetProcessDpiAwarenessContext(context=0x{context:X}) -> 1\n",
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// `NtUserDisableProcessWindowFiltering` only toggles GUI-only filtering
/// behavior. In the headless sandbox it is a success-shaped no-op.
pub(crate) fn nt_user_disable_process_window_filtering(
    ctx: &mut crate::ExecutionContext,
) -> NtStatus {
    ctx.regs.rax = 1;

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform()
            .debug_log_print("NT shim: NtUserDisableProcessWindowFiltering -> 1\n");
    }

    NtStatus::STATUS_SUCCESS
}

/// `NtUserSetProcessMousewheelRoutingMode` configures GUI input routing.
/// Console guests have no mouse-wheel routing, but USER32 treats a nonzero
/// result as success.
pub(crate) fn nt_user_set_process_mousewheel_routing_mode(
    ctx: &mut crate::ExecutionContext,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let mode = args.arg0 as u32;
    ctx.regs.rax = 1;

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtUserSetProcessMousewheelRoutingMode(mode={mode}) -> 1\n",
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// `NtUserLoadUserApiHook` lazily loads optional USER API hook state.
/// Returning zero keeps USER32 on the no-hook path without surfacing a hard
/// failure.
pub(crate) fn nt_user_load_user_api_hook(ctx: &mut crate::ExecutionContext) -> NtStatus {
    ctx.regs.rax = 0;

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform()
            .debug_log_print("NT shim: NtUserLoadUserApiHook -> 0\n");
    }

    NtStatus::STATUS_SUCCESS
}

/// `NtGdiInit2` returns a non-null per-process GDI shared section.
///
/// On real Windows the kernel maps a ~2 MB shared section that carries the
/// GDI handle-table, ETW trace handles and miscellaneous subsystem state.
/// `gdi32full!GdiDllInitialize` later reads entries at offsets up to
/// `0x180210+` via `pGdiSharedMemory`; if any of the checked slots are zero
/// the init fails.  We therefore allocate a region large enough to cover the
/// known offsets and seed the required entries with non-zero sentinels.
///
/// Additionally, `gdi32full!GdiProcessSetup` reads `PEB+0xF8`
/// (GdiSharedHandleTable) and sets `pGdiSharedMemory = base + 0x180000`.
/// We must write the shared section base to PEB+0xF8 so both paths converge
/// on the same allocation.
pub(crate) fn nt_gdi_init2(
    ctx: &mut crate::ExecutionContext,
    process_state: &Arc<NtProcessState>,
    teb_va: usize,
) -> NtStatus {
    // The largest known access is at 0x180210 + 21*8 = 0x180318.
    // Round up generously to 0x182000 (pages).
    const GDI_SHARED_SIZE: usize = 0x182000;

    let shared_va = match alloc_zeroed_user_region(process_state, GDI_SHARED_SIZE) {
        Ok(va) => va,
        Err(status) => return status,
    };

    // Seed the three table ranges that `gdi32full` probes during init:
    //   0x1800B0 + i*8  (main trace-handle table, indices 0..=21)
    //   0x180160 + i*8  (alternate trace-handle table)
    //   0x180210 + i*8  (extended subsystem table)
    // And single entries:
    //   0x180138  (fallback entry)
    //   0x1801E8  (fallback entry)
    // A non-zero sentinel of `1` satisfies the `cmp ..., 0 / je fail` checks
    // in `gdi32full!GdiDllInitialize` without being a valid function pointer.
    const SENTINEL: u64 = 1;
    unsafe {
        let base = shared_va as *mut u8;

        // Main table: 0x1800B0 + i*8 for i in 0..22
        for i in 0u64..22 {
            let off = 0x1800B0usize + (i as usize) * 8;
            core::ptr::write((base.add(off)) as *mut u64, SENTINEL);
        }

        // Alternate table: 0x180160 + i*8 for i in 0..22
        for i in 0u64..22 {
            let off = 0x180160usize + (i as usize) * 8;
            core::ptr::write((base.add(off)) as *mut u64, SENTINEL);
        }

        // Extended table: 0x180210 + i*8 for i in 0..22
        for i in 0u64..22 {
            let off = 0x180210usize + (i as usize) * 8;
            core::ptr::write((base.add(off)) as *mut u64, SENTINEL);
        }

        // Single fallback entries
        core::ptr::write((base.add(0x180138)) as *mut u64, SENTINEL);
        core::ptr::write((base.add(0x1801E8)) as *mut u64, SENTINEL);
    }

    // Write the shared section base to PEB.GdiSharedHandleTable (PEB+0xF8)
    // so that GdiProcessSetup can derive pGdiSharedMemory = base + 0x180000.
    if teb_va != 0 {
        unsafe {
            // SAFETY: TEB and PEB are writable guest allocations that the shim
            // owns for the lifetime of the process.
            let peb_va = core::ptr::read((teb_va + 0x60) as *const u64) as usize;
            if peb_va != 0 {
                core::ptr::write(
                    (peb_va + crate::peb_teb::peb_offsets::GDI_SHARED_HANDLE_TABLE) as *mut u64,
                    shared_va as u64,
                );
            }
        }
    }

    ctx.regs.rax = shared_va;

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtGdiInit2 shared=0x{shared_va:X} size=0x{GDI_SHARED_SIZE:X}\n",
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// `NtGdiInit` returns a non-null GDI shared-memory anchor.
pub(crate) fn nt_gdi_init(
    ctx: &mut crate::ExecutionContext,
    process_state: &Arc<NtProcessState>,
) -> NtStatus {
    let shared_va = match alloc_zeroed_user_page(process_state) {
        Ok(va) => va,
        Err(status) => return status,
    };

    ctx.regs.rax = shared_va;

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtGdiInit shared=0x{shared_va:X}\n",
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// `NtUserGetSystemMetrics` returns system metric values.
///
/// In the headless sandbox we return sensible defaults for well-known metrics.
/// Critically, `SM_CLEANBOOT` (67) must return `0` (normal boot) — libuv's
/// `uv__winsock_init()` skips `WSAStartup()` entirely when this returns `1`,
/// which breaks all networking.
pub(crate) fn nt_user_get_system_metrics(ctx: &mut crate::ExecutionContext) -> NtStatus {
    const SM_CLEANBOOT: u32 = 67;
    const SM_CXSCREEN: u32 = 0;
    const SM_CYSCREEN: u32 = 1;

    let args = NtSyscallArgs::from_ctx(ctx);
    let index = args.arg0 as u32;

    let value: usize = match index {
        SM_CLEANBOOT => 0, // Normal boot — critical for WinSock init
        SM_CXSCREEN => 1920,
        SM_CYSCREEN => 1080,
        _ => 0,
    };

    ctx.regs.rax = value;

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtUserGetSystemMetrics(index={index}) -> {value}\n",
        ));
    }

    NtStatus::STATUS_SUCCESS
}
