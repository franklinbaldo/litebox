// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Child process spawning for the Windows NT shim.
//!
//! Implements real process creation where each child gets its own VA partition
//! with a private ntdll, heap, and address space — avoiding the TEB corruption
//! that occurs when processes share a single ntdll/heap.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
use litebox::mm::PageManager;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION;
use litebox_common_windows::pe_loader::{load_pe, PeMemoryMapper, SectionPermissions};
use litebox_common_windows::pe_parser::PeParsedFile;
use litebox_platform_multiplex::Platform;

use crate::{
    handle_table::{HandleTable, NtObject, PipeBuffer, ProcessObject, ThreadObject},
    peb_teb::{build_peb_teb_bytes, PebTebLayout, PebTebParams},
    NtProcessState, NtSharedState, PAGE_SIZE, REAL_DLL_OFFSET, TRAMPOLINE_OFFSET,
};

/// Offset for PEB/TEB region relative to partition start.
/// Must match the runner's `PEB_TEB_OFFSET`.
const PEB_TEB_OFFSET: usize = 0x7E_FFF0_0000;

/// Guest stack size for child processes.
const CHILD_STACK_SIZE: usize = 0x0010_0000; // 1 MiB

// LDR hash table constants (must match runner).
const LDRP_HASH_BUCKET_COUNT: usize = 32;
const LIST_ENTRY_SIZE: usize = 16;
const LDR_HASH_LINKS_OFFSET: usize = 0x70;
const LDR_BASE_NAME_HASH_VALUE_OFFSET: usize = 0x108;

// --- Inline guest memory helpers (same as runner) ---

unsafe fn write_guest_usize(addr: usize, value: usize) {
    unsafe { (addr as *mut usize).write(value) };
}

unsafe fn write_guest_u32(addr: usize, value: u32) {
    unsafe { (addr as *mut u32).write(value) };
}

unsafe fn read_guest_u32(addr: usize) -> u32 {
    unsafe { (addr as *const u32).read() }
}

/// Result of spawning a child process.
pub(crate) struct SpawnResult {
    /// Handle to the child process object.
    pub process_handle: u32,
    /// Handle to the child's initial thread object.
    pub thread_handle: u32,
    /// Guest-visible process ID.
    pub process_id: u32,
    /// Guest-visible thread ID.
    pub thread_id: u32,
}

/// A PeMemoryMapper that maps into a child process's PageManager.
struct ChildPmMapper<'a> {
    pm: &'a PageManager<Platform, PAGE_SIZE>,
}

impl ChildPmMapper<'_> {
    fn pre_reserve(
        &self,
        va: usize,
        size: usize,
    ) -> Result<(), litebox_common_windows::pe_loader::PeLoadError> {
        use litebox_common_windows::pe_loader::PeLoadError;
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let addr = NonZeroAddress::<PAGE_SIZE>::new(va).ok_or(PeLoadError::MapFailed)?;
        let page_size = NonZeroPageSize::<PAGE_SIZE>::new(aligned).ok_or(PeLoadError::MapFailed)?;
        let flags = CreatePagesFlags::FIXED_ADDR
            | CreatePagesFlags::NOREPLACE
            | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
        unsafe {
            self.pm
                .create_writable_pages(Some(addr), page_size, flags, |_| Ok(0))
        }
        .map_err(|_| PeLoadError::MapFailed)?;
        Ok(())
    }
}

impl PeMemoryMapper for ChildPmMapper<'_> {
    fn map_section(
        &mut self,
        va: usize,
        data: &[u8],
        size: usize,
        perm: SectionPermissions,
    ) -> Result<(), litebox_common_windows::pe_loader::PeLoadError> {
        use litebox_common_windows::pe_loader::PeLoadError;
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if aligned == 0 {
            return Ok(());
        }
        // Pages are already committed-writable from pre_reserve().
        if !data.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), va as *mut u8, data.len());
            }
        }
        if data.len() < size {
            unsafe {
                core::ptr::write_bytes((va + data.len()) as *mut u8, 0, size - data.len());
            }
        }
        // Set proper page permissions — ntdll code sections need to be
        // executable BEFORE ntdll's loader runs (LdrInitializeThunk is in
        // ntdll itself). Without this, the child hits DEP violations.
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(va);
        match perm {
            SectionPermissions::ReadExecute => unsafe {
                self.pm.make_pages_executable(ptr, aligned)
            },
            SectionPermissions::ReadOnly => unsafe { self.pm.make_pages_readable(ptr, aligned) },
            SectionPermissions::ReadWrite => {
                // Already writable from pre_reserve — nothing to do.
                Ok(())
            }
        }
        .map_err(|_| PeLoadError::MapFailed)?;

        Ok(())
    }
}

/// Spawn a real child process in a new VA partition.
///
/// Creates a new address space, loads ntdll + the child EXE, builds PEB/TEB,
/// seeds the loader data structures, creates a child NtSharedState with
/// inherited pipe handles, and spawns a host thread to run the child.
pub(crate) fn spawn_child_process<FS: crate::NtShimFS>(
    parent_shared: &Arc<NtSharedState<FS>>,
    exe_path_nt: &str,
    command_line: &str,
    stdin_pipe: Option<Arc<PipeBuffer>>,
    stdout_pipe: Option<Arc<PipeBuffer>>,
    stderr_pipe: Option<Arc<PipeBuffer>>,
    env_strings_for_child: alloc::vec::Vec<alloc::string::String>,
) -> Result<SpawnResult, i32> {
    let boot_data = parent_shared
        .ntdll_boot_data
        .get()
        .ok_or(0xC000_0001u32 as i32)?; // STATUS_UNSUCCESSFUL

    let platform = litebox_platform_multiplex::platform();

    // ── Step 1: Create new VA partition ──────────────────────────
    use litebox::platform::AddressSpaceProvider;
    let child_as_id = platform
        .create_address_space()
        .map_err(|_| 0xC000_0017u32 as i32)?; // STATUS_NO_MEMORY
    let child_range = platform
        .address_space_range(child_as_id)
        .map_err(|_| 0xC000_0017u32 as i32)?;
    let child_va_start = child_range.start;
    let child_va_end = child_range.end;

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] Created child VA partition: 0x{child_va_start:X}..0x{child_va_end:X}\n"
        ));
    }

    // ── Step 2: Create child PageManager ─────────────────────────
    let child_pm = PageManager::new(&parent_shared.litebox, child_range);
    let child_process_state = Arc::new(NtProcessState::new(child_pm));

    // ── Step 3: Map ntdll into child partition ───────────────────
    let ntdll_load_va = child_va_start + REAL_DLL_OFFSET;
    let parsed = PeParsedFile::parse(&boot_data.image).map_err(|_| 0xC000_0001u32 as i32)?;
    let ntdll_image_size = parsed.size_of_image as usize;

    let mut mapper = ChildPmMapper {
        pm: &child_process_state.pm,
    };
    mapper
        .pre_reserve(ntdll_load_va, ntdll_image_size)
        .map_err(|_| 0xC000_0017u32 as i32)?;
    let ntdll_info = load_pe(&parsed, &boot_data.image, ntdll_load_va, &mut mapper)
        .map_err(|_| 0xC000_0001u32 as i32)?;

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] ntdll loaded at 0x{:X} (size=0x{:X})\n",
            ntdll_info.image_base,
            ntdll_info.image_size
        ));
    }

    // ── Step 4: Map trampoline ───────────────────────────────────
    let tramp_va = child_va_start + TRAMPOLINE_OFFSET;
    mapper
        .pre_reserve(tramp_va, PAGE_SIZE)
        .map_err(|_| 0xC000_0017u32 as i32)?;
    // Trampoline bytes already have the shim entry pointer written.
    unsafe {
        core::ptr::copy_nonoverlapping(
            boot_data.trampoline.as_ptr(),
            tramp_va as *mut u8,
            boot_data.trampoline.len().min(PAGE_SIZE),
        );
    }
    // Trampoline must be executable — it contains the syscall entry stub.
    {
        let tramp_ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(tramp_va);
        unsafe {
            child_process_state
                .pm
                .make_pages_executable(tramp_ptr, PAGE_SIZE)
        }
        .map_err(|_| 0xC000_0017u32 as i32)?;
    }

    // Store trampoline code VA for win32k stub patching.
    child_process_state.set_trampoline_code_va(tramp_va + 0x08);

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform()
            .debug_log_print(&alloc::format!("[spawn] Trampoline at 0x{tramp_va:X}\n"));
    }

    // ── Step 5: Make .mrdata writable ────────────────────────────
    for section in &parsed.sections {
        let name = core::str::from_utf8(&section.name)
            .unwrap_or("")
            .trim_end_matches('\0');
        if name == ".mrdata" {
            let start = ntdll_load_va + section.virtual_address as usize;
            let vsize = section.virtual_size.max(section.size_of_raw_data) as usize;
            let pages = (vsize + 0xFFF) & !0xFFF;
            unsafe {
                for off in (0..pages).step_by(0x1000) {
                    let addr = start + off;
                    let ptr = addr as *mut u8;
                    let mut old_protect: u32 = 0;
                    unsafe extern "system" {
                        fn VirtualProtect(
                            addr: *mut u8,
                            size: usize,
                            new_protect: u32,
                            old_protect: *mut u32,
                        ) -> i32;
                    }
                    VirtualProtect(
                        ptr,
                        0x1000,
                        0x04, /* PAGE_READWRITE */
                        &raw mut old_protect,
                    );
                }
            }
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "[spawn] Made .mrdata writable: 0x{start:X}..0x{:X}\n",
                    start + pages
                ));
            }
        }
    }

    // ── Step 6: Populate inverted function table ─────────────────
    if boot_data.inverted_function_table_rva != 0 {
        let ift_va = ntdll_load_va + boot_data.inverted_function_table_rva;
        if parsed.data_directories.len() > IMAGE_DIRECTORY_ENTRY_EXCEPTION {
            let exc_dir = &parsed.data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if exc_dir.virtual_address != 0 && exc_dir.size != 0 {
                let entry_va = ift_va + 0x10;
                let exc_dir_va = ntdll_load_va + exc_dir.virtual_address as usize;
                unsafe {
                    (entry_va as *mut u64).write(exc_dir_va as u64);
                    ((entry_va + 8) as *mut u64).write(ntdll_load_va as u64);
                    ((entry_va + 16) as *mut u32).write(parsed.size_of_image);
                    ((entry_va + 20) as *mut u32).write(exc_dir.size);
                }
            }
        }
        child_process_state.set_inverted_function_table_va(ift_va);
    }

    // Set ntdll exception-related VAs on child process state.
    child_process_state.set_rtl_dispatch_exception_va(
        if boot_data.rtl_dispatch_exception_rva != 0 {
            ntdll_load_va + boot_data.rtl_dispatch_exception_rva
        } else {
            0
        },
    );
    child_process_state.set_rtl_restore_context_va(if boot_data.rtl_restore_context_rva != 0 {
        ntdll_load_va + boot_data.rtl_restore_context_rva
    } else {
        0
    });
    child_process_state.set_zw_raise_exception_va(if boot_data.zw_raise_exception_rva != 0 {
        ntdll_load_va + boot_data.zw_raise_exception_rva
    } else {
        0
    });
    child_process_state.set_rtl_raise_status_va(if boot_data.rtl_raise_status_rva != 0 {
        ntdll_load_va + boot_data.rtl_raise_status_rva
    } else {
        0
    });

    // ── Step 7: Load child EXE from VFS ──────────────────────────
    // Resolve the NT path to a VFS path.
    let vfs_path = nt_path_to_vfs_path(exe_path_nt);
    let fs = parent_shared.fs.get().ok_or(0xC000_0001u32 as i32)?;

    let exe_data = read_vfs_file(&**fs, &vfs_path).map_err(|_| 0xC000_0034u32 as i32)?; // STATUS_OBJECT_NAME_NOT_FOUND

    let exe_parsed = PeParsedFile::parse(&exe_data).map_err(|_| 0xC000_0001u32 as i32)?;

    let preferred_base = exe_parsed.image_base as usize;
    let exe_base = if preferred_base >= child_va_start && preferred_base < child_va_end {
        preferred_base
    } else {
        (child_va_start + 0xFFFF) & !0xFFFF
    };

    mapper
        .pre_reserve(exe_base, exe_parsed.size_of_image as usize)
        .map_err(|_| 0xC000_0017u32 as i32)?;
    let exe_info = load_pe(&exe_parsed, &exe_data, exe_base, &mut mapper)
        .map_err(|_| 0xC000_0001u32 as i32)?;

    // Patch in-memory ImageBase to match actual load address (same as runner).
    // Headers are now ReadOnly after load_pe(), so temporarily make writable.
    unsafe {
        let hdr_ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(exe_base);
        let _ = child_process_state
            .pm
            .make_pages_writable(hdr_ptr, PAGE_SIZE);
        let pe_sig_off = *(exe_base as *const u32).byte_add(0x3C) as usize;
        let opt_hdr = exe_base + pe_sig_off + 0x18;
        let image_base_ptr = (opt_hdr + 0x18) as *mut u64;
        core::ptr::write(image_base_ptr, exe_base as u64);
        let _ = child_process_state
            .pm
            .make_pages_readable(hdr_ptr, PAGE_SIZE);
    }

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] Child EXE loaded at 0x{:X} (entry=0x{:X})\n",
            exe_info.image_base,
            exe_info.entry_point
        ));
    }

    // Register modules on child process state.
    let exe_base_name = exe_path_nt.rsplit('\\').next().unwrap_or("child.exe");
    let exe_full_path = nt_path_to_win32_path(exe_path_nt);
    let exe_dir_win32 = win32_path_directory(&exe_full_path);
    let exe_module = crate::ModuleBase {
        name: alloc::string::String::from(exe_base_name),
        path: exe_full_path.clone(),
        base_address: exe_info.image_base,
        image_size: exe_info.image_size,
    };
    let ntdll_module = crate::ModuleBase {
        name: alloc::string::String::from("ntdll.dll"),
        path: alloc::string::String::from("C:\\Windows\\System32\\ntdll.dll"),
        base_address: ntdll_info.image_base,
        image_size: ntdll_info.image_size,
    };
    child_process_state.register_module(exe_module.clone());
    child_process_state.track_image_mapping(exe_module.base_address, exe_module.image_size);
    child_process_state.register_module(ntdll_module.clone());
    child_process_state.track_image_mapping(ntdll_module.base_address, ntdll_module.image_size);

    // ── Step 8: Allocate child stack ─────────────────────────────
    let stack_size = NonZeroPageSize::<PAGE_SIZE>::new(CHILD_STACK_SIZE)
        .expect("stack size must be page-aligned");
    let stack_base_ptr = unsafe {
        child_process_state.pm.create_writable_pages(
            None,
            stack_size,
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    }
    .map_err(|_| 0xC000_0017u32 as i32)?;
    let stack_base = litebox::platform::RawConstPointer::as_usize(&stack_base_ptr);
    let stack_alloc_top = stack_base + CHILD_STACK_SIZE;

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] Child stack: base=0x{stack_base:X}, top=0x{stack_alloc_top:X}\n"
        ));
    }

    // ── Step 9: Create PEB/TEB ───────────────────────────────────
    let peb_teb_base = child_va_start + PEB_TEB_OFFSET;
    let peb_teb_layout = PebTebLayout::at_base(peb_teb_base);

    // Allocate a child process ID and thread ID.
    let child_pid = {
        let mut id = parent_shared.next_process_id.lock();
        let pid = *id;
        *id += 4;
        pid
    };
    let child_tid = child_pid + 4;

    // Read the host's API set map address from the host PEB.
    #[allow(clippy::cast_ptr_alignment)]
    let host_api_set_map: usize = unsafe {
        let host_peb: *const u8;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) host_peb, options(nostack, readonly));
        *host_peb.add(0x68).cast::<usize>()
    };

    // Allocate a zeroed GDI shared handle table for the child.
    const GDI_SHARED_SIZE: usize = 0x20_0000;
    let gdi_shared_va = {
        let nz_size = NonZeroPageSize::<PAGE_SIZE>::new(GDI_SHARED_SIZE)
            .expect("GDI shared size must be page-aligned");
        let ptr = unsafe {
            child_process_state.pm.create_writable_pages(
                None,
                nz_size,
                CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                |_| Ok(0),
            )
        }
        .map_err(|_| 0xC000_0017u32 as i32)?;
        litebox::platform::RawConstPointer::as_usize(&ptr)
    };

    let peb_teb_params = PebTebParams {
        stack_base: stack_alloc_top,
        stack_limit: stack_base,
        image_base: exe_info.image_base,
        image_size: exe_info.image_size,
        process_heap: 0, // ntdll creates the heap via RtlCreateHeap
        command_line_wide: command_line.encode_utf16().collect(),
        image_path_wide: alloc::format!("\\??\\{exe_full_path}")
            .encode_utf16()
            .collect(),
        exe_full_path: exe_full_path.encode_utf16().collect(),
        exe_base_name: alloc::string::String::from(exe_base_name)
            .encode_utf16()
            .collect(),
        current_directory_wide: {
            let cwd = parent_shared.current_directory.lock().clone();
            let mut cwd_wide: Vec<u16> = cwd.encode_utf16().collect();
            if !cwd.ends_with('\\') {
                cwd_wide.push(b'\\' as u16);
            }
            cwd_wide
        },
        stdin_handle: 0, // will be overwritten below
        stdout_handle: 0,
        stderr_handle: 0,
        ntdll_base: ntdll_info.image_base,
        ntdll_size: ntdll_info.image_size,
        process_id: u64::from(child_pid),
        thread_id: u64::from(child_tid),
        api_set_map: host_api_set_map,
        gdi_shared_handle_table: gdi_shared_va,
        env_strings: env_strings_for_child.clone(),
    };

    // ── Step 10: Create child NtSharedState ──────────────────────
    // Build the child's handle table with inherited pipe handles.
    let (mut child_handles, child_stdin_h, child_stdout_h, child_stderr_h) =
        HandleTable::with_stdio(parent_shared.litebox.clone());

    // Replace the default stdio with the pipe handles if provided.
    // IMPORTANT: HandleTable::insert() returns a NEW handle number (it never
    // reuses closed slots), so we must track the actual handle values and use
    // those in the PEB ProcessParameters — not the original with_stdio() values.
    let actual_stdin_h = if let Some(ref pipe) = stdin_pipe {
        child_handles.close(child_stdin_h);
        pipe.increment(false); // bump client reference count for child handle
        child_handles.insert(NtObject::Pipe {
            buffer: Arc::clone(pipe),
            is_server: false, // child reads from client end
            io_completion: None,
        })
    } else {
        child_stdin_h
    };
    let actual_stdout_h = if let Some(ref pipe) = stdout_pipe {
        child_handles.close(child_stdout_h);
        pipe.increment(false); // bump client reference count for child handle
        child_handles.insert(NtObject::Pipe {
            buffer: Arc::clone(pipe),
            is_server: false, // child writes to client (write) end
            io_completion: None,
        })
    } else {
        child_stdout_h
    };
    let actual_stderr_h = if let Some(ref pipe) = stderr_pipe {
        child_handles.close(child_stderr_h);
        pipe.increment(false); // bump client reference count for child handle
        child_handles.insert(NtObject::Pipe {
            buffer: Arc::clone(pipe),
            is_server: false, // child writes to client (write) end
            io_completion: None,
        })
    } else {
        child_stderr_h
    };

    // Build PEB/TEB bytes with the actual pipe handle values.
    let final_params = PebTebParams {
        stdin_handle: u64::from(actual_stdin_h),
        stdout_handle: u64::from(actual_stdout_h),
        stderr_handle: u64::from(actual_stderr_h),
        ..peb_teb_params
    };
    let peb_teb_bytes = build_peb_teb_bytes(&peb_teb_layout, &final_params);

    // Map PEB/TEB region.
    let peb_teb_size = NonZeroPageSize::<PAGE_SIZE>::new(peb_teb_layout.total_size)
        .expect("PEB/TEB size must be page-aligned");
    let peb_teb_addr =
        NonZeroAddress::<PAGE_SIZE>::new(peb_teb_base).expect("PEB/TEB base must be page-aligned");
    unsafe {
        child_process_state.pm.create_writable_pages(
            Some(peb_teb_addr),
            peb_teb_size,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |ptr| {
                ptr.copy_from_slice(0, &peb_teb_bytes)
                    .ok_or(litebox::mm::linux::MappingError::OutOfMemory)?;
                Ok(peb_teb_layout.total_size)
            },
        )
    }
    .map_err(|_| 0xC000_0017u32 as i32)?;

    // Clear LDRP_ENTRY_PROCESSED and LDRP_PROCESS_ATTACH_CALLED from the child's
    // EXE LDR_DATA_TABLE_ENTRY so ntdll's loader will walk the EXE's import table
    // and discover its dependent DLLs (e.g. python314.dll, VCRUNTIME140.dll).
    // The EXE entry sits at ldr_data_va + 0x60, flags field at +0x68 within it.
    unsafe {
        let exe_ldr_flags_va = (peb_teb_layout.ldr_data_va + 0x60 + 0x68) as *mut u32;
        let flags = core::ptr::read(exe_ldr_flags_va);
        let new_flags = flags & !(0x0000_4000u32 | 0x0008_0000u32);
        core::ptr::write(exe_ldr_flags_va, new_flags);
    }

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        let flags_after =
            unsafe { core::ptr::read((peb_teb_layout.ldr_data_va + 0x60 + 0x68) as *const u32) };
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] Cleared LDRP_ENTRY_PROCESSED on child EXE LDR entry, flags now=0x{flags_after:X}\n"
        ));

        // Dump the child EXE's import directory from the mapped PE.
        let img_base = exe_info.image_base;
        let pe_sig_off = unsafe { *(img_base as *const u32).byte_add(0x3C) } as usize;
        let opt_hdr = img_base + pe_sig_off + 0x18;
        let num_dd = unsafe { *((opt_hdr + 0x6C) as *const u32) } as usize;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] Child EXE import diag: img_base=0x{img_base:X}, pe_sig_off=0x{pe_sig_off:X}, num_data_dirs={num_dd}\n"
        ));
        if num_dd > 1 {
            // Import directory is data directory index 1
            let dd_base = opt_hdr + 0x70;
            let import_rva = unsafe { *((dd_base + 1 * 8) as *const u32) } as usize;
            let import_size = unsafe { *((dd_base + 1 * 8 + 4) as *const u32) } as usize;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "[spawn] Child EXE import dir: RVA=0x{import_rva:X}, size=0x{import_size:X}\n"
            ));
            if import_rva != 0 {
                let import_va = img_base + import_rva;
                // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes. Dump first few.
                for i in 0..8 {
                    let desc = import_va + i * 20;
                    let orig_ft = unsafe { *(desc as *const u32) } as usize;
                    let name_rva = unsafe { *((desc + 12) as *const u32) } as usize;
                    let first_thunk = unsafe { *((desc + 16) as *const u32) } as usize;
                    if orig_ft == 0 && name_rva == 0 && first_thunk == 0 {
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "[spawn]   import[{i}]: END (null terminator)\n"
                        ));
                        break;
                    }
                    let dll_name = if name_rva != 0 {
                        let name_ptr = (img_base + name_rva) as *const u8;
                        let mut name = alloc::string::String::new();
                        for j in 0..128 {
                            let b = unsafe { *name_ptr.add(j) };
                            if b == 0 {
                                break;
                            }
                            name.push(b as char);
                        }
                        name
                    } else {
                        alloc::string::String::from("<null>")
                    };
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "[spawn]   import[{i}]: name=\"{dll_name}\" orig_ft=0x{orig_ft:X} first_thunk=0x{first_thunk:X}\n"
                    ));
                }
            }
        }

        // Also dump the LDR entry DllBase to verify it matches
        let ldr_dll_base =
            unsafe { core::ptr::read((peb_teb_layout.ldr_data_va + 0x60 + 0x30) as *const u64) };
        let peb_image_base =
            unsafe { core::ptr::read((peb_teb_layout.peb_va + 0x10) as *const u64) };
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] LDR EXE DllBase=0x{ldr_dll_base:X}, PEB ImageBaseAddress=0x{peb_image_base:X}\n"
        ));
    }

    // ── Step 11: Seed LdrpHashTable + PebLdr ─────────────────────
    let pebldr_va = ntdll_load_va + boot_data.pebldr_rva;
    let ldrp_hash_table_va = ntdll_load_va + boot_data.ldrp_hash_table_rva;

    unsafe {
        // For the child, set up PebLdr with ONLY ntdll in the LDR list.
        // Do NOT add the EXE entry — let ntdll's LdrpInitializeProcess discover
        // the EXE from PEB->ImageBaseAddress and create its own LDR entry,
        // which triggers proper import table walking.
        init_child_pebldr(peb_teb_layout.peb_va, pebldr_va, peb_teb_layout.ldr_data_va);
        // Set LdrpImageEntry = NULL so ntdll knows it needs to create the EXE entry.
        init_child_loader_globals(pebldr_va, peb_teb_layout.ldr_data_va);
        // Only put ntdll in the hash table — not the EXE.
        init_child_loader_hash_table(ldrp_hash_table_va, peb_teb_layout.ldr_data_va);
    }

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] Seeded PebLdr=0x{pebldr_va:X}, HashTable=0x{ldrp_hash_table_va:X}\n"
        ));
    }

    // ── Step 12: Build CONTEXT for LdrInitializeThunk ────────────
    let ldr_init_va = ntdll_load_va + boot_data.ldr_init_thunk_rva;
    let rtl_uts_va = ntdll_load_va + boot_data.rtl_user_thread_start_rva;

    const CONTEXT_SIZE: usize = 0x4D0;
    const CONTEXT_FULL: u32 = 0x10_000B;

    let context_va = (stack_alloc_top - CONTEXT_SIZE) & !0xF;
    let ldr_rsp = context_va - 0x28;

    {
        let mut ctx_bytes = alloc::vec![0u8; CONTEXT_SIZE];
        let default_fp = litebox_common_linux::FpRegs::default();
        // ContextFlags at 0x30
        ctx_bytes[0x30..0x34].copy_from_slice(&CONTEXT_FULL.to_le_bytes());
        // EFlags at 0x44
        ctx_bytes[0x44..0x48].copy_from_slice(&0x202u32.to_le_bytes());
        // SegCs at 0x38
        ctx_bytes[0x38..0x3A].copy_from_slice(&0x33u16.to_le_bytes());
        // SegSs at 0x42
        ctx_bytes[0x42..0x44].copy_from_slice(&0x2Bu16.to_le_bytes());
        // Rcx = EXE entry point
        ctx_bytes[0x80..0x88].copy_from_slice(&(exe_info.entry_point as u64).to_le_bytes());
        // Rdx = 0 (thread parameter)
        ctx_bytes[0x88..0x90].copy_from_slice(&0u64.to_le_bytes());
        // Rsp (post-init stack)
        ctx_bytes[0x98..0xA0].copy_from_slice(&((context_va - 0x1F8) as u64).to_le_bytes());
        // Rip = RtlUserThreadStart
        ctx_bytes[0xF8..0x100].copy_from_slice(&(rtl_uts_va as u64).to_le_bytes());
        // FP/SIMD state
        ctx_bytes[0x34..0x38].copy_from_slice(&default_fp.data[24..28]);
        ctx_bytes[0x100..0x100 + 512].copy_from_slice(&default_fp.data[..512]);

        unsafe {
            core::ptr::copy_nonoverlapping(ctx_bytes.as_ptr(), context_va as *mut u8, CONTEXT_SIZE);
        }
    }

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] CONTEXT at 0x{context_va:X}, LdrInit=0x{ldr_init_va:X}, RSP=0x{ldr_rsp:X}\n"
        ));
    }

    // ── Step 13: Create child process/thread objects ─────────────
    let process_exit_code = Arc::new(core::sync::atomic::AtomicI32::new(259)); // STILL_ACTIVE
    let process_exit_requested = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let process_obj = Arc::new(ProcessObject::new_real(
        child_pid,
        Arc::clone(&process_exit_code),
        Arc::clone(&process_exit_requested),
        child_as_id,
    ));
    let thread_obj = Arc::new(ThreadObject::new(child_tid, 0, peb_teb_layout.teb_va));

    // Insert process and thread into parent's handle table.
    let (process_handle, thread_handle) = {
        let mut handles = parent_shared.handles.lock();
        let ph = handles.insert(NtObject::Process {
            state: Arc::clone(&process_obj),
        });
        let th = handles.insert(NtObject::Thread(Arc::clone(&thread_obj)));
        (ph, th)
    };

    // ── Step 14: Create child NtSharedState + NtShimEntrypoints ──
    let child_shared = Arc::new(NtSharedState {
        litebox: parent_shared.litebox.clone(),
        ntdll_boot_data: {
            let once = spin::Once::new();
            let _ = once.call_once(|| Arc::clone(boot_data));
            once
        },
        handles: spin::Mutex::new(child_handles),
        stdin_handle: actual_stdin_h,
        stdout_handle: actual_stdout_h,
        stderr_handle: actual_stderr_h,
        process_exit_requested: core::sync::atomic::AtomicBool::new(false),
        process_exit_code: core::sync::atomic::AtomicI32::new(0),
        process_state: Arc::clone(&child_process_state),
        tls_next: spin::Mutex::new(0),
        tls_free_list: spin::Mutex::new(Vec::new()),
        fls_next: spin::Mutex::new(0),
        fls_free_list: spin::Mutex::new(Vec::new()),
        unhandled_exception_filter: spin::Mutex::new(0),
        env_vars: spin::Mutex::new({
            // If the caller provided an explicit environment block, parse it.
            // Otherwise inherit the parent's environment variables.
            if env_strings_for_child.is_empty() {
                parent_shared.env_vars.lock().clone()
            } else {
                let mut m = alloc::collections::BTreeMap::new();
                for s in &env_strings_for_child {
                    if let Some(eq_pos) = s.find('=') {
                        let key = &s[..eq_pos];
                        let val = &s[eq_pos + 1..];
                        if !key.is_empty() {
                            m.insert(
                                alloc::string::String::from(key),
                                alloc::string::String::from(val),
                            );
                        }
                    }
                }
                m
            }
        }),
        env_block_pool: spin::Mutex::new(Vec::new()),
        current_directory: spin::Mutex::new(parent_shared.current_directory.lock().clone()),
        next_thread_id: spin::Mutex::new(child_tid + crate::peb_teb::SYNTHETIC_THREAD_ID_INCREMENT),
        threads_by_id: spin::Mutex::new({
            let mut m = alloc::collections::BTreeMap::new();
            m.insert(child_tid, Arc::clone(&thread_obj));
            m
        }),
        condition_variables: spin::Mutex::new(alloc::collections::BTreeMap::new()),
        dynamic_function_tables: spin::Mutex::new(alloc::collections::BTreeMap::new()),
        srw_locks: spin::Mutex::new(alloc::collections::BTreeMap::new()),
        net: {
            let once = spin::Once::new();
            if let Some(net) = parent_shared.net.get() {
                let _ = once.call_once(|| Arc::clone(net));
            }
            once
        },
        timer2_list: spin::Mutex::new(Vec::new()),

        console_input_pending: spin::Mutex::new(Vec::new()),
        // Share parent's NLS data with child via Arc clone.
        nls_data: {
            let once = spin::Once::new();
            if let Some(nls_arc) = parent_shared.nls_data.get() {
                let _ = once.call_once(|| alloc::sync::Arc::clone(nls_arc));
            }
            once
        },
        csr_state: spin::Mutex::new(crate::CsrState::default()),
        wnf_states: spin::Mutex::new({
            let mut m = alloc::collections::BTreeMap::new();
            m.insert(
                crate::WNF_STATE_FEATURE_CONFIGURATION,
                crate::WnfStateValue {
                    change_stamp: 0x35,
                    data: alloc::vec![0x35, 0, 0, 0, 0, 0, 0, 0],
                },
            );
            m
        }),
        nls_section_mappings: spin::Mutex::new(alloc::collections::BTreeMap::new()),
        trace_notification_event: spin::Mutex::new(None),
        etw_provider_traits_set: spin::Mutex::new(alloc::collections::BTreeSet::new()),
        default_hard_error_mode: core::sync::atomic::AtomicU32::new(0x8002),
        next_registered_msg_id: core::sync::atomic::AtomicU32::new(0xC000),
        fs: {
            let once = spin::Once::new();
            if let Some(fs) = parent_shared.fs.get() {
                let _ = once.call_once(|| Arc::clone(fs));
            }
            once
        },
        guest_va_start: core::sync::atomic::AtomicUsize::new(child_va_start),
        guest_va_end: core::sync::atomic::AtomicUsize::new(child_va_end),
        syscall_map: {
            let once = spin::Once::new();
            let _ = once.call_once(|| boot_data.syscall_map.clone());
            once
        },
        win32k_syscall_map: spin::Once::new(),
        unhandled_stubs: {
            let once = spin::Once::new();
            if !boot_data.unhandled_stubs.is_empty() {
                let _ = once.call_once(|| boot_data.unhandled_stubs.clone());
            }
            once
        },
        tls_templates: spin::Once::new(),
        thread_wakers: spin::Mutex::new(alloc::collections::BTreeMap::new()),
        thread_interrupt_handles: spin::Mutex::new(alloc::collections::BTreeMap::new()),
        live_child_thread_count: core::sync::atomic::AtomicU32::new(0),
        main_thread_id: child_tid,
        child_threads_terminated: core::sync::atomic::AtomicU32::new(0),
        child_threads_created: core::sync::atomic::AtomicU32::new(0),
        thread_last_syscall: core::array::from_fn(|_| core::sync::atomic::AtomicU32::new(0)),
        recent_alert_posts: spin::Mutex::new(alloc::collections::VecDeque::new()),
        recent_chain_events: spin::Mutex::new(alloc::collections::VecDeque::new()),
        guest_gs_breakpoint_probes: spin::Mutex::new(alloc::collections::BTreeMap::new()),
        recent_vm_teardowns: spin::Mutex::new(alloc::collections::VecDeque::new()),
        pipe_registry: spin::Mutex::new(alloc::collections::BTreeMap::new()),
        next_process_id: spin::Mutex::new(child_pid + 100),
        exe_directory_vfs: spin::Mutex::new(crate::win32_path_to_vfs_dir(exe_dir_win32)),
        // Child processes spawned with pipe redirections have no console.
        // This causes NtCreateFile for \Device\ConDrv\* to fail with
        // STATUS_INVALID_HANDLE, forcing the CRT to use the pipe handles
        // from ProcessParameters instead.
        has_console: stdin_pipe.is_none() && stdout_pipe.is_none() && stderr_pipe.is_none(),
    });

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] Child NtSharedState stdio: stdin_handle=0x{:X} stdout_handle=0x{:X} stderr_handle=0x{:X} has_console={}\n",
            child_shared.stdin_handle, child_shared.stdout_handle, child_shared.stderr_handle, child_shared.has_console,
        ));
    }

    // ── Step 15: Spawn child thread via InitThread pattern ───────
    let child_shim = crate::NtShimEntrypoints::new_for_child_process(
        Arc::clone(&child_shared),
        child_tid,
        peb_teb_layout.teb_va,
    );

    let child_ctx = litebox_common_linux::ExecutionContext::default();
    let init_args = Box::new(NtChildProcessInit {
        child_shim,
        child_teb_va: peb_teb_layout.teb_va,
        guest_va_start: child_va_start,
        guest_va_end: child_va_end,
        process_obj: Arc::clone(&process_obj),
        init_state: crate::NtInitState {
            entry_point: ldr_init_va,
            stack_top: ldr_rsp,
            teb_va: peb_teb_layout.teb_va,
            peb_va: peb_teb_layout.peb_va,
            image_base: exe_info.image_base,
            image_size: exe_info.image_size,
            process_params_va: peb_teb_layout.process_params_va,
            cmdline_ansi_va: 0,
            env_block_va: peb_teb_layout.env_block_va,
            module_bases: alloc::vec![
                crate::ModuleBase {
                    name: alloc::string::String::from(exe_base_name),
                    path: exe_full_path.clone(),
                    base_address: exe_info.image_base,
                    image_size: exe_info.image_size,
                },
                crate::ModuleBase {
                    name: alloc::string::String::from("ntdll.dll"),
                    path: alloc::string::String::from("C:\\Windows\\System32\\ntdll.dll"),
                    base_address: ntdll_info.image_base,
                    image_size: ntdll_info.image_size,
                },
            ],
            guest_va_start: child_va_start,
            guest_va_end: child_va_end,
            exe_path: exe_full_path.clone(),
            current_directory: parent_shared.current_directory.lock().clone(),
            initial_rcx: context_va,
            initial_rdx: ntdll_load_va,
            rtl_user_thread_start_va: rtl_uts_va,
            ldr_init_thunk_va: ldr_init_va,
            ki_user_exception_dispatcher_rva: boot_data.ki_user_exception_dispatcher_rva,
        },
    });

    use litebox::platform::ThreadProvider;
    if unsafe { platform.spawn_thread(&child_ctx, init_args) }.is_err() {
        // Spawning failed — remove handles from parent table.
        let mut handles = parent_shared.handles.lock();
        handles.close(process_handle);
        handles.close(thread_handle);
        return Err(0xC000_0017u32 as i32);
    }

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "[spawn] Child process spawned: pid={child_pid}, tid={child_tid}\n"
        ));
    }

    Ok(SpawnResult {
        process_handle,
        thread_handle,
        process_id: child_pid,
        thread_id: child_tid,
    })
}

// ── Child process InitThread implementation ─────────────────────

/// Carries the child process's shim, init state, and cleanup info.
/// Used with `platform.spawn_thread()` to start the child process's
/// main thread following the same pattern as `NtChildThreadInit` in thread.rs.
struct NtChildProcessInit<FS: crate::NtShimFS> {
    child_shim: crate::NtShimEntrypoints<FS>,
    child_teb_va: usize,
    guest_va_start: usize,
    guest_va_end: usize,
    process_obj: Arc<ProcessObject>,
    init_state: crate::NtInitState,
}

// Safety: All fields are Send — NtShimEntrypoints fields are Mutex/Arc/Atomic,
// ProcessObject is Arc-wrapped, NtInitState contains owned String/Vec.
unsafe impl<FS: crate::NtShimFS> Send for NtChildProcessInit<FS> {}

impl<FS: crate::NtShimFS> litebox::shim::InitThread for NtChildProcessInit<FS> {
    type ExecutionContext = litebox_common_linux::ExecutionContext;

    fn init(
        self: Box<Self>,
    ) -> Box<dyn litebox::shim::EnterShim<ExecutionContext = Self::ExecutionContext>> {
        // Set FS base for this host thread to point to the child TEB.
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            litebox_platform_windows_userland::WindowsUserland::set_guest_va_range(
                self.guest_va_start..self.guest_va_end,
            );
            litebox_platform_windows_userland::WindowsUserland::set_guest_teb_base(
                self.child_teb_va as u64,
            );
        }

        // Destructure to move fields out individually.
        let NtChildProcessInit {
            mut child_shim,
            process_obj,
            init_state,
            ..
        } = *self;

        // Set the init state so EnterShim::init() knows how to configure registers.
        child_shim.set_init_state(init_state);

        // Wrap in ChildProcessShim to add exit-cleanup logic.
        Box::new(ChildProcessShim {
            inner: child_shim,
            process_obj,
        })
    }
}

/// Wrapper around `NtShimEntrypoints` that adds child-process exit cleanup.
///
/// When the child process terminates, `thread_terminated()` sets the exit code
/// on the `ProcessObject` so the parent can observe it via NtWaitForSingleObject.
struct ChildProcessShim<FS: crate::NtShimFS> {
    inner: crate::NtShimEntrypoints<FS>,
    process_obj: Arc<ProcessObject>,
}

impl<FS: crate::NtShimFS> litebox::shim::EnterShim for ChildProcessShim<FS> {
    type ExecutionContext = litebox_common_linux::ExecutionContext;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> litebox::shim::ContinueOperation {
        self.inner.init(ctx)
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> litebox::shim::ContinueOperation {
        self.inner.syscall(ctx)
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> litebox::shim::ContinueOperation {
        self.inner.exception(ctx, info)
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> litebox::shim::ContinueOperation {
        self.inner.interrupt(ctx)
    }

    fn thread_terminated(&self) {
        // Retrieve the child's exit code and signal the ProcessObject.
        let exit_code = self.inner.exit_code();

        #[cfg(any(debug_assertions, feature = "trace_debug"))]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "[spawn] Child process exited with code {exit_code}\n"
            ));
        }

        // Close all handles the child held (files, sockets, pipes, etc.).
        // This ensures the parent's blocking reads will see EOF when the child
        // exits, even for pipe handles created during the child's lifetime
        // (e.g. ConDrv->Pipe redirects).
        //
        // This MUST happen BEFORE signaling the process object because real
        // Windows closes all handles (breaking pipes) before the process object
        // becomes signaled. The parent may rely on pipe EOF arriving before
        // the process-exit notification.
        {
            let mut handles = self.inner.shared.handles.lock();
            handles.close_all();
        }

        // Now signal the process as exited. This wakes NtWaitForSingleObject
        // waiters and fires any NtAssociateWaitCompletionPacket IOCP entries.
        self.process_obj.set_exit_code(exit_code);

        // Clean up the child thread's per-thread resources (stack, TEB).
        self.inner.cleanup_current_thread_resources();

        // Release all committed pages in the child's VA partition, then
        // free the partition slot so it can be reused by future children.
        let address_space_id = self.process_obj.address_space_id;
        if address_space_id != 0 {
            // Safety: the child process has exited and all its threads have
            // terminated. No guest code can access these pages any more.
            let pm = &self.inner.shared.process_state.pm;
            if let Err(_e) = unsafe { pm.release_memory(|_, _| true) } {
                #[cfg(any(debug_assertions, feature = "trace_debug"))]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "[spawn] Warning: pm.release_memory() failed for child AS {address_space_id}\n"
                    ));
                }
            }

            use litebox::platform::AddressSpaceProvider;
            if let Err(_e) =
                litebox_platform_multiplex::platform().destroy_address_space(address_space_id)
            {
                #[cfg(any(debug_assertions, feature = "trace_debug"))]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "[spawn] Warning: destroy_address_space({address_space_id}) failed\n"
                    ));
                }
            } else {
                #[cfg(any(debug_assertions, feature = "trace_debug"))]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "[spawn] Freed child VA partition (AS {address_space_id})\n"
                    ));
                }
            }
        }
    }
}

// --- LDR seeding helpers (same as runner) ---

unsafe fn init_ntdll_pebldr(peb_va: usize, pebldr_va: usize, ldr_data_va: usize) {
    let exe_entry_va = ldr_data_va + 0x60;
    let ntdll_entry_va = ldr_data_va + 0x180;
    let head_load = pebldr_va + 0x10;
    let head_mem = pebldr_va + 0x20;
    let head_init = pebldr_va + 0x30;

    unsafe {
        write_guest_usize(peb_va + 0x18, pebldr_va);
        write_guest_u32(pebldr_va, 0x58);
        write_guest_u32(pebldr_va + 0x04, 1);
        write_guest_usize(pebldr_va + 0x08, 0);

        write_guest_usize(exe_entry_va, ntdll_entry_va);
        write_guest_usize(exe_entry_va + 0x08, head_load);
        write_guest_usize(exe_entry_va + 0x10, ntdll_entry_va + 0x10);
        write_guest_usize(exe_entry_va + 0x18, head_mem);

        write_guest_usize(ntdll_entry_va, head_load);
        write_guest_usize(ntdll_entry_va + 0x08, exe_entry_va);
        write_guest_usize(ntdll_entry_va + 0x10, head_mem);
        write_guest_usize(ntdll_entry_va + 0x18, exe_entry_va + 0x10);
        write_guest_usize(ntdll_entry_va + 0x20, head_init);
        write_guest_usize(ntdll_entry_va + 0x28, head_init);

        write_guest_usize(head_load, exe_entry_va);
        write_guest_usize(head_load + 8, ntdll_entry_va);
        write_guest_usize(head_mem, exe_entry_va + 0x10);
        write_guest_usize(head_mem + 8, ntdll_entry_va + 0x10);
        write_guest_usize(head_init, ntdll_entry_va + 0x20);
        write_guest_usize(head_init + 8, ntdll_entry_va + 0x20);
    }
}

/// Child-specific: set up PebLdr with ONLY ntdll in the load/memory/init-order
/// lists.  The EXE entry is deliberately omitted so ntdll's `LdrpInitializeProcess`
/// will discover the EXE from `PEB->ImageBaseAddress` and create its own LDR entry,
/// triggering full import-table resolution.
unsafe fn init_child_pebldr(peb_va: usize, pebldr_va: usize, ldr_data_va: usize) {
    let ntdll_entry_va = ldr_data_va + 0x180;
    let head_load = pebldr_va + 0x10;
    let head_mem = pebldr_va + 0x20;
    let head_init = pebldr_va + 0x30;

    unsafe {
        // PEB->Ldr
        write_guest_usize(peb_va + 0x18, pebldr_va);
        // PEB_LDR_DATA: Length, Initialized, SsHandle
        write_guest_u32(pebldr_va, 0x58);
        write_guest_u32(pebldr_va + 0x04, 1);
        write_guest_usize(pebldr_va + 0x08, 0);

        // InLoadOrderModuleList: head <-> ntdll <-> head
        write_guest_usize(ntdll_entry_va, head_load); // ntdll.Flink -> head
        write_guest_usize(ntdll_entry_va + 0x08, head_load); // ntdll.Blink -> head
        write_guest_usize(head_load, ntdll_entry_va); // head.Flink -> ntdll
        write_guest_usize(head_load + 8, ntdll_entry_va); // head.Blink -> ntdll

        // InMemoryOrderModuleList: head <-> ntdll+0x10 <-> head
        write_guest_usize(ntdll_entry_va + 0x10, head_mem);
        write_guest_usize(ntdll_entry_va + 0x18, head_mem);
        write_guest_usize(head_mem, ntdll_entry_va + 0x10);
        write_guest_usize(head_mem + 8, ntdll_entry_va + 0x10);

        // InInitializationOrderModuleList: head <-> ntdll+0x20 <-> head
        write_guest_usize(ntdll_entry_va + 0x20, head_init);
        write_guest_usize(ntdll_entry_va + 0x28, head_init);
        write_guest_usize(head_init, ntdll_entry_va + 0x20);
        write_guest_usize(head_init + 8, ntdll_entry_va + 0x20);
    }
}

unsafe fn init_ntdll_loader_globals(pebldr_va: usize, ldr_data_va: usize) {
    let exe_entry_va = ldr_data_va + 0x60;
    let ntdll_entry_va = ldr_data_va + 0x180;
    let ldrp_image_entry_va = pebldr_va - 0x118;
    let ldrp_ntdll_entry_va = pebldr_va + 0x58;

    unsafe {
        write_guest_usize(ldrp_image_entry_va, exe_entry_va);
        write_guest_usize(ldrp_ntdll_entry_va, ntdll_entry_va);
    }
}

/// Child-specific: set LdrpImageEntry = NULL so ntdll creates the EXE entry,
/// and set LdrpNtDllDataTableEntry = ntdll entry as usual.
unsafe fn init_child_loader_globals(pebldr_va: usize, ldr_data_va: usize) {
    let ntdll_entry_va = ldr_data_va + 0x180;
    let ldrp_image_entry_va = pebldr_va - 0x118;
    let ldrp_ntdll_entry_va = pebldr_va + 0x58;

    unsafe {
        write_guest_usize(ldrp_image_entry_va, 0); // NULL — let ntdll discover the EXE
        write_guest_usize(ldrp_ntdll_entry_va, ntdll_entry_va);
    }
}

unsafe fn init_ntdll_loader_hash_table(hash_table_va: usize, ldr_data_va: usize) {
    for bucket in 0..LDRP_HASH_BUCKET_COUNT {
        let head = hash_table_va + bucket * LIST_ENTRY_SIZE;
        unsafe {
            write_guest_usize(head, head);
            write_guest_usize(head + 8, head);
        }
    }

    for entry_va in [ldr_data_va + 0x60, ldr_data_va + 0x180] {
        let hash = unsafe { read_guest_u32(entry_va + LDR_BASE_NAME_HASH_VALUE_OFFSET) } as usize;
        let head = hash_table_va + (hash & (LDRP_HASH_BUCKET_COUNT - 1)) * LIST_ENTRY_SIZE;
        let hash_links = entry_va + LDR_HASH_LINKS_OFFSET;
        let tail = unsafe { (head as *const usize).add(1).read() };
        unsafe {
            write_guest_usize(hash_links, head);
            write_guest_usize(hash_links + 8, tail);
            write_guest_usize(tail, hash_links);
            write_guest_usize(head + 8, hash_links);
        }
    }
}

/// Child-specific: only insert ntdll into the hash table, not the EXE.
unsafe fn init_child_loader_hash_table(hash_table_va: usize, ldr_data_va: usize) {
    for bucket in 0..LDRP_HASH_BUCKET_COUNT {
        let head = hash_table_va + bucket * LIST_ENTRY_SIZE;
        unsafe {
            write_guest_usize(head, head);
            write_guest_usize(head + 8, head);
        }
    }

    // Only ntdll entry (at ldr_data_va + 0x180).
    let entry_va = ldr_data_va + 0x180;
    let hash = unsafe { read_guest_u32(entry_va + LDR_BASE_NAME_HASH_VALUE_OFFSET) } as usize;
    let head = hash_table_va + (hash & (LDRP_HASH_BUCKET_COUNT - 1)) * LIST_ENTRY_SIZE;
    let hash_links = entry_va + LDR_HASH_LINKS_OFFSET;
    let tail = unsafe { (head as *const usize).add(1).read() };
    unsafe {
        write_guest_usize(hash_links, head);
        write_guest_usize(hash_links + 8, tail);
        write_guest_usize(tail, hash_links);
        write_guest_usize(head + 8, hash_links);
    }
}

// --- Helper to convert NT paths to Win32 paths ---

/// Convert an NT path like `\??\C:\Users\foo\python.exe` to a Win32 path
/// like `C:\Users\foo\python.exe`.
fn nt_path_to_win32_path(nt_path: &str) -> alloc::string::String {
    let path = nt_path
        .strip_prefix("\\??\\")
        .or_else(|| nt_path.strip_prefix("\\\\?\\"))
        .unwrap_or(nt_path);
    alloc::string::String::from(path)
}

/// Extract the directory portion of a Win32 path.
/// e.g. `C:\Users\foo\python.exe` → `C:\Users\foo`
fn win32_path_directory(path: &str) -> &str {
    path.rfind('\\').map_or(path, |i| &path[..i])
}

// --- Helper to convert NT paths to VFS paths ---

fn nt_path_to_vfs_path(nt_path: &str) -> alloc::string::String {
    // NT paths like \??\C:\Windows\System32\cmd.exe
    // or \\?\C:\path or C:\path
    let path = nt_path
        .strip_prefix("\\??\\")
        .or_else(|| nt_path.strip_prefix("\\\\?\\"))
        .unwrap_or(nt_path);

    // Convert C:\foo\bar → /c/foo/bar
    let mut vfs = alloc::string::String::with_capacity(path.len() + 1);
    vfs.push('/');
    for ch in path.chars() {
        if ch == '\\' {
            vfs.push('/');
        } else {
            // Lowercase drive letter
            for lc in ch.to_lowercase() {
                vfs.push(lc);
            }
        }
    }
    // Remove the colon after drive letter: /c:/foo → /c/foo
    if vfs.len() >= 3 && vfs.as_bytes()[2] == b':' {
        vfs.remove(2);
    }
    vfs
}

/// Read a file from VFS into a Vec<u8>.
fn read_vfs_file<FS: crate::NtShimFS>(fs: &FS, path: &str) -> Result<Vec<u8>, i32> {
    use litebox::fs::FileSystem as _;

    let fd = fs
        .open(path, litebox::fs::OFlags::RDONLY, litebox::fs::Mode::RUSR)
        .map_err(|_| -1)?;

    // Get file size by seeking to end.
    let size = fs
        .seek(&fd, 0, litebox::fs::SeekWhence::RelativeToEnd)
        .map_err(|_| -1)?;
    // Seek back to start.
    let _ = fs.seek(&fd, 0, litebox::fs::SeekWhence::RelativeToBeginning);

    let mut data = alloc::vec![0u8; size];
    let mut offset = 0;
    while offset < size {
        let n = fs.read(&fd, &mut data[offset..], None).map_err(|_| -1)?;
        if n == 0 {
            break;
        }
        offset += n;
    }
    let _ = fs.close(&fd);
    Ok(data)
}
