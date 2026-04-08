// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Real-DLL loader for the Windows userland runner.
//!
//! Loads real System32 DLLs (ntdll.dll with rewritten syscalls,
//! kernel32.dll, ucrtbase.dll, etc.) from a pre-built tar file into
//! the guest address space. The ntdll syscall stubs are rewritten
//! to jump to the litebox shim, while all other DLL code runs
//! natively — matching the Linux approach where real shared libraries
//! run unmodified and only the syscall entry points are intercepted.

use crate::PmMapper;

use anyhow::{Result, anyhow};
use litebox_common_windows::ntdll_rewriter;
use litebox_common_windows::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION;
use litebox_common_windows::pe_loader::load_pe;
use litebox_common_windows::pe_parser::PeParsedFile;

/// Offset for the real-DLL region relative to the guest partition start.
/// Placed high enough to leave ample room below for regular guest mappings.
pub const REAL_DLL_OFFSET: usize = 0x7F_0000_0000;

/// Offset for the ntdll syscall trampoline relative to partition start.
/// Placed just below the DLL region to avoid 64KB alignment conflicts.
const TRAMPOLINE_OFFSET: usize = REAL_DLL_OFFSET - 0x1_0000;

/// Read an entire file from VFS into a `Vec<u8>`.
///
/// Opens the file at `path`, queries its size, reads it, and closes the fd.
pub fn read_vfs_file(fs: &litebox_shim_windows::NtFS, path: &str) -> Result<Vec<u8>> {
    use litebox::fs::FileSystem as _;

    let fd = fs
        .open(path, litebox::fs::OFlags::RDONLY, litebox::fs::Mode::RUSR)
        .map_err(|e| anyhow!("VFS open {path:?}: {e:?}"))?;
    let size = fs.fd_file_status(&fd).map(|s| s.size).unwrap_or(0);
    let mut buf = vec![0u8; size];
    let n = fs.read(&fd, &mut buf, None).unwrap_or(0);
    buf.truncate(n);
    let _ = fs.close(&fd);
    if buf.is_empty() {
        return Err(anyhow!("VFS file {path:?} is empty or unreadable"));
    }
    Ok(buf)
}

/// Find a file in VFS by its basename (case-insensitive) under `dir_path`.
///
/// Lists the directory entries and returns the full VFS path of the first
/// file whose name matches `target_name` (case-insensitive).
pub fn find_vfs_file(
    fs: &litebox_shim_windows::NtFS,
    dir_path: &str,
    target_name: &str,
) -> Option<String> {
    use litebox::fs::FileSystem as _;

    let fd = fs
        .open(
            dir_path,
            litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
            litebox::fs::Mode::RUSR,
        )
        .ok()?;
    let entries = fs.read_dir(&fd).ok()?;
    let _ = fs.close(&fd);

    let target_lower = target_name.to_ascii_lowercase();
    for entry in &entries {
        if entry.name.to_ascii_lowercase() == target_lower {
            let sep = if dir_path.ends_with('/') { "" } else { "/" };
            return Some(format!("{dir_path}{sep}{}", entry.name));
        }
    }
    None
}

/// Find a file anywhere in the VFS by searching known directories,
/// then falling back to a recursive search from the root.
///
/// Searches root (`/`) and common Windows paths first for `filename`,
/// then recursively searches the entire VFS tree.
pub fn find_vfs_file_by_name(fs: &litebox_shim_windows::NtFS, filename: &str) -> Option<String> {
    // Search directories in priority order: root, then Windows System32 paths.
    let search_dirs = ["/", "/c/windows/system32", "/c/windows"];
    for dir in &search_dirs {
        if let Some(path) = find_vfs_file(fs, dir, filename) {
            return Some(path);
        }
    }
    // Fall back to recursive search from root.
    find_vfs_file_recursive(fs, "/", filename)
}

/// Recursively search a VFS directory tree for a file by basename suffix
/// (case-insensitive). Returns the full VFS path if found.
fn find_vfs_file_recursive(
    fs: &litebox_shim_windows::NtFS,
    dir_path: &str,
    target_suffix: &str,
) -> Option<String> {
    use litebox::fs::FileSystem as _;

    let fd = fs
        .open(
            dir_path,
            litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
            litebox::fs::Mode::RUSR,
        )
        .ok()?;
    let entries = fs.read_dir(&fd).ok()?;
    let _ = fs.close(&fd);

    let target_lower = target_suffix.to_ascii_lowercase();
    let mut subdirs = Vec::new();

    for entry in &entries {
        let name_lower = entry.name.to_ascii_lowercase();
        if name_lower.ends_with(&target_lower)
            && entry.file_type != litebox::fs::FileType::Directory
        {
            let sep = if dir_path.ends_with('/') { "" } else { "/" };
            return Some(format!("{dir_path}{sep}{}", entry.name));
        }
        // Collect subdirectories for recursive search using VFS metadata.
        // Skip "." and ".." to avoid infinite recursion.
        if entry.file_type == litebox::fs::FileType::Directory
            && entry.name != "."
            && entry.name != ".."
        {
            let sep = if dir_path.ends_with('/') { "" } else { "/" };
            subdirs.push(format!("{dir_path}{sep}{}", entry.name));
        }
    }

    // Recurse into subdirectories.
    for subdir in subdirs {
        if let Some(found) = find_vfs_file_recursive(fs, &subdir, target_suffix) {
            return Some(found);
        }
    }
    None
}

/// Information about a loaded DLL in guest memory.
#[allow(dead_code)]
pub struct LoadedDll {
    pub name: String,
    pub base_address: usize,
    pub image_size: usize,
    pub entry_point: usize,
    pub pe_data: Vec<u8>,
    pub has_entry_point: bool,
}

/// Result of loading ntdll for the ntdll-driven init approach.
///
/// Only ntdll is loaded and rewritten. The ntdll loader (LdrpInitialize)
/// will load all other DLLs via syscalls, which the shim intercepts and
/// serves from the tar file.
pub struct NtdllInitLoadResult {
    /// The loaded ntdll DLL info.
    pub ntdll: LoadedDll,
    /// The trampoline page bytes (must be mapped at `trampoline_va`).
    pub trampoline: Vec<u8>,
    /// VA where the trampoline should be mapped.
    pub trampoline_va: usize,
    /// Offset within trampoline where the shim entry pointer goes.
    pub entry_ptr_offset: usize,
    /// Number of ntdll syscall stubs that were rewritten.
    #[allow(dead_code)]
    pub stubs_rewritten: usize,
    /// Number of stubs whose syscall number was identified (matched export name).
    #[allow(dead_code)]
    pub stubs_identified: usize,
    /// VA of ntdll!LdrInitializeThunk (thread entry point).
    pub ldr_init_thunk_va: usize,
    /// VA of ntdll!RtlUserThreadStart (for CONTEXT.Rip after init).
    pub rtl_user_thread_start_va: usize,
    /// Mapping from real Windows syscall numbers to NtSyscallId.
    pub syscall_map: litebox_common_windows::NtSyscallMap,
    /// Syscall number → export name for stubs not in NtSyscallId (for debug logging).
    pub unhandled_stubs: Vec<(u32, String)>,
    /// RVA of KiUserExceptionDispatcher in ntdll (for SEH dispatch).
    pub ki_user_exception_dispatcher_rva: Option<usize>,
    /// Guest VA of `ntdll!RtlDispatchException`.
    pub rtl_dispatch_exception_va: usize,
    /// Guest VA of `ntdll!RtlRestoreContext`.
    pub rtl_restore_context_va: usize,
    /// Guest VA of `ntdll!ZwRaiseException`.
    pub zw_raise_exception_va: usize,
    /// Guest VA of `ntdll!RtlRaiseStatus`.
    pub rtl_raise_status_va: usize,
    /// Guest VA of `ntdll!KiUserInvertedFunctionTable`.  The shim uses this
    /// to register loaded DLLs so SEH unwinding finds their .pdata.
    pub inverted_function_table_va: usize,
    /// Guest VA of `ntdll!LdrpHashTable`.
    pub ldrp_hash_table_va: usize,
    /// Guest VA of `ntdll!PebLdr`.
    pub pebldr_va: usize,
}

fn find_ntdll_hash_table_va(parsed: &PeParsedFile, image_base: usize) -> Result<usize> {
    let text = parsed
        .sections
        .iter()
        .find(|s| s.name.starts_with(b".text"))
        .ok_or_else(|| anyhow!("ntdll missing .text section"))?;

    // 41 83 E5 1F                and r13d, 1Fh
    // 48 8D 05 xx xx xx xx       lea rax, [rip+disp32]  ; LdrpHashTable
    // 49 C1 E5 04                shl r13, 4
    // 4C 03 E8                   add r13, rax
    // 4D 8B 7D 00                mov r15, [r13]
    // 4D 3B FD                   cmp r15, r13
    const PATTERN: [Option<u8>; 25] = [
        Some(0x41),
        Some(0x83),
        Some(0xE5),
        Some(0x1F),
        Some(0x48),
        Some(0x8D),
        Some(0x05),
        None,
        None,
        None,
        None,
        Some(0x49),
        Some(0xC1),
        Some(0xE5),
        Some(0x04),
        Some(0x4C),
        Some(0x03),
        Some(0xE8),
        Some(0x4D),
        Some(0x8B),
        Some(0x7D),
        Some(0x00),
        Some(0x4D),
        Some(0x3B),
        Some(0xFD),
    ];

    let text_va = image_base + text.virtual_address as usize;
    let text_len = text.virtual_size.max(text.size_of_raw_data) as usize;
    let text_bytes = unsafe { core::slice::from_raw_parts(text_va as *const u8, text_len) };

    let mut match_va = None;
    for off in 0..=text_bytes.len().saturating_sub(PATTERN.len()) {
        let matched = PATTERN
            .iter()
            .enumerate()
            .all(|(i, byte)| byte.is_none_or(|b| text_bytes[off + i] == b));
        if !matched {
            continue;
        }

        if match_va.is_some() {
            anyhow::bail!("ntdll LdrpHashTable signature matched multiple locations");
        }

        let disp = i32::from_le_bytes(text_bytes[off + 7..off + 11].try_into().unwrap()) as isize;
        let lea_next_rip = (text_va + off + 11) as isize;
        match_va = Some((lea_next_rip + disp) as usize);
    }

    match_va.ok_or_else(|| anyhow!("failed to locate ntdll!LdrpHashTable"))
}

fn find_ntdll_pebldr_va(parsed: &PeParsedFile, image_base: usize) -> Result<usize> {
    let text = parsed
        .sections
        .iter()
        .find(|s| s.name.starts_with(b".text"))
        .ok_or_else(|| anyhow!("ntdll missing .text section"))?;

    // 48 8B 3D xx xx xx xx       mov rdi, [rip+disp32]  ; PebLdr+0x10
    // BB 01 00 00 00             mov ebx, 1
    // 83 64 24 60 00             and dword ptr [rsp+60h], 0
    // 48 8D 05 yy yy yy yy       lea rax, [rip+disp32]  ; PebLdr+0x10
    // 48 3B F8                   cmp rdi, rax
    const PATTERN: [Option<u8>; 27] = [
        Some(0x48),
        Some(0x8B),
        Some(0x3D),
        None,
        None,
        None,
        None,
        Some(0xBB),
        Some(0x01),
        Some(0x00),
        Some(0x00),
        Some(0x00),
        Some(0x83),
        Some(0x64),
        Some(0x24),
        Some(0x60),
        Some(0x00),
        Some(0x48),
        Some(0x8D),
        Some(0x05),
        None,
        None,
        None,
        None,
        Some(0x48),
        Some(0x3B),
        Some(0xF8),
    ];

    let text_va = image_base + text.virtual_address as usize;
    let text_len = text.virtual_size.max(text.size_of_raw_data) as usize;
    let text_bytes = unsafe { core::slice::from_raw_parts(text_va as *const u8, text_len) };

    let mut match_va = None;
    for off in 0..=text_bytes.len().saturating_sub(PATTERN.len()) {
        let matched = PATTERN
            .iter()
            .enumerate()
            .all(|(i, byte)| byte.is_none_or(|b| text_bytes[off + i] == b));
        if !matched {
            continue;
        }

        let disp_load =
            i32::from_le_bytes(text_bytes[off + 3..off + 7].try_into().unwrap()) as isize;
        let disp_lea =
            i32::from_le_bytes(text_bytes[off + 20..off + 24].try_into().unwrap()) as isize;
        let head_va_from_load = ((text_va + off + 7) as isize + disp_load) as usize;
        let head_va_from_lea = ((text_va + off + 24) as isize + disp_lea) as usize;

        if head_va_from_load != head_va_from_lea {
            continue;
        }

        if match_va.is_some() {
            anyhow::bail!("ntdll PebLdr signature matched multiple locations");
        }

        match_va = Some(head_va_from_load - 0x10);
    }

    match_va.ok_or_else(|| anyhow!("failed to locate ntdll!PebLdr"))
}

/// Load only ntdll.dll from VFS for the ntdll-driven init approach.
///
/// Finds ntdll.dll in the VFS, rewrites its syscall stubs to use the
/// trampoline, and loads it into guest memory via `mapper`.
pub fn load_ntdll_for_init(
    fs: &litebox_shim_windows::NtFS,
    mapper: &mut PmMapper<'_>,
    partition_start: usize,
) -> Result<NtdllInitLoadResult> {
    let ntdll_path = find_vfs_file_by_name(fs, "ntdll.dll")
        .ok_or_else(|| anyhow!("ntdll.dll not found in VFS"))?;
    let ntdll_data = read_vfs_file(fs, &ntdll_path)?;
    trace_debugln!(
        "[real-dlls] Read ntdll.dll from VFS ({} bytes, path={ntdll_path:?})",
        ntdll_data.len()
    );
    let ntdll_load_va = partition_start + REAL_DLL_OFFSET;

    let trampoline_va = partition_start + TRAMPOLINE_OFFSET;

    // Rewrite ntdll syscall stubs.
    let rewrite =
        ntdll_rewriter::rewrite_ntdll(&ntdll_data, ntdll_load_va as u64, trampoline_va as u64);
    trace_debugln!(
        "[real-dlls] Rewrote {} ntdll syscall stubs ({} identified)",
        rewrite.stubs_rewritten,
        rewrite.stubs_identified,
    );
    // Log unhandled stubs for debugging.
    #[cfg(all(debug_assertions, feature = "trace_debug"))]
    for (nr, name) in &rewrite.unhandled_stubs {
        trace_debugln!("[real-dlls] unhandled stub: nr=0x{nr:04X} name={name}");
    }

    let image = rewrite.image;
    // Parse and load ntdll into guest memory.
    let parsed =
        PeParsedFile::parse(&image).map_err(|e| anyhow!("Failed to parse rewritten ntdll: {e}"))?;
    let image_size = parsed.size_of_image as usize;
    mapper
        .pre_reserve(ntdll_load_va, image_size)
        .map_err(|e| anyhow!("Failed to reserve VA for ntdll: {e:?}"))?;
    let info = load_pe(&parsed, &image, ntdll_load_va, mapper)
        .map_err(|e| anyhow!("Failed to load ntdll: {e}"))?;

    trace_debugln!(
        "[real-dlls] ntdll loaded at 0x{:X} (size=0x{:X})",
        info.image_base,
        info.image_size
    );

    let ldrp_hash_table_va = find_ntdll_hash_table_va(&parsed, info.image_base)?;
    trace_debugln!("[real-dlls] LdrpHashTable at 0x{ldrp_hash_table_va:X}");

    let pebldr_va = find_ntdll_pebldr_va(&parsed, info.image_base)?;
    trace_debugln!("[real-dlls] PebLdr at 0x{pebldr_va:X}");

    // Make ntdll's .mrdata section writable.  This section contains internal
    // mutable data (KiUserInvertedFunctionTable, loader data, etc.) that
    // ntdll's code needs to write during initialization.  On real Windows the
    // kernel loads ntdll with writable .mrdata; our load_pe uses the PE section
    // flags which may mark it read-only.
    for section in &parsed.sections {
        let name = core::str::from_utf8(&section.name)
            .unwrap_or("")
            .trim_end_matches('\0');
        if name == ".mrdata" {
            let start = info.image_base + section.virtual_address as usize;
            let vsize = section.virtual_size.max(section.size_of_raw_data) as usize;
            let pages = (vsize + 0xFFF) & !0xFFF;
            unsafe {
                for off in (0..pages).step_by(0x1000) {
                    let addr = start + off;
                    let ptr = addr as *mut u8;
                    // Make writable via the host OS.
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
            trace_debugln!(
                "[real-dlls] Made .mrdata writable: 0x{start:X}..0x{:X} ({pages} bytes)",
                start + pages
            );
        }
    }

    // Find LdrInitializeThunk and RtlUserThreadStart exports.
    let exports = parsed.exports(&image);
    #[allow(clippy::similar_names)]
    let (ldr_init_thunk_va, rtl_user_thread_start_va) = {
        let ldr_init_rva = exports
            .iter()
            .find(|e| e.name == Some("LdrInitializeThunk"))
            .map(|e| e.rva)
            .ok_or_else(|| anyhow!("ntdll missing LdrInitializeThunk export"))?;
        let rtl_user_thread_start_rva = exports
            .iter()
            .find(|e| e.name == Some("RtlUserThreadStart"))
            .map(|e| e.rva)
            .ok_or_else(|| anyhow!("ntdll missing RtlUserThreadStart export"))?;

        (
            ntdll_load_va + ldr_init_rva as usize,
            ntdll_load_va + rtl_user_thread_start_rva as usize,
        )
    };

    trace_debugln!(
        "[real-dlls] LdrInitializeThunk at 0x{ldr_init_thunk_va:X}, \
         RtlUserThreadStart at 0x{rtl_user_thread_start_va:X}"
    );

    // Also look up KiUserExceptionDispatcher for SEH dispatch.
    let ki_user_exception_dispatcher_rva = exports
        .iter()
        .find(|e| e.name == Some("KiUserExceptionDispatcher"))
        .map(|e| e.rva as usize);
    let find_export_va = |name: &str| -> usize {
        exports
            .iter()
            .find(|e| e.name == Some(name))
            .map_or(0, |e| ntdll_load_va + e.rva as usize)
    };
    let rtl_dispatch_exception_va = ki_user_exception_dispatcher_rva
        .and_then(|ki_rva| {
            let ki_off = parsed.rva_to_file_offset(ki_rva as u32)?;
            let bytes = image.get(ki_off..image.len().min(ki_off + 0x80))?;
            const PATTERN: [u8; 14] = [
                0x48, 0x8B, 0xCC, 0x48, 0x81, 0xC1, 0xF0, 0x04, 0x00, 0x00, 0x48, 0x8B, 0xD4, 0xE8,
            ];
            let idx = bytes.windows(PATTERN.len()).position(|w| w == PATTERN)?;
            let call_off = ki_off + idx + PATTERN.len() - 1;
            let disp = i32::from_le_bytes(image.get(call_off + 1..call_off + 5)?.try_into().ok()?);
            let next_rva = ki_rva + idx + PATTERN.len() + 4;
            Some((ntdll_load_va as isize + next_rva as isize + disp as isize) as usize)
        })
        .unwrap_or(0);
    let rtl_restore_context_va = find_export_va("RtlRestoreContext");
    let zw_raise_exception_va = find_export_va("ZwRaiseException");
    let rtl_raise_status_va = find_export_va("RtlRaiseStatus");

    // --- Populate the inverted function table for ntdll -----------------------
    //
    // On real Windows the kernel writes ntdll's RUNTIME_FUNCTION table into
    // `KiUserInvertedFunctionTable` before giving control to user mode.  Our
    // guest ntdll's copy is initialised from the PE file where entry 0 is all
    // zeroes.  Without it, RtlDispatchException can't walk the SEH chain and
    // any exception during init becomes unhandleable (infinite NtRaiseException
    // loop).
    //
    // KiUserInvertedFunctionTable layout:
    //   +0x00  u32  CurrentSize (already 1 in the PE)
    //   +0x04  u32  MaximumSize (512)
    //   +0x08  u32  Epoch
    //   +0x0C  u8   Overflow + 3 reserved
    //   +0x10  Entry[0]:
    //     +0x00  u64  ExceptionDirectory   (ptr to RUNTIME_FUNCTION array)
    //     +0x08  u64  ImageBase
    //     +0x10  u32  ImageSize
    //     +0x14  u32  ExceptionDirectorySize
    let mut ift_va_result = 0usize;
    if let Some(ift_export) = exports
        .iter()
        .find(|e| e.name == Some("KiUserInvertedFunctionTable"))
    {
        let ift_va = ntdll_load_va + ift_export.rva as usize;
        ift_va_result = ift_va;
        // Exception directory (.pdata) from the PE data directories.
        if parsed.data_directories.len() > IMAGE_DIRECTORY_ENTRY_EXCEPTION {
            let exc_dir = &parsed.data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if exc_dir.virtual_address != 0 && exc_dir.size != 0 {
                let entry_va = ift_va + 0x10; // first table entry
                let exc_dir_va = ntdll_load_va + exc_dir.virtual_address as usize;

                // Safety: ift_va points into committed guest memory (ntdll's
                // .mrdata section) that we just loaded.
                unsafe {
                    // Entry.ExceptionDirectory (u64)
                    (entry_va as *mut u64).write(exc_dir_va as u64);
                    // Entry.ImageBase (u64)
                    ((entry_va + 8) as *mut u64).write(ntdll_load_va as u64);
                    // Entry.ImageSize (u32)
                    ((entry_va + 16) as *mut u32).write(parsed.size_of_image);
                    // Entry.ExceptionDirectorySize (u32)
                    ((entry_va + 20) as *mut u32).write(exc_dir.size);
                }

                trace_debugln!(
                    "[real-dlls] Populated KiUserInvertedFunctionTable entry 0: \
                     ExcDir=0x{exc_dir_va:X} Base=0x{ntdll_load_va:X} \
                     Size=0x{:X} ExcSize=0x{:X}",
                    parsed.size_of_image,
                    exc_dir.size
                );
            }
        }
    } else {
        trace_debugln!("[real-dlls] WARN: KiUserInvertedFunctionTable export not found");
    }

    let ntdll = LoadedDll {
        name: String::from("ntdll.dll"),
        base_address: info.image_base,
        image_size: info.image_size,
        entry_point: if parsed.entry_point != 0 {
            info.image_base + parsed.entry_point as usize
        } else {
            0
        },
        pe_data: image,
        has_entry_point: parsed.entry_point != 0,
    };

    Ok(NtdllInitLoadResult {
        ntdll,
        trampoline: rewrite.trampoline,
        trampoline_va,
        entry_ptr_offset: rewrite.entry_ptr_offset,
        stubs_rewritten: rewrite.stubs_rewritten,
        stubs_identified: rewrite.stubs_identified,
        ldr_init_thunk_va,
        rtl_user_thread_start_va,
        syscall_map: rewrite.syscall_map,
        unhandled_stubs: rewrite.unhandled_stubs,
        ki_user_exception_dispatcher_rva,
        rtl_dispatch_exception_va,
        rtl_restore_context_va,
        zw_raise_exception_va,
        rtl_raise_status_va,
        inverted_function_table_va: ift_va_result,
        ldrp_hash_table_va,
        pebldr_va,
    })
}
