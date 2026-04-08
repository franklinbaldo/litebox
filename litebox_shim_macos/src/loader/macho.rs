// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach-O binary loader.
//!
//! This module is aarch64-only, so u64→usize casts are lossless.

#![expect(
    clippy::cast_possible_truncation,
    reason = "aarch64 is 64-bit; u64 fits in usize"
)]

use alloc::ffi::CString;
use alloc::vec::Vec;
use litebox::mm::linux::{CreatePagesFlags, PAGE_SIZE};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, SystemInfoProvider as _};
use object::Endianness;
use object::macho;
use object::read::macho::MachHeader;

use super::stack::UserStack;
use super::{DEFAULT_LOW_ADDR, DEFAULT_STACK_SIZE, DyldLoadInfo, MachoLoadInfo, MachoLoaderError};
use crate::{MutPtr, ShimFS, Task};

/// Byte offset of the PC register within an LC_UNIXTHREAD ARM64 thread state command.
///
/// Layout: cmd(4) + cmdsize(4) + flavor(4) + count(4) = 16 bytes header,
/// then 32 general-purpose registers (x0-x30, sp) at 8 bytes each = 256 bytes.
/// PC is at register index 32 (after the 32 GPRs).
const ARM64_THREAD_STATE_PC_OFFSET: usize = 16 + 32 * 8;

struct SegmentInfo {
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    initprot: u32,
    segname: [u8; 16],
}

pub(crate) fn load<FS: ShimFS>(
    task: &Task<FS>,
    data: &[u8],
    argv: Vec<CString>,
    envp: Vec<CString>,
    dyld_bytes: Option<&[u8]>,
) -> Result<MachoLoadInfo, MachoLoaderError> {
    // If this is a fat/universal binary, extract the arm64(e) slice first.
    let data = if let Some((offset, size)) = extract_arm64_slice(data) {
        &data[offset..offset + size]
    } else {
        data
    };

    // Parse header
    let header = macho::MachHeader64::<Endianness>::parse(data, 0)
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("invalid header: {e}")))?;
    let endian = header
        .endian()
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("endianness: {e}")))?;

    // Validate: must be ARM64 MH_EXECUTE
    if header.cputype(endian) != macho::CPU_TYPE_ARM64 {
        return Err(MachoLoaderError::UnsupportedFormat);
    }
    if header.filetype(endian) != macho::MH_EXECUTE {
        return Err(MachoLoaderError::UnsupportedFormat);
    }

    // Collect segments and find entry point
    let mut segments = Vec::new();
    let mut entry_offset: Option<u64> = None;
    let mut is_lc_main = false;
    let mut text_vmaddr: Option<u64> = None;
    let mut has_dylinker = false;

    let mut commands = header
        .load_commands(endian, data, 0)
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("load commands: {e}")))?;

    while let Some(cmd) = commands
        .next()
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("iterate commands: {e}")))?
    {
        // Try to parse as LC_SEGMENT_64
        if let Some((seg, _sections)) = cmd
            .segment_64()
            .map_err(|e| MachoLoaderError::ParseError(alloc::format!("segment: {e}")))?
        {
            let name = &seg.segname;
            if *name == *b"__PAGEZERO\0\0\0\0\0\0" {
                continue;
            }
            if name.starts_with(b"__TEXT") {
                text_vmaddr = Some(seg.vmaddr.get(endian));
            }
            segments.push(SegmentInfo {
                vmaddr: seg.vmaddr.get(endian),
                vmsize: seg.vmsize.get(endian),
                fileoff: seg.fileoff.get(endian),
                filesize: seg.filesize.get(endian),
                initprot: seg.initprot.get(endian),
                segname: *name,
            });
            continue;
        }

        // Try to parse as LC_MAIN
        if let Some(ep) = cmd
            .entry_point()
            .map_err(|e| MachoLoaderError::ParseError(alloc::format!("entry point: {e}")))?
        {
            entry_offset = Some(ep.entryoff.get(endian));
            is_lc_main = true;
            continue;
        }

        // Check for LC_UNIXTHREAD
        if cmd.cmd() == macho::LC_UNIXTHREAD {
            let cmd_data = cmd.raw_data();
            if cmd_data.len() >= ARM64_THREAD_STATE_PC_OFFSET + 8 {
                let pc = u64::from_le_bytes(
                    cmd_data[ARM64_THREAD_STATE_PC_OFFSET..ARM64_THREAD_STATE_PC_OFFSET + 8]
                        .try_into()
                        .unwrap(),
                );
                entry_offset = Some(pc);
                is_lc_main = false;
            }
        }

        // Check for LC_LOAD_DYLINKER
        if cmd.cmd() == macho::LC_LOAD_DYLINKER {
            has_dylinker = true;
        }
    }

    if segments.is_empty() {
        return Err(MachoLoaderError::NoTextSegment);
    }

    // --- Reserve-then-map strategy ---
    //
    // Static Mach-O binaries have absolute load addresses (typically __TEXT at
    // 0x100000000). We cannot use MAP_FIXED at these addresses because the
    // host process itself may occupy that region (e.g., the cargo test runner
    // on macOS is also loaded at 0x100000000).
    //
    // Instead, we follow the same approach as the ELF loader for PIE binaries:
    // 1. Compute the total VA span of all loadable segments.
    // 2. Reserve that span with a hint-based mmap (no MAP_FIXED) — let the
    //    kernel pick a free region.
    // 3. Compute a "slide" (relocation offset) = reserved_base - min_vmaddr.
    // 4. Map individual segments with MAP_FIXED *within* the reserved region.
    //
    // Since we only support static binaries without relocations, the guest code
    // uses absolute addresses. The syscall rewriter's trampoline uses
    // PC-relative addressing (ADRP+ADD), so it works at any address. The guest
    // assembly itself must also use PC-relative addressing for this to work.
    // Our test binaries are written with this constraint in mind.

    // Step 1: Compute the VA span of all loadable segments.
    let min_vmaddr = segments
        .iter()
        .filter(|s| s.vmsize > 0)
        .map(|s| s.vmaddr as usize)
        .min()
        .unwrap_or(DEFAULT_LOW_ADDR);
    let max_vmend = segments
        .iter()
        .filter(|s| s.vmsize > 0)
        .map(|s| (s.vmaddr + s.vmsize) as usize)
        .max()
        .unwrap_or(DEFAULT_LOW_ADDR);

    let page_aligned_min = min_vmaddr & !(PAGE_SIZE - 1);
    let page_aligned_max = max_vmend.next_multiple_of(PAGE_SIZE);
    let total_span = page_aligned_max - page_aligned_min;

    // Step 2: Reserve the full span with a hint (no MAP_FIXED).
    let reserve_flags =
        litebox_common_linux::MapFlags::MAP_ANONYMOUS | litebox_common_linux::MapFlags::MAP_PRIVATE;
    let reserved_base = litebox_common_linux::mm::do_mmap(
        &task.global.pm,
        Some(DEFAULT_LOW_ADDR),
        total_span,
        litebox_common_linux::ProtFlags::PROT_NONE,
        reserve_flags,
        false,
        |_| Ok(0),
    )
    .map_err(|e| {
        MachoLoaderError::MappingError(alloc::format!(
            "reserve {total_span:#x} bytes for segments: {e:?}"
        ))
    })?
    .as_usize();

    // Step 3: Compute the slide (relocation offset).
    let slide = reserved_base.wrapping_sub(page_aligned_min);

    // Step 4: Map each segment with MAP_FIXED within the reserved region.
    // Map as RW first to copy data, then mprotect to final permissions.
    for seg in &segments {
        if seg.vmsize == 0 {
            continue;
        }

        let vm_addr = (seg.vmaddr as usize).wrapping_add(slide);
        let vm_size = (seg.vmsize as usize).next_multiple_of(PAGE_SIZE);

        // Determine the final protection from the Mach-O initprot
        let final_prot = prot_from_macho(seg.initprot);

        // Map as RW initially so we can copy segment data
        let initial_prot = litebox_common_linux::ProtFlags::PROT_READ_WRITE;
        let flags = litebox_common_linux::MapFlags::MAP_ANONYMOUS
            | litebox_common_linux::MapFlags::MAP_PRIVATE
            | litebox_common_linux::MapFlags::MAP_FIXED;

        litebox_common_linux::mm::do_mmap(
            &task.global.pm,
            Some(vm_addr),
            vm_size,
            initial_prot,
            flags,
            false,
            |_| Ok(0),
        )
        .map_err(|e| {
            MachoLoaderError::MappingError(alloc::format!(
                "mmap segment {:?} at {vm_addr:#x} size {vm_size:#x}: {e:?}",
                core::str::from_utf8(&seg.segname).unwrap_or("<invalid>")
            ))
        })?;

        // Copy segment data from file
        let file_size = seg.filesize as usize;
        if file_size > 0 {
            let file_off = seg.fileoff as usize;
            if file_off + file_size > data.len() {
                return Err(MachoLoaderError::ParseError(alloc::format!(
                    "segment data at offset {file_off:#x} size {file_size:#x} exceeds file"
                )));
            }
            let dest: MutPtr<u8> = MutPtr::from_usize(vm_addr);
            dest.copy_from_slice(0, &data[file_off..file_off + file_size])
                .ok_or(MachoLoaderError::MemoryError(
                    "failed to copy segment data".into(),
                ))?;
        }

        // Set final protection if it differs from the initial RW mapping
        if final_prot != litebox_common_linux::ProtFlags::PROT_READ_WRITE {
            litebox_common_linux::mm::sys_mprotect(
                &task.global.pm,
                MutPtr::from_usize(vm_addr),
                vm_size,
                final_prot,
            )
            .map_err(|e| {
                MachoLoaderError::MappingError(alloc::format!(
                    "mprotect segment at {vm_addr:#x}: {e:?}"
                ))
            })?;
        }
    }

    // Compute entry point (apply slide)
    let entry_point = if is_lc_main {
        let text_base = text_vmaddr.ok_or(MachoLoaderError::NoTextSegment)?;
        let offset = entry_offset.ok_or(MachoLoaderError::NoEntryPoint)?;
        ((text_base + offset) as usize).wrapping_add(slide)
    } else {
        (entry_offset.ok_or(MachoLoaderError::NoEntryPoint)? as usize).wrapping_add(slide)
    };

    // Set brk after highest mapped segment (with slide applied).
    // NOTE: Do NOT call set_initial_brk yet — the trampoline initialization
    // below may extend brk past the TLS table.
    let max_end = segments
        .iter()
        .map(|s| ((s.vmaddr + s.vmsize) as usize).wrapping_add(slide))
        .max()
        .unwrap_or(DEFAULT_LOW_ADDR);
    let mut brk = max_end.next_multiple_of(PAGE_SIZE);

    // --- Allocate TLS lookup table ---
    //
    // The TLS table is needed whenever syscall interception is active —
    // either from a __LITEBOX trampoline in the main binary (static case)
    // or from the mmap-hook rewriting code loaded via dyld (dynamic case).
    // We allocate it unconditionally so that load_dyld() can reference it.
    //
    // Layout: array of [guest_tpidr: u64, host_tls: u64] entries.
    // 256 usable entries + 8 overflow sentinel entries for hash probe.
    #[allow(clippy::items_after_statements)]
    const TLS_ENTRY_SIZE: usize = 16;
    #[allow(clippy::items_after_statements)]
    const TLS_TABLE_USABLE_ENTRIES: usize = 256;
    #[allow(clippy::items_after_statements)]
    const TLS_TABLE_OVERFLOW_ENTRIES: usize = 8;
    #[allow(clippy::items_after_statements)]
    const TLS_TABLE_TOTAL_ENTRIES: usize = TLS_TABLE_USABLE_ENTRIES + TLS_TABLE_OVERFLOW_ENTRIES;
    #[allow(clippy::items_after_statements)]
    const TLS_TABLE_SIZE: usize = TLS_TABLE_TOTAL_ENTRIES * TLS_ENTRY_SIZE; // 4224 bytes
    // On macOS aarch64, the host page size is 16KB. Align the TLS table
    // to 16KB to ensure it gets its own host page and doesn't share a
    // page with any trampoline (which may be mprotected to R-X).
    #[allow(clippy::items_after_statements)]
    const HOST_PAGE_SIZE: usize = 16384;

    let tls_table_addr = brk.next_multiple_of(HOST_PAGE_SIZE);
    let tls_table_end = (tls_table_addr + TLS_TABLE_SIZE).next_multiple_of(PAGE_SIZE);
    log_unsupported!(
        "load_macho: about to alloc TLS table at {tls_table_addr:#x}..{tls_table_end:#x} (brk={brk:#x})"
    );

    let tls_flags = litebox_common_linux::MapFlags::MAP_ANONYMOUS
        | litebox_common_linux::MapFlags::MAP_PRIVATE
        | litebox_common_linux::MapFlags::MAP_FIXED;
    litebox_common_linux::mm::do_mmap(
        &task.global.pm,
        Some(tls_table_addr),
        tls_table_end - tls_table_addr,
        litebox_common_linux::ProtFlags::PROT_READ_WRITE,
        tls_flags,
        false,
        |_| Ok(0),
    )
    .map_err(|e| {
        MachoLoaderError::MappingError(alloc::format!(
            "mmap TLS table at {tls_table_addr:#x}: {e:?}"
        ))
    })?;

    log_unsupported!("load_macho: TLS table allocated OK");
    // Initialize all guest_tpidr fields with sentinel 0xFFFFFFFFFFFFFFFF.
    let sentinel: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    let tls_dest: MutPtr<u8> = MutPtr::from_usize(tls_table_addr);
    for i in 0..TLS_TABLE_TOTAL_ENTRIES {
        let entry_offset = i * TLS_ENTRY_SIZE;
        tls_dest
            .copy_from_slice(entry_offset, &sentinel.to_ne_bytes())
            .ok_or(MachoLoaderError::MemoryError(
                "failed to initialize TLS table entry".into(),
            ))?;
    }

    // Store TLS table address in the global atomic so the platform's
    // update_host_tls_entry() can find and write to it.
    litebox_common_linux::HOST_TLS_TABLE_ADDR
        .store(tls_table_addr, core::sync::atomic::Ordering::Release);

    // Update brk past the TLS table.
    brk = brk.max(tls_table_end);
    log_unsupported!("load_macho: TLS table initialized, HOST_TLS_TABLE_ADDR set to {tls_table_addr:#x}");

    // --- Initialize trampoline callback address (if __LITEBOX segment exists) ---
    //
    // The __LITEBOX segment contains the trampoline code emitted by the
    // Mach-O syscall rewriter. The first 8 bytes are reserved for the
    // platform's syscall callback address, and bytes 8..16 are reserved
    // for the TLS lookup table pointer. The rewriter initializes both to
    // zero; we must fill them in now that the segment is mapped.
    //
    // For dynamically linked binaries that weren't rewritten, there is no
    // __LITEBOX segment — the TLS table was already allocated above and
    // dyld's trampoline will be initialized in load_dyld().
    if let Some(litebox_seg) = segments
        .iter()
        .find(|s| s.segname.starts_with(b"__LITEBOX"))
    {
        let trampoline_start = (litebox_seg.vmaddr as usize).wrapping_add(slide);
        let trampoline_size = (litebox_seg.vmsize as usize).next_multiple_of(PAGE_SIZE);
        log_unsupported!(
            "load_macho: __LITEBOX trampoline at {trampoline_start:#x} size {trampoline_size:#x}"
        );

        // Make the trampoline writable so we can fill in the callback and TLS
        // table pointer. It was already mprotected to R-X during segment mapping.
        litebox_common_linux::mm::sys_mprotect(
            &task.global.pm,
            MutPtr::from_usize(trampoline_start),
            trampoline_size,
            litebox_common_linux::ProtFlags::PROT_READ_WRITE,
        )
        .map_err(|e| {
            MachoLoaderError::MappingError(alloc::format!("mprotect __LITEBOX RW for init: {e:?}"))
        })?;

        // Write the syscall callback address at offset 0.
        let callback_addr = litebox_platform_multiplex::platform().get_syscall_entry_point();
        let dest: MutPtr<u8> = MutPtr::from_usize(trampoline_start);
        dest.copy_from_slice(0, &callback_addr.to_ne_bytes())
            .ok_or(MachoLoaderError::MemoryError(
                "failed to write trampoline callback address".into(),
            ))?;

        // Write the TLS table address at trampoline offset 8.
        dest.copy_from_slice(8, &tls_table_addr.to_ne_bytes())
            .ok_or(MachoLoaderError::MemoryError(
                "failed to write TLS table address in trampoline".into(),
            ))?;

        // Re-protect the trampoline as R-X (executable code).
        litebox_common_linux::mm::sys_mprotect(
            &task.global.pm,
            MutPtr::from_usize(trampoline_start),
            trampoline_size,
            litebox_common_linux::ProtFlags::PROT_READ_EXEC,
        )
        .map_err(|e| {
            MachoLoaderError::MappingError(alloc::format!(
                "mprotect __LITEBOX R-X after init: {e:?}"
            ))
        })?;
        log_unsupported!("load_macho: __LITEBOX trampoline initialized OK");
    }

    // Set the initial brk now that all segments and TLS table are mapped.
    task.global.pm.set_initial_brk(brk);
    log_unsupported!("load_macho: set_initial_brk done (brk={brk:#x})");

    // --- Load dyld if the binary has LC_LOAD_DYLINKER ---
    //
    // When the binary is dynamically linked, we load /usr/lib/dyld alongside
    // the main binary. dyld takes over as the entry point and is responsible
    // for loading shared libraries at runtime (via mmap, which our mmap-hook
    // intercepts for code patching).
    let mut dyld_entry: Option<usize> = None;
    log_unsupported!(
        "load_macho: binary mapped. has_dylinker={} entry_point={entry_point:#x} reserved_base={reserved_base:#x} slide={slide:#x}",
        has_dylinker
    );
    if has_dylinker {
        log_unsupported!("load_macho: has_dylinker=true, dyld_bytes.is_some()={}", dyld_bytes.is_some());
        // Determine the dyld binary data to use.  On initial load the caller
        // passes dyld_bytes directly.  On re-exec (execve) the caller passes
        // None and we retrieve the previously-stored bytes from Global.
        let dyld_data_owned: Option<alloc::vec::Vec<u8>> = if let Some(data) = dyld_bytes {
            // First load: store a copy in Global for future execve calls.
            {
                let mut stored = task.global.dyld_bytes.write();
                *stored = Some(data.to_vec());
            }
            None // signal to use dyld_bytes directly below
        } else {
            // Re-exec path: read the stored bytes.
            let stored = task.global.dyld_bytes.read();
            if let Some(ref bytes) = *stored {
                Some(bytes.clone())
            } else {
                return Err(MachoLoaderError::ParseError(
                    "binary requires dyld but no dyld_bytes provided and no prior dyld loaded"
                        .into(),
                ));
            }
        };

        log_unsupported!("load_macho: dyld_data_owned.is_some()={}", dyld_data_owned.is_some());
        // Load dyld fresh — always, even on re-exec.  This ensures dyld's
        // __DATA segments start pristine, matching real macOS kernel behavior
        // where dyld is freshly mapped from disk on every execve().
        let dyld_slice: &[u8] = match (&dyld_data_owned, dyld_bytes) {
            (Some(owned), _) => owned.as_slice(),
            (None, Some(orig)) => orig,
            _ => unreachable!(),
        };
        log_unsupported!("load_macho: about to call load_dyld (slice len={})", dyld_slice.len());
        let dyld_info = load_dyld(task, dyld_slice)?;
        log_unsupported!("load_macho: load_dyld OK: entry={:#x} base={:#x} end={:#x}", dyld_info.entry_point, dyld_info.base, dyld_info.end);
        // Store dyld address range so release_memory can skip it if needed,
        // and store entry point for reference.
        task.global
            .dyld_entry_point
            .store(dyld_info.entry_point, core::sync::atomic::Ordering::Release);
        task.global
            .dyld_base
            .store(dyld_info.base, core::sync::atomic::Ordering::Release);
        task.global
            .dyld_end
            .store(dyld_info.end, core::sync::atomic::Ordering::Release);
        dyld_entry = Some(dyld_info.entry_point);
    }

    // Use dyld's entry point if loaded, otherwise use the main binary's.
    let final_entry = dyld_entry.unwrap_or(entry_point);
    // When dyld is loaded, it uses LC_UNIXTHREAD-style entry (stack-based args).
    let final_is_lc_main = dyld_entry.is_none() && is_lc_main;

    // Allocate stack
    let sp = unsafe {
        let length = litebox::mm::linux::NonZeroPageSize::new(DEFAULT_STACK_SIZE)
            .expect("DEFAULT_STACK_SIZE is not page-aligned");
        task.global
            .pm
            .create_stack_pages(None, length, CreatePagesFlags::empty())
            .map_err(|e| {
                MachoLoaderError::MappingError(alloc::format!("stack allocation: {e:?}"))
            })?
    };
    log_unsupported!(
        "stack allocated: sp={:#x}, size={DEFAULT_STACK_SIZE:#x}, range=[{:#x}..{:#x}]",
        sp.as_usize(),
        sp.as_usize() - DEFAULT_STACK_SIZE,
        sp.as_usize(),
    );
    let mut stack =
        UserStack::new(sp, DEFAULT_STACK_SIZE).ok_or(MachoLoaderError::InvalidStackAddr)?;

    if dyld_entry.is_some() {
        // Build apple entries for dyld.
        //
        // dyld reads KernelArgs from the stack. Critical apple entries:
        // - executable_mh=<hex>: the mapped address of the main binary's
        //   mach_header_64. dyld uses this to find LC_LOAD_DYLIB commands.
        // - executable_path=<path>: the executable's file path.
        //
        // The Mach-O header is at the start of the __TEXT segment, which
        // is the first mapped segment (at reserved_base after slide).
        let executable_mh = reserved_base;
        let executable_path = argv
            .first()
            .map_or("./a.out", |a| a.to_str().unwrap_or("./a.out"));
        let apple = alloc::vec![
            CString::new(alloc::format!("executable_mh=0x{executable_mh:x}"))
                .map_err(|_| MachoLoaderError::InvalidStackAddr)?,
            CString::new(alloc::format!("executable_path={executable_path}"))
                .map_err(|_| MachoLoaderError::InvalidStackAddr)?,
        ];
        // Use init_for_dyld to produce the KernelArgs layout that dyld
        // expects: [mainExecutable mach_header*, argc, argv..., NULL,
        // envp..., NULL, apple..., NULL].
        stack
            .init_for_dyld(argv, envp, apple, executable_mh)
            .ok_or(MachoLoaderError::InvalidStackAddr)?;
    } else {
        stack
            .init(argv, envp)
            .ok_or(MachoLoaderError::InvalidStackAddr)?;
    }

    Ok(MachoLoadInfo {
        entry_point: final_entry,
        user_stack_top: stack.get_cur_stack_top(),
        is_lc_main: final_is_lc_main,
        has_dylinker,
        reserved_base,
        slide,
    })
}

/// Extract the arm64/arm64e slice from a universal (fat) Mach-O binary.
///
/// Returns the byte range (offset, size) of the arm64 slice within the input.
/// If the input is not a fat binary, returns None.
pub(crate) fn extract_arm64_slice(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 8 {
        return None;
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().ok()?);
    // FAT_MAGIC is always big-endian (0xCAFEBABE). Since we read with from_be_bytes,
    // we only need to check for this value. FAT_MAGIC_64 (0xCAFEBABF) uses
    // fat_arch_64 entries with different layout and is not supported.
    if magic != 0xCAFE_BABE {
        return None; // Not a fat binary (or unsupported FAT_MAGIC_64)
    }
    let nfat_arch = u32::from_be_bytes(data[4..8].try_into().ok()?);

    // Each fat_arch entry is 20 bytes: cputype(4), cpusubtype(4), offset(4), size(4), align(4)
    for i in 0..nfat_arch as usize {
        let entry_offset = 8 + i * 20;
        if entry_offset + 20 > data.len() {
            return None;
        }
        let cputype = u32::from_be_bytes(data[entry_offset..entry_offset + 4].try_into().ok()?);
        // CPU_TYPE_ARM64 = 0x0100000C (16777228)
        if cputype == 0x0100_000C {
            let offset =
                u32::from_be_bytes(data[entry_offset + 8..entry_offset + 12].try_into().ok()?)
                    as usize;
            let size =
                u32::from_be_bytes(data[entry_offset + 12..entry_offset + 16].try_into().ok()?)
                    as usize;
            return Some((offset, size));
        }
    }
    None
}

/// Load dyld from a (possibly fat) binary, rewriting syscalls and mapping segments.
///
/// Returns `DyldLoadInfo` with dyld's entry point and slide.
fn load_dyld<FS: ShimFS>(
    task: &Task<FS>,
    dyld_bytes: &[u8],
) -> Result<DyldLoadInfo, MachoLoaderError> {
    const DYLD_HINT_OFFSET: usize = 256 * 1024 * 1024; // 256 MB

    // Extract arm64 slice if this is a universal binary
    let slice_data: &[u8] = if let Some((offset, size)) = extract_arm64_slice(dyld_bytes) {
        if offset + size > dyld_bytes.len() {
            return Err(MachoLoaderError::ParseError(
                "arm64 slice extends beyond file".into(),
            ));
        }
        &dyld_bytes[offset..offset + size]
    } else {
        dyld_bytes
    };

    // Rewrite SVC #0x80 instructions in dyld
    log_unsupported!("load_dyld: rewriting dyld (slice len={})", slice_data.len());
    let mut rewritten = litebox_syscall_rewriter_macho::hook_syscalls_in_macho(slice_data)
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld rewrite failed: {e}")))?;
    log_unsupported!("load_dyld: rewrite done (rewritten len={})", rewritten.len());

    // Patch out `restartWithDyldInCache` call.
    //
    // On macOS-on-macOS the shared cache's copy of dyld already has host-
    // dirty state (e.g. `sMemoryManagerInitialized = 1` in TPRO pages that
    // are hardware write-protected and cannot be reset).  If the loaded dyld
    // calls `restartWithDyldInCache`, it jumps into the shared cache's dyld
    // `start` which calls `MemoryManager::init` again and hits the assertion
    // `!sMemoryManagerInitialized`.
    //
    // We prevent this by scanning for the `bl restartWithDyldInCache`
    // instruction (`restartWithDyldInCache` has the signature
    //   mov sp, x0       (0x9100001F)
    //   br  x3           (0xD61F0060)
    // ) and NOPing the BL that targets it.
    patch_restart_with_dyld_in_cache(&mut rewritten);

    // Patch out library initializer execution.
    //
    // On macOS-on-macOS the host process has already fully initialised
    // libSystem, pthread, malloc, etc. via the shared cache.  When the
    // guest dyld reaches `runAllInitializersForMain()`, it calls
    // `PrebuiltLoader::runInitializers()` for every library — including
    // libSystem.  `libSystem_initializer` calls `__pthread_init` which
    // detects re-initialisation and executes `brk #0xB001`, which the
    // kernel translates to an uncatchable SIGKILL.
    //
    // We fix this by NOPing the `bl findAndRunAllInitializers` inside
    // `PrebuiltLoader::runInitializers`.  The rest of that function still
    // runs (marking each loader as "initialised" in dyld's state tables),
    // so dyld's bookkeeping stays consistent — but no actual initialiser
    // code executes.
    patch_skip_initializers(&mut rewritten);

    // Layer 6: Redirect the non-simulator exit path in dyld's `start()`.
    //
    // After `main()` returns, dyld calls `LibSystemHelpersWrapper::exit()`
    // which goes through the shared cache's `exit()` → real `SVC #0x80` →
    // terminates the HOST process.  We redirect that `BL` to call the
    // loaded dyld's own `___exit` stub instead.  That stub (`mov x16, #1;
    // svc #0x80`) was already rewritten by the SVC patcher, so the exit
    // goes through the shim and is handled correctly.
    patch_exit_to_host(&mut rewritten);

    let data: &[u8] = &rewritten;

    // Parse dyld Mach-O header
    let header = macho::MachHeader64::<Endianness>::parse(data, 0)
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld invalid header: {e}")))?;
    let endian = header
        .endian()
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld endianness: {e}")))?;

    // Validate: must be ARM64, MH_DYLINKER (filetype 7)
    if header.cputype(endian) != macho::CPU_TYPE_ARM64 {
        return Err(MachoLoaderError::UnsupportedFormat);
    }
    if header.filetype(endian) != macho::MH_DYLINKER {
        return Err(MachoLoaderError::UnsupportedFormat);
    }

    // Collect segments and find entry point (LC_UNIXTHREAD)
    let mut segments = Vec::new();
    let mut entry_pc: Option<u64> = None;

    let mut commands = header
        .load_commands(endian, data, 0)
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld load commands: {e}")))?;

    while let Some(cmd) = commands
        .next()
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld iterate commands: {e}")))?
    {
        if let Some((seg, _sections)) = cmd
            .segment_64()
            .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld segment: {e}")))?
        {
            let name = &seg.segname;
            if *name == *b"__PAGEZERO\0\0\0\0\0\0" {
                continue;
            }
            segments.push(SegmentInfo {
                vmaddr: seg.vmaddr.get(endian),
                vmsize: seg.vmsize.get(endian),
                fileoff: seg.fileoff.get(endian),
                filesize: seg.filesize.get(endian),
                initprot: seg.initprot.get(endian),
                segname: *name,
            });
            continue;
        }

        // LC_UNIXTHREAD for dyld entry point
        if cmd.cmd() == macho::LC_UNIXTHREAD {
            let cmd_data = cmd.raw_data();
            if cmd_data.len() >= ARM64_THREAD_STATE_PC_OFFSET + 8 {
                let pc = u64::from_le_bytes(
                    cmd_data[ARM64_THREAD_STATE_PC_OFFSET..ARM64_THREAD_STATE_PC_OFFSET + 8]
                        .try_into()
                        .unwrap(),
                );
                entry_pc = Some(pc);
            }
        }
    }

    if segments.is_empty() {
        return Err(MachoLoaderError::NoTextSegment);
    }

    // Reserve-then-map strategy, same as for main binary but with a hint address
    // 256MB above DEFAULT_LOW_ADDR to avoid the main binary. This is only a hint —
    // if the region is occupied, the kernel will choose a different address.
    let min_vmaddr = segments
        .iter()
        .filter(|s| s.vmsize > 0)
        .map(|s| s.vmaddr as usize)
        .min()
        .unwrap_or(DEFAULT_LOW_ADDR);
    let max_vmend = segments
        .iter()
        .filter(|s| s.vmsize > 0)
        .map(|s| (s.vmaddr + s.vmsize) as usize)
        .max()
        .unwrap_or(DEFAULT_LOW_ADDR);

    let page_aligned_min = min_vmaddr & !(PAGE_SIZE - 1);
    let page_aligned_max = max_vmend.next_multiple_of(PAGE_SIZE);
    let total_span = page_aligned_max - page_aligned_min;

    let reserve_flags =
        litebox_common_linux::MapFlags::MAP_ANONYMOUS | litebox_common_linux::MapFlags::MAP_PRIVATE;
    let reserved_base = litebox_common_linux::mm::do_mmap(
        &task.global.pm,
        Some(DEFAULT_LOW_ADDR + DYLD_HINT_OFFSET),
        total_span,
        litebox_common_linux::ProtFlags::PROT_NONE,
        reserve_flags,
        false,
        |_| Ok(0),
    )
    .map_err(|e| {
        MachoLoaderError::MappingError(alloc::format!("dyld reserve {total_span:#x} bytes: {e:?}"))
    })?
    .as_usize();

    let slide = reserved_base.wrapping_sub(page_aligned_min);
    log_unsupported!("load_dyld: reserved at {reserved_base:#x}, slide={slide:#x}, total_span={total_span:#x}");

    // Map each segment
    for seg in &segments {
        if seg.vmsize == 0 {
            continue;
        }

        let vm_addr = (seg.vmaddr as usize).wrapping_add(slide);
        let vm_size = (seg.vmsize as usize).next_multiple_of(PAGE_SIZE);
        let final_prot = prot_from_macho(seg.initprot);
        let initial_prot = litebox_common_linux::ProtFlags::PROT_READ_WRITE;
        let flags = litebox_common_linux::MapFlags::MAP_ANONYMOUS
            | litebox_common_linux::MapFlags::MAP_PRIVATE
            | litebox_common_linux::MapFlags::MAP_FIXED;

        litebox_common_linux::mm::do_mmap(
            &task.global.pm,
            Some(vm_addr),
            vm_size,
            initial_prot,
            flags,
            false,
            |_| Ok(0),
        )
        .map_err(|e| {
            MachoLoaderError::MappingError(alloc::format!(
                "dyld mmap segment {:?} at {vm_addr:#x} size {vm_size:#x}: {e:?}",
                core::str::from_utf8(&seg.segname).unwrap_or("<invalid>")
            ))
        })?;

        log_unsupported!(
            "load_dyld: mapped segment {:?} at {vm_addr:#x} size {vm_size:#x}",
            core::str::from_utf8(&seg.segname).unwrap_or("<invalid>")
        );
        let file_size = seg.filesize as usize;
        if file_size > 0 {
            let file_off = seg.fileoff as usize;
            if file_off + file_size > data.len() {
                return Err(MachoLoaderError::ParseError(alloc::format!(
                    "dyld segment data at offset {file_off:#x} size {file_size:#x} exceeds file"
                )));
            }
            let dest: MutPtr<u8> = MutPtr::from_usize(vm_addr);
            dest.copy_from_slice(0, &data[file_off..file_off + file_size])
                .ok_or(MachoLoaderError::MemoryError(
                    "failed to copy dyld segment data".into(),
                ))?;
            log_unsupported!("load_dyld: copied {file_size:#x} bytes from file offset {file_off:#x}");
        }

        if final_prot != litebox_common_linux::ProtFlags::PROT_READ_WRITE {
            litebox_common_linux::mm::sys_mprotect(
                &task.global.pm,
                MutPtr::from_usize(vm_addr),
                vm_size,
                final_prot,
            )
            .map_err(|e| {
                MachoLoaderError::MappingError(alloc::format!(
                    "dyld mprotect segment at {vm_addr:#x}: {e:?}"
                ))
            })?;
        }
    }

    // Compute dyld entry point (LC_UNIXTHREAD gives absolute PC, apply slide)
    let entry_point =
        (entry_pc.ok_or(MachoLoaderError::NoEntryPoint)? as usize).wrapping_add(slide);

    // Debug: log dyld load info
    if cfg!(debug_assertions) {
        log_unsupported!(
            "dyld loaded: slide={slide:#x} entry={entry_point:#x} reserved_base={reserved_base:#x} min_vmaddr={min_vmaddr:#x}"
        );
    }

    // --- Initialize dyld's __LITEBOX trampoline ---
    //
    // dyld has its own __LITEBOX segment from the rewriter. We need to:
    // 1. Write the syscall callback address at offset 0 (same as main binary)
    // 2. Write the SAME TLS table address at offset 8 (reuse the one from main binary)
    // 3. Do NOT allocate a new TLS table
    // 4. Do NOT update HOST_TLS_TABLE_ADDR
    if let Some(litebox_seg) = segments
        .iter()
        .find(|s| s.segname.starts_with(b"__LITEBOX"))
    {
        let trampoline_start = (litebox_seg.vmaddr as usize).wrapping_add(slide);
        let trampoline_size = (litebox_seg.vmsize as usize).next_multiple_of(PAGE_SIZE);

        // Make writable
        litebox_common_linux::mm::sys_mprotect(
            &task.global.pm,
            MutPtr::from_usize(trampoline_start),
            trampoline_size,
            litebox_common_linux::ProtFlags::PROT_READ_WRITE,
        )
        .map_err(|e| {
            MachoLoaderError::MappingError(alloc::format!(
                "dyld mprotect __LITEBOX RW for init: {e:?}"
            ))
        })?;

        // Write syscall callback address at offset 0
        let callback_addr = litebox_platform_multiplex::platform().get_syscall_entry_point();
        let dest: MutPtr<u8> = MutPtr::from_usize(trampoline_start);
        dest.copy_from_slice(0, &callback_addr.to_ne_bytes())
            .ok_or(MachoLoaderError::MemoryError(
                "failed to write dyld trampoline callback address".into(),
            ))?;

        // Reuse the TLS table from the main binary (already allocated and stored)
        let tls_table_addr =
            litebox_common_linux::HOST_TLS_TABLE_ADDR.load(core::sync::atomic::Ordering::Acquire);
        dest.copy_from_slice(8, &tls_table_addr.to_ne_bytes())
            .ok_or(MachoLoaderError::MemoryError(
                "failed to write TLS table address in dyld trampoline".into(),
            ))?;

        // Re-protect as R-X
        litebox_common_linux::mm::sys_mprotect(
            &task.global.pm,
            MutPtr::from_usize(trampoline_start),
            trampoline_size,
            litebox_common_linux::ProtFlags::PROT_READ_EXEC,
        )
        .map_err(|e| {
            MachoLoaderError::MappingError(alloc::format!(
                "dyld mprotect __LITEBOX R-X after init: {e:?}"
            ))
        })?;
    }

    Ok(DyldLoadInfo {
        entry_point,
        slide,
        base: reserved_base,
        end: reserved_base + total_span,
    })
}

/// Convert macOS VM_PROT_* flags to litebox ProtFlags.
fn prot_from_macho(prot: u32) -> litebox_common_linux::ProtFlags {
    let mut flags = litebox_common_linux::ProtFlags::empty();
    if prot & macho::VM_PROT_READ != 0 {
        flags |= litebox_common_linux::ProtFlags::PROT_READ;
    }
    if prot & macho::VM_PROT_WRITE != 0 {
        flags |= litebox_common_linux::ProtFlags::PROT_WRITE;
    }
    if prot & macho::VM_PROT_EXECUTE != 0 {
        flags |= litebox_common_linux::ProtFlags::PROT_EXEC;
    }
    flags
}

/// ARM64 NOP instruction encoding.
const ARM64_NOP: u32 = 0xD503_201F;

/// Patch `restartWithDyldInCache` to return immediately instead of jumping to
/// the shared-cache copy of dyld.
///
/// `restartWithDyldInCache` is a two-instruction function:
///     mov sp, x0    (0x9100_001F)   — overwrite stack pointer
///     br  x3        (0xD61F_0060)   — jump to shared-cache dyld
///
/// We replace these with:
///     ret           (0xD65F_03C0)   — return to caller
///     nop           (0xD503_201F)   — padding
///
/// This lets the code *after* `bl restartWithDyldInCache` in dyld's `start()`
/// execute normally.  That code was previously unreachable ("dead code") because
/// `restartWithDyldInCache` never returned — it jumped to the shared-cache dyld.
/// But it contains essential initialisation (e.g. `SharedCacheLoader` setup)
/// that downstream code depends on.
///
/// On macOS-on-macOS the shared cache's dyld has stale TPRO state that cannot
/// be reset (hardware write-protected).  If the loaded dyld restarts into the
/// cached copy, `MemoryManager::init` hits `assert(!sMemoryManagerInitialized)`.
/// Making the function return prevents the restart and keeps execution in the
/// loaded dyld's pristine (disk-loaded) code.
///
/// The previously-dead code may call `shared_region_check_np` with an invalid
/// address and toggle TPRO protection on shared cache pages; both of those are
/// handled by guards in `sys_shared_region_check_np` (rejects invalid addresses)
/// and `sys_mach_vm_protect` (skips shared cache pages).
fn patch_restart_with_dyld_in_cache(data: &mut [u8]) {
    const MOV_SP_X0: u32 = 0x9100_001F; // mov sp, x0
    const BR_X3: u32 = 0xD61F_0060; // br  x3
    const ARM64_RET: u32 = 0xD65F_03C0; // ret

    // Scan for the two-instruction signature.
    let mut i = 0;
    while i + 8 <= data.len() {
        let w0 = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        let w1 = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap());
        if w0 == MOV_SP_X0 && w1 == BR_X3 {
            log_unsupported!(
                "patch_restart_with_dyld_in_cache: found at offset {:#x}, replacing with RET+NOP",
                i,
            );
            data[i..i + 4].copy_from_slice(&ARM64_RET.to_le_bytes());
            data[i + 4..i + 8].copy_from_slice(&ARM64_NOP.to_le_bytes());
            return;
        }
        i += 4;
    }

    log_unsupported!("patch_restart_with_dyld_in_cache: signature not found, skipping");
}

/// Patch `PrebuiltLoader::runInitializers` to skip the call to
/// `findAndRunAllInitializers`, preventing shared-cache library
/// initialisers from running on macOS-on-macOS.
///
/// `PrebuiltLoader::runInitializers` has this prologue:
///
/// ```text
///     pacibsp                      (0xD503_237F)
///     stp  x20, x19, [sp, #-0x20]! (0xA9BE_4FF4)
///     stp  x29, x30, [sp, #0x10]  (0xA901_7BFD)
///     add  x29, sp, #0x10         (0x9100_43FD)
///     mov  x19, x1                (0xAA01_03F3)
///     mov  x20, x0                (0xAA00_03F4)
///     ldrh w8, [x0, #0x2c]        (0x7940_5808)
///     tbz  w8, #0, +0xC           (0x3600_0088)
///     mov  x0, x20                (0xAA14_03E0)
///     mov  x1, x19                (0xAA13_03E1)
///     bl   findAndRunAllInitializers  ← NOP this
/// ```
///
/// We scan for the unique five-instruction signature:
///     ldrh w8, [x0, #0x2c]  /  tbz w8, #0, +0xC  /
///     mov x0, x20  /  mov x1, x19  /  bl ...
/// and NOP the BL.
///
/// After this patch `runInitializers` still marks each loader as
/// "initialised" (state byte = 9 at offset `[loader_array + idx]`), so
/// dyld's bookkeeping remains consistent.  No actual initialiser code
/// runs — which is correct on macOS-on-macOS because the host already
/// ran all shared-cache initialisers.
fn patch_skip_initializers(data: &mut [u8]) {
    // Five-instruction signature preceding the BL.
    const LDRH_W8_X0_0X2C: u32 = 0x7940_5808;
    const TBZ_W8_0_PLUS_0XC: u32 = 0x3600_0088;
    const MOV_X0_X20: u32 = 0xAA14_03E0;
    const MOV_X1_X19: u32 = 0xAA13_03E1;

    let mut i = 0;
    while i + 20 <= data.len() {
        let w0 = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        let w1 = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap());
        let w2 = u32::from_le_bytes(data[i + 8..i + 12].try_into().unwrap());
        let w3 = u32::from_le_bytes(data[i + 12..i + 16].try_into().unwrap());
        let w4 = u32::from_le_bytes(data[i + 16..i + 20].try_into().unwrap());

        if w0 == LDRH_W8_X0_0X2C
            && w1 == TBZ_W8_0_PLUS_0XC
            && w2 == MOV_X0_X20
            && w3 == MOV_X1_X19
            && (w4 >> 26) == 0b100101
        // BL opcode (bit 31 distinguishes BL from B)
        {
            let bl_offset = i + 16;
            log_unsupported!(
                "patch_skip_initializers: found BL to findAndRunAllInitializers at offset {:#x}, \
                 replacing with NOP",
                bl_offset,
            );
            data[bl_offset..bl_offset + 4].copy_from_slice(&ARM64_NOP.to_le_bytes());
            return;
        }
        i += 4;
    }

    log_unsupported!("patch_skip_initializers: signature not found, skipping");
}

/// Redirect `dyld4::start()`'s call to `LibSystemHelpersWrapper::exit()` so
/// that it calls the loaded dyld's own `___exit` instead.
///
/// After `main()` returns, dyld calls `exit()`.  On non-simulator platforms
/// it dispatches through `LibSystemHelpersWrapper::exit()`, which calls the
/// shared cache's `exit()` implementation via a vtable.  That function
/// executes a real `SVC #0x80` (not intercepted) that terminates the *host*
/// process rather than the guest.
///
/// The loaded dyld already contains its own `___exit` stub
/// (`mov x16, #0x1; svc #0x80`) whose SVC *is* rewritten by the SVC
/// patcher — so calling it goes through the shim correctly.
///
/// The two calls sit next to each other in `dyld4::start()`:
///
/// ```text
///     cbz  w0, +0xC              (0x3400_0060)
///     mov  x0, x19               (0xAA13_03E0)     ← simulator path
///     bl   ___exit               (BL_A)
///     ldr  x8, [sp, #0x1d0]     (0xF940_EBE8)     ← non-simulator path
///     add  x0, x8, #0xa0        (0x9102_8100)
///     mov  x1, x19              (0xAA13_03E1)
///     bl   LibSystemHelpersWrapper::exit  (BL_B)
/// ```
///
/// `LibSystemHelpersWrapper::exit` takes `(self, exitCode)` — exit code in
/// `x1`.  But `___exit` takes exit code in `x0`.  So we rewrite the
/// non-simulator path to:
///
/// ```text
///     mov  x0, x19              ← put exit code in x0
///     NOP
///     NOP
///     bl   ___exit              ← adjusted BL
/// ```
fn patch_exit_to_host(data: &mut [u8]) {
    const CBZ_W0_PLUS_0XC: u32 = 0x3400_0060;
    const MOV_X0_X19: u32 = 0xAA13_03E0;
    const LDR_X8_SP_0X1D0: u32 = 0xF940_EBE8;
    const ADD_X0_X8_0XA0: u32 = 0x9102_8100;
    const MOV_X1_X19: u32 = 0xAA13_03E1;

    let mut i = 0;
    while i + 28 <= data.len() {
        let w0 = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        let w1 = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap());
        let w2 = u32::from_le_bytes(data[i + 8..i + 12].try_into().unwrap()); // BL_A
        let w3 = u32::from_le_bytes(data[i + 12..i + 16].try_into().unwrap());
        let w4 = u32::from_le_bytes(data[i + 16..i + 20].try_into().unwrap());
        let w5 = u32::from_le_bytes(data[i + 20..i + 24].try_into().unwrap());
        let w6 = u32::from_le_bytes(data[i + 24..i + 28].try_into().unwrap()); // BL_B

        if w0 == CBZ_W0_PLUS_0XC
            && w1 == MOV_X0_X19
            && (w2 >> 26) == 0b100101 // BL_A
            && w3 == LDR_X8_SP_0X1D0
            && w4 == ADD_X0_X8_0XA0
            && w5 == MOV_X1_X19
            && (w6 >> 26) == 0b100101
        // BL_B
        {
            // Extract BL_A's signed imm26.
            let bl_a_imm26 = {
                let raw = (w2 & 0x03FF_FFFF).cast_signed();
                if raw & (1 << 25) != 0 {
                    raw | (!0x03FF_FFFF_u32).cast_signed()
                } else {
                    raw
                }
            };
            // BL_A is at file offset (i+8), targeting ___exit at some offset.
            // BL_B is at file offset (i+24).
            // The ___exit offset = (i+8) + bl_a_imm26 * 4.
            // New imm26 for BL_B = (___exit_offset - (i+24)) / 4
            //                    = bl_a_imm26 + (i+8)/4 - (i+24)/4
            //                    = bl_a_imm26 - 4
            let new_imm26 = bl_a_imm26 - 4;
            let new_bl = (0b100101_u32 << 26) | (new_imm26.cast_unsigned() & 0x03FF_FFFF);

            // Rewrite the non-simulator path: put exit code (x19) into x0,
            // NOP the two now-unnecessary instructions, and redirect BL.
            //
            //   w3 (ldr x8, ...) → mov x0, x19
            //   w4 (add x0, ...) → NOP
            //   w5 (mov x1, ...) → NOP
            //   w6 (bl wrapper)  → bl ___exit (adjusted)
            let w3_offset = i + 12;
            data[w3_offset..w3_offset + 4].copy_from_slice(&MOV_X0_X19.to_le_bytes());
            data[w3_offset + 4..w3_offset + 8].copy_from_slice(&ARM64_NOP.to_le_bytes());
            data[w3_offset + 8..w3_offset + 12].copy_from_slice(&ARM64_NOP.to_le_bytes());

            let bl_b_offset = i + 24;
            log_unsupported!(
                "patch_exit_to_host: redirecting BL at offset {:#x} to ___exit \
                 (was {:#010x}, now {:#010x})",
                bl_b_offset,
                w6,
                new_bl,
            );
            data[bl_b_offset..bl_b_offset + 4].copy_from_slice(&new_bl.to_le_bytes());
            return;
        }
        i += 4;
    }

    log_unsupported!("patch_exit_to_host: signature not found, skipping");
}
