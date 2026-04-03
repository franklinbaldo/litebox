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
use super::{DEFAULT_LOW_ADDR, DEFAULT_STACK_SIZE, MachoLoadInfo, MachoLoaderError};
use crate::{MutPtr, ShimFS, Task};

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
) -> Result<MachoLoadInfo, MachoLoaderError> {
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
            // ARM64 thread state layout:
            // cmd(4) + cmdsize(4) + flavor(4) + count(4) = 16 bytes header
            // Then 32 general-purpose registers (x0-x30, sp) at 8 bytes each = 256 bytes
            // PC is at register index 32 (after the 32 GPRs)
            let pc_offset = 16 + 32 * 8;
            if cmd_data.len() >= pc_offset + 8 {
                let pc = u64::from_le_bytes(cmd_data[pc_offset..pc_offset + 8].try_into().unwrap());
                entry_offset = Some(pc);
                is_lc_main = false;
            }
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

    // --- Initialize trampoline callback address and TLS table ---
    //
    // The __LITEBOX segment contains the trampoline code emitted by the
    // Mach-O syscall rewriter. The first 8 bytes are reserved for the
    // platform's syscall callback address, and bytes 8..16 are reserved
    // for the TLS lookup table pointer. The rewriter initializes both to
    // zero; we must fill them in now that the segment is mapped.
    //
    // This mirrors what the ELF loader does in load_trampoline().
    #[allow(clippy::items_after_statements)]
    if let Some(litebox_seg) = segments
        .iter()
        .find(|s| s.segname.starts_with(b"__LITEBOX"))
    {
        let trampoline_start = (litebox_seg.vmaddr as usize).wrapping_add(slide);
        let trampoline_size = (litebox_seg.vmsize as usize).next_multiple_of(PAGE_SIZE);

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

        // Allocate TLS lookup table.
        //
        // Layout: array of [guest_tpidr: u64, host_tls: u64] entries.
        // 256 usable entries + 8 overflow sentinel entries for hash probe.
        const TLS_ENTRY_SIZE: usize = 16;
        const TLS_TABLE_USABLE_ENTRIES: usize = 256;
        const TLS_TABLE_OVERFLOW_ENTRIES: usize = 8;
        const TLS_TABLE_TOTAL_ENTRIES: usize =
            TLS_TABLE_USABLE_ENTRIES + TLS_TABLE_OVERFLOW_ENTRIES;
        const TLS_TABLE_SIZE: usize = TLS_TABLE_TOTAL_ENTRIES * TLS_ENTRY_SIZE; // 4224 bytes

        // On macOS aarch64, the host page size is 16KB. Align the TLS table
        // to 16KB to ensure it gets its own host page and doesn't share a
        // page with the trampoline (which will be mprotected to R-X).
        const HOST_PAGE_SIZE: usize = 16384;
        let tls_table_addr = brk
            .max(trampoline_start + trampoline_size)
            .next_multiple_of(HOST_PAGE_SIZE);
        let tls_table_end = (tls_table_addr + TLS_TABLE_SIZE).next_multiple_of(PAGE_SIZE);

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

        // Write the TLS table address at trampoline offset 8.
        dest.copy_from_slice(8, &tls_table_addr.to_ne_bytes())
            .ok_or(MachoLoaderError::MemoryError(
                "failed to write TLS table address in trampoline".into(),
            ))?;

        // Store TLS table address in the global atomic so the platform's
        // update_host_tls_entry() can find and write to it.
        litebox_common_linux::HOST_TLS_TABLE_ADDR
            .store(tls_table_addr, core::sync::atomic::Ordering::Release);

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

        // Update brk past the TLS table.
        brk = brk.max(tls_table_end);
    }

    // Set the initial brk now that all segments and TLS table are mapped.
    task.global.pm.set_initial_brk(brk);

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
    let mut stack =
        UserStack::new(sp, DEFAULT_STACK_SIZE).ok_or(MachoLoaderError::InvalidStackAddr)?;
    stack
        .init(argv, envp)
        .ok_or(MachoLoaderError::InvalidStackAddr)?;

    Ok(MachoLoadInfo {
        entry_point,
        user_stack_top: stack.get_cur_stack_top(),
        is_lc_main,
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
