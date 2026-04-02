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
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use object::macho;
use object::read::macho::MachHeader;
use object::Endianness;

use super::stack::UserStack;
use super::{MachoLoadInfo, MachoLoaderError, DEFAULT_LOW_ADDR, DEFAULT_STACK_SIZE};
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

    // Map segments using do_mmap (same as sys_mmap uses internally).
    // Map as RW first to copy data, then mprotect to final permissions.
    for seg in &segments {
        if seg.vmsize == 0 {
            continue;
        }

        let vm_addr = seg.vmaddr as usize;
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

    // Compute entry point
    let entry_point = if is_lc_main {
        let text_base = text_vmaddr.ok_or(MachoLoaderError::NoTextSegment)?;
        let offset = entry_offset.ok_or(MachoLoaderError::NoEntryPoint)?;
        (text_base + offset) as usize
    } else {
        entry_offset.ok_or(MachoLoaderError::NoEntryPoint)? as usize
    };

    // Set brk after highest mapped segment
    let max_end = segments
        .iter()
        .map(|s| (s.vmaddr + s.vmsize) as usize)
        .max()
        .unwrap_or(DEFAULT_LOW_ADDR);
    let brk = max_end.next_multiple_of(PAGE_SIZE);
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
