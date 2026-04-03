// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Rewrite Mach-O files to hook syscalls.
//!
//! This crate supports AArch64 Mach-O executables (MH_EXECUTE).

pub mod arm64;

pub use arm64::patch_code_segment;

use object::macho;
use object::read::macho::{MachHeader, Segment};
use object::Endianness;
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("unsupported object file format")]
    UnsupportedObjectFile,
    #[error("no executable sections found")]
    NoTextSectionFound,
    #[error("no SVC #0x80 instructions found")]
    NoSvcInstructionsFound,
    #[error("disassembly failure: {0}")]
    DisassemblyFailure(String),
    #[error("insufficient header space for new load command")]
    InsufficientHeaderSpace,
}

pub type Result<T> = core::result::Result<T, Error>;

/// Parse a Mach-O binary and extract executable section info.
fn parse_text_sections(data: &[u8]) -> Result<Vec<arm64::TextSectionInfo>> {
    let header = macho::MachHeader64::<Endianness>::parse(data, 0)
        .map_err(|e| Error::ParseError(format!("invalid Mach-O header: {e}")))?;
    let endian = header
        .endian()
        .map_err(|e| Error::ParseError(format!("unsupported endianness: {e}")))?;

    // Validate: must be MH_EXECUTE or MH_DYLINKER, CPU_TYPE_ARM64
    if header.cputype(endian) != macho::CPU_TYPE_ARM64 {
        return Err(Error::UnsupportedObjectFile);
    }
    let filetype = header.filetype(endian);
    // MH_DYLINKER = 7 (the dynamic linker, e.g. /usr/lib/dyld)
    if filetype != macho::MH_EXECUTE && filetype != 7 {
        return Err(Error::UnsupportedObjectFile);
    }

    let mut sections = Vec::new();
    let mut commands = header
        .load_commands(endian, data, 0)
        .map_err(|e| Error::ParseError(format!("failed to read load commands: {e}")))?;

    while let Some(cmd) = commands
        .next()
        .map_err(|e| Error::ParseError(format!("failed to iterate load commands: {e}")))?
    {
        if let Some((seg, section_data)) = cmd
            .segment_64()
            .map_err(|e| Error::ParseError(format!("failed to parse segment: {e}")))?
        {
            let segname = seg.segname();
            // Skip __PAGEZERO
            if *segname == *b"__PAGEZERO\0\0\0\0\0\0" {
                continue;
            }
            // Iterate sections within the segment
            let seg_sections: &[macho::Section64<Endianness>] = seg
                .sections(endian, section_data)
                .map_err(|e| Error::ParseError(format!("failed to read sections: {e}")))?;
            for section in seg_sections {
                let flags = section.flags.get(endian);
                let section_type = flags & macho::SECTION_TYPE;
                // Include regular code sections and stub sections
                if section_type == macho::S_REGULAR || section_type == macho::S_SYMBOL_STUBS {
                    let attrs = flags & macho::SECTION_ATTRIBUTES;
                    if attrs & macho::S_ATTR_SOME_INSTRUCTIONS != 0
                        || attrs & macho::S_ATTR_PURE_INSTRUCTIONS != 0
                    {
                        #[allow(clippy::cast_possible_truncation)] // aarch64-only: u64 fits usize.
                        sections.push(arm64::TextSectionInfo {
                            vaddr: section.addr.get(endian),
                            file_offset: section.offset.get(endian) as usize,
                            size: section.size.get(endian) as usize,
                        });
                    }
                }
            }
        }
    }

    if sections.is_empty() {
        return Err(Error::NoTextSectionFound);
    }
    Ok(sections)
}

/// Find the highest virtual address + size across all segments.
fn find_max_segment_end(data: &[u8]) -> Result<u64> {
    let header = macho::MachHeader64::<Endianness>::parse(data, 0)
        .map_err(|e| Error::ParseError(format!("{e}")))?;
    let endian = header
        .endian()
        .map_err(|e| Error::ParseError(format!("{e}")))?;
    let mut max_end: u64 = 0;
    let mut commands = header
        .load_commands(endian, data, 0)
        .map_err(|e| Error::ParseError(format!("{e}")))?;
    while let Some(cmd) = commands
        .next()
        .map_err(|e| Error::ParseError(format!("{e}")))?
    {
        if let Some((seg, _)) = cmd
            .segment_64()
            .map_err(|e| Error::ParseError(format!("{e}")))?
        {
            let end = seg.vmaddr(endian) + seg.vmsize(endian);
            if end > max_end {
                max_end = end;
            }
        }
    }
    Ok(max_end)
}

/// Size of a segment_command_64 structure.
const SEGMENT_COMMAND_64_SIZE: usize = 72;

#[allow(clippy::cast_possible_truncation)]
fn insert_load_command_and_trampoline(
    buf: &mut Vec<u8>,
    trampoline_data: &[u8],
    trampoline_vaddr: u64,
) -> Result<()> {
    let header = macho::MachHeader64::<Endianness>::parse(buf.as_slice(), 0)
        .map_err(|e| Error::ParseError(format!("{e}")))?;
    let endian = header
        .endian()
        .map_err(|e| Error::ParseError(format!("{e}")))?;

    let header_size = core::mem::size_of::<macho::MachHeader64<Endianness>>();
    let existing_cmds_size = header.sizeofcmds(endian) as usize;
    let cmds_end = header_size + existing_cmds_size;

    // Find earliest section/segment data offset to know how much header space is free.
    //
    // The __TEXT segment typically starts at fileoff=0, which includes the Mach-O header
    // and load commands. We need to find the first *section* offset within such segments,
    // or the fileoff of non-zero-offset segments, to determine where actual content begins
    // after the header area.
    let mut earliest_data_offset = buf.len();
    let mut commands = header
        .load_commands(endian, buf.as_slice(), 0)
        .map_err(|e| Error::ParseError(format!("{e}")))?;
    while let Some(cmd) = commands
        .next()
        .map_err(|e| Error::ParseError(format!("{e}")))?
    {
        if let Some((seg, section_data)) = cmd
            .segment_64()
            .map_err(|e| Error::ParseError(format!("{e}")))?
        {
            let off = seg.fileoff(endian) as usize;
            let sz = seg.filesize(endian) as usize;
            if sz == 0 {
                continue;
            }
            if off == 0 {
                // Segment at fileoff 0 contains the header. Look at individual
                // section offsets to find where actual content starts.
                let sections: &[macho::Section64<Endianness>] = seg
                    .sections(endian, section_data)
                    .map_err(|e| Error::ParseError(format!("{e}")))?;
                for section in sections {
                    let sec_off = section.offset.get(endian) as usize;
                    if sec_off > 0 && sec_off < earliest_data_offset {
                        earliest_data_offset = sec_off;
                    }
                }
            } else if off < earliest_data_offset {
                earliest_data_offset = off;
            }
        }
    }

    let available = earliest_data_offset.saturating_sub(cmds_end);
    if available < SEGMENT_COMMAND_64_SIZE {
        return Err(Error::InsufficientHeaderSpace);
    }

    // Append trampoline data at end of file, 16KB page-aligned
    let trampoline_file_offset = (buf.len() + 0x3FFF) & !0x3FFF;
    buf.resize(trampoline_file_offset, 0); // pad to page boundary
    buf.extend_from_slice(trampoline_data);
    let trampoline_file_size = trampoline_data.len();
    // Round vm size up to 16KB page
    let trampoline_vm_size = (trampoline_file_size + 0x3FFF) & !0x3FFF;

    // Build LC_SEGMENT_64 command bytes
    let mut seg_cmd = [0u8; SEGMENT_COMMAND_64_SIZE];
    // cmd = LC_SEGMENT_64
    seg_cmd[0..4].copy_from_slice(&macho::LC_SEGMENT_64.to_le_bytes());
    // cmdsize
    seg_cmd[4..8].copy_from_slice(&(SEGMENT_COMMAND_64_SIZE as u32).to_le_bytes());
    // segname = "__LITEBOX\0..."
    seg_cmd[8..24].copy_from_slice(b"__LITEBOX\0\0\0\0\0\0\0");
    // vmaddr
    seg_cmd[24..32].copy_from_slice(&trampoline_vaddr.to_le_bytes());
    // vmsize
    seg_cmd[32..40].copy_from_slice(&(trampoline_vm_size as u64).to_le_bytes());
    // fileoff
    seg_cmd[40..48].copy_from_slice(&(trampoline_file_offset as u64).to_le_bytes());
    // filesize
    seg_cmd[48..56].copy_from_slice(&(trampoline_file_size as u64).to_le_bytes());
    // maxprot = VM_PROT_READ | VM_PROT_EXECUTE (5)
    seg_cmd[56..60].copy_from_slice(&5u32.to_le_bytes());
    // initprot = VM_PROT_READ | VM_PROT_EXECUTE (5)
    seg_cmd[60..64].copy_from_slice(&5u32.to_le_bytes());
    // nsects = 0
    seg_cmd[64..68].copy_from_slice(&0u32.to_le_bytes());
    // flags = 0
    seg_cmd[68..72].copy_from_slice(&0u32.to_le_bytes());

    // Verify the header space we're about to overwrite is all zeros (unused padding)
    if buf[cmds_end..cmds_end + SEGMENT_COMMAND_64_SIZE]
        .iter()
        .any(|&b| b != 0)
    {
        return Err(Error::InsufficientHeaderSpace);
    }

    // Insert the load command at cmds_end
    buf[cmds_end..cmds_end + SEGMENT_COMMAND_64_SIZE].copy_from_slice(&seg_cmd);

    // Update header: ncmds += 1, sizeofcmds += 72
    let ncmds_offset = 16; // offset of ncmds in MachHeader64
    let sizeofcmds_offset = 20;
    let old_ncmds = u32::from_le_bytes(buf[ncmds_offset..ncmds_offset + 4].try_into().unwrap());
    let old_sizeofcmds = u32::from_le_bytes(
        buf[sizeofcmds_offset..sizeofcmds_offset + 4]
            .try_into()
            .unwrap(),
    );
    buf[ncmds_offset..ncmds_offset + 4].copy_from_slice(&(old_ncmds + 1).to_le_bytes());
    buf[sizeofcmds_offset..sizeofcmds_offset + 4]
        .copy_from_slice(&(old_sizeofcmds + SEGMENT_COMMAND_64_SIZE as u32).to_le_bytes());

    Ok(())
}

/// Rewrite a Mach-O binary to hook `svc #0x80` instructions.
///
/// Returns the rewritten binary bytes.
pub fn hook_syscalls_in_macho(input_binary: &[u8]) -> Result<Vec<u8>> {
    let text_sections = parse_text_sections(input_binary)?;
    let mut buf = input_binary.to_vec();

    // Compute trampoline vaddr: page-aligned address past all segments
    let max_vaddr = find_max_segment_end(input_binary)?;
    let trampoline_vaddr = (max_vaddr + 0x3FFF) & !0x3FFF; // 16KB page align

    let trampoline_data = arm64::hook_syscalls_aarch64(&mut buf, &text_sections, trampoline_vaddr)?;

    insert_load_command_and_trampoline(&mut buf, &trampoline_data, trampoline_vaddr)?;

    Ok(buf)
}
