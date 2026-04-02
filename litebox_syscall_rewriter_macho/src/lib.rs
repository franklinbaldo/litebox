// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Rewrite Mach-O files to hook syscalls.
//!
//! This crate supports AArch64 Mach-O executables (MH_EXECUTE).

pub mod arm64;

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

    // Validate: must be MH_EXECUTE, CPU_TYPE_ARM64
    if header.cputype(endian) != macho::CPU_TYPE_ARM64 {
        return Err(Error::UnsupportedObjectFile);
    }
    let filetype = header.filetype(endian);
    if filetype != macho::MH_EXECUTE {
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

/// Rewrite a Mach-O binary to hook `svc #0x80` instructions.
///
/// Returns the rewritten binary bytes.
pub fn hook_syscalls_in_macho(input_binary: &[u8]) -> Result<Vec<u8>> {
    let text_sections = parse_text_sections(input_binary)?;
    let buf = input_binary.to_vec();
    let sites = arm64::find_patch_sites(&text_sections, &buf)?;

    if sites.is_empty() {
        return Err(Error::NoSvcInstructionsFound);
    }

    // TODO: Task 5 will add trampoline emission and patching here.
    let _ = sites;

    todo!("trampoline emission not yet implemented")
}
