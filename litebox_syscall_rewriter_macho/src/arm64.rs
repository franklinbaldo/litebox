// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 Mach-O syscall rewriting.

use crate::{Error, Result};

/// `SVC #0x80` encoding: 0xD4001001
pub const SVC_0X80: u32 = 0xD4001001;

/// Metadata for an executable section in the Mach-O.
#[derive(Debug)]
pub struct TextSectionInfo {
    /// Virtual address of the section.
    pub vaddr: u64,
    /// File offset of the section.
    pub file_offset: usize,
    /// Size of the section in bytes.
    pub size: usize,
}

/// A site in the binary that needs patching.
#[derive(Debug)]
pub struct PatchSite {
    /// File offset of the instruction.
    pub file_offset: usize,
    /// Virtual address of the instruction.
    pub vaddr: u64,
    /// Kind of patch.
    pub kind: PatchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchKind {
    /// `SVC #0x80` — BSD syscall.
    Svc,
}

/// Find all patch sites in the given executable sections.
pub fn find_patch_sites(text_sections: &[TextSectionInfo], buf: &[u8]) -> Result<Vec<PatchSite>> {
    let mut sites = Vec::new();
    for section in text_sections {
        let start = section.file_offset;
        let end = start + section.size;
        if end > buf.len() {
            return Err(Error::ParseError(format!(
                "section at offset {start:#x} extends past end of file"
            )));
        }
        // Walk 4 bytes at a time
        let mut offset = start;
        let mut vaddr = section.vaddr;
        while offset + 4 <= end {
            let insn = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
            if insn == SVC_0X80 {
                sites.push(PatchSite {
                    file_offset: offset,
                    vaddr,
                    kind: PatchKind::Svc,
                });
            }
            offset += 4;
            vaddr += 4;
        }
    }
    Ok(sites)
}
