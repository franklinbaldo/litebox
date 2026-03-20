// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Writer for `.lbfs` archives. Requires the `std` feature.

use std::io::{self, Write};
use std::path::Path;

use zerocopy::IntoBytes;

use crate::{
    ENTRY_TYPE_DIR, ENTRY_TYPE_FILE, MAGIC, PAGE_SIZE, RawEntryHeader, RawFileHeader, align_to_page,
};
use zerocopy::little_endian::{U16, U32, U64};

/// A single file or directory to be added to an archive.
pub struct InputEntry {
    /// Path within the archive (no leading `/`).
    pub path: String,
    /// Entry type: [`ENTRY_TYPE_FILE`] or [`ENTRY_TYPE_DIR`].
    pub entry_type: u16,
    /// File contents (empty for directories).
    pub data: Vec<u8>,
    /// POSIX permission mode bits (masked to 0o7777).
    pub mode: u32,
    /// Owner user ID.
    pub uid: u16,
    /// Owner group ID.
    pub gid: u16,
}

/// Build an `.lbfs` archive from a list of entries and write it to `output`.
pub fn write_archive(entries: &[InputEntry], mut output: impl Write) -> io::Result<()> {
    let mut header_size = size_of::<RawFileHeader>();
    for entry in entries {
        header_size += size_of::<RawEntryHeader>() + entry.path.len();
    }
    let data_region_start = align_to_page(header_size);

    let mut data_offsets: Vec<u64> = Vec::with_capacity(entries.len());
    let mut current_offset = data_region_start;
    for entry in entries {
        if entry.entry_type == ENTRY_TYPE_FILE {
            data_offsets.push(current_offset as u64);
            let pages = entry.data.len().div_ceil(PAGE_SIZE);
            current_offset += pages * PAGE_SIZE;
        } else {
            data_offsets.push(0);
        }
    }

    let file_header = RawFileHeader {
        magic: *MAGIC,
        entry_count: U64::new(entries.len() as u64),
    };
    output.write_all(file_header.as_bytes())?;

    for (i, entry) in entries.iter().enumerate() {
        let page_count = if entry.entry_type == ENTRY_TYPE_FILE {
            #[expect(
                clippy::missing_panics_doc,
                reason = "to panic, it'd need a 16 TiB file, at which point there are bigger problems lol"
            )]
            u32::try_from(entry.data.len().div_ceil(PAGE_SIZE)).unwrap()
        } else {
            0
        };
        let byte_size = if entry.entry_type == ENTRY_TYPE_FILE {
            entry.data.len() as u64
        } else {
            0
        };

        let raw = RawEntryHeader {
            path_len: U16::new(
                u16::try_from(entry.path.len())
                    .map_err(|_| io::Error::other("overlarge path length"))?,
            ),
            entry_type: U16::new(entry.entry_type),
            page_count: U32::new(page_count),
            byte_size: U64::new(byte_size),
            data_offset: U64::new(data_offsets[i]),
            mode: U32::new(entry.mode),
            uid: U16::new(entry.uid),
            gid: U16::new(entry.gid),
        };
        output.write_all(raw.as_bytes())?;
        output.write_all(entry.path.as_bytes())?;
    }

    let written_header = size_of::<RawFileHeader>()
        + entries
            .iter()
            .map(|e| size_of::<RawEntryHeader>() + e.path.len())
            .sum::<usize>();
    let padding = data_region_start - written_header;
    if padding > 0 {
        output.write_all(&vec![0u8; padding])?;
    }

    for entry in entries {
        if entry.entry_type != ENTRY_TYPE_FILE {
            continue;
        }
        output.write_all(&entry.data)?;
        let remainder = entry.data.len() % PAGE_SIZE;
        if remainder != 0 {
            let file_padding = PAGE_SIZE - remainder;
            output.write_all(&vec![0u8; file_padding])?;
        }
    }

    output.flush()?;
    Ok(())
}

/// Collect all files and directories under `root` into a list of [`InputEntry`] values
/// suitable for [`write_archive`].
pub fn collect_from_directory(root: &Path) -> io::Result<Vec<InputEntry>> {
    use std::os::unix::fs::MetadataExt;

    let mut entries = Vec::new();
    let walker = walkdir::WalkDir::new(root)
        .follow_links(true)
        .sort_by_file_name();

    for result in walker {
        let dir_entry = result.map_err(io::Error::other)?;
        let rel_path = dir_entry
            .path()
            .strip_prefix(root)
            .map_err(io::Error::other)?;

        if rel_path.as_os_str().is_empty() {
            continue;
        }

        let rel_str = rel_path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 path"))?
            .to_string();

        let metadata = dir_entry.metadata().map_err(io::Error::other)?;
        let mode = metadata.mode() & 0o7777;
        let uid =
            u16::try_from(metadata.uid()).map_err(|_| io::Error::other("uid must be < 65536"))?;
        let gid =
            u16::try_from(metadata.gid()).map_err(|_| io::Error::other("gid must be < 65536"))?;

        if metadata.is_dir() {
            entries.push(InputEntry {
                path: rel_str,
                entry_type: ENTRY_TYPE_DIR,
                data: Vec::new(),
                mode,
                uid,
                gid,
            });
        } else if metadata.is_file() {
            let data = std::fs::read(dir_entry.path())?;
            entries.push(InputEntry {
                path: rel_str,
                entry_type: ENTRY_TYPE_FILE,
                data,
                mode,
                uid,
                gid,
            });
        }
    }

    Ok(entries)
}
