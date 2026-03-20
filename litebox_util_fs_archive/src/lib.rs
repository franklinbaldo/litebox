// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LiteBox filesystem archive (`.lbfs`) format library.
//!
//! This crate provides reading and writing support for `.lbfs` archive files,
//! a page-aligned archive format designed for efficient mmap-based access.
//!
//! # Format
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │ Magic: "LiteBoxFSArchive v1\n"                      │
//! │ entry_count: u64 (little-endian)                    │
//! │ Entry 0: [path_len:u16][type:u16][page_count:u32]   │
//! │          [byte_size:u64]                            |
//! |          [data_offset:u64]                          │
//! │          [mode:u32][uid:u16][gid:u16]               │
//! │          [path bytes...]                            │
//! │ Entry 1: ...                                        │
//! │ ...                                                 │
//! │ Zero-padding to 4096-byte alignment                 │
//! ├─────────────────────────────────────────────────────┤
//! │ File 0 data (at data_offset, page-aligned)          │
//! │ (padded to page boundary)                           │
//! │ File 1 data ...                                     │
//! │ ...                                                 │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! All multi-byte integers are little-endian. Entry type 0 = file, 1 = directory.
//!
//! Directories have `byte_size = 0`, `page_count = 0`, `data_offset = 0`.
//!
//! Every file's `data_offset` is 4096-aligned.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;

use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const PAGE_SIZE: usize = 4096;

pub const MAGIC: &[u8; 20] = b"LiteBoxFSArchive v1\n";

/// A file entry
pub const ENTRY_TYPE_FILE: u16 = 0;
/// A directory entry
pub const ENTRY_TYPE_DIR: u16 = 1;

/// The fixed-size file header: magic bytes followed by the entry count.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct RawFileHeader {
    pub magic: [u8; 20],
    pub entry_count: U64,
}

/// The fixed-size portion of each entry header (before the variable-length path).
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy, Debug)]
pub struct RawEntryHeader {
    /// Length of the path string that follows this header.
    pub path_len: U16,
    /// Entry type, see [`ENTRY_TYPE_FILE`] and [`ENTRY_TYPE_DIR`]
    pub entry_type: U16,
    /// Number of 4096-byte pages occupied by this entry's data.
    pub page_count: U32,
    /// Exact byte size of the file content.
    pub byte_size: U64,
    /// Absolute byte offset from start of archive where data begins (page-aligned).
    pub data_offset: U64,
    /// POSIX permission mode bits.
    pub mode: U32,
    /// Owner user ID.
    pub uid: U16,
    /// Owner group ID.
    pub gid: U16,
}

/// A parsed header entry from an `.lbfs` archive (owned, with the path string).
#[derive(Debug, Clone)]
pub struct Entry {
    /// The raw fixed-size header fields.
    pub header: RawEntryHeader,
    /// The path of this entry (no leading `/`).
    pub path: String,
}

impl Entry {
    pub fn is_file(&self) -> bool {
        self.header.entry_type.get() == ENTRY_TYPE_FILE
    }

    pub fn is_dir(&self) -> bool {
        self.header.entry_type.get() == ENTRY_TYPE_DIR
    }
}

/// Error type for parsing `.lbfs` archives.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("archive data too short")]
    TooShort,
    #[error("invalid magic header")]
    InvalidMagic,
    #[error("truncated header")]
    TruncatedHeader,
    #[error("invalid entry type: {0}")]
    InvalidEntryType(u16),
    #[error("entry path is not valid UTF-8")]
    InvalidPath,
    #[error("data offset {0} is not page-aligned")]
    UnalignedDataOffset(u64),
    #[error("file data extends beyond archive")]
    DataOutOfBounds,
}

/// A parsed `.lbfs` archive, referencing the underlying data slice.
///
/// This struct is the primary interface for `no_std` consumers. It borrows
/// the archive data and provides O(1) access to file contents via the
/// pre-parsed entry index.
pub struct Archive<'a> {
    data: &'a [u8],
    entries: Vec<Entry>,
}

impl<'a> Archive<'a> {
    /// Parse an `.lbfs` archive from a byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < size_of::<RawFileHeader>() {
            return Err(ParseError::TooShort);
        }

        let (file_header, rest) =
            RawFileHeader::ref_from_prefix(data).map_err(|_| ParseError::TooShort)?;

        if file_header.magic != *MAGIC {
            return Err(ParseError::InvalidMagic);
        }

        let entry_count = file_header.entry_count.get();
        let mut remainder = rest;
        let mut entries = Vec::new();

        for _ in 0..entry_count {
            let (raw, after_header) = RawEntryHeader::ref_from_prefix(remainder)
                .map_err(|_| ParseError::TruncatedHeader)?;

            let path_len = raw.path_len.get() as usize;
            if after_header.len() < path_len {
                return Err(ParseError::TruncatedHeader);
            }

            let path_bytes = &after_header[..path_len];
            let path = core::str::from_utf8(path_bytes).map_err(|_| ParseError::InvalidPath)?;

            remainder = &after_header[path_len..];

            let entry_type = raw.entry_type.get();
            if entry_type != ENTRY_TYPE_FILE && entry_type != ENTRY_TYPE_DIR {
                return Err(ParseError::InvalidEntryType(entry_type));
            }

            if entry_type == ENTRY_TYPE_FILE {
                let offset = usize::try_from(raw.data_offset.get())
                    .map_err(|_| ParseError::DataOutOfBounds)?;
                if !offset.is_multiple_of(PAGE_SIZE) {
                    return Err(ParseError::UnalignedDataOffset(raw.data_offset.get()));
                }
                let end = offset
                    .checked_add(
                        usize::try_from(raw.byte_size.get())
                            .map_err(|_| ParseError::DataOutOfBounds)?,
                    )
                    .ok_or(ParseError::DataOutOfBounds)?;
                if end > data.len() {
                    return Err(ParseError::DataOutOfBounds);
                }
            }

            entries.push(Entry {
                header: *raw,
                path: String::from(path),
            });
        }

        Ok(Self { data, entries })
    }

    /// Returns the list of entries in this archive.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Returns the raw file content for a file entry.
    ///
    /// # Panics
    ///
    /// Panics if the entry is not a file or offsets are out of bounds (which
    /// cannot happen if the archive was successfully parsed).
    pub fn file_data(&self, entry: &Entry) -> &'a [u8] {
        assert!(entry.is_file(), "file_data called on non-file entry");
        let start = usize::try_from(entry.header.data_offset.get()).unwrap();
        let end = start
            .checked_add(usize::try_from(entry.header.byte_size.get()).unwrap())
            .unwrap();
        &self.data[start..end]
    }

    /// Returns the underlying raw archive data.
    pub fn raw_data(&self) -> &'a [u8] {
        self.data
    }
}

/// Align `offset` up to the next multiple of `PAGE_SIZE`.
pub const fn align_to_page(offset: usize) -> usize {
    (offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

#[cfg(feature = "std")]
pub mod writer;
