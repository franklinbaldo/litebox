// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach-O loader for the macOS shim.

pub(crate) mod macho;
pub(crate) mod stack;

use alloc::string::String;
use thiserror::Error;

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// Default low address, above the 4GB `__PAGEZERO` segment.
pub(crate) const DEFAULT_LOW_ADDR: usize = 0x1_0000_0000;

#[derive(Error, Debug)]
pub enum MachoLoaderError {
    #[error("failed to parse Mach-O: {0}")]
    ParseError(String),
    #[error("unsupported Mach-O format")]
    UnsupportedFormat,
    #[error("no entry point found (need LC_MAIN or LC_UNIXTHREAD)")]
    NoEntryPoint,
    #[error("no __TEXT segment found")]
    NoTextSegment,
    #[error("invalid stack")]
    InvalidStackAddr,
    #[error("failed to mmap: {0}")]
    MappingError(String),
    #[error("memory error: {0}")]
    MemoryError(String),
}

/// Load info returned by the Mach-O loader.
pub struct MachoLoadInfo {
    /// The program entry point virtual address.
    pub entry_point: usize,
    /// The initial stack pointer (top of initialized stack).
    pub user_stack_top: usize,
    /// True if the binary uses LC_MAIN (entry is called as a function with
    /// argc in x0, argv in x1, envp in x2, apple in x3).
    /// False for LC_UNIXTHREAD (raw jump, argc at sp, argv at sp+8, etc).
    pub is_lc_main: bool,
    /// True if the binary has an LC_LOAD_DYLINKER command.
    pub has_dylinker: bool,
}

/// Load info returned by `load_dyld`.
pub(crate) struct DyldLoadInfo {
    /// dyld's entry point (from LC_UNIXTHREAD).
    pub(crate) entry_point: usize,
    /// The slide applied to dyld's segments.
    #[expect(dead_code, reason = "will be used when dyld debugging is needed")]
    pub(crate) slide: usize,
    /// Base address of the mapped dyld binary.
    pub(crate) base: usize,
    /// End address (exclusive) of the mapped dyld binary.
    pub(crate) end: usize,
}

/// Load a rewritten Mach-O binary and prepare it for execution.
pub(crate) fn load_macho<FS: crate::ShimFS>(
    task: &crate::Task<FS>,
    program_bytes: &[u8],
    argv: alloc::vec::Vec<alloc::ffi::CString>,
    envp: alloc::vec::Vec<alloc::ffi::CString>,
    dyld_bytes: Option<&[u8]>,
) -> Result<MachoLoadInfo, MachoLoaderError> {
    macho::load(task, program_bytes, argv, envp, dyld_bytes)
}
