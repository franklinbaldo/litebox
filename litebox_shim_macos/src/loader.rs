// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach-O loader stub for the macOS shim.
//!
//! Task 7 will implement the actual Mach-O loader that parses program bytes,
//! maps segments, and sets up the initial register context (entrypoint, stack).

/// Information returned by the Mach-O loader after successfully loading a binary.
pub struct MachoLoadInfo {
    /// The virtual address of the program entry point.
    pub entry_point: usize,
    /// The top of the user stack (initial SP value).
    pub user_stack_top: usize,
    /// Whether the entry was found via `LC_MAIN` (true) or `LC_UNIXTHREAD` (false).
    pub is_lc_main: bool,
}

/// Errors that can occur during Mach-O program loading.
#[derive(Debug)]
pub enum MachoLoaderError {
    /// The loader is not yet implemented (placeholder).
    NotImplemented,
}

impl core::fmt::Display for MachoLoaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MachoLoaderError::NotImplemented => write!(f, "Mach-O loader not yet implemented"),
        }
    }
}

/// Load a Mach-O binary into the task's address space.
///
/// # Stub
/// This is a placeholder for Task 7, which will implement the actual loader.
#[expect(dead_code, reason = "stub placeholder for Task 7")]
pub(crate) fn load_macho<FS: crate::ShimFS>(
    _task: &crate::Task<FS>,
    _program_bytes: &[u8],
    _argv: alloc::vec::Vec<alloc::ffi::CString>,
    _envp: alloc::vec::Vec<alloc::ffi::CString>,
) -> Result<MachoLoadInfo, MachoLoaderError> {
    todo!("Mach-O loader not yet implemented")
}
