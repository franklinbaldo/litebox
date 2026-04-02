// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Rewrite Mach-O files to hook syscalls.
//!
//! This crate supports AArch64 Mach-O executables (MH_EXECUTE).

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

/// Rewrite a Mach-O binary to hook `svc #0x80` instructions.
///
/// Returns the rewritten binary bytes.
pub fn hook_syscalls_in_macho(input_binary: &[u8]) -> Result<Vec<u8>> {
    let _ = input_binary;
    todo!("Mach-O rewriter not yet implemented")
}
