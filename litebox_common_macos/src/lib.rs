// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common macOS items suitable for LiteBox

#![no_std]

extern crate alloc;

pub mod errno;
pub mod syscall;

// Re-export PtRegs from litebox_common_linux (same aarch64 register layout).
pub use litebox_common_linux::PtRegs;
