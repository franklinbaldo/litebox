// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module contains the loader for the LiteBox shim.

#![cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
pub mod auxv;
pub mod elf;
mod stack;

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// A default low address is used for the binary (which grows upwards) to avoid
/// conflicts with the kernel's memory mappings (which grows downwards).
///
/// On macOS arm64 this must be above the 4GB `__PAGEZERO` segment.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) const DEFAULT_LOW_ADDR: usize = 0x1000_0000;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const DEFAULT_LOW_ADDR: usize = 0x1_0000_0000;
