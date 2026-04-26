// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module contains the loader for the LiteBox shim.

#![cfg(target_arch = "x86_64")]
pub mod auxv;
pub mod elf;
mod stack;

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// Offset added to the process's `addr_min` when computing the PIE load hint.
/// This places binaries low in the partition (growing upwards), leaving
/// room for top-down allocations (stack, mmap) at the high end.
pub(crate) const PIE_LOAD_OFFSET: usize = 0x1000_0000; // 256 MiB
