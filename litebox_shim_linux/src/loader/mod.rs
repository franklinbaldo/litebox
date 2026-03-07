// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module contains the loader for the LiteBox shim.

#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub mod auxv;
pub mod elf;
mod stack;

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB
