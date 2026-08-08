// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Architectural x86_64 paging constants.
//!
//! These are properties of the CPU, not of any particular hypervisor, so they
//! are shared by every host implementation.

/// Size of a 4 KiB page in bytes.
pub const PAGE_SIZE: usize = 4096;

/// `log2(PAGE_SIZE)`.
pub const PAGE_SHIFT: usize = 12;

/// Number of page table entries in one 4 KiB page table.
pub const PTES_PER_PAGE: usize = 512;
