// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Definitions for aarch64 signal context structures.

use zerocopy::{FromBytes, IntoBytes};

/// sigcontext for aarch64
/// See: https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm64/include/uapi/asm/sigcontext.h
///
/// Note: The kernel's `__reserved` field has `__attribute__((__aligned__(16)))`,
/// giving the overall struct a 16-byte alignment requirement.  This alignment
/// is enforced via explicit padding in `Ucontext` rather than via `repr(align(16))`
/// here, because `align(16)` would add trailing padding that conflicts with
/// zerocopy's `IntoBytes` derive.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
pub struct Sigcontext {
    pub fault_address: u64,
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    /// 4K reserved for FP/SIMD state and future extensions
    pub __reserved: [u8; 4096],
}
