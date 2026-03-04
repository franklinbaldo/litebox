// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of syscall interception for Linux userland.

#[cfg(all(target_arch = "x86_64", feature = "systrap_backend"))]
pub(crate) mod systrap;

#[cfg(all(target_arch = "x86_64", feature = "systrap_backend"))]
pub(crate) use systrap::init_sys_intercept;

#[cfg(target_arch = "x86")]
pub(crate) fn init_sys_intercept() {
    // TODO: Actually start intercepting syscalls on 32-bit Linux.
    //
    // Temporarily, we are not setting anything up, while getting things compiling onto 32-bit Linux.
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn init_sys_intercept() {
    // Syscall interception on aarch64 is handled by the rewriter backend.
    // No seccomp/systrap setup needed.
}

/// Certain syscalls with this magic argument are allowed.
/// This is useful for syscall interception where we need to invoke the original syscall.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYSCALL_ARG_MAGIC: usize = usize::from_le_bytes(*b"LITE BOX");
#[cfg(target_arch = "x86")]
pub(crate) const SYSCALL_ARG_MAGIC: usize = usize::from_le_bytes(*b"LtBx");
#[cfg(target_arch = "aarch64")]
pub(crate) const SYSCALL_ARG_MAGIC: usize = usize::from_le_bytes(*b"LITE BOX");

pub(crate) const MMAP_FLAG_MAGIC: u32 = 1 << 31;
