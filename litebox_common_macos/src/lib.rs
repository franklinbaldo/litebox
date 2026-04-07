// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common macOS items suitable for LiteBox

#![no_std]

extern crate alloc;

pub mod errno;
pub mod syscall;

// Re-export PtRegs from litebox_common_linux (same aarch64 register layout).
pub use litebox_common_linux::PtRegs;

/// macOS rlimit struct (same as BSD struct rlimit on 64-bit).
#[repr(C)]
#[derive(Copy, Clone, Debug, zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

/// macOS `stack_t` / `struct sigaltstack` (used by sigaltstack syscall).
///
/// Layout: `{ void *ss_sp, size_t ss_size, int ss_flags, int _pad }` = 24 bytes.
#[repr(C)]
#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
)]
pub struct SigAltStack {
    /// Stack base pointer.
    pub ss_sp: usize,
    /// Stack size in bytes.
    pub ss_size: usize,
    /// Flags (SS_ONSTACK, SS_DISABLE).
    pub ss_flags: i32,
    /// Explicit padding for repr(C) alignment (unused).
    /// Explicit padding for repr(C) alignment.
    pub pad: i32,
}

impl SigAltStack {
    /// A disabled (empty) altstack.
    pub const DISABLED: Self = Self {
        ss_sp: 0,
        ss_size: 0,
        ss_flags: SS_DISABLE,
        pad: 0,
    };
}

/// SS_ONSTACK: currently executing on the alternate signal stack.
pub const SS_ONSTACK: i32 = 0x0001;
/// SS_DISABLE: alternate signal stack is disabled.
pub const SS_DISABLE: i32 = 0x0004;
/// Minimum signal stack size (from macOS headers: MINSIGSTKSZ = 32768).
pub const MINSIGSTKSZ: usize = 32768;

/// macOS RLIMIT_* resource constants (BSD numbering, differs from Linux).
#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum RlimitResource {
    Cpu = 0,
    Fsize = 1,
    Data = 2,
    Stack = 3,
    Core = 4,
    /// RSS on macOS; also used as AS (address space).
    Rss = 5,
    Memlock = 6,
    Nproc = 7,
    Nofile = 8,
}

impl RlimitResource {
    /// Total number of resource types we track.
    pub const COUNT: usize = 9;

    /// Try to convert a raw u32 to a resource variant.
    pub fn from_raw(n: u32) -> Option<Self> {
        match n {
            0 => Some(Self::Cpu),
            1 => Some(Self::Fsize),
            2 => Some(Self::Data),
            3 => Some(Self::Stack),
            4 => Some(Self::Core),
            5 => Some(Self::Rss),
            6 => Some(Self::Memlock),
            7 => Some(Self::Nproc),
            8 => Some(Self::Nofile),
            _ => None,
        }
    }
}
