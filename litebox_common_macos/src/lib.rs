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
