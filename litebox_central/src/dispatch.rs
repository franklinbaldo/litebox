// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Conversion from [`SqEntry`] (ring buffer IPC) to [`SyscallRequest`]
//! (shim dispatch layer).
//!
//! This module builds a synthetic [`PtRegs`] from the arguments stored in an
//! [`SqEntry`] and delegates to [`SyscallRequest::try_from_raw`] for parsing.

use litebox_common_linux::{PtRegs, SyscallRequest, errno::Errno};
use litebox_ipc::ring::SqEntry;
use litebox_platform_multiplex::Platform;

/// Build a synthetic [`PtRegs`] from an [`SqEntry`]'s arguments.
///
/// Maps the six syscall arguments into the x86-64 register convention:
///
/// | `args` index | register   |
/// |--------------|------------|
/// | 0            | `rdi`      |
/// | 1            | `rsi`      |
/// | 2            | `rdx`      |
/// | 3            | `r10`      |
/// | 4            | `r8`       |
/// | 5            | `r9`       |
///
/// `orig_rax` is set from `entry.syscall_nr`.
#[cfg(target_arch = "x86_64")]
#[allow(clippy::cast_possible_truncation)] // x86_64: usize == u64, no truncation
pub(crate) fn sq_entry_to_ptregs(entry: &SqEntry) -> PtRegs {
    PtRegs {
        rdi: entry.args[0] as usize,
        rsi: entry.args[1] as usize,
        rdx: entry.args[2] as usize,
        r10: entry.args[3] as usize,
        r8: entry.args[4] as usize,
        r9: entry.args[5] as usize,
        orig_rax: entry.syscall_nr as usize,
        ..PtRegs::default()
    }
}

/// Parse an [`SqEntry`] into a typed [`SyscallRequest`].
///
/// Constructs synthetic [`PtRegs`] from the entry's argument array and syscall
/// number, then delegates to [`SyscallRequest::try_from_raw`].
///
/// Unsupported or unknown syscall numbers are logged to stderr and produce
/// an `Err(Errno)`.
pub fn parse_sq_entry(entry: &SqEntry) -> Result<SyscallRequest<Platform>, Errno> {
    let regs = sq_entry_to_ptregs(entry);
    SyscallRequest::<Platform>::try_from_raw(entry.syscall_nr as usize, &regs, |args| {
        eprintln!("litebox_central: unsupported syscall: {args}");
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU8;

    use super::*;

    /// Helper to create a zeroed `SqEntry` with the given syscall number.
    fn make_sq_entry(syscall_nr: u32) -> SqEntry {
        SqEntry {
            seq: 0,
            syscall_nr,
            thread_slot: 0,
            flags: 0,
            args: [0u64; 6],
            data_offset: 0,
            data_len: 0,
            ready: AtomicU8::new(0),
            _pad: [0u8; 23],
        }
    }

    #[test]
    fn parse_getpid() {
        // SYS_getpid is 39 on x86_64
        let entry = make_sq_entry(libc::SYS_getpid as u32);
        let result = parse_sq_entry(&entry);
        assert!(
            result.is_ok(),
            "getpid should parse successfully, got: {result:?}"
        );
    }

    #[test]
    fn parse_unknown_syscall() {
        let entry = make_sq_entry(0xFFFF);
        let result = parse_sq_entry(&entry);
        assert!(result.is_err(), "unknown syscall 0xFFFF should return Err");
    }
}
