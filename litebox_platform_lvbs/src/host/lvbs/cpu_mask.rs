// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Linux `cpu_online_mask` ABI, as read from VTL0.
//!
//! Moved here from `host/linux.rs`. The rest of that file (`pt_regs`,
//! `Timespec`) is host-agnostic Linux ABI and stays shared; this type is not,
//! so it lives under `host/lvbs/` like everything else LVBS-specific.

#[cfg(feature = "host_lvbs")]
use litebox_common_lvbs::MAX_CORES;
#[cfg(feature = "host_lvbs")]
use zerocopy::{FromBytes, Immutable, KnownLayout};

#[cfg(feature = "host_lvbs")]
const BITS_PER_LONG: usize = 64;

/// The Linux `cpu_online_mask` ABI.
///
/// LVBS-only: the sole consumer is `mshv::vsm`, which reads VTL0's online mask
/// to drive AP boots. A KVM guest has no VTL0 peer to read a mask from, and no
/// AP bring-up of its own, so this is gated out rather than left to compile
/// dead. It is `pub`, so `dead_code` would never have flagged it.
#[cfg(feature = "host_lvbs")]
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct CpuMask {
    bits: [u64; MAX_CORES.div_ceil(BITS_PER_LONG)],
}

#[cfg(feature = "host_lvbs")]
impl CpuMask {
    #[expect(dead_code)]
    fn new() -> Self {
        CpuMask {
            bits: [0; MAX_CORES.div_ceil(BITS_PER_LONG)],
        }
    }

    pub fn for_each_cpu<F>(&self, mut f: F)
    where
        F: FnMut(usize),
    {
        for (i, &word) in self.bits.iter().enumerate() {
            if word == 0 {
                continue;
            }

            for j in 0..BITS_PER_LONG {
                if (word & (1 << j)) != 0 {
                    f(i * BITS_PER_LONG + j);
                }
            }
        }
    }
}
