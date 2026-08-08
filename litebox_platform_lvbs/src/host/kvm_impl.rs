// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for a plain KVM/QEMU guest.
//!
//! Unlike LVBS, LiteBox here *is* the kernel: there is no VTL0 peer to delegate
//! to. The security boundary is ring 0 vs ring 3, enforced by page tables,
//! SMEP/SMAP and the syscall gate — a conventional OS threat model rather than
//! a VBS one.
//!
//! Phase 1 note: every method below is still a stub. Real implementations land
//! with the boot path in Phase 2.

use crate::{Errno, HostInterface, arch::ioport::serial_print_string};

pub type KvmGuest = crate::LinuxKernel<HostKvmInterface>;

pub struct HostKvmInterface;

impl HostInterface for HostKvmInterface {
    fn log(msg: &str) {
        serial_print_string(msg);
    }

    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        unimplemented!("KVM host allocator lands in Phase 2")
    }

    unsafe fn free(_addr: usize) {
        unimplemented!("KVM host allocator lands in Phase 2")
    }

    fn exit() -> ! {
        unimplemented!("isa-debug-exit lands in Phase 2")
    }

    fn terminate(_reason_set: u64, _reason_code: u64) -> ! {
        unimplemented!("isa-debug-exit lands in Phase 2")
    }

    fn wake_many(_mutex: &core::sync::atomic::AtomicU32, _n: usize) -> Result<usize, Errno> {
        unimplemented!()
    }

    fn block_or_maybe_timeout(
        _mutex: &core::sync::atomic::AtomicU32,
        _val: u32,
        _timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno> {
        unimplemented!()
    }

    fn send_ip_packet(_packet: &[u8]) -> Result<usize, Errno> {
        unimplemented!("virtio-net is post-milestone-1")
    }

    fn receive_ip_packet(_packet: &mut [u8]) -> Result<usize, Errno> {
        unimplemented!("virtio-net is post-milestone-1")
    }

    /// Unreachable on KVM: there is no lower VTL to switch back to.
    fn switch(_result: u64) -> ! {
        unreachable!("no VTL0 peer exists in a plain KVM guest")
    }
}
