// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! GS-based thread-local storage for micro-LiteBox.

use crate::state::MicroState;

/// Per-thread micro-LiteBox state, pointed to by GS base.
///
/// **ABI contract**: the assembly trampoline accesses fields by byte offset.
/// Do not reorder fields.
#[repr(C)]
pub struct MicroTls {
    /// Self-pointer for sanity checks (offset 0x00).
    pub self_ptr: *mut MicroTls,
    /// Pointer to the global [`MicroState`] (offset 0x08).
    pub micro: *mut MicroState,
    /// Thread slot assigned by central (offset 0x10).
    pub thread_slot: u64,
    /// Monotonic sequence counter for SQ entries (offset 0x18).
    pub seq_counter: u64,
    /// Return address save slot used by the asm trampoline (offset 0x20).
    pub return_addr: u64,
}

// Compile-time offset verification.
const _: () = {
    assert!(core::mem::offset_of!(MicroTls, self_ptr) == 0x00);
    assert!(core::mem::offset_of!(MicroTls, micro) == 0x08);
    assert!(core::mem::offset_of!(MicroTls, thread_slot) == 0x10);
    assert!(core::mem::offset_of!(MicroTls, seq_counter) == 0x18);
    assert!(core::mem::offset_of!(MicroTls, return_addr) == 0x20);
};

const TLS_ALLOC_SIZE: usize = 4096;

/// Initialize GS-based TLS for the current thread.
///
/// # Safety
///
/// - Must be called exactly once per thread, before any guest code runs.
/// - `micro_state` must be a valid pointer that outlives the thread.
///
/// # Panics
///
/// Panics if `mmap` fails to allocate the TLS page or if `arch_prctl` fails
/// to set the GS base.
pub unsafe fn micro_init_thread_inner(
    micro_state: *mut MicroState,
    thread_slot: u16,
) -> *mut MicroTls {
    let ptr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            TLS_ALLOC_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap for MicroTls failed");

    let tls = ptr.cast::<MicroTls>();
    unsafe {
        (*tls).self_ptr = tls;
        (*tls).micro = micro_state;
        (*tls).thread_slot = u64::from(thread_slot);
        (*tls).seq_counter = 0;
        (*tls).return_addr = 0;
    }

    // ARCH_SET_GS = 0x1001
    let ret = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i32, tls as usize) };
    assert_eq!(ret, 0, "arch_prctl(ARCH_SET_GS) failed: {ret}");

    tls
}

/// Public convenience wrapper: initialize TLS for the current thread.
///
/// # Safety
///
/// See [`micro_init_thread_inner`].
pub unsafe fn micro_init_thread(thread_slot: u16) {
    let micro_state = crate::state::global_micro_state_ptr();
    unsafe {
        micro_init_thread_inner(micro_state, thread_slot);
    }
}

/// Read the current thread's [`MicroTls`] pointer from GS base.
///
/// # Safety
///
/// GS base must have been set by [`micro_init_thread`] on this thread.
#[inline]
pub unsafe fn current_tls() -> *mut MicroTls {
    let ptr: usize;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x00]",
            out(reg) ptr,
            options(nostack, preserves_flags, readonly),
        );
    }
    ptr as *mut MicroTls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_field_offsets() {
        assert_eq!(core::mem::offset_of!(MicroTls, self_ptr), 0x00);
        assert_eq!(core::mem::offset_of!(MicroTls, micro), 0x08);
        assert_eq!(core::mem::offset_of!(MicroTls, thread_slot), 0x10);
        assert_eq!(core::mem::offset_of!(MicroTls, seq_counter), 0x18);
        assert_eq!(core::mem::offset_of!(MicroTls, return_addr), 0x20);
    }

    #[test]
    fn tls_struct_size() {
        assert_eq!(core::mem::size_of::<MicroTls>(), 40);
    }

    #[test]
    fn init_and_read_tls() {
        let mut dummy_state = crate::state::MicroState::zeroed();
        let tls = unsafe { micro_init_thread_inner(&raw mut dummy_state, 7) };
        assert!(!tls.is_null());

        unsafe {
            assert_eq!((*tls).self_ptr, tls);
            assert_eq!((*tls).micro, &raw mut dummy_state);
            assert_eq!((*tls).thread_slot, 7);
            assert_eq!((*tls).seq_counter, 0);
            assert_eq!((*tls).return_addr, 0);
        }

        let read_tls = unsafe { current_tls() };
        assert_eq!(read_tls, tls);

        // Clean up.
        unsafe { libc::munmap(tls.cast(), TLS_ALLOC_SIZE) };
    }
}
