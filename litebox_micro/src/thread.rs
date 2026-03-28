// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thread creation support for `clone(CLONE_VM|CLONE_THREAD)`.
//!
//! When central returns `EXEC_LOCAL` for a clone syscall, micro executes the real
//! `clone()` via glibc. The child thread initializes GS-based TLS, registers
//! with central, handles guest TLS (FS base) and `set_child_tid`, then jumps to
//! the guest's return address with RAX=0 (the child's expected clone return
//! value).

use litebox_ipc::messages::MSG_THREAD_REGISTER;
use litebox_ipc::ring::CqEntry;

/// Clone flags that micro handles in software rather than passing to the kernel.
///
/// - `CLONE_SETTLS`: We set FS base ourselves after GS-TLS init.
/// - `CLONE_CHILD_SETTID`: We write central's assigned TID, not the kernel TID.
/// - `CLONE_PARENT_SETTID`: We write central's assigned TID, not the kernel TID.
const STRIPPED_FLAGS: libc::c_int =
    libc::CLONE_SETTLS | libc::CLONE_CHILD_SETTID | libc::CLONE_PARENT_SETTID;

/// Bootstrap data passed to the new thread's entry function.
/// Allocated on the heap by the parent; the child takes ownership.
#[repr(C)]
struct ThreadBootstrap {
    /// Guest's return address (where to jump after clone returns 0).
    guest_return_addr: u64,
    /// Guest's TLS pointer (if `CLONE_SETTLS` was in the original flags). 0 = none.
    guest_tls: u64,
    /// Address to write child TID (`CLONE_CHILD_SETTID`). 0 = none.
    set_child_tid_ptr: u64,
    /// Address to write child TID for the parent (`CLONE_PARENT_SETTID`). 0 = none.
    parent_tid_ptr: u64,
    /// The child TID assigned by central's shim.
    child_tid: i32,
    /// Original clone flags from the guest.
    original_flags: u64,
}

/// Entry function for a cloned thread.
///
/// This is the callback passed to glibc's `clone()`. It runs on the child's
/// new stack. After setup it jumps to the guest's return address and never
/// returns.
///
/// # Safety
/// `arg` must point to a valid heap-allocated `ThreadBootstrap`.
/// This is declared as a safe `extern "C"` fn to satisfy `libc::clone`'s
/// signature, but the caller must ensure `arg` is valid.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
extern "C" fn clone_child_entry(arg: *mut libc::c_void) -> libc::c_int {
    let bootstrap = unsafe { Box::from_raw(arg.cast::<ThreadBootstrap>()) };

    // 1. Initialize GS-based TLS for this thread.
    //    Use thread_slot 0 temporarily — we'll get the real slot from central.
    let micro_state = crate::state::global_micro_state_ptr();
    let tls = unsafe { crate::tls::micro_init_thread_inner(micro_state, 0) };

    // 2. Register with central to get a real thread_slot.
    let args = [u64::MAX, 0, 0, 0, 0, 0]; // auto-assign
    let cq = unsafe { crate::handler::submit_and_wait(tls, MSG_THREAD_REGISTER, &args, 0) };
    let thread_slot = cq.result as u16;
    unsafe { (*tls).thread_slot = u64::from(thread_slot) };

    // 3. Handle CLONE_SETTLS: set FS base for guest's glibc TLS.
    if bootstrap.original_flags & (libc::CLONE_SETTLS as u64) != 0 && bootstrap.guest_tls != 0 {
        unsafe {
            libc::syscall(
                libc::SYS_arch_prctl,
                0x1002i32, // ARCH_SET_FS
                bootstrap.guest_tls as usize,
            );
        }
    }

    // 4. Handle CLONE_CHILD_SETTID: write central's child TID to the
    //    guest-specified address.
    if bootstrap.original_flags & (libc::CLONE_CHILD_SETTID as u64) != 0
        && bootstrap.set_child_tid_ptr != 0
    {
        unsafe {
            *(bootstrap.set_child_tid_ptr as *mut i32) = bootstrap.child_tid;
        }
    }

    // 5. Jump to guest code with return value 0 (clone returns 0 in child).
    let return_addr = bootstrap.guest_return_addr;
    drop(bootstrap);

    unsafe {
        core::arch::asm!(
            "jmp {ret_addr}",
            ret_addr = in(reg) return_addr,
            // RAX = 0: clone returns 0 in the child. Using an explicit
            // register input for RAX (instead of `xor eax, eax` in the asm
            // template) prevents the compiler from allocating `ret_addr` to
            // RAX, which would be clobbered by the zeroing.
            in("rax") 0u64,
            options(noreturn),
        );
    }
}

/// Handle a clone syscall that central authorized for local execution.
///
/// `args` contains the original clone arguments from the guest:
/// - `args[0]` = flags
/// - `args[1]` = `child_stack`
/// - `args[2]` = `parent_tidptr`
/// - `args[3]` = `child_tidptr`
/// - `args[4]` = tls
///
/// `cq` contains the response from central with the child TID in `cq.result`.
///
/// Returns the child TID (to the parent). The child thread is spawned
/// and will independently initialize and register with central.
///
/// # Safety
/// - The global [`MicroState`](crate::state::MicroState) must be initialized.
/// - TLS must be initialized for the calling thread.
/// - `args` and `cq` must be valid.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe fn handle_clone(args: &[u64; 6], cq: &CqEntry) -> i64 {
    let flags = args[0];
    let child_stack = args[1] as *mut libc::c_void;
    let parent_tid_ptr = args[2];
    let child_tid_ptr = args[3];
    let guest_tls = args[4];
    let child_tid = cq.result as i32;

    // Read the guest's return address from our TLS before clone.
    // The trampoline saved it at gs:[0x20]. After clone, the parent might
    // continue and overwrite it, so we capture it now.
    let tls = unsafe { crate::tls::current_tls() };
    let guest_return_addr = unsafe { (*tls).return_addr };

    // Heap-allocate bootstrap data. The child takes ownership via Box::from_raw.
    let bootstrap = Box::new(ThreadBootstrap {
        guest_return_addr,
        guest_tls,
        set_child_tid_ptr: child_tid_ptr,
        parent_tid_ptr,
        child_tid,
        original_flags: flags,
    });
    let bootstrap_ptr = Box::into_raw(bootstrap).cast::<libc::c_void>();

    // Strip flags that we handle in software. The kernel should not try to
    // write TIDs or set TLS — we do it ourselves with central's assigned TID.
    let kernel_flags = (flags as libc::c_int) & !STRIPPED_FLAGS;

    // Call glibc's clone(). The child will start in clone_child_entry.
    // Varargs after `arg`: parent_tidptr, tls, child_tidptr — all null/0
    // since we stripped the corresponding flags.
    let result = unsafe {
        libc::clone(
            clone_child_entry,
            child_stack,
            kernel_flags,
            bootstrap_ptr,
            core::ptr::null_mut::<libc::pid_t>(), // parent_tidptr (unused)
            core::ptr::null_mut::<libc::c_void>(), // tls (unused)
            core::ptr::null_mut::<libc::pid_t>(), // child_tidptr (unused)
        )
    };

    if result == -1 {
        // clone failed — reclaim the bootstrap memory.
        let _ = unsafe { Box::from_raw(bootstrap_ptr.cast::<ThreadBootstrap>()) };
        let errno = unsafe { *libc::__errno_location() };
        return -i64::from(errno);
    }

    // Handle CLONE_PARENT_SETTID: write central's child TID to the parent's
    // specified address. We do this in the parent (after clone succeeds) since
    // glibc normally does it before returning to the parent.
    if flags & (libc::CLONE_PARENT_SETTID as u64) != 0 && parent_tid_ptr != 0 {
        unsafe {
            *(parent_tid_ptr as *mut i32) = child_tid;
        }
    }

    // Parent: return the child TID assigned by central (not the kernel TID).
    i64::from(child_tid)
}
