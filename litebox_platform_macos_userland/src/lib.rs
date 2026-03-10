// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on macOS (Apple Silicon).

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::cell::Cell;
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::Duration;

use litebox::fs::OFlags;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::{
    CowAllocationError, FixedAddressBehavior, MemoryRegionPermissions,
};
use litebox::platform::{ImmediatelyWokenUp, RawConstPointer as _};
use litebox::shim::ContinueOperation;
use litebox::utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_common_linux::{MapFlags, ProtFlags, PunchthroughSyscall, vmap::VmapManager};

use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

const KERN_SUCCESS: i32 = 0;
const VM_REGION_SUBMAP_INFO_COUNT_64: u32 = 16;

#[repr(C)]
struct vm_region_submap_info_64 {
    _data: [u32; VM_REGION_SUBMAP_INFO_COUNT_64 as usize],
}

unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn mach_vm_region_recurse(
        target_task: u32,
        address: *mut u64,
        size: *mut u64,
        nesting_depth: *mut u32,
        info: *mut vm_region_submap_info_64,
        info_count: *mut u32,
    ) -> i32;
    fn __ulock_wait(
        operation: u32,
        addr: *mut libc::c_void,
        value: u64,
        timeout_us: u32,
    ) -> libc::c_int;
    fn __ulock_wake(operation: u32, addr: *mut libc::c_void, wake_value: u64) -> libc::c_int;
}

const UL_COMPARE_AND_WAIT: u32 = 1;
const ULF_WAKE_ALL: u32 = 0x0000_0100;

/// The macOS userland platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct MacosUserland {
    tun_socket_fd: std::sync::RwLock<Option<std::os::fd::OwnedFd>>,
    /// Reserved pages that are not available for guest programs to use.
    reserved_pages: Vec<core::ops::Range<usize>>,
    /// The base address of the VDSO.
    vdso_address: Option<usize>,
    /// CoW-eligible memory regions. Maps start address of the static slice, to the info needed to
    /// re-mmap the file.
    cow_regions: std::sync::RwLock<std::collections::BTreeMap<usize, CowRegionInfo>>,
}

impl core::fmt::Debug for MacosUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MacosUserland").finish_non_exhaustive()
    }
}

/// Information about a CoW-eligible memory region backed by a file.
#[derive(Debug, Clone)]
struct CowRegionInfo {
    /// The path to the backing file on the host filesystem.
    file_path: PathBuf,
    /// Length of the backing file.
    file_length: usize,
}

#[repr(C)]
#[derive(Default)]
struct ThreadControlBlock {
    scratch: usize,
    host_sp: usize,
    guest_context_top: usize,
    guest_tpidr: usize,
    in_guest: u8,
    interrupt: u8,
    _pad: [u8; 6],
}

#[allow(dead_code)]
const fn tcb_offset_scratch() -> isize {
    0
}

#[allow(dead_code)]
const fn tcb_offset_host_sp() -> isize {
    8
}

const fn tcb_offset_guest_context_top() -> isize {
    16
}

const fn tcb_offset_guest_tpidr() -> isize {
    24
}

const fn tcb_offset_in_guest() -> isize {
    32
}

const fn tcb_offset_interrupt() -> isize {
    33
}

impl MacosUserland {
    /// Create a new userland-Linux platform for use in `LiteBox`.
    ///
    /// Takes an optional tun device name (such as `"tun0"` or `"tun99"`) to connect networking (if
    /// not specified, networking is disabled).
    ///
    /// # Panics
    ///
    /// Panics if the tun device could not be successfully opened.
    pub fn new(tun_device_name: Option<&str>) -> &'static Self {
        register_exception_handlers();

        let tun_socket_fd = std::sync::RwLock::new(None);
        if tun_device_name.is_some() {
            unimplemented!("macOS TUN (utun) networking not yet implemented");
        }

        let reserved_pages = Self::read_maps();
        let platform = Self {
            tun_socket_fd,
            reserved_pages,
            vdso_address: None,
            cow_regions: std::sync::RwLock::new(std::collections::BTreeMap::new()),
        };
        Box::leak(Box::new(platform))
    }

    /// Register a CoW-eligible memory region backed by a file.
    ///
    /// # Panics
    ///
    /// Panics if an overlapping region is already registered.
    pub fn register_cow_region(&self, data: &'static [u8], file_path: impl Into<PathBuf>) {
        let start = data.as_ptr() as usize;
        let info = CowRegionInfo {
            file_path: file_path.into(),
            file_length: data.len(),
        };

        let mut regions = self.cow_regions.write().unwrap();
        assert!(
            regions.range(start..start + data.len()).next().is_none(),
            "Attempting to register an overlapping region"
        );
        let old = regions.insert(start, info);
        assert!(old.is_none());
    }

    /// Look up the file backing a static slice for CoW mapping.
    ///
    /// Returns `Some((file_path, offset_in_file))` if the slice is backed by a registered
    /// CoW region, `None` otherwise.
    fn lookup_cow_region(&self, source_data: &'static [u8]) -> Option<(PathBuf, usize)> {
        let slice_start = source_data.as_ptr() as usize;
        let slice_len = source_data.len();

        let regions = self.cow_regions.read().unwrap();

        if let Some((&region_start, info)) = regions.range(..=slice_start).next_back() {
            let region_end = region_start.checked_add(info.file_length).unwrap();
            let slice_end = slice_start.checked_add(slice_len).unwrap();

            if slice_start >= region_start && slice_end <= region_end {
                return Some((info.file_path.clone(), slice_start - region_start));
            }
        }
        None
    }

    fn read_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        let mut reserved_pages = alloc::vec::Vec::new();
        let mut address: u64 = 0;

        loop {
            let mut size: u64 = 0;
            let mut depth: u32 = 0;
            let mut info: vm_region_submap_info_64 = unsafe { core::mem::zeroed() };
            let mut count = VM_REGION_SUBMAP_INFO_COUNT_64;

            let kr = unsafe {
                mach_vm_region_recurse(
                    mach_task_self(),
                    &raw mut address,
                    &raw mut size,
                    &raw mut depth,
                    &raw mut info,
                    &raw mut count,
                )
            };
            if kr != KERN_SUCCESS {
                break;
            }

            let start = usize::try_from(address).unwrap();
            let end = usize::try_from(address.checked_add(size).unwrap()).unwrap();
            reserved_pages.push(start..end);
            address = address.checked_add(size).unwrap();
        }

        reserved_pages
    }

    #[expect(
        clippy::missing_panics_doc,
        reason = "panicking only on failures of documented linux contracts"
    )]
    #[allow(clippy::useless_conversion)]
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        let tid = unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) }
            .try_into()
            .unwrap();
        let ppid = unsafe { libc::getppid() }.try_into().unwrap();
        litebox_common_linux::TaskParams {
            pid: tid,
            ppid,
            uid: unsafe { libc::getuid() }.try_into().unwrap(),
            euid: unsafe { libc::geteuid() }.try_into().unwrap(),
            gid: unsafe { libc::getgid() }.try_into().unwrap(),
            egid: unsafe { libc::getegid() }.try_into().unwrap(),
        }
    }

    /// Wait until there is data available on the TUN device.
    ///
    /// # Panics
    ///
    /// Panics if the TUN device is not initialized.
    pub fn wait_on_tun(&self, timeout: Option<Duration>) {
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let mut pfd = libc::pollfd {
            fd: tun_fd.as_ref().unwrap().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = unsafe {
            libc::poll(
                &raw mut pfd,
                1,
                timeout.map_or(-1, |t| {
                    let ms = t.as_millis();
                    i32::try_from(ms).unwrap_or(i32::MAX)
                }),
            )
        };
    }
}

impl litebox::platform::Provider for MacosUserland {}

/// Runs a guest thread using the provided shim and the given initial context.
///
/// This will run until the thread terminates or returns.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread<T>(shim: T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(&shim, ctx, false);
}

/// Run a guest thread using a reference to the shim.
///
/// Unlike `run_thread`, this version takes a reference instead of ownership,
/// avoiding struct moves that could invalidate internal state.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(shim, ctx, false);
}

/// Re-enter a guest thread using a reference to the shim.
///
/// This version takes a reference instead of ownership, avoiding struct moves
/// that could invalidate internal state.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn reenter_thread<T>(shim: &T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(shim, ctx, true);
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &'a mut litebox_common_linux::PtRegs,
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
    reenter: bool,
) {
    let ctx_ptr = core::ptr::from_mut(ctx);
    let mut thread_ctx = ThreadContext { shim, ctx };
    let mut tcb = Box::new(ThreadControlBlock::default());
    ThreadHandle::run_with_handle(|| {
        with_signal_alt_stack(|| unsafe {
            let original_tpidr = litebox_common_linux::read_tpidr_el0();
            tcb.scratch = original_tpidr;
            litebox_common_linux::write_tpidr_el0((&raw mut *tcb) as usize);
            run_thread_arch(&mut thread_ctx, ctx_ptr, u8::from(reenter));
            litebox_common_linux::write_tpidr_el0(original_tpidr);
        });
    });
}

fn set_guest_tpidr(value: usize) {
    unsafe {
        (*(litebox_common_linux::read_tpidr_el0() as *mut ThreadControlBlock)).guest_tpidr = value;
    }
}

fn get_guest_tpidr() -> usize {
    unsafe { (*(litebox_common_linux::read_tpidr_el0() as *mut ThreadControlBlock)).guest_tpidr }
}

/// Runs the guest thread until it terminates.
///
/// This saves all non-volatile register state then switches to the guest
/// context. When the guest makes a syscall, it jumps back into the middle of
/// this routine, at `syscall_callback`. This code then updates the guest
/// context structure, switches back to the host stack, and calls the syscall
/// handler.
///
/// When the guest thread terminates, this function returns after restoring
/// non-volatile register state.
/// Runs the guest thread until it terminates (aarch64 version).
///
/// Saves callee-saved register state, sets up TLS, then calls the init/reenter
/// handler. Contains the `syscall_callback` entry point that the trampoline
/// branches to on SVC, plus `exception_callback` and `interrupt_callback`
/// labels for signal handler returns.
///
/// Register convention on entry:
///   x0 = thread_ctx (&mut ThreadContext)
///   x1 = ctx (*mut PtRegs)
///   x2 = reenter (u8, 0 or 1)
#[unsafe(naked)]
unsafe extern "C-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    // Save callee-saved registers and link register.
    stp x29, x30, [sp, #-96]!
    .cfi_def_cfa_offset 96
    .cfi_offset x29, -96
    .cfi_offset x30, -88
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    // Reserve 16 bytes for thread_ctx pointer (keep 16-byte alignment).
    sub sp, sp, #16
    str x0, [sp]                  // save thread_ctx

    // Save host sp and guest context top in TCB.
    mrs x8, tpidr_el0
    mov x9, sp
    str x9, [x8, #8]
    add x9, x1, #{GUEST_CONTEXT_SIZE}
    str x9, [x8, #16]

    // Call init_handler or reenter_handler based on reenter flag (in w2).
    cbnz w2, 1f
    bl {init_handler}
    b .Ldone_aarch64
1:
    bl {reenter_handler}
    b .Ldone_aarch64

    // ================================================================
    // syscall_callback: entered from trampoline on SVC #0
    //
    // At entry:
    //   x18 = host TLS base (from trampoline's per-thread table lookup)
    //   x30 = guest return address (after the rewritten SVC)
    //   Guest stack: [SP+0]=saved_x16, [SP+8]=saved_x17, [SP+16]=saved_x30, [SP+24]=guest_tpidr
    //   SP was decremented by 32 by trampoline
    //   x0-x15, x19-x29 = guest register values
    //   (x16, x17 were clobbered by trampoline; originals on guest stack)
    // ================================================================
    .cfi_endproc

    .globl _syscall_callback
_syscall_callback:
    .cfi_startproc
    // Clear in_guest flag. Must be first instruction to match the
    // expectations of interrupt_signal_handler.
    strb wzr, [x18, #32]

    // Save guest TPIDR (from trampoline stack slot) to guest_tpidr TLS var.
    // This ensures switch_to_guest restores the correct TPIDR, even if
    // the guest changed it via MSR TPIDR_EL0.
    ldr x17, [sp, #24]
    str x17, [x18, #24]

    // Restore host TPIDR_EL0.
    msr tpidr_el0, x18

    // Load guest_context_top and compute PtRegs base address.
    // We'll build PtRegs ending at guest_context_top, starting at
    // guest_context_top - GUEST_CONTEXT_SIZE.
    ldr x16, [x18, #16]
    sub x16, x16, #{GUEST_CONTEXT_SIZE}
    // x16 = base of PtRegs. We can now use x16 freely since the
    // trampoline already saved the guest's x16.

    // Save guest x0-x15 into PtRegs.regs[0..15].
    // x16 is our PtRegs base pointer. x17, x18 are scratch.
    stp x0,  x1,  [x16, #0]      // regs[0], regs[1]
    stp x2,  x3,  [x16, #16]     // regs[2], regs[3]
    stp x4,  x5,  [x16, #32]     // regs[4], regs[5]
    stp x6,  x7,  [x16, #48]     // regs[6], regs[7]
    stp x8,  x9,  [x16, #64]     // regs[8], regs[9]
    stp x10, x11, [x16, #80]     // regs[10], regs[11]
    stp x12, x13, [x16, #96]     // regs[12], regs[13]
    stp x14, x15, [x16, #112]    // regs[14], regs[15]

    // Recover guest x16, x17, x30 from guest stack frame.
    ldp x0, x1, [sp]             // x0 = guest_x16, x1 = guest_x17
    ldr x2, [sp, #16]            // x2 = guest_x30

    // Store guest x16, x17 into PtRegs.regs[16..17].
    stp x0, x1, [x16, #128]      // regs[16], regs[17]

    // x18 is host TLS; guest x18 was not saved by trampoline and was
    // clobbered. Store 0 as placeholder (platform-reserved register).
    str xzr, [x16, #144]         // regs[18] = 0

    // Save guest x19-x29.
    stp x19, x20, [x16, #152]    // regs[19], regs[20]
    stp x21, x22, [x16, #168]    // regs[21], regs[22]
    stp x23, x24, [x16, #184]    // regs[23], regs[24]
    stp x25, x26, [x16, #200]    // regs[25], regs[26]
    stp x27, x28, [x16, #216]    // regs[27], regs[28]
    str x29, [x16, #232]         // regs[29]

    // Store guest x30 (link register, recovered from stack).
    str x2, [x16, #240]          // regs[30] = guest LR

    // Compute original guest SP (trampoline decremented by 32).
    add x0, sp, #32
    str x0, [x16, #248]          // PtRegs.sp

    // Store guest PC = x30 (return address from trampoline, in our x30).
    str x30, [x16, #256]         // PtRegs.pc

    // Store pstate = 0 (we don't have direct access to guest PSTATE from
    // userspace trampoline; the signal handler path fills it properly).
    str xzr, [x16, #264]         // PtRegs.pstate

    // Switch to host stack.
    mrs x18, tpidr_el0
    ldr x0, [x18, #8]
    mov sp, x0

    // Call syscall_handler. x0 = thread_ctx (on host stack).
    ldr x0, [sp]
    bl {syscall_handler}
    // If syscall_handler returns, the thread is done.
    b .Ldone_aarch64
    .cfi_endproc

    .globl _exception_callback
_exception_callback:
    .cfi_startproc
    // Restore host stack.
    mrs x18, tpidr_el0
    ldr x9, [x18, #8]
    mov sp, x9

    ldr x0, [sp]                  // thread_ctx
    bl {exception_handler}
    b .Ldone_aarch64
    .cfi_endproc

    .globl _interrupt_callback
_interrupt_callback:
    .cfi_startproc
    // Restore host stack.
    mrs x18, tpidr_el0
    ldr x9, [x18, #8]
    mov sp, x9

    ldr x0, [sp]                  // thread_ctx
    bl {interrupt_handler}

.Ldone_aarch64:
    // Restore thread_ctx slot and callee-saved registers.
    add sp, sp, #16               // pop thread_ctx slot
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldp x27, x28, [sp, #80]
    ldp x29, x30, [sp], #96
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    ",
    GUEST_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    );
}

/// Switches to the provided guest context.
///
/// # Safety
/// The context must be valid guest context. This can only be called if
/// `run_thread_arch` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_arch`.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
/// Switches to the provided guest context (aarch64 version).
///
/// # Safety
/// The context must be valid guest context. This can only be called if
/// `run_thread_arch` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_arch`.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(
        ".globl _switch_to_guest_start",
        "_switch_to_guest_start:",
        // Set `in_guest` now, then check if there is a pending interrupt.
        // If so, jump to the interrupt handler.
        //
        // If an interrupt arrives after the check, then the signal handler
        // will see that the IP is between `switch_to_guest_start` and
        // `switch_to_guest_end` and will set `interrupt` and jump to
        // `interrupt_callback`.
        "mrs x18, tpidr_el0",
        "mov w16, #1",
        "strb w16, [x18, #32]",
        "ldrb w17, [x18, #33]",
        "cbnz w17, 2f",
        "ldr x17, [x18, #24]",
        // Load guest PC into x18 (we'll branch to it after restoring all regs).
        // x0 = ctx pointer to PtRegs.
        "ldr x16, [x0, #256]", // x16 = PtRegs.pc (guest PC)
        // Restore guest registers from PtRegs.
        // We need to restore x0-x15, x19-x30, sp.
        // x16 = guest PC (scratch), x17 = guest_tpidr, x18 = host TLS (will be overwritten)

        // Load guest x2-x15 first (x0, x1 last since x0=ctx pointer).
        "ldp x2,  x3,  [x0, #16]",
        "ldp x4,  x5,  [x0, #32]",
        "ldp x6,  x7,  [x0, #48]",
        "ldp x8,  x9,  [x0, #64]",
        "ldp x10, x11, [x0, #80]",
        "ldp x12, x13, [x0, #96]",
        "ldp x14, x15, [x0, #112]",
        // Skip regs[16..18] — x16 has guest PC, x17 has guest_tpidr,
        // x18 is platform-reserved
        "ldp x19, x20, [x0, #152]",
        "ldp x21, x22, [x0, #168]",
        "ldp x23, x24, [x0, #184]",
        "ldp x25, x26, [x0, #200]",
        "ldp x27, x28, [x0, #216]",
        "ldr x29, [x0, #232]",
        "ldr x30, [x0, #240]", // guest LR (x30)
        // Load guest SP.
        "ldr x18, [x0, #248]", // temporarily hold guest SP in x18
        // Restore guest x1 (x0 still needed as base pointer).
        "ldr x1, [x0, #8]",
        // Switch to guest TPIDR_EL0.
        "msr tpidr_el0, x17",
        // Set guest SP.
        "mov sp, x18",
        // Now load guest x0 (overwriting ctx pointer — last step).
        "ldr x0, [x0, #0]",
        // x16 = guest PC. Branch to it.
        "br x16",
        // Local trampoline for cbnz — macOS assembler rejects conditional
        // branches to non-assembler-local labels (only numbered labels qualify).
        "2: b _interrupt_callback",
        ".globl _switch_to_guest_end",
        "_switch_to_guest_end:",
    );
}

fn thread_start(
    init_thread: Box<
        dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
    >,
    mut ctx: litebox_common_linux::PtRegs,
) {
    // Allow caller to run some code before we return to the new thread.
    let shim = init_thread.init();

    run_thread_inner(shim.as_ref(), &mut ctx, false);
    // TODO: have syscall_callback return if we need to terminate the process.
    // We should return this value to the caller so load_program can return it
    // to the user.
}

// A handle to a platform thread.
#[derive(Clone)]
pub struct ThreadHandle(std::sync::Arc<std::sync::Mutex<Option<libc::pthread_t>>>);

thread_local! {
    static CURRENT_THREAD: std::cell::RefCell<Option<ThreadHandle>> = const { std::cell::RefCell::new(None) };
}

impl ThreadHandle {
    /// Runs `f`, ensuring that [`ThreadHandle::current`] can be called within `f`.
    fn run_with_handle<R>(f: impl FnOnce() -> R) -> R {
        let handle = ThreadHandle(std::sync::Arc::new(std::sync::Mutex::new(Some(unsafe {
            libc::pthread_self()
        }))));
        CURRENT_THREAD.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "nested with_thread_handle calls are not supported"
            );
            *current = Some(handle);
        });
        let _guard = litebox::utils::defer(|| {
            let current = CURRENT_THREAD.take().unwrap();
            *current.0.lock().unwrap() = None;
        });
        f()
    }

    /// Returns the current thread handle.
    fn current() -> Self {
        CURRENT_THREAD.with_borrow(|thread| {
            thread
                .clone()
                .expect("current_thread called outside of a LiteBox thread")
        })
    }

    /// Interrupts the thread, delivering a signal to it.
    fn interrupt(&self) {
        let thread = self.0.lock().unwrap();
        if let Some(&thread) = thread.as_ref() {
            unsafe {
                libc::pthread_kill(thread, INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed));
            }
        }
    }
}

impl litebox::platform::ThreadProvider for MacosUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        init_thread: Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let ctx = ctx.clone();
        // TODO: do we need to wait for the handle in the main thread?
        let _handle = std::thread::Builder::new().spawn(move || thread_start(init_thread, ctx))?;

        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        ThreadHandle::current()
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
    }
}

impl litebox::platform::RawMutexProvider for MacosUserland {
    type RawMutex = RawMutex;
}

pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
}

impl RawMutex {
    const fn new() -> Self {
        Self {
            inner: AtomicU32::new(0),
        }
    }

    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // We immediately wake up (without even hitting syscalls) if we can clearly see that the
        // value is different.
        if self.inner.load(Ordering::SeqCst) != val {
            return Err(ImmediatelyWokenUp);
        }

        let timeout_us = timeout.map_or(0, |d| u32::try_from(d.as_micros()).unwrap_or(u32::MAX));

        loop {
            let ret = unsafe {
                __ulock_wait(
                    UL_COMPARE_AND_WAIT,
                    (&raw const self.inner).cast_mut().cast(),
                    u64::from(val),
                    timeout_us,
                )
            };
            if ret >= 0 {
                return Ok(UnblockedOrTimedOut::Unblocked);
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EAGAIN) => return Err(ImmediatelyWokenUp),
                Some(libc::ETIMEDOUT) => return Ok(UnblockedOrTimedOut::TimedOut),
                Some(libc::EINTR) => {}
                _ => panic!(
                    "Unexpected error for __ulock_wait: {}",
                    std::io::Error::last_os_error()
                ),
            }
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0);
        let flags = if n > 1 { ULF_WAKE_ALL } else { 0 };
        let ret = unsafe {
            __ulock_wake(
                UL_COMPARE_AND_WAIT | flags,
                (&raw const self.inner).cast_mut().cast(),
                0,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return 0;
            }
            panic!("Unexpected error for __ulock_wake: {err}");
        }
        ret.reinterpret_as_unsigned() as usize
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(timeout))
    }
}

impl litebox::platform::IPInterfaceProvider for MacosUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let Some(tun_socket_fd) = tun_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        let n = unsafe {
            libc::write(
                tun_socket_fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            unimplemented!("unexpected error {err}")
        }
        let n = usize::try_from(n).unwrap();
        if n != packet.len() {
            unimplemented!("unexpected size {n}")
        }
        Ok(())
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let Some(tun_socket_fd) = tun_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        let n = unsafe {
            libc::read(
                tun_socket_fd.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
            )
        };
        if n < 0 {
            return Err(match std::io::Error::last_os_error().raw_os_error() {
                #[allow(unreachable_patterns, reason = "EAGAIN == EWOULDBLOCK")]
                Some(libc::EWOULDBLOCK | libc::EAGAIN) => {
                    litebox::platform::ReceiveError::WouldBlock
                }
                _ => unimplemented!("unexpected error {}", std::io::Error::last_os_error()),
            });
        }
        Ok(usize::try_from(n).unwrap())
    }
}

impl litebox::platform::TimeProvider for MacosUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        Instant {
            #[cfg_attr(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                expect(clippy::useless_conversion)
            )]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().truncate(),
            ),
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        SystemTime {
            #[cfg_attr(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                expect(clippy::useless_conversion)
            )]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().truncate(),
            ),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    inner: Duration,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.inner.checked_sub(earlier.inner)
    }
    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        Some(Self {
            inner: self.inner.checked_add(duration)?,
        })
    }
}

pub struct SystemTime {
    inner: Duration,
}

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = SystemTime {
        inner: Duration::ZERO,
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        self.inner
            .checked_sub(earlier.inner)
            .ok_or_else(|| earlier.inner.checked_sub(self.inner).unwrap())
    }
}

pub struct PunchthroughToken<'a> {
    punchthrough: PunchthroughSyscall<'a, MacosUserland>,
}

impl<'a> litebox::platform::PunchthroughToken for PunchthroughToken<'a> {
    type Punchthrough = PunchthroughSyscall<'a, MacosUserland>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        match self.punchthrough {
            PunchthroughSyscall::SetTpidr { value } => {
                set_guest_tpidr(value);
                Ok(0)
            }
            PunchthroughSyscall::_Phantom(_, _, infallible) => match infallible {},
        }
    }
}

impl litebox::platform::PunchthroughProvider for MacosUserland {
    type PunchthroughToken<'a> = PunchthroughToken<'a>;
    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
        Some(PunchthroughToken { punchthrough })
    }
}

impl litebox::platform::DebugLogProvider for MacosUserland {
    fn debug_log_print(&self, msg: &str) {
        let _ = unsafe {
            libc::write(
                litebox_common_linux::STDERR_FILENO,
                msg.as_ptr().cast(),
                msg.len(),
            )
        };
    }
}

type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
impl litebox::platform::RawPointerProvider for MacosUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

fn prot_flags(flags: MemoryRegionPermissions) -> ProtFlags {
    let mut res = ProtFlags::PROT_NONE;
    res.set(
        ProtFlags::PROT_READ,
        flags.contains(MemoryRegionPermissions::READ),
    );
    res.set(
        ProtFlags::PROT_WRITE,
        flags.contains(MemoryRegionPermissions::WRITE),
    );
    res.set(
        ProtFlags::PROT_EXEC,
        flags.contains(MemoryRegionPermissions::EXEC),
    );
    if flags.contains(MemoryRegionPermissions::SHARED) {
        unimplemented!()
    }
    res
}

/// Check whether a virtual address range is free (no existing Mach VM mappings).
///
/// Uses `mach_vm_region_recurse` to query the first region at or after `start`.
/// If that region starts at or beyond `start + len`, the range is unmapped.
fn is_range_unmapped(start: usize, len: usize) -> bool {
    let end = start + len;
    let mut address: u64 = start as u64;
    let mut size: u64 = 0;
    let mut depth: u32 = 0;
    let mut info: vm_region_submap_info_64 = unsafe { core::mem::zeroed() };
    let mut count = VM_REGION_SUBMAP_INFO_COUNT_64;

    let kr = unsafe {
        mach_vm_region_recurse(
            mach_task_self(),
            &raw mut address,
            &raw mut size,
            &raw mut depth,
            &raw mut info,
            &raw mut count,
        )
    };
    if kr != KERN_SUCCESS {
        // No more regions in the address space — range is free.
        return true;
    }
    // `mach_vm_region_recurse` returns the first region at or after `address`.
    // If that region starts at or beyond our desired end, our range is free.
    address as usize >= end
}

/// Translate Linux [`MapFlags`] to macOS `mmap` flags.
///
/// macOS does not support `MAP_GROWSDOWN`, `MAP_POPULATE`, or `MAP_FIXED_NOREPLACE`.
/// - `MAP_GROWSDOWN` and `MAP_POPULATE` are silently dropped (no macOS equivalent).
/// - `MAP_FIXED_NOREPLACE` is **not** translated here — callers must emulate it
///   separately (probe via `is_range_unmapped` + `MAP_FIXED`).
fn macos_mmap_flags(linux_flags: MapFlags) -> libc::c_int {
    let mut result: libc::c_int = 0;
    if linux_flags.contains(MapFlags::MAP_PRIVATE) {
        result |= libc::MAP_PRIVATE;
    }
    if linux_flags.contains(MapFlags::MAP_SHARED) {
        result |= libc::MAP_SHARED;
    }
    if linux_flags.contains(MapFlags::MAP_ANONYMOUS) {
        result |= libc::MAP_ANON;
    }
    if linux_flags.contains(MapFlags::MAP_FIXED) {
        result |= libc::MAP_FIXED;
    }
    // MAP_FIXED_NOREPLACE: NOT translated here. Callers emulate via
    // is_range_unmapped() + MAP_FIXED. See allocate_pages() and try_allocate_cow_pages().
    //
    // MAP_GROWSDOWN and MAP_POPULATE have no macOS equivalent — silently drop.
    result
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for MacosUserland {
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    const TASK_ADDR_MAX: usize = 0x0000_FFFF_FFFF_F000; // 48-bit VA space

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        _populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        // Emulate MAP_FIXED_NOREPLACE on macOS: probe that the range is free, then
        // use MAP_FIXED to guarantee the exact address. macOS does not honor mmap
        // address hints reliably, so a hint-only approach would spuriously fail.
        if matches!(fixed_address_behavior, FixedAddressBehavior::NoReplace) {
            if !is_range_unmapped(suggested_range.start, suggested_range.len()) {
                return Err(litebox::platform::page_mgmt::AllocationError::AddressInUse);
            }
        }
        // Build Linux-style flags, then translate to macOS.
        let linux_flags = MapFlags::MAP_PRIVATE
            | MapFlags::MAP_ANONYMOUS
            | match fixed_address_behavior {
                FixedAddressBehavior::Hint => MapFlags::empty(),
                // NoReplace uses MAP_FIXED after the range check above.
                FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace => {
                    MapFlags::MAP_FIXED
                }
            }
            | if can_grow_down {
                // MAP_GROWSDOWN has no macOS equivalent; macos_mmap_flags drops it.
                MapFlags::MAP_GROWSDOWN
            } else {
                MapFlags::empty()
            };
        let r = unsafe {
            libc::mmap(
                suggested_range.start as *mut libc::c_void,
                suggested_range.len(),
                prot_flags(initial_permissions).bits(),
                macos_mmap_flags(linux_flags),
                -1,
                0,
            )
        };
        if r == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::ENOMEM) => litebox::platform::page_mgmt::AllocationError::OutOfMemory,
                _ => panic!("unhandled mmap error {err}"),
            });
        }
        Ok(UserMutPtr::from_usize(r as usize))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let r = unsafe { libc::munmap(range.start as *mut libc::c_void, range.len()) };
        assert_eq!(r, 0, "munmap failed: {}", std::io::Error::last_os_error());
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        let new_ptr = unsafe {
            libc::mmap(
                new_range.start as *mut libc::c_void,
                new_range.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if new_ptr == libc::MAP_FAILED {
            return Err(litebox::platform::page_mgmt::RemapError::OutOfMemory);
        }

        let copy_len = old_range.len().min(new_range.len());
        unsafe {
            core::ptr::copy_nonoverlapping(
                old_range.start as *const u8,
                new_ptr.cast::<u8>(),
                copy_len,
            );
        }

        if permissions != (MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE) {
            let r =
                unsafe { libc::mprotect(new_ptr, new_range.len(), prot_flags(permissions).bits()) };
            if r != 0 {
                unsafe {
                    libc::munmap(new_ptr, new_range.len());
                }
                return Err(litebox::platform::page_mgmt::RemapError::OutOfMemory);
            }
        }

        let r = unsafe { libc::munmap(old_range.start as *mut libc::c_void, old_range.len()) };
        assert_eq!(r, 0, "munmap failed: {}", std::io::Error::last_os_error());

        Ok(UserMutPtr::from_usize(new_ptr as usize))
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        let r = unsafe {
            libc::mprotect(
                range.start as *mut libc::c_void,
                range.len(),
                prot_flags(new_permissions).bits(),
            )
        };
        assert_eq!(r, 0, "mprotect failed: {}", std::io::Error::last_os_error());
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }

    fn try_allocate_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, CowAllocationError> {
        let Some((file_path, file_offset)) = self.lookup_cow_region(source_data) else {
            return Err(CowAllocationError::UnsupportedSourceRegion);
        };
        if !file_offset.is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }

        let file_path_cstr =
            std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes()).unwrap();
        // TODO(jb): We should likely be storing pre-opened FDs, right?
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                file_path_cstr.as_ptr(),
                OFlags::RDONLY.bits().reinterpret_as_signed(),
                0,
            )
        };
        assert!(fd >= 0, "file should remain unchanged on host");

        // Emulate MAP_FIXED_NOREPLACE: probe range, then use MAP_FIXED.
        if matches!(fixed_address_behavior, FixedAddressBehavior::NoReplace)
            && !is_range_unmapped(suggested_start, source_data.len())
        {
            unsafe {
                libc::close(fd);
            }
            return Err(CowAllocationError::InternalFailure);
        }

        let mut flags = MapFlags::MAP_PRIVATE;
        match fixed_address_behavior {
            FixedAddressBehavior::Hint => {}
            // NoReplace uses MAP_FIXED after the range check above.
            FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace => {
                flags |= MapFlags::MAP_FIXED;
            }
        }

        let result = unsafe {
            libc::mmap(
                suggested_start as *mut libc::c_void,
                source_data.len(),
                prot_flags(permissions).bits(),
                macos_mmap_flags(flags),
                fd,
                file_offset.try_into().unwrap(),
            )
        };

        unsafe {
            libc::close(fd);
        }

        if result == libc::MAP_FAILED {
            Err(CowAllocationError::InternalFailure)
        } else {
            Ok(UserMutPtr::from_usize(result as usize))
        }
    }
}

impl litebox::platform::StdioProvider for MacosUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        let n = unsafe {
            libc::read(
                litebox_common_linux::STDIN_FILENO,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            return Err(match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EPIPE) => litebox::platform::StdioReadError::Closed,
                _ => panic!("unhandled error {}", std::io::Error::last_os_error()),
            });
        }
        Ok(usize::try_from(n).unwrap())
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        let fd = match stream {
            litebox::platform::StdioOutStream::Stdout => litebox_common_linux::STDOUT_FILENO,
            litebox::platform::StdioOutStream::Stderr => litebox_common_linux::STDERR_FILENO,
        };
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EPIPE) => litebox::platform::StdioWriteError::Closed,
                _ => panic!("unhandled error {}", std::io::Error::last_os_error()),
            });
        }
        Ok(usize::try_from(n).unwrap())
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        use litebox::platform::StdioStream;
        use std::io::IsTerminal as _;
        match stream {
            StdioStream::Stdin => std::io::stdin().is_terminal(),
            StdioStream::Stdout => std::io::stdout().is_terminal(),
            StdioStream::Stderr => std::io::stderr().is_terminal(),
        }
    }
}

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
    fn exception_callback();
    fn interrupt_callback();
    fn switch_to_guest_start();
    fn switch_to_guest_end();
}

unsafe extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.init(ctx));
}

unsafe extern "C-unwind" fn reenter_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.reenter(ctx));
}

/// Handles Linux syscalls and dispatches them to LiteBox implementations.
///
/// Returns only if the guest thread is exiting. Otherwise, resumes the guest
/// without returning.
///
/// # Safety
///
/// - The `ctx` pointer must be valid pointer to a `litebox_common_linux::PtRegs` structure.
/// - If any syscall argument is a pointer, it must be valid.
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development
/// purposes.
#[allow(clippy::cast_sign_loss)]
unsafe extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.syscall(ctx));
}

extern "C-unwind" fn exception_handler(
    thread_ctx: &mut ThreadContext,
    trapno: usize,
    error: usize,
    cr2: usize,
) {
    let _ = error; // unused on aarch64; signal number is in trapno
    let info = litebox::shim::ExceptionInfo {
        fault_address: cr2,
        esr: trapno as u64,
    };
    thread_ctx.call_shim(|shim, ctx| shim.exception(ctx, &info));
}

/// Update the TLS lookup table with the current thread's (guest_tpidr, host_tls) entry.
///
/// Called before entering guest code on aarch64. The trampoline's per-SVC
/// snippets use this table to find the host TLS base on syscall entry.
///
/// Uses linear scan to match the trampoline's assembly lookup.
const TLS_TABLE_ENTRIES: usize = 256;

fn update_host_tls_entry() {
    use core::sync::atomic::Ordering;

    let table_addr = litebox_common_linux::HOST_TLS_TABLE_ADDR.load(Ordering::Acquire);
    if table_addr == 0 {
        return; // No TLS table allocated (not using rewriter-based trampoline)
    }

    // Read current host TPIDR_EL0 (= host TLS base)
    let host_tls: usize;
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) host_tls, options(nostack, preserves_flags));
    }

    // Read guest_tpidr from our thread-local
    let guest_tpidr = get_guest_tpidr();

    let sentinel: u64 = 0xFFFFFFFFFFFFFFFF;
    let table = table_addr as *mut u64;

    // Linear scan from index 0 (matches trampoline assembly lookup)
    for index in 0..TLS_TABLE_ENTRIES {
        let entry = unsafe { table.add(index * 2) };
        let stored_guest_tpidr = unsafe { entry.read_volatile() };

        if stored_guest_tpidr == guest_tpidr as u64 {
            // Found existing entry - update host_tls
            unsafe { entry.add(1).write_volatile(host_tls as u64) };
            return;
        }

        if stored_guest_tpidr == sentinel {
            // Found free slot - claim it
            unsafe {
                entry.write_volatile(guest_tpidr as u64);
                entry.add(1).write_volatile(host_tls as u64);
            }
            return;
        }
        // Slot occupied by different thread - continue scanning
    }

    panic!("TLS table full: exceeded {TLS_TABLE_ENTRIES} concurrent threads");
}

extern "C-unwind" fn interrupt_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.interrupt(ctx));
}

/// Calls `f` in order to call into a shim entrypoint.
impl ThreadContext<'_> {
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
            &mut litebox_common_linux::PtRegs,
        ) -> ContinueOperation,
    ) {
        // Clear the interrupt flag before calling the shim, since we've handled it
        // now (by calling into the shim), and it might be set again by the shim
        // before returning.
        unsafe {
            (*(litebox_common_linux::read_tpidr_el0() as *mut ThreadControlBlock)).interrupt = 0;
        }
        let op = f(self.shim, self.ctx);
        match op {
            ContinueOperation::Resume => {
                update_host_tls_entry();
                unsafe { switch_to_guest(self.ctx) }
            }
            ContinueOperation::Terminate => {}
        }
    }
}

impl litebox::platform::SystemInfoProvider for MacosUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as *const () as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        self.vdso_address
    }
}

thread_local! {
    // Use `ManuallyDrop` for more efficient TLS accesses, since this is always
    // dropped manually before the thread exits.
    static PLATFORM_TLS: Cell<*mut ()> = const { Cell::new(core::ptr::null_mut()) };
}

/// MacosUserland platform's thread-local storage implementation.
unsafe impl litebox::platform::ThreadLocalStorageProvider for MacosUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(value)
    }

    fn clear_guest_thread_local_storage() {
        set_guest_tpidr(0);
    }
}

static mut NEXT_SA: [libc::sigaction; 64] = unsafe { core::mem::zeroed() };
static INTERRUPT_SIGNAL_NUMBER: AtomicI32 = AtomicI32::new(0);

fn register_exception_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        fn sigaction(sig: i32, sa: Option<&libc::sigaction>, old_sa: &mut libc::sigaction) {
            unsafe {
                let r = libc::sigaction(
                    sig,
                    sa.map_or(std::ptr::null(), |sa| &raw const *sa),
                    &raw mut *old_sa,
                );
                assert!(
                    r >= 0,
                    "failed to query existing signal handler for signal {}: {}",
                    sig,
                    std::io::Error::last_os_error()
                );
            }
        }

        let interrupt_signal = {
            let sig = libc::SIGUSR1;
            let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
            let mut old_sa = unsafe { core::mem::zeroed() };
            sigaction(sig, Some(&sa), &mut old_sa);
            assert_eq!(
                old_sa.sa_sigaction,
                libc::SIG_DFL,
                "signal {sig} handler already installed",
            );
            INTERRUPT_SIGNAL_NUMBER.store(sig, Ordering::Relaxed);
            sig
        };

        let exception_signals = &[
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGILL,
            libc::SIGTRAP,
        ];
        for &sig in exception_signals {
            unsafe {
                let mut sa: libc::sigaction = core::mem::zeroed();
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                sa.sa_sigaction = exception_signal_handler as *const () as usize;
                // Block the interrupt signal while handling exceptions to avoid
                // saving the exception signal handler state as guest state.
                libc::sigaddset(&raw mut sa.sa_mask, interrupt_signal);
                // Note: the handler could start running before this call even
                // returns, so pass `&mut NEXT_SA` directly.
                sigaction(
                    sig,
                    Some(&sa),
                    &mut NEXT_SA[sig.reinterpret_as_unsigned() as usize],
                );
            }
        }
    });
}

/// Size of the alt-stack allocation for aarch64. Must be a power of 2 so that
/// signal handlers can recover the base address by masking SP.
const ALT_STACK_ALLOC_SIZE: usize = 0x10000; // 64 KiB

/// Magic value stored at `aligned_base + ALT_STACK_ALLOC_SIZE - 16` to validate
/// that a signal handler is running on our custom alt-stack.
const ALT_STACK_MAGIC: usize = 0x4C49_5445_424F_5821; // "LITEBOX!"

/// Runs `f` with an alternate signal stack set up (aarch64 version).
///
/// On aarch64, the alt-stack must be power-of-2 aligned so that signal handlers
/// can recover the host TLS base from `SP & ~(ALT_STACK_ALLOC_SIZE - 1) +
/// ALT_STACK_ALLOC_SIZE - 8`. The host TLS pointer is stored at
/// `aligned_base + ALT_STACK_ALLOC_SIZE - 8`.
///
/// Layout:
/// ```text
/// [guard (0x1000)] [usable signal stack] [pad (8B)] [host_tls (8B)]
/// ^                                       ^          ^              ^
/// aligned_base                            SIZE-16    SIZE-8         SIZE
/// ```
fn with_signal_alt_stack<R>(f: impl FnOnce() -> R) -> R {
    let guard_page_size: usize = 0x1000;
    // Allocate double the size so we can find an aligned region within it.
    let alloc_size = ALT_STACK_ALLOC_SIZE * 2;
    let raw_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            alloc_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(
        raw_base != libc::MAP_FAILED,
        "failed to allocate memory for alternate signal stack: {}",
        std::io::Error::last_os_error()
    );

    // Find the aligned base within the allocation.
    let raw_addr = raw_base as usize;
    let aligned_base = (raw_addr + ALT_STACK_ALLOC_SIZE - 1) & !(ALT_STACK_ALLOC_SIZE - 1);

    // Unmap the unused prefix and suffix.
    let prefix_size = aligned_base - raw_addr;
    if prefix_size > 0 {
        unsafe { libc::munmap(raw_base, prefix_size) };
    }
    let suffix_start = aligned_base + ALT_STACK_ALLOC_SIZE;
    let suffix_size = (raw_addr + alloc_size) - suffix_start;
    if suffix_size > 0 {
        unsafe { libc::munmap(suffix_start as *mut libc::c_void, suffix_size) };
    }

    let aligned_ptr = aligned_base as *mut libc::c_void;
    let _unmap_guard = litebox::utils::defer(move || {
        let r = unsafe { libc::munmap(aligned_ptr, ALT_STACK_ALLOC_SIZE) };
        assert!(
            r == 0,
            "failed to free memory for alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
    });

    // Set up a guard page at the bottom.
    let r = unsafe { libc::mprotect(aligned_ptr, guard_page_size, libc::PROT_NONE) };
    assert!(
        r == 0,
        "failed to set guard page for alternate signal stack: {}",
        std::io::Error::last_os_error()
    );

    // Store host TLS pointer at aligned_base + ALT_STACK_ALLOC_SIZE - 8.
    let host_tls = unsafe { litebox_common_linux::read_tpidr_el0() };
    let host_tls_slot = (aligned_base + ALT_STACK_ALLOC_SIZE - 8) as *mut usize;
    unsafe { core::ptr::write_volatile(host_tls_slot, host_tls) };

    // Store magic value at aligned_base + ALT_STACK_ALLOC_SIZE - 16
    // so signal handlers can verify they are on our custom alt-stack.
    let magic_slot = (aligned_base + ALT_STACK_ALLOC_SIZE - 16) as *mut usize;
    unsafe { core::ptr::write_volatile(magic_slot, ALT_STACK_MAGIC) };

    // ss_size is reduced by guard_page_size and 16 (for host_tls + pad slots)
    // to prevent signal frames from clobbering the host_tls slot.
    let usable_size = ALT_STACK_ALLOC_SIZE - guard_page_size - 16;
    let alt_stack = libc::stack_t {
        ss_sp: (aligned_base + guard_page_size) as *mut libc::c_void,
        ss_flags: 0,
        ss_size: usable_size,
    };
    let mut oss = libc::stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    unsafe {
        let r = libc::sigaltstack(&raw const alt_stack, &raw mut oss);
        assert!(
            r >= 0,
            "failed to set up alternate signal stack: {}",
            std::io::Error::last_os_error(),
        );
    }
    let _restore_guard = litebox::utils::defer(|| unsafe {
        // Clear the magic value BEFORE restoring the old sigaltstack.
        // This closes the race window: once magic is cleared, any signal
        // delivered (even if still on this memory region) will see the
        // invalid magic and safely return None from signal_handler_exit_guest.
        let magic_slot = (aligned_base + ALT_STACK_ALLOC_SIZE - 16) as *mut usize;
        core::ptr::write_volatile(magic_slot, 0);
        // Ensure the write is visible before we restore the old alt-stack.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        let r = libc::sigaltstack(&raw const oss, std::ptr::null_mut());
        assert!(
            r >= 0,
            "failed to restore original signal stack: {}",
            std::io::Error::last_os_error()
        );
    });
    f()
}

/// Called from signal handlers to fix up thread state after potentially running
/// in the guest (aarch64 version).
///
/// ARM64 cannot use `rdgsbase` — instead, the host TLS is recovered from the
/// alt-stack layout: the alt-stack is power-of-2 aligned (`ALT_STACK_ALLOC_SIZE`),
/// and the host TLS pointer is stored at `aligned_base + ALT_STACK_ALLOC_SIZE - 8`.
///
/// Clears `in_guest` and optionally sets `interrupt`. If `in_guest` was
/// previously set, returns the guest context pointer.
///
/// # Safety
/// Uses `sigaltstack(NULL, &ss)` to verify we're on the custom alt-stack before
/// accessing the SP-derived aligned base. This avoids faulting on unmapped memory
/// when the signal is delivered on a non-alt-stack.
fn signal_handler_exit_guest(
    _context: &libc::ucontext_t,
    set_interrupt: bool,
) -> Option<*mut litebox_common_linux::PtRegs> {
    unsafe {
        let mut current_ss: libc::stack_t = core::mem::zeroed();
        let ret = libc::sigaltstack(std::ptr::null(), &raw mut current_ss);
        if ret != 0 || current_ss.ss_flags & libc::SS_ONSTACK == 0 {
            // Not on our alt-stack (or syscall failed). Return None without
            // touching any SP-derived addresses.
            return None;
        }

        // We're on the alt-stack. Recover host TLS from the layout.
        // The alt-stack is power-of-2 aligned, so mask SP to get the base.
        let sp_val: usize;
        core::arch::asm!("mov {}, sp", out(reg) sp_val, options(nostack, nomem));
        let aligned_base = sp_val & !(ALT_STACK_ALLOC_SIZE - 1);

        // Double-check with magic value (belt and suspenders).
        let magic_ptr = (aligned_base + ALT_STACK_ALLOC_SIZE - 16) as *const usize;
        let magic = core::ptr::read_volatile(magic_ptr);
        if magic != ALT_STACK_MAGIC {
            return None;
        }

        let host_tls_ptr = (aligned_base + ALT_STACK_ALLOC_SIZE - 8) as *const usize;
        let host_tls = core::ptr::read_volatile(host_tls_ptr);

        if host_tls == 0 {
            return None;
        }

        // Restore host TPIDR_EL0.
        // NOTE: We read current TPIDR_EL0 first (before restoring host value)
        // so we can save the guest TPIDR below if needed.
        let current_tpidr: usize;
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) current_tpidr, options(nostack, nomem));
        litebox_common_linux::write_tpidr_el0(host_tls);

        // Read and clear in_guest.
        let in_guest_ptr = (host_tls as *mut u8).byte_offset(tcb_offset_in_guest());
        let was_in_guest = core::ptr::read_volatile(in_guest_ptr);
        core::ptr::write_volatile(in_guest_ptr, 0);

        if set_interrupt {
            let interrupt_ptr = (host_tls as *mut u8).byte_offset(tcb_offset_interrupt());
            core::ptr::write_volatile(interrupt_ptr, 1);
        }

        if was_in_guest == 0 {
            return None;
        }

        // Save the guest TPIDR_EL0 to the host-side `guest_tpidr` TLS variable.
        // This ensures that when `update_host_tls_entry` is later called (e.g.
        // from `call_shim` on Resume after an interrupt), it reads the correct
        // current guest TPIDR and can find the matching entry in the TLS lookup
        // table. Only do this when we were in guest code (was_in_guest != 0),
        // because otherwise current_tpidr is already the host TLS value.
        let guest_tpidr_ptr = (host_tls as *mut usize).byte_offset(tcb_offset_guest_tpidr());
        core::ptr::write_volatile(guest_tpidr_ptr, current_tpidr);

        let ctx_top_ptr = (host_tls as *const usize).byte_offset(tcb_offset_guest_context_top());
        let guest_context_top =
            core::ptr::read_volatile(ctx_top_ptr) as *mut litebox_common_linux::PtRegs;
        Some(guest_context_top.sub(1))
    }
}

/// Copies register state from a Linux signal context to a LiteBox PtRegs
/// structure (aarch64 version).
#[allow(clippy::cast_possible_truncation)]
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: &libc::ucontext_t) {
    let mctx = unsafe { &*context.uc_mcontext };
    for i in 0..29 {
        regs.regs[i] = mctx.__ss.__x[i] as usize;
    }
    regs.regs[29] = mctx.__ss.__fp as usize;
    regs.regs[30] = mctx.__ss.__lr as usize;
    regs.sp = mctx.__ss.__sp as usize;
    regs.pc = mctx.__ss.__pc as usize;
    regs.pstate = mctx.__ss.__cpsr as usize;
}

/// Updates a Linux signal context to return to `f` with the given arguments (aarch64).
#[allow(clippy::cast_sign_loss)]
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let sigctx = unsafe { &mut *context.uc_mcontext };
    sigctx.__ss.__pc = f as usize as u64;
    sigctx.__ss.__x[0] = p0 as u64;
    sigctx.__ss.__x[1] = p1 as u64;
    sigctx.__ss.__x[2] = p2 as u64;
    sigctx.__ss.__x[3] = p3 as u64;
}

/// Signal handler for hardware exceptions (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP).
unsafe extern "C" fn exception_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    let Some(regs) = signal_handler_exit_guest(context, false) else {
        return unsafe { next_signal_handler(signum, info, context) };
    };
    copy_signal_context(unsafe { &mut *regs }, context);

    // Ensure that `run_thread_arch` is linked in so that `exception_callback` is visible.
    let _ = run_thread_arch as *const () as usize;

    // Jump to exception_callback.
    let sigctx = unsafe { &*context.uc_mcontext };
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let (trapno, err, cr2) = {
        let fault_addr = sigctx.__es.__far;
        (
            signum as isize,     // use signal number as trap number
            0isize,              // no error code concept on ARM64
            fault_addr as isize, // fault address
        )
    };
    set_signal_return(context, exception_callback, 0, trapno, err, cr2);
}

/// Runs the next signal handler in the chain.
unsafe fn next_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    if signum == libc::SIGSEGV {
        #[allow(clippy::cast_possible_truncation)]
        let ip: usize = unsafe { (*context.uc_mcontext).__ss.__pc as usize };
        if let Some(fixup_addr) = litebox::mm::exception_table::search_exception_tables(ip) {
            unsafe {
                (*context.uc_mcontext).__ss.__pc = fixup_addr as u64;
            }
            return;
        }
    }

    unsafe {
        let next_sa = &NEXT_SA[signum.reinterpret_as_unsigned() as usize];
        match next_sa.sa_sigaction {
            libc::SIG_DFL => {
                // Block this signal and raise.
                let mut set: libc::sigset_t = core::mem::zeroed();
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, signum);
                libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
                libc::raise(signum);
                unreachable!()
            }
            libc::SIG_IGN => {}
            _ => {
                // Call the next handler
                if next_sa.sa_flags & libc::SA_SIGINFO == 0 {
                    let handler: extern "C" fn(libc::c_int) =
                        core::mem::transmute(next_sa.sa_sigaction);
                    handler(signum);
                } else {
                    let handler: extern "C" fn(
                        libc::c_int,
                        *mut libc::siginfo_t,
                        *mut libc::ucontext_t,
                    ) = core::mem::transmute(next_sa.sa_sigaction);
                    handler(signum, info, context);
                }
            }
        }
    }
}

/// Signal handler for interrupt signals.
unsafe fn interrupt_signal_handler(
    _signum: libc::c_int,
    _info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    // The interrupt signal can arrive in different contexts:
    // 1. The thread is running in the host at the beginning of the syscall
    //    handler. Do nothing--the syscall handler will handle the interrupt.
    // 2. The thread is running in the host, with in_guest = 0. Just record that
    //    an interrupt is pending; it will be checked next time we switch to the
    //    guest.
    // 3. The thread is running in the host, with in_guest = 1, in the middle of
    //    restoring the guest context. We need to jump to the interrupt handler
    //    without overwriting the saved guest context.
    // 4. The thread is running in the guest. We need to save the context and
    //    jump to the interrupt handler.
    //
    // Note that this signal can't arrive while in an exception signal handler
    // since we mask the interrupt signal while handling exceptions.

    #[allow(clippy::cast_possible_truncation)]
    let ip = unsafe { (*context.uc_mcontext).__ss.__pc as usize };

    // Case 1: at the beginning of the syscall handler.
    //
    // FUTURE: handle trampoline code, too. This is somewhat less important
    // because it's probably fine for the shim to observe a guest context that
    // is inside the trampoline.
    if ip == syscall_callback as *const () as usize {
        // No need to clear `in_guest` or set interrupt; the syscall handler will
        // clear `in_guest` and call into the shim.
        return;
    }

    // Clear `in_guest` and set `interrupt`.
    let Some(regs) = signal_handler_exit_guest(context, true) else {
        // Case 2: not in guest.
        return;
    };

    // If the interrupt happened while returning to the guest, don't overwrite
    // the saved context.
    let in_switch_to_guest = (switch_to_guest_start as *const () as usize
        ..switch_to_guest_end as *const () as usize)
        .contains(&ip);
    if in_switch_to_guest {
        // Case 3: in the middle of restoring guest context. Don't overwrite it.
    } else {
        // Case 4: in guest. Copy out the context.
        copy_signal_context(unsafe { &mut *regs }, context);
    }
    // Cases 3 and 4: jump to interrupt handler.
    set_signal_return(context, interrupt_callback, 0, 0, 0, 0);
}

impl litebox::platform::CrngProvider for MacosUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

/// Dummy `VmapManager`.
///
/// In general, userland platforms do not support `vmap` and `vunmap` (which are kernel functions).
/// We might need to emulate these functions' behaviors using virtual addresses for development or
/// testing, or use a kernel module to provide this functionality (if needed).
impl<const ALIGN: usize> VmapManager<ALIGN> for MacosUserland {}

/// Dummy `VmemPageFaultHandler`.
///
/// Page faults are handled transparently by the host Linux kernel.
/// Provided to satisfy trait bounds for `PageManager::handle_page_fault`.
impl litebox::mm::linux::VmemPageFaultHandler for MacosUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for Linux userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for Linux userland")
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use std::thread::sleep;

    use litebox::platform::RawMutex;

    use crate::MacosUserland;
    use litebox::platform::PageManagementProvider;

    extern crate std;

    #[test]
    fn test_raw_mutex() {
        let mutex = std::sync::Arc::new(super::RawMutex {
            inner: AtomicU32::new(0),
        });

        let copied_mutex = mutex.clone();
        std::thread::spawn(move || {
            sleep(core::time::Duration::from_millis(500));
            copied_mutex
                .inner
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            copied_mutex.wake_many(10);
        });

        assert!(mutex.block(0).is_ok());
    }

    #[test]
    fn test_reserved_pages() {
        let platform = MacosUserland::new(None);
        let reserved_pages: Vec<_> =
            <MacosUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        // Check that the reserved pages are in order and non-overlapping
        let mut prev = 0;
        for page in reserved_pages {
            assert!(page.start >= prev);
            assert!(page.end > page.start);
            prev = page.end;
        }
    }
}
