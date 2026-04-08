// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on macOS (Apple Silicon).
//!
//! This crate is the macOS ARM64 (aarch64) counterpart of
//! [`litebox_platform_linux_userland`](../litebox_platform_linux_userland/index.html).
//! Only Apple Silicon (aarch64) is supported; there is no x86_64 macOS support.
//!
//! # Platform differences from Linux
//!
//! ## TLS and TPIDR_EL0
//!
//! On Linux aarch64 the kernel preserves `TPIDR_EL0` across context switches
//! and signal delivery, so LiteBox stores the thread-control-block (TCB)
//! pointer there and recovers it with `mrs xN, tpidr_el0` in assembly
//! trampolines.
//!
//! macOS uses `TPIDRRO_EL0` and `x18` (the platform-reserved register) for
//! its own TLS.  It makes **no guarantees** about `TPIDR_EL0`: the kernel may
//! write zero or the pthread pointer into it on any context switch or signal
//! delivery, and `sigreturn` clobbers it to the pthread value.  Therefore:
//!
//! * All assembly entry points (`run_thread_arch`, `switch_to_guest`) receive
//!   the TCB pointer as an explicit register argument instead of reading
//!   `TPIDR_EL0`.
//! * `TPIDR_EL0` is **never written** on host-side code paths.  macOS system
//!   libraries (notably `libsystem_malloc`'s XZone allocator) use TPIDR_EL0
//!   via `_os_cpu_number()` for per-CPU cache lookups.  Writing our TCB
//!   address there corrupts the CPU-number derivation and crashes malloc.
//! * The only `msr tpidr_el0` is in `switch_to_guest`, which sets the
//!   *guest* TPIDR_EL0 value just before branching into guest code.
//! * Signal handlers recover the host TLS pointer from the alt-stack layout
//!   (SP-aligned base + magic cookie) rather than from `TPIDR_EL0`.
//! * `set_signal_return` passes `host_tls` via `x9` in the signal ucontext
//!   so the callback asm can use x9 as TCB pointer for host-stack recovery.
//!   (`x18` cannot be used because Darwin sigreturn does not restore it.)
//!
//! ## Address space
//!
//! The macOS Mach-O `__PAGEZERO` segment occupies virtual addresses 0–4 GB,
//! making them permanently unmappable.  All guest mappings must be placed
//! above `TASK_ADDR_MIN = 0x1_0000_0000` (4 GB).  The vmem layer's
//! `TASK_ADDR_MIN` constant enforces this.
//!
//! ## Page size (16 KB host, 4 KB guest)
//!
//! Apple Silicon uses 16 KB pages at the hardware and kernel level.  Litebox
//! tracks VMAs at 4 KB (guest `PAGE_SIZE`) granularity.  The platform layer
//! converts between the two:
//!
//! * `mmap`, `munmap`, `mprotect` calls round addresses/sizes to 16 KB
//!   boundaries.
//! * When a single 16 KB host page contains 4 KB guest sub-pages with
//!   different permissions, the page is treated as an "edge page" and
//!   managed via fault-and-toggle (see W^X below).
//!
//! ## W^X enforcement (no RWX pages)
//!
//! macOS enforces write-xor-execute: no page may be simultaneously writable
//! and executable.  When a 16 KB host page contains guest sub-pages that
//! require both RW and RX (an "edge page"), the platform sets the page to
//! one permission and toggles on fault:
//!
//! * An instruction-abort (EC 0x20/0x21) flips the page from RW to RX.
//! * A write data-abort (EC 0x24/0x25, WnR=1) flips the page from RX to RW.
//!
//! After toggling, if the fault occurred in the guest, the handler routes
//! through `interrupt_callback` to properly restore `TPIDR_EL0` (which
//! `sigreturn` clobbers) before resuming execution via `switch_to_guest`.
//!
//! ## Signal differences
//!
//! * **SIGBUS number:** macOS `SIGBUS` = 10, Linux `SIGBUS` = 7.
//!   `macos_signal_to_linux` translates macOS signal numbers to their
//!   Linux equivalents before forwarding to the shim.
//! * **sigreturn behavior:** macOS sigreturn clobbers `TPIDR_EL0` to the
//!   pthread value and does **not** restore `x18`.  Signal handlers must
//!   pass `host_tls` through a caller-saved register (`x9`) in the ucontext.
//! * **SIGBUS for NULL dereference:** On macOS ARM64, NULL pointer accesses
//!   can arrive as SIGBUS rather than SIGSEGV.  Both exception-table
//!   recovery and the edge-page handler check for either signal.
//!
//! ## brk reservation
//!
//! A 32 MiB region is reserved above the main binary base to serve as the
//! guest's brk heap.  Anonymous `mmap` calls that the macOS kernel places
//! inside this reserved zone are retried until a non-conflicting address is
//! obtained.  See `BRK_RESERVE_SIZE` in `litebox::mm`.
//!
//! ## ELF interpreter placement
//!
//! On Linux the kernel's ELF loader places the interpreter.  On macOS the
//! platform must map it manually.  The loader queries the vmem layer for a
//! free gap above the brk reservation to avoid address collisions between
//! the interpreter, the main binary, and the brk heap.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::cell::Cell;
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
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

/// macOS arm64 uses 16KB pages. All kernel VM operations (mmap, munmap, mprotect)
/// require addresses aligned to this size. Litebox tracks VMAs at 4KB (PAGE_SIZE)
/// granularity, so the platform layer must round to HOST_PAGE_SIZE boundaries.
const HOST_PAGE_SIZE: usize = 16384;

const KERN_SUCCESS: i32 = 0;
const VM_REGION_SUBMAP_INFO_COUNT_64: u32 = 16;

/// Round `addr` down to HOST_PAGE_SIZE alignment.
const fn host_page_align_down(addr: usize) -> usize {
    addr & !(HOST_PAGE_SIZE - 1)
}

/// Round `addr` up to HOST_PAGE_SIZE alignment.
const fn host_page_align_up(addr: usize) -> usize {
    (addr + HOST_PAGE_SIZE - 1) & !(HOST_PAGE_SIZE - 1)
}

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
    fn mach_vm_allocate(target_task: u32, address: *mut u64, size: u64, flags: i32) -> i32;
    fn mach_vm_deallocate(target_task: u32, address: u64, size: u64) -> i32;
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

/// `VM_FLAGS_ANYWHERE`: Let the kernel choose any available address.
const VM_FLAGS_ANYWHERE: i32 = 1;

/// `VM_FLAGS_FIXED`: Use the specified address exactly.
const VM_FLAGS_FIXED: i32 = 0;

/// `VM_FLAGS_OVERWRITE`: Allow overwriting existing mappings (including
/// kernel-managed shared region mappings like the dyld shared cache).
const VM_FLAGS_OVERWRITE: i32 = 0x4000;
///
/// Edge pages are 16KB host pages that contain 4KB guest sub-pages with
/// conflicting permissions (e.g., RW data + RX code). Since macOS rejects
/// `mprotect(RWX)`, edge pages are set to either RW or RX, and permission
/// faults are handled by toggling the permission in the signal handler.
///
/// Typical process: ~2-6 edge pages per loaded ELF binary. With main +
/// interpreter + shared libraries, expect ~10-40 total.
const MAX_EDGE_PAGES: usize = 256;

/// Lock-free edge page registry for the fault-and-toggle W^X mechanism.
///
/// Stores 16KB-aligned addresses of edge pages. The signal handler reads
/// this without locks (atomic loads). Writers use a simple spinlock.
///
/// Each entry is an AtomicUsize: 0 = empty, nonzero = 16KB-aligned address.
static EDGE_PAGES: [std::sync::atomic::AtomicUsize; MAX_EDGE_PAGES] = {
    // const initializer for array of AtomicUsize
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    [ZERO; MAX_EDGE_PAGES]
};
static EDGE_PAGE_LOCK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Global function pointer for demand-page handling.
///
/// When a SIGBUS occurs at an address that is NOT an edge page,
/// `exception_signal_handler` calls this function (if non-null) to attempt
/// demand-page resolution.  The function should allocate a fresh page at the
/// faulting address and fill it with the correct data from the subcache file.
///
/// Returns `true` if the page was successfully served (fault resolved),
/// `false` otherwise.
///
/// This is set by the shim's `install_shared_cache` and persists across
/// execve (the shared cache and its demand-page sources are preserved).
///
/// # Safety
///
/// The function must be async-signal-safe (only raw syscalls, no heap).
static DEMAND_PAGE_HANDLER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Register a demand-page handler that will be called from the signal handler
/// for SIGBUS faults that are not edge-page faults.
///
/// The handler function signature is `unsafe fn(fault_addr: usize) -> bool`.
///
/// # Safety
///
/// The provided function pointer must be valid for the lifetime of the process
/// and must be async-signal-safe.
pub unsafe fn register_demand_page_handler(handler: unsafe fn(usize) -> bool) {
    DEMAND_PAGE_HANDLER.store(handler as usize, Ordering::Release);
}

// ── Per-sub-page edge page permission tracking ──────────────────────────────
//
// Each 16KB host page that straddles a 4KB permission boundary needs
// per-sub-page tracking so that `update_permissions` can compute the
// correct W^X-compliant composite permission (RW or RX) for the whole
// host page.  Without this, a `mprotect(PROT_NONE)` on one 4KB slice
// can demote the entire 16KB page, stripping execute permission from
// adjacent 4KB slices that still contain code.

#[derive(Clone, Copy)]
struct EdgePageState {
    addr: usize,
    subpage_perms: [u8; 4],
}

const EMPTY_EDGE_PAGE_STATE: EdgePageState = EdgePageState {
    addr: 0,
    subpage_perms: [0; 4],
};

static EDGE_PAGE_STATES: std::sync::Mutex<[EdgePageState; MAX_EDGE_PAGES]> =
    std::sync::Mutex::new([EMPTY_EDGE_PAGE_STATE; MAX_EDGE_PAGES]);

fn encode_perms(perms: MemoryRegionPermissions) -> u8 {
    (u8::from(perms.contains(MemoryRegionPermissions::READ)))
        | ((u8::from(perms.contains(MemoryRegionPermissions::WRITE))) << 1)
        | ((u8::from(perms.contains(MemoryRegionPermissions::EXEC))) << 2)
}

fn decode_perms(bits: u8) -> MemoryRegionPermissions {
    let mut perms = MemoryRegionPermissions::empty();
    if (bits & 0b001) != 0 {
        perms |= MemoryRegionPermissions::READ;
    }
    if (bits & 0b010) != 0 {
        perms |= MemoryRegionPermissions::WRITE;
    }
    if (bits & 0b100) != 0 {
        perms |= MemoryRegionPermissions::EXEC;
    }
    perms
}

fn effective_edge_page_prot(subpage_perms: [u8; 4]) -> libc::c_int {
    let mut any_read = false;
    let mut any_write = false;
    let mut any_exec = false;
    for bits in subpage_perms {
        let perms = decode_perms(bits);
        any_read |= perms.contains(MemoryRegionPermissions::READ);
        any_write |= perms.contains(MemoryRegionPermissions::WRITE);
        any_exec |= perms.contains(MemoryRegionPermissions::EXEC);
    }
    let mut prot = 0;
    if any_read || any_write || any_exec {
        prot |= ProtFlags::PROT_READ.bits();
    }
    if any_exec {
        prot |= ProtFlags::PROT_EXEC.bits();
    } else if any_write {
        prot |= ProtFlags::PROT_WRITE.bits();
    }
    prot
}

fn decode_host_protection(protection: i32) -> MemoryRegionPermissions {
    let mut perms = MemoryRegionPermissions::empty();
    perms.set(
        MemoryRegionPermissions::READ,
        protection & libc::VM_PROT_READ != 0,
    );
    perms.set(
        MemoryRegionPermissions::WRITE,
        protection & libc::VM_PROT_WRITE != 0,
    );
    perms.set(
        MemoryRegionPermissions::EXEC,
        protection & libc::VM_PROT_EXECUTE != 0,
    );
    perms
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::used_underscore_binding
)]
fn query_host_page_permissions(host_page_addr: usize) -> MemoryRegionPermissions {
    let mut address: u64 = host_page_addr as u64;
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
    if kr != KERN_SUCCESS || address as usize != host_page_addr {
        return MemoryRegionPermissions::empty();
    }

    // `vm_region_submap_info_64` is modeled here as an opaque natural_t array to
    // keep this file buildable off-macOS; the first field is `protection`.
    decode_host_protection(info._data[0] as i32)
}

fn update_edge_page_state(
    host_page_addr: usize,
    range: core::ops::Range<usize>,
    perms: MemoryRegionPermissions,
) -> libc::c_int {
    debug_assert_eq!(host_page_addr % HOST_PAGE_SIZE, 0);
    let mut table = EDGE_PAGE_STATES.lock().unwrap();
    let mut slot = None;
    for entry in table.iter_mut() {
        if entry.addr == host_page_addr {
            slot = Some(entry);
            break;
        }
        if entry.addr == 0 && slot.is_none() {
            slot = Some(entry);
        }
    }
    let Some(entry) = slot else {
        panic!("edge page state table full: exceeded {MAX_EDGE_PAGES} entries");
    };
    if entry.addr == 0 {
        entry.addr = host_page_addr;
        entry.subpage_perms = [encode_perms(query_host_page_permissions(host_page_addr)); 4];
    }
    for (idx, bits) in entry.subpage_perms.iter_mut().enumerate() {
        let sub_start = host_page_addr + idx * 4096;
        let sub_end = sub_start + 4096;
        if sub_start < range.end && sub_end > range.start {
            *bits = encode_perms(perms);
        }
    }
    effective_edge_page_prot(entry.subpage_perms)
}

fn clear_edge_page_state(host_page_addr: usize, range: core::ops::Range<usize>) -> bool {
    debug_assert_eq!(host_page_addr % HOST_PAGE_SIZE, 0);
    let mut table = EDGE_PAGE_STATES.lock().unwrap();
    let Some(entry) = table.iter_mut().find(|entry| entry.addr == host_page_addr) else {
        return false;
    };
    for (idx, bits) in entry.subpage_perms.iter_mut().enumerate() {
        let sub_start = host_page_addr + idx * 4096;
        let sub_end = sub_start + 4096;
        if sub_start < range.end && sub_end > range.start {
            *bits = 0;
        }
    }
    let any_remaining = entry.subpage_perms.iter().any(|&bits| bits != 0);
    if !any_remaining {
        *entry = EMPTY_EDGE_PAGE_STATE;
    }
    any_remaining
}

#[allow(clippy::needless_range_loop)]
fn unregister_edge_page(addr: usize) {
    debug_assert_eq!(addr % HOST_PAGE_SIZE, 0, "edge page not 16KB-aligned");

    while EDGE_PAGE_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }

    let mut write_idx = 0;
    for read_idx in 0..MAX_EDGE_PAGES {
        let value = EDGE_PAGES[read_idx].load(Ordering::Relaxed);
        if value == 0 {
            break;
        }
        if value == addr {
            continue;
        }
        if write_idx != read_idx {
            EDGE_PAGES[write_idx].store(value, Ordering::Relaxed);
        }
        write_idx += 1;
    }
    for entry in EDGE_PAGES.iter().skip(write_idx) {
        entry.store(0, Ordering::Relaxed);
    }

    EDGE_PAGE_LOCK.store(false, Ordering::Release);
}

fn sync_edge_page_mapping(range: core::ops::Range<usize>, perms: MemoryRegionPermissions) {
    let outer_start = host_page_align_down(range.start);
    let outer_end = host_page_align_up(range.end);
    let inner_start = host_page_align_up(range.start);
    let inner_end = host_page_align_down(range.end);
    let has_leading_edge = outer_start < inner_start;
    let has_trailing_edge = inner_end < outer_end;
    let leading_edge_addr = outer_start;
    let trailing_edge_addr = host_page_align_down(range.end.saturating_sub(1));

    if has_leading_edge {
        update_edge_page_state(leading_edge_addr, range.clone(), perms);
        register_edge_page(leading_edge_addr);
    }

    if has_trailing_edge && trailing_edge_addr != leading_edge_addr {
        update_edge_page_state(trailing_edge_addr, range.clone(), perms);
        register_edge_page(trailing_edge_addr);
    }

    if inner_start >= inner_end && !has_leading_edge && has_trailing_edge {
        update_edge_page_state(outer_start, range, perms);
        register_edge_page(outer_start);
    }
}

fn clear_edge_page_mapping(range: core::ops::Range<usize>) {
    let outer_start = host_page_align_down(range.start);
    let outer_end = host_page_align_up(range.end);
    let inner_start = host_page_align_up(range.start);
    let inner_end = host_page_align_down(range.end);
    let has_leading_edge = outer_start < inner_start;
    let has_trailing_edge = inner_end < outer_end;
    let leading_edge_addr = outer_start;
    let trailing_edge_addr = host_page_align_down(range.end.saturating_sub(1));

    if has_leading_edge && !clear_edge_page_state(leading_edge_addr, range.clone()) {
        unregister_edge_page(leading_edge_addr);
    }

    if has_trailing_edge
        && trailing_edge_addr != leading_edge_addr
        && !clear_edge_page_state(trailing_edge_addr, range.clone())
    {
        unregister_edge_page(trailing_edge_addr);
    }

    if inner_start >= inner_end
        && !has_leading_edge
        && has_trailing_edge
        && !clear_edge_page_state(outer_start, range)
    {
        unregister_edge_page(outer_start);
    }
}

/// Register a 16KB host page as an edge page (has mixed RW/RX sub-pages).
fn register_edge_page(addr: usize) {
    debug_assert_eq!(addr % HOST_PAGE_SIZE, 0, "edge page not 16KB-aligned");

    // Acquire spinlock
    while EDGE_PAGE_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }

    // Check if already registered
    for entry in &EDGE_PAGES {
        if entry.load(Ordering::Relaxed) == addr {
            EDGE_PAGE_LOCK.store(false, Ordering::Release);
            return;
        }
    }

    // Find empty slot
    for entry in &EDGE_PAGES {
        if entry.load(Ordering::Relaxed) == 0 {
            entry.store(addr, Ordering::Release);
            EDGE_PAGE_LOCK.store(false, Ordering::Release);
            return;
        }
    }

    EDGE_PAGE_LOCK.store(false, Ordering::Release);
    panic!("edge page table full: exceeded {MAX_EDGE_PAGES} entries");
}

/// Check if a 16KB-aligned address is a registered edge page.
/// Safe to call from signal handlers (lock-free reads).
fn is_edge_page(addr: usize) -> bool {
    let aligned = host_page_align_down(addr);
    for entry in &EDGE_PAGES {
        let v = entry.load(Ordering::Relaxed);
        if v == 0 {
            return false; // entries are packed, 0 = end
        }
        if v == aligned {
            return true;
        }
    }
    false
}

/// Ensure an edge host page exists with the given permissions.
///
/// Tries `mprotect` first to preserve existing content from adjacent
/// sub-pages. If that fails with ENOMEM (page was unmapped by a prior
/// `deallocate_pages` that rounded inward) or EACCES (page has restricted
/// `max_protection` from codesigning), falls back to `mmap MAP_FIXED`
/// to recreate the page as fresh anonymous memory.
fn ensure_edge_page(page_addr: usize, prot: libc::c_int) {
    debug_assert_eq!(page_addr % HOST_PAGE_SIZE, 0);

    let r = unsafe { libc::mprotect(page_addr as *mut libc::c_void, HOST_PAGE_SIZE, prot) };
    if r == 0 {
        return; // mprotect succeeded — page existed, content preserved
    }

    // mprotect failed — page was unmapped or has restricted max_protection.
    // ENOMEM: page was unmapped by a prior `deallocate_pages` that rounded inward.
    // EACCES: page belongs to a codesigned Mach-O mapping (e.g., host binary
    //   __DATA segment) whose max_protection doesn't allow the requested change.
    //   This happens when the guest's brk heap grows into the host binary's
    //   address range — `evict_reserved_from_brk_zone` removes the VMA tracker
    //   entries but cannot unmap host-owned pages. mmap MAP_FIXED below will
    //   forcibly replace the mapping with fresh anonymous memory.
    let errno = std::io::Error::last_os_error();
    assert!(
        errno.raw_os_error() == Some(libc::ENOMEM) || errno.raw_os_error() == Some(libc::EACCES),
        "mprotect edge page {page_addr:#x} failed with unexpected error: {errno}"
    );
    let r = unsafe {
        libc::mmap(
            page_addr as *mut libc::c_void,
            HOST_PAGE_SIZE,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    assert_ne!(
        r,
        libc::MAP_FAILED,
        "mmap MAP_FIXED edge page {:#x} failed: {}",
        page_addr,
        std::io::Error::last_os_error()
    );
}

/// Ensure an edge host page exists with RW permissions.
fn ensure_edge_page_rw(page_addr: usize) {
    let prot_rw = (ProtFlags::PROT_READ | ProtFlags::PROT_WRITE).bits();
    ensure_edge_page(page_addr, prot_rw);
}

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
    guest_x18: usize,
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

#[allow(dead_code)]
const fn tcb_offset_guest_tpidr() -> isize {
    24
}

const fn tcb_offset_in_guest() -> isize {
    32
}

const fn tcb_offset_interrupt() -> isize {
    33
}

#[allow(dead_code)]
const fn tcb_offset_guest_x18() -> isize {
    40
}

// Thread-local pointer to the current thread's `ThreadControlBlock`.
//
// On macOS, TPIDR_EL0 is only set to our TCB during guest execution (inside
// `run_thread_inner`). Code that runs outside that scope (e.g. during
// `load_program` or `clear_guest_thread_local_storage`) must use this
// thread-local to access the TCB instead of reading TPIDR_EL0 directly.
//
// The asm fast path (run_thread_arch, switch_to_guest, syscall_callback,
// signal handlers) receives the TCB via explicit register arguments or
// alt-stack recovery.
thread_local! {
    static TCB_PTR: Cell<*mut ThreadControlBlock> = const { Cell::new(core::ptr::null_mut()) };
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

        let tun_socket_fd = std::sync::RwLock::new(tun_device_name.map(Self::open_utun));

        let reserved_pages = Self::read_maps();
        let platform = Self {
            tun_socket_fd,
            reserved_pages,
            vdso_address: None,
            cow_regions: std::sync::RwLock::new(std::collections::BTreeMap::new()),
        };
        Box::leak(Box::new(platform))
    }

    /// Open a macOS utun device by name (e.g., `"utun5"`).
    ///
    /// Returns an `OwnedFd` for the utun socket, configured in non-blocking mode.
    ///
    /// # Panics
    ///
    /// Panics if the device name is invalid, the socket cannot be created, or
    /// the control info / connect calls fail.
    fn open_utun(name: &str) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd as _;

        // Constants from <sys/kern_control.h> and <net/if_utun.h>
        const PF_SYSTEM: i32 = libc::AF_SYSTEM;
        const SYSPROTO_CONTROL: i32 = 2;
        const AF_SYS_CONTROL: u16 = 2;
        const MAX_KCTL_NAME: usize = 96;
        const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

        // struct ctl_info { u32 ctl_id; char ctl_name[MAX_KCTL_NAME]; }
        #[repr(C)]
        struct CtlInfo {
            ctl_id: u32,
            ctl_name: [u8; MAX_KCTL_NAME],
        }

        // struct sockaddr_ctl
        #[repr(C)]
        struct SockaddrCtl {
            sc_len: u8,
            sc_family: u8,
            ss_sysaddr: u16,
            sc_id: u32,
            sc_unit: u32,
            sc_reserved: [u32; 5],
        }

        // CTLIOCGINFO ioctl number: _IOWR('N', 3, struct ctl_info) using BSD ioctl encoding
        // BSD: _IOC(IOC_INOUT, 'N', 3, sizeof(ctl_info))
        //    = 0xC0000000 | ((size & 0x1FFF) << 16) | ('N' << 8) | 3
        const CTLIOCGINFO: libc::c_ulong = 0xC0000000
            | ((core::mem::size_of::<CtlInfo>() as libc::c_ulong & 0x1FFF) << 16)
            | ((b'N' as libc::c_ulong) << 8)
            | 3;

        // Parse unit number from device name: "utunN" → N
        let unit_str = name
            .strip_prefix("utun")
            .unwrap_or_else(|| panic!("utun device name must start with 'utun', got: {name:?}"));
        let unit: u32 = unit_str
            .parse()
            .unwrap_or_else(|e| panic!("failed to parse utun unit number from {name:?}: {e}"));
        // macOS uses sc_unit = N + 1 for utunN
        let sc_unit = unit + 1;

        // Create PF_SYSTEM / SOCK_DGRAM / SYSPROTO_CONTROL socket
        let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        assert!(
            fd >= 0,
            "failed to create PF_SYSTEM socket: {}",
            std::io::Error::last_os_error()
        );

        // Look up the control ID for com.apple.net.utun_control
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0u8; MAX_KCTL_NAME],
        };
        info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);

        let ret = unsafe { libc::ioctl(fd, CTLIOCGINFO, &raw mut info) };
        assert!(
            ret == 0,
            "CTLIOCGINFO ioctl failed: {}",
            std::io::Error::last_os_error()
        );

        // Connect to the utun control with the desired unit number
        let addr = SockaddrCtl {
            sc_len: u8::try_from(core::mem::size_of::<SockaddrCtl>()).unwrap(),
            sc_family: u8::try_from(libc::AF_SYSTEM).unwrap(),
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit,
            sc_reserved: [0; 5],
        };
        let ret = unsafe {
            libc::connect(
                fd,
                (&raw const addr).cast(),
                u32::try_from(core::mem::size_of::<SockaddrCtl>()).unwrap(),
            )
        };
        assert!(
            ret == 0,
            "failed to connect utun socket: {}",
            std::io::Error::last_os_error()
        );

        // Set non-blocking
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(
            flags >= 0,
            "fcntl F_GETFL failed: {}",
            std::io::Error::last_os_error()
        );
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        assert!(
            ret == 0,
            "fcntl F_SETFL O_NONBLOCK failed: {}",
            std::io::Error::last_os_error()
        );

        // Take ownership of the fd
        unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }
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
    // Re-register exception handlers for the main thread.
    //
    // `install_shared_cache` resets SIGBUS/SIGSEGV/SIGTRAP to SIG_DFL
    // (because the install thread has no TLS entry).  We must reset the
    // `Once` guard and re-register before entering guest code.
    //
    // This runs in `run_thread` (not `run_thread_inner`) because it must
    // happen exactly once — spawned threads must NOT reset the `Once` or
    // they will race with concurrent `call_once` callers.
    unsafe {
        reset_exception_handler_once();
    }
    register_exception_handlers();
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
    // See `run_thread` — same reset+register before entering guest code.
    unsafe {
        reset_exception_handler_once();
    }
    register_exception_handlers();
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
        let tcb_ptr = &raw mut *tcb;
        let tcb_addr = tcb_ptr as usize;
        // Set the thread-local (for Rust code) now.
        TCB_PTR.set(tcb_ptr);
        // Register TLS entry early so that any libc calls during
        // run_thread setup (e.g. mmap in with_signal_alt_stack) that go
        // through patched shared cache SVC stubs can find this thread's
        // TCB via the trampoline's TPIDRRO_EL0-keyed TLS table.
        update_host_tls_entry();
        // Re-register exception handlers if not already done.
        //
        // For the main thread, `run_thread` already reset the `Once`
        // guard and re-registered handlers.  For spawned threads, the
        // `call_once` inside `register_exception_handlers` is a no-op
        // because the main thread already completed it.
        register_exception_handlers();
        with_signal_alt_stack(tcb_addr, || unsafe {
            // Do NOT write TPIDR_EL0 here.  macOS system libraries
            // (libsystem_malloc's XZone allocator) use TPIDR_EL0 via
            // _os_cpu_number() for per-CPU cache lookups.  Writing our
            // TCB address there corrupts the CPU-number derivation and
            // crashes malloc.  The trampoline's shared handlers use
            // TPIDRRO_EL0 (not TPIDR_EL0) for TLS table lookup, and
            // host Rust code uses TCB_PTR (thread-local).  The only
            // place that writes TPIDR_EL0 is switch_to_guest, which
            // sets the guest's virtual TPIDR_EL0 just before branching
            // into guest code.
            run_thread_arch(&mut thread_ctx, ctx_ptr, u8::from(reenter), tcb_ptr);
        });
        // After run_thread_arch returns, do NOT free the TCB or remove
        // TLS entries.  Post-run cleanup code (defer guards, Arc/Mutex
        // destructors, etc.) may call libc functions (free, munmap, ...)
        // that go through the patched shared cache gate.  The gate's
        // trampoline needs a valid TLS entry + TCB to function.
        //
        // Leak the TCB intentionally — the forked child is about to
        // _exit() anyway, so the OS reclaims all memory.
        core::mem::forget(tcb);
    });
}

fn set_guest_tpidr(value: usize) {
    let tcb = TCB_PTR.get();
    assert!(!tcb.is_null(), "set_guest_tpidr called without TCB");
    unsafe {
        (*tcb).guest_tpidr = value;
    }
}

#[allow(dead_code)]
fn get_guest_tpidr() -> usize {
    let tcb = TCB_PTR.get();
    assert!(!tcb.is_null(), "get_guest_tpidr called without TCB");
    unsafe { (*tcb).guest_tpidr }
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
    tcb: *mut ThreadControlBlock,
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
    // x3 = tcb pointer (4th argument), use it directly instead of
    // reading TPIDR_EL0 which macOS can clobber at any time.
    mov x8, x3
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
    //   x18 = UNRELIABLE (XNU may zero it via preemption; do NOT use)
    //   x30 = guest return address (after the rewritten SVC)
    //   Guest stack: [SP+0]=saved_x16, [SP+8]=saved_x17, [SP+16]=saved_x30,
    //                [SP+24]=guest_tpidr, [SP+32]=guest_x18, [SP+40]=host_tls (TCB ptr)
    //   SP was decremented by 48 by trampoline
    //   x0-x15, x19-x29 = guest register values
    //   (x16, x17 were clobbered by trampoline; originals on guest stack)
    // ================================================================
    .cfi_endproc

    .globl _syscall_callback
_syscall_callback:
    .cfi_startproc
    // Host TLS (TCB pointer) is already stored at [SP+40] by the trampoline's
    // shared SVC handler (instruction [14]: STR X16, [SP, #40]). We load it
    // from there instead of relying on x18, which XNU may have zeroed via
    // preemptive context switch between the trampoline and this point.

    // ---- HOST PASSTHROUGH FAST-PATH ----
    // If in_guest == 0, this is host-side code (e.g. free(), malloc(), _exit())
    // going through the patched shared cache gate. Execute the original SVC
    // transparently and return to the caller as if the gate wasn't there.
    ldr x17, [sp, #40]           // x17 = TCB (from trampoline-stored host_tls)
    ldrb w16, [x17, #32]         // w16 = TCB.in_guest
    cbz w16, 80f  // if !in_guest, bypass guest handling

    // Clear in_guest flag.
    strb wzr, [x17, #32]         // TCB.in_guest = 0

    // Save guest TPIDR (from trampoline stack slot) to guest_tpidr TLS var.
    ldr x17, [sp, #40]           // x17 = TCB (reload from stack)
    ldr x16, [sp, #24]           // x16 = guest_tpidr from trampoline
    str x16, [x17, #24]          // TCB.guest_tpidr = guest_tpidr

    // Do NOT write TPIDR_EL0 here.  macOS system libraries use it for
    // per-CPU data (_os_cpu_number); writing our TCB address corrupts
    // malloc's XZone per-CPU cache lookup.  Host Rust code uses
    // TCB_PTR (thread-local) to find the TCB, not TPIDR_EL0.

    // Load guest_context_top and compute PtRegs base address.
    ldr x16, [x17, #16]          // x16 = TCB.guest_context_top
    sub x16, x16, #{GUEST_CONTEXT_SIZE}
    // x16 = base of PtRegs.

    // Save guest x0-x15 into PtRegs.regs[0..15].
    // x16 is our PtRegs base pointer.
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

    // Load guest_x18 from TCB and store into PtRegs.regs[18].
    // Reload TCB from stack (x18 is unreliable).
    ldr x17, [sp, #40]           // x17 = TCB (reload)
    ldr x17, [x17, #40]          // x17 = TCB.guest_x18
    str x17, [x16, #144]         // regs[18] = guest_x18

    // Save guest x19-x29.
    stp x19, x20, [x16, #152]    // regs[19], regs[20]
    stp x21, x22, [x16, #168]    // regs[21], regs[22]
    stp x23, x24, [x16, #184]    // regs[23], regs[24]
    stp x25, x26, [x16, #200]    // regs[25], regs[26]
    stp x27, x28, [x16, #216]    // regs[27], regs[28]
    str x29, [x16, #232]         // regs[29]

    // Store guest x30 (link register, recovered from stack).
    str x2, [x16, #240]          // regs[30] = guest LR

    // Compute original guest SP (trampoline decremented by 48).
    add x0, sp, #48
    str x0, [x16, #248]          // PtRegs.sp

    // Store guest PC = x30 (return address from trampoline, in our x30).
    str x30, [x16, #256]         // PtRegs.pc

    // Store pstate = 0 (we don't have direct access to guest PSTATE from
    // userspace trampoline; the signal handler path fills it properly).
    str xzr, [x16, #264]         // PtRegs.pstate

    // Switch to host stack. Reload TCB from stack (x18 is unreliable).
    ldr x17, [sp, #40]           // x17 = TCB (reload)
    ldr x0, [x17, #8]            // x0 = TCB.host_sp
    mov sp, x0

    // Call syscall_handler. x0 = thread_ctx (on host stack).
    ldr x0, [sp]
    bl {syscall_handler}
    // If syscall_handler returns, the thread is done.
    b .Ldone_aarch64

80:
    // Host code passthrough: in_guest == 0, NOT a guest syscall.
    // The gate has already saved x16, x17, x30 to the 48-byte frame
    // at [SP+0], [SP+8], [SP+16].

    // Stash return-after-SVC address in a free slot.
    str x30, [sp, #24]

    // Restore original x16 (syscall number), x17, and x30.
    ldp x16, x17, [sp]
    ldr x30, [sp, #16]

    // Execute the real SVC.
    svc #0x80

    // Load return-after-SVC address and return.
    ldr x16, [sp, #24]
    add sp, sp, #48
    br x16
    .cfi_endproc

    .globl _exception_callback
_exception_callback:
    .cfi_startproc
    // x9  = host_tls (TCB pointer), from ucontext x[9] set by set_signal_return.
    // x1  = trapno  (from ucontext x[1])
    // x2  = error   (from ucontext x[2])
    // x3  = cr2     (from ucontext x[3])
    // Do NOT write TPIDR_EL0 — macOS system libraries use it for per-CPU data.

    // Restore host stack from TCB.
    ldr x10, [x9, #8]
    mov sp, x10

    ldr x0, [sp]                  // thread_ctx (x1-x3 preserved as args 2-4)
    bl {exception_handler}
    b .Ldone_aarch64
    .cfi_endproc

    .globl _interrupt_callback
_interrupt_callback:
    .cfi_startproc
    // x9 = host_tls (TCB pointer), passed via ucontext x[9] by set_signal_return.
    // Do NOT write TPIDR_EL0 — macOS system libraries use it for per-CPU data.
    // Restore host stack from TCB.
    ldr x10, [x9, #8]
    mov sp, x10

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
unsafe extern "C" fn switch_to_guest(
    ctx: &litebox_common_linux::PtRegs,
    tcb: *mut ThreadControlBlock,
) -> ! {
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
        //
        // IMPORTANT: We use x1 (the TCB argument) throughout the setup
        // phase instead of x18. XNU zeros x18 on EVERY kernel→userspace
        // transition — not just signal delivery, but also preemptive
        // context switches (timeslice expiry). Using x18 as TCB pointer
        // across multiple instructions creates a race where preemption
        // between any two instructions leaves x18=0, crashing on the
        // next TCB dereference. x1 is a normal callee-saved-by-kernel
        // register that survives context switches.
        "mov w16, #1",
        "strb w16, [x1, #32]",
        "ldrb w17, [x1, #33]",
        "cbnz w17, 2f",
        // === Full register restore including x16, x17, x18 ===
        //
        // On macOS, edge-page faults (W^X toggles) interrupt the guest at
        // arbitrary points and resume through this path. Unlike the SVC
        // path (where the trampoline saves/restores x16/x17), the signal
        // handler path needs ALL registers restored exactly.
        //
        // The guest is a Linux ARM64 binary where x18 is a normal
        // caller-saved register (not platform-reserved like on macOS).
        // However, x18 is fully virtualized by the rewriter: every
        // guest instruction referencing x18 goes through gates that
        // read/write TCB.guest_x18 in memory, never the physical
        // register. Therefore we do NOT restore physical x18 here —
        // it would be immediately zeroed by XNU on the next
        // kernel→userspace transition anyway.
        //
        // Strategy: stash guest_tpidr and guest_PC below the guest SP
        // (ARM64 red zone). Restore x0-x17, x19-x30 from PtRegs.
        // After setting SP, use x16 as scratch to set TPIDR, then
        // load guest_PC into x16 and branch.

        // Stash guest values below guest SP (ARM64 red zone).
        //
        // We stash guest_x0, guest_x1, guest_tpidr, and guest_PC
        // below the guest SP so we can restore them AFTER setting SP.  This
        // avoids using x18 as a temp register — XNU zeros x18 on EVERY
        // kernel→userspace transition (preemptive context switches, not just
        // signals), so holding guest SP in x18 across even 2 instructions
        // creates a race where preemption leaves SP=0.
        //
        // x1 = TCB pointer (function arg, survives preemption).
        // Stash layout below guest SP:
        //   [SP - 32] = guest_pstate
        //   [SP - 24] = guest_x0
        //   [SP - 16] = guest_x1
        //   [SP - 8]  = guest_PC
        "ldr x17, [x0, #248]",  // x17 = guest SP
        "ldr x16, [x0, #0]",    // x16 = guest x0
        "str x16, [x17, #-24]", // guest_SP[-24] = guest_x0
        "ldr x16, [x0, #8]",    // x16 = guest x1
        "str x16, [x17, #-16]", // guest_SP[-16] = guest_x1
        "ldr x16, [x0, #256]",  // x16 = guest PC
        "str x16, [x17, #-8]",  // guest_SP[-8] = guest PC
        "ldr x16, [x0, #264]",  // x16 = guest pstate
        "str x16, [x17, #-32]", // guest_SP[-32] = guest pstate
        // Restore guest x2-x17 from PtRegs (x0 still holds ctx pointer).
        "ldp x2,  x3,  [x0, #16]",
        "ldp x4,  x5,  [x0, #32]",
        "ldp x6,  x7,  [x0, #48]",
        "ldp x8,  x9,  [x0, #64]",
        "ldp x10, x11, [x0, #80]",
        "ldp x12, x13, [x0, #96]",
        "ldp x14, x15, [x0, #112]",
        "ldp x16, x17, [x0, #128]", // restore guest x16, x17
        // Restore x19-x30.
        "ldp x19, x20, [x0, #152]",
        "ldp x21, x22, [x0, #168]",
        "ldp x23, x24, [x0, #184]",
        "ldp x25, x26, [x0, #200]",
        "ldp x27, x28, [x0, #216]",
        "ldr x29, [x0, #232]",
        "ldr x30, [x0, #240]", // guest LR
        // Set guest SP.  Use x1 as temp (survives preemption, unlike x18).
        // x0 is still the PtRegs pointer here — we haven't restored guest
        // x0/x1 yet; they'll come from the stash below SP.
        "ldr x1, [x0, #248]", // x1 = guest SP (temp)
        "mov sp, x1",         // SP = guest SP (safe: x1 survives preemption)
        // Final switch: recover stashed values from below guest SP.
        // Use x16 as scratch (it will hold guest_PC for the final BR).
        "ldur x16, [sp, #-8]",  // x16 = guest PC
        "ldur x1,  [sp, #-16]", // x1 = guest x1 (from stash)
        "ldur x0,  [sp, #-32]", // x0 = guest pstate (temp)
        "msr NZCV, x0",         // restore condition flags
        "ldur x0,  [sp, #-24]", // x0 = guest x0 (from stash)
        "br x16",               // jump to guest
        // Local trampoline for cbnz — macOS assembler rejects conditional
        // branches to non-assembler-local labels (only numbered labels qualify).
        // Pass TCB (still in x1) to interrupt_callback via x9.
        // We do NOT use x18 because XNU may have zeroed it via preemption
        // between the cbnz check and this point.
        "2: mov x9, x1",
        "b _interrupt_callback",
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
    // Register a temporary TLS entry before any heap operations.
    //
    // `init_thread.init()` drops the old Box (calling `free`) and allocates
    // a new one (`malloc`).  Both go through the shared cache, whose SVC
    // stubs are patched to jump through the litebox gate.  The gate's
    // trampoline looks up the TCB via the TLS table keyed by TPIDRRO_EL0.
    // Without an entry, the trampoline loads a garbage pointer and crashes.
    //
    // We create a stack-allocated TCB with `in_guest = 0` and register it
    // in the TLS table.  The gate's host-passthrough path will then
    // correctly forward SVCs to the real kernel.  `run_thread_inner` later
    // replaces this with a heap-allocated TCB.
    let mut temp_tcb = ThreadControlBlock::default();
    TCB_PTR.set(&raw mut temp_tcb);
    update_host_tls_entry();

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
            // Use try_with to tolerate TLS destruction in forked children.
            // After fork(), Rust TLS may already be torn down; panicking
            // here would abort the child before it can _exit().
            let _ = CURRENT_THREAD.try_with(|cell| {
                if let Some(current) = cell.borrow_mut().take() {
                    *current.0.lock().unwrap() = None;
                }
            });
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

        // __ulock_wait treats timeout_us=0 as "no timeout" (infinite wait).
        // If a finite timeout was requested but rounds to 0μs, report an
        // immediate timeout instead of waiting forever.
        if timeout.is_some() && timeout_us == 0 {
            return Ok(UnblockedOrTimedOut::TimedOut);
        }

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
        // macOS utun requires a 4-byte address family header before the IP packet.
        // Detect IP version from the first nibble of the packet.
        let af: u32 = if !packet.is_empty() && (packet[0] >> 4) == 6 {
            libc::AF_INET6 as u32
        } else {
            libc::AF_INET as u32
        };
        let header = af.to_be_bytes();
        let iov = [
            libc::iovec {
                iov_base: header.as_ptr() as *mut libc::c_void,
                iov_len: header.len(),
            },
            libc::iovec {
                iov_base: packet.as_ptr() as *mut libc::c_void,
                iov_len: packet.len(),
            },
        ];
        let msg = libc::msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iov.as_ptr().cast_mut(),
            msg_iovlen: i32::try_from(iov.len()).unwrap(),
            msg_control: core::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let n = unsafe { libc::sendmsg(tun_socket_fd.as_raw_fd(), &raw const msg, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                // ENOBUFS / EAGAIN / EWOULDBLOCK: the utun socket's send buffer is full.
                // Drop the packet — smoltcp will handle retransmission via TCP.
                #[allow(unreachable_patterns, reason = "EAGAIN == EWOULDBLOCK")]
                Some(libc::ENOBUFS | libc::EAGAIN | libc::EWOULDBLOCK) => {
                    return Ok(());
                }
                _ => unimplemented!("unexpected error {err}"),
            }
        }
        let n = usize::try_from(n).unwrap();
        let expected = 4 + packet.len();
        if n != expected {
            unimplemented!("unexpected size {n}, expected {expected}")
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
        // Read into a buffer with space for the 4-byte utun address family header.
        let mut header = [0u8; 4];
        let mut iov = [
            libc::iovec {
                iov_base: header.as_mut_ptr().cast(),
                iov_len: header.len(),
            },
            libc::iovec {
                iov_base: packet.as_mut_ptr().cast(),
                iov_len: packet.len(),
            },
        ];
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = i32::try_from(iov.len()).unwrap();
        let n = unsafe { libc::recvmsg(tun_socket_fd.as_raw_fd(), &raw mut msg, 0) };
        if n < 0 {
            return Err(match std::io::Error::last_os_error().raw_os_error() {
                #[allow(unreachable_patterns, reason = "EAGAIN == EWOULDBLOCK")]
                Some(libc::EWOULDBLOCK | libc::EAGAIN) => {
                    litebox::platform::ReceiveError::WouldBlock
                }
                _ => unimplemented!("unexpected error {}", std::io::Error::last_os_error()),
            });
        }
        let n = usize::try_from(n).unwrap();
        // Strip the 4-byte header; return only the IP packet length.
        if n < 4 {
            unimplemented!("utun read returned only {n} bytes, expected at least 4")
        }
        let ip_len = n - 4;
        Ok(ip_len)
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
        // Use raw SVC write to bypass the patched shared cache gate.
        // After install_shared_cache, libc::write goes through the gate →
        // syscall_handler → handle_syscall_request → log_unsupported! →
        // debug_log_print → libc::write → gate (infinite recursion → SIGKILL).
        raw_debug_write(msg.as_bytes());
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
/// Check whether the given host address range is entirely unmapped.
///
/// Currently unused — the VMA layer handles conflict detection, but this
/// function is retained for diagnostic/debugging purposes.
#[allow(dead_code)]
#[allow(clippy::cast_possible_truncation)]
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
/// - `MAP_FIXED_NOREPLACE` is **not** translated here — callers use `MAP_FIXED`
///   directly, relying on the VMem VMA layer for conflict detection.
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
    // MAP_FIXED_NOREPLACE: NOT translated here. Callers use MAP_FIXED directly;
    // the VMem VMA layer handles conflict detection.
    //
    // MAP_GROWSDOWN and MAP_POPULATE have no macOS equivalent — silently drop.
    result
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for MacosUserland {
    // macOS arm64 enforces a 4GB __PAGEZERO segment (0x0..0x100000000).
    // Any mmap(MAP_FIXED) at addresses below 4GB fails with ENOMEM.
    // ET_EXEC (non-PIE) binaries with load addresses below 4GB are therefore
    // unsupported on macOS arm64. Only ET_DYN (PIE) binaries are supported.
    const TASK_ADDR_MIN: usize = 0x1_0000_0000; // 4GB — above __PAGEZERO
    const TASK_ADDR_MAX: usize = 0x0000_FFFF_FFFF_F000; // 48-bit VA space

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        _populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        // macOS arm64 requires 16KB-aligned addresses for all VM operations.
        // For Hint, pass the address as-is; the kernel picks a properly aligned one.
        //
        // For MAP_FIXED within a reserved region (the common case during ELF loading),
        // we must avoid clobbering adjacent 4KB sub-pages that share the same 16KB
        // host page. Two adjacent ELF LOAD segments (e.g., R+X text ending at 0x42000
        // and RW data starting at 0x3e000) may be separated by less than 16KB. A naive
        // outward-rounded mmap(MAP_FIXED) for one segment would replace the other's
        // host page with fresh anonymous memory, destroying its contents.
        //
        // Strategy for MAP_FIXED:
        // 1. mmap(MAP_FIXED, MAP_ANON) only the 16KB-aligned INTERIOR (round inward).
        //    This gives fresh anonymous pages without touching neighbors.
        // 2. mprotect the EDGE host pages (the partial 16KB pages at start/end) to the
        //    requested permissions. These pages already exist from the enclosing reserve
        //    (as PROT_NONE) or from a prior mapping. mprotect changes permissions
        //    without replacing the underlying memory.
        //
        // This ensures that data written to adjacent 4KB sub-pages within the same
        // 16KB host page is preserved.
        match fixed_address_behavior {
            FixedAddressBehavior::Hint => {
                let size = suggested_range.len();
                let prot = prot_flags(initial_permissions).bits();
                let linux_flags = MapFlags::MAP_PRIVATE
                    | MapFlags::MAP_ANONYMOUS
                    | if can_grow_down {
                        MapFlags::MAP_GROWSDOWN
                    } else {
                        MapFlags::empty()
                    };
                // No MAP_JIT — we follow strict W^X. Edge pages use
                // fault-and-toggle instead (see exception_signal_handler).
                let native_flags = macos_mmap_flags(linux_flags);

                // Attempt 1: mmap with the suggested hint address.
                let r = unsafe {
                    libc::mmap(
                        suggested_range.start as *mut libc::c_void,
                        size,
                        prot,
                        native_flags,
                        -1,
                        0,
                    )
                };
                if r != libc::MAP_FAILED {
                    return Ok(UserMutPtr::from_usize(r as usize));
                }
                let errno1 = std::io::Error::last_os_error();

                // Attempt 2: mmap with NULL hint — let the kernel choose freely.
                // On macOS, CONFIG_MAP_RANGES may confine anonymous mmap to a
                // specific heap range.  A NULL hint lets the kernel search that
                // range from its start.
                let r =
                    unsafe { libc::mmap(core::ptr::null_mut(), size, prot, native_flags, -1, 0) };
                if r != libc::MAP_FAILED {
                    return Ok(UserMutPtr::from_usize(r as usize));
                }
                let errno2 = std::io::Error::last_os_error();

                // Attempt 3: mach_vm_allocate at the Mach VM layer.
                // This bypasses the BSD mmap layer and its CONFIG_MAP_RANGES
                // routing.  mach_vm_allocate with VM_FLAGS_ANYWHERE asks the
                // kernel to place the allocation at any available address.
                // The memory is created with VM_PROT_DEFAULT (RW).  We then
                // mprotect to the desired permissions.
                let mut address: u64 = 0;
                let kr = unsafe {
                    mach_vm_allocate(
                        mach_task_self(),
                        &raw mut address,
                        size as u64,
                        VM_FLAGS_ANYWHERE,
                    )
                };
                if kr == KERN_SUCCESS {
                    #[allow(clippy::cast_possible_truncation)] // aarch64-only: always 64-bit
                    let addr = address as usize;
                    // mach_vm_allocate gives RW pages.  Set the requested
                    // protection (often PROT_NONE for address space reservations).
                    if prot != (libc::PROT_READ | libc::PROT_WRITE) {
                        let mprotect_ret =
                            unsafe { libc::mprotect(addr as *mut libc::c_void, size, prot) };
                        if mprotect_ret != 0 {
                            // mprotect failed — clean up and fall through to error.
                            unsafe {
                                mach_vm_deallocate(mach_task_self(), address, size as u64);
                            }
                            return Err(litebox::platform::page_mgmt::AllocationError::OutOfMemory);
                        }
                    }
                    return Ok(UserMutPtr::from_usize(addr));
                }

                // All attempts exhausted.  Log diagnostics for debugging.
                eprintln!(
                    "[allocate_pages] all 3 attempts failed for size={:#x} prot={}: \
                     mmap(hint={:#x})={}, mmap(NULL)={}, mach_vm_allocate kr={}",
                    size, prot, suggested_range.start, errno1, errno2, kr,
                );
                Err(litebox::platform::page_mgmt::AllocationError::OutOfMemory)
            }
            FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace => {
                if fixed_address_behavior == FixedAddressBehavior::Replace {
                    clear_edge_page_mapping(suggested_range.clone());
                }

                let outer_start = host_page_align_down(suggested_range.start);
                let outer_end = host_page_align_up(suggested_range.end);
                let inner_start = host_page_align_up(suggested_range.start);
                let inner_end = host_page_align_down(suggested_range.end);
                let prot = prot_flags(initial_permissions).bits();
                // Edge host pages use RW because allocate_pages callers need to
                // write content (e.g., ELF segment data). If guest later executes
                // code on an edge page, the fault-and-toggle handler in
                // exception_signal_handler will flip it to RX on demand.

                // Step 1: Map the 16KB-aligned interior.
                //
                // For NoReplace: use mach_vm_allocate(VM_FLAGS_FIXED) *without*
                // VM_FLAGS_OVERWRITE. This fails cleanly with KERN_NO_SPACE if
                // the region overlaps existing host mappings, without clobbering
                // anything. This is critical for set_initial_brk's gap
                // reservation, where the gap range may overlap live host memory
                // (heap, system allocator) on some machines.
                //
                // For Replace: use MAP_FIXED to atomically replace existing
                // mappings (the normal ELF segment loading path).
                if inner_start < inner_end {
                    if fixed_address_behavior == FixedAddressBehavior::NoReplace {
                        // Safe non-clobbering path for NoReplace.
                        let mut addr = inner_start as u64;
                        let size = (inner_end - inner_start) as u64;
                        let kr = unsafe {
                            mach_vm_allocate(
                                mach_task_self(),
                                &raw mut addr,
                                size,
                                VM_FLAGS_FIXED,
                            )
                        };
                        if kr != 0 {
                            return Err(
                                litebox::platform::page_mgmt::AllocationError::AddressInUseByPlatform,
                            );
                        }
                        // mach_vm_allocate gives RW. Set requested protection.
                        if prot != (libc::PROT_READ | libc::PROT_WRITE) {
                            let r = unsafe {
                                libc::mprotect(
                                    inner_start as *mut libc::c_void,
                                    inner_end - inner_start,
                                    prot,
                                )
                            };
                            if r != 0 {
                                unsafe {
                                    mach_vm_deallocate(
                                        mach_task_self(),
                                        inner_start as u64,
                                        size,
                                    );
                                }
                                return Err(
                                    litebox::platform::page_mgmt::AllocationError::AddressInUseByPlatform,
                                );
                            }
                        }
                    } else {
                        // Replace path: MAP_FIXED atomically replaces existing
                        // mappings with fresh anonymous memory.
                        let r = unsafe {
                            libc::mmap(
                                inner_start as *mut libc::c_void,
                                inner_end - inner_start,
                                prot,
                                macos_mmap_flags(
                                    MapFlags::MAP_PRIVATE
                                        | MapFlags::MAP_ANONYMOUS
                                        | MapFlags::MAP_FIXED,
                                ),
                                -1,
                                0,
                            )
                        };
                        if r == libc::MAP_FAILED {
                            let err = std::io::Error::last_os_error();
                            match err.raw_os_error() {
                                Some(libc::ENOMEM) => {
                                    return Err(
                                        litebox::platform::page_mgmt::AllocationError::OutOfMemory,
                                    );
                                }
                                Some(libc::EACCES | libc::EPERM) => {
                                    // MAP_FIXED on a region owned by the platform
                                    // (e.g. the host shared cache) returns EACCES.
                                    // Fall back to mach_vm_allocate with VM_FLAGS_OVERWRITE
                                    // which can replace kernel-managed shared region mappings.
                                    let mut addr = inner_start as u64;
                                    let size = (inner_end - inner_start) as u64;
                                    let kr = unsafe {
                                        mach_vm_allocate(
                                            mach_task_self(),
                                            &raw mut addr,
                                            size,
                                            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                        )
                                    };
                                    if kr != 0 {
                                        return Err(litebox::platform::page_mgmt::AllocationError::AddressInUseByPlatform);
                                    }
                                    // mach_vm_allocate gives RW pages. Set the
                                    // requested protection.
                                    if prot != (libc::PROT_READ | libc::PROT_WRITE) {
                                        let r = unsafe {
                                            libc::mprotect(
                                                inner_start as *mut libc::c_void,
                                                inner_end - inner_start,
                                                prot,
                                            )
                                        };
                                        if r != 0 {
                                            unsafe {
                                                mach_vm_deallocate(
                                                    mach_task_self(),
                                                    inner_start as u64,
                                                    size,
                                                );
                                            }
                                            return Err(litebox::platform::page_mgmt::AllocationError::AddressInUseByPlatform);
                                        }
                                    }
                                }
                                _ => panic!("unhandled mmap error {err}"),
                            }
                        }
                    }
                }

                // Step 2: Ensure edge host pages exist with RW permissions.
                // Edge pages may still exist from the reserve or prior mapping, or
                // may have been unmapped by a prior deallocate_pages (which rounds
                // inward to 16KB). ensure_edge_page_rw handles both cases.
                //
                // We use RW because allocate_pages callers typically write content
                // (ELF segment data, anonymous zero-fill). If guest code later executes
                // on these pages, the fault-and-toggle handler flips them to RX.
                //
                // Collect distinct edge host page addresses, then handle each once.
                // Leading edge: the host page containing suggested_range.start
                // Trailing edge: the host page containing suggested_range.end - 1
                // (only if different from leading edge)
                let has_leading_edge = outer_start < inner_start;
                let has_trailing_edge = inner_end < outer_end;
                let leading_edge_addr = outer_start;
                let trailing_edge_addr =
                    host_page_align_down(suggested_range.end.saturating_sub(1));

                if has_leading_edge {
                    ensure_edge_page_rw(leading_edge_addr);
                    register_edge_page(leading_edge_addr);
                }

                if has_trailing_edge && trailing_edge_addr != leading_edge_addr {
                    ensure_edge_page_rw(trailing_edge_addr);
                    register_edge_page(trailing_edge_addr);
                }

                // If range is sub-16KB and both start and end are within a single
                // host page with the start already 16KB-aligned (no leading edge),
                // the interior is empty and no edge was handled above. Handle
                // this by ensuring the enclosing host page directly.
                if inner_start >= inner_end && !has_leading_edge && has_trailing_edge {
                    ensure_edge_page_rw(outer_start);
                    register_edge_page(outer_start);
                }

                sync_edge_page_mapping(suggested_range.clone(), initial_permissions);

                // Zero the edge sub-pages that fall within our range but outside the
                // interior mmap. The interior was freshly mmap'd as MAP_ANON (guaranteed
                // zeroed), but edge sub-pages were only mprotect'd, preserving whatever
                // stale content existed in the host page. Anonymous allocations must
                // return zeroed memory, so we explicitly zero these edge regions.
                //
                // Leading edge: [suggested_range.start .. min(inner_start, suggested_range.end))
                // Trailing edge: [max(inner_end, suggested_range.start) .. suggested_range.end)
                let leading_zero_end = inner_start.min(suggested_range.end);
                if suggested_range.start < leading_zero_end {
                    unsafe {
                        core::ptr::write_bytes(
                            suggested_range.start as *mut u8,
                            0,
                            leading_zero_end - suggested_range.start,
                        );
                    }
                }
                let trailing_zero_start = inner_end.max(suggested_range.start);
                if trailing_zero_start < suggested_range.end
                    && trailing_zero_start >= leading_zero_end
                {
                    unsafe {
                        core::ptr::write_bytes(
                            trailing_zero_start as *mut u8,
                            0,
                            suggested_range.end - trailing_zero_start,
                        );
                    }
                }

                Ok(UserMutPtr::from_usize(suggested_range.start))
            }
        }
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        clear_edge_page_mapping(range.clone());

        // Round inward to HOST_PAGE_SIZE boundaries to avoid unmapping adjacent
        // 4KB sub-pages that belong to other VMAs within the same 16KB host page.
        // Sub-16KB edge portions are left mapped (as PROT_NONE from the original
        // reserve) and will be reclaimed when the enclosing host page is fully
        // deallocated or replaced by a subsequent MAP_FIXED mmap.
        let aligned_start = host_page_align_up(range.start);
        let aligned_end = host_page_align_down(range.end);
        if aligned_start < aligned_end {
            let r = unsafe {
                libc::munmap(
                    aligned_start as *mut libc::c_void,
                    aligned_end - aligned_start,
                )
            };
            assert_eq!(r, 0, "munmap failed: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        // Allocate new range using the same edge-page-aware strategy as
        // allocate_pages: inward-rounded interior mmap + edge page mprotect.
        // This avoids clobbering neighboring sub-pages in shared 16KB host pages.
        let new_inner_start = host_page_align_up(new_range.start);
        let new_inner_end = host_page_align_down(new_range.end);
        let new_outer_start = host_page_align_down(new_range.start);
        let new_outer_end = host_page_align_up(new_range.end);

        // Step 1: mmap the 16KB-aligned interior of the new range.
        if new_inner_start < new_inner_end {
            let r = unsafe {
                libc::mmap(
                    new_inner_start as *mut libc::c_void,
                    new_inner_end - new_inner_start,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if r == libc::MAP_FAILED {
                return Err(litebox::platform::page_mgmt::RemapError::OutOfMemory);
            }
        }

        // Step 2: Ensure edge host pages of the new range exist with RW.
        let has_leading_edge = new_outer_start < new_inner_start;
        let has_trailing_edge = new_inner_end < new_outer_end;
        let leading_edge_addr = new_outer_start;
        let trailing_edge_addr = host_page_align_down(new_range.end.saturating_sub(1));

        if has_leading_edge {
            ensure_edge_page_rw(leading_edge_addr);
            register_edge_page(leading_edge_addr);
        }
        if has_trailing_edge && trailing_edge_addr != leading_edge_addr {
            ensure_edge_page_rw(trailing_edge_addr);
            register_edge_page(trailing_edge_addr);
        }
        if new_inner_start >= new_inner_end && !has_leading_edge && has_trailing_edge {
            ensure_edge_page_rw(new_outer_start);
            register_edge_page(new_outer_start);
        }

        sync_edge_page_mapping(
            new_range.clone(),
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
        );

        // Zero edge sub-pages in the new range (anonymous memory must be zeroed).
        let leading_zero_end = new_inner_start.min(new_range.end);
        if new_range.start < leading_zero_end {
            unsafe {
                core::ptr::write_bytes(
                    new_range.start as *mut u8,
                    0,
                    leading_zero_end - new_range.start,
                );
            }
        }
        let trailing_zero_start = new_inner_end.max(new_range.start);
        if trailing_zero_start < new_range.end && trailing_zero_start >= leading_zero_end {
            unsafe {
                core::ptr::write_bytes(
                    trailing_zero_start as *mut u8,
                    0,
                    new_range.end - trailing_zero_start,
                );
            }
        }

        // Step 3: Copy data from old range to new range.
        let copy_len = old_range.len().min(new_range.len());
        let dst = new_range.start as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(old_range.start as *const u8, dst, copy_len);
        }

        // Step 4: Apply final permissions if not already RW.
        if permissions != (MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE) {
            // Interior: direct mprotect with exact permissions.
            if new_inner_start < new_inner_end {
                let r = unsafe {
                    libc::mprotect(
                        new_inner_start as *mut libc::c_void,
                        new_inner_end - new_inner_start,
                        prot_flags(permissions).bits(),
                    )
                };
                if r != 0 {
                    // Cleanup: munmap only the interior we allocated.
                    if new_inner_start < new_inner_end {
                        unsafe {
                            libc::munmap(
                                new_inner_start as *mut libc::c_void,
                                new_inner_end - new_inner_start,
                            );
                        }
                    }
                    return Err(litebox::platform::page_mgmt::RemapError::OutOfMemory);
                }
            }
            // Edge pages: register them for fault-and-toggle handling if
            // the permissions include EXEC. The edge pages stay RW; the
            // signal handler will flip them to RX on demand.
        }

        // Step 5: Deallocate old range using inward rounding (same as
        // deallocate_pages) to avoid destroying neighboring sub-pages.
        clear_edge_page_mapping(old_range.clone());
        let old_aligned_start = host_page_align_up(old_range.start);
        let old_aligned_end = host_page_align_down(old_range.end);
        if old_aligned_start < old_aligned_end {
            let r = unsafe {
                libc::munmap(
                    old_aligned_start as *mut libc::c_void,
                    old_aligned_end - old_aligned_start,
                )
            };
            assert_eq!(r, 0, "munmap failed: {}", std::io::Error::last_os_error());
        }

        Ok(UserMutPtr::from_usize(new_range.start))
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        // macOS arm64 16KB page handling for mprotect:
        //
        // Multiple 4KB VMAs with different permission requirements may share the
        // same 16KB host page (e.g., an RW data segment tail and an R+X trampoline
        // starting in the same 16KB page). Since mprotect operates on whole host
        // pages, we cannot set per-4KB permissions independently.
        //
        // Strategy (W^X compliant — no RWX):
        // - Interior host pages (fully enclosed): set to exactly the requested permissions.
        // - Edge host pages (partially covered): use per-sub-page tracking to
        //   compute the correct W^X-compliant composite permission (RW or RX)
        //   based on ALL sub-pages within the 16KB host page, not just the
        //   requested permissions. This prevents a PROT_NONE request on one
        //   4KB slice from stripping EXEC from adjacent slices that still
        //   contain code.
        let outer_start = host_page_align_down(range.start);
        let outer_end = host_page_align_up(range.end);
        let inner_start = host_page_align_up(range.start);
        let inner_end = host_page_align_down(range.end);
        let prot = prot_flags(new_permissions).bits();

        // Interior: exact permissions on fully-enclosed host pages.
        if inner_start < inner_end {
            let r = unsafe {
                libc::mprotect(
                    inner_start as *mut libc::c_void,
                    inner_end - inner_start,
                    prot,
                )
            };
            if r != 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EACCES | libc::EPERM) => {
                        // mprotect fails with EACCES on host shared cache pages.
                        // Use mach_vm_allocate(VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)
                        // to claim the pages, then retry mprotect.
                        let mut addr = inner_start as u64;
                        let size = (inner_end - inner_start) as u64;
                        let kr = unsafe {
                            mach_vm_allocate(
                                mach_task_self(),
                                &raw mut addr,
                                size,
                                VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                            )
                        };
                        if kr != 0 {
                            return Err(
                                litebox::platform::page_mgmt::PermissionUpdateError::Unallocated,
                            );
                        }
                        // mach_vm_allocate gives RW pages. Set requested protection.
                        if prot != (libc::PROT_READ | libc::PROT_WRITE) {
                            let r = unsafe {
                                libc::mprotect(
                                    inner_start as *mut libc::c_void,
                                    inner_end - inner_start,
                                    prot,
                                )
                            };
                            if r != 0 {
                                // mprotect failed after allocate; deallocate and fail.
                                unsafe {
                                    mach_vm_deallocate(mach_task_self(), inner_start as u64, size);
                                }
                                return Err(
                                    litebox::platform::page_mgmt::PermissionUpdateError::Unallocated,
                                );
                            }
                        }
                    }
                    _ => {
                        // Other errors (e.g. brk zone pages not gap-reserved).
                        // Return Unallocated so callers can fall back.
                        return Err(
                            litebox::platform::page_mgmt::PermissionUpdateError::Unallocated,
                        );
                    }
                }
            }
        }

        // Edge host pages: update per-sub-page state and compute W^X composite
        // permission from ALL sub-pages in the host page. Register for
        // fault-and-toggle handling.
        let has_leading_edge = outer_start < inner_start;
        let has_trailing_edge = inner_end < outer_end;
        let leading_edge_addr = outer_start;
        let trailing_edge_addr = host_page_align_down(range.end.saturating_sub(1));

        if has_leading_edge {
            let edge_prot =
                update_edge_page_state(leading_edge_addr, range.clone(), new_permissions);
            ensure_edge_page(leading_edge_addr, edge_prot);
            register_edge_page(leading_edge_addr);
        }

        if has_trailing_edge && trailing_edge_addr != leading_edge_addr {
            let edge_prot =
                update_edge_page_state(trailing_edge_addr, range.clone(), new_permissions);
            ensure_edge_page(trailing_edge_addr, edge_prot);
            register_edge_page(trailing_edge_addr);
        }

        // If range is sub-16KB, starts at a 16KB boundary (no leading edge),
        // and the interior is empty, no mprotect has fired yet. Handle by
        // ensuring the enclosing host page directly.
        if inner_start >= inner_end && !has_leading_edge && has_trailing_edge {
            let edge_prot = update_edge_page_state(outer_start, range.clone(), new_permissions);
            ensure_edge_page(outer_start, edge_prot);
            register_edge_page(outer_start);
        }

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
        // macOS arm64 requires file offsets to be HOST_PAGE_SIZE-aligned for mmap.
        // ELF files built for Linux use 4KB alignment, which won't satisfy this.
        if !file_offset.is_multiple_of(HOST_PAGE_SIZE) {
            return Err(CowAllocationError::Unaligned);
        }
        if !file_offset.is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }
        // For MAP_FIXED operations, also require the address and length to be
        // HOST_PAGE_SIZE-aligned. If they aren't, the outward-rounded mmap would
        // replace edge host pages' content, clobbering adjacent 4KB sub-pages.
        // Fall back to the memcpy path which uses our edge-safe allocate_pages.
        if matches!(
            fixed_address_behavior,
            FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace
        ) && (!suggested_start.is_multiple_of(HOST_PAGE_SIZE)
            || !source_data.len().is_multiple_of(HOST_PAGE_SIZE))
        {
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

        // For MAP_FIXED, the address and length are guaranteed HOST_PAGE_SIZE-aligned
        // (we reject unaligned cases above). For Hint, pass as-is.
        let (mmap_start, mmap_len) = match fixed_address_behavior {
            FixedAddressBehavior::Hint => (suggested_start, source_data.len()),
            FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace => {
                // These are already 16KB-aligned; the align calls are defensive.
                let aligned_start = host_page_align_down(suggested_start);
                let aligned_end = host_page_align_up(suggested_start + source_data.len());
                (aligned_start, aligned_end - aligned_start)
            }
        };

        // NoReplace: no host-level probe needed — see comment in allocate_pages().
        // The VMem layer already verified no VMA-level conflicts.

        let mut flags = MapFlags::MAP_PRIVATE;
        match fixed_address_behavior {
            FixedAddressBehavior::Hint => {}
            FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace => {
                flags |= MapFlags::MAP_FIXED;
            }
        }

        let result = unsafe {
            libc::mmap(
                mmap_start as *mut libc::c_void,
                mmap_len,
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
            let tracked_start = match fixed_address_behavior {
                FixedAddressBehavior::Hint => result as usize,
                FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace => suggested_start,
            };
            let tracked_range = tracked_start..(tracked_start + source_data.len());
            if fixed_address_behavior == FixedAddressBehavior::Replace {
                clear_edge_page_mapping(tracked_range.clone());
            }
            sync_edge_page_mapping(tracked_range, permissions);

            // Return the original suggested_start for fixed-address operations so
            // the VMem layer's 4KB bookkeeping is consistent, even though the
            // kernel mapped a wider 16KB-aligned region.
            match fixed_address_behavior {
                FixedAddressBehavior::Hint => Ok(UserMutPtr::from_usize(result as usize)),
                FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace => {
                    Ok(UserMutPtr::from_usize(suggested_start))
                }
            }
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
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.init(ctx));
}

unsafe extern "C-unwind" fn reenter_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.reenter(ctx));
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
    // Intercept sigreturn (BSD 184) when called from _sigtramp.
    //
    // When a host signal handler (exception_signal_handler, etc.) is invoked
    // while the guest is running, the handler modifies the ucontext via
    // set_signal_return() to redirect sigreturn to exception_callback /
    // interrupt_callback. The signal handler then returns to _sigtramp,
    // which calls __sigreturn (in libsystem_kernel). But __sigreturn's SVC
    // has been patched by install_shared_cache, so the gate intercepts it
    // as a guest syscall.
    //
    // We detect this case by checking if the caller's LR points into
    // _sigtramp. When it does, we execute a raw SVC to pass the sigreturn
    // through to the host kernel, which restores the modified context and
    // jumps to the appropriate callback.
    //
    // NOTE: this raw SVC does NOT return — the kernel replaces the entire
    // CPU context, effectively longjmp-ing to the callback.
    {
        let nr = thread_ctx.ctx.regs[16];
        // BSD sigreturn = 184 or 0x20000B8 (depending on the stub).
        // The gate preserves x16 as-is from the SVC caller.
        let is_sigreturn = nr == 184 || nr == 0x2000_00B8;
        if is_sigreturn {
            let lr = thread_ctx.ctx.regs[30];
            let sigtramp = get_sigtramp_addr();

            // _sigtramp is typically ~100 bytes; use 256 for safety.
            if sigtramp != 0 && lr >= sigtramp && lr < sigtramp + 256 {
                let uctx = thread_ctx.ctx.regs[0];

                // Read the target PC and parameters from the ucontext.
                // set_signal_return() wrote: pc=callback, x[0]=p0, x[1]=trapno,
                // x[2]=err, x[3]=cr2, x[9]=host_tls.
                //
                // On macOS arm64:
                //   uc_mcontext is at offset 48 in ucontext_t.
                //   mcontext.__es = 16 bytes (__far:u64, __esr:u32, __exception:u32)
                //   mcontext.__ss.__x[i] at offset 16 + i*8
                //   mcontext.__ss.__pc at offset 16 + 29*8 + 8 + 8 + 8 = 272
                let mctx_ptr = unsafe { core::ptr::read_volatile((uctx as *const usize).add(6)) }; // offset 48

                if mctx_ptr != 0 {
                    let mctx = mctx_ptr as *const u64;
                    #[allow(clippy::cast_possible_truncation)]
                    let target_pc = unsafe { core::ptr::read_volatile(mctx.add(272 / 8)) } as usize;
                    #[allow(clippy::cast_possible_truncation)]
                    let x1_val = unsafe { core::ptr::read_volatile(mctx.add(3)) } as usize; // trapno: offset (16+8)/8=3
                    #[allow(clippy::cast_possible_truncation)]
                    let x2_val = unsafe { core::ptr::read_volatile(mctx.add(4)) } as usize; // error: offset (16+16)/8=4
                    #[allow(clippy::cast_possible_truncation)]
                    let x3_val = unsafe { core::ptr::read_volatile(mctx.add(5)) } as usize; // cr2: offset (16+24)/8=5

                    // Ensure that `run_thread_arch` is linked in.
                    let _ = run_thread_arch as *const () as usize;

                    let exc_cb = exception_callback as *const () as usize;
                    let int_cb = interrupt_callback as *const () as usize;

                    if target_pc == exc_cb {
                        exception_handler(thread_ctx, x1_val, x2_val, x3_val);
                        return;
                    } else if target_pc == int_cb {
                        interrupt_handler(thread_ctx);
                        return;
                    }

                }
            }
        }
    }
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.syscall(ctx));
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
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.exception(ctx, &info));
}

/// Update the TLS lookup table with the current thread's entry.
///
/// Called before entering guest code on aarch64. The trampoline's shared
/// handlers use this table to find the host TLS (TCB) base on SVC/x18/MRS/MSR entry.
///
/// Uses linear scan to match the trampoline's assembly lookup.
/// Entry format: `[key: u64, host_tls: u64]` (16 bytes per entry).
/// Key is TPIDRRO_EL0 on macOS. Sentinel `0xFFFF_FFFF_FFFF_FFFF` marks
/// the end of valid entries. Tombstone `0` marks freed slots that can be
/// reclaimed.
///
/// Thread-safety: claiming a free slot (sentinel or tombstone) uses
/// `AtomicU64::compare_exchange` (CAS) so that two concurrent threads
/// cannot claim the same slot. On CAS failure, the scan retries from
/// the beginning.
const TLS_TABLE_ENTRIES: usize = 256;
const TLS_TABLE_SENTINEL: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Register (or update) the current host thread in the TLS lookup table.
///
/// Must be called after a new TLS table is allocated and the trampoline
/// headers are updated (e.g. after execve re-creates the TLS table),
/// so that subsequent libc calls through patched shared-cache SVCs can
/// find this thread's TCB via the TPIDRRO_EL0 key.
///
/// Returns silently if no TLS table is allocated or if the current
/// thread has no TCB (e.g. during first exec before `run_thread`).
///
/// # Panics
///
/// Panics if the TLS table is full (more than 256 concurrent threads).
pub fn update_host_tls_entry() {
    use core::sync::atomic::{AtomicU64, Ordering};

    let table_addr = litebox_common_linux::HOST_TLS_TABLE_ADDR.load(Ordering::Acquire);
    if table_addr == 0 {
        return; // No TLS table allocated (not using rewriter-based trampoline)
    }

    let tcb = TCB_PTR.get();
    if tcb.is_null() {
        return; // No TCB yet (first exec, before run_thread)
    }
    let host_tls = tcb as usize;

    // TPIDRRO_EL0 is the lookup key — stable per-pthread, never clobbered.
    let tpidrro = unsafe { litebox_common_linux::read_tpidrro_el0() } as u64;

    'retry: loop {
        let mut first_free: Option<usize> = None;

        for index in 0..TLS_TABLE_ENTRIES {
            let key_ptr = unsafe { &*((table_addr + index * 16) as *const AtomicU64) };

            let stored_key = key_ptr.load(Ordering::Acquire);

            if stored_key == tpidrro {
                // Found our entry — update host_tls in case it changed.
                let val_ptr = (table_addr + index * 16 + 8) as *mut u64;
                unsafe { val_ptr.write_volatile(host_tls as u64) };
                return;
            }

            if stored_key == TLS_TABLE_SENTINEL {
                // End of table — no existing entry for our TPIDRRO_EL0.
                if first_free.is_none() {
                    first_free = Some(index);
                }
                break;
            }

            // Tombstone (key=0): freed by remove_host_tls_entries.
            // Remember as candidate but keep scanning for existing entry.
            if stored_key == 0 && first_free.is_none() {
                first_free = Some(index);
            }
        }

        // Claim the first free slot (tombstone or sentinel) via CAS.
        let free_index = first_free.expect("TLS table full: exceeded 256 concurrent threads");
        let key_ptr = unsafe { &*((table_addr + free_index * 16) as *const AtomicU64) };
        let val_ptr = (table_addr + free_index * 16 + 8) as *mut u64;

        // Re-read the key — it may have changed since our scan.
        let current = key_ptr.load(Ordering::Acquire);

        // Only try CAS on sentinel or tombstone slots.
        if current != TLS_TABLE_SENTINEL && current != 0 {
            // Slot was claimed by another thread. Rescan.
            continue 'retry;
        }

        if key_ptr
            .compare_exchange(current, tpidrro, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Claimed. Write host_tls value.
            unsafe { val_ptr.write_volatile(host_tls as u64) };
            return;
        }
        // CAS failed — another thread grabbed this slot. Rescan.
    }
}

/// Remove the current thread's TLS table entry by writing a tombstone (key=0).
///
/// Called when a thread exits `run_thread_inner` to prevent stale entries
/// from accumulating in the table. Without cleanup, the 256-entry table
/// would eventually fill up for long-running programs that create many
/// cumulative threads.
///
/// Uses tombstone value 0 (not sentinel) so that entries at higher indices
/// remain reachable by the assembly linear scan. The assembly scanner only
/// stops at sentinel (0xFFFF_FFFF_FFFF_FFFF), not at tombstones.
///
/// Only the owning thread calls this for its own TPIDRRO_EL0 key,
/// so there is no race on the entry being removed.
#[allow(dead_code)]
fn remove_host_tls_entries() {
    use core::sync::atomic::{AtomicU64, Ordering};

    let table_addr = litebox_common_linux::HOST_TLS_TABLE_ADDR.load(Ordering::Acquire);
    if table_addr == 0 {
        return;
    }

    let tpidrro = unsafe { litebox_common_linux::read_tpidrro_el0() } as u64;

    for index in 0..TLS_TABLE_ENTRIES {
        let key_ptr = unsafe { &*((table_addr + index * 16) as *const AtomicU64) };

        let stored_key = key_ptr.load(Ordering::Acquire);

        if stored_key == tpidrro {
            // Found our entry — replace key with sentinel to free the slot.
            // The assembly scanner will see this as end-of-table and stop,
            // but entries beyond it are still valid (they were written with
            // higher indices). This creates a "hole" in the table.
            //
            // The hole is harmless: update_host_tls_entry scans past
            // sentinels... wait, no — the assembly scanner stops at the
            // first sentinel. So we cannot just write a sentinel here
            // without compacting.
            //
            // Instead, we use a tombstone approach: write 0 as the key.
            // The value 0 is not a valid TPIDRRO_EL0 (macOS always sets
            // it to the pthread TSD base, which is a high userspace address).
            // The assembly scanner will see key=0, which won't match any
            // thread's TPIDRRO_EL0, and will continue scanning past it
            // (it only stops at sentinel 0xFFFF_FFFF_FFFF_FFFF).
            //
            // update_host_tls_entry will also scan past tombstones (key=0)
            // and can reclaim them via CAS when claiming a new slot.
            key_ptr.store(0, Ordering::Release);
            return;
        }

        if stored_key == TLS_TABLE_SENTINEL {
            // Reached end of table without finding our entry. This can
            // happen if the thread never successfully claimed a slot
            // (e.g., table was full, or thread exited before entering guest).
            return;
        }
    }
}

extern "C-unwind" fn interrupt_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx, interrupt| {
        if interrupt {
            shim.interrupt(ctx)
        } else {
            // We got here just to restore TPIDR_EL0 (e.g., after an edge-page
            // toggle), so don't bother the shim. Matches the Windows platform's
            // approach to FS base restoration.
            ContinueOperation::Resume
        }
    });
}

/// Calls `f` in order to call into a shim entrypoint.
impl ThreadContext<'_> {
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
            &mut litebox_common_linux::PtRegs,
            bool,
        ) -> ContinueOperation,
    ) {
        // Clear the interrupt flag before calling the shim, since we've handled it
        // now (by calling into the shim), and it might be set again by the shim
        // before returning.
        let tcb = TCB_PTR.get();
        assert!(!tcb.is_null(), "call_shim called without TCB");
        let interrupt = unsafe { (*tcb).interrupt != 0 };
        unsafe {
            (*tcb).interrupt = 0;
        }
        let op = f(self.shim, self.ctx, interrupt);
        match op {
            ContinueOperation::Resume => {
                update_host_tls_entry();

                // Pass TCB explicitly to switch_to_guest.  Do NOT write
                // TPIDR_EL0 here — macOS system libraries use it for
                // per-CPU data and corrupting it crashes malloc.
                // switch_to_guest sets the guest's virtual TPIDR_EL0
                // from TCB.guest_tpidr just before branching into guest
                // code.
                let tcb = TCB_PTR.get();
                unsafe { switch_to_guest(self.ctx, tcb) }
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
        // On macOS, this may be called outside run_thread_inner (e.g. during
        // execve handling) when no TCB is active. In that case, guest_tpidr
        // is already zero (default), so this is a no-op.
        let tcb = TCB_PTR.get();
        if !tcb.is_null() {
            unsafe { (*tcb).guest_tpidr = 0 };
        }
    }
}

static mut NEXT_SA: [libc::sigaction; 64] = unsafe { core::mem::zeroed() };
static INTERRUPT_SIGNAL_NUMBER: AtomicI32 = AtomicI32::new(0);

// ---------------------------------------------------------------------------
// Raw host syscall helpers
//
// After `install_shared_cache` patches all SVC sites in the shared cache,
// every `libc::*` function that issues a syscall goes through the litebox
// gate → `syscall_callback` → shim dispatcher.  The shim handles these as
// *guest* syscalls (virtual mmap, virtual sigaction, etc.), which is wrong
// for host-side operations such as signal handler registration and alt-stack
// setup.
//
// The helpers below issue the real macOS BSD SVC directly via inline assembly,
// bypassing the patched gate entirely.
// ---------------------------------------------------------------------------

/// macOS BSD syscall numbers.
const RAW_SYS_SIGACTION: u64 = 46;
const RAW_SYS_SIGALTSTACK: u64 = 53;
const RAW_SYS_MUNMAP: u64 = 73;
const RAW_SYS_MPROTECT: u64 = 74;
const RAW_SYS_WRITE: u64 = 4;
const RAW_SYS_MMAP: u64 = 197;

/// Raw `write(fd, buf, len)` via inline assembly.
///
/// Bypasses the patched shared cache gate entirely — safe to call from
/// `syscall_handler` and other host-side code after `install_shared_cache`.
fn raw_debug_write(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    unsafe {
        core::arch::asm!(
            "mov x0, #2",            // fd = stderr
            "mov x1, {buf}",
            "mov x2, {len}",
            "mov x16, {nr}",
            "svc #0x80",
            buf = in(reg) buf.as_ptr(),
            len = in(reg) buf.len(),
            nr = in(reg) RAW_SYS_WRITE | (0x200_0000u64),
            out("x0") _,
            out("x1") _,
            out("x2") _,
            out("x16") _,
            clobber_abi("C"),
        );
    }
}

/// Raw `mmap(addr, len, prot, flags, fd, offset)` via inline assembly.
///
/// Returns the mapped address on success, or a negative errno on failure.
///
/// # Safety
///
/// Caller must ensure arguments are valid for the mmap syscall.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_arguments
)]
unsafe fn raw_host_mmap(
    addr: usize,
    len: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> Result<usize, i32> {
    let ret: u64;
    let err_flag: u64;
    unsafe {
        core::arch::asm!(
            "mov x16, {syscall_nr}",
            "svc #0x80",
            "cset {err}, cs",
            syscall_nr = in(reg) RAW_SYS_MMAP,
            in("x0") addr as u64,
            in("x1") len as u64,
            in("x2") prot as u64,
            in("x3") flags as u64,
            in("x4") fd as u64,
            in("x5") offset as u64,
            err = out(reg) err_flag,
            lateout("x0") ret,
            out("x16") _,
        );
    }
    if err_flag != 0 {
        Err(ret as i32)
    } else {
        Ok(ret as usize)
    }
}

/// Raw `munmap(addr, len)` via inline assembly.
///
/// # Safety
///
/// Caller must ensure arguments are valid for the munmap syscall.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
unsafe fn raw_host_munmap(addr: usize, len: usize) -> Result<(), i32> {
    let ret: u64;
    let err_flag: u64;
    unsafe {
        core::arch::asm!(
            "mov x16, {syscall_nr}",
            "svc #0x80",
            "cset {err}, cs",
            syscall_nr = in(reg) RAW_SYS_MUNMAP,
            in("x0") addr as u64,
            in("x1") len as u64,
            err = out(reg) err_flag,
            lateout("x0") ret,
            out("x16") _,
        );
    }
    if err_flag != 0 {
        Err(ret as i32)
    } else {
        Ok(())
    }
}

/// Raw `mprotect(addr, len, prot)` via inline assembly.
///
/// # Safety
///
/// Caller must ensure arguments are valid for the mprotect syscall.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
unsafe fn raw_host_mprotect(addr: usize, len: usize, prot: i32) -> Result<(), i32> {
    let ret: u64;
    let err_flag: u64;
    unsafe {
        core::arch::asm!(
            "mov x16, {syscall_nr}",
            "svc #0x80",
            "cset {err}, cs",
            syscall_nr = in(reg) RAW_SYS_MPROTECT,
            in("x0") addr as u64,
            in("x1") len as u64,
            in("x2") prot as u64,
            err = out(reg) err_flag,
            lateout("x0") ret,
            out("x16") _,
        );
    }
    if err_flag != 0 {
        Err(ret as i32)
    } else {
        Ok(())
    }
}

/// Raw `__sigaction(signum, nact, oact)` via inline assembly.
///
/// `nact` points to a 24-byte `struct __sigaction` (kernel ABI):
///   `[0..8]  sa_handler/sa_sigaction`
///   `[8..16] sa_tramp (_sigtramp)`
///   `[16..20] sa_mask`
///   `[20..24] sa_flags`
///
/// `oact` points to a 16-byte `struct sigaction` (userspace ABI):
///   `[0..8]  sa_handler/sa_sigaction`
///   `[8..12] sa_mask`
///   `[12..16] sa_flags`
///
/// # Safety
///
/// Caller must ensure `nact` and `oact` point to valid memory with the
/// correct sizes.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
unsafe fn raw_host_sigaction(signum: i32, nact: *const u8, oact: *mut u8) -> Result<(), i32> {
    let ret: u64;
    let err_flag: u64;
    unsafe {
        core::arch::asm!(
            "mov x16, {syscall_nr}",
            "svc #0x80",
            "cset {err}, cs",
            syscall_nr = in(reg) RAW_SYS_SIGACTION,
            in("x0") signum as u64,
            in("x1") nact as u64,
            in("x2") oact as u64,
            err = out(reg) err_flag,
            lateout("x0") ret,
            out("x16") _,
        );
    }
    if err_flag != 0 {
        Err(ret as i32)
    } else {
        Ok(())
    }
}

/// Raw `sigaltstack(ss, oss)` via inline assembly.
///
/// Both `ss` and `oss` point to `struct stack_t` (24 bytes on macOS aarch64):
///   `[0..8]  ss_sp`
///   `[8..16] ss_size`
///   `[16..20] ss_flags` (+ 4 bytes padding)
///
/// Either pointer may be null.
///
/// # Safety
///
/// Caller must ensure pointers (if non-null) point to valid `stack_t` structs.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
unsafe fn raw_host_sigaltstack(
    ss: *const libc::stack_t,
    oss: *mut libc::stack_t,
) -> Result<(), i32> {
    let ret: u64;
    let err_flag: u64;
    unsafe {
        core::arch::asm!(
            "mov x16, {syscall_nr}",
            "svc #0x80",
            "cset {err}, cs",
            syscall_nr = in(reg) RAW_SYS_SIGALTSTACK,
            in("x0") ss as u64,
            in("x1") oss as u64,
            err = out(reg) err_flag,
            lateout("x0") ret,
            out("x16") _,
        );
    }
    if err_flag != 0 {
        Err(ret as i32)
    } else {
        Ok(())
    }
}

/// Address of `_sigtramp` in libsystem_platform, resolved once via `dlsym`.
///
/// The kernel-level `__sigaction` struct requires `sa_tramp` to point to
/// `_sigtramp`. The libc `sigaction()` wrapper adds this automatically, but
/// our raw SVC bypass must provide it explicitly.
///
/// Stored as an `AtomicUsize` (instead of `OnceLock`) because `OnceLock` may
/// not properly inherit its "initialized" state across `fork()` in all
/// configurations.
static SIGTRAMP_ADDR: AtomicUsize = AtomicUsize::new(0);

/// Returns the address of `_sigtramp`, resolving it by walking the Mach-O
/// symbol table of `libsystem_platform.dylib` on first call.
///
/// `_sigtramp` is a **local** text symbol (`t` in `nm`) — NOT an exported
/// symbol.  `dlsym(RTLD_DEFAULT, "_sigtramp")` returns NULL.  We must parse
/// the in-memory Mach-O headers to find it.
///
/// This function only reads in-memory data structures (no syscalls, no locks)
/// and is safe to call both before and after `fork()`, and even after the
/// shared cache `__TEXT` segments have been patched.
///
/// # Panics
///
/// Panics if `libsystem_platform.dylib` is not loaded or if `__sigtramp` is
/// not found in its symbol table.
pub fn get_sigtramp_addr() -> usize {
    let addr = SIGTRAMP_ADDR.load(Ordering::Acquire);
    if addr != 0 {
        return addr;
    }
    let resolved = resolve_sigtramp_from_macho();
    SIGTRAMP_ADDR.store(resolved, Ordering::Release);
    resolved
}

/// Walk the loaded dyld images to find `__sigtramp` (C-mangled `_sigtramp`)
/// in `libsystem_platform.dylib`'s symbol table.
///
/// # Safety
///
/// Reads Mach-O headers and symbol tables that are mapped into the process's
/// address space by dyld.  No allocations, no syscalls, no locks.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    deprecated
)]
fn resolve_sigtramp_from_macho() -> usize {
    // Mach-O load command constants (not all exposed by libc crate).
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;

    /// Mach-O `symtab_command`.
    #[repr(C)]
    struct SymtabCmd {
        cmd: u32,
        cmdsize: u32,
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
    }

    /// Mach-O `segment_command_64` (abbreviated — we only need a few fields).
    #[repr(C)]
    struct SegCmd64 {
        cmd: u32,
        cmdsize: u32,
        segname: [u8; 16],
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        // remaining fields not needed
    }

    /// Mach-O `nlist_64`.
    #[repr(C)]
    struct SymEntry64 {
        strx: u32,
        sym_type: u8,
        sect: u8,
        desc: u16,
        value: u64,
    }

    unsafe {
        let count = libc::_dyld_image_count();
        for i in 0..count {
            let name_ptr = libc::_dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }
            // Check if this image is libsystem_platform.dylib.
            let name = core::ffi::CStr::from_ptr(name_ptr);
            let name_bytes = name.to_bytes();
            if !name_bytes
                .windows(b"libsystem_platform".len())
                .any(|w| w == b"libsystem_platform")
            {
                continue;
            }

            let header = libc::_dyld_get_image_header(i);
            if header.is_null() {
                continue;
            }
            let slide = libc::_dyld_get_image_vmaddr_slide(i);

            // Cast to mach_header_64 to read ncmds.
            let hdr = header.cast::<libc::mach_header_64>();
            let ncmds = (*hdr).ncmds;

            // Walk load commands.
            let mut lc_ptr = hdr
                .cast::<u8>()
                .add(core::mem::size_of::<libc::mach_header_64>());
            let mut linkedit_vmaddr: u64 = 0;
            let mut linkedit_fileoff: u64 = 0;
            let mut linkedit_found = false;
            let mut symtab_ptr: *const SymtabCmd = core::ptr::null();

            for _ in 0..ncmds {
                let cmd = core::ptr::read_unaligned(lc_ptr.cast::<u32>());
                let cmdsize = core::ptr::read_unaligned(lc_ptr.add(4).cast::<u32>());

                if cmd == LC_SEGMENT_64 {
                    let seg = lc_ptr.cast::<SegCmd64>();
                    // Check for __LINKEDIT.
                    let segname = core::ptr::addr_of!((*seg).segname).read_unaligned();
                    if segname[..10] == *b"__LINKEDIT" {
                        linkedit_vmaddr = core::ptr::addr_of!((*seg).vmaddr).read_unaligned();
                        linkedit_fileoff = core::ptr::addr_of!((*seg).fileoff).read_unaligned();
                        linkedit_found = true;
                    }
                } else if cmd == LC_SYMTAB {
                    symtab_ptr = lc_ptr.cast::<SymtabCmd>();
                }

                lc_ptr = lc_ptr.add(cmdsize as usize);
            }

            assert!(
                linkedit_found && !symtab_ptr.is_null(),
                "libsystem_platform.dylib missing __LINKEDIT or LC_SYMTAB"
            );

            // Compute base of __LINKEDIT in memory.
            let linkedit_base =
                (linkedit_vmaddr as usize).wrapping_add(slide as usize) as *const u8;

            let symoff = core::ptr::addr_of!((*symtab_ptr).symoff).read_unaligned() as usize;
            let nsyms = core::ptr::addr_of!((*symtab_ptr).nsyms).read_unaligned() as usize;
            let stroff = core::ptr::addr_of!((*symtab_ptr).stroff).read_unaligned() as usize;

            let syms = linkedit_base
                .add(symoff - linkedit_fileoff as usize)
                .cast::<SymEntry64>();
            let strtab = linkedit_base.add(stroff - linkedit_fileoff as usize);

            for k in 0..nsyms {
                let entry_ptr = syms.add(k);
                let strx = core::ptr::addr_of!((*entry_ptr).strx).read_unaligned() as usize;
                let value = core::ptr::addr_of!((*entry_ptr).value).read_unaligned();
                let sym_name_ptr = strtab.add(strx);

                // Compare against "__sigtramp" (C-mangled name of `_sigtramp`).
                let target = b"__sigtramp\0";
                let mut matches = true;
                for (j, &b) in target.iter().enumerate() {
                    if *sym_name_ptr.add(j) != b {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    let addr = (value as usize).wrapping_add(slide as usize);
                    assert!(addr != 0, "__sigtramp has zero address");
                    return addr;
                }
            }

            panic!("__sigtramp not found in libsystem_platform.dylib symbol table");
        }
    }
    panic!("libsystem_platform.dylib not found among loaded images");
}

/// Build a kernel-level `__sigaction` struct (24 bytes) and call `SYS_SIGACTION`.
///
/// This is the raw equivalent of `libc::sigaction()`, bypassing the patched
/// shared cache gate.
///
/// `handler` is the signal handler function pointer (`SA_SIGINFO`-style).
/// `mask` is the signal mask to apply during handler execution.
/// `flags` is the `SA_*` flags (e.g., `SA_SIGINFO | SA_ONSTACK`).
/// `old_sa` receives the previous signal action (16-byte `struct sigaction`).
///
/// # Safety
///
/// Caller must ensure `handler` is a valid function pointer and `old_sa` is
/// valid.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
unsafe fn raw_host_sigaction_install(
    signum: i32,
    handler: usize,
    mask: libc::sigset_t,
    flags: i32,
    old_sa: &mut libc::sigaction,
) {
    let tramp = get_sigtramp_addr();
    // Build kernel __sigaction (24 bytes):
    //   [0..8]   sa_handler
    //   [8..16]  sa_tramp
    //   [16..20] sa_mask (sigset_t = u32 on macOS)
    //   [20..24] sa_flags
    let mut ksa = [0u8; 24];
    ksa[0..8].copy_from_slice(&(handler as u64).to_ne_bytes());
    ksa[8..16].copy_from_slice(&(tramp as u64).to_ne_bytes());
    ksa[16..20].copy_from_slice(&mask.to_ne_bytes());
    ksa[20..24].copy_from_slice(&flags.to_ne_bytes());

    let r = unsafe {
        raw_host_sigaction(
            signum,
            ksa.as_ptr(),
            std::ptr::from_mut(old_sa).cast::<u8>(),
        )
    };
    assert!(
        r.is_ok(),
        "raw_host_sigaction failed for signal {signum}: errno {}",
        r.unwrap_err()
    );
}

/// Module-level `Once` for [`register_exception_handlers`].
///
/// Promoted from a function-local `static` so that [`reset_exception_handler_once`]
/// can reset it after `fork()`.
static EXCEPTION_HANDLER_ONCE: std::sync::Once = std::sync::Once::new();

/// Reset the exception-handler registration guard so that
/// `register_exception_handlers` will re-register signal handlers on the
/// next call to [`MacosUserland::new`].
///
/// This is intended **only** for use in a `fork()`ed child process.  After
/// `fork()`, the child inherits the parent's signal handlers, but those may
/// have been overwritten by test infrastructure (e.g. a crash handler).  The
/// child must re-register its own handlers so that guest page faults are
/// handled by the platform's exception handler rather than the test's crash
/// handler.
///
/// # Safety
///
/// - Must only be called from a single-threaded context (e.g. immediately
///   after `fork()` in the child, before spawning any threads).
/// - The caller must call [`MacosUserland::new`] again afterward.
pub unsafe fn reset_exception_handler_once() {
    // `std::sync::Once` contains an internal state word.  We reset it by
    // overwriting with a fresh `Once`.
    let ptr: *const std::sync::Once = &raw const EXCEPTION_HANDLER_ONCE;
    let ptr_mut = ptr.cast_mut();
    unsafe {
        ptr_mut.write(std::sync::Once::new());
    }
}

fn register_exception_handlers() {
    EXCEPTION_HANDLER_ONCE.call_once(|| {
        // Use raw SVC-based sigaction to bypass the patched shared cache gate.
        // After install_shared_cache, libc::sigaction goes through the gate →
        // syscall_callback → shim, which handles it as a guest sigaction
        // (updating the virtual signal table, not the real kernel disposition).

        let interrupt_signal = {
            let sig = libc::SIGUSR1;
            let mask: libc::sigset_t = 0;
            let flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            let mut old_sa: libc::sigaction = unsafe { core::mem::zeroed() };
            unsafe {
                raw_host_sigaction_install(
                    sig,
                    interrupt_signal_handler as *const () as usize,
                    mask,
                    flags,
                    &mut old_sa,
                );
            }
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
            // Build a mask that blocks the interrupt signal during exception
            // handling to avoid saving the exception handler state as guest state.
            let mut mask: libc::sigset_t = 0;
            unsafe {
                libc::sigaddset(&raw mut mask, interrupt_signal);
            }
            let flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            let mut old_sa: libc::sigaction = unsafe { core::mem::zeroed() };
            unsafe {
                raw_host_sigaction_install(
                    sig,
                    exception_signal_handler as *const () as usize,
                    mask,
                    flags,
                    &mut old_sa,
                );
            }
            // Guard against circular handler chain: if the old handler IS
            // exception_signal_handler (e.g. after fork + reset_exception_handler_once),
            // store SIG_DFL instead to avoid infinite recursion in next_signal_handler.
            let our_handler = exception_signal_handler as *const () as usize;
            if old_sa.sa_sigaction == our_handler {
                old_sa.sa_sigaction = libc::SIG_DFL;
                old_sa.sa_flags = 0;
            }
            unsafe {
                NEXT_SA[sig.reinterpret_as_unsigned() as usize] = old_sa;
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
fn with_signal_alt_stack<R>(host_tls: usize, f: impl FnOnce() -> R) -> R {
    let guard_page_size: usize = 0x1000;
    // Allocate double the size so we can find an aligned region within it.
    let alloc_size = ALT_STACK_ALLOC_SIZE * 2;
    let raw_addr = unsafe {
        raw_host_mmap(
            0,
            alloc_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
    .expect("failed to allocate memory for alternate signal stack");

    // Find the aligned base within the allocation.
    let aligned_base = (raw_addr + ALT_STACK_ALLOC_SIZE - 1) & !(ALT_STACK_ALLOC_SIZE - 1);

    // Unmap the unused prefix and suffix.
    let prefix_size = aligned_base - raw_addr;
    if prefix_size > 0 {
        unsafe {
            let _ = raw_host_munmap(raw_addr, prefix_size);
        }
    }
    let suffix_start = aligned_base + ALT_STACK_ALLOC_SIZE;
    let suffix_size = (raw_addr + alloc_size) - suffix_start;
    if suffix_size > 0 {
        unsafe {
            let _ = raw_host_munmap(suffix_start, suffix_size);
        }
    }

    let _unmap_guard = litebox::utils::defer(move || {
        let r = unsafe { raw_host_munmap(aligned_base, ALT_STACK_ALLOC_SIZE) };
        assert!(r.is_ok(), "failed to free alternate signal stack memory");
    });

    // Set up a guard page at the bottom.
    let r = unsafe { raw_host_mprotect(aligned_base, guard_page_size, libc::PROT_NONE) };
    assert!(
        r.is_ok(),
        "failed to set guard page for alternate signal stack"
    );

    // Store host TLS pointer at aligned_base + ALT_STACK_ALLOC_SIZE - 8.
    // On macOS, the caller passes the TCB pointer (which is what TPIDR_EL0
    // must be restored to in signal handlers). On Linux, this would be the
    // system TLS pointer (read from TPIDR_EL0 before the call).
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
        let r = raw_host_sigaltstack(&raw const alt_stack, &raw mut oss);
        assert!(r.is_ok(), "failed to set up alternate signal stack");
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

        // macOS sigaltstack rejects ss_size < MINSIGSTKSZ even when
        // SS_DISABLE is set (arguably a kernel bug). Ensure the size
        // meets the minimum so restoration of a "disabled" state works.
        let mut restored = oss;
        if restored.ss_flags & libc::SS_DISABLE != 0 && restored.ss_size < libc::MINSIGSTKSZ {
            restored.ss_size = libc::MINSIGSTKSZ;
        }
        let r = raw_host_sigaltstack(&raw const restored, std::ptr::null_mut());
        assert!(r.is_ok(), "failed to restore original signal stack");
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
///
/// Returns `(guest_regs, host_tls)` if in guest, `None` otherwise. The caller
/// needs `host_tls` to pass through `set_signal_return` → x18, because macOS
/// sigreturn clobbers TPIDR_EL0.
fn signal_handler_exit_guest(
    _context: &libc::ucontext_t,
    set_interrupt: bool,
) -> Option<(*mut litebox_common_linux::PtRegs, usize)> {
    unsafe {
        let mut current_ss: libc::stack_t = core::mem::zeroed();
        // Use raw SVC to bypass the patched gate. libc::sigaltstack would
        // go through the gate → syscall_callback → shim, which would
        // clobber SP and process it as a guest syscall.
        let ret = raw_host_sigaltstack(std::ptr::null(), &raw mut current_ss);
        if ret.is_err() || current_ss.ss_flags & libc::SS_ONSTACK == 0 {
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

        // Do NOT write TPIDR_EL0 here.  macOS system libraries use it for
        // per-CPU data (_os_cpu_number); writing our TCB address there
        // corrupts malloc's XZone per-CPU cache lookup.
        //
        // On macOS, we do NOT read TPIDR_EL0 to save the guest TPIDR because
        // the kernel already clobbered it to the pthread value on signal
        // delivery (and any mprotect/sigaltstack/write syscalls in the signal
        // handler clobber it further). The correct guest TPIDR is already in
        // `tcb.guest_tpidr`, set by the last `switch_to_guest` or
        // `syscall_callback`. Unlike Linux (where the kernel preserves
        // TPIDR_EL0 for signal handlers), macOS makes it unreliable here.

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

        // NOTE: On macOS we do NOT update guest_tpidr here. The kernel
        // clobbers TPIDR_EL0 to the pthread value on signal delivery, so
        // `mrs tpidr_el0` would give the wrong value. The correct guest
        // TPIDR is already in `tcb.guest_tpidr` from the last
        // `switch_to_guest` (which loaded it from guest_tpidr) or from
        // `syscall_callback` (which saved it from the trampoline stack
        // slot). On Linux, the kernel preserves TPIDR_EL0 in signal
        // handlers so the original code reads it here — but on macOS
        // that's broken.

        let ctx_top_ptr = (host_tls as *const usize).byte_offset(tcb_offset_guest_context_top());
        let guest_context_top =
            core::ptr::read_volatile(ctx_top_ptr) as *mut litebox_common_linux::PtRegs;
        Some((guest_context_top.sub(1), host_tls))
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

    // macOS zeroes x18 on every kernel→userspace transition (signal delivery,
    // context switch). The mach context's x18 is therefore always 0. Override
    // regs[18] with the authoritative guest_x18 from the TCB, which is kept
    // up-to-date by the x18 virtualization gates in the rewriter trampoline.
    let tcb = TCB_PTR.get();
    if !tcb.is_null() {
        regs.regs[18] = unsafe { (*tcb).guest_x18 };
    }
}

/// Updates a Linux signal context to return to `f` with the given arguments (aarch64).
///
/// Also writes `host_tls` into x18 in the ucontext, so the callback asm can
/// restore TPIDR_EL0 after sigreturn (macOS clobbers TPIDR_EL0 on sigreturn).
#[allow(clippy::cast_sign_loss)]
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    host_tls: usize,
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
    // Pass host_tls via x9 so callback asm can use it as TCB pointer
    // to recover the host stack.  macOS sigreturn does NOT restore x18
    // (platform-reserved register on Darwin ARM64), so we use x9 instead.
    // x9 is a standard caller-saved temp register that IS properly restored.
    sigctx.__ss.__x[9] = host_tls as u64;
}

/// Translate a macOS signal number to the equivalent Linux signal number.
///
/// The shim's `handle_exception_request` matches against Linux signal numbers.
/// Most exception signals have the same number on both platforms, but SIGBUS
/// differs: macOS=10, Linux=7.
fn macos_signal_to_linux(signum: libc::c_int) -> libc::c_int {
    // Linux signal numbers for reference:
    //   SIGILL=4, SIGTRAP=5, SIGBUS=7, SIGFPE=8, SIGSEGV=11
    match signum {
        libc::SIGBUS => 7,  // macOS SIGBUS=10 → Linux SIGBUS=7
        libc::SIGILL => 4,  // same on both
        libc::SIGTRAP => 5, // same on both
        libc::SIGFPE => 8,  // same on both
        _ => 11,            // SIGSEGV and unknown → Linux SIGSEGV=11
    }
}

/// Signal handler for hardware exceptions (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP).
#[allow(clippy::cast_possible_truncation)]
unsafe extern "C" fn exception_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    // Fault-and-toggle W^X: handle permission faults on edge pages.
    //
    // Edge pages are 16KB host pages containing 4KB guest sub-pages with
    // conflicting permissions. They are set to either RW or RX. When the
    // "wrong" access type occurs, we toggle the permission and resume.
    //
    // This must be checked before signal_handler_exit_guest because:
    // 1. Host code can fault on edge pages during writes (e.g., ELF loading)
    // 2. Guest code can fault when executing code on an RW edge page
    if signum == libc::SIGSEGV || signum == libc::SIGBUS {
        let sigctx_edge = unsafe { &*context.uc_mcontext };
        let far = sigctx_edge.__es.__far as usize;
        let esr = sigctx_edge.__es.__esr;
        let ec = (esr >> 26) & 0x3F;

        if is_edge_page(far) {
            let page_addr = host_page_align_down(far);
            // EC 0x20/0x21 = Instruction Abort → page needs EXEC → flip to RX
            // EC 0x24/0x25 = Data Abort, check WnR (bit 6) for write → flip to RW
            let toggled = if ec == 0x20 || ec == 0x21 {
                // Instruction abort: guest tried to execute, page is currently RW.
                // Flip to RX.  Use raw SVC to bypass the patched shared cache gate.
                unsafe {
                    raw_host_mprotect(
                        page_addr,
                        HOST_PAGE_SIZE,
                        (ProtFlags::PROT_READ | ProtFlags::PROT_EXEC).bits(),
                    )
                }
                .is_ok()
            } else if (ec == 0x24 || ec == 0x25) && (esr & (1 << 6)) != 0 {
                // Data abort with WnR=1: guest/host tried to write, page is currently RX.
                // Flip to RW.  Use raw SVC to bypass the patched shared cache gate.
                unsafe {
                    raw_host_mprotect(
                        page_addr,
                        HOST_PAGE_SIZE,
                        (ProtFlags::PROT_READ | ProtFlags::PROT_WRITE).bits(),
                    )
                }
                .is_ok()
            } else {
                false
            };

            if toggled {
                // If we're in the guest, we can't just return: macOS sigreturn
                // clobbers TPIDR_EL0 to the per-CPU pthread value, not the
                // guest's virtual TPIDR_EL0.  Route through the interrupt path
                // which resumes via switch_to_guest (which sets the correct
                // guest TPIDR_EL0 from TCB.guest_tpidr before entering guest).
                //
                // This matches the Windows platform's approach to FS base
                // restoration after Windows clobbers it on context switches.
                //
                // If we're NOT in the guest (host code writing to an edge page,
                // e.g. during ELF loading), just return directly — host code
                // doesn't use TPIDR_EL0 for guest TLS.
                if let Some((regs, host_tls)) = signal_handler_exit_guest(context, false) {
                    // If the fault happened during switch_to_guest (restoring
                    // guest context), don't overwrite the saved PtRegs — they
                    // already contain the correct guest state from before the
                    // switch. Copying the ucontext here would save partially-
                    // restored intermediate register values as "guest" state.
                    // This mirrors the same check in interrupt_signal_handler.
                    let ip = sigctx_edge.__ss.__pc as usize;
                    let in_switch_to_guest = (switch_to_guest_start as *const () as usize
                        ..switch_to_guest_end as *const () as usize)
                        .contains(&ip);
                    if !in_switch_to_guest {
                        copy_signal_context(unsafe { &mut *regs }, context);
                    }

                    // Ensure that `run_thread_arch` is linked in so that
                    // `interrupt_callback` is visible.
                    let _ = run_thread_arch as *const () as usize;

                    set_signal_return(context, interrupt_callback, host_tls, 0, 0, 0, 0);
                }
                return;
            }
            // If we couldn't toggle (unexpected EC), fall through to normal handling.
        }
    }

    // Demand-page check: serve SIGBUS faults on shared-cache pages that
    // have no physical backing.  This handles BOTH guest and host faults
    // (e.g. libc::mmap wrapper accessing shared-cache data during the
    // second exec after execve, when the demand-page shim handler would
    // not be reachable via signal_handler_exit_guest).
    if signum == libc::SIGBUS {
        let handler_addr = DEMAND_PAGE_HANDLER.load(Ordering::Acquire);
        if handler_addr != 0 {
            let sigctx_dp = unsafe { &*context.uc_mcontext };
            let fault_addr = sigctx_dp.__es.__far as usize;
            let handler: unsafe fn(usize) -> bool =
                unsafe { core::mem::transmute(handler_addr) };
            if unsafe { handler(fault_addr) } {
                // Page was served.  If we were in guest code, we must NOT
                // simply return — macOS sigreturn clobbers TPIDR_EL0 to the
                // pthread value, which would break the guest's TLS.  Route
                // through interrupt_callback → switch_to_guest to restore
                // the correct TPIDR_EL0 before resuming guest execution.
                if let Some((regs, host_tls)) = signal_handler_exit_guest(context, false) {
                    let ip = sigctx_dp.__ss.__pc as usize;
                    let in_switch_to_guest = (switch_to_guest_start as *const () as usize
                        ..switch_to_guest_end as *const () as usize)
                        .contains(&ip);
                    if !in_switch_to_guest {
                        copy_signal_context(unsafe { &mut *regs }, context);
                    }
                    let _ = run_thread_arch as *const () as usize;
                    set_signal_return(context, interrupt_callback, host_tls, 0, 0, 0, 0);
                }
                // Host-side fault: just return — sigreturn is fine for host code.
                return;
            }
        }
    }

    let Some((regs, host_tls)) = signal_handler_exit_guest(context, false) else {
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
        // Translate macOS signal number to Linux equivalent before passing
        // to the shim. The shim's handle_exception_request matches against
        // Linux signal numbers (SIGBUS=7, SIGFPE=8, SIGILL=4, SIGTRAP=5,
        // SIGSEGV=11). Most are the same on both platforms, but SIGBUS
        // differs: macOS=10, Linux=7.
        let linux_signum = macos_signal_to_linux(signum);
        (
            linux_signum as isize, // Linux signal number as trap number
            0isize,                // no error code concept on ARM64
            fault_addr as isize,   // fault address
        )
    };
    set_signal_return(context, exception_callback, host_tls, 0, trapno, err, cr2);
}

/// Runs the next signal handler in the chain.
unsafe fn next_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    // On macOS, memory faults can be delivered as either SIGSEGV or SIGBUS
    // (e.g., NULL dereference on ARM64 is typically SIGBUS). Check both
    // for exception table recovery.
    if signum == libc::SIGSEGV || signum == libc::SIGBUS {
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
                // Terminate the process with the conventional exit code for
                // an unhandled signal.  We use a raw SVC _exit() to bypass
                // the patched shared cache gate — libc::raise would go
                // through the gate, get intercepted, and return normally,
                // which would hit unreachable!().
                #[allow(clippy::cast_sign_loss)]
                let exit_code = (128 + signum) as u64;
                core::arch::asm!(
                    "mov x0, {code}",
                    "mov x16, #1",  // SYS_exit = 1
                    "svc #0x80",
                    code = in(reg) exit_code,
                    options(noreturn),
                );
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

    // Case 1: in the syscall_callback prologue (before in_guest is cleared).
    //
    // syscall_callback's first instruction loads TCB from [SP+40] (stored by
    // the trampoline), and the second instruction clears in_guest.
    // During these 2 instructions, in_guest is still 1. If the interrupt
    // arrives here, just return — syscall_callback will clear in_guest and
    // call into the shim which will check for interrupts.
    //
    // FUTURE: handle trampoline code, too. This is somewhat less important
    // because it's probably fine for the shim to observe a guest context that
    // is inside the trampoline.
    let syscall_callback_addr = syscall_callback as *const () as usize;
    if (syscall_callback_addr..syscall_callback_addr + 8).contains(&ip) {
        // No need to clear `in_guest` or set interrupt; the syscall handler will
        // clear `in_guest` and call into the shim.
        return;
    }

    // Clear `in_guest` and set `interrupt`.
    let Some((regs, host_tls)) = signal_handler_exit_guest(context, true) else {
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
    set_signal_return(context, interrupt_callback, host_tls, 0, 0, 0, 0);
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
