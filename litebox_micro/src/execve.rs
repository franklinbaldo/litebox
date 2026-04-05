// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Execve handling: serialize args, receive ELF data from central, map
//! segments, and jump to the new entry point.

use litebox_ipc::ring::{CqEntry, cq_flags};

use crate::state::MicroState;
use crate::tls::MicroTls;
use crate::trampoline::SyscallArgs;

// ── Data structures ──────────────────────────────────────────────────────

/// Header sent by central in the execve CQ response data region.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecveHeader {
    /// Number of segments to map (main ELF + interpreter).
    pub num_segments: u32,
    /// Padding for alignment.
    pub pad0: u32,
    /// Entry point address (interpreter entry if dynamic, else main entry).
    /// This is where we actually jump to.
    pub entry_point: u64,
    /// The main binary's entry point (for AT_ENTRY auxv).
    pub at_entry: u64,
    /// Program break address.
    pub brk: u64,
    /// Address of program headers in memory (for AT_PHDR).
    pub phdr_addr: u64,
    /// Number of program headers.
    pub phnum: u32,
    /// Size of each program header entry.
    pub phent: u32,
    /// Interpreter base address (0 if static binary).
    pub interp_base: u64,
    /// Number of argv entries.
    pub argc: u32,
    /// Number of envp entries.
    pub envc: u32,
    /// Offset in data region (relative to header start) where argv strings start.
    pub argv_offset: u32,
    /// Total byte length of serialized argv strings (NUL-separated).
    pub argv_len: u32,
    /// Offset in data region where envp strings start.
    pub envp_offset: u32,
    /// Total byte length of serialized envp strings (NUL-separated).
    pub envp_len: u32,
    /// Syscall entry point address (for trampoline patching).
    pub syscall_entry_point: u64,
    /// Start of the reserved bump-allocator range for anonymous mmap(NULL).
    /// 0 means no bump allocator is available.
    pub mmap_bump_start: u64,
    /// End (exclusive) of the bump-allocator range.
    pub mmap_bump_end: u64,
    /// Base address of the main binary's virtual address range.
    pub main_range_base: u64,
    /// Total length of the main binary's virtual address range.
    pub main_range_len: u64,
    /// Base address of the interpreter's virtual address range (0 if no interp).
    pub interp_range_base: u64,
    /// Total length of the interpreter's virtual address range (0 if no interp).
    pub interp_range_len: u64,
    /// Offset in aligned memfd where the main binary's file data starts (for
    /// range-level mmap).  `u64::MAX` means the main binary is not in aligned memfd.
    pub main_file_base_offset: u64,
    /// Page-rounded length of the main binary's file data to mmap from aligned memfd.
    pub main_file_map_len: u64,
    /// Offset in aligned memfd where the interpreter's file data starts.
    /// `u64::MAX` means the interpreter is not in aligned memfd.
    pub interp_file_base_offset: u64,
    /// Page-rounded length of the interpreter's file data to mmap from aligned memfd.
    pub interp_file_map_len: u64,
}

/// Describes a loaded ELF segment that micro must map.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecveSegment {
    /// Virtual address where this segment should be mapped (already base-adjusted for ET_DYN).
    pub vaddr: u64,
    /// Length of the mapping (page-aligned).
    pub map_len: u64,
    /// Length of file-backed data within the mapping.
    pub data_len: u64,
    /// Protection flags (PROT_READ | PROT_WRITE | PROT_EXEC bitmask).
    pub prot: u32,
    /// Non-zero if this segment carries trampoline data that follows immediately
    /// after the file-backed data. The trampoline data has format:
    /// [u32 LE: vaddr_offset from base_addr] [u32 LE: trampoline_code_size] [trampoline_code bytes]
    pub has_trampoline: u32,
    /// Offset into the tar shmem region where this segment's file data starts.
    /// `u64::MAX` means data is in the ring data region at `data_offset` (non-tar binary).
    pub tar_data_offset: u64,
    /// Offset in data region where this segment's file data starts (relative to header start).
    pub data_offset: u64,
    /// Byte offset within this segment where BSS (zero-fill) begins.
    ///
    /// When copying file data from the aligned data memfd, the raw file bytes
    /// past `p_filesz` may contain non-zero data (section headers, trampoline
    /// data, etc.) that must be zeroed because the ELF spec requires it.
    /// Micro must zero `[vaddr + bss_zero_offset, vaddr + data_len)` after
    /// copying from aligned_base.  If `bss_zero_offset == data_len`, there
    /// is no BSS to zero.
    pub bss_zero_offset: u64,
}

// ── Serialization (micro → central) ─────────────────────────────────────

/// Serialize pathname, argv, and envp into a data buffer for transfer to central.
///
/// Format: `[u32 path_len][path bytes with NUL][u32 argc][u32 arg0_len][arg0+NUL]...[u32 envc][u32 env0_len][env0+NUL]...`
///
/// Returns the number of bytes written, or `None` if the buffer is too small.
///
/// # Safety
///
/// `argv_ptr` and `envp_ptr` must be null-terminated arrays of null-terminated C string pointers.
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn serialize_execve_args(
    buf: &mut [u8],
    pathname: &core::ffi::CStr,
    argv_ptr: *const *const i8,
    envp_ptr: *const *const i8,
) -> Option<usize> {
    let mut pos = 0usize;

    // Write pathname.
    let path_bytes = pathname.to_bytes_with_nul();
    let path_len = path_bytes.len() as u32;
    if pos + 4 + path_bytes.len() > buf.len() {
        return None;
    }
    buf[pos..pos + 4].copy_from_slice(&path_len.to_le_bytes());
    pos += 4;
    buf[pos..pos + path_bytes.len()].copy_from_slice(path_bytes);
    pos += path_bytes.len();

    // Count and write argv.
    let mut argc: u32 = 0;
    if !argv_ptr.is_null() {
        let mut p = argv_ptr;
        while !unsafe { *p }.is_null() {
            argc += 1;
            p = unsafe { p.add(1) };
        }
    }
    if pos + 4 > buf.len() {
        return None;
    }
    buf[pos..pos + 4].copy_from_slice(&argc.to_le_bytes());
    pos += 4;

    if !argv_ptr.is_null() {
        let mut p = argv_ptr;
        for _ in 0..argc {
            let cstr = unsafe { core::ffi::CStr::from_ptr(*p) };
            let bytes = cstr.to_bytes_with_nul();
            let arg_len = bytes.len() as u32;
            if pos + 4 + bytes.len() > buf.len() {
                return None;
            }
            buf[pos..pos + 4].copy_from_slice(&arg_len.to_le_bytes());
            pos += 4;
            buf[pos..pos + bytes.len()].copy_from_slice(bytes);
            pos += bytes.len();
            p = unsafe { p.add(1) };
        }
    }

    // Count and write envp.
    let mut envc: u32 = 0;
    if !envp_ptr.is_null() {
        let mut p = envp_ptr;
        while !unsafe { *p }.is_null() {
            envc += 1;
            p = unsafe { p.add(1) };
        }
    }
    if pos + 4 > buf.len() {
        return None;
    }
    buf[pos..pos + 4].copy_from_slice(&envc.to_le_bytes());
    pos += 4;

    if !envp_ptr.is_null() {
        let mut p = envp_ptr;
        for _ in 0..envc {
            let cstr = unsafe { core::ffi::CStr::from_ptr(*p) };
            let bytes = cstr.to_bytes_with_nul();
            let env_len = bytes.len() as u32;
            if pos + 4 + bytes.len() > buf.len() {
                return None;
            }
            buf[pos..pos + 4].copy_from_slice(&env_len.to_le_bytes());
            pos += 4;
            buf[pos..pos + bytes.len()].copy_from_slice(bytes);
            pos += bytes.len();
            p = unsafe { p.add(1) };
        }
    }

    Some(pos)
}

// ── Stack building ──────────────────────────────────────────────────────

/// 8 MiB — matches the default Linux `RLIMIT_STACK`.
const STACK_SIZE: usize = 8 * 1024 * 1024;

/// Auxiliary vector key constants (mirrors Linux `AT_*`).
#[allow(non_upper_case_globals)]
mod at {
    pub const AT_NULL: usize = 0;
    pub const AT_PHDR: usize = 3;
    pub const AT_PHENT: usize = 4;
    pub const AT_PHNUM: usize = 5;
    pub const AT_PAGESZ: usize = 6;
    pub const AT_BASE: usize = 7;
    pub const AT_ENTRY: usize = 9;
    pub const AT_UID: usize = 11;
    pub const AT_EUID: usize = 12;
    pub const AT_GID: usize = 13;
    pub const AT_EGID: usize = 14;
    pub const AT_CLKTCK: usize = 17;
    pub const AT_RANDOM: usize = 25;
}

/// Build an ELF initial stack: argc, argv ptrs, NULL, envp ptrs, NULL, auxv, random, strings.
///
/// Returns the stack pointer (pointing at argc, 16-byte aligned).
#[allow(clippy::cast_possible_truncation)]
fn build_exec_stack(
    stack_base: usize,
    stack_size: usize,
    argv_strings: &[&[u8]], // NUL-terminated strings
    envp_strings: &[&[u8]], // NUL-terminated strings
    header: &ExecveHeader,
) -> usize {
    let mut pos = stack_size;

    // Helper: write bytes at current pos (growing downward).
    let write_bytes = |pos: &mut usize, data: &[u8], base: usize| {
        *pos -= data.len();
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), (base + *pos) as *mut u8, data.len());
        }
    };

    let write_usize = |pos: &mut usize, val: usize, base: usize| {
        *pos -= core::mem::size_of::<usize>();
        unsafe {
            core::ptr::copy_nonoverlapping(
                val.to_ne_bytes().as_ptr(),
                (base + *pos) as *mut u8,
                core::mem::size_of::<usize>(),
            );
        }
    };

    // ── end marker (NULL) ──────────────────────────────────────────
    write_usize(&mut pos, 0, stack_base);

    // ── environment strings (ASCIIZ) ───────────────────────────────
    let mut env_addrs = [0usize; 1024]; // max 1024 envp entries
    let env_count = envp_strings.len().min(1024);
    for i in (0..env_count).rev() {
        write_bytes(&mut pos, envp_strings[i], stack_base);
        env_addrs[i] = stack_base + pos;
    }

    // ── argument strings (ASCIIZ) ──────────────────────────────────
    let mut arg_addrs = [0usize; 1024]; // max 1024 argv entries
    let arg_count = argv_strings.len().min(1024);
    for i in (0..arg_count).rev() {
        write_bytes(&mut pos, argv_strings[i], stack_base);
        arg_addrs[i] = stack_base + pos;
    }

    // ── AT_RANDOM: 16 pseudo-random bytes ──────────────────────────
    let random_bytes: [u8; 16] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
        0xEF,
    ];
    write_bytes(&mut pos, &random_bytes, stack_base);
    let at_random_addr = stack_base + pos;

    // ── alignment padding ──────────────────────────────────────────
    // Align pos to usize boundary first.
    pos &= !(core::mem::size_of::<usize>() - 1);

    // Build auxv list to count entries.
    // Fixed entries: PAGESZ, PHDR, PHENT, PHNUM, ENTRY, UID, EUID, GID, EGID, CLKTCK, RANDOM = 11
    // Optional: BASE (if interp_base != 0) = +1
    // Plus AT_NULL terminator = +1
    let auxv_count = 11 + usize::from(header.interp_base != 0) + 1;

    let remaining_entries =
        // auxv: entries * 2 words each
        auxv_count * 2
        // envp pointers + NULL terminator
        + env_count + 1
        // argv pointers + NULL terminator
        + arg_count + 1
        // argc
        + 1;
    let bytes_needed = remaining_entries * core::mem::size_of::<usize>();
    let final_pos = pos - bytes_needed;
    let aligned_final = final_pos & !15; // align down to 16 bytes
    pos -= final_pos - aligned_final;

    // ── auxv entries (push from top down) ──────────────────────────
    // AT_NULL terminator.
    write_usize(&mut pos, 0, stack_base);
    write_usize(&mut pos, at::AT_NULL, stack_base);

    // Push entries in reverse order so they appear ascending in memory.
    // We use a fixed order.
    write_usize(&mut pos, at_random_addr, stack_base);
    write_usize(&mut pos, at::AT_RANDOM, stack_base);

    write_usize(&mut pos, 100, stack_base);
    write_usize(&mut pos, at::AT_CLKTCK, stack_base);

    write_usize(&mut pos, 0, stack_base);
    write_usize(&mut pos, at::AT_EGID, stack_base);

    write_usize(&mut pos, 0, stack_base);
    write_usize(&mut pos, at::AT_GID, stack_base);

    write_usize(&mut pos, 0, stack_base);
    write_usize(&mut pos, at::AT_EUID, stack_base);

    write_usize(&mut pos, 0, stack_base);
    write_usize(&mut pos, at::AT_UID, stack_base);

    write_usize(&mut pos, header.at_entry as usize, stack_base);
    write_usize(&mut pos, at::AT_ENTRY, stack_base);

    if header.interp_base != 0 {
        write_usize(&mut pos, header.interp_base as usize, stack_base);
        write_usize(&mut pos, at::AT_BASE, stack_base);
    }

    write_usize(&mut pos, 4096, stack_base);
    write_usize(&mut pos, at::AT_PAGESZ, stack_base);

    write_usize(&mut pos, header.phnum as usize, stack_base);
    write_usize(&mut pos, at::AT_PHNUM, stack_base);

    write_usize(&mut pos, header.phent as usize, stack_base);
    write_usize(&mut pos, at::AT_PHENT, stack_base);

    write_usize(&mut pos, header.phdr_addr as usize, stack_base);
    write_usize(&mut pos, at::AT_PHDR, stack_base);

    // ── envp pointers ──────────────────────────────────────────────
    write_usize(&mut pos, 0, stack_base); // NULL terminator
    for i in (0..env_count).rev() {
        write_usize(&mut pos, env_addrs[i], stack_base);
    }

    // ── argv pointers ──────────────────────────────────────────────
    write_usize(&mut pos, 0, stack_base); // NULL terminator
    for i in (0..arg_count).rev() {
        write_usize(&mut pos, arg_addrs[i], stack_base);
    }

    // ── argc ───────────────────────────────────────────────────────
    write_usize(&mut pos, arg_count, stack_base);

    stack_base + pos
}

// ── Main entry point ────────────────────────────────────────────────────

/// Handle an execve syscall from the guest.
///
/// Serializes path/argv/envp into the data region, submits to central,
/// and on success, tears down old memory, maps new segments, and jumps
/// to the new entry point.
///
/// On error (before point-of-no-return), returns the negative errno.
/// On success, does NOT return — jumps to new entry point.
///
/// # Safety
///
/// - `tls` must point to valid initialized `MicroTls`.
/// - `args` must contain valid execve arguments.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
pub unsafe fn handle_execve(tls: *mut MicroTls, args: &SyscallArgs) -> i64 {
    let micro = unsafe { &*(*tls).micro };

    // Extract execve arguments.
    let pathname_ptr = args.args[0] as *const i8;
    let argv_ptr = args.args[1] as *const *const i8;
    let envp_ptr = args.args[2] as *const *const i8;

    if pathname_ptr.is_null() {
        return -i64::from(libc::EFAULT);
    }

    let pathname = unsafe { core::ffi::CStr::from_ptr(pathname_ptr) };

    // Serialize path/argv/envp into the data region.
    let data_region_ptr = unsafe { micro.ring_base.add(micro.layout.data_region_offset) };
    let data_region =
        unsafe { core::slice::from_raw_parts_mut(data_region_ptr, micro.layout.data_region_size) };

    let Some(data_len) =
        (unsafe { serialize_execve_args(data_region, pathname, argv_ptr, envp_ptr) })
    else {
        return -i64::from(libc::E2BIG);
    };

    // Submit SYS_execve to central with the serialized data.
    // We build a custom SQ entry with data_offset=0, data_len=serialized length.
    // The submit_and_wait function handles the normal pathname copy, but for execve
    // we already wrote the data ourselves. We need to submit with the right flags.
    let sq_args = args.args;
    // Override the args so central knows where the data is.
    // We'll use a special submission that sets data fields.
    let cq = unsafe { submit_execve_sq(tls, args.nr as u32, &sq_args, data_len as u32) };

    if cq.result < 0 {
        return cq.result;
    }

    // Central returned success with EXEC_LOCAL | HAS_DATA.
    if cq.flags & cq_flags::EXEC_LOCAL == 0 || cq.flags & cq_flags::HAS_DATA == 0 {
        return -i64::from(libc::ENOEXEC);
    }

    // Point of no return — execute the new binary.
    unsafe { execute_execve(tls, &cq, micro) }
}

/// Submit an execve SQ entry with pre-populated data region.
///
/// Similar to `submit_and_wait` but sets `data_offset` and `data_len` directly
/// instead of copying a pathname.
///
/// # Safety
///
/// - `tls` must point to valid initialized `MicroTls`.
#[allow(clippy::cast_possible_truncation, clippy::cast_ptr_alignment)]
unsafe fn submit_execve_sq(
    tls: *mut MicroTls,
    syscall_nr: u32,
    args: &[u64; 6],
    data_len: u32,
) -> CqEntry {
    use core::sync::atomic::Ordering::Acquire;
    use litebox_ipc::cq::{cq_find_by_seq, cq_tail};
    use litebox_ipc::ring::{RingHeader, SqEntry, sq_flags};
    use litebox_ipc::sq::{sq_acquire_slot, sq_publish};
    use litebox_ipc::wait::spin_then_wait;

    let micro = unsafe { &*(*tls).micro };
    let header = unsafe { &*(micro.ring_base.cast::<RingHeader>()) };
    let sq_entries = unsafe {
        micro
            .ring_base
            .add(micro.layout.sq_entries_offset)
            .cast::<SqEntry>()
    };
    let cq_entries = unsafe {
        micro
            .ring_base
            .add(micro.layout.cq_entries_offset)
            .cast::<litebox_ipc::ring::CqEntry>()
    };

    let seq = unsafe { (*tls).seq_counter };
    unsafe { (*tls).seq_counter += 1 };

    let thread_slot = unsafe { (*tls).thread_slot as u16 };
    let notify_slot = &header.cq_notify_slots[thread_slot as usize];
    let search_start = cq_tail(header);

    let slot_idx = unsafe { sq_acquire_slot(header) };
    let entry = unsafe { &mut *sq_entries.add(slot_idx as usize) };

    entry.seq = seq;
    entry.syscall_nr = syscall_nr;
    entry.thread_slot = thread_slot;
    entry.flags = sq_flags::NEED_AUTH;
    entry.args = *args;
    entry.data_offset = 0;
    entry.data_len = data_len;

    sq_publish(entry);
    header
        .sq_notify
        .fetch_add(1, core::sync::atomic::Ordering::Release);
    // Wake central in case it fell through to futex_wait.
    unsafe {
        crate::raw_syscall::futex4(
            core::ptr::from_ref(&header.sq_notify) as usize,
            libc::FUTEX_WAKE,
            1,
            0,
        );
    }

    loop {
        if let Some(cq) = unsafe { cq_find_by_seq(header, cq_entries, search_start, seq) } {
            return cq;
        }
        let current = notify_slot.load(Acquire);
        if let Some(cq) = unsafe { cq_find_by_seq(header, cq_entries, search_start, seq) } {
            return cq;
        }
        // Spin aggressively (10,000 iters ≈ 100 µs), then timed futex
        // fallback that periodically checks whether central is still alive.
        spin_then_wait(notify_slot, current, |addr, exp| {
            // Use a timed futex wait (100 ms) so we can check liveness.
            #[repr(C)]
            struct Timespec {
                tv_sec: i64,
                tv_nsec: i64,
            }
            let ts = Timespec {
                tv_sec: 0,
                tv_nsec: 100_000_000,
            };
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(addr) as usize,
                    libc::FUTEX_WAIT,
                    exp,
                    core::ptr::from_ref(&ts) as usize,
                );
            }
            crate::handler::check_central_alive(header, micro.central_pid);
        });
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Maximum number of segment extents tracked per binary range for gap
/// protection.  Must be large enough for the segment count of any single
/// binary (main or interpreter) plus its trampoline.
const MAX_SEGS_PER_RANGE: usize = 16;

/// Protect gaps between mapped segments within a bulk-mapped range.
///
/// `extents` contains `count` initialized `(start, end)` pairs (not
/// necessarily sorted).  Any region within `[range_base, range_base +
/// range_len)` that is NOT covered by any extent is mprotect'd to
/// `PROT_NONE`.
///
/// This function uses an insertion sort on the stack-allocated extent
/// array (at most `MAX_SEGS_PER_RANGE` entries) to avoid heap allocation.
fn protect_range_gaps(
    range_base: usize,
    range_len: usize,
    extents: &[core::mem::MaybeUninit<(usize, usize)>; MAX_SEGS_PER_RANGE],
    count: usize,
) {
    if range_len == 0 || count == 0 {
        return;
    }

    // Copy into a sortable stack array.
    let mut sorted: [(usize, usize); MAX_SEGS_PER_RANGE] = [(0, 0); MAX_SEGS_PER_RANGE];
    for i in 0..count {
        sorted[i] = unsafe { extents[i].assume_init() };
    }

    // Insertion sort by start address (count is small, typically 5-8).
    for i in 1..count {
        let key = sorted[i];
        let mut j = i;
        while j > 0 && sorted[j - 1].0 > key.0 {
            sorted[j] = sorted[j - 1];
            j -= 1;
        }
        sorted[j] = key;
    }

    // Merge overlapping/adjacent extents and protect gaps.
    let range_end = range_base + range_len;
    let mut cursor = range_base;

    let mut i = 0;
    while i < count {
        let (mut ext_start, mut ext_end) = sorted[i];

        // Merge with subsequent overlapping/adjacent extents.
        while i + 1 < count && sorted[i + 1].0 <= ext_end {
            i += 1;
            ext_end = ext_end.max(sorted[i].1);
        }

        // Clamp to range boundaries.
        ext_start = ext_start.max(range_base);
        ext_end = ext_end.min(range_end);

        // Gap before this extent?
        if ext_start > cursor {
            unsafe {
                crate::raw_syscall::mprotect(cursor, ext_start - cursor, libc::PROT_NONE);
            }
        }
        cursor = ext_end;
        i += 1;
    }

    // Trailing gap after last extent?
    if cursor < range_end {
        unsafe {
            crate::raw_syscall::mprotect(cursor, range_end - cursor, libc::PROT_NONE);
        }
    }
}

// ── Execute execve ──────────────────────────────────────────────────────

/// Execute an execve prepared by central. Does NOT return.
///
/// # Safety
/// - Data region must contain valid `ExecveHeader` + `ExecveSegment` array + segment data.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::too_many_lines
)]
unsafe fn execute_execve(
    tls: *mut MicroTls,
    cq: &CqEntry,
    micro: &MicroState,
) -> ! {
    let data_region_ptr = unsafe { micro.ring_base.add(micro.layout.data_region_offset) };
    let data_base = unsafe { data_region_ptr.add(cq.data_offset as usize) };

    // Read the header.
    let header = unsafe { &*(data_base.cast::<ExecveHeader>()) };

    // Read the segments array (immediately after the header).
    let segments_ptr = unsafe { data_base.add(core::mem::size_of::<ExecveHeader>()) };
    let num_segments = header.num_segments as usize;

    // ── Parse argv/envp and build stack BEFORE mapping segments ─────────
    //
    // CRITICAL: All heap allocations and complex data manipulation must
    // happen before the segment mapping loop. The segment mapping uses
    // MAP_FIXED which can overwrite parts of the old binary's data segments,
    // corrupting glibc's malloc arena locks (accessed via FS-based TLS).
    // Any heap allocation after segment mapping would call glibc malloc,
    // which would find its internal locks in a corrupt state and block
    // forever on a futex wait.
    //
    // The data region is in shared memory (at a high address), so it's
    // safe to read from before or after mapping. We use stack-allocated
    // fixed-size arrays to avoid any heap allocation.

    let argv_data = unsafe {
        core::slice::from_raw_parts(
            data_base.add(header.argv_offset as usize),
            header.argv_len as usize,
        )
    };
    let envp_data = unsafe {
        core::slice::from_raw_parts(
            data_base.add(header.envp_offset as usize),
            header.envp_len as usize,
        )
    };

    // Split NUL-separated strings into stack-allocated fixed-size arrays.
    let empty: &[u8] = &[];
    let mut argv_strings = [empty; MAX_STRINGS];
    let argc = split_nul_strings_into(argv_data, header.argc as usize, &mut argv_strings);
    let mut envp_strings = [empty; MAX_STRINGS];
    let envc = split_nul_strings_into(envp_data, header.envc as usize, &mut envp_strings);

    let argv_refs: &[&[u8]] = &argv_strings[..argc];
    let envp_refs: &[&[u8]] = &envp_strings[..envc];

    // Allocate a new stack (must happen before segment mapping too).
    let stack_ret = unsafe {
        crate::raw_syscall::mmap(
            0,
            STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_STACK | libc::MAP_GROWSDOWN,
            -1,
            0,
        )
    };
    let stack_base = stack_ret as usize;
    if crate::raw_syscall::is_error(stack_ret) {
        unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 127) };
        unreachable!();
    }

    let stack_pointer = build_exec_stack(stack_base, STACK_SIZE, argv_refs, envp_refs, header);

    let entry_point = header.entry_point as usize;

    // Set the emulated guest brk to the end of the new binary's segments.
    // The kernel's real brk cannot be moved to the new binary's address range
    // (it stays at the host process's original brk), so micro emulates brk
    // by tracking this value and using mmap/munmap for the guest.
    micro
        .guest_brk
        .store(header.brk as usize, core::sync::atomic::Ordering::Release);

    // Initialize the anonymous mmap bump allocator from the range central
    // reserved for us.  After this, anonymous mmap(NULL, ...) calls can be
    // handled locally without a ring round-trip.
    if header.mmap_bump_start != 0 {
        micro.mmap_bump_next.store(
            header.mmap_bump_start as usize,
            core::sync::atomic::Ordering::Release,
        );
        // mmap_bump_end is not atomic — safe to write here because we are
        // single-threaded at this point (post-execve, pre-entry).  We go
        // through the raw MicroState pointer to avoid UB from &T → &mut T.
        let micro_ptr = unsafe { (*tls).micro };
        unsafe { (*micro_ptr).mmap_bump_end = header.mmap_bump_end as usize };
    }

    // ── Map segments (point of no return) ──────────────────────────────
    //
    // After this point, no heap allocations or glibc calls are safe.
    // Only raw syscalls via inline asm are allowed.
    //
    // Coalesced mapping: instead of one mmap per segment (~11 kernel
    // calls), we do two bulk mmaps — one for the main binary's entire
    // virtual address range and one for the interpreter's.  Then we
    // memcpy each segment's data and mprotect to final permissions.
    // Gaps between segments within each range are protected PROT_NONE.

    // ── Phase 1: Range-level mmap — one per binary ────────────────────
    //
    // Instead of bulk anonymous mmap + per-segment file-backed mmap overlays
    // (~12 kernel calls), we do 1-2 mmaps per binary:
    //   1. A single file-backed mmap(MAP_FIXED, MAP_PRIVATE, aligned_fd, file_base)
    //      covering the file-backed portion of the virtual range.
    //   2. If the virtual range extends beyond the file data (BSS tail),
    //      an anonymous mmap for the remainder.
    //
    // This works because the entire ELF file is contiguous in the aligned
    // memfd and ELF segments maintain a constant vaddr-to-file-offset
    // relationship.  Gaps between segments within each range are later
    // protected with PROT_NONE.

    let main_base = header.main_range_base as usize;
    let main_len = header.main_range_len as usize;
    let interp_base = header.interp_range_base as usize;
    let interp_len = header.interp_range_len as usize;

    // Track whether file-backed range mmaps actually succeeded.
    let mut main_file_mmap_ok = false;
    let mut interp_file_mmap_ok = false;

    // Map main binary range.
    if main_len > 0 {
        let file_base = header.main_file_base_offset;
        let file_map_len = header.main_file_map_len as usize;

        if file_base != u64::MAX && file_map_len > 0 && micro.aligned_fd >= 0 {
            // File-backed mmap covering the entire main binary's file data.
            let ret = unsafe {
                crate::raw_syscall::mmap(
                    main_base,
                    file_map_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_FIXED | libc::MAP_PRIVATE,
                    micro.aligned_fd,
                    file_base as i64,
                )
            };
            if crate::raw_syscall::is_error(ret) {
                // Fallback to anonymous mmap for the whole range.
                let ret2 = unsafe {
                    crate::raw_syscall::mmap(
                        main_base,
                        main_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                if crate::raw_syscall::is_error(ret2) {
                    unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 127) };
                    unreachable!();
                }

            } else {
                main_file_mmap_ok = true;

                // If the virtual range extends beyond file data (BSS tail),
                // map the remainder as anonymous.
                if main_len > file_map_len {
                    let bss_base = main_base + file_map_len;
                    let bss_len = main_len - file_map_len;
                    let ret2 = unsafe {
                        crate::raw_syscall::mmap(
                            bss_base,
                            bss_len,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                            -1,
                            0,
                        )
                    };
                    if crate::raw_syscall::is_error(ret2) {
                        unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 127) };
                        unreachable!();
                    }
    
                }
            }
        } else {
            // No aligned memfd — anonymous mmap for the whole range.
            let ret = unsafe {
                crate::raw_syscall::mmap(
                    main_base,
                    main_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if crate::raw_syscall::is_error(ret) {
                unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 127) };
                unreachable!();
            }
        }
    }

    // Map interpreter range.
    if interp_len > 0 {
        let file_base = header.interp_file_base_offset;
        let file_map_len = header.interp_file_map_len as usize;

        if file_base != u64::MAX && file_map_len > 0 && micro.aligned_fd >= 0 {
            let ret = unsafe {
                crate::raw_syscall::mmap(
                    interp_base,
                    file_map_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_FIXED | libc::MAP_PRIVATE,
                    micro.aligned_fd,
                    file_base as i64,
                )
            };
            if crate::raw_syscall::is_error(ret) {
                let ret2 = unsafe {
                    crate::raw_syscall::mmap(
                        interp_base,
                        interp_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                if crate::raw_syscall::is_error(ret2) {
                    unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 127) };
                    unreachable!();
                }

            } else {
                interp_file_mmap_ok = true;
                if interp_len > file_map_len {
                    let bss_base = interp_base + file_map_len;
                    let bss_len = interp_len - file_map_len;
                    let ret2 = unsafe {
                        crate::raw_syscall::mmap(
                            bss_base,
                            bss_len,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                            -1,
                            0,
                        )
                    };
                    if crate::raw_syscall::is_error(ret2) {
                        unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 127) };
                        unreachable!();
                    }
    
                }
            }
        } else {
            let ret = unsafe {
                crate::raw_syscall::mmap(
                    interp_base,
                    interp_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if crate::raw_syscall::is_error(ret) {
                unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 127) };
                unreachable!();
            }
        }
    }

    // ── Phase 2: Copy data + set permissions per segment ──────────────
    //
    // The bulk mmap already created RW anonymous pages across each
    // binary's entire span.  We only need to memcpy file data into each
    // segment and then mprotect segments whose final permissions differ
    // from RW.

    // Track segment extents for gap computation (max 16 segments per range).
    // Each entry is (vaddr, end_vaddr).
    let mut main_extents: [core::mem::MaybeUninit<(usize, usize)>; MAX_SEGS_PER_RANGE] =
        unsafe { core::mem::MaybeUninit::uninit().assume_init() };
    let mut interp_extents: [core::mem::MaybeUninit<(usize, usize)>; MAX_SEGS_PER_RANGE] =
        unsafe { core::mem::MaybeUninit::uninit().assume_init() };
    let mut main_ext_count: usize = 0;
    let mut interp_ext_count: usize = 0;

    // Track trampolines for deferred RX mprotect (max 2: one per binary).
    let mut tramp_mprotects: [(usize, usize); 2] = [(0, 0); 2];
    let mut tramp_mprotect_count: usize = 0;

    // ── Pass 1: BSS zeroing + non-tar data copy + trampoline patching ──
    //
    // The range-level mmap in Phase 1 already placed file-backed data for
    // tar-backed binaries.  We only need to:
    //   (a) Zero BSS within file-backed pages (data past p_filesz may
    //       contain section headers or trampoline data).
    //   (b) Copy data for non-tar segments from the ring data region.
    //   (c) Patch trampoline code while pages are still RW.
    //
    // Use the tracked mmap success flags instead of re-checking header
    // fields, since the mmap itself may have failed even when headers
    // indicated file-backed mapping was possible.
    let main_range_mapped = main_file_mmap_ok;
    let interp_range_mapped = interp_file_mmap_ok;

    for i in 0..num_segments {
        let seg = unsafe {
            &*(segments_ptr
                .add(i * core::mem::size_of::<ExecveSegment>())
                .cast::<ExecveSegment>())
        };

        let vaddr = seg.vaddr as usize;
        let map_len = seg.map_len as usize;
        let data_len = seg.data_len as usize;

        if map_len == 0 {
            continue;
        }

        if data_len > 0 && seg.tar_data_offset != u64::MAX {
            // Tar-backed segment.
            //
            // Check if this segment's binary had a successful range-level mmap
            // AND that the range-level mmap placed the data at the correct
            // virtual address for this specific segment.
            //
            // Range-level mmap assumes a constant vaddr-to-file-offset mapping:
            //   data at vaddr V comes from memfd offset (file_base + V - range_base)
            // But this invariant can break in PIE binaries where the linker
            // inserts a virtual address gap between RO and RW segments (for
            // RELRO).  When it breaks, the data at this segment's vaddr is
            // from the WRONG file offset and must be corrected via memcpy.
            let in_main_range = main_len > 0
                && vaddr >= main_base
                && vaddr + map_len <= main_base + main_len;
            let (range_mapped, range_base, file_base_offset) = if in_main_range {
                (main_range_mapped, main_base, header.main_file_base_offset)
            } else {
                (interp_range_mapped, interp_base, header.interp_file_base_offset)
            };

            // Check if the range-level mmap placed data correctly for THIS segment.
            // Expected memfd offset = file_base_offset + (vaddr - range_base)
            // Actual per-segment memfd offset = seg.tar_data_offset
            let data_correctly_placed = if range_mapped && file_base_offset != u64::MAX {
                let expected = file_base_offset as usize + (vaddr - range_base);
                expected == seg.tar_data_offset as usize
            } else {
                false
            };

            if !data_correctly_placed {
                // Range-level mmap wasn't used or placed wrong data — memcpy.
                let tar_off = seg.tar_data_offset as usize;
                if micro.aligned_base.is_null() || tar_off + data_len > micro.aligned_size {
                    unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 127) };
                }
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        micro.aligned_base.add(tar_off),
                        vaddr as *mut u8,
                        data_len,
                    );
                }
            }

            // Zero BSS within the file-backed portion of tar-backed segments.
            //
            // The raw file data past p_filesz may contain section headers,
            // trampoline data, or other non-zero bytes.  The ELF spec requires
            // BSS to be zero, so we zero from bss_zero_offset to data_len.
            let bss_off = seg.bss_zero_offset as usize;
            if bss_off < data_len {
                unsafe {
                    core::ptr::write_bytes((vaddr + bss_off) as *mut u8, 0, data_len - bss_off);
                }
            }
        } else if data_len > 0 {
            // Ring data region path (non-tar binary, tar_data_offset == u64::MAX)
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data_base.add(seg.data_offset as usize),
                    vaddr as *mut u8,
                    data_len,
                );
            }
        }

        // Handle trampoline data: copy + patch while still writable.
        if seg.has_trampoline != 0 {
            let tramp_desc_ptr = if seg.tar_data_offset == u64::MAX {
                // Non-tar: trampoline desc follows file data in ring
                unsafe { data_base.add(seg.data_offset as usize + data_len) }
            } else {
                // Tar-backed: trampoline desc is at data_offset directly (no file data in ring)
                unsafe { data_base.add(seg.data_offset as usize) }
            };
            let tramp_vaddr_offset = unsafe {
                u32::from_le_bytes(
                    core::slice::from_raw_parts(tramp_desc_ptr, 4)
                        .try_into()
                        .unwrap(),
                ) as usize
            };
            let tramp_size = unsafe {
                u32::from_le_bytes(
                    core::slice::from_raw_parts(tramp_desc_ptr.add(4), 4)
                        .try_into()
                        .unwrap(),
                ) as usize
            };

            if tramp_size > 0 {
                let tramp_data_src = unsafe { tramp_desc_ptr.add(8) };
                let tramp_addr = tramp_vaddr_offset;
                let tramp_page_size = (tramp_size + 0xFFF) & !0xFFF;

                // Copy trampoline code (region is still RW from bulk mmap).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        tramp_data_src,
                        tramp_addr as *mut u8,
                        tramp_size,
                    );
                }

                // Patch the syscall entry point at offset 0 with micro's
                // own trampoline entry (central sends 0 as a placeholder).
                let entry_addr = crate::trampoline::get_syscall_entry_point() as u64;
                unsafe {
                    *(tramp_addr as *mut u64) = entry_addr;
                }

                // Defer mprotect(RX) to pass 2.
                if tramp_mprotect_count < 2 {
                    tramp_mprotects[tramp_mprotect_count] = (tramp_addr, tramp_page_size);
                    tramp_mprotect_count += 1;
                }

                // Record trampoline extent for gap computation.
                let tramp_end = tramp_addr + tramp_page_size;
                if main_len > 0
                    && tramp_addr >= main_base
                    && tramp_end <= main_base + main_len
                    && main_ext_count < MAX_SEGS_PER_RANGE
                {
                    main_extents[main_ext_count].write((tramp_addr, tramp_end));
                    main_ext_count += 1;
                } else if interp_len > 0
                    && tramp_addr >= interp_base
                    && tramp_end <= interp_base + interp_len
                    && interp_ext_count < MAX_SEGS_PER_RANGE
                {
                    interp_extents[interp_ext_count].write((tramp_addr, tramp_end));
                    interp_ext_count += 1;
                }
            }
        }

        // Record this segment's extent for gap computation.
        let seg_end = vaddr + map_len;
        if main_len > 0
            && vaddr >= main_base
            && seg_end <= main_base + main_len
            && main_ext_count < MAX_SEGS_PER_RANGE
        {
            main_extents[main_ext_count].write((vaddr, seg_end));
            main_ext_count += 1;
        } else if interp_len > 0
            && vaddr >= interp_base
            && seg_end <= interp_base + interp_len
            && interp_ext_count < MAX_SEGS_PER_RANGE
        {
            interp_extents[interp_ext_count].write((vaddr, seg_end));
            interp_ext_count += 1;
        }
    }

    // ── Pass 2: Set final permissions (coalesced) ─────────────────────
    //
    // Collect all segments + trampolines that need non-RW permissions,
    // sort by vaddr, and merge adjacent entries with the same prot into
    // single mprotect calls.  This reduces kernel syscalls from O(segments)
    // to O(distinct protection regions).

    // Max entries: num_segments + 2 trampolines.
    #[allow(clippy::items_after_statements)]
    const MAX_PROT_ENTRIES: usize = 18;
    let mut prot_entries: [(usize, usize, i32); MAX_PROT_ENTRIES] = [(0, 0, 0); MAX_PROT_ENTRIES];
    let mut prot_count: usize = 0;

    // Collect segment entries that need non-RW protection.
    for i in 0..num_segments {
        let seg = unsafe {
            &*(segments_ptr
                .add(i * core::mem::size_of::<ExecveSegment>())
                .cast::<ExecveSegment>())
        };
        let vaddr = seg.vaddr as usize;
        let map_len = seg.map_len as usize;
        let final_prot = seg.prot as i32;

        if map_len == 0 {
            continue;
        }
        if final_prot != (libc::PROT_READ | libc::PROT_WRITE) && prot_count < MAX_PROT_ENTRIES {
            prot_entries[prot_count] = (vaddr, map_len, final_prot);
            prot_count += 1;
        }
    }

    // Add trampoline entries (RX protection).
    for &(addr, size) in tramp_mprotects.iter().take(tramp_mprotect_count) {
        if prot_count < MAX_PROT_ENTRIES {
            prot_entries[prot_count] = (addr, size, libc::PROT_READ | libc::PROT_EXEC);
            prot_count += 1;
        }
    }

    // Sort by vaddr (insertion sort — small array, no_std).
    for i in 1..prot_count {
        let mut j = i;
        while j > 0 && prot_entries[j].0 < prot_entries[j - 1].0 {
            prot_entries.swap(j, j - 1);
            j -= 1;
        }
    }

    // Merge adjacent entries with the same prot and emit coalesced mprotect calls.
    {
        let mut i = 0;
        while i < prot_count {
            let mut end = prot_entries[i].0 + prot_entries[i].1;
            let prot = prot_entries[i].2;
            let start = prot_entries[i].0;

            // Merge with subsequent entries that have the same prot and are
            // adjacent (or overlapping).
            let mut j = i + 1;
            while j < prot_count && prot_entries[j].2 == prot && prot_entries[j].0 <= end {
                let j_end = prot_entries[j].0 + prot_entries[j].1;
                if j_end > end {
                    end = j_end;
                }
                j += 1;
            }

            unsafe { crate::raw_syscall::mprotect(start, end - start, prot) };

            i = j;
        }
    }

    // ── Phase 3: Protect gaps between segments with PROT_NONE ─────────
    //
    // Walk each range's extents in address order.  Any gap between
    // consecutive extents (or between range boundary and first/last
    // extent) is mprotect'd to PROT_NONE so stray accesses fault.

    protect_range_gaps(main_base, main_len, &main_extents, main_ext_count);
    protect_range_gaps(interp_base, interp_len, &interp_extents, interp_ext_count);

    // Jump to the new entry point. This never returns.
    //
    // CRITICAL: The arch_prctl(ARCH_SET_FS, 0) to reset the FS base MUST
    // happen inside the inline asm block, not via a Rust libc::syscall()
    // call. After FS is zeroed, ANY Rust-generated code that accesses
    // %fs:0x28 (stack canary) will SIGSEGV. By doing it in asm, we
    // guarantee no compiler-generated TLS accesses occur between the
    // reset and the jump to the new entry point.
    //
    // Note: The program break is NOT reset here via a raw brk() syscall
    // because the kernel's mm->start_brk is fixed at process creation
    // time and cannot be lowered to the new binary's address range.
    // Instead, brk is emulated in micro's local_exec handler using the
    // guest_brk field in MicroState.
    //
    // Register strategy: we use r12/r13 to hold stack_pointer/entry_point
    // across the arch_prctl syscall (syscall clobbers rax, rcx, r11).
    // r12/r13 are callee-saved and not touched by `syscall`.
    unsafe {
        core::arch::asm!(
            // Save values in callee-saved registers across the syscall.
            "mov r12, rcx",     // r12 = stack_pointer
            "mov r13, rdx",     // r13 = entry_point
            // Reset FS base to 0 via arch_prctl(ARCH_SET_FS, 0).
            // This lets the new ld-linux set up fresh glibc TLS.
            // GS base is left intact — it points to micro's own TLS.
            "mov rax, 158",     // SYS_arch_prctl
            "mov rdi, 0x1002",  // ARCH_SET_FS
            "xor rsi, rsi",     // addr = 0
            "syscall",
            // Set up new stack and jump.
            "mov rsp, r12",
            // Use an absolute jump instead of push+ret to avoid
            // any potential stack issues.
            "jmp r13",
            in("rcx") stack_pointer,
            in("rdx") entry_point,
            options(noreturn),
        );
    }
}

/// Maximum number of argv/envp entries supported in execve.
const MAX_STRINGS: usize = 1024;

/// Split NUL-separated byte data into individual NUL-terminated string slices,
/// storing results in a caller-provided fixed-size array.
///
/// Each returned slice includes its trailing NUL byte.
/// Returns the number of entries actually written to `out`.
fn split_nul_strings_into<'a>(
    data: &'a [u8],
    count: usize,
    out: &mut [&'a [u8]; MAX_STRINGS],
) -> usize {
    let n = count.min(MAX_STRINGS);
    let mut pos = 0;
    let mut written = 0;
    for _ in 0..n {
        if pos >= data.len() {
            break;
        }
        // Find the NUL terminator.
        let end = data[pos..]
            .iter()
            .position(|&b| b == 0)
            .map_or(data.len(), |p| pos + p + 1);
        out[written] = &data[pos..end];
        written += 1;
        pos = end;
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execve_header_size() {
        // Verify the struct is a reasonable size (no unexpected padding).
        let size = core::mem::size_of::<ExecveHeader>();
        assert!(size > 0);
        // ExecveHeader has: 2*u32 + 4*u64 + 2*u32 + u64 + 2*u32 + 4*u32 + u64 + 2*u64 + 4*u64 + 4*u64
        // = 8 + 32 + 8 + 8 + 8 + 16 + 8 + 16 + 32 + 32 = 168 bytes
        assert_eq!(size, 168);
    }

    #[test]
    fn execve_segment_size() {
        let size = core::mem::size_of::<ExecveSegment>();
        // ExecveSegment: 3*u64 + 2*u32 + 3*u64 = 24 + 8 + 24 = 56 bytes
        assert_eq!(size, 56);
    }

    #[test]
    fn serialize_execve_args_basic() {
        let mut buf = [0u8; 1024];
        let path = c"/bin/hello";
        let arg0 = c"/bin/hello";
        let arg1 = c"world";
        let argv: [*const i8; 3] = [arg0.as_ptr(), arg1.as_ptr(), core::ptr::null()];
        let env0 = c"HOME=/root";
        let envp: [*const i8; 2] = [env0.as_ptr(), core::ptr::null()];

        let len = unsafe { serialize_execve_args(&mut buf, path, argv.as_ptr(), envp.as_ptr()) };
        assert!(len.is_some());
        let len = len.unwrap();
        assert!(len > 0);

        // Verify path length.
        let path_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert_eq!(path_len, 11); // "/bin/hello\0"
    }

    #[test]
    fn split_nul_strings_basic() {
        let data = b"hello\0world\0";
        let empty: &[u8] = &[];
        let mut out = [empty; MAX_STRINGS];
        let count = split_nul_strings_into(data, 2, &mut out);
        assert_eq!(count, 2);
        assert_eq!(out[0], b"hello\0");
        assert_eq!(out[1], b"world\0");
    }

    #[test]
    fn build_exec_stack_basic() {
        // Allocate a test stack.
        let stack_size: usize = 64 * 1024;
        let base_ret = unsafe {
            crate::raw_syscall::mmap(
                0,
                stack_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert!(!crate::raw_syscall::is_error(base_ret));
        let base = base_ret as usize;

        let argv: [&[u8]; 2] = [b"./hello\0", b"world\0"];
        let envp: [&[u8]; 1] = [b"HOME=/root\0"];
        let header = ExecveHeader {
            num_segments: 0,
            pad0: 0,
            entry_point: 0x400000,
            at_entry: 0x400000,
            brk: 0x600000,
            phdr_addr: 0x400040,
            phnum: 4,
            phent: 56,
            interp_base: 0,
            argc: 2,
            envc: 1,
            argv_offset: 0,
            argv_len: 0,
            envp_offset: 0,
            envp_len: 0,
            syscall_entry_point: 0,
            mmap_bump_start: 0,
            mmap_bump_end: 0,
            main_range_base: 0,
            main_range_len: 0,
            interp_range_base: 0,
            interp_range_len: 0,
            main_file_base_offset: u64::MAX,
            main_file_map_len: 0,
            interp_file_base_offset: u64::MAX,
            interp_file_map_len: 0,
        };

        let sp = build_exec_stack(base, stack_size, &argv, &envp, &header);

        // SP must be 16-byte aligned.
        assert_eq!(sp % 16, 0, "SP is not 16-byte aligned");
        assert!(sp >= base);
        assert!(sp < base + stack_size);

        // Read argc.
        let argc = unsafe { *(sp as *const usize) };
        assert_eq!(argc, 2);

        // Clean up.
        unsafe { crate::raw_syscall::munmap(base, stack_size) };
    }
}
