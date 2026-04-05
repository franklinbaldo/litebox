// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Core syscall handler called from the assembly trampoline.

use core::sync::atomic::Ordering::{Acquire, Relaxed};

use litebox_ipc::cq::{cq_find_by_seq, cq_tail};
use litebox_ipc::ring::{CqEntry, RingHeader, SharedRingLayout, SqEntry, cq_flags};
use litebox_ipc::sq::{sq_acquire_slot, sq_publish};

use litebox_ipc::wait::spin_then_wait;

use crate::local_exec::execute_locally;
use crate::tls::MicroTls;
use crate::trampoline::SyscallArgs;

fn futex_wake(addr: &core::sync::atomic::AtomicU32) {
    unsafe {
        crate::raw_syscall::futex4(core::ptr::from_ref(addr) as usize, libc::FUTEX_WAKE, 1, 0);
    }
}

/// Handle `sendmsg(fd, msg, flags)` by gathering the iovec data from the
/// guest's `msghdr` and sending it as a regular `SYS_write` to central.
///
/// This allows socketpair fds (virtual, managed by central's shim) to work
/// without full msghdr marshaling. Ancillary data (e.g. `SCM_RIGHTS`) is
/// silently dropped — nginx's basic master→worker channel commands work
/// without it.
///
/// # Safety
///
/// - `tls` must point to a valid, initialized `MicroTls`.
/// - `args` must point to a valid `SyscallArgs` with `sendmsg` arguments.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
unsafe fn handle_sendmsg_as_write(tls: *mut MicroTls, args: &SyscallArgs) -> i64 {
    let fd = args.args[0];
    let msg_ptr = args.args[1] as *const u8;
    // flags = args.args[2]; // ignored for the write conversion

    if msg_ptr.is_null() {
        return -i64::from(libc::EFAULT);
    }

    // Read msghdr fields from guest memory.
    // struct msghdr layout on x86-64:
    //   msg_name:       *mut void    (8 bytes, offset 0)
    //   msg_namelen:    socklen_t    (4 bytes, offset 8)
    //   _pad:           4 bytes      (offset 12, for alignment)
    //   msg_iov:        *mut iovec   (8 bytes, offset 16)
    //   msg_iovlen:     size_t       (8 bytes, offset 24)
    //   msg_control:    *mut void    (8 bytes, offset 32)
    //   msg_controllen: size_t       (8 bytes, offset 40)
    //   msg_flags:      int          (4 bytes, offset 48)
    let iov_ptr =
        unsafe { core::ptr::read_unaligned(msg_ptr.add(16).cast::<usize>()) } as *const u8;
    let iov_len = unsafe { core::ptr::read_unaligned(msg_ptr.add(24).cast::<usize>()) };

    if iov_ptr.is_null() || iov_len == 0 {
        return 0; // nothing to send
    }

    // Gather iovec data into a stack buffer.
    // nginx channel messages are small (≤32 bytes), so 4096 is plenty.
    let mut buf = core::mem::MaybeUninit::<[u8; 4096]>::uninit();
    let buf_ptr = buf.as_mut_ptr().cast::<u8>();
    let mut total = 0usize;

    for i in 0..iov_len {
        let iov_entry = unsafe { iov_ptr.add(i * IOVEC_SIZE) };
        let base = unsafe { core::ptr::read_unaligned(iov_entry.cast::<usize>()) } as *const u8;
        let len = unsafe { core::ptr::read_unaligned(iov_entry.add(8).cast::<usize>()) };

        if base.is_null() || len == 0 {
            continue;
        }

        let remaining = 4096 - total;
        let copy_len = len.min(remaining);
        if copy_len == 0 {
            break;
        }

        unsafe { core::ptr::copy_nonoverlapping(base, buf_ptr.add(total), copy_len) };
        total += copy_len;
    }

    if total == 0 {
        return 0;
    }

    // Rewrite as SYS_write(fd, buf, total).
    let write_args = [fd, buf_ptr as u64, total as u64, 0, 0, 0];
    let cq = unsafe {
        submit_and_wait(
            tls,
            libc::SYS_write as u32,
            &write_args,
            litebox_ipc::ring::sq_flags::NEED_AUTH,
        )
    };

    if cq.flags & cq_flags::EXEC_LOCAL != 0 {
        // Central says exec locally — this shouldn't happen for write,
        // but handle it gracefully.
        return cq.result;
    }

    cq.result
}

/// Handle `recvmsg(fd, msg, flags)` by reading data from central via
/// `SYS_read` and scattering it into the guest's iovec.
///
/// Ancillary data is not supported — `msg_controllen` is set to 0.
///
/// # Safety
///
/// - `tls` must point to a valid, initialized `MicroTls`.
/// - `args` must point to a valid `SyscallArgs` with `recvmsg` arguments.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::ptr_cast_constness
)]
unsafe fn handle_recvmsg_as_read(tls: *mut MicroTls, args: &SyscallArgs) -> i64 {
    let fd = args.args[0];
    let msg_ptr = args.args[1] as *mut u8;
    // flags = args.args[2]; // ignored for the read conversion

    if msg_ptr.is_null() {
        return -i64::from(libc::EFAULT);
    }

    // Read msg_control and msg_controllen BEFORE processing, so we can zero
    // the control buffer after the read to prevent the caller from parsing
    // stale cmsg data.
    let msg_control =
        unsafe { core::ptr::read_unaligned(msg_ptr.add(32).cast::<usize>()) } as *mut u8;
    let msg_controllen = unsafe { core::ptr::read_unaligned(msg_ptr.add(40).cast::<usize>()) };

    // Read iovec info from msghdr.
    let iov_ptr = unsafe { core::ptr::read_unaligned(msg_ptr.add(16).cast::<usize>()) } as *mut u8;
    let iov_len = unsafe { core::ptr::read_unaligned(msg_ptr.add(24).cast::<usize>()) };

    if iov_ptr.is_null() || iov_len == 0 {
        return 0;
    }

    // Calculate total iovec capacity.
    let mut total_capacity = 0usize;
    for i in 0..iov_len {
        let iov_entry = unsafe { iov_ptr.add(i * IOVEC_SIZE) };
        let len = unsafe { core::ptr::read_unaligned(iov_entry.add(8).cast::<usize>()) };
        total_capacity += len;
    }

    let read_len = total_capacity.min(4096);
    if read_len == 0 {
        return 0;
    }

    // Read into a stack buffer.
    let mut buf = core::mem::MaybeUninit::<[u8; 4096]>::uninit();
    let buf_ptr = buf.as_mut_ptr().cast::<u8>();

    let read_args = [fd, buf_ptr as u64, read_len as u64, 0, 0, 0];
    let cq = unsafe {
        submit_and_wait(
            tls,
            libc::SYS_read as u32,
            &read_args,
            litebox_ipc::ring::sq_flags::NEED_AUTH,
        )
    };

    let bytes_read = if cq.flags & cq_flags::EXEC_LOCAL != 0 {
        // Central returned data via shmem data region.
        if cq.result < 0 {
            return cq.result;
        }
        let n = cq.result as usize;
        if cq.flags & cq_flags::HAS_DATA != 0 && n > 0 {
            let micro = unsafe { &*(*tls).micro };
            let data_src = unsafe {
                micro
                    .ring_base
                    .add(micro.layout.data_region_offset)
                    .add(cq.data_offset as usize)
            };
            let copy_len = n.min(4096);
            unsafe { core::ptr::copy_nonoverlapping(data_src, buf_ptr, copy_len) };
            copy_len
        } else {
            n
        }
    } else {
        if cq.result < 0 {
            return cq.result;
        }
        cq.result as usize
    };

    // Scatter into iovec.
    let mut offset = 0usize;
    for i in 0..iov_len {
        if offset >= bytes_read {
            break;
        }
        let iov_entry = unsafe { (iov_ptr as *const u8).add(i * IOVEC_SIZE) };
        let base = unsafe { core::ptr::read_unaligned(iov_entry.cast::<usize>()) } as *mut u8;
        let len = unsafe { core::ptr::read_unaligned(iov_entry.add(8).cast::<usize>()) };

        if base.is_null() || len == 0 {
            continue;
        }

        let copy_len = len.min(bytes_read - offset);
        unsafe { core::ptr::copy_nonoverlapping(buf_ptr.add(offset), base, copy_len) };
        offset += copy_len;
    }

    // Fake ancillary data: construct a valid SCM_RIGHTS cmsghdr with fd=-1
    // so callers like nginx's ngx_read_channel() that unconditionally parse
    // ancillary data for OPEN_CHANNEL commands won't error out.
    // cmsghdr layout on x86-64:
    //   cmsg_len:   size_t (8 bytes, offset 0)  = CMSG_LEN(sizeof(int)) = 20
    //   cmsg_level: int    (4 bytes, offset 8)   = SOL_SOCKET = 1
    //   cmsg_type:  int    (4 bytes, offset 12)  = SCM_RIGHTS = 1
    //   data:       int    (4 bytes, offset 16)  = fd = -1
    // Total: 20 bytes (CMSG_LEN), padded to 24 (CMSG_SPACE).
    if !msg_control.is_null() && msg_controllen >= 24 {
        // Zero the buffer first to clear any stale data.
        let zero_len = msg_controllen.min(256);
        unsafe { core::ptr::write_bytes(msg_control, 0, zero_len) };
        // Write fake cmsghdr.
        unsafe { core::ptr::write_unaligned(msg_control.cast::<u64>(), 20) }; // cmsg_len = 20
        unsafe { core::ptr::write_unaligned(msg_control.add(8).cast::<i32>(), 1) }; // cmsg_level = SOL_SOCKET
        unsafe { core::ptr::write_unaligned(msg_control.add(12).cast::<i32>(), 1) }; // cmsg_type = SCM_RIGHTS
        unsafe { core::ptr::write_unaligned(msg_control.add(16).cast::<i32>(), -1) }; // fd = -1
        // Set msg_controllen to CMSG_SPACE(sizeof(int)) = 24.
        unsafe { core::ptr::write_unaligned(msg_ptr.add(40).cast::<usize>(), 24) };
    } else if !msg_control.is_null() && msg_controllen > 0 {
        // Buffer too small for a fake cmsghdr — just zero everything.
        let zero_len = msg_controllen.min(256);
        unsafe { core::ptr::write_bytes(msg_control, 0, zero_len) };
        unsafe { core::ptr::write_unaligned(msg_ptr.add(40).cast::<usize>(), 0) };
    } else {
        unsafe { core::ptr::write_unaligned(msg_ptr.add(40).cast::<usize>(), 0) };
    }
    unsafe { core::ptr::write_unaligned(msg_ptr.add(48).cast::<i32>(), 0) }; // msg_flags = 0

    offset as i64
}

/// Like [`futex_wait`] but with a 100 ms timeout so micro can periodically
/// check whether central is still alive.
fn futex_wait_timed(addr: &core::sync::atomic::AtomicU32, expected: u32) {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000, // 100 ms
    };
    unsafe {
        crate::raw_syscall::futex4(
            core::ptr::from_ref(addr) as usize,
            libc::FUTEX_WAIT,
            expected,
            core::ptr::from_ref(&ts) as usize,
        );
    }
}

/// Check whether central is still alive.  If not, terminate micro immediately.
///
/// Two-tier detection:
/// 1. Fast path — `header.is_exiting` is set cooperatively by central on
///    normal exit or panic.
/// 2. Slow path — open `/proc/<pid>/status` and check for zombie state or
///    non-existence.  Unlike `kill(pid, 0)`, this correctly detects zombies
///    (which `kill` reports as alive since the PID still exists).
pub(crate) fn check_central_alive(header: &RingHeader, central_pid: u32) {
    // Fast: cooperative flag.
    if header.is_exiting.load(Relaxed) != 0 {
        unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 1) };
    }
    // Slow: probe whether central is alive and not a zombie.
    if central_pid != 0 && !is_process_alive(central_pid) {
        unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 1) };
    }
}

/// Check if a process is alive (exists and is not a zombie) by reading
/// `/proc/<pid>/status`.  Returns `false` if the process does not exist
/// or is in zombie state.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn is_process_alive(pid: u32) -> bool {
    // Build "/proc/<pid>/status\0" on the stack.  Max PID is ~4 million
    // (7 digits), so 32 bytes is plenty.  Use MaybeUninit to avoid SSE-
    // aligned zeroing (movaps) which faults when the stack is only 8-byte
    // aligned in the micro syscall context.
    let mut buf: core::mem::MaybeUninit<[u8; 32]> = core::mem::MaybeUninit::uninit();
    let buf_ptr = buf.as_mut_ptr().cast::<u8>();
    let prefix = b"/proc/";
    unsafe { core::ptr::copy_nonoverlapping(prefix.as_ptr(), buf_ptr, prefix.len()) };
    let mut pos = prefix.len();

    // Write PID digits.
    let mut digits = [0u8; 10];
    let mut n = pid;
    let mut dlen = 0;
    if n == 0 {
        digits[0] = b'0';
        dlen = 1;
    } else {
        while n > 0 {
            digits[dlen] = b'0' + (n % 10) as u8;
            n /= 10;
            dlen += 1;
        }
        // Reverse digits.
        let mut i = 0;
        let mut j = dlen - 1;
        while i < j {
            digits.swap(i, j);
            i += 1;
            j -= 1;
        }
    }
    unsafe { core::ptr::copy_nonoverlapping(digits.as_ptr(), buf_ptr.add(pos), dlen) };
    pos += dlen;

    let suffix = b"/status\0";
    unsafe { core::ptr::copy_nonoverlapping(suffix.as_ptr(), buf_ptr.add(pos), suffix.len()) };

    // Open the file.
    let fd = unsafe { crate::raw_syscall::open(buf_ptr, libc::O_RDONLY) };
    if fd < 0 {
        // ENOENT / ESRCH — process is gone.
        return false;
    }

    // Read enough to find the "State:" line.  The first ~200 bytes of
    // /proc/<pid>/status contain Name:, Umask:, State:, etc.
    // Use MaybeUninit to avoid aligned zeroing on the stack.
    let mut rbuf: core::mem::MaybeUninit<[u8; 256]> = core::mem::MaybeUninit::uninit();
    let rbuf_ptr = rbuf.as_mut_ptr().cast::<u8>();
    let nread = unsafe { crate::raw_syscall::read(fd as i32, rbuf_ptr, 256) };
    unsafe { crate::raw_syscall::close(fd as i32) };

    if nread <= 0 {
        return false;
    }

    // Search for "State:\tZ" in the buffer.
    let len = nread as usize;
    let pattern = b"State:\tZ";
    if len >= pattern.len() {
        let mut i = 0;
        while i + pattern.len() <= len {
            let matches = unsafe {
                let slice = core::slice::from_raw_parts(rbuf_ptr.add(i), pattern.len());
                slice == pattern.as_slice()
            };
            if matches {
                // Zombie detected.
                return false;
            }
            i += 1;
        }
    }

    true
}

#[inline]
#[allow(clippy::cast_ptr_alignment)] // ring_base is guaranteed to be properly aligned
unsafe fn ring_ptrs(
    base: *mut u8,
    layout: &SharedRingLayout,
) -> (&'static RingHeader, *mut SqEntry, *const CqEntry) {
    let header = unsafe { &*(base.cast::<RingHeader>()) };
    let sq_entries = unsafe { base.add(layout.sq_entries_offset).cast::<SqEntry>() };
    let cq_entries = unsafe { base.add(layout.cq_entries_offset).cast::<CqEntry>() };
    (header, sq_entries, cq_entries)
}

/// Per-thread region size in the data region for pathname transfer.
const PATHNAME_REGION_SIZE: usize = 4096;

/// Returns the argument index that contains a pathname pointer for the given
/// syscall, or `None` if the syscall doesn't carry a pathname argument that
/// central needs to dereference.
#[allow(clippy::cast_possible_truncation)]
fn pathname_arg_index(nr: u32) -> Option<usize> {
    #[allow(clippy::match_same_arms)] // arms kept separate for per-syscall documentation
    match i64::from(nr) {
        libc::SYS_openat => Some(1),     // openat(dirfd, pathname, flags, mode)
        libc::SYS_open => Some(0),       // open(pathname, flags, mode)
        libc::SYS_creat => Some(0),      // creat(pathname, mode)
        libc::SYS_access => Some(0),     // access(pathname, mode)
        libc::SYS_stat => Some(0),       // stat(pathname, statbuf)
        libc::SYS_lstat => Some(0),      // lstat(pathname, statbuf)
        libc::SYS_readlink => Some(0),   // readlink(pathname, buf, bufsiz)
        libc::SYS_readlinkat => Some(1), // readlinkat(dirfd, pathname, buf, bufsiz)
        libc::SYS_unlink => Some(0),     // unlink(pathname)
        libc::SYS_chdir => Some(0),      // chdir(pathname)
        libc::SYS_mkdir => Some(0),      // mkdir(pathname, mode)
        libc::SYS_unlinkat => Some(1),   // unlinkat(dirfd, pathname, flags)
        libc::SYS_newfstatat
            if {
                // newfstatat(dirfd, pathname, statbuf, flags)
                // Only if pathname != empty string (AT_EMPTY_PATH uses fd only)
                true
            } =>
        {
            Some(1)
        }
        libc::SYS_faccessat => Some(1), // faccessat(dirfd, pathname, mode)
        libc::SYS_faccessat2 => Some(1), // faccessat2(dirfd, pathname, mode, flags)
        _ => None,
    }
}

/// Copy the pathname string from the guest's memory into the shared data
/// region. Updates the SQ entry's `data_offset` and `data_len` fields.
///
/// Each thread uses a 4 KiB region at `thread_slot * 4096` within the data
/// region, avoiding conflicts between concurrent threads.
///
/// # Safety
///
/// The pathname pointer (from `args`) must be a valid C string in the guest's
/// address space.
fn copy_pathname_to_data_region(
    entry: &mut SqEntry,
    args: &[u64; 6],
    syscall_nr: u32,
    ring_base: *mut u8,
    layout: &SharedRingLayout,
) {
    let Some(arg_idx) = pathname_arg_index(syscall_nr) else {
        return;
    };

    let pathname_ptr = args[arg_idx] as *const u8;
    if pathname_ptr.is_null() {
        return;
    }

    // Read the pathname as a C string (NUL-terminated) from guest memory.
    // SAFETY: The guest passed this pointer as a syscall argument, so it
    // should point to a valid NUL-terminated string in guest memory.
    let cstr = unsafe { core::ffi::CStr::from_ptr(pathname_ptr.cast()) };
    let bytes = cstr.to_bytes_with_nul();

    // Compute per-thread offset in the data region.
    let thread_offset = entry.thread_slot as usize * PATHNAME_REGION_SIZE;
    let max_len = PATHNAME_REGION_SIZE.min(bytes.len());
    if thread_offset + max_len > layout.data_region_size {
        // Data region too small — skip the copy. Central will segfault,
        // but this shouldn't happen with the default 4 MiB region.
        return;
    }

    // Copy into the data region.
    unsafe {
        let dst = ring_base.add(layout.data_region_offset + thread_offset);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, max_len);
    }

    #[allow(clippy::cast_possible_truncation)]
    {
        entry.data_offset = thread_offset as u32;
        entry.data_len = max_len as u32;
    }
}

/// Base offset in the data region where write data starts.
///
/// Pathname slots use `thread_slot * PATHNAME_REGION_SIZE` (up to
/// `MAX_PATHNAME_SLOTS * 4096 = 256 * 4096 = 1 MiB`).  Write data is placed
/// past all pathname slots to avoid conflicts with concurrent pathname
/// transfers from other threads.
const WRITE_DATA_BASE_OFFSET: usize = 256 * PATHNAME_REGION_SIZE; // 1 MiB

/// Per-thread region size for write data in the data region (64 KiB).
///
/// Each thread can write up to this many bytes per syscall. Writes larger
/// than this are capped (the kernel will return a short write).
const WRITE_DATA_REGION_SIZE: usize = 65536;

/// Size of a single `iovec` struct on x86-64 (16 bytes: `iov_base` + `iov_len`).
const IOVEC_SIZE: usize = 16;

/// Returns `(buf_arg_index, count_arg_index)` for write-family syscalls,
/// or `None` if this is not a write syscall.
#[allow(clippy::cast_possible_truncation)]
fn write_data_arg_info(nr: u32) -> Option<(usize, usize)> {
    #[allow(clippy::match_same_arms)] // arms kept separate for per-syscall documentation
    match i64::from(nr) {
        libc::SYS_write => Some((1, 2)),    // write(fd, buf, count)
        libc::SYS_pwrite64 => Some((1, 2)), // pwrite64(fd, buf, count, offset)
        libc::SYS_sendto => Some((1, 2)),   // sendto(fd, buf, len, flags, dest_addr, addrlen)
        _ => None,
    }
}

/// Copy write data from the guest's memory into the shared data region.
///
/// Updates the SQ entry's `data_offset` and `data_len` fields so central
/// knows where to find the data.
///
/// Each thread uses a separate region in the data region past the pathname
/// slots: `WRITE_DATA_BASE_OFFSET + thread_slot * WRITE_DATA_REGION_SIZE`.
///
/// # Safety
///
/// The buffer pointer (from `args`) must point to valid readable memory of
/// at least `count` bytes in the guest's address space.
#[allow(clippy::cast_possible_truncation)]
fn copy_write_data_to_data_region(
    entry: &mut SqEntry,
    args: &[u64; 6],
    syscall_nr: u32,
    ring_base: *mut u8,
    layout: &SharedRingLayout,
) {
    let Some((buf_idx, count_idx)) = write_data_arg_info(syscall_nr) else {
        return;
    };

    let buf_ptr = args[buf_idx] as *const u8;
    let count = args[count_idx] as usize;

    if buf_ptr.is_null() || count == 0 {
        return;
    }

    // Compute per-thread offset in the write data zone.
    let thread_offset =
        WRITE_DATA_BASE_OFFSET + entry.thread_slot as usize * WRITE_DATA_REGION_SIZE;
    let max_len = count.min(WRITE_DATA_REGION_SIZE);
    if thread_offset + max_len > layout.data_region_size {
        // Data region too small — skip the copy.
        return;
    }

    // Copy from guest memory into the data region.
    unsafe {
        let dst = ring_base.add(layout.data_region_offset + thread_offset);
        core::ptr::copy_nonoverlapping(buf_ptr, dst, max_len);
    }

    #[allow(clippy::cast_possible_truncation)]
    {
        entry.data_offset = thread_offset as u32;
        entry.data_len = max_len as u32;
    }
}

/// Copy the destination sockaddr for `sendto` into the shmem write-data zone,
/// appended immediately after the send buffer data.
///
/// `copy_write_data_to_data_region` has already placed the send buffer at
/// `[data_offset..data_offset + send_len)`. This function appends the
/// sockaddr at `[data_offset + send_len..data_offset + send_len + addrlen)`
/// and updates `entry.data_len` to include both.
///
/// # Safety
///
/// The dest_addr pointer (from `args[4]`) must point to valid readable memory
/// of at least `addrlen` (args[5]) bytes in the guest's address space.
#[allow(clippy::cast_possible_truncation)]
fn copy_sendto_sockaddr_to_data_region(
    entry: &mut SqEntry,
    args: &[u64; 6],
    syscall_nr: u32,
    ring_base: *mut u8,
    layout: &SharedRingLayout,
) {
    if i64::from(syscall_nr) != libc::SYS_sendto {
        return;
    }

    let dest_addr = args[4] as *const u8;
    let addrlen = args[5] as usize;

    if dest_addr.is_null() || addrlen == 0 {
        return;
    }

    // The send buffer was already placed at entry.data_offset with length
    // entry.data_len by copy_write_data_to_data_region. Append sockaddr after it.
    let send_data_end = entry.data_offset as usize + entry.data_len as usize;
    if send_data_end + addrlen > layout.data_region_size {
        // Not enough room — skip sockaddr copy (sendto will proceed without it).
        return;
    }

    unsafe {
        let dst = ring_base.add(layout.data_region_offset + send_data_end);
        core::ptr::copy_nonoverlapping(dest_addr, dst, addrlen);
    }

    entry.data_len += addrlen as u32;
}

/// Returns `true` for scatter/gather write-family syscalls (writev, pwritev,
/// pwritev2).
#[allow(clippy::cast_possible_truncation)]
fn is_writev_family(nr: u32) -> bool {
    matches!(
        i64::from(nr),
        libc::SYS_writev | libc::SYS_pwritev | libc::SYS_pwritev2
    )
}

/// Gather iovec data from the guest's memory into the shared data region.
///
/// For writev-family syscalls, micro reads the iovec array from the guest,
/// concatenates all buffers into a single contiguous region in the shmem
/// data zone (the same per-thread slot used by `copy_write_data_to_data_region`),
/// and sets `entry.data_offset` / `entry.data_len` so central can dispatch
/// the gathered data as a flat write through the shim.
///
/// # Safety
///
/// The iov pointer (from `args[1]`) must point to a valid array of `iovcnt`
/// `iovec` structs in the guest's address space, and each `iov_base` must
/// point to valid readable memory of `iov_len` bytes.
#[allow(clippy::cast_possible_truncation)]
fn copy_writev_data_to_data_region(
    entry: &mut SqEntry,
    args: &[u64; 6],
    syscall_nr: u32,
    ring_base: *mut u8,
    layout: &SharedRingLayout,
) {
    if !is_writev_family(syscall_nr) {
        return;
    }

    let iov_ptr = args[1] as *const u8;
    let iovcnt = args[2] as usize;

    if iov_ptr.is_null() || iovcnt == 0 {
        return;
    }

    // Compute per-thread offset in the write data zone.
    let thread_offset =
        WRITE_DATA_BASE_OFFSET + entry.thread_slot as usize * WRITE_DATA_REGION_SIZE;

    // Each iovec is 16 bytes on x86-64: { iov_base: *const u8, iov_len: usize }.
    let mut total_copied: usize = 0;

    for i in 0..iovcnt {
        // Read iov_base and iov_len from the guest's iovec array.
        let iov_entry_ptr = unsafe { iov_ptr.add(i * IOVEC_SIZE) };
        let iov_base =
            unsafe { core::ptr::read_unaligned(iov_entry_ptr.cast::<u64>()) } as *const u8;
        let iov_len =
            unsafe { core::ptr::read_unaligned(iov_entry_ptr.add(8).cast::<u64>()) } as usize;

        if iov_base.is_null() || iov_len == 0 {
            continue;
        }

        let remaining = WRITE_DATA_REGION_SIZE.saturating_sub(total_copied);
        if remaining == 0 {
            break;
        }
        let copy_len = iov_len.min(remaining);

        if thread_offset + total_copied + copy_len > layout.data_region_size {
            // Data region too small — stop copying.
            break;
        }

        unsafe {
            let dst = ring_base.add(layout.data_region_offset + thread_offset + total_copied);
            core::ptr::copy_nonoverlapping(iov_base, dst, copy_len);
        }

        total_copied += copy_len;
    }

    if total_copied > 0 {
        entry.data_offset = thread_offset as u32;
        entry.data_len = total_copied as u32;
    }
}

/// Copy socket input data (sockaddr for connect/bind, optval for setsockopt)
/// from the guest's memory into the shared data region.
///
/// These syscalls carry pointer arguments that central cannot dereference
/// (separate address space). Micro copies the data into the per-thread
/// pathname zone (`thread_slot * 4096`) and sets `entry.data_offset` /
/// `entry.data_len` so central can read it.
///
/// SAFETY: connect/bind/setsockopt are NOT pathname syscalls and NOT
/// write-data syscalls, so the existing copy functions won't touch
/// `entry.data_offset`/`entry.data_len` for these syscalls.
///
/// # Safety
///
/// The pointer argument (sockaddr or optval) must point to valid readable
/// memory of at least the specified size in the guest's address space.
#[allow(clippy::cast_possible_truncation)]
fn copy_socket_input_to_data_region(
    entry: &mut SqEntry,
    args: &[u64; 6],
    syscall_nr: u32,
    ring_base: *mut u8,
    layout: &SharedRingLayout,
) {
    // Determine pointer arg index and data size for syscalls where central
    // needs input data from the guest's memory.
    let (ptr_idx, data_size) = match i64::from(syscall_nr) {
        // connect/bind(fd, sockaddr*, addrlen) — sockaddr at arg1, size at arg2
        libc::SYS_connect | libc::SYS_bind => (1usize, args[2] as usize),
        // setsockopt(fd, level, optname, optval*, optlen) — optval at arg3, size at arg4
        libc::SYS_setsockopt => (3, args[4] as usize),
        // ioctl(fd, request, arg) — for FIONBIO (0x5421) and FIOASYNC (0x5452), arg at index 2 is int*
        libc::SYS_ioctl if args[1] == 0x5421 || args[1] == 0x5452 => (2, 4),
        // epoll_ctl(epfd, op, fd, event*) — event at arg3, 12 bytes (packed epoll_event)
        // For EPOLL_CTL_DEL (op=2), event is ignored/NULL.
        libc::SYS_epoll_ctl if args[1] != 2 && args[3] != 0 => (3, 12),
        _ => return,
    };

    let data_ptr = args[ptr_idx] as *const u8;

    if data_ptr.is_null() || data_size == 0 {
        return;
    }

    // Compute per-thread offset in the pathname zone of the data region.
    let thread_offset = entry.thread_slot as usize * PATHNAME_REGION_SIZE;
    let max_len = data_size.min(PATHNAME_REGION_SIZE);
    if thread_offset + max_len > layout.data_region_size {
        return;
    }

    // Copy from guest memory into the data region.
    unsafe {
        let dst = ring_base.add(layout.data_region_offset + thread_offset);
        core::ptr::copy_nonoverlapping(data_ptr, dst, max_len);
    }

    entry.data_offset = thread_offset as u32;
    entry.data_len = max_len as u32;
}

/// Returns `(input_arg_index, input_size)` for bidirectional syscalls where
/// central needs input data from the guest's memory. Returns `None` if the
/// syscall has no input pointer, or the pointer is NULL.
///
/// Currently only `prlimit64` is bidirectional through central.
#[allow(clippy::cast_possible_truncation)]
fn bidirectional_input_info(nr: u32, args: &[u64; 6]) -> Option<(usize, usize)> {
    match i64::from(nr) {
        libc::SYS_prlimit64 => {
            // prlimit64(pid, resource, new_limit, old_limit): input=arg2 (new_limit)
            // Rlimit64 = 16 bytes (2 × u64)
            if args[2] != 0 { Some((2, 16)) } else { None }
        }
        _ => None,
    }
}

/// Copy input data for bidirectional syscalls from the guest's memory into
/// the shared data region, so central can pass it to the shim.
///
/// Uses the same write-data zone as `copy_write_data_to_data_region`:
/// `WRITE_DATA_BASE_OFFSET + thread_slot * WRITE_DATA_REGION_SIZE`.
///
/// # Safety
///
/// The input pointer (from `args`) must point to valid readable memory of
/// at least `size` bytes in the guest's address space.
#[allow(clippy::cast_possible_truncation)]
fn copy_bidirectional_input_to_data_region(
    entry: &mut SqEntry,
    args: &[u64; 6],
    syscall_nr: u32,
    ring_base: *mut u8,
    layout: &SharedRingLayout,
) {
    let Some((input_idx, input_size)) = bidirectional_input_info(syscall_nr, args) else {
        return;
    };

    let input_ptr = args[input_idx] as *const u8;
    if input_ptr.is_null() || input_size == 0 {
        return;
    }

    // Use the write data zone (same offset scheme as write data).
    let thread_offset =
        WRITE_DATA_BASE_OFFSET + entry.thread_slot as usize * WRITE_DATA_REGION_SIZE;
    if thread_offset + input_size > layout.data_region_size {
        return;
    }

    // Copy input data from guest memory into the data region.
    unsafe {
        let dst = ring_base.add(layout.data_region_offset + thread_offset);
        core::ptr::copy_nonoverlapping(input_ptr, dst, input_size);
    }

    entry.data_offset = thread_offset as u32;
    entry.data_len = input_size as u32;
}

/// Submit an `SqEntry` and wait for the corresponding `CqEntry`.
///
/// # Safety
///
/// - `tls` must point to a valid, initialized `MicroTls`.
/// - The ring buffer referenced by the TLS must be valid and properly mapped.
#[allow(clippy::cast_possible_truncation)] // slot indices and thread_slot fit in smaller types
pub(crate) unsafe fn submit_and_wait(
    tls: *mut MicroTls,
    syscall_nr: u32,
    args: &[u64; 6],
    flags: u16,
) -> CqEntry {
    let micro = unsafe { &*(*tls).micro };
    let (header, sq_entries, cq_entries) = unsafe { ring_ptrs(micro.ring_base, &micro.layout) };

    let seq = unsafe { (*tls).seq_counter };
    unsafe { (*tls).seq_counter += 1 };

    // Capture the CQ tail BEFORE publishing the SQ entry so that we
    // don't miss a fast completion that arrives before we start scanning.
    let thread_slot = unsafe { (*tls).thread_slot as u16 };
    let notify_slot = &header.cq_notify_slots[thread_slot as usize];
    let search_start = cq_tail(header);

    let slot_idx = unsafe { sq_acquire_slot(header) };
    let entry = unsafe { &mut *sq_entries.add(slot_idx as usize) };

    entry.seq = seq;
    entry.syscall_nr = syscall_nr;
    entry.thread_slot = thread_slot;
    entry.flags = flags;
    entry.args = *args;
    entry.data_offset = 0;
    entry.data_len = 0;

    // For pathname syscalls, copy the pathname string from the guest's address
    // space into the shared data region so central can read it (central is a
    // separate process and cannot dereference guest pointers directly).
    copy_pathname_to_data_region(entry, args, syscall_nr, micro.ring_base, &micro.layout);

    // For write-family syscalls, copy the write buffer from the guest's
    // address space into the data region so central can dispatch through
    // the shim (which may handle virtual fds).
    copy_write_data_to_data_region(entry, args, syscall_nr, micro.ring_base, &micro.layout);

    // For sendto, append the destination sockaddr after the send buffer
    // in the shmem write-data zone so central can pass it to the shim.
    copy_sendto_sockaddr_to_data_region(entry, args, syscall_nr, micro.ring_base, &micro.layout);

    // For scatter/gather write syscalls (writev, pwritev, pwritev2), gather
    // the iovec buffers into a contiguous flat buffer in the data region.
    copy_writev_data_to_data_region(entry, args, syscall_nr, micro.ring_base, &micro.layout);

    // For bidirectional syscalls (prlimit64), copy the input struct from
    // the guest's memory so central can pass it to the shim.
    // Note: rt_sigaction, rt_sigprocmask, sigaltstack are now Tier 2
    // (notify-after-execute) and no longer go through this path.
    copy_bidirectional_input_to_data_region(
        entry,
        args,
        syscall_nr,
        micro.ring_base,
        &micro.layout,
    );

    // For socket input syscalls (connect, bind, setsockopt), copy the
    // sockaddr/optval from guest memory into the shmem pathname zone.
    copy_socket_input_to_data_region(entry, args, syscall_nr, micro.ring_base, &micro.layout);

    sq_publish(entry);
    header
        .sq_notify
        .fetch_add(1, core::sync::atomic::Ordering::Release);
    // Only issue FUTEX_WAKE if central has entered futex sleep.
    if header
        .sq_consumer_sleeping
        .load(core::sync::atomic::Ordering::Acquire)
        != 0
    {
        futex_wake(&header.sq_notify);
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
            // Set our sleeping bit so central can skip FUTEX_WAKE.
            let bit = 1u64 << unsafe { (*tls).thread_slot };
            header
                .cq_consumers_sleeping
                .fetch_or(bit, core::sync::atomic::Ordering::Release);
            // Re-check before sleeping to avoid lost wake.
            if addr.load(core::sync::atomic::Ordering::Acquire) != exp {
                header
                    .cq_consumers_sleeping
                    .fetch_and(!bit, core::sync::atomic::Ordering::Relaxed);
                return;
            }
            futex_wait_timed(addr, exp);
            header
                .cq_consumers_sleeping
                .fetch_and(!bit, core::sync::atomic::Ordering::Relaxed);
            // After the futex times out (or spurious wake), check whether
            // central has signalled that it is shutting down.
            check_central_alive(header, micro.central_pid);
        });
    }
}

/// Report the result of a locally-executed syscall back to central.
///
/// # Safety
///
/// - `tls` must point to a valid, initialized `MicroTls`.
#[allow(clippy::cast_sign_loss)] // result is intentionally reinterpreted as u64 for transport
unsafe fn report_local_result(tls: *mut MicroTls, original_seq: u64, result: i64) {
    let args = [original_seq, result.cast_unsigned(), 0, 0, 0, 0];
    unsafe {
        submit_and_wait(tls, litebox_ipc::messages::MSG_LOCAL_RESULT, &args, 0);
    }
}

/// Send a fire-and-forget notification to central.
///
/// Publishes an SQ entry with the `NOTIFY_ONLY` flag. Central will process
/// the notification (update state tracking) but will NOT write a CQ response.
/// Micro returns immediately without waiting.
///
/// # Safety
///
/// - `tls` must point to a valid, initialized `MicroTls`.
/// - The ring buffer referenced by the TLS must be valid and properly mapped.
#[allow(clippy::cast_possible_truncation)]
pub(crate) unsafe fn notify_central(tls: *mut MicroTls, syscall_nr: u32, args: &[u64; 6]) {
    let micro = unsafe { &*(*tls).micro };
    let (header, sq_entries, _cq_entries) = unsafe { ring_ptrs(micro.ring_base, &micro.layout) };

    let seq = unsafe { (*tls).seq_counter };
    unsafe { (*tls).seq_counter += 1 };

    let thread_slot = unsafe { (*tls).thread_slot as u16 };

    let slot_idx = unsafe { sq_acquire_slot(header) };
    let entry = unsafe { &mut *sq_entries.add(slot_idx as usize) };

    entry.seq = seq;
    entry.syscall_nr = syscall_nr;
    entry.thread_slot = thread_slot;
    entry.flags = litebox_ipc::ring::sq_flags::NOTIFY_ONLY;
    entry.args = *args;
    entry.data_offset = 0;
    entry.data_len = 0;

    sq_publish(entry);
    header
        .sq_notify
        .fetch_add(1, core::sync::atomic::Ordering::Release);
    // Only issue FUTEX_WAKE if central has entered futex sleep.
    if header
        .sq_consumer_sleeping
        .load(core::sync::atomic::Ordering::Acquire)
        != 0
    {
        futex_wake(&header.sq_notify);
    }
    // No CQ wait — fire and forget.
}

/// Handle a read-only `prlimit64(0, resource, NULL, old_limit)` entirely in
/// micro without a ring round-trip.
///
/// Returns the same hardcoded virtual rlimit values that central's shim uses.
/// The `Rlimit64` struct is `{ rlim_cur: u64, rlim_max: u64 }` = 16 bytes.
fn handle_prlimit64_readonly(resource: u32, old_limit_ptr: *mut u8) -> i64 {
    // Resource constants from <linux/resource.h>:
    const RLIMIT_STACK: u32 = 3;
    const RLIMIT_CORE: u32 = 4;
    const RLIMIT_NOFILE: u32 = 7;
    const NUM_RESOURCES: u32 = 16;

    if resource >= NUM_RESOURCES {
        return -i64::from(libc::EINVAL);
    }

    // Virtual rlimit values (matching litebox_shim_linux::ResourceLimits::default):
    // - STACK:  cur = 8 MiB, max = INFINITY
    // - CORE:   cur = 0,     max = INFINITY
    // - NOFILE: cur = 1M,    max = 1M
    // - All others: cur = INFINITY, max = INFINITY
    let (cur, max): (u64, u64) = match resource {
        RLIMIT_STACK => (8_388_608, u64::MAX),
        RLIMIT_CORE => (0, u64::MAX),
        RLIMIT_NOFILE => (1_048_576, 1_048_576),
        _ => (u64::MAX, u64::MAX),
    };

    // Write the Rlimit64 struct to the guest's output buffer.
    // SAFETY: the guest provided a valid pointer for the old_limit output.
    unsafe {
        core::ptr::write_unaligned(old_limit_ptr.cast::<u64>(), cur);
        core::ptr::write_unaligned(old_limit_ptr.add(8).cast::<u64>(), max);
    }
    0 // success
}

/// Tier 1: Syscalls that execute locally with NO notification to central.
/// These create no state, or only state that lives in micro's memory
/// (fork-copies correctly without central needing to know).
pub(crate) fn is_tier1_micro_local(nr: u32) -> bool {
    matches!(
        i64::from(nr),
        // Process/user identity: return virtual values from MicroState.
        // set* variants are no-ops (guest is always virtual root).
        libc::SYS_getpid
            | libc::SYS_getppid
            | libc::SYS_getuid
            | libc::SYS_getgid
            | libc::SYS_geteuid
            | libc::SYS_getegid
            | libc::SYS_setuid
            | libc::SYS_setgid
            | libc::SYS_setreuid
            | libc::SYS_setregid
            | libc::SYS_setresuid
            | libc::SYS_setresgid
            | libc::SYS_getresuid
            | libc::SYS_getresgid
            | libc::SYS_getgroups
            | libc::SYS_setgroups
            // Sleep: blocking, no state change
            | libc::SYS_nanosleep
            | libc::SYS_clock_nanosleep
            // Thread setup: thread-local only, correct after fork by definition
            | libc::SYS_arch_prctl
            | libc::SYS_set_tid_address
            | libc::SYS_set_robust_list
            | libc::SYS_rseq
            | libc::SYS_rt_sigsuspend
            // Time queries: read-only, no state in central.
            // Raw host syscall gives correct wall-clock / monotonic time.
            | libc::SYS_clock_gettime
            | libc::SYS_clock_getres
            | libc::SYS_gettimeofday
            | libc::SYS_time
            // Memory query: read-only on micro's address space
            | libc::SYS_mincore
            // Filesystem sync: no-op (central owns the filesystem)
            | libc::SYS_sync
    )
}

/// Tier 2: Syscalls that execute locally but MUST notify central of the
/// state change for fork reconstruction. Micro executes first, then sends
/// a fire-and-forget notification.
pub(crate) fn is_tier2_notify(nr: u32) -> bool {
    matches!(
        i64::from(nr),
        // Signal state: micro executes locally, notifies central for fork reconstruction.
        libc::SYS_rt_sigaction
        | libc::SYS_rt_sigprocmask
        | libc::SYS_sigaltstack
        // Alarm: creates kernel timer that fork does NOT inherit.
        | libc::SYS_alarm
        // Wait: reaps children, consumes SIGCHLD — destructive.
        | libc::SYS_wait4
        // VMA operations: must execute in micro's address space, notify central for VMA tracking.
        | libc::SYS_munmap
        | libc::SYS_mprotect
        | libc::SYS_madvise
        // umask: process-local, but central's shim uses get_umask() for open/creat/mkdir.
        | libc::SYS_umask
    )
}

/// Main syscall handler called from the assembly trampoline.
///
/// # Safety
///
/// - `args` must point to a valid `SyscallArgs` struct on the stack.
/// - GS-based TLS must have been initialized for the current thread.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation)] // syscall number constants always fit in u32
pub unsafe extern "C" fn micro_handle_syscall(args: *const SyscallArgs) -> i64 {
    let args = unsafe { &*args };
    let tls = unsafe { crate::tls::current_tls() };

    let nr = args.nr as u32;

    // TRAMP-CHECK removed — was causing segfault that killed process before fork.

    // Execve: special handling — serialize args and manage the exec protocol.
    if nr == libc::SYS_execve as u32 {
        return unsafe { crate::execve::handle_execve(tls, args) };
    }

    // Tier 1: silent micro-local — no notification to central.
    if is_tier1_micro_local(nr) {
        return unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
    }

    // Tier 2: execute locally, then notify central for state tracking.
    if is_tier2_notify(nr) {
        let result = unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
        let notify_nr = crate::local_exec::tier2_notify_message(nr);
        let notify_args = unsafe { crate::local_exec::tier2_notify_args(nr, &args.args, result) };
        unsafe { notify_central(tls, notify_nr, &notify_args) };
        return result;
    }

    // brk fast-path: post-execve, brk is entirely managed by micro's
    // guest_brk watermark. Central does zero work for brk.
    if nr == libc::SYS_brk as u32 {
        let state = unsafe { crate::state::global_micro_state() };
        let current = state.guest_brk.load(core::sync::atomic::Ordering::Acquire);
        if current != 0 {
            return unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
        }
        // Pre-execve: fall through to central round-trip.
    }

    // Linux AIO stubs: nginx (Alpine, compiled with --with-file-aio) probes
    // AIO support via io_setup() during event module init and treats ENOSYS
    // as fatal. Stub io_setup to return success with a dummy context so
    // nginx can start. With `aio off;` in nginx.conf, no actual AIO
    // operations are submitted.
    #[allow(clippy::cast_possible_truncation)]
    if nr == libc::SYS_io_setup as u32 {
        // io_setup(unsigned nr_events, aio_context_t *ctx_idp)
        // Write a dummy non-zero context ID to *ctx_idp and return 0.
        let ctx_ptr = args.args[1] as *mut u64;
        if !ctx_ptr.is_null() {
            unsafe { core::ptr::write(ctx_ptr, 0xdead_a100_u64) };
        }
        return 0;
    }
    if matches!(
        i64::from(nr),
        libc::SYS_io_destroy | libc::SYS_io_getevents | libc::SYS_io_submit | libc::SYS_io_cancel
    ) {
        // Stub: return 0 (no events, no submissions).
        return 0;
    }

    // prlimit64 fast-path: read-only queries (pid == 0 or self, new_limit == NULL)
    // are handled entirely in micro using the same hardcoded virtual rlimit
    // values that central's shim returns.  This eliminates one ring round-trip
    // per exec (ld-linux queries RLIMIT_STACK on every startup).
    #[allow(clippy::cast_possible_truncation)]
    if nr == libc::SYS_prlimit64 as u32 {
        let pid = args.args[0];
        let new_limit = args.args[2];
        let old_limit = args.args[3];
        if (pid == 0) && new_limit == 0 && old_limit != 0 {
            return handle_prlimit64_readonly(args.args[1] as u32, old_limit as *mut u8);
        }
        // Write case or pid != 0: fall through to central round-trip.
    }

    // Anonymous mmap(NULL) fast-path: use the bump allocator to avoid a
    // ring round-trip.  ld-linux issues ~1 anonymous mmap(NULL) call per
    // exec; handling it locally saves ~144 µs per exec.
    //
    // Conditions: addr == NULL, MAP_ANONYMOUS set, MAP_FIXED not set, fd == -1.
    // The bump allocator hands out addresses from a pre-reserved range
    // (MMAP_BUMP_START..MMAP_BUMP_END) and sends a Tier 2 fire-and-forget
    // notification so central can track the VMA for fork reconstruction.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    if nr == libc::SYS_mmap as u32 {
        let addr = args.args[0];
        let len = args.args[1] as usize;
        let prot = args.args[2] as i32;
        let flags = args.args[3] as i32;
        let fd = args.args[4] as i32;

        let is_anon = flags & libc::MAP_ANONYMOUS != 0;
        let is_fixed = flags & libc::MAP_FIXED != 0;

        if addr == 0 && is_anon && !is_fixed && fd == -1 && len > 0 {
            let state = unsafe { crate::state::global_micro_state() };
            let bump_end = state.mmap_bump_end;

            if bump_end != 0 {
                // Page-align the requested length.
                let aligned_len = (len + 0xFFF) & !0xFFF;
                let next = state
                    .mmap_bump_next
                    .fetch_add(aligned_len, core::sync::atomic::Ordering::Relaxed);

                if next + aligned_len <= bump_end {
                    // Execute the mmap locally with MAP_FIXED at the bump address.
                    let result = unsafe {
                        crate::raw_syscall::mmap(
                            next,
                            aligned_len,
                            prot,
                            (flags | libc::MAP_FIXED) & !libc::MAP_GROWSDOWN,
                            -1,
                            0,
                        )
                    };

                    if crate::raw_syscall::is_error(result) {
                        // Roll back the bump pointer on failure.
                        state
                            .mmap_bump_next
                            .fetch_sub(aligned_len, core::sync::atomic::Ordering::Relaxed);
                        return result;
                    }

                    // Tier 2 notification: tell central about the new mapping.
                    // Protocol: addr, len, prot, flags, 0, 0
                    let notify_args = [
                        next as u64,
                        aligned_len as u64,
                        #[allow(clippy::cast_sign_loss)]
                        {
                            prot as u64
                        },
                        u64::from(flags.cast_unsigned()),
                        0,
                        0,
                    ];
                    unsafe {
                        notify_central(tls, litebox_ipc::messages::MSG_NOTIFY_MMAP, &notify_args);
                    }

                    return result;
                }
                // Bump allocator exhausted — roll back and fall through to central.
                state
                    .mmap_bump_next
                    .fetch_sub(aligned_len, core::sync::atomic::Ordering::Relaxed);
            }
            // bump_end == 0 means pre-execve or not initialized; fall through.
        }
        // Non-anonymous, MAP_FIXED, or explicit addr: fall through to central.
    }

    // Unregister file fd tracking on close.  File I/O still goes through
    // central, but micro tracks which fds have shmem slots so it must drop
    // the mapping before the fd is actually closed.
    #[allow(clippy::cast_possible_truncation)]
    if i64::from(nr) == libc::SYS_close {
        let fd = args.args[0] as i32;
        let micro_mut = unsafe { &mut *(*tls).micro };
        micro_mut.unregister_file_fd(fd);
        // Fall through to submit_and_wait for central to handle close + slot cleanup
    }

    // For dup2/dup3 the target fd (args[1]) may have a file shmem slot.
    // Unregister it before submitting, since central will free the old slot.
    #[allow(clippy::cast_possible_truncation)]
    if matches!(i64::from(nr), libc::SYS_dup2 | libc::SYS_dup3) {
        let target_fd = args.args[1] as i32;
        let micro_mut = unsafe { &mut *(*tls).micro };
        micro_mut.unregister_file_fd(target_fd);
    }

    // Shmem pipe fast-path: read/write on pipe fds bypass central entirely.
    {
        let micro = unsafe { &*(*tls).micro };
        let fd = args.args[0] as i32;
        if let Some((shmem_offset, is_write_end)) = micro.find_pipe_fd(fd) {
            match i64::from(nr) {
                libc::SYS_write if is_write_end => {
                    let buf = args.args[1] as *const u8;
                    let count = args.args[2] as usize;
                    return unsafe { shmem_pipe_write(micro, shmem_offset, buf, count) };
                }
                libc::SYS_read if !is_write_end => {
                    let buf = args.args[1] as *mut u8;
                    let count = args.args[2] as usize;
                    return unsafe { shmem_pipe_read(micro, shmem_offset, buf, count) };
                }
                libc::SYS_close => {
                    // Unregister the pipe fd locally, then let close fall through
                    // to central (which handles shim fd closure and shmem flags).
                    let micro_mut = unsafe { &mut *(*tls).micro };
                    micro_mut.unregister_pipe_fd(fd);
                    // Fall through to submit_and_wait for central to handle close
                }
                _ => {} // dup, fcntl, etc. — fall through to central
            }
        }
    }

    // Shmem socket fast-path: read/write/recvfrom/sendto bypass central entirely.
    // Close falls through to central for shmem cleanup.
    #[allow(clippy::cast_possible_truncation)]
    {
        let micro = unsafe { &*(*tls).micro };
        let fd = args.args[0] as i32;
        if let Some(shmem_offset) = micro.find_socket_fd(fd) {
            match i64::from(nr) {
                libc::SYS_read => {
                    let buf = args.args[1] as *mut u8;
                    let count = args.args[2] as usize;
                    return unsafe { shmem_socket_read(micro, shmem_offset, buf, count) };
                }
                libc::SYS_recvfrom => {
                    let flags = args.args[3] as i32;
                    let src_addr = args.args[4];
                    // Fast-path only when no address requested and simple flags
                    if src_addr == 0 && (flags == 0 || flags == libc::MSG_NOSIGNAL) {
                        let buf = args.args[1] as *mut u8;
                        let count = args.args[2] as usize;
                        return unsafe { shmem_socket_read(micro, shmem_offset, buf, count) };
                    }
                    // Otherwise fall through to central
                }
                libc::SYS_write => {
                    let buf = args.args[1] as *const u8;
                    let count = args.args[2] as usize;
                    return unsafe { shmem_socket_write(micro, shmem_offset, buf, count) };
                }
                libc::SYS_sendto => {
                    let flags = args.args[3] as i32;
                    let dest_addr = args.args[4];
                    if dest_addr == 0 && (flags == 0 || flags == libc::MSG_NOSIGNAL) {
                        let buf = args.args[1] as *const u8;
                        let count = args.args[2] as usize;
                        return unsafe { shmem_socket_write(micro, shmem_offset, buf, count) };
                    }
                    // Otherwise fall through to central
                }
                libc::SYS_writev => {
                    // writev(fd, iov, iovcnt) — flatten iov and write to shmem TX ring.
                    let iov_ptr = args.args[1] as *const u8;
                    let iovcnt = args.args[2] as usize;
                    return unsafe { shmem_socket_writev(micro, shmem_offset, iov_ptr, iovcnt) };
                }
                libc::SYS_close => {
                    let micro_mut = unsafe { &mut *(*tls).micro };
                    micro_mut.unregister_socket_fd(fd);
                    // Fall through to submit_and_wait for central to handle close + shmem cleanup
                }
                _ => {} // setsockopt, getsockopt, shutdown, etc. — fall through to central
            }
        }
    }

    // Tar shmem file fast-path: read/pread64 on tar-backed fds bypass central.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
    {
        let micro = unsafe { &mut *(*tls).micro };
        let fd = args.args[0] as i32;
        let tar_base = micro.tar_base;
        let tar_size = micro.tar_size;
        if let Some(entry) = micro.find_tar_file_fd_mut(fd) {
            match i64::from(nr) {
                libc::SYS_read => {
                    let buf = args.args[1] as *mut u8;
                    let count = args.args[2] as usize;
                    let remaining = entry.tar_len.saturating_sub(entry.cursor) as usize;
                    let to_read = count.min(remaining);
                    if to_read > 0 {
                        let src_offset = entry.tar_offset + entry.cursor;
                        if (src_offset as usize) + to_read > tar_size {
                            return -i64::from(libc::EIO);
                        }
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                tar_base.add(src_offset as usize),
                                buf,
                                to_read,
                            );
                        }
                        entry.cursor += to_read as u64;
                    }
                    return to_read as i64;
                }
                libc::SYS_pread64 => {
                    let buf = args.args[1] as *mut u8;
                    let count = args.args[2] as usize;
                    let offset = args.args[3];
                    if offset >= entry.tar_len {
                        return 0;
                    }
                    let remaining = (entry.tar_len - offset) as usize;
                    let to_read = count.min(remaining);
                    if to_read > 0 {
                        let src_offset = entry.tar_offset + offset;
                        if (src_offset as usize) + to_read > tar_size {
                            return -i64::from(libc::EIO);
                        }
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                tar_base.add(src_offset as usize),
                                buf,
                                to_read,
                            );
                        }
                    }
                    return to_read as i64;
                }
                _ => {} // other syscalls fall through
            }
        }
    }

    // lseek on tar-backed fds: handle locally.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )]
    if i64::from(nr) == libc::SYS_lseek {
        let micro = unsafe { &mut *(*tls).micro };
        let fd = args.args[0] as i32;
        if let Some(entry) = micro.find_tar_file_fd_mut(fd) {
            let offset = args.args[1] as i64;
            let whence = args.args[2] as i32;
            let new_pos: i64 = match whence {
                libc::SEEK_SET => offset,
                libc::SEEK_CUR => entry.cursor as i64 + offset,
                libc::SEEK_END => entry.tar_len as i64 + offset,
                _ => return -i64::from(libc::EINVAL),
            };
            if new_pos < 0 {
                return -i64::from(libc::EINVAL);
            }
            entry.cursor = new_pos as u64;
            return new_pos;
        }
    }

    // exit_group: notify central (fire-and-forget) then die immediately.
    //
    // exit_group terminates the entire process. We must NOT use submit_and_wait
    // — the child server thread sees `is_exiting()` after dispatching
    // exit_group, breaks out of its run loop, and may release/reset the
    // shared ring before we read the CQ response, causing a deadlock.
    // Instead, notify central so it can update its exiting state, then
    // execute the raw syscall which kills the process.
    //
    // Note: SYS_exit (thread exit) still uses the normal submit_and_wait
    // path because it doesn't trigger is_exiting on the primary task and
    // needs the thread deregistration round-trip.
    #[allow(clippy::cast_possible_truncation)]
    if nr == libc::SYS_exit_group as u32 {
        unsafe { notify_central(tls, nr, &args.args) };
        unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, args.args[0]) };
        // unreachable — process is dead
    }

    // sendmsg → write conversion: extract iovec data from guest's msghdr
    // and rewrite as SYS_write. This allows socketpair fds (virtual, managed
    // by central's shim) to work without implementing full msghdr marshaling.
    // Ancillary data (SCM_RIGHTS) is silently dropped — nginx can function
    // without it for basic master→worker channel commands.
    #[allow(clippy::cast_possible_truncation)]
    if nr == libc::SYS_sendmsg as u32 {
        return unsafe { handle_sendmsg_as_write(tls, args) };
    }

    // recvmsg → read conversion: similar to sendmsg, read data from central
    // and scatter into the guest's iovec.
    #[allow(clippy::cast_possible_truncation)]
    if nr == libc::SYS_recvmsg as u32 {
        return unsafe { handle_recvmsg_as_read(tls, args) };
    }

    // File shmem write pre-copy: for write-family syscalls on fds with a shmem
    // file slot, copy data into the per-fd TX ring and submit with FILE_SHMEM
    // flag. Central reads from the ring instead of the data_region.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_ptr_alignment
    )]
    if matches!(
        i64::from(nr),
        libc::SYS_write
            | libc::SYS_pwrite64
            | libc::SYS_writev
            | libc::SYS_pwritev
            | libc::SYS_pwritev2
    ) {
        let fd = args.args[0] as i32;
        let micro = unsafe { &*(*tls).micro };
        if let Some(shmem_offset) = micro.find_file_fd(fd) {
            let header = unsafe {
                micro
                    .ring_base
                    .add(micro.layout.data_region_offset)
                    .add(shmem_offset as usize)
                    .cast::<litebox_ipc::socket_ring::ShmemSocketHeader>()
            };

            match i64::from(nr) {
                libc::SYS_write | libc::SYS_pwrite64 => {
                    // Flat write: copy buffer into TX ring
                    let buf_ptr = args.args[1] as *const u8;
                    let count = args.args[2] as usize;
                    if count > 0 && !buf_ptr.is_null() {
                        let buf = unsafe { core::slice::from_raw_parts(buf_ptr, count) };
                        let written =
                            unsafe { litebox_ipc::socket_ring::socket_try_write(header, buf) };
                        if written < 0 {
                            return written;
                        }
                    }
                }
                libc::SYS_writev | libc::SYS_pwritev | libc::SYS_pwritev2 => {
                    // Scatter-gather write: flatten iovec into TX ring
                    let iov_ptr = args.args[1] as *const u8;
                    let iovcnt = args.args[2] as usize;
                    if !iov_ptr.is_null() && iovcnt > 0 {
                        for i in 0..iovcnt {
                            let iov_entry = unsafe { iov_ptr.add(i * IOVEC_SIZE) };
                            let iov_base =
                                unsafe { core::ptr::read_unaligned(iov_entry.cast::<u64>()) }
                                    as *const u8;
                            let iov_len = unsafe {
                                core::ptr::read_unaligned(iov_entry.add(8).cast::<u64>())
                            } as usize;

                            if iov_base.is_null() || iov_len == 0 {
                                continue;
                            }

                            let buf = unsafe { core::slice::from_raw_parts(iov_base, iov_len) };
                            let written =
                                unsafe { litebox_ipc::socket_ring::socket_try_write(header, buf) };
                            if written < 0 {
                                return written;
                            }
                        }
                    }
                }
                _ => {} // unreachable due to outer match
            }

            let cq = unsafe {
                submit_and_wait(
                    tls,
                    nr,
                    &args.args,
                    litebox_ipc::ring::sq_flags::NEED_AUTH
                        | litebox_ipc::ring::sq_flags::FILE_SHMEM,
                )
            };
            return cq.result;
        }
    }

    let cq =
        unsafe { submit_and_wait(tls, nr, &args.args, litebox_ipc::ring::sq_flags::NEED_AUTH) };

    if cq.flags & cq_flags::EXEC_LOCAL != 0 {
        // For SYS_exit: deregister thread before it dies
        if nr == libc::SYS_exit as u32 {
            let dereg_args = [unsafe { (*tls).thread_slot }, 0, 0, 0, 0, 0];
            unsafe {
                submit_and_wait(
                    tls,
                    litebox_ipc::messages::MSG_THREAD_DEREGISTER,
                    &dereg_args,
                    0,
                );
            }
        }

        // pipe2: central created shmem pipe, extract response from data region.
        #[allow(clippy::cast_ptr_alignment)] // data region is properly aligned for Pipe2Response
        if nr == libc::SYS_pipe2 as u32 && cq.flags & cq_flags::HAS_DATA != 0 {
            let micro = unsafe { &mut *(*tls).micro };
            let data_base = unsafe { micro.ring_base.add(micro.layout.data_region_offset) };
            let resp = unsafe {
                &*(data_base
                    .add(cq.data_offset as usize)
                    .cast::<litebox_ipc::messages::Pipe2Response>())
            };
            // Register both pipe fds for fast-path read/write.
            micro.register_pipe_fd(resp.read_fd, resp.pipe_slot_offset, false);
            micro.register_pipe_fd(resp.write_fd, resp.pipe_slot_offset, true);
            // Write fd pair to guest's output pointer.
            let fds_ptr = args.args[0] as *mut i32;
            unsafe {
                core::ptr::write(fds_ptr, resp.read_fd);
                core::ptr::write(fds_ptr.add(1), resp.write_fd);
            }
            return 0; // success
        }

        // accept/accept4: central allocated a shmem socket slot, extract
        // AcceptResponse from data region.
        #[allow(clippy::cast_ptr_alignment)] // data region is properly aligned for AcceptResponse
        if matches!(i64::from(nr), libc::SYS_accept | libc::SYS_accept4)
            && cq.flags & cq_flags::HAS_DATA != 0
            && cq.result >= 0
            && cq.data_len == core::mem::size_of::<litebox_ipc::messages::AcceptResponse>() as u32
        {
            let micro = unsafe { &mut *(*tls).micro };
            let data_base = unsafe { micro.ring_base.add(micro.layout.data_region_offset) };
            let resp = unsafe {
                &*(data_base
                    .add(cq.data_offset as usize)
                    .cast::<litebox_ipc::messages::AcceptResponse>())
            };
            micro.register_socket_fd(resp.fd, resp.socket_slot_offset);
            // Copy peer addr to guest's buffer if requested.
            let addr_ptr = args.args[1] as *mut u8;
            let addrlen_ptr = args.args[2] as *mut u32;
            if !addr_ptr.is_null() && !addrlen_ptr.is_null() {
                let copy_len = (resp.peer_addr_len as usize).min(16);
                unsafe {
                    core::ptr::copy_nonoverlapping(resp.peer_addr.as_ptr(), addr_ptr, copy_len);
                    core::ptr::write(addrlen_ptr, resp.peer_addr_len);
                }
            }
            return cq.result; // return the new fd
        }

        // open/openat/dup/dup2/dup3: central allocated a shmem file slot,
        // extract OpenResponse from data region.
        #[allow(clippy::cast_ptr_alignment)] // data region is properly aligned for OpenResponse
        if matches!(
            i64::from(nr),
            libc::SYS_open | libc::SYS_openat | libc::SYS_dup | libc::SYS_dup2 | libc::SYS_dup3
        ) && cq.flags & cq_flags::HAS_DATA != 0
            && cq.result >= 0
            && cq.data_len == core::mem::size_of::<litebox_ipc::messages::OpenResponse>() as u32
        {
            let micro = unsafe { &mut *(*tls).micro };
            let data_base = unsafe { micro.ring_base.add(micro.layout.data_region_offset) };
            let resp = unsafe {
                &*(data_base
                    .add(cq.data_offset as usize)
                    .cast::<litebox_ipc::messages::OpenResponse>())
            };
            if resp.file_slot_offset != 0 {
                micro.register_file_fd(
                    resp.fd,
                    resp.file_slot_offset,
                    resp.tar_offset,
                    resp.tar_len,
                );
            }
            return cq.result; // return the fd
        }

        // File shmem read post-copy: central placed data into the per-fd RX
        // ring. Copy it into the guest buffer and return the result directly.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_ptr_alignment
        )]
        if cq.flags & cq_flags::FILE_SHMEM_DATA != 0 && cq.result > 0 {
            let fd = args.args[0] as i32;
            let micro = unsafe { &*(*tls).micro };
            if let Some(shmem_offset) = micro.find_file_fd(fd) {
                let header = unsafe {
                    micro
                        .ring_base
                        .add(micro.layout.data_region_offset)
                        .add(shmem_offset as usize)
                        .cast::<litebox_ipc::socket_ring::ShmemSocketHeader>()
                };
                let buf_ptr = args.args[1] as *mut u8;
                let count = cq.result as usize;
                let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };
                unsafe { litebox_ipc::socket_ring::socket_try_read(header, buf) };
            }
            // NO_REPORT is set — skip report_local_result
            return cq.result;
        }

        let micro = unsafe { &*(*tls).micro };
        let result = unsafe {
            execute_locally(
                nr,
                &args.args,
                &cq,
                micro.ring_base,
                &micro.layout,
                micro.syscall_entry_point,
            )
        };

        // After a fork, the child has remapped to a new ring and already sent
        // MSG_CHILD_READY.  Sending report_local_result on the child's ring
        // would confuse central, so skip it.
        let is_fork = nr == libc::SYS_fork as u32
            || nr == libc::SYS_vfork as u32
            || (nr == libc::SYS_clone as u32 && args.args[0] & 0x100 == 0); // no CLONE_VM → fork
        let is_fork_child = result == 0 && is_fork;

        // After fork, clear the *parent's* pipe fd table.  The child will
        // use its own shim task's virtual pipes (HeapRb).  The parent must
        // also fall back to the shim so both processes share the same pipe
        // data buffer.  Without this, parent writes to shmem but child
        // reads from HeapRb → deadlock.  (Phase B will add cross-process
        // shmem pipes; until then, post-fork pipe I/O goes through central.)
        if is_fork && result > 0 {
            let micro_mut = unsafe { &mut *(*tls).micro };
            micro_mut.pipe_fds = [None; litebox_ipc::ring::MAX_PIPE_SLOTS];
            micro_mut.socket_fds = [None; litebox_ipc::ring::MAX_SOCKET_SLOTS];
            micro_mut.file_fds = [None; litebox_ipc::ring::MAX_FILE_SLOTS];
        }

        if !is_fork_child && (cq.flags & cq_flags::NO_REPORT == 0) {
            unsafe { report_local_result(tls, cq.seq, result) };
        }

        result
    } else {
        cq.result
    }
}

/// Write to a shmem pipe ring buffer with blocking support.
///
/// # Safety
///
/// `buf_ptr` must point to valid readable memory of at least `count` bytes.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_ptr_alignment,
    clippy::ptr_as_ptr
)]
unsafe fn shmem_pipe_write(
    micro: &crate::state::MicroState,
    shmem_offset: u32,
    buf_ptr: *const u8,
    count: usize,
) -> i64 {
    if count == 0 {
        return 0;
    }
    let header = unsafe {
        micro
            .ring_base
            .add(micro.layout.data_region_offset)
            .add(shmem_offset as usize)
            .cast::<litebox_ipc::ring::ShmemPipeHeader>()
    };
    let buf = unsafe { core::slice::from_raw_parts(buf_ptr, count) };
    let mut total_written = 0usize;

    loop {
        let result = unsafe { litebox_ipc::pipe::pipe_try_write(header, &buf[total_written..]) };
        if result == -i64::from(libc::EPIPE) {
            if total_written > 0 {
                return total_written as i64;
            }
            // TODO: send SIGPIPE to current thread
            return -i64::from(libc::EPIPE);
        }
        if result > 0 {
            total_written += result as usize;
            if total_written >= count {
                // Wake reader (may be blocked on empty buffer)
                let head_ptr = unsafe { &(*header).head };
                unsafe {
                    crate::raw_syscall::futex4(
                        core::ptr::from_ref(head_ptr).cast::<u8>() as usize,
                        libc::FUTEX_WAKE,
                        1,
                        0,
                    );
                }
                return total_written as i64;
            }
            // Partial write — continue for blocking pipes
            continue;
        }
        // result == -EAGAIN: buffer full
        let flags = unsafe { (*header).flags.load(core::sync::atomic::Ordering::Relaxed) };
        if flags & litebox_ipc::ring::pipe_flags::NONBLOCK != 0 {
            if total_written > 0 {
                return total_written as i64;
            }
            return -i64::from(libc::EAGAIN);
        }
        // Blocking: spin briefly then futex-wait on head (reader will advance it)
        let head_ptr = unsafe { &(*header).head };
        let current_head = head_ptr.load(core::sync::atomic::Ordering::Relaxed);
        for _ in 0..100 {
            core::hint::spin_loop();
            if head_ptr.load(core::sync::atomic::Ordering::Relaxed) != current_head {
                break;
            }
        }
        if head_ptr.load(core::sync::atomic::Ordering::Relaxed) == current_head {
            // Still no progress — futex wait on head
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(head_ptr).cast::<u8>() as usize,
                    libc::FUTEX_WAIT,
                    current_head as u32, // compare low 32 bits
                    0,
                );
            }
        }
    }
}

/// Read from a shmem pipe ring buffer with blocking support.
///
/// # Safety
///
/// `buf_ptr` must point to valid writable memory of at least `count` bytes.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_ptr_alignment,
    clippy::ptr_as_ptr
)]
unsafe fn shmem_pipe_read(
    micro: &crate::state::MicroState,
    shmem_offset: u32,
    buf_ptr: *mut u8,
    count: usize,
) -> i64 {
    if count == 0 {
        return 0;
    }
    let header = unsafe {
        micro
            .ring_base
            .add(micro.layout.data_region_offset)
            .add(shmem_offset as usize)
            .cast::<litebox_ipc::ring::ShmemPipeHeader>()
    };
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };

    loop {
        let result = unsafe { litebox_ipc::pipe::pipe_try_read(header, buf) };
        if result > 0 {
            // Wake writer (may be blocked on full buffer)
            let tail_ptr = unsafe { &(*header).tail };
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(tail_ptr).cast::<u8>() as usize,
                    libc::FUTEX_WAKE,
                    1,
                    0,
                );
            }
            return result;
        }
        if result == 0 {
            // EOF — writer closed and buffer empty
            return 0;
        }
        // result == -EAGAIN: buffer empty
        let flags = unsafe { (*header).flags.load(core::sync::atomic::Ordering::Relaxed) };
        if flags & litebox_ipc::ring::pipe_flags::NONBLOCK != 0 {
            return -i64::from(libc::EAGAIN);
        }
        // Blocking: spin briefly then futex-wait on tail (writer will advance it)
        let tail_ptr = unsafe { &(*header).tail };
        let current_tail = tail_ptr.load(core::sync::atomic::Ordering::Relaxed);
        for _ in 0..100 {
            core::hint::spin_loop();
            if tail_ptr.load(core::sync::atomic::Ordering::Relaxed) != current_tail {
                break;
            }
        }
        if tail_ptr.load(core::sync::atomic::Ordering::Relaxed) == current_tail {
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(tail_ptr).cast::<u8>() as usize,
                    libc::FUTEX_WAIT,
                    current_tail as u32,
                    0,
                );
            }
        }
    }
}

/// Read from a shmem socket RX ring buffer with blocking support.
///
/// # Safety
///
/// `buf_ptr` must point to valid writable memory of at least `count` bytes.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_ptr_alignment,
    clippy::ptr_as_ptr
)]
unsafe fn shmem_socket_read(
    micro: &crate::state::MicroState,
    shmem_offset: u32,
    buf_ptr: *mut u8,
    count: usize,
) -> i64 {
    if count == 0 {
        return 0;
    }
    let header = unsafe {
        micro
            .ring_base
            .add(micro.layout.data_region_offset)
            .add(shmem_offset as usize)
            .cast::<litebox_ipc::socket_ring::ShmemSocketHeader>()
    };
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };

    loop {
        let result = unsafe { litebox_ipc::socket_ring::socket_try_read(header, buf) };
        if result > 0 {
            // Wake net-worker (may need to fill more RX data from smoltcp)
            let rx_head_ptr = unsafe { &(*header).rx_head };
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(rx_head_ptr).cast::<u8>() as usize,
                    libc::FUTEX_WAKE,
                    1,
                    0,
                );
            }
            return result;
        }
        if result == 0 {
            return 0; // EOF (RX_SHUTDOWN + empty)
        }
        if result != -i64::from(libc::EAGAIN) {
            return result; // error (ECONNRESET, etc.)
        }
        // -EAGAIN: buffer empty
        let flags = unsafe { (*header).flags.load(core::sync::atomic::Ordering::Relaxed) };
        if flags & litebox_ipc::socket_ring::socket_flags::NONBLOCK != 0 {
            return -i64::from(libc::EAGAIN);
        }
        // Blocking: spin briefly then futex-wait on rx_tail
        let rx_tail_ptr = unsafe { &(*header).rx_tail };
        let current_tail = rx_tail_ptr.load(core::sync::atomic::Ordering::Relaxed);
        for _ in 0..100 {
            core::hint::spin_loop();
            if rx_tail_ptr.load(core::sync::atomic::Ordering::Relaxed) != current_tail {
                break;
            }
        }
        if rx_tail_ptr.load(core::sync::atomic::Ordering::Relaxed) == current_tail {
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(rx_tail_ptr).cast::<u8>() as usize,
                    libc::FUTEX_WAIT,
                    current_tail as u32, // compare low 32 bits
                    0,
                );
            }
        }
    }
}

/// Write to a shmem socket TX ring buffer with blocking support.
///
/// # Safety
///
/// `buf_ptr` must point to valid readable memory of at least `count` bytes.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_ptr_alignment,
    clippy::ptr_as_ptr
)]
unsafe fn shmem_socket_write(
    micro: &crate::state::MicroState,
    shmem_offset: u32,
    buf_ptr: *const u8,
    count: usize,
) -> i64 {
    if count == 0 {
        return 0;
    }
    let header = unsafe {
        micro
            .ring_base
            .add(micro.layout.data_region_offset)
            .add(shmem_offset as usize)
            .cast::<litebox_ipc::socket_ring::ShmemSocketHeader>()
    };
    let buf = unsafe { core::slice::from_raw_parts(buf_ptr, count) };
    let mut total_written = 0usize;

    loop {
        let result =
            unsafe { litebox_ipc::socket_ring::socket_try_write(header, &buf[total_written..]) };
        if result == -i64::from(libc::EPIPE) {
            if total_written > 0 {
                return total_written as i64;
            }
            return -i64::from(libc::EPIPE);
        }
        if result > 0 {
            total_written += result as usize;
            // Wake net-worker after each chunk so it drains TX ring
            let tx_tail_ptr = unsafe { &(*header).tx_tail };
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(tx_tail_ptr).cast::<u8>() as usize,
                    libc::FUTEX_WAKE,
                    1,
                    0,
                );
            }
            if total_written >= count {
                return total_written as i64;
            }
            continue;
        }
        // result == -EAGAIN: buffer full
        let flags = unsafe { (*header).flags.load(core::sync::atomic::Ordering::Relaxed) };
        if flags & litebox_ipc::socket_ring::socket_flags::NONBLOCK != 0 {
            if total_written > 0 {
                return total_written as i64;
            }
            return -i64::from(libc::EAGAIN);
        }
        // Blocking: spin briefly then futex-wait on tx_head
        let tx_head_ptr = unsafe { &(*header).tx_head };
        let current_head = tx_head_ptr.load(core::sync::atomic::Ordering::Relaxed);
        for _ in 0..100 {
            core::hint::spin_loop();
            if tx_head_ptr.load(core::sync::atomic::Ordering::Relaxed) != current_head {
                break;
            }
        }
        if tx_head_ptr.load(core::sync::atomic::Ordering::Relaxed) == current_head {
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(tx_head_ptr).cast::<u8>() as usize,
                    libc::FUTEX_WAIT,
                    current_head as u32, // compare low 32 bits
                    0,
                );
            }
        }
    }
}

/// Write gathered iov data to a shmem socket TX ring buffer.
///
/// Iterates the iovec array, writing each buffer's data to the shmem TX
/// ring. Returns the total number of bytes written, or a negative errno.
///
/// # Safety
///
/// `iov_ptr` must point to a valid array of `iovcnt` iovec structs in the
/// guest's address space. Each iov_base must be valid readable memory.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_ptr_alignment,
    clippy::ptr_as_ptr,
    clippy::items_after_statements
)]
unsafe fn shmem_socket_writev(
    micro: &crate::state::MicroState,
    shmem_offset: u32,
    iov_ptr: *const u8,
    iovcnt: usize,
) -> i64 {
    if iov_ptr.is_null() || iovcnt == 0 {
        return 0;
    }

    const IOVEC_SIZE: usize = 16; // sizeof(struct iovec) on x86-64
    let mut total_written = 0i64;

    for i in 0..iovcnt {
        let iov_entry = unsafe { iov_ptr.add(i * IOVEC_SIZE) };
        let iov_base = unsafe { core::ptr::read_unaligned(iov_entry.cast::<u64>()) } as *const u8;
        let iov_len = unsafe { core::ptr::read_unaligned(iov_entry.add(8).cast::<u64>()) } as usize;

        if iov_base.is_null() || iov_len == 0 {
            continue;
        }

        let buf = unsafe { core::slice::from_raw_parts(iov_base, iov_len) };
        let result = unsafe { shmem_socket_write(micro, shmem_offset, buf.as_ptr(), buf.len()) };
        if result > 0 {
            total_written += result;
        } else if result < 0 {
            // Error or EAGAIN — return what we've written so far, or the error
            if total_written > 0 {
                return total_written;
            }
            return result;
        }
    }

    total_written
}
