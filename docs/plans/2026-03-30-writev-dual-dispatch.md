# writev/pwritev/pwritev2 Dual-Dispatch Fix

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix writev/pwritev/pwritev2 to go through central's shim for virtual fd resolution (like write/pwrite64), instead of always executing locally in micro.

**Architecture:** Micro gathers iovec data into a contiguous buffer in the shmem data region (same region write uses), then sends to central as a flattened write. Central dispatches through the shim using `SYS_write` (not writev — the data is already contiguous). If the shim returns EBADF (real OS fd like a pipe), central sets EXEC_LOCAL and micro executes the original `writev` syscall locally. For `pwritev`/`pwritev2`, the file offset is preserved through the dispatch.

**Tech Stack:** Rust, litebox_ipc shmem ring, litebox_central server, litebox_micro handler

---

## Task 1: Remove writev/pwritev/pwritev2 from needs_local_exec

**Files:**
- Modify: `litebox_central/src/server.rs:708-750` (needs_local_exec function)

**Step 1: Remove the three entries**

Remove `libc::SYS_writev`, `libc::SYS_pwritev`, `libc::SYS_pwritev2` from the `needs_local_exec()` match. Also remove/update the comment about scatter/gather writes.

**Step 2: Build**

Run: `cargo build -p litebox_central`
Expected: PASS (these syscalls now fall through to the default shim dispatch path)

**Step 3: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "fix(central): remove writev/pwritev/pwritev2 from needs_local_exec"
```

---

## Task 2: Add writev iovec gathering in micro's handler

**Files:**
- Modify: `litebox_micro/src/handler.rs` (write_data_arg_info, add writev gathering)

**Step 1: Extend write_data_arg_info or add iovec gathering**

The existing `write_data_arg_info()` returns `(buf_idx, count_idx)` for flat writes. writev is different — it takes `(fd, iov, iovcnt)` where `iov` is a pointer to an array of `struct iovec { void *iov_base; size_t iov_len; }`.

Add a new function `copy_writev_data_to_data_region()` that:
1. Checks if the syscall is writev/pwritev/pwritev2
2. Reads the iov pointer and iovcnt from args
3. Walks the iovec array in micro's memory, gathering data into a contiguous buffer in the shmem data region
4. Sets entry.data_offset and entry.data_len
5. Stores the total gathered length

The iovec arg positions:
- `writev(fd, iov, iovcnt)` — iov=args[1], iovcnt=args[2]
- `pwritev(fd, iov, iovcnt, offset)` — iov=args[1], iovcnt=args[2], offset=args[3]
- `pwritev2(fd, iov, iovcnt, offset, flags)` — iov=args[1], iovcnt=args[2], offset=args[3]

On x86-64, `struct iovec` is 16 bytes: `iov_base(8) + iov_len(8)`.

```rust
/// Returns true for writev-family syscalls that need iovec gathering.
fn is_writev_family(nr: u32) -> bool {
    matches!(
        i64::from(nr),
        libc::SYS_writev | libc::SYS_pwritev | libc::SYS_pwritev2
    )
}

/// Gather iovec data from guest memory into the shmem data region.
///
/// Walks the iovec array pointed to by args[1], concatenates all
/// buffers into a contiguous region in shmem. Sets entry.data_offset
/// and entry.data_len to the gathered data location and total size.
///
/// # Safety
///
/// The iov pointer (args[1]) and all iov_base pointers must point to
/// valid readable memory in the guest's address space.
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
    let max_region = if thread_offset < layout.data_region_size {
        (layout.data_region_size - thread_offset).min(WRITE_DATA_REGION_SIZE)
    } else {
        return;
    };

    let dst_base = unsafe { ring_base.add(layout.data_region_offset + thread_offset) };
    let mut total_copied = 0usize;

    // Walk iovec array: each entry is { iov_base: *const u8 (8 bytes), iov_len: usize (8 bytes) }
    for i in 0..iovcnt {
        let iov_entry = unsafe { iov_ptr.add(i * 16) };
        let iov_base = unsafe { core::ptr::read_unaligned(iov_entry as *const u64) } as *const u8;
        let iov_len =
            unsafe { core::ptr::read_unaligned(iov_entry.add(8) as *const u64) } as usize;

        if iov_base.is_null() || iov_len == 0 {
            continue;
        }

        let copy_len = iov_len.min(max_region - total_copied);
        if copy_len == 0 {
            break; // Data region full.
        }

        unsafe {
            core::ptr::copy_nonoverlapping(iov_base, dst_base.add(total_copied), copy_len);
        }
        total_copied += copy_len;

        if total_copied >= max_region {
            break;
        }
    }

    if total_copied > 0 {
        entry.data_offset = thread_offset as u32;
        entry.data_len = total_copied as u32;
    }
}
```

Call this from the SQ submission path, right after `copy_write_data_to_data_region`:

```rust
copy_writev_data_to_data_region(entry, args, syscall_nr, micro.ring_base, &micro.layout);
```

**Step 2: Build and test**

Run: `cargo clippy -p litebox -p litebox_shim_linux -p litebox_micro -p litebox_launcher`
Expected: PASS

**Step 3: Commit**

```bash
git add litebox_micro/src/handler.rs
git commit -m "feat(micro): gather writev iovec data into shmem data region"
```

---

## Task 3: Add writev to data-consuming I/O dispatch in central

**Files:**
- Modify: `litebox_central/src/server.rs` (is_data_consuming_io, handle_data_consuming_io)

**Step 1: Add writev family to is_data_consuming_io**

```rust
fn is_data_consuming_io(nr: u32) -> bool {
    matches!(
        i64::from(nr),
        libc::SYS_write
            | libc::SYS_pwrite64
            | libc::SYS_writev
            | libc::SYS_pwritev
            | libc::SYS_pwritev2
    )
}
```

**Step 2: Add writev dispatch arms in handle_data_consuming_io**

After reading data from shmem (which micro already gathered into a contiguous buffer), dispatch writev as a flat `write` or `pwrite64` through the shim:

```rust
libc::SYS_writev => {
    // writev(fd, iov, iovcnt) — micro gathered iov data into flat buffer.
    // Dispatch as write(fd, buf, count) through shim.
    regs.orig_rax = libc::SYS_write as usize;
    regs.rsi = buf_ptr;    // buf = gathered data
    regs.rdx = len;        // count = total gathered size
}
libc::SYS_pwritev => {
    // pwritev(fd, iov, iovcnt, offset) — dispatch as pwrite64.
    regs.orig_rax = libc::SYS_pwrite64 as usize;
    regs.rsi = buf_ptr;
    regs.rdx = len;
    // r10 = offset (args[3]), already set from sq_entry_to_ptregs
}
libc::SYS_pwritev2 => {
    // pwritev2(fd, iov, iovcnt, offset, flags) — dispatch as pwrite64.
    // flags (args[4]) are ignored since pwrite64 has no flags.
    // If offset == -1, pwritev2 acts like writev (use current position).
    let offset = entry.args[3] as i64;
    if offset == -1 {
        regs.orig_rax = libc::SYS_write as usize;
        regs.rsi = buf_ptr;
        regs.rdx = len;
    } else {
        regs.orig_rax = libc::SYS_pwrite64 as usize;
        regs.rsi = buf_ptr;
        regs.rdx = len;
    }
}
```

**Step 3: Build**

Run: `cargo build -p litebox_central`
Expected: PASS

**Step 4: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "feat(central): dispatch writev/pwritev/pwritev2 as flattened writes through shim"
```

---

## Task 4: Add pwritev/pwritev2 handlers in micro's execute_locally

**Files:**
- Modify: `litebox_micro/src/local_exec.rs` (execute_locally, add missing arms)

**Step 1: Add pwritev and pwritev2 arms**

The writev arm already exists at `local_exec.rs:650`. Add pwritev and pwritev2 nearby:

```rust
nr if nr == libc::SYS_pwritev as u32 => unsafe {
    raw_syscall::syscall4(libc::SYS_pwritev, args[0], args[1], args[2], args[3])
},
nr if nr == libc::SYS_pwritev2 as u32 => unsafe {
    raw_syscall::syscall5(libc::SYS_pwritev2, args[0], args[1], args[2], args[3], args[4])
},
```

These are needed for the EBADF fallback path when central says EXEC_LOCAL (the fd is a real OS fd like a pipe).

Also need to add the EBADF handling pattern for writev/pwritev/pwritev2 in execute_locally — currently the writev arm just does a raw syscall unconditionally, but after this change it would only be reached via EXEC_LOCAL from central (which is the correct behavior).

**Step 2: Build and test**

Run: `cargo clippy -p litebox -p litebox_shim_linux -p litebox_micro -p litebox_launcher`
Expected: PASS

**Step 3: Commit**

```bash
git add litebox_micro/src/local_exec.rs
git commit -m "feat(micro): add pwritev/pwritev2 handlers in execute_locally"
```

---

## Task 5: Integration test with benchmarks

**Step 1: Run all benchmarks**

```bash
pkill -9 litebox_central; pkill -9 litebox; sleep 0.5
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --release --duration 10 --iterations 1 --benchmarks dhry2reg
python3 run_unixbench.py --mode micro --release --duration 10 --iterations 1 --benchmarks syscall
python3 run_unixbench.py --mode micro --release --duration 10 --iterations 1 --benchmarks pipe
python3 run_unixbench.py --mode micro --release --duration 10 --iterations 1 --benchmarks context1
python3 run_unixbench.py --mode micro --release --duration 10 --iterations 1 --benchmarks shell1
```

Expected: All benchmarks complete without regression. The pipe benchmark is especially relevant since pipe write uses writev in some paths.
