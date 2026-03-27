# Micro-LiteBox Design — Part 1: Ring Buffer IPC

## Overview

Communication between micro-LiteBox (in-process) and central LiteBox
(host process) uses a shared-memory ring buffer pair modeled after
Linux's io_uring: a Submission Queue (SQ) and a Completion Queue (CQ).

## Shared Memory Layout

```text
┌──────────────────────────────────────────────┐
│              Shared Memory Region             │
├──────────────────────────────────────────────┤
│  Ring Header (cache-line aligned)            │
│  ┌─────────────────────────────────────────┐ │
│  │ SQ: head (central reads, micro writes)  │ │
│  │ SQ: tail (micro writes, central reads)  │ │
│  │ CQ: head (micro reads, central writes)  │ │
│  │ CQ: tail (central writes, micro reads)  │ │
│  │ SQ notify futex                         │ │
│  │ CQ notify slots[MAX_THREADS]            │ │
│  └─────────────────────────────────────────┘ │
├──────────────────────────────────────────────┤
│  SQ Entries[RING_SIZE]                       │
│  (each 64 bytes, cache-line aligned)         │
├──────────────────────────────────────────────┤
│  CQ Entries[RING_SIZE]                       │
│  (each 32 bytes)                             │
├──────────────────────────────────────────────┤
│  Shared Data Region (4 MiB default)          │
│  (bulk data: file contents, buffers, paths)  │
└──────────────────────────────────────────────┘
```

Default `RING_SIZE`: 256 entries (power of two for mask-based indexing).

## SqEntry Structure

```text
#[repr(C, align(64))]
struct SqEntry {
    /// Monotonic sequence number (set by submitter)
    seq: u64,
    /// Syscall number (e.g., SYS_read, SYS_mmap)
    syscall_nr: u32,
    /// Thread slot index (for CQ demux and wake)
    thread_slot: u16,
    /// Flags (BATCH, NEED_AUTH, REPORT_RESULT, etc.)
    flags: u16,
    /// Syscall arguments (up to 6)
    args: [u64; 6],
    /// Offset into shared data region (for bulk data)
    data_offset: u32,
    /// Length of data in shared region
    data_len: u32,
    /// Ready flag: set to 1 when entry is fully written
    ready: AtomicU8,
    /// Padding to 64 bytes
    _pad: [u8; 7],
}
```

Total: 64 bytes per entry (one cache line on x86).

## CqEntry Structure

```text
#[repr(C)]
struct CqEntry {
    /// Matches SqEntry.seq for correlation
    seq: u64,
    /// Syscall return value (or negative errno)
    result: i64,
    /// Flags (AUTH_GRANTED, EXEC_LOCAL, etc.)
    flags: u32,
    /// Thread slot (copied from SqEntry for demux)
    thread_slot: u16,
    /// Padding
    _pad: [u8; 2],
    /// Additional data offset (for results with bulk data)
    data_offset: u32,
    /// Additional data length
    data_len: u32,
}
```

Total: 32 bytes per entry.

## Synchronization Protocol

### Submission (micro → central)

```text
1. Allocate SQ slot:
   my_slot = sq.tail.fetch_add(1, Relaxed) & RING_MASK

2. Write entry fields (args, syscall_nr, etc.)
   All non-atomic writes.

3. Set ready flag:
   entry.ready.store(1, Release)
   // Release fence ensures all fields visible before ready

4. Wake central (if needed):
   futex_wake(&ring.sq_notify, 1)
```

### Consumption (central reads SQ)

```text
1. Read SQ head:
   slot = sq.head & RING_MASK

2. Check ready flag:
   while entry.ready.load(Acquire) == 0 { spin/wait }
   // Acquire fence ensures all fields are visible

3. Process entry, advance head:
   sq.head += 1

4. Clear ready flag:
   entry.ready.store(0, Release)
```

### Completion (central → micro)

```text
1. Write CQ entry at cq.tail & RING_MASK

2. Advance CQ tail:
   cq.tail.fetch_add(1, Release)

3. Wake specific guest thread:
   futex_wake(&cq.notify_slots[entry.thread_slot], 1)
```

### Receiving completion (micro reads CQ)

```text
1. Wait on per-thread notify slot:
   futex_wait(&cq.notify_slots[my_slot], old_val)

2. Scan CQ for entry matching my seq number

3. Advance CQ head when entry consumed
```

## Shared Data Region

For syscalls that transfer bulk data (read/write buffers, file paths,
etc.), the SQ/CQ entries reference offsets into the shared data region:

- **Guest → Central** (e.g., write, path for open): Micro writes data
  at `data_offset` before submitting SQ entry
- **Central → Guest** (e.g., read results): Central writes data at
  `data_offset` before writing CQ entry
- **Allocation**: Simple bump allocator per-thread, reset after each
  syscall completion. No cross-thread sharing needed.

Default size: 4 MiB. Configurable at ring setup time. For transfers
larger than the region, data is chunked across multiple round-trips.

## Ring Setup

Central allocates the shared memory region via `mmap(MAP_SHARED)` on
a memfd. The fd is passed to the guest process at startup (or after
fork, when central sets up a new ring for the child). Micro-LiteBox
maps the same fd into its address space.
