# Micro-LiteBox Design — Part 5: Concurrency

## Overview

Multiple guest threads within a single process share one ring buffer
pair (SQ + CQ). This document covers how concurrent access is handled
without locks and without thundering-herd wake problems.

## SQ Contention (Multiple Submitters)

When multiple guest threads submit syscalls simultaneously, they
contend for SQ slots. Resolution uses atomic `fetch_add`:

```text
Thread A                          Thread B
────────                          ────────
slot = tail.fetch_add(1) → 5     slot = tail.fetch_add(1) → 6
write entry at slot 5             write entry at slot 6
entry[5].ready.store(1, Release)  entry[6].ready.store(1, Release)
futex_wake(sq_notify)             futex_wake(sq_notify)
```

Properties:
- **Lock-free**: `fetch_add` is a single atomic instruction (LOCK XADD)
- **No lost entries**: Each thread gets a unique slot
- **Out-of-order writes**: Thread B might finish writing before Thread A.
  This is safe because central checks the `ready` flag per-entry.

### Handling SQ Full

If `tail - head >= RING_SIZE`, the SQ is full. The submitting thread
must wait for central to consume entries:

```text
fn acquire_sq_slot(ring: &Ring) -> u32 {
    loop {
        let tail = ring.sq.tail.load(Relaxed);
        let head = ring.sq.head.load(Acquire);
        if tail - head < RING_SIZE as u64 {
            match ring.sq.tail.compare_exchange_weak(
                tail, tail + 1, AcqRel, Relaxed
            ) {
                Ok(_) => return (tail & RING_MASK) as u32,
                Err(_) => continue, // CAS retry
            }
        }
        // SQ full: yield and retry
        core::hint::spin_loop();
    }
}
```

Note: Under SQ-full contention, we switch from `fetch_add` to CAS to
avoid over-advancing the tail past the ring capacity.

## CQ Demultiplexing

Central writes completions to the CQ. Multiple guest threads may be
waiting for different completions. Each thread needs to find ITS
completion without scanning the entire CQ.

### Per-Thread Wake Slots

```text
Ring Header:
  cq_notify_slots: [AtomicU32; MAX_THREADS]
```

Each guest thread is assigned a `thread_slot` (0..MAX_THREADS-1) at
registration time. When central completes a request:

```text
Central:
  // Write CQ entry
  cq.entries[cq.tail & RING_MASK] = CqEntry { seq, result, thread_slot, ... };
  cq.tail.fetch_add(1, Release);

  // Wake ONLY the requesting thread
  cq.notify_slots[thread_slot].fetch_add(1, Release);
  futex_wake(&cq.notify_slots[thread_slot], 1);
```

Guest thread:

```text
fn wait_completion(seq: u64, my_slot: u16) -> CqEntry {
    let notify = &ring.cq.notify_slots[my_slot as usize];
    let old = notify.load(Acquire);

    loop {
        // Scan CQ for our entry
        if let Some(entry) = scan_cq_for_seq(seq) {
            return entry;
        }
        // Wait for wake
        spin_then_futex_wait(notify, old);
    }
}
```

This avoids thundering herd: only the thread whose syscall completed
is woken. Other threads sleeping on different slots are undisturbed.

## Thread Registration

When a new guest thread is created:

```text
1. Parent thread submits MSG_THREAD_REGISTER to central
2. Central allocates a thread_slot (0..MAX_THREADS-1)
3. Central returns slot assignment in CQ
4. New thread stores its slot in thread-local storage
5. Thread uses this slot for all future submissions
```

When a thread exits:

```text
1. Thread submits MSG_THREAD_DEREGISTER
2. Central frees the thread_slot for reuse
3. Thread's notify slot is cleared
```

### MAX_THREADS

Default: 64 threads per process. This determines the size of the
`cq_notify_slots` array. If a process needs more, central can
reallocate the ring (rare — 64 is sufficient for most workloads).

## Ordering Guarantees

### Within a single thread

Syscalls from one thread are submitted in order (that thread writes
to SQ sequentially). Central processes them in SQ order, so results
are returned in submission order for a single thread.

### Across threads

No ordering guarantee between threads. Thread A's syscall may complete
before or after Thread B's, regardless of submission order. This matches
real kernel behavior.

### Happens-before relationships

The release/acquire pairs ensure:

```text
Micro writes entry fields
  │ (ordinary stores)
  ▼
entry.ready.store(1, Release)   ──────►   entry.ready.load(Acquire)
                                            │
                                            ▼
                                          Central reads entry fields
                                            │ (ordinary loads)
                                            ▼
                                          Central writes CQ entry
                                            │ (ordinary stores)
                                            ▼
                                          cq.tail.fetch_add(1, Release) ──►  cq.tail.load(Acquire)
                                                                                │
                                                                                ▼
                                                                              Micro reads CQ entry
```

## Batched Submission

A thread can write multiple SQ entries before waking central:

```text
fn submit_batch(entries: &[SqEntry]) {
    for entry in entries {
        let slot = acquire_sq_slot();
        write_entry(slot, entry);
    }
    // Single wake for the whole batch
    futex_wake(&ring.sq_notify, 1);
}
```

Central's consumption loop drains all ready entries before sleeping,
so one wake is sufficient for an entire batch. This amortizes the
~2 μs futex wake cost across multiple syscalls.

## Central-Side Concurrency

Initially: one worker thread per guest process. No concurrency within
a single process's request handling.

If a process's syscall blocks (e.g., read from a slow fd), the worker
thread blocks too. This means other syscalls from the same process queue
up. This is acceptable initially because:

- Blocking syscalls are rare in event-driven code
- Non-blocking I/O with epoll is the common pattern
- A thread pool per-process is a future optimization

Future: async worker with io_uring on the central side for truly
non-blocking dispatch.
