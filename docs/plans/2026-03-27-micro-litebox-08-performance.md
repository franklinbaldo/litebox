# Micro-LiteBox Design — Part 8: Performance

## Overhead Budget

Target: remote syscall round-trip should add **2–10 μs** over a direct
host syscall. Breakdown:

| Phase | Budget | Mechanism |
|-------|--------|-----------|
| SQ write + fence | ~100 ns | Atomic store + store fence |
| Wake central | 0–500 ns | Adaptive spin avoids futex in fast path |
| Central poll + dispatch | ~200 ns | Spinning worker sees entry immediately |
| Handler execution | varies | Same as today's shim handlers |
| CQ write + fence | ~100 ns | Atomic store + store fence |
| Wake guest | 0–500 ns | Futex on per-thread slot |
| Guest read CQ | ~50 ns | Load from shared memory |

Hot-path (central already spinning): **~500 ns** added overhead.
Cold-path (futex wake needed): **~2–5 μs** added overhead.
Worst case (batched, queued behind other entries): **~10 μs**.

## Adaptive Spinning

Both micro-LiteBox (waiting for CQ) and central (waiting for SQ) use
the same adaptive spin strategy:

```text
const SPIN_ITERS: u32 = 200;    // ~200 ns on modern x86
const BACKOFF_ITERS: u32 = 50;  // Pause-based backoff rounds

fn spin_then_wait(futex_addr: &AtomicU32, expected: u32) {
    // Phase 1: Busy spin with pause hints
    for _ in 0..SPIN_ITERS {
        if futex_addr.load(Ordering::Acquire) != expected {
            return; // Fast path: data arrived during spin
        }
        core::hint::spin_loop();
    }

    // Phase 2: Exponential backoff
    for i in 0..BACKOFF_ITERS {
        for _ in 0..(1 << i.min(6)) {
            core::hint::spin_loop();
        }
        if futex_addr.load(Ordering::Acquire) != expected {
            return;
        }
    }

    // Phase 3: Futex wait (kernel sleep)
    futex_wait(futex_addr, expected);
}
```

This keeps latency low when the other side is actively processing,
while avoiding CPU waste during idle periods.

## Batched Submissions

Micro-LiteBox can batch multiple SQ entries before waking central:

```text
fn submit_batch(ring: &Ring, entries: &[SqEntry]) {
    for entry in entries {
        ring.sq.push(entry);
    }
    // Single fence + single futex_wake for entire batch
    atomic::fence(Ordering::Release);
    futex_wake(&ring.sq.notify, 1);
}
```

Useful for sequences like: open + fstat + mmap + close.
Central processes all queued entries before sleeping, so batching
amortizes the wake overhead across multiple syscalls.

## Zero-Copy Data Transfer

The shared data region avoids copying buffers between processes:

- **Read syscalls**: Central writes file data directly into the shared
  data region at the offset specified in SqEntry.data_offset. Guest
  reads from the same offset after CQ completion.
- **Write syscalls**: Guest writes data into shared region before
  submitting SQ entry. Central reads from the same offset.
- **Large transfers**: Chunked into shared-region-sized pieces. Each
  chunk is a separate SQ/CQ round-trip. Default region size: 4 MiB
  (configurable).

No serialization/deserialization for bulk data. Only SqEntry/CqEntry
metadata uses structured layout.

## Cached Read-Only Values

Some syscalls return values that never change for a process:

| Syscall | Caching Strategy |
|---------|-----------------|
| `getpid` | Cached at process creation, updated on fork |
| `gettid` | Cached at thread registration |
| `getuid/getgid` | Cached, invalidated on setuid/setgid |
| `getcwd` | Cached, invalidated on chdir/fchdir |
| `uname` | Cached once at startup (never changes) |

Micro-LiteBox serves these locally without a ring-buffer round-trip.
Values are set by central during process/thread setup and stored in
micro-LiteBox's local forkable state.

## Central Threading Model

Initial model: **one worker thread per guest process**.

Rationale:
- Simple: no locking on GlobalState (single writer)
- Predictable: no cross-process contention
- Sufficient: most guest workloads are single-threaded or lightly
  multi-threaded

For multi-threaded guests, all threads within one process share
the same SQ/CQ. Central's worker thread serves all threads of
that process sequentially. This is acceptable because:
- Most syscalls are fast (< 1 μs handler time)
- Guest threads doing I/O are typically blocked anyway
- True parallelism in syscall handling is a future optimization

Future model: thread pool with work-stealing, sharded GlobalState
locks, and per-subsystem parallelism (fs ops in parallel with
network ops).

## Benchmarking Plan

Key benchmarks to validate the design:

1. **Null syscall** — getpid() round-trip latency (target: < 200 ns cached)
2. **Simple syscall** — write(fd, buf, 1) round-trip (target: < 3 μs)
3. **Fork latency** — fork() + immediate exit (target: < 50 μs)
4. **Throughput** — sequential write(fd, buf, 4096) calls/sec
5. **Multi-process** — 100 forked children each doing syscalls
6. **Contention** — 8 threads in one process submitting simultaneously

Compare against: direct LiteBox (no micro split), native Linux,
and gVisor/runsc for reference.
