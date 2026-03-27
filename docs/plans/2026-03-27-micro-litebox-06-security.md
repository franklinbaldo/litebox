# Micro-LiteBox Design — Part 6: Security

## Threat Model

The guest process is untrusted. It may attempt to:

1. **Forge syscall requests** — Submit SQ entries with crafted arguments
   to access unauthorized resources
2. **Corrupt shared memory** — Modify SQ entries after submission, corrupt
   ring buffer metadata, overwrite CQ entries
3. **Escape the sandbox** — Execute raw syscalls bypassing micro-LiteBox
4. **Exploit TOCTOU** — Change shared data between central's validation
   and micro's execution
5. **Denial of service** — Flood the ring buffer, exhaust central resources
6. **Information leak** — Read stale data from shared region belonging to
   other operations

## Defense Layers

### Layer 1: Seccomp (Kernel Enforcement)

The guest process runs under a strict seccomp-BPF filter that:

```text
Allowed syscalls (executed via micro-LiteBox):
  - mmap, munmap, mremap, mprotect, brk, madvise
  - clone (with specific flag restrictions)
  - futex (for ring buffer synchronization only)
  - write to specific fds (ring buffer notification)
  - read from specific fds
  - exit, exit_group
  - rt_sigreturn (for signal handler return)

Everything else → SIGSYS → intercepted by micro-LiteBox → forwarded to central
```

This is the first line of defense. Even if guest code bypasses micro-LiteBox
entirely, the kernel blocks unauthorized syscalls.

### Layer 2: Central Validation

Central treats ALL SQ entries as untrusted input:

```text
fn validate_sq_entry(entry: &SqEntry, ctx: &ProcessContext) -> Result<()> {
    // 1. Syscall number in valid range
    if entry.syscall_nr > MAX_SYSCALL_NR {
        return Err(EINVAL);
    }

    // 2. Thread slot is registered
    if !ctx.registered_threads.contains(entry.thread_slot) {
        return Err(EINVAL);
    }

    // 3. Data region bounds check
    if entry.data_offset + entry.data_len > SHARED_REGION_SIZE {
        return Err(EFAULT);
    }

    // 4. Argument validation (syscall-specific)
    validate_syscall_args(entry.syscall_nr, &entry.args, ctx)?;

    // 5. Sequence number is monotonic per-thread
    if entry.seq <= ctx.last_seq[entry.thread_slot] {
        return Err(EINVAL);
    }

    Ok(())
}
```

### Layer 3: Authorization

Central enforces policy on every request:

- **File access**: Path resolution with sandbox boundaries, no symlink
  escapes, no access outside allowed directories
- **Network**: Allowed destinations/ports, rate limiting
- **Process creation**: Fork/exec limits, resource quotas
- **Memory**: Address space size limits, mmap flag restrictions
  (no MAP_FIXED to arbitrary addresses)

Authorization happens BEFORE telling micro to execute locally. If denied,
central returns an error code directly in the CQ entry.

### Layer 4: Isolation

Each guest process gets its own:
- Ring buffer pair (separate shared memory region)
- Data region (no cross-process data sharing)
- GlobalState in central (separate fd table, page table, etc.)

A compromised guest process cannot:
- Read/write another process's ring buffer (different mmap)
- Influence another process's central state
- Access another process's file descriptors

### Layer 5: Integrity

Central copies data OUT of shared memory before acting on it:

```text
fn safe_read_path(entry: &SqEntry, shared: &SharedRegion) -> Result<PathBuf> {
    // Copy path from shared region into central's heap
    // BEFORE any validation or use
    let path_bytes = shared.copy_bytes(entry.data_offset, entry.data_len)?;

    // Now validate the copied data (guest can't modify it anymore)
    let path = validate_path(&path_bytes)?;
    Ok(path)
}
```

This prevents TOCTOU attacks where the guest modifies shared data
between central's validation and use.

## Specific Attack Mitigations

### Forged fd access

Guest cannot forge file descriptors. All fd operations go through
central, which maintains the real fd table. Guest fds are logical
numbers that central maps to real host fds.

### Ring buffer corruption

- **SQ metadata corruption**: Central validates head/tail bounds before
  reading. Out-of-bounds values are clamped or rejected.
- **CQ corruption by guest**: Guest can only read CQ, not write. The CQ
  region could be mapped read-only in the guest (requires separate mmap
  for SQ write + CQ read-only). Alternative: central detects corrupted
  CQ entries via sequence number validation.
- **Ready flag races**: Central only reads entry fields after ready=1.
  If guest clears ready prematurely, central spins/waits (safe).

### Fork bomb

Central enforces process limits:
```text
if ctx.process_tree.count() >= MAX_PROCESSES {
    return Err(EAGAIN);
}
```

### Shared data exhaustion

Per-thread bump allocator is reset after each syscall. A thread can't
exhaust the shared region because its allocation is bounded by the
region size. If a thread's data exceeds the region, the syscall fails
with ENOMEM.

## Security Limitations

1. **Side channels**: Shared memory timing can leak information about
   central's processing. Not in scope for initial design.
2. **Guest-to-guest via central**: If two guest processes interact via
   pipes/signals through central, information flow is by design. Central
   mediates but doesn't prevent intentional IPC.
3. **Micro-LiteBox compromise**: If guest achieves arbitrary code
   execution in micro-LiteBox's context, seccomp is the last defense.
   Micro-LiteBox runs with the same privilege as the guest.
4. **Kernel vulnerabilities**: If the host kernel has vulnerabilities in
   clone/mmap/futex (the allowed syscalls), the guest may exploit them.
   This is inherent to any user-space sandbox.
