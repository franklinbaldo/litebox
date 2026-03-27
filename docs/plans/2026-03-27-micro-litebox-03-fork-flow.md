# Micro-LiteBox Design — Part 3: Fork Flow

## Overview

Fork is the primary motivation for the micro-LiteBox architecture.
This document describes the complete sequence from when a guest process
calls `fork()` to when both parent and child are running independently.

## Fork Mechanism

We use the host kernel's `clone(SIGCHLD)` (equivalent to fork) for real
Copy-on-Write semantics. The kernel duplicates the address space with
CoW page mappings, giving each process an independent virtual memory
space without copying physical pages upfront.

## Complete Fork Sequence

### Step 1: Guest calls fork()

```text
Guest code: pid_t child = fork();
→ Intercepted by seccomp SIGSYS handler
→ Enters micro-LiteBox's handle_syscall()
```

### Step 2: Micro requests fork authorization

```text
Micro-LiteBox:
  sq_entry = SqEntry {
      syscall_nr: SYS_clone,
      flags: FLAG_NEED_AUTH,
      args: [SIGCHLD, 0, 0, 0, 0, 0],
      ...
  };
  submit(sq_entry);
  wait_for_completion();
```

### Step 3: Central prepares for fork

```text
Central LiteBox:
  1. Validates fork request (policy check)
  2. Allocates new PID for child
  3. Creates new shared memory region + ring buffers for child
  4. Deep-copies parent's GlobalState for child:
     - Page table metadata (VMA list, permissions)
     - File descriptor table (dup all fds, increment refcounts)
     - Signal dispositions (copied, pending signals cleared)
     - Current working directory, umask, credentials
  5. Registers child in process tree
  6. Sends CQ response with:
     - flags: FLAG_EXEC_LOCAL (authorized for local execution)
     - child_ring_fd: memfd for child's new ring buffer
     - child_pid: assigned PID
```

### Step 4: Micro executes fork locally

```text
Micro-LiteBox:
  // Received authorization + child ring fd
  child_pid = clone(SIGCHLD);  // Real kernel fork with CoW
```

### Step 5: Parent resumes

```text
Parent (clone returned child_pid > 0):
  1. Report fork result to central:
     submit(SqEntry { syscall_nr: MSG_FORK_RESULT, args: [child_pid] })
  2. Return child_pid to guest code
```

### Step 6: Child initializes

```text
Child (clone returned 0):
  1. Inherited micro-LiteBox state via CoW (all plain data, safe)
  2. Update local PID cache
  3. Close/unmap parent's ring buffer
  4. Map child's new ring buffer (using fd from step 3)
  5. Reset thread state (child is single-threaded per POSIX)
  6. Send MSG_CHILD_READY to central via new ring
  7. Wait for MSG_CHILD_ACK from central
  8. Return 0 to guest code
```

### Step 7: Central activates child

```text
Central:
  1. Receives MSG_CHILD_READY from child's ring
  2. Starts worker thread for child process
  3. Sends MSG_CHILD_ACK
  4. Child is now fully operational
```

### Step 8: Both processes running independently

```text
Parent → parent ring → central worker (parent)
Child  → child ring  → central worker (child)

Independent GlobalState instances in central.
Independent address spaces with CoW sharing in kernel.
```

## Multi-Threaded Fork

POSIX specifies that fork in a multi-threaded process creates a child
with only one thread (the calling thread). Other threads do not exist
in the child. This simplifies our design:

- **Parent**: All threads continue normally. No disruption.
- **Child**: Only the forking thread's micro-LiteBox state matters.
  Other threads' ring buffer slots are irrelevant (those threads
  don't exist in the child).
- **Central**: Child's GlobalState starts with thread count = 1.
  Thread slots are reset.

### Hazard: Locks held by other threads

If other threads in the parent held locks (e.g., malloc mutex) at fork
time, those locks are duplicated in locked state in the child. This is
a well-known POSIX problem. Mitigations:

- Micro-LiteBox itself holds NO locks (by design), so its state is safe
- Guest-side locks (glibc malloc, etc.) are the guest's responsibility
- We support `pthread_atfork()` handlers for cleanup

## Handling the Child Ring FD

The child's ring buffer fd must be available in the child process after
fork. Options:

**Chosen approach**: Central creates the memfd before authorizing fork.
The fd number is communicated in the CQ entry. Micro-LiteBox calls
`dup2()` to place it at a known fd number before fork. After fork, both
parent and child have the fd. Parent closes it. Child uses it to mmap
the new ring.

Alternative considered: Using `pidfd_getfd()` or `/proc/pid/fd` after
fork — rejected as more complex and racy.

## Error Handling

| Error | Handling |
|-------|----------|
| Central denies fork | Return -EPERM to guest |
| clone() fails in micro | Report failure to central, central rolls back child state |
| Child fails to map ring | Child exits with error, central cleans up |
| Child MSG_CHILD_READY timeout | Central kills child, cleans up |
| Parent dies before child init | Central detects via ring disconnect, reparents child |

## Fork + Exec Pattern

The common `fork() + exec()` pattern is optimized in Part 4 (Exec Flow).
Central can detect when exec immediately follows fork and skip some
setup work (e.g., deep-copying state that will be thrown away on exec).

Future optimization: support `vfork()` semantics where the parent is
suspended until the child calls exec/exit, avoiding unnecessary CoW
page faults.
