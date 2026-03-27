# Micro-LiteBox Design — Part 4: Exec Flow

## Overview

`exec()` replaces the current process image with a new program. In the
micro-LiteBox architecture, this requires coordination between micro
(which must load the new binary into the guest address space) and
central (which manages the logical process state reset).

## Exec Sequence

### Step 1: Guest calls execve()

```text
Guest: execve("/bin/ls", argv, envp);
→ Intercepted by seccomp → micro-LiteBox
```

### Step 2: Micro forwards to central

```text
Micro-LiteBox:
  // Copy path, argv, envp into shared data region
  write_to_shared(path, argv, envp);
  submit(SqEntry {
      syscall_nr: SYS_execve,
      data_offset: ...,
      data_len: ...,
  });
  wait_for_completion();
```

### Step 3: Central prepares ExecPlan

Central performs all the work that doesn't require guest address space
access:

```text
Central:
  1. Resolve path (PATH lookup, symlink resolution)
  2. Read binary headers (ELF validation)
  3. Check permissions (execute bit, setuid/setgid)
  4. Determine binary type (static, dynamic, interpreter needed)
  5. Compute memory layout:
     - Text segment: addr, size, offset in file
     - Data segment: addr, size, offset in file
     - BSS: addr, size
     - Stack: addr, size
     - Interpreter (ld-linux.so): if dynamic binary
     - VDSO, auxv entries
  6. Handle close-on-exec fds (close them in fd table)
  7. Reset signal dispositions to SIG_DFL
  8. Build ExecPlan and send to micro
```

### Step 4: ExecPlan structure

```text
struct ExecPlan {
    /// Segments to unmap (tear down old address space)
    unmaps: Vec<(addr, len)>,

    /// Segments to map from the binary
    maps: Vec<MapSegment>,

    /// Initial stack contents (argv, envp, auxv)
    stack: StackSetup,

    /// Entry point address
    entry_point: u64,

    /// Interpreter entry point (if dynamic)
    interp_entry: Option<u64>,

    /// Binary data chunks (in shared data region)
    binary_chunks: Vec<DataChunk>,
}

struct MapSegment {
    addr: u64,
    len: u64,
    prot: u32,         // PROT_READ | PROT_WRITE | PROT_EXEC
    flags: u32,        // MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS
    data_offset: u32,  // Offset in shared region (if file-backed)
    data_len: u32,     // Length of initial data
    file_offset: u64,  // Offset in original binary
}
```

### Step 5: Micro executes ExecPlan locally

```text
Micro-LiteBox:
  1. Unmap old segments (munmap each entry in unmaps)
  2. Map new segments (mmap MAP_FIXED for each map entry)
  3. Copy binary data from shared region into mapped pages
  4. Set up initial stack (argv, envp, auxv)
  5. Reset micro-LiteBox state:
     - Clear cached values
     - Reset seq counter
     - Keep existing ring buffer (reused!)
  6. Report exec success to central
  7. Jump to entry point (or interpreter entry if dynamic)
```

### Step 6: Central finalizes

```text
Central:
  1. Receives exec success report
  2. Resets process GlobalState:
     - Clear page table metadata (new address space)
     - Keep fd table (minus close-on-exec fds, already closed)
     - Reset signals to defaults
     - Clear pending signals
     - Reset credentials if setuid binary
  3. Process continues with new program image
```

## Ring Buffer Survival

The ring buffer shared memory region survives exec because:

- It's mapped in the guest address space via a memfd
- Micro-LiteBox knows its location and remaps it if needed
- The memfd fd is NOT marked close-on-exec

After exec, the new micro-LiteBox runtime (loaded as part of the
process initialization) reconnects to the existing ring buffer using
the preserved fd.

## Large Binary Handling

When binary segments are larger than the shared data region (4 MiB
default), they are transferred in chunks:

```text
Central:
  for chunk in binary.chunks(SHARED_REGION_SIZE) {
      // Write chunk to shared region
      memcpy(shared_region, chunk);
      // Tell micro to consume it
      send_cq(CqEntry {
          flags: FLAG_EXEC_CHUNK,
          data_offset: 0,
          data_len: chunk.len(),
      });
      // Wait for micro to acknowledge
      wait_for_ack();
  }
```

This streaming approach handles arbitrarily large binaries without
requiring a huge shared region.

## Script Execution (Shebang)

For script files (starting with `#!`), central handles the shebang
interpretation:

```text
Central:
  1. Read first line: #!/usr/bin/python3
  2. Recursively resolve interpreter path
  3. Build ExecPlan for the interpreter binary
  4. Include script path in argv (as interpreter argument)
```

The guest never sees the shebang parsing — central handles it entirely.

## Error Handling

| Error | Handling |
|-------|----------|
| Path not found | Central returns -ENOENT, no address space changes |
| Permission denied | Central returns -EACCES, no address space changes |
| Invalid ELF | Central returns -ENOEXEC, no address space changes |
| mmap fails during exec | Micro reports failure, process is killed (POSIX: exec failure after point of no return is fatal) |
| Chunk transfer fails | Process is killed (partially loaded, unrecoverable) |

Key property: If exec fails BEFORE the point of no return (before any
unmaps), the original process image is preserved and the error is
returned to the caller. After the point of no return, failure is fatal.
