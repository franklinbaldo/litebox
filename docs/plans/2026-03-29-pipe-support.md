# Pipe Support for UnixBench context1 Benchmark

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable pipe-based I/O through micro-LiteBox so the UnixBench "Pipe-based Context Switching" benchmark (`context1.c`) runs correctly.

**Architecture:** Pipes are created as real OS pipes in micro's process (EXEC_LOCAL), not as virtual shim pipes. This means pipe fds exist as real kernel fds, inherited across fork. Read/write on pipe fds goes directly through the OS. Close is dual-dispatched (central first for shim cleanup, then EXEC_LOCAL for real fd close). Central's data-producing IO for `read` falls back to EXEC_LOCAL when the shim returns EBADF (meaning the fd is a real OS fd, not a shim-managed fd).

**Tech Stack:** Rust, libc, litebox_ipc, litebox_central, litebox_micro

---

### Task 1: Add pipe2, alarm, close, signal to needs_local_exec + micro handlers

**Files:**
- Modify: `litebox_central/src/server.rs` — `needs_local_exec()` function
- Modify: `litebox_central/src/server.rs` — `handle_data_producing_io()` for read EBADF fallback  
- Modify: `litebox_central/src/server.rs` — `handle_syscall()` for close dual-dispatch
- Modify: `litebox_micro/src/local_exec.rs` — `execute_locally()` match arms

**Step 1: Add pipe2, alarm to needs_local_exec in central**

In `litebox_central/src/server.rs`, add to the `needs_local_exec` match:
```rust
// Pipe: create real OS pipes in micro's process.
| libc::SYS_pipe2
// Timer: process-level alarm must run in micro.
| libc::SYS_alarm
```

**Step 2: Add close dual-dispatch to handle_syscall in central**

In `litebox_central/src/server.rs`, add a new block in `handle_syscall()` before the `needs_local_exec` check:

```rust
// Close: dual-dispatch. Try shim first for fd table cleanup, then
// always EXEC_LOCAL so micro closes the real fd.
#[allow(clippy::cast_possible_truncation)]
if nr == libc::SYS_close as u32 {
    let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
    let shim_result = self.dispatch_to_task(entry.thread_slot, &mut regs);
    // Ignore EBADF from shim (fd may be a real OS fd not in shim's table).
    let _ = shim_result;
    cq.flags = cq_flags::EXEC_LOCAL;
    return cq;
}
```

**Step 3: Add read EBADF fallback in handle_data_producing_io**

In the `SYS_read` arm of `handle_data_producing_io()`, after `self.dispatch_to_task(...)`, if the result is `-EBADF`, fall through to EXEC_LOCAL instead of returning the error:

```rust
libc::SYS_read => {
    let count = entry.args[2] as usize;
    let capped = count.min(data_region.len());
    regs.rsi = data_ptr;
    regs.rdx = capped;
    cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
    if cq.result > 0 {
        cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA;
        cq.data_offset = 0;
        cq.data_len = cq.result as u32;
    } else if cq.result == 0 {
        cq.flags = cq_flags::EXEC_LOCAL;
    } else if cq.result == -i64::from(libc::EBADF) {
        // Fd not in shim's table — it's a real OS fd (e.g. pipe).
        // Let micro execute the read locally.
        cq.result = 0;
        cq.flags = cq_flags::EXEC_LOCAL;
    }
    // Other negative: error, pass through directly.
}
```

**Step 4: Add pipe2, alarm, close, read-local handlers to execute_locally in micro**

In `litebox_micro/src/local_exec.rs`, add match arms:

```rust
nr if nr == libc::SYS_pipe2 as u32 => unsafe {
    libc::syscall(
        libc::SYS_pipe2,
        args[0] as usize, // pipefd[2] pointer
        args[1] as i32,   // flags
    )
},
nr if nr == libc::SYS_alarm as u32 => unsafe {
    libc::syscall(libc::SYS_alarm, args[0] as u32)
},
nr if nr == libc::SYS_close as u32 => unsafe {
    libc::syscall(libc::SYS_close, args[0] as i32)
},
```

Also modify the `SYS_read` arm to handle the case where `cq.flags` has `EXEC_LOCAL` but NOT `HAS_DATA` and `cq.result == 0` (the EBADF fallback case). In this case, execute read locally:

```rust
nr if nr == libc::SYS_read as u32 => {
    if cq.flags & cq_flags::HAS_DATA != 0 {
        // Central read file data into the shmem data region.
        let guest_buf = args[1] as *mut u8;
        let data_len = cq.data_len as usize;
        if !ring_base.is_null() && data_len > 0 {
            unsafe {
                let data_src = ring_base
                    .add(layout.data_region_offset)
                    .add(cq.data_offset as usize);
                core::ptr::copy_nonoverlapping(data_src, guest_buf, data_len);
            }
        }
        cq.result
    } else if cq.result == 0 && cq.flags & cq_flags::EXEC_LOCAL != 0 {
        // EBADF fallback or EOF: if EXEC_LOCAL is set and no HAS_DATA,
        // execute read locally (the fd is a real OS fd like a pipe).
        unsafe {
            libc::syscall(
                libc::SYS_read,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
            )
        }
    } else {
        // Error or EOF from central dispatch.
        cq.result
    }
}
```

**Step 5: Build and run unit tests**

```bash
cargo build -p litebox_central -p litebox_micro
cargo nextest run -p litebox_micro
```

**Step 6: Commit**

```bash
git add litebox_central/src/server.rs litebox_micro/src/local_exec.rs
git commit -m "feat: add pipe2, alarm, close, and read EBADF fallback for pipe support"
```

### Task 2: Write and run pipe_nolibc integration test

**Files:**
- Create: `litebox_launcher/tests/pipe_nolibc.c` — simple nolibc test program that creates a pipe, writes, reads, verifies
- Modify: `litebox_launcher/tests/integration.rs` — add `test_pipe_nolibc_end_to_end`

**Step 1: Write pipe_nolibc.c**

```c
// Minimal nolibc pipe test: pipe2 → write → read → verify → exit
#include <unistd.h>

// Raw syscall helpers (nolibc)
static long my_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    register long r10 __asm__("r10") = a3;
    register long r8  __asm__("r8")  = a4;
    register long r9  __asm__("r9")  = a5;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

#define SYS_write   1
#define SYS_close   3
#define SYS_pipe2   293
#define SYS_exit_group 231
#define SYS_read    0

void _start(void) {
    int pipefd[2];
    
    // Create pipe
    long ret = my_syscall(SYS_pipe2, (long)pipefd, 0, 0, 0, 0, 0);
    if (ret != 0) {
        const char msg[] = "pipe2 failed\n";
        my_syscall(SYS_write, 2, (long)msg, sizeof(msg)-1, 0, 0, 0);
        my_syscall(SYS_exit_group, 1, 0, 0, 0, 0, 0);
    }
    
    // Write to pipe
    unsigned long val = 0xDEADBEEF;
    ret = my_syscall(SYS_write, pipefd[1], (long)&val, sizeof(val), 0, 0, 0);
    if (ret != sizeof(val)) {
        const char msg[] = "write failed\n";
        my_syscall(SYS_write, 2, (long)msg, sizeof(msg)-1, 0, 0, 0);
        my_syscall(SYS_exit_group, 1, 0, 0, 0, 0, 0);
    }
    
    // Close write end
    my_syscall(SYS_close, pipefd[1], 0, 0, 0, 0, 0);
    
    // Read from pipe
    unsigned long check = 0;
    ret = my_syscall(SYS_read, pipefd[0], (long)&check, sizeof(check), 0, 0, 0);
    if (ret != sizeof(check)) {
        const char msg[] = "read failed\n";
        my_syscall(SYS_write, 2, (long)msg, sizeof(msg)-1, 0, 0, 0);
        my_syscall(SYS_exit_group, 1, 0, 0, 0, 0, 0);
    }
    
    // Close read end
    my_syscall(SYS_close, pipefd[0], 0, 0, 0, 0, 0);
    
    // Verify
    if (check == 0xDEADBEEF) {
        const char msg[] = "Pipe test passed!\n";
        my_syscall(SYS_write, 1, (long)msg, sizeof(msg)-1, 0, 0, 0);
        my_syscall(SYS_exit_group, 0, 0, 0, 0, 0, 0);
    } else {
        const char msg[] = "Pipe data mismatch!\n";
        my_syscall(SYS_write, 2, (long)msg, sizeof(msg)-1, 0, 0, 0);
        my_syscall(SYS_exit_group, 1, 0, 0, 0, 0, 0);
    }
}
```

**Step 2: Add integration test**

Follow the same pattern as `test_hello_nolibc_end_to_end` but for the pipe test program. Assert stdout contains "Pipe test passed!" and exit is success.

**Step 3: Build and run test**

```bash
cargo nextest run -p litebox_launcher -- --ignored test_pipe_nolibc
```

**Step 4: Commit**

```bash
git add litebox_launcher/tests/pipe_nolibc.c litebox_launcher/tests/integration.rs
git commit -m "test: add pipe_nolibc integration test"
```

### Task 3: Write and run pipe_fork_nolibc integration test

**Files:**
- Create: `litebox_launcher/tests/pipe_fork_nolibc.c` — nolibc test: pipe → fork → parent writes, child reads, verifies
- Modify: `litebox_launcher/tests/integration.rs` — add `test_pipe_fork_nolibc_end_to_end`

**Step 1: Write pipe_fork_nolibc.c**

A nolibc program that:
1. Creates a pipe with pipe2
2. Forks
3. Parent closes read end, writes a value, closes write end, waits for child
4. Child closes write end, reads a value, verifies, prints result, exits

**Step 2: Add integration test**

Assert stdout contains "Pipe fork test passed!" and exit is success.

**Step 3: Build and run test**

```bash
cargo nextest run -p litebox_launcher -- --ignored test_pipe_fork_nolibc
```

**Step 4: Commit**

### Task 4: Run UnixBench context1 benchmark through litebox

**Files:**
- Create: `litebox_launcher/tests/context1.c` — copy of UnixBench context1.c (with timeit.c inlined)
- Modify: `litebox_launcher/tests/integration.rs` — add `test_context1_benchmark`

This is a dynamic glibc program, so it needs the packager workflow (same as test_dynamic_hello_world).

**Step 1: Prepare context1.c with inlined timeit.c**

**Step 2: Add integration test**

Follow the `test_dynamic_hello_world` pattern but for context1. Run with a 1-second duration. Assert stderr contains "COUNT|" (the output format) and exit is success.

**Step 3: Build and run test**

```bash
cargo nextest run -p litebox_launcher -- --ignored test_context1
```

**Step 4: Commit**
