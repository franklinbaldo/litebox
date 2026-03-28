# Phase C: Integration Testing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the full launcher→micro→central pipeline end-to-end and run a minimal "hello world" guest binary through it, proving the micro-LiteBox architecture works.

**Architecture:** Fix the remaining gaps (shmem fd handoff, futex flags, exit detection), create a test harness that compiles+rewrites a nolibc static binary, and run it through the full pipeline: launcher creates shmem → spawns central → inits micro → loads ELF → guest writes "Hello" via ring-buffer IPC → central handles it → guest exits.

**Tech Stack:** Rust (edition 2024), libc, litebox_syscall_rewriter, gcc (static nolibc compilation)

---

### Task 1: Fix futex flag mismatch in litebox_micro

**Files:**
- Modify: `litebox_micro/src/handler.rs`

The micro side uses `FUTEX_PRIVATE_FLAG` on all futex operations. Private futexes only work within a single address space. Since micro and central are separate processes sharing memory via `MAP_SHARED` memfd, the private flag must be removed.

**Step 1: Remove FUTEX_PRIVATE_FLAG from futex_wait and futex_wake**

In `handler.rs`, the `futex_wait` function uses:
```rust
libc::SYS_futex, addr, libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG, expected, ...
```
Change to:
```rust
libc::SYS_futex, addr, libc::FUTEX_WAIT, expected, ...
```

Same for `futex_wake`:
```rust
libc::SYS_futex, addr, libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG, 1, ...
```
Change to:
```rust
libc::SYS_futex, addr, libc::FUTEX_WAKE, 1, ...
```

**Step 2: Verify**

Run: `cargo nextest run -p litebox_micro`
Expected: All tests pass (futex operations still work without PRIVATE_FLAG in same-process tests).

Run: `cargo clippy -p litebox_micro -- -D warnings`
Expected: Clean.

---

### Task 2: Make SharedRegion::from_fd public in litebox_central

**Files:**
- Modify: `litebox_central/src/shmem.rs`

Change `fn from_fd(...)` to `pub fn from_fd(...)`. This allows `main.rs` to construct a `SharedRegion` from a launcher-provided fd.

**Step 1: Make from_fd pub**

Change the signature from:
```rust
fn from_fd(fd: OwnedFd, layout: SharedRingLayout) -> anyhow::Result<Self>
```
to:
```rust
pub fn from_fd(fd: OwnedFd, layout: SharedRingLayout) -> anyhow::Result<Self>
```

**Step 2: Verify**

Run: `cargo check -p litebox_central`
Expected: PASS

---

### Task 3: Add --shmem-fd CLI argument to litebox_central

**Files:**
- Modify: `litebox_central/Cargo.toml` (add `clap` dependency)
- Modify: `litebox_central/src/main.rs`

Central must accept `--shmem-fd=N` to use a launcher-provided shared memory fd instead of creating its own.

**Step 1: Add clap dependency**

In `litebox_central/Cargo.toml`, add:
```toml
clap = { version = "4", features = ["derive"] }
```

**Step 2: Add CLI parsing to main.rs**

```rust
use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Shared memory file descriptor (inherited from launcher).
    /// If not provided, central creates its own shmem.
    #[arg(long)]
    shmem_fd: Option<i32>,
}
```

In `main()`:
```rust
let args = Args::parse();
let region = if let Some(fd) = args.shmem_fd {
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let layout = SharedRingLayout::default_layout();
    shmem::SharedRegion::from_fd(owned_fd, layout)?
} else {
    shmem::SharedRegion::new()?
};
```

**Step 3: Verify**

Run: `cargo check -p litebox_central`
Expected: PASS

---

### Task 4: Expose is_exiting on LinuxShimTask

**Files:**
- Modify: `litebox_shim_linux/src/lib.rs`

Central's server loop needs to know when the guest has called `exit_group()` so it can stop looping and exit. Currently `dispatch_syscall` returns 0 for both exit and success, with no way to distinguish.

Add a method to `LinuxShimTask`:

```rust
impl<FS: ShimFS> LinuxShimTask<FS> {
    /// Returns true if the task's process has started exiting
    /// (e.g. after exit_group was called).
    pub fn is_exiting(&self) -> bool {
        self.task.is_exiting()
    }
}
```

Note: `Task::is_exiting()` already exists at `litebox_shim_linux/src/syscalls/process.rs:310-312`.

**Verify:**

Run: `cargo check -p litebox_shim_linux`
Expected: PASS

---

### Task 5: Update central server loop with exit detection

**Files:**
- Modify: `litebox_central/src/server.rs`

After dispatching a syscall, check `self.task.is_exiting()`. If true, push the final CQ entry, then break the loop and return.

In `server.rs`, after the `handle_syscall` call and CQ push/notify, add:
```rust
// Check if the guest process is exiting.
if self.task.is_exiting() {
    eprintln!("litebox_central: guest exiting");
    break;
}
```

Also update `run` to return `Ok(())` on clean exit.

**Verify:**

Run: `cargo check -p litebox_central`
Expected: PASS

---

### Task 6: Update launcher's central spawn to exec litebox_central

**Files:**
- Modify: `litebox_launcher/src/central.rs`

Replace the child's `exit(0)` stub with an actual `exec` of `litebox_central`. The launcher finds the central binary via `std::env::current_exe()` path heuristics (same directory as the launcher binary, or via an env var).

```rust
0 => {
    // Child: exec litebox_central with --shmem-fd=N
    let fd_arg = format!("--shmem-fd={shmem_fd}");
    let central_path = find_central_binary();
    let c_path = CString::new(central_path).unwrap();
    let c_arg0 = CString::new("litebox_central").unwrap();
    let c_arg1 = CString::new(fd_arg).unwrap();
    let args = [c_arg0.as_ptr(), c_arg1.as_ptr(), std::ptr::null()];
    unsafe { libc::execvp(c_path.as_ptr(), args.as_ptr()) };
    // If exec failed:
    eprintln!("litebox_launcher: exec litebox_central failed: {}", std::io::Error::last_os_error());
    std::process::exit(1);
}
```

Where `find_central_binary()` first checks `LITEBOX_CENTRAL_PATH` env var, then checks the same directory as the current executable, then falls back to just `"litebox_central"` (relying on PATH).

**Verify:**

Run: `cargo check -p litebox_launcher`
Expected: PASS

---

### Task 7: Wait for central readiness before loading ELF

**Files:**
- Modify: `litebox_launcher/src/main.rs`

After spawning central, the launcher should wait briefly for central to initialize before loading the ELF and jumping to guest. Central writes to the ring header when ready.

Simple approach: sleep briefly (e.g. 100ms) to let central initialize. A more robust approach would be a readiness futex in the ring header, but that requires modifying litebox_ipc. For the initial integration, a small sleep is acceptable.

Add after central spawn:
```rust
// Give central time to initialize (platform, shim, server loop).
// TODO: Replace with proper readiness signaling via ring header.
std::thread::sleep(std::time::Duration::from_millis(200));
```

**Verify:**

Run: `cargo check -p litebox_launcher`
Expected: PASS

---

### Task 8: Add initial brk to central's headless task

**Files:**
- Modify: `litebox_central/src/server.rs` or `litebox_central/src/main.rs`

The shim's `PageManager::brk()` panics if the initial brk hasn't been set. For the headless task (created via `create_task`, no ELF loading), we need to set it manually.

The `GlobalState` has a `pm` (PageManager) field. We need to call `pm.set_initial_brk(some_address)` before any brk syscall can be served.

However, `GlobalState` is `pub(crate)` and `PageManager::set_initial_brk` may not be easily accessible. A simpler approach: since we're using a nolibc binary for the initial test, brk won't be called. Add a TODO comment and defer this to when libc-linked binaries are supported.

In `server.rs`, add a comment in `handle_syscall`:
```rust
// TODO: set_initial_brk in PageManager before serving brk() syscalls.
// Currently, the headless task has brk=0 which will panic on brk().
// This is OK for nolibc test binaries that don't call brk.
```

---

### Task 9: Create integration test binary and test harness

**Files:**
- Create: `litebox_launcher/tests/integration.rs`
- Create: `litebox_launcher/tests/hello_nolibc.c`

**Step 1: Create the test C source**

A minimal nolibc static binary that writes "Hello from micro-LiteBox!\n" to stdout and exits:

```c
// hello_nolibc.c — minimal no-libc test binary for micro-LiteBox integration
// Compile: gcc -static -nostdlib -o hello_nolibc hello_nolibc.c
#include <asm/unistd.h>

void _start(void) {
    const char msg[] = "Hello from micro-LiteBox!\n";
    // write(1, msg, sizeof(msg)-1)
    long ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(__NR_write), "D"(1), "S"(msg), "d"(sizeof(msg)-1)
        : "rcx", "r11", "memory"
    );
    // exit_group(0)
    asm volatile(
        "syscall"
        :
        : "a"(__NR_exit_group), "D"(0)
        : "rcx", "r11", "memory"
    );
    __builtin_unreachable();
}
```

**Step 2: Create the integration test**

The test:
1. Compiles `hello_nolibc.c` with `gcc -static -nostdlib`
2. Rewrites it with `litebox_syscall_rewriter` (via `cargo run -p litebox_syscall_rewriter`)
3. Builds `litebox_launcher` and `litebox_central` (via `cargo build -p litebox_launcher -p litebox_central`)
4. Runs `litebox_launcher <rewritten-binary>` as a subprocess
5. Captures stderr (where central's StdioProvider writes guest stdout)
6. Asserts the output contains "Hello from micro-LiteBox!"
7. Asserts the exit code is 0

```rust
use std::process::Command;

#[test]
#[ignore] // Run with: cargo nextest run -p litebox_launcher -- --ignored
fn test_hello_nolibc_end_to_end() {
    // Step 1: Compile
    let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let c_src = test_dir.join("hello_nolibc.c");
    let compiled = test_dir.join("hello_nolibc");
    let status = Command::new("gcc")
        .args(["-static", "-nostdlib", "-o"])
        .arg(&compiled)
        .arg(&c_src)
        .status()
        .expect("gcc should run");
    assert!(status.success(), "gcc compilation failed");

    // Step 2: Rewrite
    let rewritten = test_dir.join("hello_nolibc.hooked");
    let status = Command::new("cargo")
        .args(["run", "-p", "litebox_syscall_rewriter", "--"])
        .arg(&compiled)
        .arg("-o")
        .arg(&rewritten)
        .status()
        .expect("rewriter should run");
    assert!(status.success(), "syscall rewriter failed");

    // Step 3: Build launcher + central
    let status = Command::new("cargo")
        .args(["build", "-p", "litebox_launcher", "-p", "litebox_central"])
        .status()
        .expect("cargo build should run");
    assert!(status.success(), "build failed");

    // Step 4: Run launcher
    let target_dir = /* find target/debug dir */;
    let launcher = target_dir.join("litebox_launcher");
    let output = Command::new(&launcher)
        .arg(&rewritten)
        .output()
        .expect("launcher should run");

    // Step 5: Check output
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Hello from micro-LiteBox!"),
        "Expected guest output in stderr, got: {stderr}"
    );
    assert!(
        output.status.success(),
        "launcher exited with status: {:?}\nstderr: {stderr}",
        output.status
    );
}
```

**Step 3: Verify**

Run: `cargo nextest run -p litebox_launcher -- --ignored`
Expected: The test compiles, rewrites, launches, and the guest output appears.

---

### Task 10: Fix issues discovered during integration testing — COMPLETE

Nine bugs were found and fixed during integration testing:

**BUG 1 (FIXED):** `jump_to_guest` zeroed all registers including inputs — the inline asm zeroed RCX/RDX via `xor` before using them as `in(reg)` operands. Fix: explicit register constraints (`in("rcx")`, `in("rdx")`), zero those registers after consuming them. File: `litebox_launcher/src/entry.rs`

**BUG 2 (FIXED):** `sq_notify` counter never incremented — micro's `submit_and_wait` called `futex_wake(&header.sq_notify)` but never incremented the counter. Central's `spin_then_wait` waited for the VALUE to change, which never happened. Fix: added `header.sq_notify.fetch_add(1, Release)` before `futex_wake`. File: `litebox_micro/src/handler.rs`

**BUG 3 (FIXED):** Central filesystem missing device nodes — bare `InMemFs` caused panic because `/dev/stdin`, `/dev/stdout`, `/dev/stderr` don't exist. Fix: layered FS with `devices(upper)` + `in_mem(lower)` using `LowerLayerWritableFiles` semantics. File: `litebox_central/src/main.rs`

**BUG 4 (FIXED):** Central panics on guest pointer dereference — syscalls with guest memory pointers (write, read, etc.) cannot be executed by central (separate address space). Fix: central returns `EXEC_LOCAL` flag for pointer-bearing syscalls; micro executes them locally via real syscalls. For exit/exit_group, central also dispatches through the shim before returning EXEC_LOCAL. Files: `litebox_central/src/server.rs`, `litebox_micro/src/local_exec.rs`

**BUG 5 (FIXED):** Central server TOCTOU in SQ consumption — between `sq_try_consume()` returning false and loading `sq_notify`, micro could publish the entry AND increment sq_notify. Fix: double-check `sq_try_consume()` after loading sq_notify but before `spin_then_wait`. File: `litebox_central/src/server.rs`

**BUG 6 (FIXED):** Micro CQ search_start captured too late — `search_start = cq_tail(header)` was set AFTER submitting the SQ entry, missing fast completions. Fix: capture `cq_tail(header)` BEFORE publishing the SQ entry. File: `litebox_micro/src/handler.rs`

**BUG 7 (FIXED):** Micro CQ search_start updated past entries in wait loop — at the bottom of the CQ wait loop, `search_start = cq_tail(header)` jumped past unscanned entries. Fix: removed the update; search_start is set once before submission. File: `litebox_micro/src/handler.rs`

**BUG 8 (FIXED):** Central child process holds parent's stdout/stderr pipes — `Command::output()` waits for ALL pipe handles to close, but the forked central inherits the launcher's pipe handles. Fix: redirect child's stdout to `/dev/null` after fork, before exec. File: `litebox_launcher/src/central.rs`

**BUG 9 (FIXED):** Trampoline clobbers guest's red zone — the micro trampoline's `sub rsp, 56` for `SyscallArgs` overlapped with the guest's 128-byte red zone (below RSP) used by leaf functions and inline asm. Fix: added `sub rsp, 128` to skip the red zone before allocating `SyscallArgs`. File: `litebox_micro/src/trampoline.rs`

---

## Notes

- ALL 10 TASKS COMPLETE. The full pipeline works end-to-end.
- The nolibc binary avoids `brk()`, `mmap()`, and other complex syscalls — it only uses `write()` and `exit_group()`, which are the simplest to handle through the full pipeline.
- Guest `write()` is executed locally by micro (EXEC_LOCAL path). Guest output appears on launcher's stdout.
- The `#[ignore]` attribute on the integration test means it won't run in normal `cargo nextest run`. Use `--ignored` flag to opt in.
- After this phase works, Phase D (multi-thread) and Phase E (exec) can build on the proven pipeline.
- The `litebox_central` binary must be built separately (it's excluded from default-members). The test handles this via explicit `cargo build -p litebox_central`.
