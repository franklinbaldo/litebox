# litebox_micro Design Document

## Goal

`litebox_micro` is a lightweight, forkable in-process agent that intercepts
guest syscalls and proxies them to `litebox_central` via shared-memory ring
buffer IPC. It executes locally-authorized operations (mmap, fork, etc.) in
the guest's address space and reports results back to central.

## Architecture

Micro-LiteBox is deliberately "dumb" — it has no ELF loader, no file
descriptor table, no page manager, no policy engine. It is a local execution
agent controlled by central. All syscalls, including locally-executed ones,
require central's authorization first. Micro always reports results back so
central maintains accurate state.

The binary rewriter (litebox_syscall_rewriter) pre-rewrites guest ELF
binaries, replacing `syscall` instructions with `JMP` to trampoline stubs.
Each trampoline stub loads the return address into `RCX` and performs an
indirect jump through the address at trampoline offset 0. At load time,
this address is patched to `micro_syscall_entry` — micro's assembly entry
point.

Central handles ELF loading: it parses the binary, determines the segment
layout, and sends mmap/mprotect commands to micro via the ring buffer. Micro
executes them in the guest's address space. This keeps micro minimal.

## Dependencies

- `litebox_ipc` — SqEntry, CqEntry, ring buffer operations, wait primitives
- `libc` — raw syscalls for local execution (mmap, fork, arch_prctl, etc.)

No dependency on `litebox`, `litebox_shim_linux`, or any platform crate.

## Critical Invariant

All micro state is plain, forkable data. No `Arc`, no `Mutex`, no
cross-process references. When `fork()` duplicates the process, micro's state
is duplicated correctly by CoW.

## Components

### 1. Assembly Trampoline (`trampoline.rs`)

x86_64 only for v1. Entry point compatible with the syscall rewriter's
calling convention:

```
On entry:
  RCX = return address (set by LEA in trampoline stub)
  RAX = syscall number
  RDI, RSI, RDX, R10, R8, R9 = syscall args (Linux ABI)
  R11 = scratch (would contain rflags after real syscall)
```

The assembly entry point:
1. Saves return address to GS-based TLS (`gs:[0x20]`)
2. Builds a `SyscallArgs` struct on the stack (nr + 6 args, 56 bytes)
3. Calls `micro_handle_syscall(args: *const SyscallArgs) -> i64`
4. Restores return address from TLS
5. Returns to guest via `jmp rcx`

```asm
micro_syscall_entry:
    mov     gs:[0x20], rcx          // save return addr to TLS
    sub     rsp, 56                 // SyscallArgs on stack
    mov     [rsp+0x00], rax         // nr
    mov     [rsp+0x08], rdi         // arg0
    mov     [rsp+0x10], rsi         // arg1
    mov     [rsp+0x18], rdx         // arg2
    mov     [rsp+0x20], r10         // arg3
    mov     [rsp+0x28], r8          // arg4
    mov     [rsp+0x30], r9          // arg5
    mov     rdi, rsp                // C arg0 = &SyscallArgs
    call    micro_handle_syscall    // returns result in rax
    add     rsp, 56
    mov     rcx, gs:[0x20]          // restore return addr
    jmp     rcx                     // back to guest
```

### 2. GS-Based Thread-Local Storage (`tls.rs`)

Per-thread state accessed via the GS segment register. The guest uses FS
for its own TLS (glibc); we use GS which is typically unused on x86_64
Linux.

```rust
#[repr(C)]
pub struct MicroTls {
    pub self_ptr: *mut MicroTls,      // gs:0x00
    pub micro: *mut MicroState,       // gs:0x08
    pub thread_slot: u64,             // gs:0x10 (u16 value, u64 for alignment)
    pub seq_counter: u64,             // gs:0x18
    pub return_addr: u64,             // gs:0x20 (used by asm trampoline)
}
```

Initialization: `mmap` a page, fill in fields, call
`arch_prctl(ARCH_SET_GS, ptr)`. This must happen before the seccomp filter
is installed (or use a raw syscall that bypasses seccomp).

Fork safety: GS base is a per-thread CPU register, inherited by fork. The
child's TLS page is CoW-duplicated. We update `micro` pointer in
`post_fork_child`.

### 3. Global Micro State (`state.rs`)

```rust
pub struct MicroState {
    pub ring_base: *mut u8,
    pub ring_size: usize,
    pub ring_fd: i32,
    pub pid: u32,
    pub ppid: u32,
}
```

Stored as a global `static mut`. Only one instance per process. Updated
atomically during fork (child only, single-threaded at that point per POSIX).

### 4. Syscall Handler (`handler.rs`)

The core Rust function called from assembly:

```rust
#[repr(C)]
pub struct SyscallArgs {
    pub nr: u64,
    pub args: [u64; 6],
}

extern "C" fn micro_handle_syscall(args: *const SyscallArgs) -> i64 {
    // 1. Read TLS: get micro state, thread slot, sequence counter
    // 2. Build SqEntry { seq, syscall_nr, thread_slot, args }
    // 3. Push to SQ ring buffer
    // 4. Wake central (futex_wake on SQ notify word)
    // 5. Wait for CqEntry with matching seq (spin-then-futex on CQ slot)
    // 6. If FLAG_EXEC_LOCAL: execute locally, report result back
    // 7. Return result in rax
}
```

### 5. Local Execution (`local_exec.rs`)

When central returns `FLAG_EXEC_LOCAL`, micro executes the real host syscall
in the guest's address space:

- `SYS_mmap` — `libc::mmap()` with possibly adjusted parameters from central
- `SYS_munmap` — `libc::munmap()`
- `SYS_mprotect` — `libc::mprotect()`
- `SYS_mremap` — `libc::mremap()`
- `SYS_madvise` — `libc::madvise()`
- `SYS_brk` — `libc::brk()` / `libc::sbrk()`
- `SYS_clone` (with SIGCHLD) — `libc::fork()` + post-fork setup
- `SYS_arch_prctl` — `libc::syscall(SYS_arch_prctl, ...)`

After execution, micro submits a result-report `SqEntry` so central can
update its state tracking.

### 6. Fork Handling (`fork.rs`)

Fork is the primary motivation for the micro architecture. Flow:

1. Guest calls `fork()` → intercepted → submitted to central
2. Central: validates, allocates child PID, creates child ring buffer
   (memfd_create), deep-copies parent GlobalState, returns
   `FLAG_EXEC_LOCAL + child_ring_fd + child_pid` in CqEntry
3. Micro: `dup2(child_ring_fd, RESERVED_FD)` so both parent and child
   have it after fork. Calls real `fork()`.
4. Parent: closes reserved fd, reports child PID to central, returns to guest
5. Child:
   a. Unmaps parent's ring buffer
   b. Maps own ring buffer from reserved fd
   c. Updates MicroState (pid, ppid, ring_base, ring_fd)
   d. Resets TLS (thread_slot=0, seq_counter=0)
   e. Sends MSG_CHILD_READY to central via new ring
   f. Waits for MSG_CHILD_ACK
   g. Closes reserved fd
   h. Returns 0 to guest

## Public API

```rust
/// Initialize micro-LiteBox. Called once per process.
pub fn micro_init(ring_fd: i32, ring_base: *mut u8, ring_size: usize, pid: u32, ppid: u32);

/// Initialize TLS for the current thread. Called once per thread.
pub fn micro_init_thread(thread_slot: u16);

/// Get the syscall entry point address (for trampoline patching).
pub fn get_syscall_entry_point() -> usize;
```

## What's Out of Scope (v1)

- Multi-thread support (clone with CLONE_VM) — needs thread registration
- exec() support — needs binary loading coordination
- Cached read-only syscalls (getpid, getuid, etc.)
- x86 (32-bit) support
- seccomp fallback for non-rewritten binaries
- The host launcher binary

## Testing Strategy

Unit tests use a mock ring buffer (mmap anonymous memory, initialize ring
headers, simulate central responses):

- `test_tls_init` — verify GS base setup and field access
- `test_sq_submission` — verify SqEntry is correctly built from SyscallArgs
- `test_cq_wait` — verify waiting for CqEntry with matching sequence number
- `test_local_exec_mmap` — verify mmap local execution
- `test_fork_flow` — verify post-fork state (requires real fork)
