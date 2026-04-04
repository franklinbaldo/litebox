# macOS Signal Delivery for litebox_shim_macos

## Goal

Implement macOS-native signal delivery in `litebox_shim_macos` so that guest Mach-O programs can register signal handlers via `sigaction`, receive signals from hardware exceptions (e.g., SIGSEGV from null/bad pointer dereference), inspect/modify `ucontext_t` in the handler, and resume execution via `sigreturn`.

The immediate milestone is passing a `signal.c` test that exercises the full SIGSEGV delivery and recovery cycle. The design supports eventual full macOS signal semantics.

## Approach

**XNU-faithful emulation:** The signal frame layout, struct definitions, register conventions, and syscall interfaces follow the XNU kernel's `sendsig()` / `sigreturn()` ABI exactly. Guest programs compiled with macOS headers work unchanged.

Key simplifications for the initial implementation:
- **No NEON state save/restore** (mcontext `__ns` zeroed out)
- **No sigreturn token validation** (token argument ignored)
- **No `kill`/`tkill`/`tgkill`** (process-directed signals deferred)
- **No `sigaltstack`** (alternate signal stack deferred)
- **No RT signals** (macOS doesn't have them anyway)
- **No `sigpending`/`sigsuspend`/`sigwait`** (deferred)

## macOS Signal ABI Reference

### Signal numbers

macOS uses 32-bit `sigset_t` (signals 1-31). Key signals:

| Signal | Number | Default |
|--------|--------|---------|
| SIGHUP | 1 | Terminate |
| SIGINT | 2 | Terminate |
| SIGQUIT | 3 | Core |
| SIGILL | 4 | Core |
| SIGTRAP | 5 | Core |
| SIGABRT | 6 | Core |
| SIGBUS | 10 | Core |
| SIGSEGV | 11 | Core |
| SIGPIPE | 13 | Terminate |
| SIGTERM | 15 | Terminate |
| SIGKILL | 9 | Terminate (uncatchable) |
| SIGSTOP | 17 | Stop (uncatchable) |

### `struct __sigaction` (kernel-facing, 24 bytes)

This is what the `sigaction(46)` BSD syscall receives from libc:

```
offset  size  field
------  ----  -----
 0       8    sa_handler/sa_sigaction  (function pointer)
 8       8    sa_tramp                (_sigtramp address from libsystem_platform)
16       4    sa_mask                 (sigset_t, 32-bit)
20       4    sa_flags                (SA_SIGINFO, SA_ONSTACK, SA_NODEFER, etc.)
```

### `struct sigaction` (user-facing, 16 bytes)

This is what `sigaction()` returns in `old_act` to userspace:

```
offset  size  field
------  ----  -----
 0       8    sa_handler/sa_sigaction
 8       4    sa_mask
12       4    sa_flags
```

### SA_* flags

```
SA_ONSTACK   = 0x0001
SA_RESTART   = 0x0002
SA_RESETHAND = 0x0004
SA_NOCLDSTOP = 0x0008
SA_NODEFER   = 0x0010
SA_NOCLDWAIT = 0x0020
SA_SIGINFO   = 0x0040
SA_USERTRAMP = 0x0100
SA_64REGSET  = 0x0200
```

### `siginfo_t` (104 bytes)

```
offset  size  field
------  ----  -----
 0       4    si_signo
 4       4    si_errno
 8       4    si_code
12       4    si_pid
16       4    si_uid
20       4    si_status
24       8    si_addr          (faulting address for SIGSEGV/SIGBUS)
32       8    si_value
40       8    si_band
48      56    __pad[7]
```

Signal codes for SIGSEGV: `SEGV_MAPERR = 1` (address not mapped), `SEGV_ACCERR = 2` (permission denied).

### `ucontext_t` (56 bytes, without inline mcontext)

```
offset  size  field
------  ----  -----
 0       4    uc_onstack
 4       4    uc_sigmask       (sigset_t, 32-bit)
 8      24    uc_stack         (stack_t: ss_sp[8], ss_size[8], ss_flags[4], pad[4])
32       8    uc_link
40       8    uc_mcsize        (816 for arm64)
48       8    uc_mcontext      (pointer to mcontext64_t)
```

Note: `uc_mcontext` is a **pointer** to the mcontext, NOT inline. The mcontext is placed separately on the stack and `uc_mcontext` points to it.

### `__darwin_mcontext64` (816 bytes)

```
offset  size  field
------  ----  -----
  0      16   __es  (__darwin_arm_exception_state64)
 16     272   __ss  (__darwin_arm_thread_state64)
288     528   __ns  (__darwin_arm_neon_state64)
```

#### `__darwin_arm_exception_state64` (16 bytes)

```
offset  size  field
------  ----  -----
 0       8    __far        (fault address register)
 8       4    __esr        (exception syndrome register)
12       4    __exception  (arm exception number)
```

#### `__darwin_arm_thread_state64` (272 bytes)

```
offset  size  field
------  ----  -----
  0     232   __x[29]      (general regs x0-x28, 8 bytes each)
232       8   __fp         (frame pointer, x29)
240       8   __lr         (link register, x30)
248       8   __sp         (stack pointer)
256       8   __pc         (program counter)
264       4   __cpsr       (current program status register)
268       4   __pad        (alignment padding)
```

#### `__darwin_arm_neon_state64` (528 bytes)

```
offset  size  field
------  ----  -----
  0     512   __v[32]      (NEON/FP registers v0-v31, 16 bytes each)
512       4   __fpsr       (FP status register)
516       4   __fpcr       (FP control register)
520       8   (padding)
```

### XNU signal frame on guest stack

The kernel's `sendsig()` pushes this frame onto the user stack:

```
High addresses (original SP)
  ┌─────────────────────────────────┐
  │        128-byte red zone        │
  ├─────────────────────────────────┤ ← sp + 160
  │   mcontext64_t (816 bytes)      │
  │     __es (16)                   │
  │     __ss (272)                  │
  │     __ns (528)                  │
  ├─────────────────────────────────┤ ← sp + 104
  │   ucontext_t (56 bytes)         │
  │     uc_mcontext → sp+160        │
  ├─────────────────────────────────┤ ← sp + 0
  │   siginfo_t (104 bytes)         │
  └─────────────────────────────────┘ ← new SP (16-byte aligned)
```

Total frame size: `104 + 56 + 816 = 976 bytes` plus 128-byte red zone = 1104 bytes before alignment.

### Register convention for `_sigtramp` entry

When the kernel delivers a signal, it sets:

```
x0 = catcher          (user signal handler function pointer)
x1 = infostyle        (UC_FLAVOR = 30)
x2 = signal number
x3 = pointer to siginfo_t on stack
x4 = pointer to ucontext_t on stack
x5 = sigreturn token  (0 in our implementation)
pc = sa_tramp          (_sigtramp from libsystem_platform, stored at sigaction time)
sp = new stack pointer (bottom of signal frame)
```

`_sigtramp` then calls the handler as `handler(signum, siginfo*, ucontext*)` and afterwards calls `__sigreturn(uctx, 30, token)`.

### `sigreturn` (BSD syscall 184)

Arguments:
- `x0` = pointer to `ucontext_t`
- `x1` = infostyle (UC_FLAVOR = 30)
- `x2` = token (ignored by our implementation)

Behavior:
1. Read `ucontext_t` from `x0`
2. Read `mcontext64_t` from `uctx->uc_mcontext` (pointer indirection)
3. Restore all general registers from `mcontext.__ss`
4. Restore signal mask from `uctx->uc_sigmask`
5. Resume execution at restored PC

## Data Structures

### Process-level: Signal handler table

Added to `Process` in `litebox_shim_macos/src/lib.rs`:

```rust
/// Per-signal handler registration (matches macOS struct __sigaction).
struct SignalHandler {
    handler: u64,   // sa_handler/sa_sigaction address, or SIG_DFL(0)/SIG_IGN(1)
    tramp: u64,     // sa_tramp (_sigtramp address from libc)
    mask: u32,      // sa_mask (macOS 32-bit sigset_t)
    flags: u32,     // sa_flags
}

// In Process:
signal_handlers: Mutex<Platform, [SignalHandler; 32]>,
```

Signals 1-31 are stored at indices 1-31 (index 0 unused). `Mutex` is `litebox::sync::Mutex<Platform, T>` since the shim is `#![no_std]`.

SIGKILL (9) and SIGSTOP (17) are marked immutable and reject `sigaction` calls.

### Task-level: Per-thread signal state

Added to `Task` in `litebox_shim_macos/src/lib.rs`:

```rust
// In Task:
blocked_signals: AtomicU32,             // sigprocmask state
pending_signals: Mutex<Platform, PendingSignals>,
```

```rust
struct PendingSignals {
    pending: u32,                        // bitmask of pending signals
    info: [MacosSignalInfo; 32],         // siginfo data per signal
}

struct MacosSignalInfo {
    signo: i32,
    code: i32,
    addr: u64,      // fault address for SIGSEGV/SIGBUS
}
```

`last_exception` is not stored separately — the fault address is captured at the point where the signal is queued.

## Syscall Implementations

### `sys_sigaction` (BSD syscall 46)

**File:** `litebox_shim_macos/src/syscalls/signal.rs`

1. Validate `signum` is 1-31; reject SIGKILL(9)/SIGSTOP(17) with `EINVAL`
2. Lock `process.signal_handlers`
3. If `old_act != 0`: write user-facing `struct sigaction` (16 bytes) to guest memory
4. If `new_act != 0`: read kernel-facing `struct __sigaction` (24 bytes) from guest memory, store handler + tramp + mask + flags
5. Return 0 on success

### `sys_sigprocmask` (BSD syscall 48)

**File:** `litebox_shim_macos/src/syscalls/signal.rs`

1. If `oldset != 0`: write current `blocked_signals` (4 bytes) to guest memory
2. If `set != 0`: read new mask (4 bytes) from guest memory
3. Apply based on `how`: `SIG_BLOCK(1)` = OR, `SIG_UNBLOCK(2)` = AND NOT, `SIG_SETMASK(3)` = replace
4. Never allow blocking SIGKILL(9) or SIGSTOP(17)
5. After unmasking, check for deliverable pending signals (future optimization)

### `sys_sigreturn` (BSD syscall 184) — NEW

**File:** `litebox_shim_macos/src/syscalls/signal.rs`

**New syscall number:** add `SIGRETURN = 184` to `litebox_common_macos/src/syscall.rs`
**New enum variant:** add `Sigreturn { uctx: usize, infostyle: i32 }` to `MacosSyscallRequest`

1. Read `ucontext_t` (56 bytes) from guest memory at `x0`
2. Read `mcontext64_t` (816 bytes) from `uctx.uc_mcontext` pointer
3. Restore general registers (x0-x28, fp, lr, sp, pc, cpsr) from `mcontext.__ss` into `PtRegs`
4. Restore signal mask from `uctx.uc_sigmask` into `task.blocked_signals`
5. NEON state: ignored for now
6. Token (x2): ignored
7. Return the restored `x0` value

Special handling: `sigreturn` must NOT follow the normal return-value convention (carry flag + x0). Instead it restores the full register set and resumes at the restored PC. The syscall dispatch must detect `Sigreturn` and skip `set_syscall_return`.

## Signal Delivery

### Exception path change

**File:** `litebox_shim_macos/src/lib.rs`, `MacosShimEntrypoints::exception()`

Current behavior: log and terminate unconditionally.

New behavior:

```
fn exception(&self, ctx, info) -> ContinueOperation {
    let macos_signum = linux_to_macos_signal(info.esr as i32);
    let handler = self.task.process.signal_handlers.lock()[macos_signum as usize];

    match handler.handler {
        0 => {
            // SIG_DFL: terminate (current behavior)
            log_unsupported!("EXCEPTION ...");
            self.task.process.group_exit.store(true, Ordering::Release);
            self.task.terminated.store(true, Ordering::Release);
            ContinueOperation::Terminate
        }
        1 => {
            // SIG_IGN: ignore and resume (unusual for SIGSEGV but valid)
            ContinueOperation::Continue
        }
        _ => {
            // User handler: deliver signal
            self.task.deliver_signal(ctx, macos_signum, info.fault_address, &handler);
            ContinueOperation::Continue
        }
    }
}
```

### Signal number mapping

The platform layer (`exception_signal_handler`) currently passes the Linux signal number in `ExceptionInfo.esr`. The macOS shim needs macOS signal numbers for the guest.

Add `linux_to_macos_signal()` in the shim:

```rust
fn linux_to_macos_signal(linux_sig: i32) -> i32 {
    match linux_sig {
        7 => 10,   // Linux SIGBUS=7 → macOS SIGBUS=10
        4 => 4,    // SIGILL same
        5 => 5,    // SIGTRAP same
        8 => 8,    // SIGFPE same
        11 => 11,  // SIGSEGV same
        _ => linux_sig,
    }
}
```

### `deliver_signal()` — signal frame construction

**File:** new method on `Task` (or in a new `signal.rs` module under `syscalls/`)

Steps:

1. **Compute stack pointer:**
   ```
   frame_size = 104 (siginfo) + 56 (ucontext) + 816 (mcontext) = 976
   new_sp = (ctx.sp - 128 - frame_size) & !0xF  // subtract redzone, align to 16
   ```

2. **Build mcontext64 (816 bytes):**
   - `__es.__far` = fault_address
   - `__es.__esr` = 0
   - `__es.__exception` = 0
   - `__ss.__x[0..29]` = ctx.regs[0..29]
   - `__ss.__fp` = ctx.regs[29]
   - `__ss.__lr` = ctx.regs[30]
   - `__ss.__sp` = ctx.sp
   - `__ss.__pc` = ctx.pc
   - `__ss.__cpsr` = ctx.pstate as u32
   - `__ss.__pad` = 0
   - `__ns` = all zeros (NEON not saved)

3. **Build ucontext (56 bytes):**
   - `uc_onstack` = 0
   - `uc_sigmask` = current `blocked_signals`
   - `uc_stack` = {0, 0, 0} (no altstack support yet)
   - `uc_link` = 0
   - `uc_mcsize` = 816
   - `uc_mcontext` = `new_sp + 160` (pointer to mcontext on stack)

4. **Build siginfo (104 bytes):**
   - `si_signo` = macos signal number
   - `si_errno` = 0
   - `si_code` = `SEGV_MAPERR` (1) for SIGSEGV
   - `si_addr` = fault_address
   - remaining fields = 0

5. **Write frame to guest stack** using `MutPtr::write_at_offset`:
   - siginfo at `new_sp + 0`
   - ucontext at `new_sp + 104`
   - mcontext at `new_sp + 160`

6. **Update blocked mask:** add `handler.mask | (1 << (signum - 1))` unless SA_NODEFER

7. **Set guest registers:**
   ```
   ctx.regs[0] = handler.handler    // x0 = catcher
   ctx.regs[1] = 30                 // x1 = UC_FLAVOR
   ctx.regs[2] = signum             // x2 = signal number
   ctx.regs[3] = new_sp             // x3 = &siginfo
   ctx.regs[4] = new_sp + 104       // x4 = &ucontext
   ctx.regs[5] = 0                  // x5 = token (ignored)
   ctx.pc = handler.tramp           // pc = _sigtramp
   ctx.sp = new_sp                  // sp = new stack
   ```

## Test

### Test source: `signal.c`

**File:** `litebox_runner_macos_on_macos_userland/tests/signal.c`

```c
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void *recover_ip;

void segv_handler(int sig, siginfo_t *info, void *ctx) {
    printf("Caught signal %d (Segmentation fault)\n", sig);
    printf("  Fault address: %p\n", info->si_addr);

    if (info->si_addr != (void *)0xdeadbeef) {
        _exit(1);
    }

    ucontext_t *uctx = (ucontext_t *)ctx;
    uctx->uc_mcontext->__ss.__pc = (uint64_t)recover_ip;
}

int main() {
    struct sigaction sa = {0};
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    recover_ip = &&after_fault;

    printf("About to trigger SIGSEGV...\n");

    volatile int *p = (volatile int *)0xdeadbeef;
    *p = 42;

after_fault:
    printf("Resumed after skipping faulting instruction.\n");
    printf("Test succeeded; continuing normal execution.\n");
    return 0;
}
```

### Expected output

```
About to trigger SIGSEGV...
Caught signal 11 (Segmentation fault)
  Fault address: 0xdeadbeef
Resumed after skipping faulting instruction.
Test succeeded; continuing normal execution.
```

### Test function

```rust
#[test]
fn test_signal() {
    let _lock = TEST_LOCK.lock();
    let binary = compile_macho_dynamic("tests/signal.c");
    let (exit_code, stdout, _stderr) = run_macho_dynamic(&binary, &["signal"], &["PATH=/bin"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("Caught signal 11"));
    assert!(stdout.contains("Fault address: 0xdeadbeef"));
    assert!(stdout.contains("Test succeeded"));
}
```

## Module Organization

Signal-related code goes in a new module: `litebox_shim_macos/src/syscalls/signal.rs`

This module contains:
- `SignalHandler` struct
- `PendingSignals` struct
- `MacosSignalInfo` struct
- `deliver_signal()` method
- `sys_sigaction()` implementation
- `sys_sigprocmask()` implementation
- `sys_sigreturn()` implementation
- `linux_to_macos_signal()` helper
- Signal frame struct definitions (repr(C) for writing to guest memory)

The stubs in `stubs.rs` are removed and replaced with calls to the new module.

## Files Modified

| File | Change |
|------|--------|
| `litebox_common_macos/src/syscall.rs` | Add `SIGRETURN = 184`, add `Sigreturn` variant |
| `litebox_shim_macos/src/lib.rs` | Add signal fields to `Process` and `Task`, change `exception()` |
| `litebox_shim_macos/src/syscalls/mod.rs` | Add `signal` module, route `Sigreturn` |
| `litebox_shim_macos/src/syscalls/signal.rs` | New file: all signal logic |
| `litebox_shim_macos/src/syscalls/stubs.rs` | Remove `sys_sigaction` and `sys_sigprocmask` stubs |
| `litebox_runner_macos_on_macos_userland/tests/signal.c` | New test source |
| `litebox_runner_macos_on_macos_userland/tests/loader.rs` | Add `test_signal` |

## Future Work (Not in Scope)

- `sigaltstack` (BSD syscall 53)
- `kill`/`tkill` (process-directed signals)
- `sigsuspend`/`sigpending`/`sigwait`
- NEON state save/restore in mcontext
- Sigreturn token validation
- `SA_RESETHAND` (reset handler to SIG_DFL after delivery)
- `SA_RESTART` (restart interrupted syscalls)
- Signal delivery on syscall return path (pending signal processing loop)
- Child signal handling (SIGCHLD, SA_NOCLDSTOP, SA_NOCLDWAIT)
