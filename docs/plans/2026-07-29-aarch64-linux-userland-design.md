# AArch64 support for `litebox_platform_linux_userland`

Status: accepted design, not yet implemented.

Goal: run a rewritten static hello-world end to end under
`litebox_runner_linux_userland` on `aarch64-unknown-linux-gnu`.

This supersedes the earlier attempt on `sanghle/arm64/mac/shim9`. That branch
predates the current `litebox_syscall_rewriter` AArch64 ABI, which changed the
thread-pointer model and made most of the old machinery unnecessary.

## 1. Background: what the rewriter guarantees

`litebox_syscall_rewriter/src/arm64.rs` rewrites each guest `SVC #imm` into a
`B` to a 32-byte per-site gate, which branches to a shared 2-instruction handler
that loads the callback address from trampoline offset 0 and does `BR X16`. Each
gate is followed by its own 12-byte *outbound stub*, the runtime's normal way
back into the guest (see section 3).

State on entry to the callback:

| Item | Value |
| --- | --- |
| `x16` | clobbered (holds the callback address) |
| `[sp, #0]` | saved guest `x16` |
| `[sp, #8]` | guest resume PC (`svc_site + 4`) |
| `[sp, #16]` | this site's outbound stub address |
| `sp` | guest SP minus 32 (gate frame is live) |
| `x0`–`x15`, `x17`–`x30`, NZCV | pristine guest values |
| `TPIDR_EL0` | the **host** anchor |
| `[TPIDR_EL0 + 16]` | the **guest** thread pointer (`GUEST_TPIDR_OFFSET`) |

The rewriter also gates guest `MSR TPIDR_EL0` and `MRS TPIDR_EL0` so that every
guest read or write of the thread pointer is redirected to
`[TPIDR_EL0 + GUEST_TPIDR_OFFSET]`. The hardware register therefore *always*
holds the host anchor, even while guest code runs.

The runtime's obligation is exactly one thing: for every thread it starts,
reserve the slot at `[TPIDR_EL0 + 16]`.

### What this deletes relative to `shim9`

`shim9` assumed `TPIDR_EL0` was swapped between host and guest values, which
forced it to carry:

- a 256-entry open-addressed `guest_tpidr -> host_tls` hash table with tombstones,
  probe chains and an `entry[0]` fallback (`update_host_tls_entry`,
  `remove_host_tls_entry`, `update_entry0_fallback`);
- a power-of-two-aligned alternate signal stack carrying an `ALT_STACK_MAGIC`
  cookie and a host-TLS pointer, recovered in signal handlers by masking `SP`;
- a raw `sigaltstack(NULL, &oss)` syscall inside the signal handler to decide
  whether that recovery was even safe;
- an `x18`-based host-TLS-base calling convention for the callback.

None of it is needed. All of it is dropped.

## 2. TLS layout and the anchor

`TPIDR_EL0` is glibc's own thread pointer, so the runtime cannot simply claim
`[TPIDR_EL0 + 16]` — on AArch64 (TLS variant 1) that address is the start of the
main executable's static TLS block, whose contents depend on link order. Measured
on a stock Rust binary, a `.tbss` variable lands at `+48`; the same variable
placed in `.tdata` lands at exactly `+16`, because `.tdata` is linked ahead of
`.tbss`.

The platform therefore emits its control block via `global_asm!` into a `.tdata`
section, 16-byte aligned, so it occupies the head of the static TLS area:

| Offset from `TPIDR_EL0` | Symbol | Type |
| --- | --- | --- |
| +16 | `guest_tpidr` | `u64` — **rewriter ABI**, `GUEST_TPIDR_OFFSET` |
| +24 | `host_sp` | `u64` |
| +32 | `guest_context_top` | `u64` |
| +40 | `in_guest` | `u8` |
| +41 | `interrupt` | `u8` |
| +42 | `is_guest_thread` | `u8` (added during implementation) |
| +44 | `pending_host_signals` | `u32` |
| +48 | `wait_waker_addr` | `u64` |

> **Amended during implementation: `.tdata` placement is necessary but NOT
> sufficient.** The default linker script matches
> `*(.tdata .tdata.* .gnu.linkonce.td.*)` with no sorting, so `.tdata` input
> sections are laid out in input-object order. In the real runner link,
> `tracing_subscriber`'s `fmt_layer::BUF` and `layer_filters::FILTERING` — two
> 40-byte `.tdata` thread-locals — landed ahead of ours and pushed
> `guest_tpidr` to offset 96. `assert_tls_layout()` caught it at startup and
> reported the actual offset, which is exactly why it exists.
>
> The fix is `litebox_platform_linux_userland/litebox_tls.ld`, an
> `INSERT BEFORE .tbss` fragment respelling the `.tdata` rule with
> `*(.tdata.litebox_tls)` first, applied through each consuming binary's
> `build.rs`. This is **opt-in per binary**: Cargo gives a dependency no way to
> inject link arguments into its dependents, so any future binary that runs
> guest code must add the same link argument. `assert_tls_layout()` turns
> forgetting it into a startup panic rather than silent corruption.
>
> Rejected alternative: `INSERT BEFORE .tdata` with a separate output section
> also works, but strands the section in the read-only segment and inflates
> `PT_TLS` from 0xc8 to 0xc190 — 49 KB per thread.

A second field, `is_guest_thread`, was added at offset 42 (previously alignment
padding) during implementation. The x86-64 code it replaces tests `gsbase != 0`,
which is a *thread-lifetime* property; `in_guest` is *momentary* and is 0
whenever a guest thread sits in the host, including while blocked in an
interruptible wait. Using `in_guest` for the guest-thread probe would break the
`record_pending_signal` / `wait_waker_addr` wakeup path.

Offsets are used as literal `const` operands in the transition assembly rather
than `#:tprel_g1:` / `#:tprel_g0_nc:` relocation pairs. This is not an
optimization: `syscall_callback` is entered with only `x16` free and cannot
afford the second scratch register a relocation pair requires.

Because the offsets are hardcoded, `LinuxUserland::new` calls
`assert_tls_layout()`, which computes each symbol's true tprel offset via
`#:tprel_g1:` / `#:tprel_g0_nc:` and compares it against the constant. If link
order ever shifts, the process aborts with a clear message instead of silently
corrupting either host TLS or the guest thread pointer.

### Alternatives considered

- **Squat on `tcbhead_t.private` at `tp + 8`.** glibc does not use that word on
  AArch64, and it would need no linker cooperation at all. Rejected: we would not
  own the slot, so a future libc change corrupts memory silently, whereas the
  `.tdata` block fails loudly at startup.
- **Make `GUEST_TPIDR_OFFSET` configurable.** The rewriter is flexible here, but
  any constant still has to be pinned against the host's TLS layout, so this
  removes no work. 16 is kept.
- **Point `TPIDR_EL0` at a runtime-owned block.** Breaks glibc and `std` TLS on
  the host thread.

## 3. Transition assembly

`PtRegs` for AArch64 is 288 bytes, 16-byte aligned: `regs[0..=30]` at
`0x00..0xF0`, `sp` at `0xF8`, `pc` at `0x100`, `pstate` at `0x108`, `orig_x0` at
`0x110`, `syscallno` at `0x118`.

### `run_thread_arch(thread_ctx, ctx, reenter)`

Mirrors the x86-64 version. Saves `x19`–`x28`, `x29`, `x30`; stores `thread_ctx`
at `[sp]`; writes `host_sp` and `guest_context_top = ctx + 288` into the TLS
block; dispatches to `init_handler` or `reenter_handler`. It hosts the
`syscall_callback`, `exception_callback` and `interrupt_callback` labels and the
shared `.Ldone` epilogue.

Unlike x86-64 there is no `rdfsbase` / `wrgsbase` step, because there is no
second thread-pointer register to prime.

### `syscall_callback`

```
mrs  x16, tpidr_el0
strb wzr, [x16, #40]        // in_guest = 0; must be first, see case 1 below
ldr  x16, [x16, #32]        // guest_context_top
sub  x16, x16, #288         // -> PtRegs base
stp  x0, x1, [x16]          // ... x2..x15 -> #16..#112
ldp  x0, x1, [sp]           // x0 = guest x16, x1 = resume PC
str  x0, [x16, #128]        // regs[16]
str  x17, [x16, #136]       // x17, x18, x19..x30 -> #144..#240
add  x0, sp, #32
str  x0, [x16, #248]        // sp: undo the gate's frame -> true guest SP
str  x1, [x16, #256]        // pc
ldr  x0, [sp, #16]          // this site's outbound stub
mrs  x17, tpidr_el0
str  x0, [x17, #56]         // outbound_stub
str  x1, [x17, #64]         // outbound_pc
mrs  x0, nzcv
str  x0, [x16, #264]        // pstate
ldr  x0, [x16]
str  x0, [x16, #272]        // orig_x0
str  w8, [x16, #280]        // syscallno
mov  x0, #-38
str  x0, [x16]              // regs[0] = -ENOSYS, matching the kernel
mrs  x17, tpidr_el0
ldr  x17, [x17, #24]        // host_sp
mov  sp, x17
ldr  x0, [sp]               // thread_ctx
bl   {syscall_handler}
```

Guest `x30` is captured before `bl` clobbers it. There is no thread-pointer save
or restore anywhere in this path.

### `switch_to_guest(ctx)`

Bracketed by `switch_to_guest_start:` / `switch_to_guest_end:` so
`interrupt_signal_handler` can detect a partially restored context. Sets
`in_guest = 1`, tests `interrupt` and branches to `interrupt_callback` if set,
then chooses its exit path, and restores NZCV, SP, `x0`–`x15` and `x17`–`x30`.

**Guest `x16` (IP0) is fully restored, via the rewriter's per-site outbound
stub.** AArch64 offers no memory-indirect branch, so a branch target must occupy
a register that would otherwise hold guest state; restoring all 31 GPRs *and*
branching is impossible **from the runtime side**. The fix moves the final hop
into guest-adjacent code the rewriter emits, where the branch target is a
*static* address and therefore needs no register:

```
outbound_N:
    ldr x16, [sp, #0]     // restore guest x16
    add sp, sp, #32       // pop the gate frame
    b   site+4            // static direct branch: no scratch register needed
```

`syscall_callback` copied the stub's address and its resume PC into the TLS
control block (`outbound_stub` at 56, `outbound_pc` at 64) — deliberately, so
nothing depends on the gate frame below `sp` surviving the round trip through
the shim. `switch_to_guest` then does:

```
ldr x1, [x17, #56]    // outbound_stub
ldr x2, [x17, #64]    // outbound_pc
ldr x3, [x0, #256]    // ctx pc
ldr x4, [x0, #248]    // ctx sp (the true guest SP)
cmp x2, x3
b.ne 4f               // PC redirected -> fallback
cbz x1, 4f            // no stub recorded -> fallback
mov x16, x1
sub x4, x4, #32       // the stub pops the frame, so hand it SP one frame low
mov sp, x4
ldr x5, [x0, #128]    // ctx regs[16]
str x5, [sp, #0]      // stage it where the stub reloads it from
b   5f
4:  mov x16, x3       // fallback: direct branch, guest x16 clobbered
    mov sp, x4
5:  ...restore x0-x15, x17-x30, NZCV...
    br  x16
```

`PtRegs::sp` therefore keeps meaning the true guest SP throughout, which is what
the shim sees and may manipulate. `[sp, #0]` is re-materialized from
`PtRegs::regs[16]` rather than trusted from the gate, so a shim that
legitimately edits `regs[16]` is honoured.

**Scope and the fallback.** The stub only resumes at the original syscall site.
When the shim redirects `PtRegs::pc` — signal delivery, `execve` — the PC
comparison fails and the runtime falls back to `br x16`, clobbering guest `x16`.
That is correct there: the guest is not resuming the interrupted instruction
stream, and restoring an arbitrary PC *with* full register state is what an
`rt_sigreturn` frame is for.

The recorded pair is not invalidated after use. It is always self-consistent —
`outbound_stub` branches to `outbound_pc` by construction — so a stale record can
only be selected when `PtRegs::pc` equals the PC that stub branches to, i.e.
when taking it is equivalent to the fallback except that `x16` also survives.
Clearing it would instead open a window in which an interrupt between the clear
and the `br` silently downgrades to the clobbering path.

See `litebox_syscall_rewriter::arm64`, "Callback register contract: `X16` is
preserved across an `SVC`".

Alternatives considered and rejected for now: resuming via a synthesized
`rt_sigreturn` frame is fully general and atomically restores PSTATE, but costs
an extra syscall on every guest syscall return.

## 4. Signal handling

Because `TPIDR_EL0` always holds the host anchor, signal handlers may use
ordinary Rust TLS unconditionally. `with_signal_alt_stack` stays shared with
x86-64 and needs no AArch64 variant.

- `signal_handler_exit_guest` — read and clear `in_guest`, optionally set
  `interrupt`, return `guest_context_top - 1`. No `sigaltstack` probe, no SP
  masking, no magic cookie, and no guest-thread-pointer save, since the guest
  pointer already lives in its own slot.
- `copy_signal_context` — copies `uc_mcontext.regs[0..31]`, `sp`, `pc`, `pstate`.
- `set_signal_return` — sets `uc_mcontext.pc` and passes arguments in
  `regs[0..3]`.
- `exception_signal_handler` — AArch64 has no `REG_TRAPNO` / `REG_ERR` /
  `REG_CR2`. It synthesizes `ExceptionInfo { exception, fault_address, esr,
  kernel_mode: false }` from `siginfo.si_addr` and the signal number:
  SIGSEGV and SIGBUS map to `DATA_ABORT_LOWER_EL`, SIGILL to
  `INSTRUCTION_ABORT_LOWER_EL`, SIGTRAP to `BRK64`.
- `interrupt_signal_handler` — the four-case analysis ports unchanged; `ip` comes
  from `uc_mcontext.pc`.

## 5. Remaining platform plumbing

- `TASK_ADDR_MAX = 0x0000_FFFF_FFFF_F000` (48-bit VA).
- `Sysno::open` does not exist on AArch64. Four call sites move to
  `openat(AT_FDCWD, ...)`, which is correct on both architectures.
- `enable_seccomp_filter` becomes architecture-generic by selecting
  `seccompiler::TargetArch::aarch64`.
- `run_test_thread` loses its `rdfsbase` / `wrgsbase` mirroring entirely.
- `get_vdso_address` stays `None`.
- `futex` and `mmap` are present on AArch64, so those `Sysno` selections just
  gain the architecture to their `cfg`.

## 6. Upstream changes

`litebox::platform::arch::ArchSpecificRegister` is an empty enum on AArch64. Add
a `TpidrEl0` variant, implemented as a read or write of the `guest_tpidr` slot,
with the same user-address validation `is_valid_user_fs_base` applies on x86-64.
This is what the shim needs for `CLONE_SETTLS`, since AArch64 has no
`arch_prctl`.

`litebox_shim_linux` does not currently build for AArch64: roughly 51 errors,
concentrated in `syscalls/signal/mod.rs` (23), `syscalls/process.rs` (13),
`lib.rs` (9) and `syscalls/mm.rs` (4), plus single errors in `misc.rs` and
`file.rs`. These are predominantly `ExceptionInfo` and `PtRegs` field mismatches
and x86-only syscall constants. Signal delivery is made to compile and be
plausibly correct, but is not exercised by the hello-world target.

## 7. Verification

1. `assert_tls_layout()` passes as a unit test, pinning `guest_tpidr` to +16.
2. The crate builds and its existing unit tests (`test_raw_mutex`,
   `test_reserved_pages`, `test_seccomp_filter`) pass on AArch64.
3. A `tests/loader.rs`-style direct `run_thread` exercises the transition
   assembly without the full runner.
4. `hello.c` is rewritten through the AArch64 rewriter and runs end to end under
   `litebox_runner_linux_userland`. The harness in
   `litebox_runner_linux_userland/tests/run.rs` hardcodes `lib/x86_64-linux-gnu`
   and needs an AArch64 arm.

## 8. Out of scope

Threads, dynamic linking, real signal delivery to the guest, and the full
`tests/run.rs` matrix.
