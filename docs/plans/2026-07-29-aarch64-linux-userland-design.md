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
| `[TPIDR_EL0 + guest_tpidr_offset]` | the **guest** thread pointer (offset patched in at load time) |

The rewriter also gates guest `MSR TPIDR_EL0` and `MRS TPIDR_EL0` so that every
guest read or write of the thread pointer is redirected to that slot. The
hardware register therefore *always* holds the host anchor, even while guest
code runs.

The runtime's obligation is exactly one thing: for every thread it starts,
reserve a guest thread-pointer slot at a fixed offset from `TPIDR_EL0` — and
report that offset to the loader, which patches it into each rewritten binary
(see section 2).

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

The platform emits its per-thread control block via `global_asm!` into `.tbss`,
8-byte aligned. Field offsets are **relative to the block**, not to
`TPIDR_EL0`:

| Offset in block | Symbol | Type |
| --- | --- | --- |
| +0 | `litebox_tls_block` | the anchor symbol (aliases `guest_tpidr`) |
| +0 | `guest_tpidr` | `u64` — the slot rewritten guests read/write |
| +8 | `host_sp` | `u64` |
| +16 | `guest_context_top` | `u64` |
| +24 | `in_guest` | `u8` |
| +25 | `interrupt` | `u8` |
| +26 | `is_guest_thread` | `u8` (added during implementation) |
| +28 | `pending_host_signals` | `u32` |
| +32 | `wait_waker_addr` | `u64` |
| +40 | `outbound_stub` | `u64` |
| +48 | `outbound_pc` | `u64` |

`is_guest_thread` occupies what was alignment padding. The x86-64 code it
replaces tests `gsbase != 0`, which is a *thread-lifetime* property; `in_guest`
is *momentary* and is 0 whenever a guest thread sits in the host, including
while blocked in an interruptible wait. Using `in_guest` for the guest-thread
probe would break the `record_pending_signal` / `wait_waker_addr` wakeup path.

**Where the block lands relative to `TPIDR_EL0` is deliberately not fixed.** It
is wherever the linker puts our thread-locals inside the static TLS area, which
depends on every other TLS object in the link and is therefore different for
every binary that embeds LiteBox.

### Addressing the block: one anchor sequence, one register

The transition assembly cannot spend a second scratch register on TLS
addressing: `syscall_callback` is entered with only `x16` free. That is what
originally motivated hardcoding absolute `TPIDR_EL0` offsets — the
`#:tprel_g1:` / `#:tprel_g0_nc:` `MOVZ`/`MOVK` pair builds the offset in a
register of its own before it can be added to the thread pointer, so it needs
two.

The AArch64 **local-exec** relocation pair `#:tprel_hi12:` / `#:tprel_lo12_nc:`
does not:

```
mrs x16, tpidr_el0
add x16, x16, #:tprel_hi12:litebox_tls_block, lsl #12
add x16, x16, #:tprel_lo12_nc:litebox_tls_block
```

Three instructions, one register, and the linker fills in the offset. This is
the `tls_anchor!` macro. Every fragment materializes the block base once and
then addresses each field with a literal displacement from `tls_offset`.

`assert_tls_layout()` still runs at `LinuxUserland::new`, but it now checks a
different thing: that the block's *internal* layout matches `tls_offset`. That
is a property of this crate alone and constrains nothing about the rest of the
link. It also checks that the block's thread-pointer offset is still one a
rewriter gate can encode (see below).

### The guest thread-pointer slot: patched at load time, not baked in

The rewriter virtualizes every guest `MSR`/`MRS TPIDR_EL0` into a load or store
of `guest_tpidr` via a scaled `LDR`/`STR` off the host anchor. That immediate is
baked into the rewritten *guest* binary — but its value is a property of the
*host* runtime's link, and one rewritten binary has to run under any host build.
The two cannot both be constants.

So the rewriter emits the gates with a placeholder immediate
(`GUEST_TPIDR_OFFSET_PLACEHOLDER`, deliberately the largest the field can hold),
and the loader calls `aarch64_patch_guest_tpidr_offset` with the offset the
runtime measured for itself, after reading the trampoline blob and before
mapping it executable. This happens for every rewritten object — the executable,
the interpreter and every shared library alike — each of which carries its own
trampoline. All three go through one place: the shim's `mmap` pre-patched path
(`do_mmap_file` → `maybe_patch_exec_segment`). The executable and the
interpreter are not special, because the shim's `MapMemory` implements
`map_file` as `sys_mmap`, so loading them lands in `do_mmap_file` exactly like a
library the guest's own dynamic linker maps later.

The patch sites need no side table. Everything in a trampoline from the shared
SVC handler onwards is an instruction word the rewriter emitted (the header's
callback slot is the blob's only data), and the placeholder saturates the scaled
immediate, so a linear scan finds exactly the gates' slot accesses. Each hit is
additionally checked to have one of the two register shapes a gate emits, so a
blob the rewriter did not produce is rejected rather than silently mangled.

Two properties are asserted rather than assumed. The measured offset must be
8-aligned (the immediate's scale) and at most `0xFFF * 8 = 32760`. Both hold by
construction — the block is `.align 3`, and 32KB of static TLS ahead of us is
not a thing — but an exotic link now fails legibly at startup instead of
faulting inside a guest gate. The placeholder is chosen so that an *unpatched*
gate dereferences 32KB past the thread pointer and faults, rather than silently
reading live host TLS.

### Removed: the `litebox_tls.ld` linker script

The original design pinned `guest_tpidr` at exactly `TPIDR_EL0 + 16` — the head
of the static TLS area on TLS variant 1 — by emitting the block into a
`.tdata.litebox_tls` section and forcing it to the front with an
`INSERT BEFORE .tbss` linker fragment, applied through each consuming binary's
`build.rs` (`-Wl,-T,litebox_tls.ld`). Without it, `tracing_subscriber`'s two
40-byte `.tdata` thread-locals landed ahead of ours and pushed `guest_tpidr` to
offset 96, which `assert_tls_layout()` caught at startup.

Both the script and the `build.rs` are **deleted**. Three reasons:

1. **It is not inheritable.** Cargo gives a library no way to inject link
   arguments into its dependents, so *every* binary that embeds LiteBox had to
   add the link argument itself. That is an unacceptable imposition for an
   embeddable sandboxing library, and it can never be made automatic.
2. **It is not portable.** `INSERT BEFORE` is a GNU-ld/lld directive. The
   Windows and macOS hosts this design must eventually support have no
   equivalent.
3. **It is unnecessary.** Both things that needed the fixed offset now get it
   dynamically: the host's own assembly through the local-exec anchor, and the
   guest's gates through load-time patching.

Measured after the change, the runner's block lands at `TPIDR_EL0 + 264` — a
number nothing in the system knows ahead of time, and that is the point.

### Alternatives considered

- **Squat on `tcbhead_t.private` at `tp + 8`.** glibc does not use that word on
  AArch64, and it would need no linker cooperation at all. Rejected: we would not
  own the slot, so a future libc change corrupts memory silently, whereas our own
  block fails loudly at startup.
- **Keep a fixed `GUEST_TPIDR_OFFSET`, configurable per build.** Any constant
  still has to be pinned against the host's TLS layout, which is exactly the
  imposition being removed. Rejected.
- **Point `TPIDR_EL0` at a runtime-owned block.** Breaks glibc and `std` TLS on
  the host thread.
- **Patch the host's own transition assembly at startup** instead of using
  relocations. Requires making our own `.text` writable at runtime, for no
  benefit over a relocation the linker already knows how to resolve.

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
mrs  x16, tpidr_el0         // ) tls_anchor!("x16"): x16 -> block base,
add  x16, x16, #:tprel_hi12:litebox_tls_block, lsl #12   // ) three instructions,
add  x16, x16, #:tprel_lo12_nc:litebox_tls_block         // ) one register
strb wzr, [x16, #24]        // in_guest = 0; must be first, see case 1 below
ldr  x16, [x16, #16]        // guest_context_top
sub  x16, x16, #288         // -> PtRegs base
stp  x0, x1, [x16]          // ... x2..x15 -> #16..#112
ldp  x0, x1, [sp]           // x0 = guest x16, x1 = resume PC
str  x0, [x16, #128]        // regs[16]
str  x17, [x16, #136]       // x17, x18, x19..x30 -> #144..#240
add  x0, sp, #32
str  x0, [x16, #248]        // sp: undo the gate's frame -> true guest SP
str  x1, [x16, #256]        // pc
ldr  x0, [sp, #16]          // this site's outbound stub
mrs  x17, tpidr_el0         // ) tls_anchor!("x17")
add  x17, x17, #:tprel_hi12:litebox_tls_block, lsl #12
add  x17, x17, #:tprel_lo12_nc:litebox_tls_block
str  x0, [x17, #40]         // outbound_stub
str  x1, [x17, #48]         // outbound_pc
mrs  x0, nzcv
str  x0, [x16, #264]        // pstate
ldr  x0, [x16]
str  x0, [x16, #272]        // orig_x0
str  w8, [x16, #280]        // syscallno
mov  x0, #-38
str  x0, [x16]              // regs[0] = -ENOSYS, matching the kernel
mrs  x17, tpidr_el0         // ) tls_anchor!("x17")
add  x17, x17, #:tprel_hi12:litebox_tls_block, lsl #12
add  x17, x17, #:tprel_lo12_nc:litebox_tls_block
ldr  x17, [x17, #8]         // host_sp
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
control block (`outbound_stub` at +40, `outbound_pc` at +48 within the block) —
deliberately, so
nothing depends on the gate frame below `sp` surviving the round trip through
the shim. `switch_to_guest` then does:

```
ldr x1, [x17, #40]    // outbound_stub (x17 anchored on the block)
ldr x2, [x17, #48]    // outbound_pc
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

## 8. Known issues

### The appended trampoline can be placed inside another object

Accepted as a known issue and deliberately not fixed here. It is pre-existing
and architecture-independent, not something this port introduces.

The trampoline the rewriter appends lives *outside* every `PT_LOAD`, so the
dynamic loader never learns the range exists and never reserves it. Its address
is chosen at runtime by `litebox_syscall_rewriter::trampoline_addr_for`, which
can only establish that the address is clear of *its own* object and of the
loader's scaffolding for that object — never that it is free overall. glibc
packs objects adjacently, so no free gap is guaranteed, and by the time the shim
maps here the next object may already own the range.

The failure mode is silent corruption of an adjacent object, not a clean error.
The shim maps the trampoline with `MAP_FIXED`; over a range *fully* covered by an
existing mapping that straddles no mapping boundary, so it succeeds and simply
replaces the victim's pages. Nothing faults until the overwritten bytes are used,
arbitrarily far from the cause.

Reproduction, with perl: `libperl` maps `[0xffffff1d0000, 0xffffff589000)`, and
`libc`'s trampoline is placed at `[0xffffff1e0000, 0xffffff1ea000)` — 64 KiB
*inside* libperl. Mapping it overwrites ~40 KiB of libperl's text/rodata,
corrupting a `DT_NEEDED` string. The baseline placement rule overlapped libperl
too, by 0x8000, so this is not a regression from the aarch64 placement change.

Adjusting the arithmetic in `trampoline_addr_for` cannot fix this, only change
which programs collide. The likely fix is to stop guessing at a free gap at
runtime and make the range genuinely reserved: have the rewriter emit a `PT_LOAD`
covering the trampoline, so the dynamic loader maps it as part of the object's
span and places everything else clear of it — the guarantee every ordinary
segment already has. The `TODO` lives on `trampoline_addr_for`, where the
address is chosen.

## 9. Out of scope

Threads, dynamic linking, real signal delivery to the guest, and the full
`tests/run.rs` matrix.
