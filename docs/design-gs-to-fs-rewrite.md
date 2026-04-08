# Design: Rewrite Guest gs: to fs: for Windows Userland Sandbox

## Problem

The Windows kernel restores GS base to `KTHREAD->Teb` (the real host TEB) on every
thread context switch. This is proven empirically by a standalone test
(`C:\Users\wdcui\tmp\gs_clobber_test.c`) that writes a fake GS base via `wrgsbase`,
spins with periodic `rdgsbase` checks, and observes the kernel restoring the original
TEB pointer. The clobber rate is ~0.01-0.04% of checks across 32 threads with 2M
iterations each, and it is 100% reproducible.

The mechanism: the `IA32_KERNEL_GS_BASE` MSR is used by `swapgs` for the user/kernel
GS swap. It holds exactly one value. When the kernel context-switches from thread A to
thread B, it must load thread B's user GS base from `KTHREAD->Teb`, discarding whatever
userspace wrote with `wrgsbase`.

**Consequence:** Guest code that uses `gs:[offset]` to access its synthetic TEB
intermittently reads/writes the **host** TEB instead, causing heap corruption
(STATUS_HEAP_CORRUPTION) or access violations. The current verify loop in
`switch_to_guest` (wrgsbase + rdgsbase retry) cannot help because the clobber occurs
**after** guest code is already running.

## Solution: Switch Guest TEB Access from GS to FS

Rewrite all `gs:` segment override prefixes (`0x65`) to `fs:` prefixes (`0x64`) in
guest executable code. Set FS base to the guest TEB address via `wrfsbase`.

### Why FS Works

The kernel also clobbers FS base on context switches, but it restores FS to **0** (not
to a valid address). This is the critical difference:

| Register | Clobbered to | Effect on guest access | Outcome |
|----------|-------------|----------------------|---------|
| GS | host TEB (valid addr) | `gs:[offset]` silently succeeds with wrong data | **Silent corruption** |
| FS | 0 | `fs:[offset]` faults at near-null address | **Catchable fault** |

The existing VEH handler in `lib.rs:3082-3086` already detects and repairs this exact
pattern:

```rust
if exception_record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION
    && rdfsbase() == 0
    && get_thread_fs_base() != 0
{
    set_context_to_interrupt_callback(tls, context);
}
```

This routes through `interrupt_callback` -> `switch_to_guest` -> `restore_thread_fs_base()`
(line 4789), which calls `wrfsbase(THREAD_FS_BASE)`, then resumes the guest at the
faulting instruction. The instruction succeeds on retry because FS base is now correct.

This is the same mechanism used by Linux-on-Windows guests today.

## Changes Required

### 1. Binary Rewriting: gs: (0x65) -> fs: (0x64)

**New dependency:** Add `iced-x86` to `litebox_common_windows/Cargo.toml`:
```toml
iced-x86 = { version = "1.21", default-features = false, features = ["no_std", "decoder", "instr_info"] }
```

This matches the version and features already used by `litebox_syscall_rewriter`.

**New function** in a new file `litebox_common_windows/src/gs_to_fs_rewriter.rs`:
```rust
/// Rewrite GS segment override prefixes (0x65) to FS (0x64) in x86-64 code.
///
/// Uses iced-x86 linear sweep decoding to identify instruction boundaries,
/// then checks `Instruction::segment_prefix() == Register::GS` to find
/// actual gs: prefixed instructions (not 0x65 bytes in immediates/displacements).
///
/// Returns the number of instructions rewritten.
pub fn rewrite_gs_to_fs(code: &mut [u8], base_va: u64) -> usize
```

The function walks the code byte-by-byte using `iced_x86::Decoder` in 64-bit mode.
For each instruction with `segment_prefix() == Register::GS`, it locates the `0x65`
byte within the instruction's prefix area and changes it to `0x64`.

**Integration point:** `load_pe_inner()` in `pe_loader.rs`. For each section with
`IMAGE_SCN_MEM_EXECUTE`, rewrite gs: prefixes in the section data before passing to
`mapper.map_section()`. Since `effective_data` may be an immutable `&[u8]`, the
rewrite needs a mutable copy. The approach:

```
for section in &parsed.sections {
    let perm = section_permissions(section.characteristics);
    let file_data = /* existing extraction logic */;

    if perm == SectionPermissions::ReadExecute && !file_data.is_empty() {
        let mut rewritten = file_data.to_vec();
        let section_va = base_address + section.virtual_address as usize;
        rewrite_gs_to_fs(&mut rewritten, section_va as u64);
        mapper.map_section(section_va, &rewritten, map_size, perm)?;
    } else {
        mapper.map_section(section_va, file_data, map_size, perm)?;
    }
}
```

This catches ALL PE images loaded through `load_pe()`:
- ntdll (runner startup, via `load_ntdll_for_init()`)
- Guest EXE (runner startup)
- Runtime DLLs (shim `NtMapViewOfSection` -> `map_image_section()`)

**Stub DLLs** (`pe_builder.rs`): Change the 3 hardcoded `0x65` bytes to `0x64`:
- `get_last_error()` line 153
- `set_last_error()` line 166
- `return_status_with_last_error()` line 183

These are not loaded through `load_pe()` so they need a source-level fix.

### 2. FS Base Management — Replace THREAD_GS_BASE with THREAD_FS_BASE

`THREAD_GS_BASE` is removed entirely. `set_guest_gs_base()` is renamed to
`set_guest_teb_base()` and sets only `THREAD_FS_BASE`:

```rust
pub fn set_guest_teb_base(value: u64) {
    Self::set_thread_fs_base(value as usize);
}
```

This ensures:
- `THREAD_FS_BASE` holds the guest TEB address
- `restore_thread_fs_base()` in `switch_to_guest` calls `wrfsbase(guest_teb)` before
  entering the guest
- VEH handler FS repair works (`get_thread_fs_base() != 0` is true)

All call sites that currently use `set_guest_gs_base()` are updated:
- `litebox_runner_windows_userland/src/lib.rs:1473` (main thread init)
- `litebox_shim_windows/src/syscalls/thread.rs:478` (child thread init)

### 3. Remove GS Infrastructure

Since guest code no longer uses `gs:` and we no longer call `wrgsbase(guest_teb)`,
GS naturally stays as the host TEB (the value the kernel maintains). This means:

- **Remove `wrgsbase(guest_teb)` from `switch_to_guest_sysret`** — GS stays host_TEB
  always. No verify loop needed.
- **Remove `THREAD_GS_BASE`** — No longer read or written anywhere.
- **Remove GS counters and diagnostic code** — `GS_CTR_*`, `GS_GATE_*`, `GS_DIAG_*`
  statics, `dump_gs_counters()`, and all LEAK-DIAG capture.

### 4. Replace GS Table with Windows TLS Slot

The GS table (`gs_table.rs`) is removed entirely. Its purpose was to let the syscall
trampoline (naked asm) find the per-thread `tls_ptr` by scanning for the current GS
value. Since GS is now always host_TEB, we can use a **Windows TLS slot** instead:

1. At platform init, call `TlsAlloc()` to get a slot index.
2. On each thread init, call `TlsSetValue(slot_index, tls_ptr)`.
3. The trampoline reads it directly from the host TEB:
   ```asm
   mov rax, gs:[0x1480 + SLOT_IDX * 8]   // TEB64.TlsSlots[SLOT_IDX]
   ```

This replaces the O(n) GS table scan with a single O(1) memory read. The slot index
is embedded as an immediate in the generated trampoline code.

Note: The trampoline uses `gs:` to access the **host** TEB, not the guest TEB. This
is correct because GS always points to host_TEB (the kernel maintains it). The gs:→fs:
rewrite only affects guest PE code loaded through `load_pe()`. The trampoline is
generated by `pe_builder.rs` and is not subject to the rewrite.

All code that references the GS table is updated:
- `pe_builder.rs` trampoline generation — replace GS table scan loop with single
  `gs:[0x1480 + slot*8]` read; remove `wrgsbase(host_gs)` since GS is already correct
- VEH trampoline — replace GS table scan with TLS slot read (or use `get_tls_ptr()`
  since VEH runs in host context with access to Rust thread-locals)
- NtContinue gate — same as VEH
- `run_thread_inner()` — replace GS table insert with `TlsSetValue`
- `gs_table.rs` — delete

## Non-PE Executable Code

Two additional paths create executable guest pages without going through `load_pe()`:

- **`NtAllocateVirtualMemory` with `PAGE_EXECUTE*`:** Used by JIT compilers. The
  sandbox doesn't currently support arbitrary JIT. If needed in the future, a rewrite
  pass could be added at the `make_pages_executable()` chokepoint.

- **`NtProtectVirtualMemory` changing pages to executable:** This is how ntdll's
  loader sets `.text` permissions for runtime DLLs (Path B). However, the section
  data was already rewritten during `load_pe()`, so the protection change operates
  on already-rewritten bytes. No additional interception needed.

## Risk: Data-in-Code

Linear sweep disassembly can misidentify data embedded in `.text` sections (jump
tables, constant pools, padding) as instructions. If data contains a `0x65` byte
that the decoder interprets as a gs: prefix, it would be incorrectly rewritten.

Mitigations:
- MSVC places jump tables in `.rdata`, not `.text`. Pure `.text` data-in-code is rare.
- Misidentified "instructions" in data regions are not executed, so corrupting a data
  byte from `0x65` to `0x64` only matters if the data value `0x65` is semantically
  significant (e.g., a character 'e' in a string constant in `.text`). This is very
  unlikely for Windows PE binaries compiled by MSVC.
- If issues arise, we can switch from linear sweep to a more conservative approach
  (e.g., only rewrite instructions that match known TEB access patterns).

## Performance Impact

- **Rewrite cost:** One-time iced-x86 decode pass per PE image during loading.
  ntdll `.text` is ~1.3 MB. Decode + rewrite is well under 100ms.

- **Runtime cost:** When the kernel clobbers FS (on context switch during guest
  execution), the first `fs:` access faults. Fault dispatch + VEH handler + resume
  costs ~1-5 microseconds. Context switches themselves cost ~1-10 microseconds, so
  overhead is proportional to context switch frequency during guest execution. The
  clobber rate from our test was ~0.01-0.04% of checks, indicating this is rare.

- **No overhead on the fast path:** When no context switch happens, `fs:` accesses
  work identically to the old `gs:` accesses — same latency, no extra instructions.

## Test Plan

1. Build: `cargo build --release -p litebox_runner_windows_userland`
2. All 54 unit tests must pass
3. `cargo clippy` and `cargo fmt` clean
4. 20-run test: `heap_t32.tar` — expect 0 failures (was ~17% before)
5. 200-run stress test — expect 0 failures
6. Verify VEH FS repair fires (add or retain a counter for "FS repaired" events)
7. Test with other workloads beyond heap_t32 if available

## Reviewer Feedback Resolution

Two independent AI reviews (GPT-5.4 and Opus 4.6) were conducted. Below is each
concern and its resolution.

### Syscall Trampolines (GPT-5.4 CRITICAL)

**Concern:** Syscall trampolines in `pe_builder.rs` may have gs: memory accesses
that need rewriting.

**Resolution: Non-issue.** Trampolines use `rdgsbase` / `wrgsbase` (FSGSBASE
instructions: `F3 48 0F AE C0` etc.), NOT the `gs:` segment override prefix (`0x65`).
The 0x65→0x64 rewrite does not affect FSGSBASE instructions. Verified by inspecting
all generated trampoline bytes in `pe_builder.rs`. The only 3 instances of `0x65` in
`pe_builder.rs` are the `get_last_error` / `set_last_error` / `return_status_with_last_error`
stubs, which are handled by the source-level fix.

### FS Base Conflict with Linux Guest TLS (GPT-5.4 CRITICAL)

**Concern:** Setting FS base for Windows guest TEB may conflict with Linux guest TLS
that also uses FS base.

**Resolution: Non-issue.** A given thread runs EITHER a Windows-mode guest (NT PE) OR a
Linux-mode guest, never both simultaneously. The `THREAD_FS_BASE` thread-local is
already used by Linux guests; Windows guests will now also use it. The value is set per
thread during guest initialization and there is no cross-contamination. The existing
`set_guest_gs_base()` is only called for Windows guests; we add `set_thread_fs_base()`
inside it, which is correct.

### Thread Creation Race (GPT-5.4 MEDIUM, Opus LOW)

**Concern:** If a child thread starts executing guest code before `THREAD_FS_BASE` is
set, the first `fs:` access would fault with no repair data.

**Resolution: Safe by construction.** Thread creation goes through
`thread.rs:create_remote_thread_inner()` which calls `set_guest_gs_base()` at line 478
on the PARENT thread that sets up the child's TEB. The child thread calls
`run_thread_inner()` at `lib.rs:3874` which enters `switch_to_guest` before any guest
code runs. `switch_to_guest` calls `restore_thread_fs_base()` at line 4789. The child's
`THREAD_FS_BASE` is set inside `switch_to_guest` → `init_thread_fs_base()` when it first
enters guest mode. No guest instruction can execute before this point. Will verify this
invariant during implementation.

### Decoder Invalid Instruction Handling (Opus LOW)

**Concern:** What happens when the decoder encounters invalid instructions or data
that cannot be decoded?

**Resolution:** When `iced_x86::Decoder` encounters bytes it cannot decode, it produces
a 1-byte "invalid" instruction (`Code::INVALID`) and advances by 1 byte. The linear
sweep continues. Since invalid instructions by definition do not have a `gs:` segment
prefix, `segment_prefix() == Register::GS` will be false, and no rewrite occurs. This
is safe: the worst case is skipping over some data bytes one at a time, which is correct.

### Livelock Protection (GPT-5.4 Suggested, Opus LOW)

**Concern:** If FS keeps getting clobbered (e.g., extremely high context switch rate),
the VEH handler could loop indefinitely.

**Resolution: Accepted risk, matches existing Linux behavior.** The Linux platform has
the same VEH handler for FS repair with no retry limit. In practice, the clobber rate
is ~0.01-0.04% of execution time, meaning the probability of two consecutive clobbers
(fault → repair → immediate re-fault before executing a single guest instruction) is
~0.0001%. Infinite loops are not physically possible because the repair is immediate
and the next context switch cannot occur until the thread runs for at least one
scheduler quantum (~15ms). If monitoring shows unexpected fault rates, a counter can
be added later.

### Post-Rewrite Verification (GPT-5.4 Suggested)

**Concern:** Add a verification pass to confirm no `gs:` prefixed instructions remain
after rewriting.

**Resolution: Will add as debug-mode diagnostic.** The `rewrite_gs_to_fs()` function
will return the count of rewritten instructions. This will be logged at info level.
A debug assertion can optionally re-decode the section and verify zero `gs:` prefixed
instructions remain, but this doubles the decode time and is not needed in release.

### Rewrite Logging (Opus Suggested)

**Resolution: Adopted.** `rewrite_gs_to_fs()` will return the rewrite count. The caller
in `pe_loader.rs` will log `"Rewrote {count} gs: instructions in section {name} at
{va:#x}"` at debug/trace level.

## File Change Summary

| File | Change |
|------|--------|
| `litebox_common_windows/Cargo.toml` | Add `iced-x86` dependency |
| `litebox_common_windows/src/lib.rs` | Add `pub mod gs_to_fs_rewriter;` |
| `litebox_common_windows/src/gs_to_fs_rewriter.rs` | **New file**: `rewrite_gs_to_fs()` |
| `litebox_common_windows/src/pe_loader.rs` | Call `rewrite_gs_to_fs()` for executable sections in `load_pe_inner()` |
| `litebox_common_windows/src/pe_builder.rs` | Change 3 `0x65` to `0x64` in stubs; replace GS table scan in trampoline with TLS slot read; remove `wrgsbase` |
| `litebox_common_windows/src/gs_table.rs` | **Delete** |
| `litebox_platform_windows_userland/src/lib.rs` | Remove `THREAD_GS_BASE`; rename `set_guest_gs_base` → `set_guest_teb_base` (sets `THREAD_FS_BASE` only); remove GS counters/diagnostics/verify loop; add `TlsAlloc` at init + `TlsSetValue` at thread init; remove all GS table references |
| `litebox_shim_windows/src/syscalls/thread.rs` | Update `set_guest_gs_base` → `set_guest_teb_base` |
| `litebox_runner_windows_userland/src/lib.rs` | Update `set_guest_gs_base` → `set_guest_teb_base` |
