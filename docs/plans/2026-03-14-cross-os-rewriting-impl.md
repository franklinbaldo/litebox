# Cross-OS Rewriting Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable the syscall rewriter to produce macOS-targeted (or Windows-targeted) ARM64 binaries when running on any host OS/arch, via a `--target-os` CLI parameter.

**Architecture:** Replace all 83 `#[cfg(target_os = ...)]` compile-time gates in `arm64.rs` with runtime dispatch through a `TargetOs` enum. Remove the `#[cfg(target_arch = "aarch64")]` gate on the arm64 module so it compiles on any host. Thread `target_os: TargetOs` through the rewriter pipeline.

**Tech Stack:** Rust, clap (CLI), existing ARM64 instruction encoders

**Design doc:** `docs/plans/2026-03-14-cross-os-rewriting.md`

---

### Task 1: Add `TargetOs` enum and convert constants to methods

**Files:**
- Modify: `litebox_syscall_rewriter/src/arm64.rs:1-232`

**Step 1: Add the TargetOs enum**

Insert after line 9 (after the `use` statement), before the constants:

```rust
/// Target operating system for the rewritten binary.
///
/// On x86, all targets produce identical output.
/// On ARM64, each OS has distinct rewriting behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetOs {
    Linux,
    MacOs,
    Windows,
}

impl TargetOs {
    pub const fn is_macos(self) -> bool {
        matches!(self, Self::MacOs)
    }
}
```

**Step 2: Replace paired constants with TargetOs methods**

Add these methods to the `impl TargetOs` block. Remove the 22 paired `#[cfg]` constant declarations (lines 73-152) and the macOS-only constants (lines 155-179) and the GATES_START_OFFSET constants (lines 225-231):

```rust
impl TargetOs {
    // ... is_macos above ...

    // Shared SVC handler
    pub const fn shared_svc_handler_insn_count(self) -> usize {
        match self {
            Self::Linux | Self::Windows => 18,
            Self::MacOs => 18,
        }
    }
    pub const fn shared_svc_handler_size(self) -> usize {
        self.shared_svc_handler_insn_count() * 4
    }

    // SVC gate
    pub const fn svc_gate_insn_count(self) -> usize {
        match self {
            Self::Linux | Self::Windows => 6,
            Self::MacOs => 7,
        }
    }
    pub const fn svc_gate_size(self) -> usize {
        self.svc_gate_insn_count() * 4
    }

    // Shared MSR handler
    pub const fn shared_msr_handler_insn_count(self) -> usize {
        match self {
            Self::Linux | Self::Windows => 19,
            Self::MacOs => 17,
        }
    }
    pub const fn shared_msr_handler_size(self) -> usize {
        self.shared_msr_handler_insn_count() * 4
    }

    // MSR gate
    pub const fn msr_gate_insn_count(self) -> usize {
        match self {
            Self::Linux | Self::Windows => 9,
            Self::MacOs => 13,
        }
    }
    pub const fn msr_gate_size(self) -> usize {
        self.msr_gate_insn_count() * 4
    }
    pub const fn msr_gate_special_size(self) -> usize {
        (self.msr_gate_insn_count() + 1) * 4
    }

    // MRS gate
    pub const fn mrs_gate_insn_count(self) -> usize {
        match self {
            Self::Linux | Self::Windows => 5,
            Self::MacOs => 13,
        }
    }
    pub const fn mrs_gate_size(self) -> usize {
        self.mrs_gate_insn_count() * 4
    }

    // macOS-only shared handlers (values only meaningful when self == MacOs)
    pub const fn shared_mrs_handler_insn_count(self) -> usize { 16 }
    pub const fn shared_mrs_handler_size(self) -> usize {
        self.shared_mrs_handler_insn_count() * 4
    }
    pub const fn shared_x18_load_handler_insn_count(self) -> usize { 16 }
    pub const fn shared_x18_load_handler_size(self) -> usize {
        self.shared_x18_load_handler_insn_count() * 4
    }
    pub const fn shared_x18_save_handler_insn_count(self) -> usize { 16 }
    pub const fn shared_x18_save_handler_size(self) -> usize {
        self.shared_x18_save_handler_insn_count() * 4
    }

    // x18 gate constants (only meaningful when self == MacOs)
    pub const fn x18_gate_read_insn_count(self) -> usize { 14 }
    pub const fn x18_gate_write_insn_count(self) -> usize { 14 }
    pub const fn x18_gate_readwrite_insn_count(self) -> usize { 16 }

    // Layout offsets
    pub const fn sigreturn_gate_offset(self) -> usize { 24 }

    pub const fn shared_svc_handler_offset(self) -> usize {
        self.sigreturn_gate_offset() + self.svc_gate_size()
    }

    pub const fn shared_msr_handler_offset(self) -> usize {
        self.shared_svc_handler_offset() + self.shared_svc_handler_size()
    }

    pub const fn shared_mrs_handler_offset(self) -> usize {
        self.shared_msr_handler_offset() + self.shared_msr_handler_size()
    }

    pub const fn shared_x18_load_handler_offset(self) -> usize {
        self.shared_mrs_handler_offset() + self.shared_mrs_handler_size()
    }

    pub const fn shared_x18_save_handler_offset(self) -> usize {
        self.shared_x18_load_handler_offset() + self.shared_x18_load_handler_size()
    }

    pub const fn gates_start_offset(self) -> usize {
        match self {
            Self::Linux | Self::Windows => {
                self.shared_msr_handler_offset() + self.shared_msr_handler_size()
            }
            Self::MacOs => {
                self.shared_x18_save_handler_offset() + self.shared_x18_save_handler_size()
            }
        }
    }

    pub fn msr_gate_size_for_rt(self, rt: u8) -> usize {
        match rt {
            16 | 17 | 30 => self.msr_gate_special_size(),
            _ => self.msr_gate_size(),
        }
    }
}
```

**Step 3: Remove old constant declarations**

Delete the following line ranges (all `#[cfg]`-gated constant pairs):
- Lines 73-82 (SHARED_SVC_HANDLER_INSN_COUNT/SIZE, linux + macos)
- Lines 84-94 (SVC_GATE_INSN_COUNT/SIZE, linux + macos)
- Lines 96-106 (SHARED_MSR_HANDLER_INSN_COUNT/SIZE, linux + macos)
- Lines 127-140 (MSR_GATE_INSN_COUNT/SIZE/SPECIAL_SIZE, linux + macos)
- Lines 142-152 (MRS_GATE_INSN_COUNT/SIZE, linux + macos)
- Lines 155-170 (SHARED_MRS_HANDLER_*, SHARED_X18_LOAD_HANDLER_*, SHARED_X18_SAVE_HANDLER_*, macos|test)
- Lines 173-179 (X18_GATE_*_INSN_COUNT, macos|test)
- Lines 199-231 (offset constants: SHARED_SVC_HANDLER_OFFSET through GATES_START_OFFSET)

Keep:
- Lines 182-183 (NOP) — remove the `#[cfg_attr(not(target_os = "macos"), allow(dead_code))]`, keep just `const NOP: u32 = 0xD503201F;`
- Lines 185-197 (HEADER_CALLBACK_OFFSET, HEADER_TLS_TABLE_OFFSET, HEADER_SIGRETURN_OFFSET, SIGRETURN_GATE_OFFSET) — these are platform-independent

**Step 4: Run `cargo check` on the rewriter crate**

Run: `cargo check -p litebox_syscall_rewriter 2>&1 | head -60`
Expected: Many errors about missing constants (GATES_START_OFFSET, SVC_GATE_SIZE, etc.) — this is expected and will be fixed in subsequent tasks.

**Step 5: Commit**

```
feat(rewriter): add TargetOs enum and convert constants to methods
```

---

### Task 2: Remove cfg gates from PatchKind, helper functions, and encoder functions

**Files:**
- Modify: `litebox_syscall_rewriter/src/arm64.rs`

**Step 1: Remove cfg from PatchKind::X18Use**

At line 782, remove the `#[cfg(any(target_os = "macos", test))]` attribute from the `X18Use` variant. The variant becomes unconditionally compiled.

**Step 2: Remove cfg from encoder functions**

Remove `#[cfg]` attributes from:
- `encode_mrs_tpidrro_el0` (line 456, `#[cfg(target_os = "macos")]`)
- `encode_mrs_nzcv` (line 468, `#[cfg(any(target_os = "macos", test))]`)
- `encode_msr_nzcv` (line 476, `#[cfg(any(target_os = "macos", test))]`)
- `encode_brk` (line 486, `#[cfg(target_os = "macos")]`)

**Step 3: Remove cfg from x18 helper functions**

Remove `#[cfg(any(target_os = "macos", test))]` from:
- `references_x18` (line 813)
- `is_store_instruction` (line 859)
- `rewrite_x18` (line 901)
- `adjust_sp_relative_offset` (line 971)
- `needs_sp_fixup` (line 1138)
- `x18_gate_size` (line 1196)

**Step 4: Remove cfg from macOS-only emit functions**

Remove `#[cfg(target_os = "macos")]` from:
- `emit_shared_mrs_handler` (line 2567)
- `emit_shared_mrs_handler_macos` (line 2606)
- `emit_shared_x18_load_handler` (line 2777)
- `emit_shared_x18_save_handler` (line 2946)

Remove `#[cfg(any(target_os = "macos", test))]` from:
- `emit_x18_gate` (line 3153)

**Step 5: Commit**

```
refactor(rewriter): remove cfg gates from helpers, encoders, and PatchKind
```

---

### Task 3: Remove cfg from emit variant functions and convert dispatchers

**Files:**
- Modify: `litebox_syscall_rewriter/src/arm64.rs`

**Step 1: Remove cfg from Linux variant functions**

Remove `#[cfg(target_os = "linux")]` from:
- `emit_shared_svc_handler_linux` (line 1610)
- `emit_svc_gate_linux` (line 2001)
- `emit_shared_msr_handler_linux` (line 2207)
- `emit_msr_gate_linux` (line 3485)
- `emit_mrs_gate_linux` (line 3862)

**Step 2: Remove cfg from macOS variant functions**

Remove `#[cfg(target_os = "macos")]` from:
- `emit_shared_svc_handler_macos` (line 1817)
- `emit_svc_gate_macos` (line 2091)
- `emit_shared_msr_handler_macos` (line 2414)
- `emit_msr_gate_macos` (line 3657)
- `emit_mrs_gate_macos` (line 4022)

**Step 3: Convert 5 dispatcher functions to runtime dispatch**

Each dispatcher gets a `target_os: TargetOs` parameter. Replace `#[cfg]` blocks with `match`.

`emit_shared_svc_handler` (line 1597):
```rust
fn emit_shared_svc_handler(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
    target_os: TargetOs,
) -> Result<()> {
    match target_os {
        TargetOs::Linux | TargetOs::Windows => {
            emit_shared_svc_handler_linux(trampoline_data, handler_offset, trampoline_base_addr)
        }
        TargetOs::MacOs => {
            emit_shared_svc_handler_macos(trampoline_data, handler_offset, trampoline_base_addr)
        }
    }
}
```

Same pattern for:
- `emit_svc_gate` (line 1988) — also passes `site` param
- `emit_shared_msr_handler` (line 2195)
- `emit_msr_gate` (line 3471) — also passes `site`, `rt` params
- `emit_mrs_gate` (line 3833) — also passes `site`, `rd` params

**Step 4: Convert `msr_gate_size` to accept `target_os`**

```rust
fn msr_gate_size(target_os: TargetOs, rt: u8) -> usize {
    target_os.msr_gate_size_for_rt(rt)
}
```

Or simply inline `target_os.msr_gate_size_for_rt(rt)` at call sites and delete `msr_gate_size`.

**Step 5: Commit**

```
refactor(rewriter): convert emit dispatchers to runtime TargetOs match
```

---

### Task 4: Thread `target_os` through `find_patch_sites` and `hook_syscalls_aarch64`

**Files:**
- Modify: `litebox_syscall_rewriter/src/arm64.rs`

**Step 1: Add `target_os` to `find_patch_sites`**

At line 1213, change signature:
```rust
fn find_patch_sites(sections: &[TextSectionInfo], buf: &[u8], target_os: TargetOs) -> Result<Vec<PatchSite>> {
```

Replace the `#[cfg(target_os = "macos")]` block at lines 1250-1272 with:
```rust
if target_os.is_macos() {
    if insn != SVC_0
        && (insn & MSR_TPIDR_EL0_MASK) != MSR_TPIDR_EL0_BITS
        && (insn & MRS_TPIDR_EL0_MASK) != MRS_TPIDR_EL0_BITS
        && references_x18(insn)
    {
        let (rewritten, scratch, is_read, is_write) = rewrite_x18(insn);
        let sp_fixup = needs_sp_fixup(rewritten, 48);
        sites.push(PatchSite {
            file_offset: start + i,
            vaddr: section.vaddr + i as u64,
            kind: PatchKind::X18Use {
                insn,
                rewritten,
                scratch,
                is_read,
                is_write,
                needs_sp_fixup: sp_fixup,
            },
        });
    }
}
```

**Step 2: Add `target_os` to `hook_syscalls_aarch64`**

At line 1311, change signature:
```rust
pub(crate) fn hook_syscalls_aarch64(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    trampoline: u64,
    target_os: TargetOs,
) -> Result<(Vec<u8>, bool)> {
```

**Step 3: Convert all inline cfg blocks in `hook_syscalls_aarch64`**

Replace at line 1318:
```rust
let sites = find_patch_sites(text_sections, buf, target_os)?;
```

Replace lines 1326-1331 (`has_x18_sites`):
```rust
let has_x18_sites = if target_os.is_macos() {
    sites.iter().any(|s| matches!(s.kind, PatchKind::X18Use { .. }))
} else {
    false
};
```

Replace all constant references with method calls. For example:
- `SIGRETURN_GATE_OFFSET` → `target_os.sigreturn_gate_offset()` (but this one is 24 for all — keep as constant or use method)
- `SVC_GATE_SIZE` → `target_os.svc_gate_size()`
- `SHARED_SVC_HANDLER_OFFSET` → `target_os.shared_svc_handler_offset()`
- `SHARED_MSR_HANDLER_OFFSET` → `target_os.shared_msr_handler_offset()`
- `SHARED_MRS_HANDLER_OFFSET` → `target_os.shared_mrs_handler_offset()`
- `SHARED_X18_LOAD_HANDLER_OFFSET` → `target_os.shared_x18_load_handler_offset()`
- `SHARED_X18_SAVE_HANDLER_OFFSET` → `target_os.shared_x18_save_handler_offset()`
- `GATES_START_OFFSET` → `target_os.gates_start_offset()`

Replace the three `#[cfg(target_os = "macos")]` blocks at lines 1387-1395, 1398-1406, 1409-1417 with:
```rust
if target_os.is_macos() {
    debug_assert_eq!(trampoline_data.len(), target_os.shared_mrs_handler_offset());
    emit_shared_mrs_handler(&mut trampoline_data, target_os.shared_mrs_handler_offset(), trampoline_base_addr)?;

    debug_assert_eq!(trampoline_data.len(), target_os.shared_x18_load_handler_offset());
    emit_shared_x18_load_handler(&mut trampoline_data, target_os.shared_x18_load_handler_offset(), trampoline_base_addr)?;

    debug_assert_eq!(trampoline_data.len(), target_os.shared_x18_save_handler_offset());
    emit_shared_x18_save_handler(&mut trampoline_data, target_os.shared_x18_save_handler_offset(), trampoline_base_addr)?;
}
```

Same for the duplicate block at lines 1475-1505.

Pass `target_os` to all emit function calls:
- `emit_svc_gate(..., target_os)`
- `emit_shared_svc_handler(..., target_os)`
- `emit_shared_msr_handler(..., target_os)`
- `emit_msr_gate(..., target_os)`
- `emit_mrs_gate(..., target_os)`

Replace `#[cfg(any(target_os = "macos", test))]` on the `PatchKind::X18Use` match arm at line 1541 — just remove the cfg, the arm is always compiled now.

**Step 4: Add `UnsupportedTargetOs` error and Windows guard**

In `lib.rs` (or at the top of `hook_syscalls_aarch64`):
```rust
if matches!(target_os, TargetOs::Windows) {
    return Err(Error::UnsupportedTargetOs("aarch64-windows"));
}
```

Add to the `Error` enum in `lib.rs`:
```rust
#[error("unsupported target OS for this architecture: {0}")]
UnsupportedTargetOs(&'static str),
```

**Step 5: Run `cargo check -p litebox_syscall_rewriter`**

Expected: Should compile with no errors (but possibly warnings about unused constants like `SHARED_SVC_HANDLER_INSN_COUNT` etc. — those were deleted in Task 1).

**Step 6: Commit**

```
feat(rewriter): thread TargetOs through rewriter pipeline
```

---

### Task 5: Update `lib.rs` — remove arch gate, add `target_os` to public API

**Files:**
- Modify: `litebox_syscall_rewriter/src/lib.rs:17-18,101,160-168`

**Step 1: Remove `#[cfg(target_arch = "aarch64")]` from mod arm64**

At lines 17-18, change:
```rust
#[cfg(target_arch = "aarch64")]
mod arm64;
```
to:
```rust
mod arm64;
```

**Step 2: Re-export TargetOs from the crate root**

Add after `mod arm64`:
```rust
pub use arm64::TargetOs;
```

**Step 3: Add `target_os` parameter to `hook_syscalls_in_elf`**

Change the public function signature at line 101:
```rust
pub fn hook_syscalls_in_elf(
    input_binary: &[u8],
    trampoline: Option<u64>,
    target_os: Option<arm64::TargetOs>,
) -> Result<Vec<u8>> {
```

**Step 4: Resolve default TargetOs and pass to arm64**

After `let trampoline = trampoline.unwrap_or(0);` (line 157), add:
```rust
let target_os = target_os.unwrap_or_else(|| {
    if cfg!(target_os = "macos") {
        arm64::TargetOs::MacOs
    } else if cfg!(target_os = "windows") {
        arm64::TargetOs::Windows
    } else {
        arm64::TargetOs::Linux
    }
});
```

**Step 5: Update the AArch64 dispatch**

Replace lines 160-168:
```rust
let (trampoline_data, _syscall_insns_found) = if arch == Arch::Aarch64 {
    arm64::hook_syscalls_aarch64(buf, &text_sections, trampoline_base_addr, trampoline, target_os)?
} else {
```

(Remove the `#[cfg(target_arch)]` / `unreachable!` pattern entirely.)

**Step 6: Run `cargo check -p litebox_syscall_rewriter`**

Expected: Clean compilation.

**Step 7: Commit**

```
feat(rewriter): expose TargetOs in public API, remove target_arch gate
```

---

### Task 6: Add `--target-os` CLI parameter

**Files:**
- Modify: `litebox_syscall_rewriter/src/main.rs`

**Step 1: Add --target-os argument**

```rust
use litebox_syscall_rewriter::TargetOs;

#[derive(Parser, Debug)]
struct CliArgs {
    input_binary: PathBuf,
    #[arg(short = 'o', long = "output")]
    output_binary: Option<PathBuf>,
    #[arg(long)]
    trampoline_addr: Option<u64>,
    /// Target OS for the rewritten binary (default: host OS)
    #[arg(long, value_enum)]
    target_os: Option<TargetOs>,
}
```

Add `clap::ValueEnum` derive to `TargetOs` in `arm64.rs`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum TargetOs {
    Linux,
    #[value(name = "macos")]
    MacOs,
    Windows,
}
```

Note: Since `TargetOs` is in the rewriter crate (which depends on clap), `ValueEnum` derive is fine.

**Step 2: Pass target_os to hook_syscalls_in_elf**

```rust
let output_binary = litebox_syscall_rewriter::hook_syscalls_in_elf(
    &input_binary_bytes,
    cli_args.trampoline_addr,
    cli_args.target_os,
)?;
```

**Step 3: Verify CLI works**

Run: `cargo run -p litebox_syscall_rewriter -- --help`
Expected: Shows `--target-os <TARGET_OS>` with `[possible values: linux, macos, windows]`

**Step 4: Commit**

```
feat(rewriter): add --target-os CLI parameter
```

---

### Task 7: Update all constant references inside emit variant functions

**Files:**
- Modify: `litebox_syscall_rewriter/src/arm64.rs` (throughout variant functions)

The `_linux` and `_macos` emit variant functions internally reference the old constants (`SHARED_SVC_HANDLER_INSN_COUNT`, `SVC_GATE_SIZE`, `SHARED_MSR_HANDLER_OFFSET`, etc.). Since these constants were deleted in Task 1, these functions must be updated to accept `target_os` and call methods instead.

**Step 1: Thread `target_os` through all variant functions**

Add `target_os: TargetOs` parameter to all 10 variant functions and their macOS-only counterparts. Update internal references:

For `_linux` variants, all constant references resolve to the Linux value (e.g., `target_os.svc_gate_insn_count()` returns 6). For `_macos` variants, they resolve to macOS values.

Key replacements inside function bodies:
- `SHARED_SVC_HANDLER_INSN_COUNT` → `target_os.shared_svc_handler_insn_count()`
- `SVC_GATE_INSN_COUNT` → `target_os.svc_gate_insn_count()`
- `SHARED_SVC_HANDLER_SIZE` → `target_os.shared_svc_handler_size()`
- `SHARED_SVC_HANDLER_OFFSET` → `target_os.shared_svc_handler_offset()`
- `SHARED_MSR_HANDLER_OFFSET` → `target_os.shared_msr_handler_offset()`
- `SHARED_MSR_HANDLER_SIZE` → `target_os.shared_msr_handler_size()`
- `MSR_GATE_INSN_COUNT` → `target_os.msr_gate_insn_count()`
- `MSR_GATE_SIZE` → `target_os.msr_gate_size()`
- `MSR_GATE_SPECIAL_SIZE` → `target_os.msr_gate_special_size()`
- `MRS_GATE_INSN_COUNT` → `target_os.mrs_gate_insn_count()`
- `MRS_GATE_SIZE` → `target_os.mrs_gate_size()`
- `SHARED_MRS_HANDLER_OFFSET` → `target_os.shared_mrs_handler_offset()`
- `SHARED_MRS_HANDLER_SIZE` → `target_os.shared_mrs_handler_size()`
- `SHARED_X18_LOAD_HANDLER_OFFSET` → `target_os.shared_x18_load_handler_offset()`
- `SHARED_X18_SAVE_HANDLER_OFFSET` → `target_os.shared_x18_save_handler_offset()`
- `X18_GATE_READ_INSN_COUNT` → `target_os.x18_gate_read_insn_count()`
- `X18_GATE_WRITE_INSN_COUNT` → `target_os.x18_gate_write_insn_count()`
- `X18_GATE_READWRITE_INSN_COUNT` → `target_os.x18_gate_readwrite_insn_count()`
- `GATES_START_OFFSET` → `target_os.gates_start_offset()`

Also update `x18_gate_size` and `needs_sp_fixup` to use `target_os` methods if they reference any of these constants.

The macOS-only emit functions that don't have a linux counterpart (emit_shared_mrs_handler, emit_shared_x18_load_handler, emit_shared_x18_save_handler, emit_x18_gate) also need `target_os` threaded through for constant resolution.

**Step 2: Run `cargo check -p litebox_syscall_rewriter`**

Expected: Clean compilation.

**Step 3: Commit**

```
refactor(rewriter): thread TargetOs through all emit variant functions
```

---

### Task 8: Update tests

**Files:**
- Modify: `litebox_syscall_rewriter/src/arm64.rs` (test module, line 4214+)

**Step 1: Update `find_patch_sites` call sites in tests**

All test calls to `find_patch_sites` need the new `target_os` parameter:
- `test_find_patch_sites_single_svc` (line 4591): `find_patch_sites(&sections, &buf, TargetOs::Linux)`
- `test_find_patch_sites_multiple_svc` (line 4612): same
- `test_find_patch_sites_none` (line 4628): same
- `test_find_patch_sites_not_svc0` (line 4645): same
- `test_find_patch_sites_msr_tpidr` (line 4662): same
- `test_find_patch_sites_mixed_svc_and_msr` (line 4684): same
- `test_find_patch_sites_mrs_tpidr_detected` (line 5507): same

**Step 2: Update `hook_syscalls_aarch64` call sites in tests**

All test calls need `target_os` parameter:
- Add `TargetOs::Linux` to all existing Linux-path tests
- Tests that were gated with `#[cfg(any(target_os = "macos", test))]` should pass `TargetOs::MacOs`

Pattern: `hook_syscalls_aarch64(&mut buf, &sections, trampoline_base, callback_addr, TargetOs::Linux)`

**Step 3: Update constant references in tests**

Replace all bare constant references with method calls:
- `GATES_START_OFFSET` → `TargetOs::Linux.gates_start_offset()` (or `TargetOs::MacOs` in macOS tests)
- `SVC_GATE_SIZE` → `TargetOs::Linux.svc_gate_size()`
- `MSR_GATE_SIZE` → `TargetOs::Linux.msr_gate_size()`
- `MRS_GATE_SIZE` → `TargetOs::Linux.mrs_gate_size()`
- etc.

**Step 4: Remove any remaining `#[cfg(any(target_os = "macos", test))]` from test functions**

Since all macOS functions are now unconditionally compiled, any test-only cfg gates can be removed.

**Step 5: Run tests**

Run: `cargo test -p litebox_syscall_rewriter`
Expected: All 116 tests + 1 snapshot pass.

**Step 6: Commit**

```
test(rewriter): update all tests for TargetOs runtime dispatch
```

---

### Task 9: Clean up and verify

**Files:**
- Modify: `litebox_syscall_rewriter/src/arm64.rs` (any remaining cfg references)

**Step 1: Verify no `#[cfg(target_os` remains in arm64.rs**

Run: `grep -n 'cfg.*target_os' litebox_syscall_rewriter/src/arm64.rs`
Expected: Zero matches (only `#[cfg(test)]` on the test module should remain).

**Step 2: Verify no `#[cfg(target_arch` remains in lib.rs**

Run: `grep -n 'cfg.*target_arch' litebox_syscall_rewriter/src/lib.rs`
Expected: Zero matches.

**Step 3: Run full test suite**

Run: `cargo test -p litebox_syscall_rewriter`
Expected: All tests pass.

**Step 4: Run clippy**

Run: `cargo clippy -p litebox_syscall_rewriter -- -D warnings`
Expected: Clean.

**Step 5: Run cargo fmt**

Run: `cargo fmt -p litebox_syscall_rewriter`

**Step 6: Final commit**

```
chore(rewriter): clean up cross-OS rewriting refactor
```

---

### Task Ordering

```
Task 1 (TargetOs enum + constants) → Task 2 (remove cfg from helpers) → Task 3 (emit dispatchers) → Task 4 (pipeline threading) → Task 5 (lib.rs API) → Task 6 (CLI) → Task 7 (variant function constants) → Task 8 (tests) → Task 9 (verify)
```

Note: Tasks 1-7 can be batched into fewer commits if the intermediate states don't compile. The key invariant is that after Task 8, the full test suite passes. It is acceptable to combine Tasks 1-7 into a single large commit if intermediate compilation is impractical.

### Practical Note on Compilation

Since removing the old constants (Task 1) breaks all references before they're updated (Task 7), the recommended approach is:

**Option A (incremental):** Keep old constants as `#[allow(dead_code)]` aliases during the transition, remove them last.

**Option B (big-bang):** Do Tasks 1-8 as one atomic change, test at the end.

Option B is more practical for this mechanical refactor since intermediate states won't compile.
