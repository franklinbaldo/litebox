# Cross-OS Rewriting: Runtime Target OS Dispatch

**Date:** 2026-03-14
**Status:** Approved
**Scope:** `litebox_syscall_rewriter` crate only

## Problem

The syscall rewriter uses `#[cfg(target_os = ...)]` compile-time gates throughout
`arm64.rs` (83 occurrences) to select platform-specific constants, emit functions,
and instruction sequences. This means a Linux-built rewriter can only produce
Linux-targeted binaries, and a macOS-built rewriter can only produce macOS-targeted
binaries.

We want to run the rewriter on Linux ARM64 (or any host) and produce binaries
targeting macOS ARM64 (or any target). The rewriter doesn't execute ARM64
instructions — it generates them as byte sequences — so there's no architectural
barrier to cross-compilation.

## Design

### 1. `TargetOs` Enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TargetOs {
    Linux,
    #[value(name = "macos")]
    MacOs,
    Windows,
}
```

**Semantics by architecture:**

| Target | x86/x86-32 | ARM64 |
|--------|-----------|-------|
| Linux  | identical | Linux codepath (TPIDR_EL0-based TLS, x18 = GP) |
| MacOs  | identical | macOS codepath (TPIDRRO_EL0-keyed, x18 virtualization) |
| Windows| identical | **Not yet implemented** → `Error::UnsupportedTargetOs` |

On x86, `TargetOs` is accepted but ignored — all targets produce identical output.
On ARM64, each OS has distinct rewriting behavior (or an explicit error for unimplemented targets).

### 2. Constants → `TargetOs` Methods

All paired `#[cfg]` constants become `const fn` methods:

```rust
impl TargetOs {
    pub const fn svc_gate_insn_count(self) -> usize {
        match self { Self::Linux | Self::Windows => 6, Self::MacOs => 7 }
    }
    pub const fn shared_svc_handler_insn_count(self) -> usize {
        match self { Self::Linux | Self::Windows => 18, Self::MacOs => 18 }
    }
    pub const fn shared_msr_handler_insn_count(self) -> usize {
        match self { Self::Linux | Self::Windows => 19, Self::MacOs => 17 }
    }
    pub const fn msr_gate_insn_count(self) -> usize {
        match self { Self::Linux | Self::Windows => 9, Self::MacOs => 13 }
    }
    pub const fn mrs_gate_insn_count(self) -> usize {
        match self { Self::Linux | Self::Windows => 5, Self::MacOs => 13 }
    }
    // macOS-only handler counts (only meaningful when target_os == MacOs)
    pub const fn shared_mrs_handler_insn_count(self) -> usize { 16 }
    pub const fn shared_x18_load_handler_insn_count(self) -> usize { 16 }
    pub const fn shared_x18_save_handler_insn_count(self) -> usize { 16 }

    // Derived sizes
    pub const fn svc_gate_size(self) -> usize { self.svc_gate_insn_count() * 4 }
    pub const fn shared_svc_handler_size(self) -> usize { self.shared_svc_handler_insn_count() * 4 }
    // ... etc for all sizes

    // Layout offsets
    pub const fn sigreturn_gate_offset(self) -> usize { 24 }
    pub const fn shared_svc_handler_offset(self) -> usize {
        self.sigreturn_gate_offset() + self.svc_gate_size()
    }
    pub const fn shared_msr_handler_offset(self) -> usize {
        self.shared_svc_handler_offset() + self.shared_svc_handler_size()
    }
    pub const fn gates_start_offset(self) -> usize {
        match self {
            Self::Linux | Self::Windows => {
                self.shared_msr_handler_offset() + self.shared_msr_handler_size()
            }
            Self::MacOs => {
                let mrs = self.shared_msr_handler_offset() + self.shared_msr_handler_size();
                let x18_load = mrs + self.shared_mrs_handler_size();
                let x18_save = x18_load + self.shared_x18_load_handler_size();
                x18_save + self.shared_x18_save_handler_size()
            }
        }
    }

    pub const fn is_macos(self) -> bool { matches!(self, Self::MacOs) }
}
```

Note: `const fn` with `match` on enums is stable in Rust since 1.46. All these
methods can be evaluated at compile time when called with a literal, or at runtime
when called with a variable.

### 3. Function Dispatch

The existing pattern of paired `_linux` / `_macos` emit functions is preserved.
Only the dispatch wrappers change:

```rust
// Before:
fn emit_svc_gate(...) {
    #[cfg(target_os = "linux")]
    emit_svc_gate_linux(...);
    #[cfg(target_os = "macos")]
    emit_svc_gate_macos(...);
}

// After:
fn emit_svc_gate(target_os: TargetOs, ...) {
    match target_os {
        TargetOs::Linux | TargetOs::Windows => emit_svc_gate_linux(...),
        TargetOs::MacOs => emit_svc_gate_macos(...),
    }
}
```

Functions affected (5 dispatchers + their variants):
- `emit_shared_svc_handler` → `_linux` / `_macos`
- `emit_svc_gate` → `_linux` / `_macos`
- `emit_shared_msr_handler` → `_linux` / `_macos`
- `emit_msr_gate` → `_linux` / `_macos`
- `emit_mrs_gate` → `_linux` / `_macos`

The `_linux` and `_macos` variant functions keep their exact current bodies —
no refactoring of their internals. The only change is removing their `#[cfg]`
gate attributes.

### 4. `PatchKind::X18Use`

The `#[cfg(any(target_os = "macos", test))]` gate on the `X18Use` variant is
removed. The variant is always compiled. `find_patch_sites` conditionally emits
`X18Use` entries based on `target_os.is_macos()` at runtime.

Same for all macOS-only helper functions (`references_x18`, `rewrite_x18_insn`,
`x18_access_kind`, `adjust_sp_relative_offset`, `emit_x18_gate`,
`emit_shared_mrs_handler`, `emit_shared_x18_load_handler`,
`emit_shared_x18_save_handler`): their `#[cfg]` gates are removed; they're
always compiled.

### 5. `lib.rs` Changes

The `#[cfg(target_arch = "aarch64")]` gate on `mod arm64` is **removed**. The
ARM64 rewriter module generates instruction bytes as `u32` values — it doesn't
execute ARM64 instructions and has no inline asm. It compiles on any host
architecture.

The dispatch in `hook_syscalls_in_elf` changes from:

```rust
if arch == Arch::Aarch64 {
    #[cfg(target_arch = "aarch64")]
    { arm64::hook_syscalls_aarch64(buf, &text_sections, trampoline_base_addr, trampoline)? }
    #[cfg(not(target_arch = "aarch64"))]
    { unreachable!("AArch64 ELF cannot be loaded on non-aarch64 host") }
}
```

to:

```rust
if arch == Arch::Aarch64 {
    arm64::hook_syscalls_aarch64(buf, &text_sections, trampoline_base_addr, trampoline, target_os)?
}
```

### 6. Public API

```rust
pub fn hook_syscalls_in_elf(
    input_binary: &[u8],
    trampoline: Option<u64>,
    target_os: Option<TargetOs>,
) -> Result<Vec<u8>>
```

When `target_os` is `None`:
- On Linux hosts: defaults to `TargetOs::Linux`
- On macOS hosts: defaults to `TargetOs::MacOs`
- On Windows hosts: defaults to `TargetOs::Windows`

For x86 binaries, `target_os` is accepted but has no effect on output.

### 7. CLI

```rust
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

### 8. Error Handling

New error variant:

```rust
#[error("unsupported target OS for this architecture: {0}")]
UnsupportedTargetOs(&'static str),
```

Used when `TargetOs::Windows` is requested for ARM64 binaries.

### 9. Test Strategy

- Existing tests that test Linux codepaths: pass `TargetOs::Linux` explicitly
- Existing tests gated with `#[cfg(any(target_os = "macos", test))]`: remove
  the cfg gate, pass `TargetOs::MacOs` explicitly
- All 116 tests + 1 snapshot test continue to pass
- No new tests needed for this refactor (it's mechanical, not algorithmic)

## What This Does NOT Change

- **Platform crates** (`litebox_platform_macos_userland`, `litebox_shim_linux`):
  These are runtime crates that execute on the target platform. They keep their
  `#[cfg]` gates — they can't run on the wrong OS.
- **Emit function bodies**: The `_linux` and `_macos` variants keep their exact
  instruction sequences. No gate changes inside them.
- **x86 codepaths**: Completely unaffected.

## Scope Summary

| Item | Count |
|------|-------|
| `#[cfg]` gates to remove | 83 |
| Functions getting `target_os` param | ~15 |
| New `TargetOs` impl methods | ~20 |
| CLI changes | 1 new arg |
| Public API changes | 1 new param |
| New error variant | 1 |
| Files changed | 3 (`arm64.rs`, `lib.rs`, `main.rs`) |
