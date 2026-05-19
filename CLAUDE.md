# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What LiteBox Is

LiteBox is a security-focused sandboxing library OS written in Rust. It drastically reduces the interface to the host, thereby reducing attack surface. The core design separates a **North** interface (what applications see) from a **South** interface (what the host platform provides), allowing any North shim to be paired with any South platform.

Example use cases: running unmodified Linux programs on Windows, sandboxing Linux apps on Linux, running on SEV-SNP, OP-TEE, or LVBS (Hyper-V VTL1).

## Development Commands

```sh
cargo fmt                                    # format (required before commit)
cargo build                                  # build
cargo clippy --all-targets --all-features    # lint
cargo nextest run                            # test (preferred over cargo test)
cargo nextest run -E 'test(test_name)'       # run a single test
cargo doc --no-deps                          # build docs
```

`bacon` is available as an interactive watcher with project-specific keybindings (see `bacon.toml`):
- `c` / `alt-c` — clippy / clippy-all
- `k` / `alt-k` — check / check-all
- `n` — nextest
- `d` — doc-open
- `w` — clippy for Windows target (via PowerShell)
- `v` — build checks for LVBS (requires nightly + `build-std`)
- `alt-s` — build checks for SNP

### Special Targets

**LVBS** (`litebox_runner_lvbs`) requires a nightly toolchain, a custom target file (`litebox_runner_lvbs/x86_64_vtl1.json`), and `-Z build-std`. It is excluded from the workspace default members.

**SNP** (`litebox_runner_snp`) similarly requires a nightly toolchain with `-Z build-std` and its own `target.json`.

**Windows runner** (`litebox_runner_linux_on_windows_userland`) must be built via PowerShell with `$env:CARGO_TARGET_DIR = ".\target\windows"`.

## Architecture

### North–South Model

```
Application (Linux binary, OP-TEE TA, etc.)
        |
   [North shim]  litebox_shim_linux / litebox_shim_windows / litebox_shim_optee
        |
   [LiteBox core]  litebox/  — POSIX-like Rust API (nix/rustix-inspired)
        |
   [South platform]  litebox_platform_*
        |
   Host OS / Hypervisor / Bare metal
```

### Core Crate (`litebox/`)

`no_std` library. Provides:
- `platform::Provider` — the trait a South platform must implement
- `fd` — file descriptor table
- `fs` — filesystems (in-memory, layered, TAR read-only, 9P)
- `net` — TCP/UDP/ICMP via smoltcp
- `mm` — memory management
- `sync` — mutex, rwlock, futex, condvar
- `event` — observer/polling/wait
- `pipes`, `tls`, `shim`, `utils`
- `LiteBox` — the top-level object that wires everything together

### Platform Crates (`litebox_platform_*`)

Each implements `platform::Provider` for a specific host:
- `linux_userland` — Linux syscalls from user space
- `windows_userland` — Windows WinAPI
- `linux_kernel` — Linux kernel space
- `lvbs` — Hyper-V VTL1
- `multiplex` — selects platform at compile time via feature flags

### Shim Crates (`litebox_shim_*`)

North-side adapters that translate application ABIs into LiteBox API calls:
- `litebox_shim_linux` — Linux application ABI (syscall interception/rewriting)
- `litebox_shim_windows` — Windows application ABI
- `litebox_shim_optee` — OP-TEE TA ABI

### Runner Crates (`litebox_runner_*`)

Executable entry points that pair a specific shim with a specific platform:
- `linux_userland` — Linux apps on Linux
- `linux_on_windows_userland` — Linux apps on Windows
- `windows_userland` — Windows apps on Windows
- `optee_on_linux_userland` — OP-TEE TAs on Linux
- `lvbs` — LVBS environment
- `snp` — SEV-SNP environment

### Utilities

- `litebox_syscall_rewriter` — binary tool to rewrite syscalls in ELF binaries
- `litebox_packager` — packages applications as OCI images
- `litebox_util_log` / `litebox_util_log_macros` — logging facade supporting both `log` and `tracing` backends
- `litebox_common_linux` / `litebox_common_windows` / `litebox_common_optee` — shared platform-specific types

### Dev-Only Crates

`dev_tests` and `dev_bench` are not released and exist purely for CI/development.

## Coding Style

### Implementing New Shims, Platforms, or Runners

When adding a new shim, platform, or runner, treat the most closely related existing one as the canonical template and mirror its structure as closely as possible — module layout, trait implementations, error handling patterns, feature flag naming, and `Cargo.toml` shape. Deviate only when you have a concrete reason (e.g., the new target genuinely requires a different approach). This keeps the family of crates consistent and easy to navigate.

Concretely:
- New Linux-adjacent shim? Model it on `litebox_shim_linux`.
- New userland platform? Model it on `litebox_platform_linux_userland`.
- New runner? Model it on the runner whose North+South combination is closest.

If you spot a better pattern while implementing, apply it to the existing crates at the same time rather than diverging silently.

### Comments

Do not write comments for code that is self-explanatory from its names and structure. When you do comment, explain **why** — the non-obvious reason something is needed: a hidden constraint, a subtle invariant, a workaround for a specific platform quirk, or behavior that would surprise a reader. Skip comments that just restate what the code does.

### Visibility

Use the minimal visibility that compiles. Default to private; widen only as far as the actual use site requires — `pub(super)` before `pub(crate)`, `pub(crate)` before `pub`. Reserve bare `pub` for items that genuinely belong to the crate's public API.

### Clippy warnings

Fix clippy warnings; do not silence them with `#[allow(...)]`. An `allow` is only acceptable when the lint is genuinely wrong for the situation, and in that case the attribute must be scoped as narrowly as possible (a single item, not a module or crate) and accompanied by a comment explaining why the lint does not apply. Blanket `#![allow(...)]` at module or crate scope is not acceptable for new code.

## Key Conventions

- Every `unsafe` block **must** have a safety comment explaining why it is sound. Prefer safe abstractions.
- Favor `no_std` compatibility. Using `std` in a crate must be deliberate.
- New external dependencies must be justified and use `default-features = false`.
- Clippy runs at `pedantic` level workspace-wide (see `[workspace.lints.clippy]` in root `Cargo.toml`).
- OP-TEE runner has feature flag conflicts with the Linux runner; they cannot be compiled together — CI handles them as separate jobs.
