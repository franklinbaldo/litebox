# litebox_shim_macos Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run static aarch64 Mach-O executables on LiteBox via a new macOS shim, Mach-O syscall rewriter, and Mach-O loader.

**Architecture:** New crates `litebox_common_macos`, `litebox_syscall_rewriter_macho`, `litebox_shim_macos`, `litebox_runner_macos_on_macos_userland`. The Mach-O rewriter patches `svc #0x80` to branch to trampoline gates. The shim dispatches BSD syscalls via x16. The platform restores NZCV for carry-flag error signaling.

**Tech Stack:** Rust (edition 2024, no_std where needed), `object` crate for Mach-O parsing, Xcode `as`/`ld` for test binary compilation.

**Spec:** `docs/superpowers/specs/2026-04-01-litebox-shim-macos-design.md`

---

## Task 1: Workspace setup and crate scaffolding

Create the four new crates with minimal `Cargo.toml` and stub `lib.rs` files. Add them to the workspace. Verify they compile.

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `litebox_common_macos/Cargo.toml`
- Create: `litebox_common_macos/src/lib.rs`
- Create: `litebox_syscall_rewriter_macho/Cargo.toml`
- Create: `litebox_syscall_rewriter_macho/src/lib.rs`
- Create: `litebox_shim_macos/Cargo.toml`
- Create: `litebox_shim_macos/src/lib.rs`
- Create: `litebox_runner_macos_on_macos_userland/Cargo.toml`
- Create: `litebox_runner_macos_on_macos_userland/src/lib.rs`

- [ ] **Step 1: Add new crates to workspace `Cargo.toml`**

In the root `Cargo.toml`, add the four new crates to `members` and `default-members`:

```toml
# Add to members list (after litebox_shim_linux):
    "litebox_shim_macos",
# Add after litebox_common_optee:
    "litebox_common_macos",
# Add after litebox_syscall_rewriter:
    "litebox_syscall_rewriter_macho",
# Add after litebox_runner_linux_on_macos_userland:
    "litebox_runner_macos_on_macos_userland",
```

Also add `litebox_shim_macos`, `litebox_common_macos`, `litebox_syscall_rewriter_macho` to `default-members`. Do NOT add `litebox_runner_macos_on_macos_userland` to `default-members` (same as `litebox_platform_macos_userland` which is members-only).

- [ ] **Step 2: Create `litebox_common_macos/Cargo.toml`**

```toml
[package]
name = "litebox_common_macos"
version = "0.1.0"
edition = "2024"

[dependencies]
litebox = { path = "../litebox/", version = "0.1.0" }
litebox_common_linux = { path = "../litebox_common_linux/", version = "0.1.0" }

[lints]
workspace = true
```

- [ ] **Step 3: Create `litebox_common_macos/src/lib.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common macOS items suitable for LiteBox

#![no_std]

extern crate alloc;

// Re-export PtRegs from litebox_common_linux (same aarch64 register layout).
pub use litebox_common_linux::PtRegs;
```

- [ ] **Step 4: Create `litebox_syscall_rewriter_macho/Cargo.toml`**

```toml
[package]
name = "litebox_syscall_rewriter_macho"
version = "0.1.0"
edition = "2024"

[dependencies]
object = { version = "0.36.7", default-features = false, features = ["macho", "read", "std"] }
thiserror = { version = "2.0.6", default-features = false }
zerocopy = { version = "0.8", features = ["derive"] }

[lints]
workspace = true

[dev-dependencies]
tempfile = "3.19.1"
```

- [ ] **Step 5: Create `litebox_syscall_rewriter_macho/src/lib.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Rewrite Mach-O files to hook syscalls.
//!
//! This crate supports AArch64 Mach-O executables (MH_EXECUTE).

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("unsupported object file format")]
    UnsupportedObjectFile,
    #[error("no executable sections found")]
    NoTextSectionFound,
    #[error("no SVC #0x80 instructions found")]
    NoSvcInstructionsFound,
    #[error("disassembly failure: {0}")]
    DisassemblyFailure(String),
    #[error("insufficient header space for new load command")]
    InsufficientHeaderSpace,
}

pub type Result<T> = core::result::Result<T, Error>;

/// Rewrite a Mach-O binary to hook `svc #0x80` instructions.
///
/// Returns the rewritten binary bytes.
pub fn hook_syscalls_in_macho(input_binary: &[u8]) -> Result<Vec<u8>> {
    let _ = input_binary;
    todo!("Mach-O rewriter not yet implemented")
}
```

- [ ] **Step 6: Create `litebox_shim_macos/Cargo.toml`**

```toml
[package]
name = "litebox_shim_macos"
version = "0.1.0"
edition = "2024"

[dependencies]
litebox = { path = "../litebox/", version = "0.1.0" }
litebox_common_macos = { path = "../litebox_common_macos/", version = "0.1.0" }
litebox_common_linux = { path = "../litebox_common_linux/", version = "0.1.0" }
litebox_platform_multiplex = { path = "../litebox_platform_multiplex/", version = "0.1.0", default-features = false }
thiserror = { version = "2.0.6", default-features = false }

[features]
default = ["platform_macos_userland"]
platform_macos_userland = ["litebox_platform_multiplex/platform_macos_userland"]

[lints]
workspace = true
```

- [ ] **Step 7: Create `litebox_shim_macos/src/lib.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a macOS-compatible ABI via LiteBox.

#![no_std]
#![cfg(target_arch = "aarch64")]

extern crate alloc;
```

- [ ] **Step 8: Create `litebox_runner_macos_on_macos_userland/Cargo.toml`**

```toml
[package]
name = "litebox_runner_macos_on_macos_userland"
version = "0.1.0"
edition = "2024"

[dependencies]
anyhow = "1.0.97"
clap = { version = "4.5.33", features = ["derive"] }
libc = { version = "0.2.169", default-features = false }
litebox = { version = "0.1.0", path = "../litebox" }
litebox_common_macos = { version = "0.1.0", path = "../litebox_common_macos" }
litebox_common_linux = { version = "0.1.0", path = "../litebox_common_linux" }
litebox_platform_macos_userland = { version = "0.1.0", path = "../litebox_platform_macos_userland" }
litebox_platform_multiplex = { version = "0.1.0", path = "../litebox_platform_multiplex", default-features = false, features = ["platform_macos_userland"] }
litebox_shim_macos = { version = "0.1.0", path = "../litebox_shim_macos" }
litebox_syscall_rewriter_macho = { version = "0.1.0", path = "../litebox_syscall_rewriter_macho" }
memmap2 = "0.9.8"

[lints]
workspace = true
```

- [ ] **Step 9: Create `litebox_runner_macos_on_macos_userland/src/lib.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
```

- [ ] **Step 10: Verify everything compiles**

Run: `cargo check -p litebox_common_macos -p litebox_syscall_rewriter_macho -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland`

Expected: compiles with no errors (warnings OK).

- [ ] **Step 11: Commit**

```bash
git add -A && git commit -m "scaffold: add litebox_common_macos, litebox_syscall_rewriter_macho, litebox_shim_macos, litebox_runner_macos_on_macos_userland crates"
```

---

## Task 2: `litebox_common_macos` — errno, syscall numbers, and MacosSyscallRequest

Implement macOS ABI definitions: errno enum, syscall number constants, carry flag helpers, and the `MacosSyscallRequest` enum with `try_from_raw`.

**Files:**
- Modify: `litebox_common_macos/src/lib.rs`
- Create: `litebox_common_macos/src/errno.rs`
- Create: `litebox_common_macos/src/syscall.rs`

- [ ] **Step 1: Create `litebox_common_macos/src/errno.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS BSD errno values.

/// macOS errno values (BSD-derived).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Errno {
    EPERM = 1,
    ENOENT = 2,
    ESRCH = 3,
    EINTR = 4,
    EIO = 5,
    ENXIO = 6,
    E2BIG = 7,
    ENOEXEC = 8,
    EBADF = 9,
    ECHILD = 10,
    EDEADLK = 11,
    ENOMEM = 12,
    EACCES = 13,
    EFAULT = 14,
    ENOTBLK = 15,
    EBUSY = 16,
    EEXIST = 17,
    EXDEV = 18,
    ENODEV = 19,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    ENFILE = 23,
    EMFILE = 24,
    ENOTTY = 25,
    ETXTBSY = 26,
    EFBIG = 27,
    ENOSPC = 28,
    ESPIPE = 29,
    EROFS = 30,
    EMLINK = 31,
    EPIPE = 32,
    EDOM = 33,
    ERANGE = 34,
    EAGAIN = 35,
    ENOSYS = 78,
    ENOTSUP = 45,
}

impl Errno {
    /// Return the raw errno value as a positive integer (for the macOS ABI).
    pub const fn raw(self) -> usize {
        self as i32 as usize
    }
}

impl core::fmt::Display for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
```

- [ ] **Step 2: Create `litebox_common_macos/src/syscall.rs`**

This file defines `MacosSyscallRequest` and `try_from_raw`. The key difference from Linux: syscall number comes from `ctx.regs[16]` (x16).

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS BSD syscall request decoding.

use litebox_common_linux::PtRegs;
use litebox::platform::{RawConstPointer, RawMutPointer};
use litebox_platform_multiplex::Platform;

use crate::errno::Errno;

// BSD syscall numbers (aarch64 macOS).
pub mod nr {
    pub const EXIT: usize = 1;
    pub const READ: usize = 3;
    pub const WRITE: usize = 4;
    pub const OPEN: usize = 5;
    pub const CLOSE: usize = 6;
    pub const GETPID: usize = 20;
    pub const GETUID: usize = 24;
    pub const GETEUID: usize = 25;
    pub const GETEGID: usize = 43;
    pub const SIGACTION: usize = 46;
    pub const GETGID: usize = 47;
    pub const SIGPROCMASK: usize = 48;
    pub const IOCTL: usize = 54;
    pub const MUNMAP: usize = 73;
    pub const MPROTECT: usize = 74;
    pub const MADVISE: usize = 75;
    pub const MMAP: usize = 197;
    pub const LSEEK: usize = 199;
    pub const SYSCTL: usize = 202;
    pub const ISSETUGID: usize = 327;
    pub const FSTAT64: usize = 339;
}

/// A decoded macOS BSD syscall request.
pub enum MacosSyscallRequest {
    Exit { status: i32 },
    Read {
        fd: i32,
        buf: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
        count: usize,
    },
    Write {
        fd: i32,
        buf: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<u8>,
        count: usize,
    },
    Close { fd: i32 },
    Getpid,
    Getuid,
    Geteuid,
    Getgid,
    Getegid,
    Issetugid,
    Mmap {
        addr: usize,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    },
    Munmap { addr: usize, length: usize },
    Mprotect { addr: usize, length: usize, prot: i32 },
    Unknown { number: usize },
}

impl MacosSyscallRequest {
    /// Decode a syscall request from the register state.
    ///
    /// macOS aarch64: syscall number in x16, args in x0-x5.
    pub fn try_from_raw(ctx: &PtRegs) -> Self {
        let nr = ctx.regs[16];
        let a0 = ctx.regs[0];
        let a1 = ctx.regs[1];
        let a2 = ctx.regs[2];
        let a3 = ctx.regs[3];
        let a4 = ctx.regs[4];
        let a5 = ctx.regs[5];

        match nr {
            nr::EXIT => MacosSyscallRequest::Exit { status: a0 as i32 },
            nr::READ => MacosSyscallRequest::Read {
                fd: a0 as i32,
                buf: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::from_usize(a1),
                count: a2,
            },
            nr::WRITE => MacosSyscallRequest::Write {
                fd: a0 as i32,
                buf: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::from_usize(a1),
                count: a2,
            },
            nr::CLOSE => MacosSyscallRequest::Close { fd: a0 as i32 },
            nr::GETPID => MacosSyscallRequest::Getpid,
            nr::GETUID => MacosSyscallRequest::Getuid,
            nr::GETEUID => MacosSyscallRequest::Geteuid,
            nr::GETGID => MacosSyscallRequest::Getgid,
            nr::GETEGID => MacosSyscallRequest::Getegid,
            nr::ISSETUGID => MacosSyscallRequest::Issetugid,
            nr::MMAP => MacosSyscallRequest::Mmap {
                addr: a0,
                length: a1,
                prot: a2 as i32,
                flags: a3 as i32,
                fd: a4 as i32,
                offset: a5 as i64,
            },
            nr::MUNMAP => MacosSyscallRequest::Munmap { addr: a0, length: a1 },
            nr::MPROTECT => MacosSyscallRequest::Mprotect {
                addr: a0,
                length: a1,
                prot: a2 as i32,
            },
            _ => MacosSyscallRequest::Unknown { number: nr },
        }
    }
}

/// The NZCV carry bit in CPSR/PSTATE (bit 29).
pub const CARRY_BIT: usize = 1 << 29;

/// Set the syscall return value per macOS ABI.
///
/// On success: x0 = result, carry clear.
/// On error: x0 = errno (positive), carry set.
pub fn set_syscall_return(ctx: &mut PtRegs, result: Result<usize, Errno>) {
    match result {
        Ok(val) => {
            ctx.regs[0] = val;
            ctx.pstate &= !CARRY_BIT;
        }
        Err(errno) => {
            ctx.regs[0] = errno.raw();
            ctx.pstate |= CARRY_BIT;
        }
    }
}
```

- [ ] **Step 3: Update `litebox_common_macos/src/lib.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common macOS items suitable for LiteBox

#![no_std]

extern crate alloc;

pub mod errno;
pub mod syscall;

// Re-export PtRegs from litebox_common_linux (same aarch64 register layout).
pub use litebox_common_linux::PtRegs;
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p litebox_common_macos`

Expected: compiles successfully.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(common_macos): add MacosSyscallRequest, MacosErrno, carry flag helpers"
```

---

## Task 3: Platform change — restore NZCV in `switch_to_guest`

Modify `litebox_platform_macos_userland/src/lib.rs` so `switch_to_guest` restores `PtRegs.pstate` (NZCV) before jumping to the guest. This is required for the macOS carry-flag error convention.

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs` (the `switch_to_guest` naked function, around line 1227-1330)

- [ ] **Step 1: Add pstate stash below guest SP**

In `switch_to_guest`, the current stash layout below guest SP is:
```
[SP - 24] = guest_x0
[SP - 16] = guest_x1
[SP - 8]  = guest_PC
```

Add pstate at `[SP - 32]`:
```
[SP - 32] = guest_pstate
[SP - 24] = guest_x0
[SP - 16] = guest_x1
[SP - 8]  = guest_PC
```

Find the stash block (lines ~1289-1295) and add a stash for pstate. The PtRegs.pstate is at offset 264 (`31*8 + 8 + 8 = 264`).

Add after the line `"str x16, [x17, #-8]",  // guest_SP[-8] = guest PC`:
```asm
"ldr x16, [x0, #264]",  // x16 = guest pstate
"str x16, [x17, #-32]", // guest_SP[-32] = guest pstate
```

- [ ] **Step 2: Restore NZCV before final jump**

Before the final `br x16` (line ~1323), insert `msr NZCV` restoration. The sequence currently ends:
```asm
"ldur x16, [sp, #-8]",  // x16 = guest PC
"ldur x1,  [sp, #-16]", // x1 = guest x1
"ldur x0,  [sp, #-24]", // x0 = guest x0
"br x16",               // jump to guest
```

Change to:
```asm
"ldur x16, [sp, #-8]",  // x16 = guest PC
"ldur x1,  [sp, #-16]", // x1 = guest x1 (from stash)
"ldur x0,  [sp, #-32]", // x0 = guest pstate (TEMP — will use x0 for msr then reload)
"msr NZCV, x0",         // restore condition flags
"ldur x0,  [sp, #-24]", // x0 = guest x0 (from stash)
"br x16",               // jump to guest
```

This adds 2 instructions. The key insight: we briefly use x0 as a scratch to load pstate, write it to NZCV, then immediately reload x0 with the actual guest x0 value.

- [ ] **Step 3: Verify the Linux runner still works**

Run: `cargo test -p litebox_runner_linux_on_macos_userland -- --test-threads=1`

Expected: existing tests pass. The Linux shim stores `pstate = 0` so NZCV = 0 (all clear), matching the previous implicit behavior.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "fix(platform_macos): restore NZCV from PtRegs.pstate in switch_to_guest"
```

---

## Task 4: Mach-O syscall rewriter — parsing and SVC scanning

Implement the Mach-O parser and SVC site scanner. This task produces a crate that can find all `svc #0x80` sites in a Mach-O binary but does not yet patch them.

**Files:**
- Modify: `litebox_syscall_rewriter_macho/src/lib.rs`
- Create: `litebox_syscall_rewriter_macho/src/arm64.rs`

- [ ] **Step 1: Create `litebox_syscall_rewriter_macho/src/arm64.rs` with types and constants**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 Mach-O syscall rewriting.

use crate::{Error, Result};

/// `SVC #0x80` encoding: 0xD4001001
pub const SVC_0X80: u32 = 0xD4001001;

/// Metadata for an executable section in the Mach-O.
#[derive(Debug)]
pub struct TextSectionInfo {
    /// Virtual address of the section.
    pub vaddr: u64,
    /// File offset of the section.
    pub file_offset: usize,
    /// Size of the section in bytes.
    pub size: usize,
}

/// A site in the binary that needs patching.
#[derive(Debug)]
pub struct PatchSite {
    /// File offset of the instruction.
    pub file_offset: usize,
    /// Virtual address of the instruction.
    pub vaddr: u64,
    /// Kind of patch.
    pub kind: PatchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchKind {
    /// `SVC #0x80` — BSD syscall.
    Svc,
}

/// Find all patch sites in the given executable sections.
pub fn find_patch_sites(
    text_sections: &[TextSectionInfo],
    buf: &[u8],
) -> Result<Vec<PatchSite>> {
    let mut sites = Vec::new();
    for section in text_sections {
        let start = section.file_offset;
        let end = start + section.size;
        if end > buf.len() {
            return Err(Error::ParseError(format!(
                "section at offset {start:#x} extends past end of file"
            )));
        }
        // Walk 4 bytes at a time
        let mut offset = start;
        let mut vaddr = section.vaddr;
        while offset + 4 <= end {
            let insn = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
            if insn == SVC_0X80 {
                sites.push(PatchSite {
                    file_offset: offset,
                    vaddr,
                    kind: PatchKind::Svc,
                });
            }
            offset += 4;
            vaddr += 4;
        }
    }
    Ok(sites)
}
```

- [ ] **Step 2: Implement Mach-O parsing in `lib.rs`**

Replace the stub `hook_syscalls_in_macho` with actual parsing:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Rewrite Mach-O files to hook syscalls.
//!
//! This crate supports AArch64 Mach-O executables (MH_EXECUTE).

mod arm64;

use object::macho;
use object::read::macho::{MachHeader, MachOFile64};
use object::read::macho::LoadCommandVariant;
use object::{Endianness, ReadRef};
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("unsupported object file format")]
    UnsupportedObjectFile,
    #[error("no executable sections found")]
    NoTextSectionFound,
    #[error("no SVC #0x80 instructions found")]
    NoSvcInstructionsFound,
    #[error("disassembly failure: {0}")]
    DisassemblyFailure(String),
    #[error("insufficient header space for new load command")]
    InsufficientHeaderSpace,
}

pub type Result<T> = core::result::Result<T, Error>;

/// Parse a Mach-O binary and extract executable section info.
fn parse_text_sections(data: &[u8]) -> Result<Vec<arm64::TextSectionInfo>> {
    let header = macho::MachHeader64::<Endianness>::parse(data, 0)
        .map_err(|e| Error::ParseError(format!("invalid Mach-O header: {e}")))?;
    let endian = header.endian()
        .map_err(|e| Error::ParseError(format!("unsupported endianness: {e}")))?;

    // Validate: must be MH_EXECUTE, CPU_TYPE_ARM64
    if header.cputype(endian) != macho::CPU_TYPE_ARM64 {
        return Err(Error::UnsupportedObjectFile);
    }
    let filetype = header.filetype(endian);
    if filetype != macho::MH_EXECUTE {
        return Err(Error::UnsupportedObjectFile);
    }

    let mut sections = Vec::new();
    let mut commands = header.load_commands(endian, data, 0)
        .map_err(|e| Error::ParseError(format!("failed to read load commands: {e}")))?;

    while let Some(cmd) = commands.next()
        .map_err(|e| Error::ParseError(format!("failed to iterate load commands: {e}")))? {
        if let Some((seg, section_data)) = cmd.segment_64()
            .map_err(|e| Error::ParseError(format!("failed to parse segment: {e}")))? {
            // Check if any section in this segment is executable
            let segname = seg.name();
            // Skip __PAGEZERO
            if segname == *b"__PAGEZERO\0\0\0\0\0\0" {
                continue;
            }
            // Iterate sections within the segment
            let seg_sections = seg.sections(endian, section_data)
                .map_err(|e| Error::ParseError(format!("failed to read sections: {e}")))?;
            for section in seg_sections {
                let flags = section.flags(endian);
                let section_type = flags & macho::SECTION_TYPE;
                // Include regular code sections and stub sections
                if section_type == macho::S_REGULAR
                    || section_type == macho::S_SYMBOL_STUBS
                {
                    let sect_flags = section.flags(endian);
                    let attrs = sect_flags & macho::SECTION_ATTRIBUTES;
                    if attrs & macho::S_ATTR_SOME_INSTRUCTIONS != 0
                        || attrs & macho::S_ATTR_PURE_INSTRUCTIONS != 0
                    {
                        sections.push(arm64::TextSectionInfo {
                            vaddr: section.addr(endian).into(),
                            file_offset: section.offset(endian) as usize,
                            size: section.size(endian) as usize,
                        });
                    }
                }
            }
        }
    }

    if sections.is_empty() {
        return Err(Error::NoTextSectionFound);
    }
    Ok(sections)
}

/// Rewrite a Mach-O binary to hook `svc #0x80` instructions.
///
/// Returns the rewritten binary bytes.
pub fn hook_syscalls_in_macho(input_binary: &[u8]) -> Result<Vec<u8>> {
    let text_sections = parse_text_sections(input_binary)?;
    let mut buf = input_binary.to_vec();
    let sites = arm64::find_patch_sites(&text_sections, &buf)?;

    if sites.is_empty() {
        return Err(Error::NoSvcInstructionsFound);
    }

    // TODO: Task 5 will add trampoline emission and patching here.
    let _ = &mut buf;
    let _ = sites;

    todo!("trampoline emission not yet implemented")
}
```

- [ ] **Step 3: Verify parsing compiles and test with a placeholder**

Run: `cargo check -p litebox_syscall_rewriter_macho`

Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat(rewriter_macho): add Mach-O parser and SVC #0x80 site scanner"
```

---

## Task 5: Mach-O syscall rewriter — trampoline emission and binary patching

Copy the trampoline emission functions from the ELF rewriter (`litebox_syscall_rewriter/src/arm64.rs`) and integrate them with the Mach-O rewriter. Implement the binary patching logic: emit trampoline segment, patch SVC sites to branch to gates, insert new `LC_SEGMENT_64` load command.

**Files:**
- Modify: `litebox_syscall_rewriter_macho/src/arm64.rs` — add trampoline emission + encoding helpers
- Modify: `litebox_syscall_rewriter_macho/src/lib.rs` — complete `hook_syscalls_in_macho`

- [ ] **Step 1: Copy encoding helper functions from ELF rewriter**

Copy the following functions from `litebox_syscall_rewriter/src/arm64.rs` into `litebox_syscall_rewriter_macho/src/arm64.rs`:
- `encode_b` (encode B imm26)
- `encode_b_cond` (encode B.cond)
- `encode_br` (encode BR Xn)
- `encode_brk` (encode BRK imm16)
- `encode_adrp` (encode ADRP)
- `encode_add_imm` (encode ADD Xd, Xn, imm12)
- `encode_sub_sp_imm` (encode SUB SP, SP, imm12)
- `encode_stp_offset` (encode STP)
- `encode_str_imm_unsigned` (encode STR unsigned offset)
- `encode_ldr_imm_unsigned` (encode LDR unsigned offset)
- `encode_ldr_literal` (encode LDR literal)
- `encode_mrs_tpidrro_el0` (encode MRS Xd, TPIDRRO_EL0)
- `encode_cmn_imm` (encode CMN Xn, imm)
- `encode_cmp_reg` (encode CMP Xn, Xm)
- All constant definitions: `COND_EQ`, etc.

These are pure functions with no ELF-specific dependencies. Copy them verbatim.

- [ ] **Step 2: Copy `emit_svc_gate_macos` and `emit_shared_svc_handler_macos`**

Copy these functions from the ELF rewriter into the Mach-O rewriter's `arm64.rs`. They generate identical machine code — the only change is updating references to use local types (`PatchSite`, constants).

Key constants to also copy/define:
```rust
pub const HEADER_CALLBACK_OFFSET: usize = 0;
pub const HEADER_TLS_TABLE_OFFSET: usize = 8;
```

The trampoline layout for the Mach-O rewriter is:
```
Offset 0:  syscall_callback address (8 bytes, filled by loader at runtime)
Offset 8:  TLS table pointer (8 bytes, filled by loader at runtime)
Offset 16: shared SVC handler (18 instructions = 72 bytes)
Offset 88: per-site SVC gates (7 instructions = 28 bytes each)
```

Note: for phase 1, we omit the sigreturn gate, MSR/MRS TPIDR handlers, and x18 handlers. We only handle `SVC #0x80`. TPIDR and x18 rewriting can be added later.

Define a top-level function:

```rust
pub fn hook_syscalls_aarch64(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
) -> Result<Vec<u8>> {
    let sites = find_patch_sites(text_sections, buf)?;
    if sites.is_empty() {
        return Err(Error::NoSvcInstructionsFound);
    }

    let mut trampoline_data = Vec::new();

    // Header: callback addr (0) + TLS table ptr (0) — filled at load time
    trampoline_data.extend_from_slice(&0u64.to_le_bytes()); // offset 0
    trampoline_data.extend_from_slice(&0u64.to_le_bytes()); // offset 8

    // Shared SVC handler at offset 16
    let handler_offset = trampoline_data.len();
    emit_shared_svc_handler_macos(&mut trampoline_data, handler_offset, trampoline_base_addr)?;

    // Per-site SVC gates
    for site in &sites {
        let gate_offset = trampoline_data.len();
        emit_svc_gate_macos(&mut trampoline_data, gate_offset, trampoline_base_addr, site)?;

        // Patch original SVC #0x80 → B <gate>
        let gate_vaddr = trampoline_base_addr + gate_offset as u64;
        let b_offset = gate_vaddr as i64 - site.vaddr as i64;
        let b_insn = encode_b(b_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "B offset {b_offset:#x} out of ±128MB range for SVC at {:#x}",
                site.vaddr
            ))
        })?;
        buf[site.file_offset..site.file_offset + 4].copy_from_slice(&b_insn.to_le_bytes());
    }

    Ok(trampoline_data)
}
```

- [ ] **Step 3: Implement `insert_load_command_and_trampoline` in `lib.rs`**

This function:
1. Finds the end of existing load commands in the Mach-O header
2. Checks there's enough space before the first section data for a new `LC_SEGMENT_64` command (72 bytes)
3. Appends trampoline data to the file
4. Writes a new `LC_SEGMENT_64` load command pointing to the trampoline
5. Increments `ncmds` and `sizeofcmds` in the Mach-O header

```rust
/// Size of a segment_command_64 structure.
const SEGMENT_COMMAND_64_SIZE: usize = 72;

fn insert_load_command_and_trampoline(
    buf: &mut Vec<u8>,
    trampoline_data: &[u8],
    trampoline_vaddr: u64,
) -> Result<()> {
    let header = macho::MachHeader64::<Endianness>::parse(buf.as_slice(), 0)
        .map_err(|e| Error::ParseError(format!("{e}")))?;
    let endian = header.endian().map_err(|e| Error::ParseError(format!("{e}")))?;

    let header_size = core::mem::size_of::<macho::MachHeader64<Endianness>>();
    let existing_cmds_size = header.sizeofcmds(endian) as usize;
    let cmds_end = header_size + existing_cmds_size;

    // Find earliest section/segment file offset to know how much header space is free
    let mut earliest_data_offset = buf.len();
    let mut commands = header.load_commands(endian, buf.as_slice(), 0)
        .map_err(|e| Error::ParseError(format!("{e}")))?;
    while let Some(cmd) = commands.next().map_err(|e| Error::ParseError(format!("{e}")))? {
        if let Some((seg, _)) = cmd.segment_64().map_err(|e| Error::ParseError(format!("{e}")))? {
            let off = seg.fileoff(endian) as usize;
            let sz = seg.filesize(endian) as usize;
            if sz > 0 && off < earliest_data_offset {
                earliest_data_offset = off;
            }
        }
    }

    let available = earliest_data_offset.saturating_sub(cmds_end);
    if available < SEGMENT_COMMAND_64_SIZE {
        return Err(Error::InsufficientHeaderSpace);
    }

    // Append trampoline data at end of file, page-aligned
    let trampoline_file_offset = (buf.len() + 0xFFF) & !0xFFF;
    buf.resize(trampoline_file_offset, 0); // pad to page boundary
    buf.extend_from_slice(trampoline_data);
    let trampoline_file_size = trampoline_data.len();
    // Round vm size up to page
    let trampoline_vm_size = (trampoline_file_size + 0x3FFF) & !0x3FFF; // 16KB pages on macOS

    // Build LC_SEGMENT_64 command bytes
    let mut seg_cmd = [0u8; SEGMENT_COMMAND_64_SIZE];
    let e = Endianness::Little; // aarch64 is always LE
    // cmd = LC_SEGMENT_64
    seg_cmd[0..4].copy_from_slice(&(macho::LC_SEGMENT_64 as u32).to_le_bytes());
    // cmdsize
    seg_cmd[4..8].copy_from_slice(&(SEGMENT_COMMAND_64_SIZE as u32).to_le_bytes());
    // segname = "__LITEBOX\0..."
    seg_cmd[8..24].copy_from_slice(b"__LITEBOX\0\0\0\0\0\0\0");
    // vmaddr
    seg_cmd[24..32].copy_from_slice(&trampoline_vaddr.to_le_bytes());
    // vmsize
    seg_cmd[32..40].copy_from_slice(&(trampoline_vm_size as u64).to_le_bytes());
    // fileoff
    seg_cmd[40..48].copy_from_slice(&(trampoline_file_offset as u64).to_le_bytes());
    // filesize
    seg_cmd[48..56].copy_from_slice(&(trampoline_file_size as u64).to_le_bytes());
    // maxprot = VM_PROT_READ | VM_PROT_EXECUTE (5)
    seg_cmd[56..60].copy_from_slice(&5u32.to_le_bytes());
    // initprot = VM_PROT_READ | VM_PROT_EXECUTE (5)
    seg_cmd[60..64].copy_from_slice(&5u32.to_le_bytes());
    // nsects = 0
    seg_cmd[64..68].copy_from_slice(&0u32.to_le_bytes());
    // flags = 0
    seg_cmd[68..72].copy_from_slice(&0u32.to_le_bytes());

    // Insert the load command at cmds_end
    buf[cmds_end..cmds_end + SEGMENT_COMMAND_64_SIZE].copy_from_slice(&seg_cmd);

    // Update header: ncmds += 1, sizeofcmds += 72
    let ncmds_offset = 16; // offset of ncmds in MachHeader64
    let sizeofcmds_offset = 20;
    let old_ncmds = u32::from_le_bytes(buf[ncmds_offset..ncmds_offset + 4].try_into().unwrap());
    let old_sizeofcmds = u32::from_le_bytes(buf[sizeofcmds_offset..sizeofcmds_offset + 4].try_into().unwrap());
    buf[ncmds_offset..ncmds_offset + 4].copy_from_slice(&(old_ncmds + 1).to_le_bytes());
    buf[sizeofcmds_offset..sizeofcmds_offset + 4]
        .copy_from_slice(&(old_sizeofcmds + SEGMENT_COMMAND_64_SIZE as u32).to_le_bytes());

    Ok(())
}
```

- [ ] **Step 4: Complete `hook_syscalls_in_macho`**

Wire everything together:

```rust
pub fn hook_syscalls_in_macho(input_binary: &[u8]) -> Result<Vec<u8>> {
    let text_sections = parse_text_sections(input_binary)?;
    let mut buf = input_binary.to_vec();

    // Compute trampoline vaddr: page-aligned address past all segments
    let max_vaddr = find_max_segment_end(input_binary)?;
    let trampoline_vaddr = (max_vaddr + 0x3FFF) & !0x3FFF; // 16KB page align

    let trampoline_data = arm64::hook_syscalls_aarch64(
        &mut buf,
        &text_sections,
        trampoline_vaddr,
    )?;

    insert_load_command_and_trampoline(&mut buf, &trampoline_data, trampoline_vaddr)?;

    Ok(buf)
}

/// Find the highest virtual address + size across all segments.
fn find_max_segment_end(data: &[u8]) -> Result<u64> {
    let header = macho::MachHeader64::<Endianness>::parse(data, 0)
        .map_err(|e| Error::ParseError(format!("{e}")))?;
    let endian = header.endian().map_err(|e| Error::ParseError(format!("{e}")))?;
    let mut max_end: u64 = 0;
    let mut commands = header.load_commands(endian, data, 0)
        .map_err(|e| Error::ParseError(format!("{e}")))?;
    while let Some(cmd) = commands.next().map_err(|e| Error::ParseError(format!("{e}")))? {
        if let Some((seg, _)) = cmd.segment_64().map_err(|e| Error::ParseError(format!("{e}")))? {
            let end = seg.vmaddr(endian) + seg.vmsize(endian);
            if end > max_end {
                max_end = end;
            }
        }
    }
    Ok(max_end)
}
```

- [ ] **Step 5: Verify compilation**

Run: `cargo check -p litebox_syscall_rewriter_macho`

Expected: compiles.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(rewriter_macho): implement trampoline emission and Mach-O binary patching"
```

---

## Task 6: `litebox_shim_macos` — shim structure and syscall dispatch

Build the shim crate's core structure: `MacosShimBuilder`, `MacosShim`, `MacosShimEntrypoints`, `GlobalState`, `Task`, and the `do_syscall` dispatcher. No loader or filesystem yet — just the scaffolding that converts a BSD syscall into a carry-flag response.

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs`
- Create: `litebox_shim_macos/src/syscalls/mod.rs`
- Create: `litebox_shim_macos/src/syscalls/process.rs`
- Create: `litebox_shim_macos/src/syscalls/file.rs`
- Create: `litebox_shim_macos/src/syscalls/mm.rs`

- [ ] **Step 1: Write `litebox_shim_macos/src/lib.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a macOS-compatible ABI via LiteBox.

#![no_std]
#![cfg(target_arch = "aarch64")]

extern crate alloc;

use alloc::ffi::CString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use litebox::{
    LiteBox,
    mm::{PageManager, linux::PAGE_SIZE},
    net::Network,
    pipes::Pipes,
    platform::{RawConstPointer as _, RawMutPointer as _, TimeProvider},
    shim::ContinueOperation,
    sync::futex::FutexManager,
};
use litebox_common_macos::PtRegs;
use litebox_common_macos::syscall::{MacosSyscallRequest, set_syscall_return};
use litebox_common_macos::errno::Errno;
use litebox_platform_multiplex::Platform;

pub mod loader;
pub mod syscalls;

// Convenience type aliases
type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

/// A trait required for file systems to be used in the shim.
pub trait ShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> ShimFS for T {}

pub type DefaultFS = MacosFS;

pub(crate) type MacosFS = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

pub struct MacosShimEntrypoints<FS: ShimFS> {
    task: Task<FS>,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<FS: ShimFS> litebox::shim::EnterShim for MacosShimEntrypoints<FS> {
    type ExecutionContext = PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(true, ctx, Task::handle_init_request)
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_syscall_request)
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        _info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        // Phase 1: terminate on any exception.
        let _ = ctx;
        ContinueOperation::Terminate
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, |_, _| {})
    }
}

impl<FS: ShimFS> MacosShimEntrypoints<FS> {
    fn enter_shim(
        &self,
        _is_init: bool,
        ctx: &mut PtRegs,
        f: impl FnOnce(&Task<FS>, &mut PtRegs),
    ) -> ContinueOperation {
        f(&self.task, ctx);
        if self.task.should_terminate() {
            ContinueOperation::Terminate
        } else {
            ContinueOperation::Resume
        }
    }
}

pub struct MacosShimBuilder<FS: ShimFS> {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    fs: Option<FS>,
}

impl<FS: ShimFS> Default for MacosShimBuilder<FS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<FS: ShimFS> MacosShimBuilder<FS> {
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            platform,
            litebox: LiteBox::new(platform),
            fs: None,
        }
    }

    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    pub fn set_fs(&mut self, fs: FS) {
        self.fs = Some(fs);
    }

    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
    ) -> DefaultFS {
        let dev_stdio = litebox::fs::devices::FileSystem::new(&self.litebox);
        litebox::fs::layered::FileSystem::new(
            &self.litebox,
            in_mem_fs,
            litebox::fs::layered::FileSystem::new(
                &self.litebox,
                dev_stdio,
                tar_ro_fs,
                litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
            ),
            litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
        )
    }

    pub fn build(self) -> MacosShim<FS> {
        let mut net = Network::new(&self.litebox);
        net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
        let global = Arc::new(GlobalState {
            platform: self.platform,
            pm: PageManager::new(&self.litebox),
            fs: self.fs.expect("File system must be set before calling build"),
            futex_manager: FutexManager::new(),
            pipes: Pipes::new(&self.litebox),
            net: litebox::sync::Mutex::new(net),
            boot_time: self.platform.now(),
            litebox: self.litebox,
        });
        MacosShim(global)
    }
}

pub struct MacosShim<FS: ShimFS>(Arc<GlobalState<FS>>);
impl<FS: ShimFS> Clone for MacosShim<FS> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub struct LoadedProgram<FS: ShimFS> {
    pub entrypoints: MacosShimEntrypoints<FS>,
    pub process: MacosShimProcess,
}

pub struct MacosShimProcess {
    exit_code: Arc<core::sync::atomic::AtomicI32>,
}

impl MacosShimProcess {
    pub fn wait(&self) -> i32 {
        self.exit_code.load(core::sync::atomic::Ordering::Acquire)
    }
}

impl<FS: ShimFS> MacosShim<FS> {
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.0.pm
    }

    pub fn load_program(
        &self,
        path: &str,
        program_bytes: &[u8],
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<FS>, loader::MachoLoaderError> {
        let exit_code = Arc::new(core::sync::atomic::AtomicI32::new(0));
        let entrypoints = MacosShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.0.clone(),
                terminated: core::cell::Cell::new(false),
                exit_code: exit_code.clone(),
            },
        };

        // Initialize stdio
        entrypoints.task.initialize_stdio();

        // Load the Mach-O program
        let load_info = loader::load_macho(
            &entrypoints.task,
            program_bytes,
            argv,
            envp,
        )?;

        // Set up PtRegs with entry point and stack pointer — the caller
        // passes these to `run_thread` which restores them into `switch_to_guest`.
        // The caller must set ctx.pc and ctx.regs[0..3] / ctx.sp from load_info.
        // We return load_info inside the entrypoints for the caller to use.

        let process = MacosShimProcess { exit_code };
        Ok(LoadedProgram {
            entrypoints,
            process,
        })
    }
}

struct GlobalState<FS: ShimFS> {
    platform: &'static Platform,
    litebox: litebox::LiteBox<Platform>,
    pm: litebox::mm::PageManager<Platform, { PAGE_SIZE }>,
    fs: FS,
    futex_manager: FutexManager<Platform>,
    pipes: Pipes<Platform>,
    net: litebox::sync::Mutex<Platform, Network<Platform>>,
    boot_time: <Platform as TimeProvider>::Instant,
}

struct Task<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    terminated: core::cell::Cell<bool>,
    exit_code: Arc<core::sync::atomic::AtomicI32>,
}

impl<FS: ShimFS> Task<FS> {
    fn should_terminate(&self) -> bool {
        self.terminated.get()
    }

    fn handle_init_request(&self, ctx: &mut PtRegs) {
        // Nothing to do on init for phase 1 — the loader has already set
        // the entry point and stack via PtRegs.
        let _ = ctx;
    }

    fn handle_syscall_request(&self, ctx: &mut PtRegs) {
        self.do_syscall(ctx);
    }

    fn initialize_stdio(&self) {
        use litebox::fs::{FileSystem as _, Mode, OFlags};

        let _stdin = self.global.fs.open(
            "/dev/stdin", OFlags::RDONLY, Mode::empty()
        );
        let _stdout = self.global.fs.open(
            "/dev/stdout", OFlags::WRONLY, Mode::empty()
        );
        let _stderr = self.global.fs.open(
            "/dev/stderr", OFlags::WRONLY, Mode::empty()
        );
        // Phase 1: FDs 0,1,2 are opened by the filesystem layer.
        // Descriptor tracking is simplified — we rely on litebox's
        // descriptor table which auto-assigns fd 0, 1, 2.
    }
}
```

- [ ] **Step 2: Write `litebox_shim_macos/src/syscalls/mod.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! BSD syscall dispatch for the macOS shim.

pub(crate) mod file;
pub(crate) mod mm;
pub(crate) mod process;

use litebox_common_macos::errno::Errno;
use litebox_common_macos::syscall::{self, MacosSyscallRequest, set_syscall_return};
use litebox_common_macos::PtRegs;

use crate::{ShimFS, Task};

impl<FS: ShimFS> Task<FS> {
    pub(crate) fn do_syscall(&self, ctx: &mut PtRegs) {
        let request = MacosSyscallRequest::try_from_raw(ctx);

        let result = match request {
            MacosSyscallRequest::Exit { status } => {
                self.sys_exit(status);
                // sys_exit sets terminated; return value doesn't matter.
                return;
            }
            MacosSyscallRequest::Write { fd, buf, count } => {
                match buf.to_owned_slice(count) {
                    Some(buf) => self.sys_write(fd, &buf),
                    None => Err(Errno::EFAULT),
                }
            }
            MacosSyscallRequest::Read { fd, buf, count } => {
                self.sys_read_to_user(fd, buf, count)
            }
            MacosSyscallRequest::Close { fd } => {
                self.sys_close(fd).map(|()| 0)
            }
            MacosSyscallRequest::Getpid => Ok(self.sys_getpid() as usize),
            MacosSyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            MacosSyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            MacosSyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            MacosSyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            MacosSyscallRequest::Issetugid => Ok(0), // not setuid/setgid
            MacosSyscallRequest::Mmap {
                addr, length, prot, flags, fd, offset,
            } => {
                self.sys_mmap(addr, length, prot, flags, fd, offset)
                    .map(|ptr| ptr.as_usize())
            }
            MacosSyscallRequest::Munmap { addr, length } => {
                self.sys_munmap(addr, length).map(|()| 0)
            }
            MacosSyscallRequest::Mprotect { addr, length, prot } => {
                self.sys_mprotect(addr, length, prot).map(|()| 0)
            }
            MacosSyscallRequest::Unknown { number } => {
                // Return ENOSYS for unknown syscalls.
                let _ = number;
                Err(Errno::ENOSYS)
            }
        };

        set_syscall_return(ctx, result);
    }
}
```

- [ ] **Step 3: Write `litebox_shim_macos/src/syscalls/process.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process-related syscalls.

use crate::{ShimFS, Task};

impl<FS: ShimFS> Task<FS> {
    pub(crate) fn sys_exit(&self, status: i32) {
        self.exit_code
            .store(status, core::sync::atomic::Ordering::Release);
        self.terminated.set(true);
    }

    pub(crate) fn sys_getpid(&self) -> i32 {
        1 // Phase 1: always PID 1
    }

    pub(crate) fn sys_getuid(&self) -> u32 {
        0
    }

    pub(crate) fn sys_geteuid(&self) -> u32 {
        0
    }

    pub(crate) fn sys_getgid(&self) -> u32 {
        0
    }

    pub(crate) fn sys_getegid(&self) -> u32 {
        0
    }
}
```

- [ ] **Step 4: Write `litebox_shim_macos/src/syscalls/file.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File-related syscalls.

use alloc::vec;
use litebox::fs::FileSystem as _;
use litebox::platform::RawMutPointer as _;
use litebox_common_macos::errno::Errno;

use crate::{MutPtr, ShimFS, Task};

/// Maximum size of a kernel buffer for read/write operations.
const MAX_KERNEL_BUF_SIZE: usize = 64 * 1024;

impl<FS: ShimFS> Task<FS> {
    pub(crate) fn sys_write(&self, fd: i32, buf: &[u8]) -> Result<usize, Errno> {
        let typed_fd = self.global.litebox.descriptor_table()
            .get_fd(fd as u32)
            .ok_or(Errno::EBADF)?;
        self.global.fs.write(&typed_fd, buf, None)
            .map_err(|_| Errno::EIO)
    }

    pub(crate) fn sys_read_to_user(
        &self,
        fd: i32,
        buf: MutPtr<u8>,
        count: usize,
    ) -> Result<usize, Errno> {
        let typed_fd = self.global.litebox.descriptor_table()
            .get_fd(fd as u32)
            .ok_or(Errno::EBADF)?;
        let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
        let size = self.global.fs.read(&typed_fd, &mut kernel_buf, None)
            .map_err(|_| Errno::EIO)?;
        buf.copy_from_slice(0, &kernel_buf[..size])
            .ok_or(Errno::EFAULT)?;
        Ok(size)
    }

    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        let typed_fd = self.global.litebox.descriptor_table()
            .get_fd(fd as u32)
            .ok_or(Errno::EBADF)?;
        self.global.fs.close(&typed_fd)
            .map_err(|_| Errno::EIO)
    }
}
```

- [ ] **Step 5: Write `litebox_shim_macos/src/syscalls/mm.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management syscalls.

use litebox::mm::linux::PAGE_SIZE;
use litebox_common_macos::errno::Errno;

use crate::{MutPtr, ShimFS, Task};

impl<FS: ShimFS> Task<FS> {
    pub(crate) fn sys_mmap(
        &self,
        addr: usize,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> Result<MutPtr<u8>, Errno> {
        // Convert macOS mmap flags to litebox-compatible flags.
        // macOS MAP_ANON = 0x1000, MAP_PRIVATE = 0x0002, MAP_FIXED = 0x0010
        // litebox_common_linux MapFlags are Linux-compatible.
        // For phase 1, we translate the common flags.
        let linux_prot = litebox_common_linux::ProtFlags::from_bits_truncate(prot as u32);

        let mut linux_flags = litebox_common_linux::MapFlags::empty();
        if flags & 0x0002 != 0 { linux_flags |= litebox_common_linux::MapFlags::MAP_PRIVATE; }
        if flags & 0x0001 != 0 { linux_flags |= litebox_common_linux::MapFlags::MAP_SHARED; }
        if flags & 0x0010 != 0 { linux_flags |= litebox_common_linux::MapFlags::MAP_FIXED; }
        if flags & 0x1000 != 0 { linux_flags |= litebox_common_linux::MapFlags::MAP_ANONYMOUS; }

        let result = unsafe {
            self.global.pm.mmap(
                addr,
                length,
                linux_prot,
                linux_flags,
                if fd < 0 { None } else {
                    self.global.litebox.descriptor_table()
                        .get_fd(fd as u32)
                },
                offset as u64,
            )
        };
        result.map_err(|_| Errno::ENOMEM)
    }

    pub(crate) fn sys_munmap(
        &self,
        addr: usize,
        length: usize,
    ) -> Result<(), Errno> {
        unsafe {
            self.global.pm.munmap(addr, length)
        }.map_err(|_| Errno::EINVAL)
    }

    pub(crate) fn sys_mprotect(
        &self,
        addr: usize,
        length: usize,
        prot: i32,
    ) -> Result<(), Errno> {
        let linux_prot = litebox_common_linux::ProtFlags::from_bits_truncate(prot as u32);
        unsafe {
            self.global.pm.mprotect(addr, length, linux_prot)
        }.map_err(|_| Errno::ENOMEM)
    }
}
```

- [ ] **Step 6: Update `litebox_shim_macos/Cargo.toml` to add litebox_common_linux dependency**

The `mm.rs` file uses `litebox_common_linux::ProtFlags` and `litebox_common_linux::MapFlags`. Verify that `litebox_common_linux` is already in the Cargo.toml (it is from Task 1).

- [ ] **Step 7: Verify compilation**

Run: `cargo check -p litebox_shim_macos`

Expected: compiles (the `loader` module is still a stub `mod.rs` from Task 1; it will be fleshed out in Task 7). Create `litebox_shim_macos/src/loader/` directory structure if needed:

Create `litebox_shim_macos/src/loader.rs` as a temporary placeholder:
```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach-O loader for the macOS shim.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MachoLoaderError {
    #[error("failed to parse Mach-O")]
    ParseError(String),
    #[error("invalid stack")]
    InvalidStackAddr,
    #[error("failed to mmap")]
    MappingError(String),
}

/// Load info returned by the Mach-O loader.
pub struct MachoLoadInfo {
    pub entry_point: usize,
    pub user_stack_top: usize,
    /// True if the binary uses LC_MAIN (call as function with args in x0-x3).
    /// False for LC_UNIXTHREAD (raw jump, args on stack).
    pub is_lc_main: bool,
}

pub(crate) fn load_macho<FS: crate::ShimFS>(
    _task: &crate::Task<FS>,
    _program_bytes: &[u8],
    _argv: alloc::vec::Vec<alloc::ffi::CString>,
    _envp: alloc::vec::Vec<alloc::ffi::CString>,
) -> Result<MachoLoadInfo, MachoLoaderError> {
    todo!("Mach-O loader not yet implemented")
}
```

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat(shim_macos): add MacosShimBuilder, MacosShimEntrypoints, Task, and do_syscall dispatch"
```

---

## Task 7: Mach-O loader — segment mapping, LC_MAIN entry, stack setup

Implement the Mach-O loader that maps `LC_SEGMENT_64` segments into litebox-managed memory, finds the entry point via `LC_MAIN`, and sets up the macOS-style user stack (`argc, argv, envp, apple[]`).

**Files:**
- Replace: `litebox_shim_macos/src/loader.rs` (replace the stub with a module directory)
- Create: `litebox_shim_macos/src/loader/mod.rs`
- Create: `litebox_shim_macos/src/loader/macho.rs`
- Create: `litebox_shim_macos/src/loader/stack.rs`
- Modify: `litebox_shim_macos/Cargo.toml` — add `object` dependency

- [ ] **Step 1: Add `object` dependency to `litebox_shim_macos/Cargo.toml`**

Add to `[dependencies]`:
```toml
object = { version = "0.36.7", default-features = false, features = ["macho", "read", "std"] }
```

- [ ] **Step 2: Create `litebox_shim_macos/src/loader/mod.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach-O loader for the macOS shim.

pub(crate) mod macho;
pub(crate) mod stack;

use thiserror::Error;

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// Default low address, above the 4GB `__PAGEZERO` segment.
pub(crate) const DEFAULT_LOW_ADDR: usize = 0x1_0000_0000;

#[derive(Error, Debug)]
pub enum MachoLoaderError {
    #[error("failed to parse Mach-O: {0}")]
    ParseError(String),
    #[error("unsupported Mach-O format")]
    UnsupportedFormat,
    #[error("no entry point found (need LC_MAIN or LC_UNIXTHREAD)")]
    NoEntryPoint,
    #[error("no __TEXT segment found")]
    NoTextSegment,
    #[error("invalid stack")]
    InvalidStackAddr,
    #[error("failed to mmap: {0}")]
    MappingError(String),
    #[error("memory error: {0}")]
    MemoryError(String),
}

/// Load info returned by the Mach-O loader.
pub struct MachoLoadInfo {
    /// The program entry point virtual address.
    pub entry_point: usize,
    /// The initial stack pointer (top of initialized stack).
    pub user_stack_top: usize,
    /// True if the binary uses LC_MAIN (entry is called as a function with
    /// argc in x0, argv in x1, envp in x2, apple in x3).
    /// False for LC_UNIXTHREAD (raw jump, argc at sp, argv at sp+8, etc).
    pub is_lc_main: bool,
}

/// Load a rewritten Mach-O binary and prepare it for execution.
///
/// This function:
/// 1. Parses the Mach-O header and load commands
/// 2. Maps each LC_SEGMENT_64 into litebox-managed memory
/// 3. Finds the entry point (LC_MAIN or LC_UNIXTHREAD)
/// 4. Sets up the user stack with argc, argv, envp, apple[]
///
/// Returns load info that the caller uses to set up PtRegs.
pub(crate) fn load_macho<FS: crate::ShimFS>(
    task: &crate::Task<FS>,
    program_bytes: &[u8],
    argv: alloc::vec::Vec<alloc::ffi::CString>,
    envp: alloc::vec::Vec<alloc::ffi::CString>,
) -> Result<MachoLoadInfo, MachoLoaderError> {
    macho::load(task, program_bytes, argv, envp)
}
```

- [ ] **Step 3: Create `litebox_shim_macos/src/loader/stack.rs`**

This is the macOS-style user stack. The layout is similar to Linux but with `apple[]` instead of `auxv`:

```
position            content                     size (bytes)
------------------------------------------------------------------------
stack pointer ->  [ argc = number of args ]     8
                  [ argv[0] (pointer) ]         8   (program name)
                  [ argv[..] (pointer) ]        8 * x
                  [ argv[n] (pointer) ]         8   (= NULL)

                  [ envp[0] (pointer) ]         8
                  [ envp[..] (pointer) ]        8 * y
                  [ envp[term] (pointer) ]      8   (= NULL)

                  [ apple[0] (pointer) ]        8
                  [ apple[term] (pointer) ]     8   (= NULL)

                  [ padding ]                   0 - 16

                  [ argument ASCIIZ strings ]   >= 0
                  [ environment ASCIIZ str. ]   >= 0
                  [ apple ASCIIZ strings ]      >= 0

                  [ end marker ]                8   (= NULL)

                  < bottom of stack >           0   (virtual)
------------------------------------------------------------------------
```

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-style user stack setup.

use alloc::ffi::CString;
use alloc::vec::Vec;
use litebox::platform::RawMutPointer;

use crate::MutPtr;

/// The stack for the macOS guest process.
pub(super) struct UserStack {
    stack_top: MutPtr<u8>,
    #[expect(dead_code)]
    len: usize,
    pos: usize,
}

impl UserStack {
    const STACK_ALIGNMENT: usize = 16;

    pub(super) fn new(stack_top: MutPtr<u8>, len: usize) -> Option<Self> {
        if stack_top.as_usize() % Self::STACK_ALIGNMENT != 0 {
            return None;
        }
        if !len.is_multiple_of(Self::STACK_ALIGNMENT) {
            return None;
        }
        Some(Self {
            stack_top,
            len,
            pos: len,
        })
    }

    pub(super) fn get_cur_stack_top(&self) -> usize {
        self.stack_top.as_usize() + self.pos
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> Option<()> {
        self.pos = self.pos.checked_sub(bytes.len())?;
        self.stack_top.copy_from_slice(self.pos, bytes)?;
        Some(())
    }

    fn push_usize(&mut self, val: usize) -> Option<()> {
        self.push_bytes(&val.to_le_bytes())
    }

    fn push_cstring(&mut self, val: &CString) -> Option<()> {
        let bytes = val.as_bytes_with_nul();
        self.push_bytes(bytes)
    }

    fn push_cstrings(&mut self, vals: &[CString]) -> Option<Vec<usize>> {
        let mut offsets = Vec::with_capacity(vals.len());
        for val in vals {
            self.push_cstring(val)?;
            offsets.push(self.pos);
        }
        Some(offsets)
    }

    fn push_pointers(&mut self, offsets: Vec<usize>) -> Option<()> {
        // Write end marker (NULL)
        self.push_usize(0)?;
        let size = offsets.len().checked_mul(size_of::<usize>())?;
        self.pos = self.pos.checked_sub(size)?;
        let ptr: MutPtr<usize> = MutPtr::from_usize(self.stack_top.as_usize() + self.pos);
        for (i, p) in offsets.iter().enumerate() {
            let addr: usize = self.stack_top.as_usize() + *p;
            ptr.write_at_offset(i as isize, addr)?;
        }
        Some(())
    }

    /// Initialize the macOS-style stack.
    ///
    /// Layout: argc, argv ptrs, NULL, envp ptrs, NULL, apple ptrs, NULL,
    /// then string data below.
    pub(super) fn init(
        &mut self,
        argv: Vec<CString>,
        env: Vec<CString>,
    ) -> Option<()> {
        // End marker at bottom of stack
        self.pos = self.pos.checked_sub(size_of::<usize>())?;
        self.stack_top.write_at_offset(
            isize::try_from(self.pos).ok()?,
            0usize,
        )?;

        // Push string data: env strings, then argv strings
        // (push in reverse order since stack grows downward)
        let envp_offsets = self.push_cstrings(&env)?;
        let argvp_offsets = self.push_cstrings(&argv)?;

        // apple[] is empty for phase 1 (just the NULL terminator)
        let apple_offsets: Vec<usize> = Vec::new();

        // Ensure stack is aligned
        let align_down = |pos: usize, alignment: usize| -> usize {
            pos & !(alignment - 1)
        };
        self.pos = align_down(self.pos, size_of::<usize>());

        // Calculate total items to push and ensure final alignment
        let len = /* apple */ (apple_offsets.len() + 1)
            + /* envp */ (envp_offsets.len() + 1)
            + /* argvp */ (argvp_offsets.len() + 1)
            + /* argc */ 1;
        let size = len * size_of::<usize>();
        let final_pos = self.pos.checked_sub(size)?;
        self.pos -= final_pos - align_down(final_pos, Self::STACK_ALIGNMENT);

        // Push apple[] (empty array with NULL terminator)
        self.push_pointers(apple_offsets)?;
        // Push envp
        self.push_pointers(envp_offsets)?;
        // Push argv
        self.push_pointers(argvp_offsets)?;
        // Push argc
        self.push_usize(argv.len())?;

        assert_eq!(self.pos, align_down(self.pos, Self::STACK_ALIGNMENT));
        Some(())
    }
}
```

- [ ] **Step 4: Create `litebox_shim_macos/src/loader/macho.rs`**

The core Mach-O loading logic:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach-O binary loader.

use alloc::ffi::CString;
use alloc::vec::Vec;
use litebox::mm::linux::{CreatePagesFlags, PAGE_SIZE};
use litebox::platform::RawMutPointer as _;
use object::macho;
use object::read::macho::MachHeader;
use object::Endianness;

use super::stack::UserStack;
use super::{MachoLoadInfo, MachoLoaderError, DEFAULT_LOW_ADDR, DEFAULT_STACK_SIZE};
use crate::{MutPtr, ShimFS, Task};

/// Parsed info about a segment to map.
struct SegmentInfo {
    /// Virtual address of the segment.
    vmaddr: u64,
    /// Virtual memory size.
    vmsize: u64,
    /// File offset.
    fileoff: u64,
    /// File size.
    filesize: u64,
    /// Max protection.
    maxprot: u32,
    /// Initial protection.
    initprot: u32,
    /// Segment name (first 16 bytes).
    segname: [u8; 16],
}

/// Load a Mach-O binary into litebox-managed memory.
pub(crate) fn load<FS: ShimFS>(
    task: &Task<FS>,
    data: &[u8],
    argv: Vec<CString>,
    envp: Vec<CString>,
) -> Result<MachoLoadInfo, MachoLoaderError> {
    // Parse header
    let header = macho::MachHeader64::<Endianness>::parse(data, 0)
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("invalid header: {e}")))?;
    let endian = header.endian()
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("endianness: {e}")))?;

    // Validate
    if header.cputype(endian) != macho::CPU_TYPE_ARM64 {
        return Err(MachoLoaderError::UnsupportedFormat);
    }
    if header.filetype(endian) != macho::MH_EXECUTE {
        return Err(MachoLoaderError::UnsupportedFormat);
    }

    // Collect segments and find entry point
    let mut segments = Vec::new();
    let mut entry_offset: Option<u64> = None;
    let mut is_lc_main = false;
    let mut text_vmaddr: Option<u64> = None;

    let mut commands = header.load_commands(endian, data, 0)
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("load commands: {e}")))?;

    while let Some(cmd) = commands.next()
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("iterate commands: {e}")))? {

        match cmd.cmd() {
            macho::LC_SEGMENT_64 => {
                if let Some((seg, _sections)) = cmd.segment_64()
                    .map_err(|e| MachoLoaderError::ParseError(alloc::format!("segment: {e}")))? {
                    let name = seg.name();
                    // Skip __PAGEZERO (first 4GB, no actual data)
                    if name == *b"__PAGEZERO\0\0\0\0\0\0" {
                        continue;
                    }
                    if name.starts_with(b"__TEXT") {
                        text_vmaddr = Some(seg.vmaddr(endian));
                    }
                    segments.push(SegmentInfo {
                        vmaddr: seg.vmaddr(endian),
                        vmsize: seg.vmsize(endian),
                        fileoff: seg.fileoff(endian),
                        filesize: seg.filesize(endian),
                        maxprot: seg.maxprot(endian) as u32,
                        initprot: seg.initprot(endian) as u32,
                        segname: name,
                    });
                }
            }
            macho::LC_MAIN => {
                // LC_MAIN: entryoff is offset from start of __TEXT segment
                let cmd_data = cmd.data();
                if cmd_data.len() >= 16 {
                    entry_offset = Some(u64::from_le_bytes(
                        cmd_data[8..16].try_into().unwrap()
                    ));
                    is_lc_main = true;
                }
            }
            macho::LC_UNIXTHREAD => {
                // LC_UNIXTHREAD: raw thread state with PC in x[32] (entry point)
                // Format: flavor(4) + count(4) + registers
                // ARM_THREAD_STATE64: flavor=6, count=68 (words)
                // x0-x28, fp(x29), lr(x30), sp, pc, cpsr, pad
                let cmd_data = cmd.data();
                if cmd_data.len() >= 8 + 4 + 4 + 33 * 8 {
                    // Skip cmd(4) + cmdsize(4) + flavor(4) + count(4) = 16 bytes header
                    // Then 32 registers (x0-x31 = sp) before pc at index 32
                    let pc_offset = 16 + 32 * 8; // offset to pc register
                    if cmd_data.len() >= pc_offset + 8 {
                        let pc = u64::from_le_bytes(
                            cmd_data[pc_offset..pc_offset + 8].try_into().unwrap()
                        );
                        entry_offset = Some(pc);
                        is_lc_main = false;
                        // For LC_UNIXTHREAD, entry_offset is the absolute PC
                    }
                }
            }
            _ => {
                // Ignore other load commands (LC_DYLD_INFO, LC_SYMTAB, etc.)
            }
        }
    }

    if segments.is_empty() {
        return Err(MachoLoaderError::NoTextSegment);
    }

    // Map segments
    for seg in &segments {
        if seg.vmsize == 0 {
            continue;
        }

        // Allocate pages for the segment
        let vm_addr = seg.vmaddr as usize;
        let vm_size = ((seg.vmsize as usize) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // Map as RW initially to write data, then mprotect to final perms
        let prot = litebox_common_linux::ProtFlags::PROT_READ
            | litebox_common_linux::ProtFlags::PROT_WRITE;
        let flags = litebox_common_linux::MapFlags::MAP_ANONYMOUS
            | litebox_common_linux::MapFlags::MAP_PRIVATE
            | litebox_common_linux::MapFlags::MAP_FIXED;

        let ptr = unsafe {
            task.global.pm.mmap(
                vm_addr,
                vm_size,
                prot,
                flags,
                None::<litebox::fd::TypedFd<FS>>,
                0,
            )
        }.map_err(|e| MachoLoaderError::MappingError(alloc::format!(
            "mmap segment at {vm_addr:#x} size {vm_size:#x}: {e:?}"
        )))?;

        // Copy segment data from file
        let file_size = seg.filesize as usize;
        if file_size > 0 {
            let file_off = seg.fileoff as usize;
            if file_off + file_size > data.len() {
                return Err(MachoLoaderError::ParseError(alloc::format!(
                    "segment data at offset {file_off:#x} size {file_size:#x} exceeds file"
                )));
            }
            let dest: MutPtr<u8> = MutPtr::from_usize(vm_addr);
            dest.copy_from_slice(0, &data[file_off..file_off + file_size])
                .ok_or(MachoLoaderError::MemoryError(
                    "failed to copy segment data".into()
                ))?;
        }

        // Set final protection
        let final_prot = prot_from_macho(seg.initprot);
        if final_prot != prot {
            unsafe {
                task.global.pm.mprotect(vm_addr, vm_size, final_prot)
            }.map_err(|e| MachoLoaderError::MappingError(alloc::format!(
                "mprotect segment at {vm_addr:#x}: {e:?}"
            )))?;
        }
    }

    // Compute entry point
    let entry_point = if is_lc_main {
        let text_base = text_vmaddr.ok_or(MachoLoaderError::NoTextSegment)?;
        let offset = entry_offset.ok_or(MachoLoaderError::NoEntryPoint)?;
        (text_base + offset) as usize
    } else {
        // LC_UNIXTHREAD: entry_offset is the absolute PC
        entry_offset.ok_or(MachoLoaderError::NoEntryPoint)? as usize
    };

    // Set brk after highest mapped segment
    let max_end = segments.iter()
        .map(|s| (s.vmaddr + s.vmsize) as usize)
        .max()
        .unwrap_or(DEFAULT_LOW_ADDR);
    let brk = max_end.next_multiple_of(PAGE_SIZE);
    task.global.pm.set_initial_brk(brk);

    // Allocate stack
    let sp = unsafe {
        let length = litebox::mm::linux::NonZeroPageSize::new(DEFAULT_STACK_SIZE)
            .expect("DEFAULT_STACK_SIZE is not page-aligned");
        task.global.pm
            .create_stack_pages(None, length, CreatePagesFlags::empty())
            .map_err(|e| MachoLoaderError::MappingError(alloc::format!(
                "stack allocation: {e:?}"
            )))?
    };
    let mut stack = UserStack::new(sp, DEFAULT_STACK_SIZE)
        .ok_or(MachoLoaderError::InvalidStackAddr)?;
    stack.init(argv, envp)
        .ok_or(MachoLoaderError::InvalidStackAddr)?;

    Ok(MachoLoadInfo {
        entry_point,
        user_stack_top: stack.get_cur_stack_top(),
        is_lc_main,
    })
}

/// Convert macOS VM_PROT_* flags to litebox ProtFlags.
fn prot_from_macho(prot: u32) -> litebox_common_linux::ProtFlags {
    let mut flags = litebox_common_linux::ProtFlags::empty();
    if prot & 1 != 0 { flags |= litebox_common_linux::ProtFlags::PROT_READ; }
    if prot & 2 != 0 { flags |= litebox_common_linux::ProtFlags::PROT_WRITE; }
    if prot & 4 != 0 { flags |= litebox_common_linux::ProtFlags::PROT_EXEC; }
    flags
}
```

- [ ] **Step 5: Delete the stub `litebox_shim_macos/src/loader.rs` file**

Replace the file with the directory module created in Step 2. (The stub from Task 6 was a single file; now it becomes `loader/mod.rs`.)

- [ ] **Step 6: Update `litebox_shim_macos/src/lib.rs` loader import**

The `pub mod loader;` declaration in `lib.rs` should now resolve to `loader/mod.rs`. Update the `load_program` method to use `MachoLoadInfo` and set up the initial `PtRegs`:

In `lib.rs`, change `load_program` to:

```rust
    pub fn load_program(
        &self,
        program_bytes: &[u8],
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<FS>, loader::MachoLoaderError> {
        let exit_code = Arc::new(core::sync::atomic::AtomicI32::new(0));
        let entrypoints = MacosShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.0.clone(),
                terminated: core::cell::Cell::new(false),
                exit_code: exit_code.clone(),
            },
        };

        entrypoints.task.initialize_stdio();

        let load_info = loader::load_macho(
            &entrypoints.task,
            program_bytes,
            argv.clone(),
            envp,
        )?;

        // Pre-populate PtRegs for the initial entry.
        // The caller will pass &mut PtRegs to run_thread; set PC and SP here.
        let mut initial_ctx = PtRegs::default();
        initial_ctx.pc = load_info.entry_point;
        initial_ctx.sp = load_info.user_stack_top;

        if load_info.is_lc_main {
            // LC_MAIN: entry called as main(argc, argv, envp, apple)
            // argc in x0, argv in x1, envp in x2, apple in x3
            initial_ctx.regs[0] = argv.len();
            // argv pointer = sp + 8 (after argc on the stack)
            initial_ctx.regs[1] = load_info.user_stack_top + 8;
            // envp pointer = sp + 8 + (argc + 1) * 8
            initial_ctx.regs[2] = load_info.user_stack_top + 8 + (argv.len() + 1) * 8;
            // apple pointer = envp_end (after NULL terminator)
            // For phase 1, apple is empty — just past envp NULL
            // We compute: envp_start + (envp_count + 1) * 8
            // But we don't have envp_count here anymore. Instead, we can
            // compute from the stack layout. For simplicity, set x3 = 0
            // (NULL — programs handle NULL apple gracefully).
            initial_ctx.regs[3] = 0;
        }
        // For LC_UNIXTHREAD: argc/argv/envp are on the stack, no register args.
        // The stack is already set up with argc at sp.

        let process = MacosShimProcess { exit_code };
        Ok(LoadedProgram {
            entrypoints,
            process,
            initial_ctx,
        })
    }
```

Update the `LoadedProgram` struct to include `initial_ctx`:

```rust
pub struct LoadedProgram<FS: ShimFS> {
    pub entrypoints: MacosShimEntrypoints<FS>,
    pub process: MacosShimProcess,
    pub initial_ctx: PtRegs,
}
```

- [ ] **Step 7: Verify compilation**

Run: `cargo check -p litebox_shim_macos`

Expected: compiles.

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat(shim_macos): implement Mach-O loader with segment mapping, LC_MAIN entry, and stack setup"
```

---

## Task 8: Runner crate — `litebox_runner_macos_on_macos_userland`

Implement the runner crate that orchestrates: read Mach-O from disk, rewrite syscalls, build shim, load program, run thread, return exit code.

**Files:**
- Modify: `litebox_runner_macos_on_macos_userland/src/lib.rs`
- Modify: `litebox_runner_macos_on_macos_userland/Cargo.toml`

- [ ] **Step 1: Update `Cargo.toml` to add `[[bin]]` section**

Add a binary target so the crate can be run as a CLI:

```toml
[[bin]]
name = "litebox_runner_macos_on_macos_userland"
path = "src/main.rs"
```

- [ ] **Step 2: Create `litebox_runner_macos_on_macos_userland/src/main.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn main() {
    let cli_args = <litebox_runner_macos_on_macos_userland::CliArgs as clap::Parser>::parse();
    if let Err(e) = litebox_runner_macos_on_macos_userland::run(cli_args) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
```

- [ ] **Step 3: Write `litebox_runner_macos_on_macos_userland/src/lib.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox::fs::{FileSystem as _, Mode};
use litebox_platform_multiplex::Platform;
use memmap2::Mmap;
use std::path::Path;

extern crate alloc;

/// Run macOS Mach-O programs with LiteBox on Apple Silicon
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs)
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Apply Mach-O syscall rewriter before running
    #[arg(long = "rewrite-syscalls", default_value = "true")]
    pub rewrite_syscalls: bool,
}

/// Run macOS Mach-O programs with LiteBox on Apple Silicon.
pub fn run(cli_args: CliArgs) -> Result<()> {
    let prog_path = Path::new(&cli_args.program_and_arguments[0]);
    let file = std::fs::File::open(prog_path)?;
    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| anyhow!("Could not mmap {}: {}", prog_path.display(), e))?;
    let prog_data: &[u8] = &mmap;

    // Rewrite syscalls if requested
    let rewritten: Vec<u8>;
    let binary_data: &[u8] = if cli_args.rewrite_syscalls {
        rewritten = litebox_syscall_rewriter_macho::hook_syscalls_in_macho(prog_data)
            .map_err(|e| anyhow!("Mach-O rewriter failed: {e}"))?;
        &rewritten
    } else {
        prog_data
    };

    // Initialize platform
    let platform = Platform::new(None);
    litebox_platform_multiplex::set_platform(platform);

    // Build shim
    let mut shim_builder = litebox_shim_macos::MacosShimBuilder::<litebox_shim_macos::DefaultFS>::new();
    let litebox = shim_builder.litebox();
    let in_mem_fs = {
        let mut fs = litebox::fs::in_mem::FileSystem::new(litebox);
        fs.with_root_privileges(|fs| {
            let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
            let _ = fs.mkdir("/tmp", mode);
        });
        fs
    };
    let tar_ro_fs = litebox::fs::tar_ro::FileSystem::new(
        litebox,
        litebox::fs::tar_ro::EMPTY_TAR_FILE.into(),
    );
    let fs = shim_builder.default_fs(in_mem_fs, tar_ro_fs);
    shim_builder.set_fs(fs);
    let shim = shim_builder.build();

    // Load program
    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();

    let program = shim
        .load_program(binary_data, argv, envp)
        .map_err(|e| anyhow!("Failed to load Mach-O: {e}"))?;

    // Run thread
    unsafe {
        litebox_platform_macos_userland::run_thread(
            program.entrypoints,
            &mut program.initial_ctx.clone(),
        );
    }

    std::process::exit(program.process.wait())
}
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p litebox_runner_macos_on_macos_userland`

Expected: compiles.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(runner_macos): implement macOS Mach-O runner CLI with rewrite, load, and run pipeline"
```

---

## Task 9: Nolibc assembly hello world test

Write a minimal aarch64 assembly test that does `write(1, "hello\n", 6)` + `exit(0)` via `svc #0x80`. This is the first end-to-end test: assemble → rewrite → load → dispatch → exit.

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/loader.rs`
- Create: `litebox_runner_macos_on_macos_userland/tests/common/mod.rs`

- [ ] **Step 1: Create `litebox_runner_macos_on_macos_userland/tests/common/mod.rs`**

Test helpers for compiling Mach-O binaries and running them:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::{Path, PathBuf};

/// Assemble and link an aarch64 Mach-O binary from assembly source.
///
/// Uses Xcode `as` and `ld` to produce a static MH_EXECUTE with LC_UNIXTHREAD
/// (no dyld, no libc).
pub fn assemble_macho(asm_source: &str, name: &str) -> PathBuf {
    let dir = std::env::var("OUT_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().to_str().unwrap().to_string());
    let dir = Path::new(&dir);

    let asm_path = dir.join(format!("{name}.s"));
    let obj_path = dir.join(format!("{name}.o"));
    let bin_path = dir.join(name);

    std::fs::write(&asm_path, asm_source).expect("write asm source");

    // Assemble
    let output = std::process::Command::new("as")
        .args([
            "-arch", "arm64",
            asm_path.to_str().unwrap(),
            "-o", obj_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run assembler");
    assert!(
        output.status.success(),
        "assembler failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Link with -static -e _start (LC_UNIXTHREAD entry)
    let output = std::process::Command::new("ld")
        .args([
            "-arch", "arm64",
            "-static",
            "-e", "_start",
            obj_path.to_str().unwrap(),
            "-o", bin_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run linker");
    assert!(
        output.status.success(),
        "linker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    bin_path
}

/// Compile a C file to a static Mach-O binary using clang (no libc).
pub fn compile_macho_nolibc(c_source: &str, name: &str) -> PathBuf {
    let dir = std::env::var("OUT_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().to_str().unwrap().to_string());
    let dir = Path::new(&dir);

    let src_path = dir.join(format!("{name}.c"));
    let bin_path = dir.join(name);

    std::fs::write(&src_path, c_source).expect("write C source");

    let output = std::process::Command::new("clang")
        .args([
            "-arch", "arm64",
            "-static",
            "-nostdlib",
            "-e", "__start",
            "-o", bin_path.to_str().unwrap(),
            src_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run clang");
    assert!(
        output.status.success(),
        "clang failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    bin_path
}

/// Rewrite a Mach-O binary using the Mach-O syscall rewriter.
pub fn rewrite_macho(input: &Path) -> Vec<u8> {
    let data = std::fs::read(input).expect("read binary");
    litebox_syscall_rewriter_macho::hook_syscalls_in_macho(&data)
        .expect("Mach-O rewriter failed")
}

/// Run a rewritten Mach-O binary through litebox, capturing stdout and exit code.
pub fn run_macho_binary(binary_data: &[u8], argv: &[&str]) -> (i32, Vec<u8>) {
    use litebox::fs::{FileSystem as _, Mode};

    let platform =
        litebox_platform_macos_userland::Platform::new(None);
    litebox_platform_multiplex::set_platform(platform);

    let mut shim_builder =
        litebox_shim_macos::MacosShimBuilder::<litebox_shim_macos::DefaultFS>::new();
    let litebox = shim_builder.litebox();

    // Create a pipe to capture stdout
    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem_fs.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        let _ = fs.mkdir("/tmp", mode);
    });
    let tar_ro_fs = litebox::fs::tar_ro::FileSystem::new(
        litebox,
        litebox::fs::tar_ro::EMPTY_TAR_FILE.into(),
    );
    let fs = shim_builder.default_fs(in_mem_fs, tar_ro_fs);
    shim_builder.set_fs(fs);
    let shim = shim_builder.build();

    let argv_cstrings: Vec<std::ffi::CString> = argv
        .iter()
        .map(|s| std::ffi::CString::new(*s).unwrap())
        .collect();
    let envp = vec![std::ffi::CString::new("PATH=/bin").unwrap()];

    let program = shim
        .load_program(binary_data, argv_cstrings, envp)
        .expect("load_program failed");

    let mut ctx = program.initial_ctx.clone();
    unsafe {
        litebox_platform_macos_userland::run_thread(program.entrypoints, &mut ctx);
    }

    let exit_code = program.process.wait();
    // Phase 1: stdout is written to the host's fd 1 via the /dev/stdout
    // device. We can't easily capture it. Return empty for now.
    // The test verifies exit code; stdout capture is a future enhancement.
    (exit_code, Vec::new())
}
```

- [ ] **Step 2: Create `litebox_runner_macos_on_macos_userland/tests/loader.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

/// Minimal aarch64 Mach-O assembly: write(1, "hello\n", 6) + exit(0)
/// using BSD syscall ABI (syscall number in x16, svc #0x80).
const HELLO_NOLIBC_ASM: &str = r#"
.global _start
.align 4

_start:
    // write(1, msg, 6)
    mov x0, #1          // fd = stdout
    adrp x1, msg@PAGE
    add x1, x1, msg@PAGEOFF
    mov x2, #6          // count = 6
    mov x16, #4         // SYS_write = 4
    svc #0x80

    // exit(0)
    mov x0, #0          // status = 0
    mov x16, #1         // SYS_exit = 1
    svc #0x80

.data
msg:
    .asciz "hello\n"
"#;

#[test]
fn test_hello_nolibc_asm() {
    let bin_path = common::assemble_macho(HELLO_NOLIBC_ASM, "hello_nolibc_asm");
    let rewritten = common::rewrite_macho(&bin_path);
    let (exit_code, _stdout) = common::run_macho_binary(&rewritten, &["hello_nolibc_asm"]);
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}
```

- [ ] **Step 3: Verify the test compiles**

Run: `cargo test -p litebox_runner_macos_on_macos_userland --no-run`

Expected: compiles (test may not pass yet until all pieces work).

- [ ] **Step 4: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- test_hello_nolibc_asm --nocapture`

Expected: test passes, exit code 0. "hello\n" appears on stdout.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "test(runner_macos): add hello_nolibc_asm end-to-end test"
```

---

## Task 10: Nolibc C hello world test

Write a C test with raw BSD syscall wrappers (no libc), compiled to a static Mach-O via `clang -static -nostdlib`.

**Files:**
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

- [ ] **Step 1: Add the nolibc C source and test**

Append to `litebox_runner_macos_on_macos_userland/tests/loader.rs`:

```rust
/// Nolibc C program with raw BSD syscall wrappers.
const HELLO_NOLIBC_C: &str = r#"
// Compile: clang -arch arm64 -static -nostdlib -e __start -o hello hello.c

static int bsd_write(int fd, const void *buf, unsigned long count)
{
    register long x0 __asm__("x0") = fd;
    register const void *x1 __asm__("x1") = buf;
    register unsigned long x2 __asm__("x2") = count;
    register long x16 __asm__("x16") = 4; // SYS_write

    __asm__ volatile("svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x16)
        : "memory", "cc");

    return (int)x0;
}

_Noreturn static void bsd_exit(int status)
{
    register long x0 __asm__("x0") = status;
    register long x16 __asm__("x16") = 1; // SYS_exit

    for (;;) {
        __asm__ volatile("svc #0x80"
            :
            : "r"(x0), "r"(x16)
            : "memory", "cc");
    }
}

void _start(void)
{
    bsd_write(1, "Hello from C!\n", 14);
    bsd_exit(0);
}
"#;

#[test]
fn test_hello_nolibc_c() {
    let bin_path = common::compile_macho_nolibc(HELLO_NOLIBC_C, "hello_nolibc_c");
    let rewritten = common::rewrite_macho(&bin_path);
    let (exit_code, _stdout) = common::run_macho_binary(&rewritten, &["hello_nolibc_c"]);
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- test_hello_nolibc_c --nocapture`

Expected: test passes, exit code 0.

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "test(runner_macos): add hello_nolibc_c test with raw BSD syscall wrappers"
```

---

## Task 11: Non-zero exit code test

Add a test that verifies non-zero exit codes propagate correctly through the shim.

**Files:**
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

- [ ] **Step 1: Add the exit code test**

Append to `litebox_runner_macos_on_macos_userland/tests/loader.rs`:

```rust
/// Assembly that exits with code 42.
const EXIT_42_ASM: &str = r#"
.global _start
.align 4

_start:
    mov x0, #42         // status = 42
    mov x16, #1         // SYS_exit = 1
    svc #0x80
"#;

#[test]
fn test_exit_code_42() {
    let bin_path = common::assemble_macho(EXIT_42_ASM, "exit_42_asm");
    let rewritten = common::rewrite_macho(&bin_path);
    let (exit_code, _) = common::run_macho_binary(&rewritten, &["exit_42"]);
    assert_eq!(exit_code, 42, "expected exit code 42, got {exit_code}");
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- test_exit_code_42 --nocapture`

Expected: test passes, exit code 42.

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "test(runner_macos): add exit code propagation test"
```

---

## Task 12: Run all tests and verify

Final verification that all tests pass together and the existing Linux runner tests still pass.

**Files:**
- No new files

- [ ] **Step 1: Run all macOS runner tests**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`

Expected: all 3 tests pass:
- `test_hello_nolibc_asm`
- `test_hello_nolibc_c`
- `test_exit_code_42`

- [ ] **Step 2: Verify Linux runner still works**

Run: `cargo test -p litebox_runner_linux_on_macos_userland -- --test-threads=1`

Expected: existing tests pass (the platform change in Task 3 is backward-compatible).

- [ ] **Step 3: Run cargo check on the whole workspace**

Run: `cargo check`

Expected: no errors.

- [ ] **Step 4: Commit (if any fixups were needed)**

```bash
git add -A && git commit -m "fix: address test failures from end-to-end integration"
```
