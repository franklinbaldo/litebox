// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Orchestrates the full ELF loading sequence: parse the main binary, parse
//! the dynamic linker (interpreter) if present, load both into memory, and
//! set up the user stack with `argv`, `envp`, and the auxiliary vector.

// The public API of this module is consumed by later launcher phases that have
// not landed yet.  Suppress dead-code warnings until then.
#![allow(dead_code)]

use std::collections::BTreeMap;

use anyhow::{Context, bail};

use crate::loader::{PAGE_SIZE, RealFile, RealMapper, RealMemory};
use litebox_common_linux::loader::ElfParsedFile;

// ── Auxiliary vector key constants ──────────────────────────────────────────

/// Auxiliary vector keys (mirrors the Linux `AT_*` constants).
///
/// We define our own copy because the canonical `AuxKey` lives in
/// `litebox_shim_linux`, which the launcher does not (and should not) depend on.
#[allow(non_camel_case_types, dead_code)]
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AuxKey {
    AT_NULL = 0,
    AT_PHDR = 3,
    AT_PHENT = 4,
    AT_PHNUM = 5,
    AT_PAGESZ = 6,
    AT_BASE = 7,
    AT_ENTRY = 9,
    AT_UID = 11,
    AT_EUID = 12,
    AT_GID = 13,
    AT_EGID = 14,
    AT_CLKTCK = 17,
    AT_RANDOM = 25,
}

// ── Public output struct ───────────────────────────────────────────────────

/// Result of successfully loading an ELF (and its interpreter, if any) along
/// with a fully-initialised user stack.
pub struct LoadedElf {
    /// Where execution should begin (interpreter entry if dynamic, else main).
    pub entry_point: usize,
    /// Stack pointer to pass to the new program (points at `argc`).
    pub stack_pointer: usize,
    /// Program break address (end of mapped segments).
    pub brk: usize,
}

// ── Stack size ─────────────────────────────────────────────────────────────

/// 8 MiB – matches the default Linux `RLIMIT_STACK`.
const STACK_SIZE: usize = 8 * 1024 * 1024;

// ── Stack builder ──────────────────────────────────────────────────────────

/// Helper for building the initial user stack from the high end downward.
struct StackBuilder {
    /// Base address of the `mmap`'d region.
    base: usize,
    /// Current write position (offset from `base`).  Starts at `STACK_SIZE`
    /// and moves toward zero as items are pushed.
    pos: usize,
}

impl StackBuilder {
    fn new(base: usize, size: usize) -> Self {
        Self { base, pos: size }
    }

    /// Current absolute address of the stack pointer.
    fn sp(&self) -> usize {
        self.base + self.pos
    }

    /// Push raw bytes, decrementing `pos`.
    ///
    /// # Panics
    ///
    /// Panics if there is not enough space remaining on the stack.
    fn push_bytes(&mut self, data: &[u8]) {
        assert!(
            self.pos >= data.len(),
            "stack overflow: need {} bytes but only {} remain",
            data.len(),
            self.pos,
        );
        self.pos -= data.len();
        let dst = (self.base + self.pos) as *mut u8;
        // SAFETY: the caller allocated `[base, base+STACK_SIZE)` as writable
        // and the assert above guarantees `pos >= 0` (i.e. within bounds).
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };
    }

    /// Push a `usize` in native-endian byte order.
    fn push_usize(&mut self, val: usize) {
        self.push_bytes(&val.to_ne_bytes());
    }

    /// Push a NUL-terminated C string (including the terminator).
    fn push_cstring(&mut self, s: &str) {
        // Push the NUL first (we write top-down).
        self.push_bytes(&[0]);
        self.push_bytes(s.as_bytes());
    }

    /// Align `pos` down to a given power-of-two alignment.
    fn align(&mut self, alignment: usize) {
        debug_assert!(alignment.is_power_of_two());
        self.pos &= !(alignment - 1);
    }
}

// ── The main loading function ──────────────────────────────────────────────

/// Load a guest ELF binary, its dynamic linker (if any), and set up the user
/// stack.
///
/// `syscall_entry_point` is the address to write into the trampoline
/// (`micro_syscall_entry`).
///
/// # Errors
///
/// Returns an error if the ELF cannot be opened, parsed, or loaded, or if
/// stack allocation fails.
pub fn load_elf(
    path: &str,
    argv: &[&str],
    envp: &[&str],
    syscall_entry_point: usize,
    rootfs_prefix: Option<&str>,
) -> anyhow::Result<LoadedElf> {
    // ── 1. Open & parse main ELF ───────────────────────────────────────
    let file = RealFile::open(path).map_err(|e| anyhow::anyhow!("open({path}): errno {e}"))?;
    let mut parsed =
        ElfParsedFile::parse(&mut &file).map_err(|e| anyhow::anyhow!("parse({path}): {e}"))?;
    parsed
        .parse_trampoline(&mut &file, syscall_entry_point)
        .map_err(|e| anyhow::anyhow!("parse_trampoline({path}): {e}"))?;

    // ── 2. Check for interpreter (dynamic linker) ──────────────────────
    let interp_cstring = parsed
        .interp(&mut &file)
        .map_err(|e| anyhow::anyhow!("interp({path}): {e}"))?;

    let interp_data: Option<(RealFile, ElfParsedFile)> = if let Some(ref name) = interp_cstring {
        let raw_interp_path = name.to_str().context("interpreter path is not UTF-8")?;
        // When --rootfs-prefix is given, resolve the interpreter relative to
        // that directory (e.g. /tmp/rootfs + /lib64/ld-linux-x86-64.so.2).
        let resolved_interp;
        let interp_path = if let Some(prefix) = rootfs_prefix {
            resolved_interp = format!("{prefix}{raw_interp_path}");
            &resolved_interp
        } else {
            raw_interp_path
        };
        let ifile = RealFile::open(interp_path)
            .map_err(|e| anyhow::anyhow!("open({interp_path}): errno {e}"))?;
        let mut iparsed = ElfParsedFile::parse(&mut &ifile)
            .map_err(|e| anyhow::anyhow!("parse({interp_path}): {e}"))?;
        iparsed
            .parse_trampoline(&mut &ifile, syscall_entry_point)
            .map_err(|e| anyhow::anyhow!("parse_trampoline({interp_path}): {e}"))?;
        Some((ifile, iparsed))
    } else {
        None
    };

    // ── 3. Load main ELF ───────────────────────────────────────────────
    let main_info = parsed
        .load(&mut RealMapper::new(file.fd()), &mut RealMemory)
        .map_err(|e| anyhow::anyhow!("load({path}): {e}"))?;

    // ── 4. Load interpreter (if any) ───────────────────────────────────
    let interp_info = if let Some((ifile, iparsed)) = &interp_data {
        Some(
            iparsed
                .load(&mut RealMapper::new(ifile.fd()), &mut RealMemory)
                .map_err(|e| anyhow::anyhow!("load(interp): {e}"))?,
        )
    } else {
        None
    };

    // ── 5. Allocate stack ──────────────────────────────────────────────
    let stack_base = allocate_stack(STACK_SIZE)?;

    // ── 6. Build auxiliary vector ──────────────────────────────────────
    let mut auxv: BTreeMap<AuxKey, usize> = BTreeMap::new();
    auxv.insert(AuxKey::AT_PAGESZ, PAGE_SIZE);
    auxv.insert(AuxKey::AT_PHDR, main_info.phdrs_addr);
    auxv.insert(AuxKey::AT_PHENT, main_info.phent_size());
    auxv.insert(AuxKey::AT_PHNUM, main_info.num_phdrs);
    auxv.insert(AuxKey::AT_ENTRY, main_info.entry_point);
    auxv.insert(AuxKey::AT_UID, 0);
    auxv.insert(AuxKey::AT_EUID, 0);
    auxv.insert(AuxKey::AT_GID, 0);
    auxv.insert(AuxKey::AT_EGID, 0);
    auxv.insert(AuxKey::AT_CLKTCK, 100);
    if let Some(ref iinfo) = interp_info {
        auxv.insert(AuxKey::AT_BASE, iinfo.base_addr);
    }

    // ── 7. Initialise user stack ──────────────────────────────────────
    let stack_pointer = init_stack(stack_base, STACK_SIZE, argv, envp, &mut auxv);

    // ── 8. Determine entry point ──────────────────────────────────────
    let entry_point = interp_info
        .as_ref()
        .map_or(main_info.entry_point, |i| i.entry_point);

    Ok(LoadedElf {
        entry_point,
        stack_pointer,
        brk: main_info.brk,
    })
}

// ── Stack allocation ───────────────────────────────────────────────────────

fn allocate_stack(size: usize) -> anyhow::Result<usize> {
    // SAFETY: standard anonymous-private mmap.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_STACK | libc::MAP_GROWSDOWN,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        let e = unsafe { *libc::__errno_location() };
        bail!("mmap(stack): errno {e}");
    }
    Ok(ptr as usize)
}

// ── Stack initialisation ───────────────────────────────────────────────────

/// Build the initial user stack.  Returns the stack pointer (points at `argc`).
///
/// Layout from high address to low (see module doc for diagram).
fn init_stack(
    stack_base: usize,
    stack_size: usize,
    argv: &[&str],
    envp: &[&str],
    auxv: &mut BTreeMap<AuxKey, usize>,
) -> usize {
    let mut sb = StackBuilder::new(stack_base, stack_size);

    // ── end marker (NULL) ──────────────────────────────────────────────
    sb.push_usize(0);

    // ── environment strings (ASCIIZ) ───────────────────────────────────
    let mut env_addrs: Vec<usize> = Vec::with_capacity(envp.len());
    for &e in envp.iter().rev() {
        sb.push_cstring(e);
        env_addrs.push(sb.sp());
    }
    env_addrs.reverse();

    // ── argument strings (ASCIIZ) ──────────────────────────────────────
    let mut arg_addrs: Vec<usize> = Vec::with_capacity(argv.len());
    for &a in argv.iter().rev() {
        sb.push_cstring(a);
        arg_addrs.push(sb.sp());
    }
    arg_addrs.reverse();

    // ── AT_RANDOM: 16 pseudo-random bytes ──────────────────────────────
    sb.push_bytes(&[
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
        0xEF,
    ]);
    auxv.insert(AuxKey::AT_RANDOM, sb.sp());

    // ── padding for 16-byte alignment ──────────────────────────────────
    // Calculate total number of usize entries from here downward, then pad
    // so the final SP is 16-byte aligned.
    sb.align(size_of::<usize>());
    let remaining_entries =
        // auxv: (N entries + terminator) * 2 words each
        (auxv.len() + 1) * 2
        // envp pointers + NULL terminator
        + envp.len() + 1
        // argv pointers + NULL terminator
        + argv.len() + 1
        // argc
        + 1;
    let bytes_needed = remaining_entries * size_of::<usize>();
    let final_pos = sb.pos - bytes_needed;
    let aligned_final = final_pos & !15; // align down to 16 bytes
    sb.pos -= final_pos - aligned_final;

    // ── auxv entries ───────────────────────────────────────────────────
    // Terminator first.
    sb.push_usize(0); // AT_NULL value
    sb.push_usize(AuxKey::AT_NULL as usize); // AT_NULL key
    // Remaining entries in reverse order (BTreeMap iterates in key order,
    // but we push from top-down so reverse to get ascending in memory).
    for (&key, &val) in auxv.iter().rev() {
        sb.push_usize(val);
        sb.push_usize(key as usize);
    }

    // ── envp pointers ──────────────────────────────────────────────────
    sb.push_usize(0); // NULL terminator
    for &addr in env_addrs.iter().rev() {
        sb.push_usize(addr);
    }

    // ── argv pointers ──────────────────────────────────────────────────
    sb.push_usize(0); // NULL terminator
    for &addr in arg_addrs.iter().rev() {
        sb.push_usize(addr);
    }

    // ── argc ───────────────────────────────────────────────────────────
    sb.push_usize(argv.len());

    debug_assert_eq!(sb.sp() % 16, 0, "stack pointer must be 16-byte aligned");

    sb.sp()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the stack layout produced by `init_stack` is well-formed:
    /// - SP is 16-byte aligned
    /// - argc matches argv count
    /// - argv pointers are terminated by NULL
    /// - envp pointers are terminated by NULL
    /// - auxv is terminated by AT_NULL
    /// - strings are recoverable
    #[test]
    fn stack_layout_is_correct() {
        let stack_size: usize = 64 * 1024; // 64 KiB is plenty for a test
        // SAFETY: test-only anonymous mapping.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                stack_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED, "mmap for test stack failed");
        let base = base as usize;

        let argv = &["./hello", "world"];
        let envp = &["HOME=/root", "PATH=/usr/bin"];
        let mut auxv: BTreeMap<AuxKey, usize> = BTreeMap::new();
        auxv.insert(AuxKey::AT_PAGESZ, 4096);
        auxv.insert(AuxKey::AT_UID, 0);
        auxv.insert(AuxKey::AT_ENTRY, 0x400000);

        let sp = init_stack(base, stack_size, argv, envp, &mut auxv);

        // SP must be 16-byte aligned.
        assert_eq!(sp % 16, 0, "SP is not 16-byte aligned");
        assert!(sp >= base, "SP underflowed below stack base");
        assert!(sp < base + stack_size, "SP overflowed above stack top");

        // Read argc.
        let argc = read_usize(sp);
        assert_eq!(argc, 2, "argc should be 2");

        // Read argv pointers.
        let argv0_ptr = read_usize(sp + size_of::<usize>());
        let argv1_ptr = read_usize(sp + 2 * size_of::<usize>());
        let argv_null = read_usize(sp + 3 * size_of::<usize>());
        assert_ne!(argv0_ptr, 0);
        assert_ne!(argv1_ptr, 0);
        assert_eq!(argv_null, 0, "argv must be NULL-terminated");

        // Verify argv strings.
        assert_eq!(read_cstr(argv0_ptr), "./hello");
        assert_eq!(read_cstr(argv1_ptr), "world");

        // Read envp pointers (start right after argv NULL).
        let envp_base = sp + 4 * size_of::<usize>();
        let envp0_ptr = read_usize(envp_base);
        let envp1_ptr = read_usize(envp_base + size_of::<usize>());
        let envp_null = read_usize(envp_base + 2 * size_of::<usize>());
        assert_ne!(envp0_ptr, 0);
        assert_ne!(envp1_ptr, 0);
        assert_eq!(envp_null, 0, "envp must be NULL-terminated");

        assert_eq!(read_cstr(envp0_ptr), "HOME=/root");
        assert_eq!(read_cstr(envp1_ptr), "PATH=/usr/bin");

        // Read auxv (starts right after envp NULL).
        let auxv_base = envp_base + 3 * size_of::<usize>();
        let mut found_null = false;
        for i in 0..64 {
            let key = read_usize(auxv_base + i * 2 * size_of::<usize>());
            let _val = read_usize(auxv_base + (i * 2 + 1) * size_of::<usize>());
            if key == AuxKey::AT_NULL as usize {
                found_null = true;
                break;
            }
        }
        assert!(found_null, "auxv must contain AT_NULL terminator");

        // Clean up.
        unsafe {
            libc::munmap(base as *mut libc::c_void, stack_size);
        }
    }

    /// Parse `/proc/self/exe` to validate that the parsing path works (we
    /// cannot fully load because that would conflict with the running process).
    #[test]
    fn parse_proc_self_exe() {
        let file = RealFile::open("/proc/self/exe").expect("open /proc/self/exe");
        let parsed = ElfParsedFile::parse(&mut &file).expect("parse /proc/self/exe");
        // At minimum, the test binary is a valid ELF.
        let _interp = parsed.interp(&mut &file).expect("interp check");
    }

    // ── Test helpers ───────────────────────────────────────────────────

    fn read_usize(addr: usize) -> usize {
        let mut buf = [0u8; size_of::<usize>()];
        // SAFETY: addr points into a valid mmap'd region.
        unsafe {
            std::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len());
        }
        usize::from_ne_bytes(buf)
    }

    fn read_cstr(addr: usize) -> String {
        // SAFETY: addr points to a NUL-terminated string in a valid mapping.
        let cstr = unsafe { std::ffi::CStr::from_ptr(addr as *const std::ffi::c_char) };
        cstr.to_string_lossy().into_owned()
    }
}
