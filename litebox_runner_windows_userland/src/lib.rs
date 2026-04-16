// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows userland PE runner for LiteBox.
//!
//! Loads a PE executable and real guest DLLs into a LiteBox address space
//! using the NT shim. Only real NT syscall stubs from guest `ntdll.dll` are
//! rewritten to jump to the shim trampoline; other guest DLL code runs as-is.
//!
//! ## Usage
//!
//! ```text
//! litebox_runner_windows_userland --dll-tar node_windows.tar --pe-file node.exe -- --version
//! ```
//!
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]
#![allow(
    // PE format code inherently involves cross-width casts and integer wrapping.
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    // Bootstrap/debug helpers define local ABI items that intentionally mirror
    // Windows layouts and signatures.
    clippy::items_after_statements,
    clippy::struct_field_names,
)]

extern crate alloc;

#[cfg(all(debug_assertions, feature = "trace_debug"))]
macro_rules! trace_debugln {
    ($($arg:tt)*) => {
        eprintln!($($arg)*);
    };
}

#[cfg(not(all(debug_assertions, feature = "trace_debug")))]
macro_rules! trace_debugln {
    ($($arg:tt)*) => {};
}

mod real_dlls;

use anyhow::{Result, anyhow};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering::Relaxed};

use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
use litebox::platform::{AddressSpaceProvider, RawConstPointer, RawMutPointer, SystemInfoProvider};
use litebox_common_windows::pe_loader::{PeLoadError, PeMemoryMapper, SectionPermissions, load_pe};
use litebox_common_windows::pe_parser::PeParsedFile;
use litebox_platform_multiplex::Platform;
use litebox_shim_windows::peb_teb::{PebTebLayout, PebTebParams, build_peb_teb_bytes};

/// Page size for the Windows userland platform.
const PAGE_SIZE: usize = 4096;

/// Stack size: 1 MiB (matching Windows default).
const GUEST_STACK_SIZE: usize = 0x0010_0000;

/// PEB/TEB region offset — placed well below the DLL region.
const PEB_TEB_OFFSET: usize = 0x7E_FFF0_0000;

#[cfg(all(debug_assertions, feature = "trace_debug"))]
fn trace_log_path(file_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("litebox_runner_windows_userland_{file_name}"))
}

#[cfg(all(debug_assertions, feature = "trace_debug"))]
fn open_trace_log_handle(file_name: &str) -> *mut core::ffi::c_void {
    use std::fs::OpenOptions;
    use std::os::windows::io::IntoRawHandle;

    match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(trace_log_path(file_name))
    {
        Ok(file) => file.into_raw_handle(),
        Err(_) => core::ptr::null_mut(),
    }
}

#[cfg(all(debug_assertions, feature = "trace_debug"))]
fn write_trace_log(file_name: &str, data: &[u8]) {
    let _ = std::fs::write(trace_log_path(file_name), data);
}

#[cfg(all(debug_assertions, feature = "trace_debug"))]
static CRASH_FILE_HANDLE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());

/// Run Windows PE programs with LiteBox.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// Path to the PE executable to run. If omitted and --dll-tar contains
    /// an .exe, that EXE is used automatically.
    #[arg(long = "pe-file", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    pub pe_file: Option<PathBuf>,
    /// Connect to a network broker via loopback TCP (e.g.,
    /// "127.0.0.1:9000") or a Windows AF_UNIX socket path. The broker must
    /// be listening and speaking the litebox IPC network protocol (LBNP
    /// handshake).
    #[arg(long = "network-broker", value_name = "ADDR_OR_PATH")]
    pub network_broker: Option<String>,
    /// Path to a tar file containing real DLLs (ntdll.dll, kernel32.dll,
    /// etc.) and optionally the main EXE.
    #[arg(long = "dll-tar", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    pub dll_tar: PathBuf,
    /// Arguments passed to the guest PE image.
    ///
    /// Use `--` before guest arguments that begin with `-`, for example:
    /// `--pe-file node.exe -- --version`.
    #[arg(trailing_var_arg = true, value_name = "ARGS", value_hint = clap::ValueHint::CommandWithArguments)]
    pub guest_arguments: Vec<String>,
    /// Connect to a 9P file broker for host filesystem access. Accepts a
    /// loopback TCP address (e.g. "127.0.0.1:9000") or an AF_UNIX socket
    /// path. The broker must speak the LB9P protocol.
    #[arg(long = "nine-p-broker", value_name = "ADDR_OR_PATH")]
    pub nine_p_broker: Option<String>,
    /// Set an environment variable inside the sandbox. Can be specified
    /// multiple times. Format: KEY=VALUE.
    ///
    /// When any `--env` values are provided, they are merged with the
    /// default sandbox environment (SYSTEMROOT, PATH, TEMP, etc.).
    ///
    /// Example: `--env "GH_TOKEN=$(gh auth token)"`
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub env_vars: Vec<String>,
}

fn quote_windows_command_line_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }

    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;

    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                out.push(ch);
            }
        }
    }

    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

fn build_guest_command_line(program_name: &str, guest_arguments: &[String]) -> String {
    core::iter::once(program_name)
        .chain(guest_arguments.iter().map(String::as_str))
        .map(quote_windows_command_line_arg)
        .collect::<Vec<_>>()
        .join(" ")
}

/// JavaScript preload that patches `dns.lookup` to use c-ares (libuv's
/// async DNS resolver) instead of the Windows `GetAddrInfoW` syscall.
///
/// Windows' `GetAddrInfoW` depends on the DNS Client service (Dnscache)
/// which communicates via ALPC/RPC — infrastructure that doesn't exist
/// inside the sandbox.  Node.js's c-ares resolver sends UDP DNS queries
/// directly, which are handled by the sandbox's smoltcp network stack.
const DNS_PATCH_JS: &str = r#"
'use strict';
const dns = require('dns');
const { Resolver } = dns;
const net = require('net');
const resolver = new Resolver();
resolver.setServers(['8.8.8.8']);
dns.lookup = function(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (typeof options === 'number') { options = { family: options }; }
    options = options || {};
    if (!hostname || hostname === 'localhost') {
        const a = (!options.family || options.family === 4) ? '127.0.0.1' : '::1';
        const f = (!options.family || options.family === 4) ? 4 : 6;
        return options.all ? callback(null, [{address:a,family:f}]) : callback(null, a, f);
    }
    if (net.isIP(hostname)) {
        const f = net.isIPv4(hostname) ? 4 : 6;
        return options.all ? callback(null,[{address:hostname,family:f}]) : callback(null,hostname,f);
    }
    const wantV4 = !options.family || options.family === 4;
    const resolve = wantV4 ? resolver.resolve4.bind(resolver) : resolver.resolve6.bind(resolver);
    resolve(hostname, (err, addrs) => {
        if (err) {
            const e = new Error('getaddrinfo ENOTFOUND ' + hostname);
            e.code = 'ENOTFOUND'; e.errno = -3008; e.hostname = hostname;
            e.syscall = 'getaddrinfo'; return callback(e);
        }
        const fam = wantV4 ? 4 : 6;
        options.all ? callback(null, addrs.map(a => ({address:a,family:fam}))) : callback(null, addrs[0], fam);
    });
};
if (dns.promises) {
    dns.promises.lookup = function(hostname, options) {
        return new Promise((resolve, reject) => {
            dns.lookup(hostname, options, (err, address, family) => {
                if (err) return reject(err);
                (options && options.all) ? resolve(address) : resolve({address,family});
            });
        });
    };
}
"#;

/// VFS path where the DNS patch preload script is written.
const DNS_PATCH_VFS_PATH: &str = "/c/windows/system32/__litebox_dns_patch.js";
/// Windows path the guest process sees for the DNS patch.
const DNS_PATCH_WIN_PATH: &str = r"C:\Windows\System32\__litebox_dns_patch.js";

/// Write the embedded DNS patch script into the VFS and return either:
/// - For `node.exe`: `--require` arguments to prepend to the guest command line.
/// - For other Node.js-based executables: empty vec (use `NODE_OPTIONS` env var instead).
///
/// Only injects for Node.js-based executables when networking is enabled.
/// Returns `(extra_args, extra_env)`.
fn inject_dns_patch<FS: litebox::fs::FileSystem>(
    vfs: &FS,
    exe_name: &str,
    has_network: bool,
) -> (Vec<String>, Option<String>) {
    if !has_network {
        return (Vec::new(), None);
    }
    // Heuristic: inject for node.exe, copilot.exe, or any electron-like
    // process that bundles Node.js.
    let name_lower = exe_name.to_ascii_lowercase();
    let is_node_based = name_lower == "node.exe"
        || name_lower == "copilot.exe"
        || name_lower.contains("node");
    if !is_node_based {
        return (Vec::new(), None);
    }

    // Write the JS file into the VFS.
    let content = DNS_PATCH_JS.as_bytes();
    let file_mode = litebox::fs::Mode::RUSR
        .union(litebox::fs::Mode::WUSR)
        .union(litebox::fs::Mode::RGRP)
        .union(litebox::fs::Mode::ROTH);
    let dir_mode = litebox::fs::Mode::RWXU
        .union(litebox::fs::Mode::RWXG)
        .union(litebox::fs::Mode::RWXO);
    ensure_vfs_parent_dirs(vfs, DNS_PATCH_VFS_PATH, dir_mode);
    match vfs.open(
        DNS_PATCH_VFS_PATH,
        litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY | litebox::fs::OFlags::TRUNC,
        file_mode,
    ) {
        Ok(fd) => {
            let mut written = 0;
            while written < content.len() {
                match vfs.write(&fd, &content[written..], None) {
                    Ok(n) if n > 0 => written += n,
                    _ => break,
                }
            }
            let _ = vfs.close(&fd);
            if written == content.len() {
                eprintln!("Injected DNS patch at {DNS_PATCH_WIN_PATH}");
                if name_lower == "node.exe" {
                    // For raw node.exe, prepend --require to arguments.
                    return (vec![
                        "--require".to_string(),
                        DNS_PATCH_WIN_PATH.to_string(),
                    ], None);
                }
                // For other Node.js-based executables (copilot.exe, etc.),
                // use NODE_OPTIONS env var so it doesn't conflict with
                // the application's own CLI argument parser.
                return (Vec::new(), Some(
                    format!("NODE_OPTIONS=--require {DNS_PATCH_WIN_PATH}"),
                ));
            }
            eprintln!("Warning: DNS patch write incomplete ({written}/{} bytes)", content.len());
        }
        Err(e) => {
            eprintln!("Warning: could not inject DNS patch: {e:?}");
        }
    }
    (Vec::new(), None)
}

fn drive_path_to_vfs(path: &str) -> Option<String> {
    if let Some(unc) = path.strip_prefix("\\\\?\\UNC\\") {
        return Some(format!("//{}", unc.replace('\\', "/").to_ascii_lowercase()));
    }
    let path = path
        .strip_prefix("\\??\\")
        .or_else(|| path.strip_prefix("\\DosDevices\\"))
        .or_else(|| path.strip_prefix("\\\\?\\"))
        .unwrap_or(path);
    if path.len() < 2 || path.as_bytes()[1] != b':' {
        return None;
    }

    let drive = (path.as_bytes()[0] as char).to_ascii_lowercase();
    let rest = if path.len() > 2 { &path[2..] } else { "" };
    Some(format!(
        "/{drive}{}",
        rest.replace('\\', "/").to_ascii_lowercase()
    ))
}

fn push_guest_host_file(
    host_path: PathBuf,
    mirrored: &mut Vec<(String, PathBuf)>,
    seen: &mut std::collections::BTreeSet<String>,
) {
    let Some(host_path_str) = host_path.to_str() else {
        return;
    };
    let Some(vfs_path) = drive_path_to_vfs(host_path_str) else {
        return;
    };
    if !seen.insert(vfs_path.clone()) {
        return;
    }
    mirrored.push((vfs_path, host_path));
}

fn collect_host_tree_files(
    root: &Path,
    mirrored: &mut Vec<(String, PathBuf)>,
    seen: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|e| {
            anyhow!(
                "Could not enumerate guest host directory {}: {e}",
                dir.display()
            )
        })? {
            let entry = entry.map_err(|e| {
                anyhow!(
                    "Could not read guest host directory entry in {}: {e}",
                    dir.display()
                )
            })?;
            let file_type = entry.file_type().map_err(|e| {
                anyhow!(
                    "Could not query guest host entry type for {}: {e}",
                    entry.path().display()
                )
            })?;
            let path = entry.path();
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                let host_path = path.canonicalize().unwrap_or(path);
                push_guest_host_file(host_path, mirrored, seen);
            }
        }
    }
    Ok(())
}

fn collect_guest_argument_host_files(
    guest_arguments: &[String],
    launch_cwd: &Path,
) -> Result<Vec<(String, PathBuf)>> {
    let mut mirrored = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut mirrored_roots = std::collections::BTreeSet::new();

    for arg in guest_arguments {
        let path = Path::new(arg);
        let is_relative_guest_path = !path.is_absolute();
        let host_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            launch_cwd.join(path)
        };
        let host_path = host_path.canonicalize().unwrap_or(host_path);
        if !host_path.is_file() {
            continue;
        }

        push_guest_host_file(host_path.clone(), &mut mirrored, &mut seen);
        if is_relative_guest_path
            && let Some(root) = host_path.parent().map(Path::to_path_buf)
            && mirrored_roots.insert(root.clone())
        {
            collect_host_tree_files(&root, &mut mirrored, &mut seen)?;
        }
    }

    Ok(mirrored)
}

fn ensure_vfs_parent_dirs<F: litebox::fs::FileSystem>(
    fs: &F,
    path: &str,
    dir_mode: litebox::fs::Mode,
) {
    let mut current = String::new();
    let mut parts = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .peekable();
    while let Some(segment) = parts.next() {
        if parts.peek().is_none() {
            break;
        }
        current.push('/');
        current.push_str(segment);
        let _ = fs.mkdir(current.as_str(), dir_mode);
    }
}

fn mirror_guest_host_files_into_vfs<F: litebox::fs::FileSystem>(
    fs: &F,
    files: &[(String, PathBuf)],
    dir_mode: litebox::fs::Mode,
    file_mode: litebox::fs::Mode,
) -> Result<()> {
    use std::io::Read as _;

    for (vfs_path, host_path) in files {
        ensure_vfs_parent_dirs(fs, vfs_path, dir_mode);
        let fd = fs
            .open(
                vfs_path.as_str(),
                litebox::fs::OFlags::CREAT
                    | litebox::fs::OFlags::WRONLY
                    | litebox::fs::OFlags::TRUNC,
                file_mode,
            )
            .map_err(|e| anyhow!("Could not mirror {vfs_path} into guest VFS: {e:?}"))?;

        let mut host_file = std::fs::File::open(host_path).map_err(|e| {
            anyhow!(
                "Could not open guest host file {}: {e}",
                host_path.display()
            )
        })?;
        #[allow(clippy::large_stack_arrays)] // 64 KiB read buffer avoids many small reads
        let mut buf = [0u8; 64 * 1024];
        loop {
            let read = host_file.read(&mut buf).map_err(|e| {
                anyhow!(
                    "Could not read guest host file {}: {e}",
                    host_path.display()
                )
            })?;
            if read == 0 {
                break;
            }
            let mut written = 0;
            while written < read {
                let n = fs.write(&fd, &buf[written..read], None).map_err(|e| {
                    anyhow!("Could not write mirrored guest file {vfs_path}: {e:?}")
                })?;
                if n == 0 {
                    let _ = fs.close(&fd);
                    return Err(anyhow!(
                        "Mirrored guest file write made no progress for {vfs_path}"
                    ));
                }
                written += n;
            }
        }

        fs.close(&fd)
            .map_err(|e| anyhow!("Could not close mirrored guest file {vfs_path}: {e:?}"))?;
    }

    Ok(())
}

const LDRP_HASH_BUCKET_COUNT: usize = 32;
const LIST_ENTRY_SIZE: usize = 16;
const LDR_HASH_LINKS_OFFSET: usize = 0x70;
const LDR_BASE_NAME_HASH_VALUE_OFFSET: usize = 0x108;

unsafe fn write_guest_usize(addr: usize, value: usize) {
    unsafe { (addr as *mut usize).write(value) };
}

unsafe fn write_guest_u32(addr: usize, value: u32) {
    unsafe { (addr as *mut u32).write(value) };
}

unsafe fn read_guest_u32(addr: usize) -> u32 {
    unsafe { (addr as *const u32).read() }
}

unsafe fn init_ntdll_pebldr(peb_va: usize, pebldr_va: usize, ldr_data_va: usize) {
    let exe_entry_va = ldr_data_va + 0x60;
    let ntdll_entry_va = ldr_data_va + 0x180;
    let head_load = pebldr_va + 0x10;
    let head_mem = pebldr_va + 0x20;
    let head_init = pebldr_va + 0x30;

    unsafe {
        write_guest_usize(peb_va + 0x18, pebldr_va);
        write_guest_u32(pebldr_va, 0x58);
        write_guest_u32(pebldr_va + 0x04, 1);
        write_guest_usize(pebldr_va + 0x08, 0);

        write_guest_usize(exe_entry_va, ntdll_entry_va);
        write_guest_usize(exe_entry_va + 0x08, head_load);
        write_guest_usize(exe_entry_va + 0x10, ntdll_entry_va + 0x10);
        write_guest_usize(exe_entry_va + 0x18, head_mem);

        write_guest_usize(ntdll_entry_va, head_load);
        write_guest_usize(ntdll_entry_va + 0x08, exe_entry_va);
        write_guest_usize(ntdll_entry_va + 0x10, head_mem);
        write_guest_usize(ntdll_entry_va + 0x18, exe_entry_va + 0x10);
        write_guest_usize(ntdll_entry_va + 0x20, head_init);
        write_guest_usize(ntdll_entry_va + 0x28, head_init);

        write_guest_usize(head_load, exe_entry_va);
        write_guest_usize(head_load + 8, ntdll_entry_va);
        write_guest_usize(head_mem, exe_entry_va + 0x10);
        write_guest_usize(head_mem + 8, ntdll_entry_va + 0x10);
        write_guest_usize(head_init, ntdll_entry_va + 0x20);
        write_guest_usize(head_init + 8, ntdll_entry_va + 0x20);
    }
}

unsafe fn init_ntdll_loader_globals(pebldr_va: usize, ldr_data_va: usize) {
    let exe_entry_va = ldr_data_va + 0x60;
    let ntdll_entry_va = ldr_data_va + 0x180;

    // On the current ntdll build, CDB shows:
    //   PebLdr                   = ntdll+0x1D28E0
    //   LdrpImageEntry          = ntdll+0x1D27C8 = PebLdr - 0x118
    //   LdrpNtDllDataTableEntry = ntdll+0x1D2938 = PebLdr + 0x58
    //
    // These are kernel-seeded globals that ntdll expects to be initialized
    // before LdrInitializeThunk runs.
    let ldrp_image_entry_va = pebldr_va - 0x118;
    let ldrp_ntdll_entry_va = pebldr_va + 0x58;

    unsafe {
        write_guest_usize(ldrp_image_entry_va, exe_entry_va);
        write_guest_usize(ldrp_ntdll_entry_va, ntdll_entry_va);
    }
}

unsafe fn init_ntdll_loader_hash_table(hash_table_va: usize, ldr_data_va: usize) {
    for bucket in 0..LDRP_HASH_BUCKET_COUNT {
        let head = hash_table_va + bucket * LIST_ENTRY_SIZE;
        unsafe {
            write_guest_usize(head, head);
            write_guest_usize(head + 8, head);
        }
    }

    for entry_va in [ldr_data_va + 0x60, ldr_data_va + 0x180] {
        let hash = unsafe { read_guest_u32(entry_va + LDR_BASE_NAME_HASH_VALUE_OFFSET) } as usize;
        let head = hash_table_va + (hash & (LDRP_HASH_BUCKET_COUNT - 1)) * LIST_ENTRY_SIZE;
        let hash_links = entry_va + LDR_HASH_LINKS_OFFSET;
        let tail = unsafe { (head as *const usize).add(1).read() };
        unsafe {
            write_guest_usize(hash_links, head);
            write_guest_usize(hash_links + 8, tail);
            write_guest_usize(tail, hash_links);
            write_guest_usize(head + 8, hash_links);
        }
    }
}

/// Run a Windows PE program with LiteBox.
///
/// # Panics
///
/// Panics if the platform cannot allocate page-aligned memory for the guest
/// stack, PEB/TEB, or PE sections. These are programming errors rather than
/// user-recoverable conditions.
#[allow(clippy::items_after_statements)]
pub fn run(cli_args: CliArgs) -> Result<()> {
    // Install a last-resort crash handler so we always see what RIP/code
    // killed the process, even if VEH failed to catch the exception.
    unsafe {
        #[allow(clippy::struct_field_names)]
        #[repr(C)]
        struct ExceptionRecord {
            exception_code: u32,
            exception_flags: u32,
            exception_record: usize,
            exception_address: usize,
            number_parameters: u32,
            _pad: u32,
            exception_information: [usize; 15],
        }
        // Windows x64 CONTEXT — use byte array for reliability.
        #[repr(C)]
        struct Context {
            data: [u8; 1232],
        }
        #[repr(C)]
        struct ExceptionPointers {
            exception_record: *const ExceptionRecord,
            context_record: *const Context,
        }
        #[cfg(all(debug_assertions, feature = "trace_debug"))]
        {
            // Keep a raw handle ready for zero-allocation crash logging.
            CRASH_FILE_HANDLE.store(open_trace_log_handle("crash_filter.txt"), Relaxed);
        }
        unsafe extern "system" fn crash_filter(info: *mut ExceptionPointers) -> i32 {
            unsafe {
                let info = &*info;
                let rec = &*info.exception_record;
                let ctx_bytes = &(*info.context_record).data;
                // Rip at offset 0xF8, Rsp at offset 0x98
                let rip = u64::from_le_bytes(ctx_bytes[0xF8..0x100].try_into().unwrap_or([0; 8]));
                let rsp = u64::from_le_bytes(ctx_bytes[0x98..0xA0].try_into().unwrap_or([0; 8]));

                #[cfg(all(debug_assertions, feature = "trace_debug"))]
                {
                    // Write to a file using raw Win32 — eprintln may not work.
                    unsafe extern "system" {
                        fn WriteFile(
                            h: *mut core::ffi::c_void,
                            buf: *const u8,
                            len: u32,
                            written: *mut u32,
                            ovl: *mut core::ffi::c_void,
                        ) -> i32;
                    }
                    // Format a minimal crash message without allocation (stack buffer).
                    let mut buf = [0u8; 512];
                    let msg = b"[CRASH] code=0x";
                    buf[..msg.len()].copy_from_slice(msg);
                    let mut pos = msg.len();
                    for i in (0..8).rev() {
                        let nibble = ((rec.exception_code >> (i * 4)) & 0xF) as u8;
                        buf[pos] = if nibble < 10 {
                            b'0' + nibble
                        } else {
                            b'A' + nibble - 10
                        };
                        pos += 1;
                    }
                    buf[pos..pos + 5].copy_from_slice(b" rip=");
                    pos += 5;
                    for i in (0..16).rev() {
                        let nibble = ((rip >> (i * 4)) & 0xF) as u8;
                        buf[pos] = if nibble < 10 {
                            b'0' + nibble
                        } else {
                            b'A' + nibble - 10
                        };
                        pos += 1;
                    }
                    buf[pos..pos + 5].copy_from_slice(b" rsp=");
                    pos += 5;
                    for i in (0..16).rev() {
                        let nibble = ((rsp >> (i * 4)) & 0xF) as u8;
                        buf[pos] = if nibble < 10 {
                            b'0' + nibble
                        } else {
                            b'A' + nibble - 10
                        };
                        pos += 1;
                    }
                    if rec.number_parameters >= 2 {
                        buf[pos..pos + 6].copy_from_slice(b" addr=");
                        pos += 6;
                        let addr = rec.exception_information[1] as u64;
                        for i in (0..16).rev() {
                            let nibble = ((addr >> (i * 4)) & 0xF) as u8;
                            buf[pos] = if nibble < 10 {
                                b'0' + nibble
                            } else {
                                b'A' + nibble - 10
                            };
                            pos += 1;
                        }
                    }
                    buf[pos] = b'\n';
                    pos += 1;

                    let cfh = CRASH_FILE_HANDLE.load(Relaxed);
                    if !cfh.is_null() && cfh != (-1isize) as *mut _ {
                        let mut w = 0u32;
                        WriteFile(
                            cfh,
                            buf.as_ptr(),
                            pos as u32,
                            &raw mut w,
                            core::ptr::null_mut(),
                        );
                    }
                }

                // Get runner image base for RVA calculation.
                unsafe extern "system" {
                    fn GetModuleHandleW(name: *const u16) -> usize;
                }
                let image_base = GetModuleHandleW(core::ptr::null()) as u64;
                let rva = rip.saturating_sub(image_base);
                eprintln!(
                    "[CRASH] Unhandled exception: code=0x{:08X} addr=0x{:X} rip=0x{:X} (base=0x{:X} rva=0x{:X}) rsp=0x{:X}",
                    rec.exception_code, rec.exception_address, rip, image_base, rva, rsp,
                );
                if rec.number_parameters >= 2 {
                    eprintln!(
                        "[CRASH]   info[0]=0x{:X} info[1]=0x{:X}",
                        rec.exception_information[0], rec.exception_information[1],
                    );
                }
                1 // EXCEPTION_EXECUTE_HANDLER
            }
        }
        unsafe extern "system" {
            fn SetUnhandledExceptionFilter(
                filter: Option<unsafe extern "system" fn(*mut ExceptionPointers) -> i32>,
            ) -> usize;
        }
        SetUnhandledExceptionFilter(Some(crash_filter));
    }

    // Secondary VEH at HIGHEST priority — catches exceptions BEFORE the main
    // VEH handler to diagnose cases where the main handler crashes.
    // Capture stderr handle NOW (while GS = host TEB) so VEH can write
    // even when GS = guest TEB.
    unsafe {
        #[repr(C)]
        struct ExPtrs2 {
            exception_record: *const u8,
            context_record: *const u8,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetStdHandle(n: u32) -> *mut core::ffi::c_void;
            fn WriteFile(
                h: *mut core::ffi::c_void,
                buf: *const u8,
                len: u32,
                written: *mut u32,
                ovl: *mut core::ffi::c_void,
            ) -> i32;
        }
        static STDERR_HANDLE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());
        static LOG_FILE_HANDLE: AtomicPtr<core::ffi::c_void> =
            AtomicPtr::new(core::ptr::null_mut());
        static RUNNER_IMAGE_BASE: AtomicU64 = AtomicU64::new(0);
        STDERR_HANDLE.store(GetStdHandle(0xFFFF_FFF4u32), Relaxed); // STD_ERROR_HANDLE
        // Capture image base while GS is still host TEB.
        {
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn GetModuleHandleW(name: *const u16) -> usize;
            }
            RUNNER_IMAGE_BASE.store(GetModuleHandleW(core::ptr::null()) as u64, Relaxed);
        }
        #[cfg(all(debug_assertions, feature = "trace_debug"))]
        {
            // Keep a raw handle ready for zero-allocation crash logging.
            LOG_FILE_HANDLE.store(open_trace_log_handle("veh_log.txt"), Relaxed);
        }
        unsafe extern "system" fn early_veh(info: *mut ExPtrs2) -> i32 {
            unsafe {
                // Zero-allocation, GS-independent handler: uses pre-captured handle.
                let info = &*info;
                let code = core::ptr::read_unaligned(info.exception_record.cast::<u32>());
                let ctx = info.context_record;
                let rip = core::ptr::read_unaligned(ctx.add(0xF8).cast::<u64>());
                let rsp = core::ptr::read_unaligned(ctx.add(0x98).cast::<u64>());
                // Format into a stack buffer (no heap allocation).
                let mut buf = [0u8; 280];
                let len = {
                    let prefix = b"[EARLY-VEH] code=0x";
                    buf[..prefix.len()].copy_from_slice(prefix);
                    let mut pos = prefix.len();
                    pos += hex_u32(&mut buf[pos..], code);
                    let mid = b" rip=0x";
                    buf[pos..pos + mid.len()].copy_from_slice(mid);
                    pos += mid.len();
                    pos += hex_u64(&mut buf[pos..], rip);
                    // Add RVA from pre-captured image base
                    let rva_tag = b" rva=0x";
                    buf[pos..pos + rva_tag.len()].copy_from_slice(rva_tag);
                    pos += rva_tag.len();
                    let rva = rip.saturating_sub(RUNNER_IMAGE_BASE.load(Relaxed));
                    pos += hex_u64(&mut buf[pos..], rva);
                    let mid2 = b" rsp=0x";
                    buf[pos..pos + mid2.len()].copy_from_slice(mid2);
                    pos += mid2.len();
                    pos += hex_u64(&mut buf[pos..], rsp);
                    buf[pos] = b'\n';
                    pos + 1
                };
                let mut written = 0u32;
                WriteFile(
                    STDERR_HANDLE.load(Relaxed),
                    buf.as_ptr(),
                    len as u32,
                    &raw mut written,
                    core::ptr::null_mut(),
                );
                // Also write to dedicated log file.
                let lfh = LOG_FILE_HANDLE.load(Relaxed);
                if !lfh.is_null() && lfh != (-1isize) as *mut core::ffi::c_void {
                    WriteFile(
                        lfh,
                        buf.as_ptr(),
                        len as u32,
                        &raw mut written,
                        core::ptr::null_mut(),
                    );
                }
                0 // EXCEPTION_CONTINUE_SEARCH
            }
        }
        // Minimal hex formatters (no allocation).
        fn hex_u32(buf: &mut [u8], v: u32) -> usize {
            let mut n = 0;
            for i in (0..8).rev() {
                let nibble = ((v >> (i * 4)) & 0xF) as u8;
                buf[n] = if nibble < 10 {
                    b'0' + nibble
                } else {
                    b'A' + nibble - 10
                };
                n += 1;
            }
            n
        }
        fn hex_u64(buf: &mut [u8], v: u64) -> usize {
            let mut n = 0;
            for i in (0..16).rev() {
                let nibble = ((v >> (i * 4)) & 0xF) as u8;
                buf[n] = if nibble < 10 {
                    b'0' + nibble
                } else {
                    b'A' + nibble - 10
                };
                n += 1;
            }
            n
        }
        unsafe extern "system" {
            fn AddVectoredExceptionHandler(
                first: u32,
                handler: Option<unsafe extern "system" fn(*mut ExPtrs2) -> i32>,
            ) -> usize;
        }
        AddVectoredExceptionHandler(1, Some(early_veh)); // 1 = head (highest priority)

        // VEH self-test: trigger a deliberate access violation and verify VEH fires.
        #[cfg(debug_assertions)]
        {
            static VEH_TEST_FIRED: core::sync::atomic::AtomicBool =
                core::sync::atomic::AtomicBool::new(false);
            unsafe extern "system" fn veh_test_handler(info: *mut ExPtrs2) -> i32 {
                unsafe {
                    let info = &*info;
                    let code = core::ptr::read_unaligned(info.exception_record.cast::<u32>());
                    if code == 0xC0000005 {
                        // ACCESS_VIOLATION — skip the faulting instruction
                        VEH_TEST_FIRED.store(true, Relaxed);
                        let ctx = info.context_record.cast_mut();
                        let rip = core::ptr::read_unaligned(ctx.add(0xF8).cast::<u64>());
                        // Skip 2 bytes (the faulting mov [0], al instruction)
                        core::ptr::write_unaligned(ctx.add(0xF8).cast::<u64>(), rip + 2);
                        return -1; // EXCEPTION_CONTINUE_EXECUTION
                    }
                    0
                }
            }
            let test_h = AddVectoredExceptionHandler(1, Some(veh_test_handler));
            // Trigger access violation: write to address 0.
            core::arch::asm!(
                "xor eax, eax",
                "mov byte ptr [rax], al", // ACCESS_VIOLATION at addr 0
                out("rax") _,
            );
            // Verify VEH fired.
            unsafe extern "system" {
                fn RemoveVectoredExceptionHandler(handle: usize) -> u32;
            }
            RemoveVectoredExceptionHandler(test_h);
            if !VEH_TEST_FIRED.load(Relaxed) {
                eprintln!("[VEH-TEST] FAIL: VEH handler did NOT fire for test exception!");
            }
        }
    }

    // The EXE can come from --pe-file, or we look for it inside the tar.
    let pe_data = if let Some(pe_path) = &cli_args.pe_file {
        std::fs::read(pe_path)
            .map_err(|e| anyhow!("Could not read PE file at {}: {}", pe_path.display(), e))?
    } else {
        // Will extract from tar VFS below.
        Vec::new()
    };

    // Initialize platform.
    let platform = Platform::new(None);
    litebox_platform_multiplex::set_platform(platform);

    // If a network broker address was provided, connect and attach the IPC
    // stream to the platform before creating the smoltcp Network (which reads
    // from the platform's IPInterfaceProvider).
    if let Some(ref broker_addr) = cli_args.network_broker {
        let stream = connect_to_broker_ipc(broker_addr)?;
        platform.set_ipc_stream(stream);
    }

    let litebox = litebox::LiteBox::new(platform);

    // Create the smoltcp network stack if any network transport is configured.
    let net = if platform.has_network() {
        let mut n = litebox::net::Network::new(&litebox);
        n.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
        Some(Arc::new(spin::Mutex::new(n)))
    } else {
        None
    };

    // Allocate guest address space.
    // NOTE: prefer_slot0_for_first_address_space() is NOT used here.
    // Unlike the Linux-on-Windows runner, the Windows runner must NOT use
    // slot 0 because the host process's ASLR allocations overlap with
    // guest VA ranges in slot 0, causing STATUS_DLL_INIT_FAILED during
    // ntdll loader initialization.
    let as_id = platform
        .create_address_space()
        .map_err(|e| anyhow!("Failed to allocate address space: {e:?}"))?;
    let as_range = platform
        .address_space_range(as_id)
        .map_err(|e| anyhow!("Failed to get address space range: {e:?}"))?;
    let guest_va_start = as_range.start;
    let guest_va_end = as_range.end;

    #[allow(non_snake_case)]
    let PEB_TEB_BASE = guest_va_start + PEB_TEB_OFFSET;

    let pm = litebox::mm::PageManager::new(&litebox, as_range);
    let syscall_entry = platform.get_syscall_entry_point() as u64;

    // Create the process state that will be shared with the shim.
    // The runner uses pm via process_state.pm for all mapping operations.
    let process_state = alloc::sync::Arc::new(litebox_shim_windows::NtProcessState::new(pm));

    // ── Loading path ────────────────────────────────────────────────
    // Load real DLLs (ntdll with rewritten syscalls) and the EXE from
    // the tar-backed VFS. ntdll's LdrpInitialize loads all other DLLs
    // via syscalls that the shim intercepts and serves from VFS.
    struct LoadResult {
        exe_entry_point: usize,
        exe_image_base: usize,
        exe_image_size: usize,
        module_bases: Vec<litebox_shim_windows::ModuleBase>,
        /// VA of LdrInitializeThunk (thread entry point).
        ldr_init_thunk_va: usize,
        /// VA of RtlUserThreadStart (CONTEXT.Rip after init).
        rtl_user_thread_start_va: usize,
        /// Layered VFS for the shim (created early so boot can read from it).
        vfs: alloc::sync::Arc<litebox_shim_windows::NtFS>,
        /// Mapping from real Windows syscall numbers to NtSyscallId.
        syscall_map: litebox_common_windows::NtSyscallMap,
        /// Unhandled stub names for debug logging of unknown syscalls.
        unhandled_stubs: Vec<(u32, String)>,
        /// RVA of KiUserExceptionDispatcher in ntdll for SEH dispatch.
        ki_user_exception_dispatcher_rva: Option<usize>,
        /// Guest VA of ntdll's internal loader hash table.
        ldrp_hash_table_va: usize,
        /// Guest VA of ntdll's internal PebLdr.
        pebldr_va: usize,
        /// Cached ntdll boot data for child process spawning.
        ntdll_boot_data: alloc::sync::Arc<litebox_shim_windows::NtdllBootData>,
    }

    let load_result = {
        // ── ntdll-driven init path ────────────────────────────────
        // Load only ntdll (with rewritten syscalls) and the EXE.
        // ntdll's LdrpInitialize will load all other DLLs via syscalls
        // that we intercept and serve from the tar file.
        let tar_data = std::fs::read(&cli_args.dll_tar).map_err(|e| {
            anyhow!(
                "Could not read DLL tar at {}: {e}",
                cli_args.dll_tar.display()
            )
        })?;
        trace_debugln!(
            "[real-dlls] Read tar: {} ({} bytes)",
            cli_args.dll_tar.display(),
            tar_data.len(),
        );
        let host_launch_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("C:\\"));
        let host_launch_cwd = host_launch_cwd.canonicalize().unwrap_or(host_launch_cwd);
        let guest_host_files =
            collect_guest_argument_host_files(&cli_args.guest_arguments, &host_launch_cwd)?;

        // Create layered VFS early so both boot loading and the shim share it.
        // Architecture: InMemFS (writable) → DeviceFS → TarFS (read-only).
        let vfs_arc = {
            let dev_fs = litebox::fs::devices::FileSystem::new(&litebox);
            let tar_fs =
                litebox::fs::tar_ro::FileSystem::new(&litebox, alloc::borrow::Cow::Owned(tar_data));

            let mut in_mem = litebox::fs::in_mem::FileSystem::new(&litebox);
            let mut mirror_result: Result<()> = Ok(());
            in_mem.with_root_privileges(|fs| {
                use litebox::fs::FileSystem as _;

                // 0o777 — writable by all users so that user 1000 (the
                // sandbox guest) can create files in any directory.
                // This is a single-user sandbox so world-writable is fine.
                const DIR_MODE: litebox::fs::Mode = litebox::fs::Mode::RWXU
                    .union(litebox::fs::Mode::RWXG)
                    .union(litebox::fs::Mode::RWXO);
                const FILE_MODE: litebox::fs::Mode = litebox::fs::Mode::RUSR
                    .union(litebox::fs::Mode::WUSR)
                    .union(litebox::fs::Mode::RGRP)
                    .union(litebox::fs::Mode::ROTH);

                for dir in [
                    "/c",
                    "/c/program files",
                    "/c/program files/common files",
                    "/c/program files/common files/ssl",
                    // Temp directories — Python/Node.js expect writable TEMP/TMP
                    "/c/windows",
                    "/c/windows/temp",
                    // User-profile temp path (matches %USERPROFILE%\AppData\Local\Temp)
                    "/c/users",
                    "/c/users/sandbox",
                    "/c/users/sandbox/appdata",
                    "/c/users/sandbox/appdata/local",
                    "/c/users/sandbox/appdata/local/temp",
                ] {
                    let _ = fs.mkdir(dir, DIR_MODE);
                }
                if let Ok(fd) = fs.open(
                    "/c/program files/common files/ssl/openssl.cnf",
                    litebox::fs::OFlags::CREAT
                        | litebox::fs::OFlags::WRONLY
                        | litebox::fs::OFlags::TRUNC,
                    FILE_MODE,
                ) {
                    let _ = fs.close(&fd);
                }

                // Create the cwd directory (and ancestors) in VFS so
                // NtQueryAttributesFile checks on the cwd succeed.
                if let Some(cwd_str) = host_launch_cwd.to_str() {
                    let cwd_cleaned = cwd_str
                        .strip_prefix("\\\\?\\")
                        .unwrap_or(cwd_str);
                    if cwd_cleaned.len() >= 2 && cwd_cleaned.as_bytes()[1] == b':' {
                        let drive = (cwd_cleaned.as_bytes()[0] as char).to_ascii_lowercase();
                        let rest = &cwd_cleaned[2..];
                        let vfs_cwd = alloc::format!(
                            "/{drive}{}",
                            rest.replace('\\', "/").to_ascii_lowercase()
                        );
                        // Create each ancestor of the vfs_cwd path.
                        let mut accum = String::new();
                        for seg in vfs_cwd.split('/').filter(|s| !s.is_empty()) {
                            accum.push('/');
                            accum.push_str(seg);
                            let _ = fs.mkdir(&accum, DIR_MODE);
                        }
                    }
                }

                if mirror_result.is_ok() {
                    mirror_result = mirror_guest_host_files_into_vfs(
                        fs,
                        &guest_host_files,
                        DIR_MODE,
                        FILE_MODE,
                    );
                }
            });
            mirror_result?;

            let inner = litebox::fs::layered::FileSystem::new(
                &litebox,
                dev_fs,
                tar_fs,
                litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
            );
            let vfs = litebox::fs::layered::FileSystem::new(
                &litebox,
                in_mem,
                inner,
                litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
            );
            alloc::sync::Arc::new(vfs)
        };
        trace_debugln!("[vfs] Layered VFS created (InMemFS → DeviceFS → TarFS)");

        // Log VFS root entries for debugging.
        #[cfg(all(debug_assertions, feature = "trace_debug"))]
        {
            use litebox::fs::FileSystem as _;
            if let Ok(fd) = vfs_arc.open(
                "/",
                litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
                litebox::fs::Mode::RUSR,
            ) {
                if let Ok(entries) = vfs_arc.read_dir(&fd) {
                    trace_debugln!("[vfs] Root entries: {}", entries.len());
                    for e in &entries {
                        trace_debugln!("  /{}: {:?}", e.name, e.file_type);
                    }
                }
                let _ = vfs_arc.close(&fd);
            }
        }

        // Mirror the --pe-file EXE into the VFS so that child processes
        // (spawned via NtCreateUserProcess) can read the same binary from
        // the virtual filesystem.
        if !pe_data.is_empty() {
            if let Some(pe_path) = &cli_args.pe_file {
                let canon = pe_path
                    .canonicalize()
                    .ok()
                    .and_then(|p| p.to_str().map(std::string::ToString::to_string));
                let win32 = canon.unwrap_or_else(|| {
                    pe_path
                        .to_str()
                        .unwrap_or("C:\\app\\unknown.exe")
                        .to_string()
                });
                let win32 = win32.strip_prefix("\\\\?\\").unwrap_or(&win32);
                // Convert to VFS path: C:\Program Files\nodejs\node.exe → /c/program files/nodejs/node.exe
                if win32.len() >= 2 && win32.as_bytes()[1] == b':' {
                    let drive = (win32.as_bytes()[0] as char).to_ascii_lowercase();
                    let rest = &win32[2..];
                    let vfs_exe_path = format!(
                        "/{drive}{}",
                        rest.replace('\\', "/").to_ascii_lowercase()
                    );
                    use litebox::fs::FileSystem as _;
                    // Ensure parent directories exist.
                    ensure_vfs_parent_dirs(
                        &*vfs_arc,
                        &vfs_exe_path,
                        litebox::fs::Mode::RWXU
                            .union(litebox::fs::Mode::RWXG)
                            .union(litebox::fs::Mode::RWXO),
                    );
                    // Write the PE bytes.
                    if let Ok(fd) = vfs_arc.open(
                        &vfs_exe_path,
                        litebox::fs::OFlags::CREAT
                            | litebox::fs::OFlags::WRONLY
                            | litebox::fs::OFlags::TRUNC,
                        litebox::fs::Mode::RUSR
                            .union(litebox::fs::Mode::WUSR)
                            .union(litebox::fs::Mode::RGRP)
                            .union(litebox::fs::Mode::ROTH),
                    ) {
                        let mut offset = 0;
                        while offset < pe_data.len() {
                            match vfs_arc.write(&fd, &pe_data[offset..], None) {
                                Ok(n) if n > 0 => offset += n,
                                _ => break,
                            }
                        }
                        let _ = vfs_arc.close(&fd);
                        trace_debugln!(
                            "[vfs] Mirrored PE file into VFS: {} ({} bytes)",
                            vfs_exe_path,
                            pe_data.len()
                        );
                    } else {
                        trace_debugln!(
                            "[vfs] WARNING: Failed to mirror PE file into VFS: {}",
                            vfs_exe_path
                        );
                    }
                }
            }
        }

        // If no --pe-file, look for an EXE inside the VFS.
        let pe_data = if pe_data.is_empty() {
            let exe_path = real_dlls::find_vfs_file_by_name(&vfs_arc, ".exe")
                .or_else(|| {
                    // Search more broadly: list root and find any .exe file.
                    use litebox::fs::FileSystem as _;
                    let fd = vfs_arc
                        .open(
                            "/",
                            litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
                            litebox::fs::Mode::RUSR,
                        )
                        .ok()?;
                    let entries = vfs_arc.read_dir(&fd).ok()?;
                    let _ = vfs_arc.close(&fd);
                    entries.iter().find_map(|e| {
                        if e.name.len() >= 4
                            && e.name[e.name.len() - 4..].eq_ignore_ascii_case(".exe")
                        {
                            Some(format!("/{}", e.name))
                        } else {
                            None
                        }
                    })
                })
                .ok_or_else(|| anyhow!("No --pe-file and no .exe found in VFS"))?;
            trace_debugln!("[real-dlls] Using {exe_path} from VFS");
            real_dlls::read_vfs_file(&vfs_arc, &exe_path)?
        } else {
            pe_data
        };

        let exe_parsed = PeParsedFile::parse(&pe_data)
            .map_err(|e| anyhow!("Failed to parse PE executable: {e}"))?;

        let preferred_base = exe_parsed.image_base as usize;
        let exe_base = if preferred_base >= guest_va_start && preferred_base < guest_va_end {
            preferred_base
        } else {
            let base = (guest_va_start + 0xFFFF) & !0xFFFF;
            trace_debugln!("[real-dlls] Rebasing EXE from 0x{preferred_base:X} to 0x{base:X}");
            base
        };
        let mut pm_mapper = PmMapper::new(&process_state.pm);
        pm_mapper
            .pre_reserve(exe_base, exe_parsed.size_of_image as usize)
            .map_err(|e| anyhow!("Failed to reserve VA for EXE: {e:?}"))?;
        let exe_info = load_pe(&exe_parsed, &pe_data, exe_base, &mut pm_mapper)
            .map_err(|e| anyhow!("Failed to load PE executable: {e}"))?;

        // Patch the in-memory PE header's ImageBase to match the actual load
        // address. Without this, ntdll's loader would see ImageBase != DllBase
        // and apply relocations *again* (on top of the runner's), causing
        // double-relocation corruption.
        {
            use litebox::platform::RawConstPointer as _;
            let hdr_ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(exe_base);
            unsafe {
                let _ = process_state.pm.make_pages_writable(hdr_ptr, PAGE_SIZE);
                let pe_sig_off = *(exe_base as *const u32).byte_add(0x3C) as usize;
                let opt_hdr = exe_base + pe_sig_off + 0x18;
                let image_base_ptr = (opt_hdr + 0x18) as *mut u64;
                core::ptr::write(image_base_ptr, exe_base as u64);
                let _ = process_state.pm.make_pages_readable(hdr_ptr, PAGE_SIZE);
            }
        }

        trace_debugln!(
            "[real-dlls] EXE loaded at 0x{:X}, entry=0x{:X}",
            exe_info.image_base,
            exe_info.entry_point
        );

        // Load ntdll with rewritten syscalls + find LdrInitializeThunk.
        let result = real_dlls::load_ntdll_for_init(&vfs_arc, &mut pm_mapper, guest_va_start)?;

        // Map the trampoline page.
        let tramp_va = result.trampoline_va;
        let entry_off = result.entry_ptr_offset;

        let mut tramp_data = result.trampoline;
        tramp_data[entry_off..entry_off + 8].copy_from_slice(&syscall_entry.to_le_bytes());

        pm_mapper
            .pre_reserve(tramp_va, PAGE_SIZE)
            .map_err(|e| anyhow!("Failed to reserve trampoline page: {e:?}"))?;
        pm_mapper
            .map_section(
                tramp_va,
                &tramp_data,
                PAGE_SIZE,
                SectionPermissions::ReadExecute,
            )
            .map_err(|e| anyhow!("Failed to map trampoline: {e:?}"))?;

        trace_debugln!(
            "[real-dlls] Trampoline at 0x{tramp_va:X}, entry ptr at +0x{entry_off:X} = 0x{syscall_entry:X}"
        );
        // Store the trampoline code VA for win32k stub patching.
        // The first 0x08 bytes are one 8-byte pointer slot (shim entry);
        // code starts at +0x08.
        process_state.set_trampoline_code_va(tramp_va + 0x08);
        // Register the full trampoline page range with the platform so the
        // NtContinue/NtContinueEx gate excludes it from gating.  The trampoline
        // is transition code that happens to live in guest VA.
        litebox_platform_windows_userland::WindowsUserland::set_syscall_trampoline_range(
            tramp_va,
            tramp_va + PAGE_SIZE,
        );
        // Store KiUserInvertedFunctionTable VA so the shim can register DLLs
        // loaded via NtMapViewOfSection (needed for SEH unwinding).
        if result.inverted_function_table_va != 0 {
            process_state.set_inverted_function_table_va(result.inverted_function_table_va);
        }
        process_state.set_rtl_dispatch_exception_va(result.rtl_dispatch_exception_va);
        process_state.set_rtl_restore_context_va(result.rtl_restore_context_va);
        process_state.set_zw_raise_exception_va(result.zw_raise_exception_va);
        process_state.set_rtl_raise_status_va(result.rtl_raise_status_va);
        trace_debugln!(
            "[real-dlls] {} stubs rewritten ({} identified)",
            result.stubs_rewritten,
            result.stubs_identified
        );

        let module_bases = vec![
            litebox_shim_windows::ModuleBase {
                name: cli_args
                    .pe_file
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .and_then(|f| f.to_str())
                    .unwrap_or("app.exe")
                    .to_string(),
                path: cli_args
                    .pe_file
                    .as_ref()
                    .and_then(|p| p.canonicalize().ok())
                    .and_then(|p| p.to_str().map(std::string::ToString::to_string))
                    .unwrap_or_else(|| String::from("C:\\app.exe")),
                base_address: exe_info.image_base,
                image_size: exe_info.image_size,
            },
            litebox_shim_windows::ModuleBase {
                name: String::from("ntdll.dll"),
                path: String::from("C:\\Windows\\System32\\ntdll.dll"),
                base_address: result.ntdll.base_address,
                image_size: result.ntdll.image_size,
            },
        ];
        for module in &module_bases {
            process_state.register_module(module.clone());
            process_state.track_image_mapping(module.base_address, module.image_size);
        }

        // Build cached NtdllBootData for child process spawning.
        // All VAs are converted to RVAs (relative to ntdll load base at
        // partition_start + REAL_DLL_OFFSET) so they're partition-independent.
        let ntdll_base = result.ntdll.base_address;
        let to_rva = |va: usize| -> usize {
            if va == 0 { 0 } else { va - ntdll_base }
        };
        let ntdll_boot_data = alloc::sync::Arc::new(litebox_shim_windows::NtdllBootData {
            image: result.ntdll.pe_data,
            trampoline: tramp_data.clone(),
            syscall_entry,
            syscall_map: result.syscall_map.clone(),
            unhandled_stubs: result.unhandled_stubs.clone(),
            ldr_init_thunk_rva: to_rva(result.ldr_init_thunk_va),
            rtl_user_thread_start_rva: to_rva(result.rtl_user_thread_start_va),
            ki_user_exception_dispatcher_rva: result.ki_user_exception_dispatcher_rva,
            rtl_dispatch_exception_rva: to_rva(result.rtl_dispatch_exception_va),
            rtl_restore_context_rva: to_rva(result.rtl_restore_context_va),
            zw_raise_exception_rva: to_rva(result.zw_raise_exception_va),
            rtl_raise_status_rva: to_rva(result.rtl_raise_status_va),
            inverted_function_table_rva: to_rva(result.inverted_function_table_va),
            ldrp_hash_table_rva: to_rva(result.ldrp_hash_table_va),
            pebldr_rva: to_rva(result.pebldr_va),
        });

        LoadResult {
            exe_entry_point: exe_info.entry_point,
            exe_image_base: exe_info.image_base,
            exe_image_size: exe_info.image_size,
            module_bases,
            ldr_init_thunk_va: result.ldr_init_thunk_va,
            rtl_user_thread_start_va: result.rtl_user_thread_start_va,
            vfs: vfs_arc,
            syscall_map: result.syscall_map,
            unhandled_stubs: result.unhandled_stubs,
            ki_user_exception_dispatcher_rva: result.ki_user_exception_dispatcher_rva,
            ldrp_hash_table_va: result.ldrp_hash_table_va,
            pebldr_va: result.pebldr_va,
            ntdll_boot_data,
        }
    };

    // ── 9P broker: optionally layer remote filesystem ───────────
    // If --nine-p-broker is specified, connect to the 9P file broker and
    // layer its remote filesystem underneath the local tar/in-mem VFS.
    // This is needed for large package trees (e.g. copilot) whose paths
    // exceed USTAR's 100-char filename limit.
    if let Some(ref broker_addr) = cli_args.nine_p_broker {
        eprintln!("Connecting to 9P broker at {broker_addr}...");
        let (ring_writer, ring_reader) = connect_nine_p_channel(broker_addr)?;

        let writer = ShmemTransportWriter(ring_writer);
        let reader = ShmemTransportReader(ring_reader);
        let msize = 4 * 1024 * 1024u32;
        let (nine_p_fs, mut reader) =
            litebox::fs::nine_p::FileSystem::new(&litebox, writer, reader, msize, "root", "/")
                .map_err(|e| anyhow!("9P attach failed: {e:?}"))?;
        eprintln!("9P broker connected.");

        // Spawn background 9P response worker thread.
        let worker_handle = nine_p_fs.worker_handle();
        let _nine_p_worker = std::thread::spawn(move || {
            let mut buf = alloc::vec::Vec::with_capacity(msize as usize);
            while worker_handle.poll_responses(&mut reader, &mut buf) {}
        });

        // Layer: local VFS (upper, writable) over 9P remote FS (lower, writable files).
        let base_vfs = alloc::sync::Arc::try_unwrap(load_result.vfs)
            .unwrap_or_else(|arc| {
                // If there are other Arc references, clone the inner FS.
                // This shouldn't happen in practice since load_result owns the only Arc.
                panic!("Expected sole ownership of VFS Arc for 9P layering, but found {} references", alloc::sync::Arc::strong_count(&arc));
            });
        let combined = litebox::fs::layered::FileSystem::new(
            &litebox,
            base_vfs,
            nine_p_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
        );
        let combined_arc = alloc::sync::Arc::new(combined);

        return create_shim_and_run(
            combined_arc,
            &cli_args,
            &litebox,
            load_result.syscall_map,
            load_result.unhandled_stubs,
            load_result.ntdll_boot_data,
            load_result.exe_entry_point,
            load_result.exe_image_base,
            load_result.exe_image_size,
            load_result.module_bases,
            load_result.ldr_init_thunk_va,
            load_result.rtl_user_thread_start_va,
            load_result.ki_user_exception_dispatcher_rva,
            load_result.ldrp_hash_table_va,
            load_result.pebldr_va,
            &process_state,
            guest_va_start,
            guest_va_end,
            PEB_TEB_BASE,
            net,
        );
    }

    // ── No 9P: use the tar/in-mem VFS directly ─────────────────
    create_shim_and_run(
        load_result.vfs,
        &cli_args,
        &litebox,
        load_result.syscall_map,
        load_result.unhandled_stubs,
        load_result.ntdll_boot_data,
        load_result.exe_entry_point,
        load_result.exe_image_base,
        load_result.exe_image_size,
        load_result.module_bases,
        load_result.ldr_init_thunk_va,
        load_result.rtl_user_thread_start_va,
        load_result.ki_user_exception_dispatcher_rva,
        load_result.ldrp_hash_table_va,
        load_result.pebldr_va,
        &process_state,
        guest_va_start,
        guest_va_end,
        PEB_TEB_BASE,
        net,
    )
}

/// Create the NT shim with the given VFS, configure it, and run the guest.
///
/// Generic over the filesystem type `FS` so the same code works with either
/// the plain tar/in-mem VFS (`NtFS`) or a 9P-layered variant.
#[allow(clippy::too_many_arguments)]
fn create_shim_and_run<FS: litebox_shim_windows::NtShimFS>(
    vfs: alloc::sync::Arc<FS>,
    cli_args: &CliArgs,
    litebox: &litebox::LiteBox<Platform>,
    syscall_map: litebox_common_windows::NtSyscallMap,
    unhandled_stubs: Vec<(u32, String)>,
    ntdll_boot_data: alloc::sync::Arc<litebox_shim_windows::NtdllBootData>,
    exe_entry_point: usize,
    exe_image_base: usize,
    exe_image_size: usize,
    module_bases: Vec<litebox_shim_windows::ModuleBase>,
    ldr_init_thunk_va: usize,
    rtl_user_thread_start_va: usize,
    ki_user_exception_dispatcher_rva: Option<usize>,
    ldrp_hash_table_va: usize,
    pebldr_va: usize,
    process_state: &alloc::sync::Arc<litebox_shim_windows::NtProcessState>,
    guest_va_start: usize,
    guest_va_end: usize,
    #[allow(non_snake_case)] PEB_TEB_BASE: usize,
    net: Option<Arc<spin::Mutex<litebox::net::Network<Platform>>>>,
) -> Result<()> {
    let stack_size = NonZeroPageSize::<PAGE_SIZE>::new(GUEST_STACK_SIZE)
        .expect("stack size must be page-aligned");
    let stack_base_ptr = unsafe {
        process_state.pm.create_writable_pages(
            None,
            stack_size,
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_ptr| Ok(0), // zero-fill
        )
    }
    .map_err(|e| anyhow!("Failed to allocate guest stack: {e:?}"))?;
    let stack_base = stack_base_ptr.as_usize();
    let stack_alloc_top = stack_base + GUEST_STACK_SIZE;
    // Reserve space at the top of the stack for shadow space and alignment.
    // The PE entry point is a tail-call target (`jmp __scrt_common_main_seh`)
    // that may write to [rsp+8..rsp+20h] (shadow space). The OS normally
    // provides this headroom; we simulate it by lowering RSP.
    // Layout: [return_addr=0][shadow0][shadow1][shadow2][shadow3]
    // 8 bytes return addr + 32 bytes shadow = 40 bytes.
    trace_debugln!(
        "Stack: base=0x{stack_base:X}, top=0x{:X}",
        stack_alloc_top - 0x28
    );

    // Synthesize PEB/TEB.
    let mut shim =
        litebox_shim_windows::NtShimEntrypoints::new(
            alloc::sync::Arc::clone(&process_state),
            litebox.clone(),
        );
    shim.set_syscall_map(syscall_map);
    if !unhandled_stubs.is_empty() {
        shim.set_unhandled_stubs(unhandled_stubs);
    }
    shim.set_ntdll_boot_data(ntdll_boot_data);
    let (stdin_h, stdout_h, stderr_h) = shim.stdio_handles();

    let peb_teb_layout = PebTebLayout::at_base(PEB_TEB_BASE);

    // PEB.ProcessHeap is set to 0 so that ntdll's LdrpInitialize creates
    // the process heap in the guest VA range via RtlCreateHeap (which calls
    // NtAllocateVirtualMemory through our shim).  Setting this to a host
    // HeapCreate handle causes heap metadata corruption because the host
    // and guest ntdll versions may differ.
    let process_heap: usize = 0;

    // Derive EXE names for PEB/TEB LDR entries from the actual PE file path.
    let (exe_full_path_str, exe_base_name_str) = if let Some(pe_path) = &cli_args.pe_file {
        let canon = pe_path
            .canonicalize()
            .ok()
            .and_then(|p| p.to_str().map(std::string::ToString::to_string));
        let full = canon.unwrap_or_else(|| {
            pe_path
                .to_str()
                .unwrap_or("C:\\app\\unknown.exe")
                .to_string()
        });
        // Strip \\?\ prefix that canonicalize adds on Windows
        let full = full.strip_prefix("\\\\?\\").unwrap_or(&full).to_string();
        let base = pe_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown.exe")
            .to_string();
        (full, base)
    } else {
        ("C:\\app\\hello.exe".to_string(), "hello.exe".to_string())
    };
    let startup_cwd = std::env::current_dir()
        .map(|cwd| cwd.canonicalize().unwrap_or(cwd))
        .ok()
        .and_then(|cwd| cwd.to_str().map(std::string::ToString::to_string))
        .unwrap_or_else(|| String::from("C:\\"));
    let mut startup_cwd = startup_cwd
        .strip_prefix("\\\\?\\")
        .unwrap_or(&startup_cwd)
        .to_string();
    if !startup_cwd.ends_with('\\') {
        startup_cwd.push('\\');
    }

    // Read the host's API set map address from the host PEB. The guest runs
    // in the same address space, so the host's map is directly accessible.
    #[allow(clippy::cast_ptr_alignment)]
    let host_api_set_map: usize = unsafe {
        let host_peb: *const u8;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) host_peb, options(nostack, readonly));
        *host_peb.add(0x68).cast::<usize>()
    };
    trace_debugln!("Host ApiSetMap at: 0x{host_api_set_map:X}");

    // Allocate a zeroed region for the GDI shared handle table. gdi32full's
    // GdiProcessSetup (when gbFirst==0) reads PEB+0xF8 and stores it as
    // gpHandleTable, then gpHandleTable+0x180000 as pGdiSharedMemory.
    // We allocate 0x200000 (2 MB) to cover both.
    const GDI_SHARED_SIZE: usize = 0x20_0000;
    let gdi_shared_va = {
        let nz_size = NonZeroPageSize::<PAGE_SIZE>::new(GDI_SHARED_SIZE)
            .expect("GDI shared size must be page-aligned");
        let ptr = unsafe {
            process_state.pm.create_writable_pages(
                None,
                nz_size,
                CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                |_| Ok(0),
            )
        }
        .map_err(|e| anyhow!("Failed to allocate GDI shared handle table: {e:?}"))?;
        use litebox::platform::RawConstPointer as _;
        ptr.as_usize()
    };
    trace_debugln!("GDI shared handle table at: 0x{gdi_shared_va:X}");

    // Inject DNS patch for Node.js-based processes when networking is enabled.
    // This patches dns.lookup to use c-ares (direct UDP) instead of
    // GetAddrInfoW which requires the Windows DNS Client service.
    let (dns_patch_args, dns_patch_env) = inject_dns_patch(
        vfs.as_ref(),
        &exe_base_name_str,
        net.is_some(),
    );
    let mut effective_guest_args = Vec::new();
    effective_guest_args.extend(dns_patch_args);
    effective_guest_args.extend(cli_args.guest_arguments.iter().cloned());

    let guest_command_line =
        build_guest_command_line(&exe_base_name_str, &effective_guest_args);
    trace_debugln!("[runner] Guest command line: {guest_command_line}");

    let peb_teb_params = PebTebParams {
        stack_base: stack_alloc_top,
        stack_limit: stack_base,
        image_base: exe_image_base,
        image_size: exe_image_size,
        process_heap,
        command_line_wide: guest_command_line.encode_utf16().collect(),
        image_path_wide: format!("\\??\\{exe_full_path_str}")
            .encode_utf16()
            .collect(),
        exe_full_path: exe_full_path_str.encode_utf16().collect(),
        exe_base_name: exe_base_name_str.encode_utf16().collect(),
        current_directory_wide: startup_cwd.encode_utf16().collect(),
        stdin_handle: u64::from(stdin_h),
        stdout_handle: u64::from(stdout_h),
        stderr_handle: u64::from(stderr_h),
        ntdll_base: module_bases
            .iter()
            .find(|m| m.name == "ntdll.dll")
            .map_or(0, |m| m.base_address),
        ntdll_size: module_bases
            .iter()
            .find(|m| m.name == "ntdll.dll")
            .map_or(0, |m| m.image_size),
        process_id: u64::from(litebox_shim_windows::peb_teb::SYNTHETIC_PROCESS_ID),
        thread_id: u64::from(litebox_shim_windows::peb_teb::SYNTHETIC_MAIN_THREAD_ID),
        api_set_map: host_api_set_map,
        gdi_shared_handle_table: gdi_shared_va,
        env_strings: {
            let has_explicit_env = !cli_args.env_vars.is_empty() || dns_patch_env.is_some();
            if !has_explicit_env {
                Vec::new() // use default hardcoded env for root process
            } else {
                // When extra env vars are provided, we must supply the full
                // environment because the PEB builder replaces (not merges)
                // when env_strings is non-empty.
                let mut env = vec![
                    "SYSTEMROOT=C:\\Windows".into(),
                    "COMSPEC=C:\\Windows\\System32\\cmd.exe".into(),
                    "PATH=C:\\Windows\\System32".into(),
                    "TEMP=C:\\Windows\\Temp".into(),
                    "TMP=C:\\Windows\\Temp".into(),
                    "USERPROFILE=C:\\Users\\sandbox".into(),
                    "HOMEDRIVE=C:".into(),
                    "HOMEPATH=\\Users\\sandbox".into(),
                    "APPDATA=C:\\Users\\sandbox\\AppData".into(),
                    "LOCALAPPDATA=C:\\Users\\sandbox\\AppData\\Local".into(),
                    "PYTHONHASHSEED=0".into(),
                    "PYTHONLEGACYWINDOWSSTDIO=1".into(),
                    "PYTHONUNBUFFERED=1".into(),
                ];
                if let Some(dns_env) = dns_patch_env {
                    env.push(dns_env);
                }
                env.extend(cli_args.env_vars.iter().cloned());
                env
            }
        },
    };
    let peb_teb_bytes = build_peb_teb_bytes(&peb_teb_layout, &peb_teb_params);

    // Map PEB/TEB region as RW.
    let peb_teb_size = NonZeroPageSize::<PAGE_SIZE>::new(peb_teb_layout.total_size)
        .expect("PEB/TEB size must be page-aligned");
    let peb_teb_addr =
        NonZeroAddress::<PAGE_SIZE>::new(PEB_TEB_BASE).expect("PEB/TEB base must be page-aligned");
    unsafe {
        process_state.pm.create_writable_pages(
            Some(peb_teb_addr),
            peb_teb_size,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |ptr| {
                ptr.copy_from_slice(0, &peb_teb_bytes)
                    .ok_or(litebox::mm::linux::MappingError::OutOfMemory)?;
                Ok(peb_teb_layout.total_size)
            },
        )
    }
    .map_err(|e| anyhow!("Failed to map PEB/TEB: {e:?}"))?;

    unsafe {
        init_ntdll_pebldr(
            peb_teb_layout.peb_va,
            pebldr_va,
            peb_teb_layout.ldr_data_va,
        );
        init_ntdll_loader_globals(pebldr_va, peb_teb_layout.ldr_data_va);
        init_ntdll_loader_hash_table(ldrp_hash_table_va, peb_teb_layout.ldr_data_va);
    }
    trace_debugln!(
        "[real-dlls] Seeded internal PebLdr at 0x{:X}",
        pebldr_va
    );
    trace_debugln!("[real-dlls] Seeded LdrpImageEntry/LdrpNtDllDataTableEntry");
    trace_debugln!(
        "[real-dlls] Seeded LdrpHashTable at 0x{:X} with EXE/ntdll entries",
        ldrp_hash_table_va
    );

    #[cfg(all(debug_assertions, feature = "trace_debug"))]
    {
        trace_debugln!(
            "PEB/TEB mapped at 0x{:X} (TEB=0x{:X}, PEB=0x{:X})",
            PEB_TEB_BASE,
            peb_teb_layout.teb_va,
            peb_teb_layout.peb_va
        );
        // Dump the LDR module entries to verify correctness.
        let ldr_va = peb_teb_layout.ldr_data_va;
        unsafe {
            let peb_image_base = core::ptr::read((peb_teb_layout.peb_va + 0x10) as *const u64);
            let peb_ldr_ptr = core::ptr::read((peb_teb_layout.peb_va + 0x18) as *const u64);
            trace_debugln!(
                "[LDR-verify] PEB.ImageBaseAddress=0x{peb_image_base:X}, PEB.Ldr=0x{peb_ldr_ptr:X} (synthetic 0x{ldr_va:X}, internal 0x{:X})",
                pebldr_va
            );

            // EXE entry at ldr_va + 0x60
            let exe_dll_base = core::ptr::read((ldr_va + 0x60 + 0x30) as *const u64);
            let exe_size = core::ptr::read((ldr_va + 0x60 + 0x40) as *const u32);
            let exe_load_order_next = core::ptr::read((ldr_va + 0x60) as *const u64);
            let exe_load_order_prev = core::ptr::read((ldr_va + 0x60 + 0x08) as *const u64);
            trace_debugln!(
                "[LDR-verify] EXE entry(0x{:X}): DllBase=0x{exe_dll_base:X} SizeOfImage=0x{exe_size:X} Flink=0x{exe_load_order_next:X} Blink=0x{exe_load_order_prev:X}",
                ldr_va + 0x60
            );

            // ntdll entry at ldr_va + 0x180
            let ntdll_dll_base = core::ptr::read((ldr_va + 0x180 + 0x30) as *const u64);
            let ntdll_size = core::ptr::read((ldr_va + 0x180 + 0x40) as *const u32);
            let ntdll_load_order_next = core::ptr::read((ldr_va + 0x180) as *const u64);
            let ntdll_load_order_prev = core::ptr::read((ldr_va + 0x180 + 0x08) as *const u64);
            trace_debugln!(
                "[LDR-verify] ntdll entry(0x{:X}): DllBase=0x{ntdll_dll_base:X} SizeOfImage=0x{ntdll_size:X} Flink=0x{ntdll_load_order_next:X} Blink=0x{ntdll_load_order_prev:X}",
                ldr_va + 0x180
            );

            // Head pointers
            let load_order_head_next = core::ptr::read((ldr_va + 0x10) as *const u64);
            let load_order_head_prev = core::ptr::read((ldr_va + 0x18) as *const u64);
            trace_debugln!(
                "[LDR-verify] InLoadOrderModuleList head(0x{:X}): Flink=0x{load_order_head_next:X} Blink=0x{load_order_head_prev:X}",
                ldr_va + 0x10
            );
        }
    }

    // Derive the EXE path for bookkeeping.
    let exe_full_path = module_bases
        .first()
        .map_or_else(|| String::from("C:\\app.exe"), |m| m.path.clone());

    // Build a CONTEXT on the guest stack and set the entry point to
    // LdrInitializeThunk. ntdll's loader will initialize the process and
    // then NtContinue to the real entry point (RtlUserThreadStart).
    let ldr_init_va = ldr_init_thunk_va;
    let rtl_uts_va = rtl_user_thread_start_va;
    let (effective_entry_point, effective_stack_top, context_ptr_arg, ntdll_base_arg) = {
        // Windows x64 CONTEXT structure layout (1232 = 0x4D0 bytes).
        const CONTEXT_SIZE: usize = 0x4D0;
        // CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
        const CONTEXT_FULL: u32 = 0x10_000B;

        // Place CONTEXT at the top of the stack (16-byte aligned).
        let context_va = (stack_alloc_top - CONTEXT_SIZE) & !0xF;
        // LdrInitializeThunk's own stack: below the CONTEXT with shadow space.
        let ldr_rsp = context_va - 0x28;

        // Build the CONTEXT that LdrInitializeThunk will pass to NtContinue
        // after initialization is complete. This describes the post-init state.
        let mut ctx_bytes = vec![0u8; CONTEXT_SIZE];
        let default_fp = litebox_common_linux::FpRegs::default();
        // ContextFlags at offset 0x30
        ctx_bytes[0x30..0x34].copy_from_slice(&CONTEXT_FULL.to_le_bytes());
        // EFlags at 0x44: IF + reserved bit 1
        ctx_bytes[0x44..0x48].copy_from_slice(&0x202u32.to_le_bytes());
        // SegCs at 0x38 = 0x33 (user-mode 64-bit CS)
        ctx_bytes[0x38..0x3A].copy_from_slice(&0x33u16.to_le_bytes());
        // SegSs at 0x42 = 0x2B (user-mode SS)
        ctx_bytes[0x42..0x44].copy_from_slice(&0x2Bu16.to_le_bytes());
        // Rcx at 0x80 = EXE entry point (first param to RtlUserThreadStart)
        ctx_bytes[0x80..0x88].copy_from_slice(&(exe_entry_point as u64).to_le_bytes());
        // Rdx at 0x88 = 0 (second param: thread parameter)
        ctx_bytes[0x88..0x90].copy_from_slice(&0u64.to_le_bytes());
        // Rsp at 0x98 = clean stack below the context.
        //
        // RtlUserThreadStart expects Windows x64 function-entry alignment:
        // RSP % 16 == 8 on entry. A real CALL would have pushed an 8-byte
        // return address; NtContinue does not, so we must bias the restored
        // RSP by +8 ourselves to preserve the same invariant.
        ctx_bytes[0x98..0xA0].copy_from_slice(&((context_va - 0x1F8) as u64).to_le_bytes());
        // Rip at 0xF8 = RtlUserThreadStart
        ctx_bytes[0xF8..0x100].copy_from_slice(&(rtl_uts_va as u64).to_le_bytes());
        // Seed both the top-level MxCsr field and CONTEXT.FltSave with sane
        // default FP/SIMD state. NtContinue restores from FltSave, so leaving
        // the FXSAVE area zeroed would start the guest with MXCSR=0 and
        // unmask floating-point exceptions.
        ctx_bytes[0x34..0x38].copy_from_slice(&default_fp.data[24..28]);
        ctx_bytes[0x100..0x100 + 512].copy_from_slice(&default_fp.data[..512]);

        // Write CONTEXT bytes to guest stack memory.
        unsafe {
            core::ptr::copy_nonoverlapping(ctx_bytes.as_ptr(), context_va as *mut u8, CONTEXT_SIZE);
        }

        // ntdll base address for the 2nd parameter to LdrInitializeThunk.
        let ntdll_base = module_bases
            .iter()
            .find(|m| m.name == "ntdll.dll")
            .map_or(0, |m| m.base_address);

        trace_debugln!(
            "[ntdll-init] CONTEXT at 0x{context_va:X} (Rip=0x{rtl_uts_va:X}, \
                  Rcx=0x{:X}), LdrInitializeThunk at 0x{ldr_init_va:X}, RSP=0x{ldr_rsp:X}, \
                 ntdll_base=0x{ntdll_base:X}",
            exe_entry_point
        );

        (ldr_init_va, ldr_rsp, context_va, ntdll_base)
    };

    // Set up initial thread state.
    shim.set_init_state(litebox_shim_windows::NtInitState {
        entry_point: effective_entry_point,
        stack_top: effective_stack_top,
        teb_va: peb_teb_layout.teb_va,
        peb_va: peb_teb_layout.peb_va,
        image_base: exe_image_base,
        image_size: exe_image_size,
        process_params_va: peb_teb_layout.process_params_va,
        cmdline_ansi_va: peb_teb_layout.cmdline_ansi_buffer_va,
        env_block_va: peb_teb_layout.env_block_va,
        module_bases: module_bases,
        guest_va_start,
        guest_va_end,
        exe_path: exe_full_path,
        current_directory: startup_cwd,
        initial_rcx: context_ptr_arg,
        initial_rdx: ntdll_base_arg,
        rtl_user_thread_start_va: rtl_user_thread_start_va,
        ldr_init_thunk_va: ldr_init_thunk_va,
        ki_user_exception_dispatcher_rva: ki_user_exception_dispatcher_rva,
    });

    // Capture NLS data from host and pass to shim (so shim doesn't call host APIs).
    if let Some(nls) = capture_host_nls_data() {
        shim.set_nls_data(nls);
    }

    // Pass the pre-built VFS to the shim for file I/O.
    shim.set_fs(vfs);

    // Attach the network stack to the shim for WinSock syscall dispatch.
    if let Some(ref net_arc) = net {
        shim.set_network(alloc::sync::Arc::clone(net_arc));
    }

    // Start the network worker thread if networking is configured.
    let shutdown = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let network_thread = start_network_worker(net.as_ref(), &shutdown);

    // Run the guest.
    // Tell the platform to set FS = guest TEB before entering guest code.
    litebox_platform_windows_userland::WindowsUserland::set_guest_va_range(
        guest_va_start..guest_va_end,
    );
    litebox_platform_windows_userland::WindowsUserland::set_guest_teb_base(
        peb_teb_layout.teb_va as u64,
    );
    let mut ctx = litebox_common_linux::ExecutionContext::default();

    // Diagnostic watchdog: monitors thread progress and force-terminates
    // the process if all threads appear stuck.
    let diag = shim.diagnostics();
    let _watchdog = std::thread::spawn(move || {
        // Wait for the guest to get past init before checking.
        std::thread::sleep(std::time::Duration::from_secs(3));
        // Check every second for stuck threads.
        let mut prev_terminated = 0u32;
        let mut stall_count = 0u32;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let created = diag.created_count();
            let terminated = diag.terminated_count();
            let live = diag.live_child_count();

            if diag.process_exit_requested() {
                // Process is shutting down normally.
                break;
            }
            if created == 0 {
                // Not started yet, keep waiting.
                stall_count = 0;
                prev_terminated = 0;
                continue;
            }
            if live == 0 {
                // All children done.
                stall_count = 0;
                prev_terminated = terminated;
                continue;
            }
            // There are live children. Check for progress.
            if terminated == prev_terminated {
                stall_count += 1;
            } else {
                stall_count = 0;
                prev_terminated = terminated;
            }
            // After 5 seconds of no progress (5 checks × 1s), dump state
            // and force-terminate.
            if stall_count >= 5 {
                let states = diag.thread_states();
                let recent_alert_posts = diag.recent_alert_posts();
                let recent_chain_events = diag.recent_chain_events();
                let mut msg = format!(
                    "[watchdog] No progress for 10s. created={created} terminated={terminated} live={live}\n"
                );
                for (
                    tid,
                    nr,
                    syscall_id,
                    last_rip,
                    last_rsp,
                    last_caller_ret,
                    last_wait_alert_addr,
                    last_incoming_alert_lock,
                    last_outgoing_alert_target_tid,
                    last_outgoing_alert_lock,
                    pending_any,
                    pending_by_id,
                    alert_waiters,
                    alert_by_id_waiters,
                    alert_posts,
                    alert_consumes,
                    tls_array_ptr,
                    tls_recopied,
                    tls_null,
                    tls_skipped,
                    alert_history,
                    debug_stage,
                    exit_stage,
                    exited,
                ) in &states
                {
                    use std::fmt::Write;
                    let _ = writeln!(
                        msg,
                        "[watchdog]   tid={tid} last_syscall=0x{nr:X} ({syscall_id:?}) last_rip=0x{last_rip:X} last_rsp=0x{last_rsp:X} caller=0x{last_caller_ret:X} wait_addr=0x{last_wait_alert_addr:X} incoming_lock=0x{last_incoming_alert_lock:X} outgoing={last_outgoing_alert_target_tid}/0x{last_outgoing_alert_lock:X} pending={pending_any}/{pending_by_id} waiters={alert_waiters}/{alert_by_id_waiters} alerts={alert_posts}/{alert_consumes} tls=0x{tls_array_ptr:X}/{tls_recopied}/{tls_null}/{tls_skipped} hist={alert_history} debug_stage=0x{debug_stage:X} exit_stage={exit_stage} exited={exited}"
                    );
                }
                if !recent_alert_posts.is_empty() {
                    msg.push_str("[watchdog]   recent_alert_posts=");
                    msg.push_str(&recent_alert_posts);
                    msg.push('\n');
                }
                if !recent_chain_events.is_empty() {
                    msg.push_str("[watchdog]   recent_chain_events=");
                    msg.push_str(&recent_chain_events);
                    msg.push('\n');
                }
                eprint!("{msg}");
                diag.force_terminate(0);
                break;
            }
        }
    });

    unsafe {
        litebox_platform_windows_userland::run_thread_ref(&shim, &mut ctx);
    }
    eprintln!("[runner] run_thread_ref returned");

    // Signal network worker to stop and wait for it.
    shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
    // Also mark the IPC transport dead so any in-progress send loop exits.
    {
        let platform = litebox_platform_multiplex::platform();
        if platform.has_network() {
            platform.poison_ipc();
        }
    }
    if let Some(handle) = network_thread {
        let _ = handle.join();
    }

    let exit_code = shim.exit_code();
    let (created, terminated, live) = shim.thread_diagnostics();
    let diagnostics = shim.diagnostics();
    let recent_chain_events = diagnostics.recent_chain_events();
    let recent_vm_teardowns = diagnostics.recent_vm_teardowns();
    let msg = format!(
        "[runner] Exiting with code 0x{:X} ({}). Regs: rip=0x{:X} rsp=0x{:X} rax=0x{:X} threads: created={} terminated={} live={}\n",
        exit_code as u32,
        exit_code,
        ctx.regs.rip,
        ctx.regs.rsp,
        ctx.regs.rax,
        created,
        terminated,
        live,
    );
    #[cfg(all(debug_assertions, feature = "trace_debug"))]
    write_trace_log("runner_exit.txt", msg.as_bytes());
    // Only print to stderr when there was an error or stuck threads.
    if exit_code != 0 || live != 0 {
        eprintln!("{msg}");
        if !recent_chain_events.is_empty() {
            eprintln!("[runner] recent_chain_events={recent_chain_events}");
        }
        if !recent_vm_teardowns.is_empty() {
            eprintln!("[runner] recent_vm_teardowns={recent_vm_teardowns}");
        }
    }
    // Use TerminateProcess to forcibly exit, bypassing atexit handlers and
    // DLL detach notifications that may deadlock if child host threads are
    // still in the process of shutting down.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn TerminateProcess(handle: *mut core::ffi::c_void, code: u32) -> i32;
    }
    unsafe { TerminateProcess(GetCurrentProcess(), exit_code as u32) };
    unreachable!()
}

/// PM-backed mapper for real DLL loading.
///
/// Uses the PageManager for all memory operations, mirroring how the
/// Linux runner routes ELF segment loading through `sys_mmap()` → platform.
/// This ensures the PM tracks every page, so `NtQueryVirtualMemory`,
/// `NtProtectVirtualMemory`, etc. work correctly for DLL and EXE regions.
///
/// Call `pre_reserve()` to allocate the full image range as writable
/// pages through the PM, then `map_section()` copies data and adjusts
/// per-section permissions.
struct PmMapper<'a> {
    pub(crate) pm: &'a litebox::mm::PageManager<Platform, PAGE_SIZE>,
}

impl<'a> PmMapper<'a> {
    fn new(pm: &'a litebox::mm::PageManager<Platform, PAGE_SIZE>) -> Self {
        Self { pm }
    }

    /// Reserve the full PE image range as writable pages via the PageManager.
    fn pre_reserve(&self, base: usize, size: usize) -> Result<(), PeLoadError> {
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        trace_debugln!("[pm-mapper] pre_reserve(0x{base:X}, 0x{aligned:X})");
        let addr = NonZeroAddress::<PAGE_SIZE>::new(base).ok_or(PeLoadError::MapFailed)?;
        let page_size = NonZeroPageSize::<PAGE_SIZE>::new(aligned).ok_or(PeLoadError::MapFailed)?;
        let flags = CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
        // Allocate as writable so map_section() can copy data into each section.
        unsafe {
            self.pm
                .create_writable_pages(Some(addr), page_size, flags, |_| Ok(0))
        }
        .map_err(|e| {
            #[cfg(not(all(debug_assertions, feature = "trace_debug")))]
            let _ = &e;
            trace_debugln!("[pm-mapper] pre_reserve FAILED: {e:?}");
            PeLoadError::MapFailed
        })?;
        Ok(())
    }
}

impl PeMemoryMapper for PmMapper<'_> {
    fn map_section(
        &mut self,
        va: usize,
        data: &[u8],
        size: usize,
        perm: SectionPermissions,
    ) -> Result<(), PeLoadError> {
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        trace_debugln!(
            "[pm-mapper] map_section(0x{va:X}, data_len={}, size=0x{size:X}/{aligned:X}, perm={perm:?})",
            data.len()
        );

        // Pages are already committed-writable from pre_reserve().
        // Copy section data.
        if !data.is_empty() {
            unsafe {
                let copy_len = data.len().min(size);
                core::ptr::copy_nonoverlapping(data.as_ptr(), va as *mut u8, copy_len);
            }
        }
        if data.len() < size {
            unsafe {
                core::ptr::write_bytes((va + data.len()) as *mut u8, 0, size - data.len());
            }
        }

        // Adjust protection to match the section's intended permissions.
        let ptr =
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::from_usize(va);
        match perm {
            SectionPermissions::ReadExecute => unsafe {
                self.pm.make_pages_executable(ptr, aligned)
            },
            SectionPermissions::ReadOnly => unsafe { self.pm.make_pages_readable(ptr, aligned) },
            SectionPermissions::ReadWrite => {
                // Already writable from pre_reserve — nothing to do.
                Ok(())
            }
        }
        .map_err(|e| {
            #[cfg(not(all(debug_assertions, feature = "trace_debug")))]
            let _ = &e;
            trace_debugln!("[pm-mapper] permission change FAILED: {e:?}");
            PeLoadError::MapFailed
        })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 9P file broker support
// ---------------------------------------------------------------------------

/// Wraps a shmem ring writer for the 9P transport trait.
struct ShmemTransportWriter(litebox_common_windows::shmem_ring::RingWriter);

/// Wraps a shmem ring reader for the 9P transport trait.
struct ShmemTransportReader(litebox_common_windows::shmem_ring::RingReader);

impl litebox::fs::nine_p::transport::Write for ShmemTransportWriter {
    fn write(
        &mut self,
        buf: &[u8],
    ) -> core::result::Result<usize, litebox::fs::nine_p::transport::WriteError> {
        std::io::Write::write(&mut self.0, buf).map_err(|err| match err.kind() {
            std::io::ErrorKind::Interrupted => {
                litebox::fs::nine_p::transport::WriteError::Interrupted
            }
            _ => litebox::fs::nine_p::transport::WriteError::Io,
        })
    }
}

impl litebox::fs::nine_p::transport::Read for ShmemTransportReader {
    fn read(
        &mut self,
        buf: &mut [u8],
    ) -> core::result::Result<usize, litebox::fs::nine_p::transport::ReadError> {
        std::io::Read::read(&mut self.0, buf).map_err(|err| match err.kind() {
            std::io::ErrorKind::Interrupted => {
                litebox::fs::nine_p::transport::ReadError::Interrupted
            }
            _ => litebox::fs::nine_p::transport::ReadError::Io,
        })
    }
}

/// Send the LB9P magic to initiate a 9P channel over an IPC stream.
fn perform_nine_p_ipc_handshake(
    stream: &mut litebox_platform_windows_userland::IpcStream,
) -> Result<()> {
    use std::io::Write;

    stream
        .write_all(b"LB9P")
        .map_err(|e| anyhow!("9P IPC handshake send failed: {e}"))
}

/// Upgrade an IPC stream to a shared-memory ring transport for 9P.
fn upgrade_ipc_stream_to_nine_p_ring(
    stream: &mut litebox_platform_windows_userland::IpcStream,
) -> Result<(
    litebox_common_windows::shmem_ring::RingWriter,
    litebox_common_windows::shmem_ring::RingReader,
)> {
    use std::io::{Read as _, Write as _};

    perform_nine_p_ipc_handshake(stream)?;

    let (pair, info) = litebox_common_windows::shmem_ring::ShmemRingPair::create()
        .map_err(|e| anyhow!("Failed to create 9P shmem ring pair: {e}"))?;
    let metadata = info.encode();

    stream
        .write_all(&[litebox_common_windows::shmem_ring::TRANSPORT_MARKER])
        .map_err(|e| anyhow!("Failed to send 9P ring transport marker: {e}"))?;
    stream
        .write_all(&metadata)
        .map_err(|e| anyhow!("Failed to send 9P ring metadata: {e}"))?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    let mut ack = [0u8; 1];
    stream
        .read_exact(&mut ack)
        .map_err(|e| anyhow!("9P ring handshake ACK failed: {e}"))?;
    stream.set_read_timeout(None).ok();
    if ack[0] != b'K' {
        anyhow::bail!("9P ring handshake: broker did not ACK shared-memory metadata");
    }

    Ok(pair.into_parts())
}

/// Connect to a 9P broker endpoint with retries, returning a shmem ring pair.
fn connect_nine_p_channel(
    endpoint: &str,
) -> Result<(
    litebox_common_windows::shmem_ring::RingWriter,
    litebox_common_windows::shmem_ring::RingReader,
)> {
    let mut attempts = 0;
    loop {
        let stream_result = match endpoint.parse::<std::net::SocketAddr>() {
            Ok(sock_addr) => connect_to_broker_tcp(endpoint, sock_addr),
            Err(_) => connect_to_broker_unix(endpoint),
        };
        match stream_result {
            Ok(mut stream) => match upgrade_ipc_stream_to_nine_p_ring(&mut stream) {
                Ok(parts) => return Ok(parts),
                Err(err) => {
                    attempts += 1;
                    if attempts >= 50 {
                        return Err(anyhow!(
                            "Failed to connect to 9P broker at {endpoint} \
                             after {attempts} attempts: {err}"
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            },
            Err(err) => {
                attempts += 1;
                if attempts >= 50 {
                    return Err(anyhow!(
                        "Failed to connect to 9P broker at {endpoint} \
                         after {attempts} attempts: {err}"
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Network Broker IPC helpers
// ---------------------------------------------------------------------------

/// IPC handshake constants (must match `litebox_broker` protocol).
const HANDSHAKE_MAGIC: &[u8; 4] = b"LBNP";
const HANDSHAKE_VERSION: u16 = 1;
const HANDSHAKE_MTU: u16 = 1600;

/// Connect to the network broker via loopback TCP or AF_UNIX and perform the
/// LBNP handshake. Returns a **non-blocking** IPC stream ready for the
/// platform's `IPInterfaceProvider` to use.
fn connect_to_broker_ipc(endpoint: &str) -> Result<litebox_platform_windows_userland::IpcStream> {
    let mut stream = match endpoint.parse::<std::net::SocketAddr>() {
        Ok(sock_addr) => connect_to_broker_tcp(endpoint, sock_addr)?,
        Err(_) => connect_to_broker_unix(endpoint)?,
    };
    perform_ipc_handshake(&mut stream)?;
    stream
        .set_nonblocking(true)
        .map_err(|e| anyhow!("Failed to set non-blocking on IPC stream: {e}"))?;
    stream.set_read_timeout(None).ok();
    Ok(stream)
}

fn connect_to_broker_tcp(
    endpoint: &str,
    sock_addr: std::net::SocketAddr,
) -> Result<litebox_platform_windows_userland::IpcStream> {
    let ip = sock_addr.ip();
    if !ip.is_loopback() {
        anyhow::bail!(
            "Broker address '{endpoint}' is not a loopback address. \
             Only 127.0.0.1 or [::1] are allowed for security."
        );
    }

    let stream =
        std::net::TcpStream::connect_timeout(&sock_addr, std::time::Duration::from_secs(5))
            .map_err(|e| anyhow!("Failed to connect to broker at {endpoint}: {e}"))?;

    stream.set_nodelay(true).ok();
    Ok(litebox_platform_windows_userland::IpcStream::from_tcp(
        stream,
    ))
}

fn connect_to_broker_unix(path: &str) -> Result<litebox_platform_windows_userland::IpcStream> {
    use std::os::windows::io::FromRawSocket;

    let (addr, addr_len) = win_sock::sockaddr_un_from_path(path)
        .map_err(|e| anyhow!("Invalid broker AF_UNIX path '{path}': {e}"))?;
    let stream = unsafe {
        win_sock::wsa_ensure_init();
        let socket = win_sock::socket(i32::from(win_sock::AF_UNIX), win_sock::SOCK_STREAM, 0);
        if socket == win_sock::INVALID_SOCKET {
            let err = win_sock::WSAGetLastError();
            if err == win_sock::WSAEAFNOSUPPORT {
                anyhow::bail!("Windows AF_UNIX is not available on this system");
            }
            anyhow::bail!("Failed to create AF_UNIX broker IPC socket: WSA error {err}");
        }
        std::net::TcpStream::from_raw_socket(socket as _)
    };
    let stream = litebox_platform_windows_userland::IpcStream::from_unix(stream);
    stream
        .set_nonblocking(true)
        .map_err(|e| anyhow!("Failed to set non-blocking on AF_UNIX IPC stream: {e}"))?;
    let raw = stream.raw_socket();
    let ret = unsafe { win_sock::connect(raw, (&raw const addr).cast(), addr_len) };
    if ret != 0 {
        let err = unsafe { win_sock::WSAGetLastError() };
        if err != win_sock::WSAEWOULDBLOCK {
            anyhow::bail!("Failed to connect to broker AF_UNIX socket at {path}: WSA error {err}");
        }
        wait_for_ipc_connect(raw, path)?;
    }
    stream
        .set_nonblocking(false)
        .map_err(|e| anyhow!("Failed to restore blocking mode on AF_UNIX IPC stream: {e}"))?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

fn wait_for_ipc_connect(raw_socket: usize, endpoint: &str) -> Result<()> {
    let mut pfd = win_sock::WSAPOLLFD {
        fd: raw_socket,
        events: win_sock::POLLOUT,
        revents: 0,
    };
    let ret = unsafe { win_sock::WSAPoll(&raw mut pfd, 1, 5000) };
    if ret == 0 {
        anyhow::bail!("Timed out connecting to broker IPC at {endpoint}");
    }
    if ret < 0 {
        anyhow::bail!(
            "Failed polling broker IPC connect at {endpoint}: WSA error {}",
            unsafe { win_sock::WSAGetLastError() }
        );
    }
    let mut err: i32 = 0;
    let mut len = i32::try_from(std::mem::size_of::<i32>()).expect("i32 size fits in i32");
    unsafe {
        win_sock::getsockopt(
            raw_socket,
            win_sock::SOL_SOCKET.cast_signed(),
            win_sock::SO_ERROR.cast_signed(),
            (&raw mut err).cast(),
            &raw mut len,
        );
    }
    if err != 0 {
        anyhow::bail!("Failed to connect to broker IPC at {endpoint}: WSA error {err}");
    }
    Ok(())
}

fn perform_ipc_handshake(stream: &mut litebox_platform_windows_userland::IpcStream) -> Result<()> {
    use std::io::{Read, Write};

    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(HANDSHAKE_MAGIC);
    msg[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
    msg[6..8].copy_from_slice(&HANDSHAKE_MTU.to_le_bytes());
    stream
        .write_all(&msg)
        .map_err(|e| anyhow!("IPC handshake send failed: {e}"))?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    let mut resp = [0u8; 8];
    stream
        .read_exact(&mut resp)
        .map_err(|e| anyhow!("IPC handshake response failed: {e}"))?;

    // Validate response.
    if &resp[0..4] != HANDSHAKE_MAGIC {
        anyhow::bail!("IPC handshake: bad magic in response");
    }
    let version = u16::from_le_bytes([resp[4], resp[5]]);
    if version != HANDSHAKE_VERSION {
        anyhow::bail!(
            "IPC handshake: version mismatch (got {version}, expected {HANDSHAKE_VERSION})"
        );
    }
    let mtu = u16::from_le_bytes([resp[6], resp[7]]);
    if mtu != HANDSHAKE_MTU {
        anyhow::bail!("IPC handshake: MTU mismatch (broker sent {mtu}, we expect {HANDSHAKE_MTU})");
    }
    trace_debugln!("IPC handshake complete: broker MTU={mtu}");
    Ok(())
}

#[allow(
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::upper_case_acronyms
)]
mod win_sock {
    use std::{io, sync::Once};

    pub const AF_UNIX: u16 = 1;
    pub const SOCK_STREAM: i32 = 1;
    pub const INVALID_SOCKET: usize = !0;
    pub const SOL_SOCKET: u32 = 0xFFFF;
    pub const SO_ERROR: u32 = 0x1007;
    pub const WSAEAFNOSUPPORT: i32 = 10047;
    pub const WSAEWOULDBLOCK: i32 = 10035;
    pub const POLLOUT: i16 = 0x0010;

    #[repr(C)]
    pub struct WSADATA {
        pub wVersion: u16,
        pub wHighVersion: u16,
        pub iMaxSockets: u16,
        pub iMaxUdpDg: u16,
        pub lpVendorInfo: *mut u8,
        pub szDescription: [u8; 257],
        pub szSystemStatus: [u8; 129],
    }

    #[repr(C)]
    pub struct SOCKADDR_UN {
        pub sun_family: u16,
        pub sun_path: [u8; 108],
    }

    #[repr(C)]
    pub struct WSAPOLLFD {
        pub fd: usize,
        pub events: i16,
        pub revents: i16,
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        pub fn WSAStartup(wVersionRequested: u16, lpWSAData: *mut WSADATA) -> i32;
        pub fn WSAGetLastError() -> i32;
        pub fn WSAPoll(fdArray: *mut WSAPOLLFD, fds: u32, timeout: i32) -> i32;
        pub fn socket(af: i32, r#type: i32, protocol: i32) -> usize;
        pub fn connect(s: usize, name: *const u8, namelen: i32) -> i32;
        pub fn getsockopt(
            s: usize,
            level: i32,
            optname: i32,
            optval: *mut u8,
            optlen: *mut i32,
        ) -> i32;
    }

    static WSA_INIT: Once = Once::new();

    pub fn wsa_ensure_init() {
        WSA_INIT.call_once(|| unsafe {
            let mut data = std::mem::zeroed::<WSADATA>();
            WSAStartup(0x0202, &raw mut data);
        });
    }

    pub fn sockaddr_un_from_path(path: &str) -> io::Result<(SOCKADDR_UN, i32)> {
        let path_bytes = path.as_bytes();
        if path_bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AF_UNIX path cannot be empty",
            ));
        }
        if path_bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AF_UNIX path cannot contain NUL bytes",
            ));
        }
        if path_bytes.len() >= 108 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "AF_UNIX path too long ({} bytes, max 107)",
                    path_bytes.len()
                ),
            ));
        }

        let mut addr = SOCKADDR_UN {
            sun_family: AF_UNIX,
            sun_path: [0; 108],
        };
        addr.sun_path[..path_bytes.len()].copy_from_slice(path_bytes);
        let addr_len =
            i32::try_from(std::mem::size_of::<u16>() + path_bytes.len() + 1).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "AF_UNIX path length overflow")
            })?;
        Ok((addr, addr_len))
    }
}

/// Start the network worker thread if a network stack is configured.
///
/// The thread repeatedly calls `perform_platform_interaction()` on the smoltcp
/// `Network`, then waits on the platform transport until data arrives or a
/// timeout fires. This mirrors the Linux runner's network worker pattern.
fn start_network_worker(
    net: Option<&Arc<spin::Mutex<litebox::net::Network<Platform>>>>,
    shutdown: &Arc<core::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    let net = net?.clone();
    let shutdown = shutdown.clone();

    let handle = std::thread::Builder::new()
        .name("network-worker".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            const DEFAULT_TIMEOUT: core::time::Duration = core::time::Duration::from_micros(100);

            while !shutdown.load(core::sync::atomic::Ordering::Relaxed) {
                let timeout = loop {
                    match net.lock().perform_platform_interaction() {
                        litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {}
                        litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                            break timeout;
                        }
                    }
                };
                let wait = match timeout {
                    Some(t) if t < DEFAULT_TIMEOUT => t,
                    _ => DEFAULT_TIMEOUT,
                };
                litebox_platform_multiplex::platform().wait_on_network(Some(wait));
            }
            // Drain remaining network interactions before exiting.
            while net
                .lock()
                .perform_platform_interaction()
                .call_again_immediately()
            {}
        })
        .expect("failed to spawn network worker thread");

    Some(handle)
}

/// Capture NLS data from the host's real ntdll so the shim doesn't need to
/// call host APIs (GetModuleHandleA, GetProcAddress, VirtualQuery) at runtime.
fn capture_host_nls_data() -> Option<litebox_shim_windows::NlsData> {
    type NtInitNlsFn = unsafe extern "system" fn(*mut *mut u8, *mut u32, *mut i64, *mut u32) -> i32;
    type NtGetNlsSectionPtrFn =
        unsafe extern "system" fn(u32, u32, *mut core::ffi::c_void, *mut *mut u8, *mut u32) -> i32;

    unsafe extern "system" {
        fn GetModuleHandleA(name: *const u8) -> *mut core::ffi::c_void;
        fn GetProcAddress(
            module: *mut core::ffi::c_void,
            name: *const u8,
        ) -> *mut core::ffi::c_void;
        fn VirtualQuery(addr: *const u8, info: *mut u8, len: usize) -> usize;
    }

    unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            return None;
        }
        let proc = GetProcAddress(ntdll, c"NtInitializeNlsFiles".as_ptr().cast());
        if proc.is_null() {
            return None;
        }
        let get_section_proc = GetProcAddress(ntdll, c"NtGetNlsSectionPtr".as_ptr().cast());
        let func: NtInitNlsFn = core::mem::transmute(proc);
        let get_section: Option<NtGetNlsSectionPtrFn> = if get_section_proc.is_null() {
            None
        } else {
            Some(core::mem::transmute::<
                *mut core::ffi::c_void,
                NtGetNlsSectionPtrFn,
            >(get_section_proc))
        };
        let mut base: *mut u8 = core::ptr::null_mut();
        let mut locale: u32 = 0;
        let mut casing: i64 = 0;
        let mut version: u32 = 0;
        let status = func(
            &raw mut base,
            &raw mut locale,
            &raw mut casing,
            &raw mut version,
        );
        if status != 0 || base.is_null() {
            return None;
        }
        // Query section size via VirtualQuery (MEMORY_BASIC_INFORMATION).
        #[repr(C)]
        struct Mbi {
            base_address: usize,
            alloc_base: usize,
            alloc_protect: u32,
            _pad0: u16,
            _pad1: u16,
            region_size: usize,
            state: u32,
            protect: u32,
            type_: u32,
            _pad2: u32,
        }
        let mut mbi = core::mem::zeroed::<Mbi>();
        let ret = VirtualQuery(base, (&raw mut mbi).cast(), core::mem::size_of::<Mbi>());
        let section_size = if ret != 0 { mbi.region_size } else { 0xD3000 };
        let section = core::slice::from_raw_parts(base, section_size).to_vec();

        // Compute sub-table offsets within the combined NLS section.
        // The combined section layout is: [ANSI CP | OEM CP | Unicode case table].
        // ANSI CP always starts at offset 0. To find where the OEM CP starts, we
        // search for the first bytes of the individually-captured OEM section within
        // the combined section. The Unicode case table follows immediately after.
        let base_addr = base as usize;
        let mut oem_cp_offset: usize = 0;
        let mut unicode_case_offset: usize = 0;

        let mut sections = alloc::vec::Vec::new();
        if let Some(get_section) = get_section {
            for section_data in [1252_u32, 437_u32, 10000_u32] {
                let mut section_ptr: *mut u8 = core::ptr::null_mut();
                let mut section_len: u32 = 0;
                let section_status = get_section(
                    11,
                    section_data,
                    core::ptr::null_mut(),
                    &raw mut section_ptr,
                    &raw mut section_len,
                );
                if section_status == 0 && !section_ptr.is_null() && section_len != 0 {
                    let bytes =
                        core::slice::from_raw_parts(section_ptr, section_len as usize).to_vec();
                    sections.push(litebox_shim_windows::NlsSectionData {
                        section_type: 11,
                        section_data,
                        bytes,
                    });
                }
            }
        }
        // Compute OEM CP and Unicode case table offsets by searching the combined
        // section for the individually-captured OEM code page data.
        // The OEM CP is code page 437 (section_data=437). Find it in the captured sections.
        let oem_section_data = sections.iter().find(|s| s.section_data == 437);
        if let Some(oem_sec) = oem_section_data {
            // Search for the first 32 bytes of the OEM section within the combined section.
            // The OEM CP starts after the ANSI CP, so search from a reasonable minimum offset.
            let needle_len = 32.min(oem_sec.bytes.len());
            let needle = &oem_sec.bytes[..needle_len];
            // Start searching from offset 0x1000 (ANSI CP is at least a few KB).
            for offset in (0x1000..section.len().saturating_sub(needle_len)).step_by(2) {
                if &section[offset..offset + needle_len] == needle {
                    oem_cp_offset = offset;
                    // Unicode case table starts right after the OEM section.
                    unicode_case_offset = offset + oem_sec.bytes.len();
                    eprintln!(
                        "[runner] NLS offsets found: oem_cp=0x{:X} unicode_case=0x{:X}",
                        oem_cp_offset, unicode_case_offset
                    );
                    break;
                }
            }
        }
        if oem_cp_offset == 0 {
            eprintln!("[runner] WARNING: could not find OEM CP offset in combined NLS section");
        }
        Some(litebox_shim_windows::NlsData {
            section,
            locale_id: locale,
            casing_size: casing,
            version,
            sections,
            oem_cp_offset,
            unicode_case_offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{build_guest_command_line, quote_windows_command_line_arg};

    #[test]
    fn windows_command_line_keeps_simple_arg_unquoted() {
        assert_eq!(quote_windows_command_line_arg("--version"), "--version");
    }

    #[test]
    fn windows_command_line_quotes_whitespace() {
        assert_eq!(
            quote_windows_command_line_arg(r"C:\Program Files\node.exe"),
            r#""C:\Program Files\node.exe""#
        );
    }

    #[test]
    fn windows_command_line_escapes_embedded_quotes() {
        assert_eq!(
            quote_windows_command_line_arg(r#"say "hello""#),
            r#""say \"hello\"""#
        );
    }

    #[test]
    fn windows_command_line_doubles_trailing_backslashes_inside_quotes() {
        assert_eq!(
            quote_windows_command_line_arg("dir with space\\"),
            r#""dir with space\\""#,
        );
    }

    #[test]
    fn guest_command_line_includes_program_and_arguments() {
        assert_eq!(
            build_guest_command_line("node.exe", &["--version".to_string()]),
            "node.exe --version"
        );
    }
}
