// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT file I/O syscall handlers.
//!
//! Implements NtCreateFile, NtReadFile, NtQueryInformationFile, and
//! NtSetInformationFile. For Phase 2, file operations pass through to the
//! host OS. A proper sandboxed VFS will be added in later phases.

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use litebox_common_windows::nt_types::{
    FileBasicInformation, FileId128, FilePositionInformation, FileStandardInformation,
    FileStatBasicInformation, FileStatInformation, IoStatusBlock, ObjectAttributes, UnicodeString,
    file_access, file_attributes, file_disposition, file_options,
};
use litebox_common_windows::ntstatus::NtStatus;

use crate::handle_table::{HandleTable, NtObject};

use super::NtSyscallArgs;

const FILE_STAT_INFORMATION_CLASS: u32 = 68;
const FILE_STAT_BASIC_INFORMATION_CLASS: u32 = 77;
const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_DEVICE_IS_MOUNTED: u32 = 0x0000_0020;
const SYNTHETIC_VOLUME_SERIAL_NUMBER: i64 = 0x4C42_4F58_0000_0001u64 as i64;

#[repr(C)]
#[derive(Clone, Copy)]
struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

#[allow(clippy::struct_field_names)]
struct HostFileTimes {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
}

// ========================================================================
// NT-style wildcard matching
// ========================================================================

/// Match a filename against an NT wildcard pattern (case-insensitive).
///
/// Supports `*` (match zero or more characters), `?` (match exactly one
/// character), and the DOS-era `*.*` idiom which matches everything.
/// Both `name` and `pattern` must already be lowercased by the caller.
pub(crate) fn nt_wildcard_match(name: &str, pattern: &str) -> bool {
    // Common fast paths.
    if pattern == "*" || pattern == "*.*" {
        return true;
    }
    glob_match(name.as_bytes(), pattern.as_bytes())
}

/// Recursive glob matcher for `*` and `?` wildcards.
fn glob_match(name: &[u8], pattern: &[u8]) -> bool {
    let mut ni = 0;
    let mut pi = 0;
    let mut star_pi = usize::MAX; // pattern index after last '*'
    let mut star_ni = 0; // name index when last '*' was seen

    while ni < name.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == name[ni]) {
            ni += 1;
            pi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi + 1;
            star_ni = ni;
            pi += 1;
        } else if star_pi != usize::MAX {
            // Backtrack: let the '*' consume one more character.
            star_ni += 1;
            ni = star_ni;
            pi = star_pi;
        } else {
            return false;
        }
    }
    // Consume trailing '*' in pattern.
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

// ========================================================================
// NT path translation
// ========================================================================

/// Result of translating an NT object path.
pub(crate) enum TranslatedPath {
    /// A VFS filesystem path (e.g., `/c/windows/system32/ntdll.dll`).
    Vfs(String),
    /// A device path routed through DeviceFS.
    Device(String),
    /// A registry path — not handled by VFS.
    Registry(String),
    /// A named pipe path (e.g., `Win32.Pipes.123.1`).
    Pipe(String),
}

/// Check if an NT path refers to a phantom executable — a file that we
/// pretend exists so that `CreateProcessW` can proceed past its pre-flight
/// checks and reach `NtCreateUserProcess`.
///
/// Returns `true` for paths ending in `.exe`, `.cmd`, `.bat`, or `.com`
/// (case-insensitive) that translate to a VFS path.
fn is_phantom_executable_path(nt_path: &str) -> bool {
    let lower = nt_path.to_ascii_lowercase();
    // Only for VFS-translatable paths (not registry, pipe, etc.)
    let Some(translated) = translate_nt_path(nt_path) else {
        return false;
    };
    match translated {
        TranslatedPath::Vfs(_) => {}
        _ => return false,
    }
    lower.ends_with(".exe")
        || lower.ends_with(".cmd")
        || lower.ends_with(".bat")
        || lower.ends_with(".com")
}

/// Translate an NT object path to a VFS path.
///
/// All VFS paths are lowercased (VFS is case-sensitive; Windows is not).
/// Backslashes are converted to forward slashes.
///
/// | NT Path                              | VFS Path                        |
/// |--------------------------------------|---------------------------------|
/// | `\??\C:\Windows\System32\ntdll.dll`  | `/c/windows/system32/ntdll.dll` |
/// | `\DosDevices\C:\foo.txt`             | `/c/foo.txt`                    |
/// | `\SystemRoot\System32\ntdll.dll`     | `/c/windows/system32/ntdll.dll` |
/// | `C:\Windows\System32\ntdll.dll`      | `/c/windows/system32/ntdll.dll` |
/// | `\Device\ConDrv\Input`               | `/dev/stdin`                    |
/// | `\Device\ConDrv\Output`              | `/dev/stdout`                   |
/// | `\??\NUL`                            | `/dev/null`                     |
/// | `\??\CON`                            | `/dev/stdout`                   |
/// | `\??\CONIN$`                         | `/dev/stdin`                    |
/// | `\??\CONOUT$`                        | `/dev/stdout`                   |
///
/// Returns `None` for paths that can't be mapped.
pub(crate) fn translate_nt_path(nt_path: &str) -> Option<TranslatedPath> {
    // \Device\ConDrv paths → DeviceFS
    if let Some(rest) = nt_path.strip_prefix("\\Device\\ConDrv\\") {
        let lower = rest.to_ascii_lowercase();
        return match lower.as_str() {
            "input" | "currentin" => Some(TranslatedPath::Device(String::from("/dev/stdin"))),
            "output" | "currentout" => Some(TranslatedPath::Device(String::from("/dev/stdout"))),
            _ => Some(TranslatedPath::Device(String::from("/dev/stdout"))),
        };
    }

    // Registry paths
    if nt_path.starts_with("\\Registry\\") || nt_path.starts_with("\\REGISTRY\\") {
        return Some(TranslatedPath::Registry(String::from(nt_path)));
    }

    // \??\<something> paths
    if let Some(rest) = nt_path.strip_prefix("\\??\\") {
        // Special device names
        let upper = rest.to_ascii_uppercase();
        if upper == "NUL" {
            return Some(TranslatedPath::Device(String::from("/dev/null")));
        }
        if upper == "CON" || upper == "CONOUT$" {
            return Some(TranslatedPath::Device(String::from("/dev/stdout")));
        }
        if upper == "CONIN$" {
            return Some(TranslatedPath::Device(String::from("/dev/stdin")));
        }
        if upper == "NSI" {
            return Some(TranslatedPath::Device(String::from("/dev/nsi")));
        }

        // Named pipe path: \??\pipe\<name>
        if let Some(pipe_rest) = rest.strip_prefix("pipe\\") {
            return Some(TranslatedPath::Pipe(String::from(pipe_rest)));
        }

        // UNC path: \??\UNC\server\share → //server/share
        if let Some(unc) = rest.strip_prefix("UNC\\") {
            let vfs = alloc::format!("//{}", unc.replace('\\', "/").to_ascii_lowercase());
            return Some(TranslatedPath::Vfs(vfs));
        }

        // Drive path: \??\C:\path → /c/path
        return drive_path_to_vfs(rest);
    }

    // \DosDevices\C:\path → /c/path
    if let Some(rest) = nt_path.strip_prefix("\\DosDevices\\") {
        return drive_path_to_vfs(rest);
    }

    // \SystemRoot\path → /c/windows/path
    if let Some(rest) = nt_path.strip_prefix("\\SystemRoot\\") {
        let vfs = alloc::format!(
            "/c/windows/{}",
            rest.replace('\\', "/").to_ascii_lowercase()
        );
        return Some(TranslatedPath::Vfs(vfs));
    }
    if nt_path == "\\SystemRoot" {
        return Some(TranslatedPath::Vfs(String::from("/c/windows")));
    }

    // Bare drive path: C:\path → /c/path
    if nt_path.len() >= 3 && nt_path.as_bytes()[1] == b':' {
        return drive_path_to_vfs(nt_path);
    }

    // Named pipe paths via \Device\NamedPipe\ or \DosDevices\pipe\
    if let Some(rest) = nt_path.strip_prefix("\\Device\\NamedPipe\\") {
        return Some(TranslatedPath::Pipe(String::from(rest)));
    }
    if let Some(rest) = nt_path.strip_prefix("\\DosDevices\\pipe\\") {
        return Some(TranslatedPath::Pipe(String::from(rest)));
    }

    None
}

/// Convert a drive-letter path like `C:\foo\bar` to VFS `/c/foo/bar`.
pub(crate) fn drive_path_to_vfs(path: &str) -> Option<TranslatedPath> {
    if let Some(unc) = path.strip_prefix("\\\\?\\UNC\\") {
        let vfs = alloc::format!("//{}", unc.replace('\\', "/").to_ascii_lowercase());
        return Some(TranslatedPath::Vfs(vfs));
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
    let rest = if path.len() > 2 {
        &path[2..] // includes leading backslash
    } else {
        ""
    };
    let vfs = alloc::format!("/{drive}{}", rest.replace('\\', "/").to_ascii_lowercase());
    Some(TranslatedPath::Vfs(vfs))
}

/// Read a UNICODE_STRING from guest memory and return the string contents.
fn read_unicode_string_from_guest(us_va: usize) -> Option<String> {
    let us: UnicodeString = crate::try_read_guest_value_unaligned(us_va)?;
    let buf_addr = us.buffer as usize;
    let byte_len = us.length as usize;
    if byte_len == 0 || buf_addr == 0 {
        return Some(alloc::string::String::new());
    }
    if !crate::is_addr_range_committed(buf_addr, byte_len) {
        return None;
    }
    let char_count = byte_len / 2;
    // Safety: range validated by is_addr_range_committed above.
    let wchars = unsafe { core::slice::from_raw_parts(buf_addr as *const u16, char_count) };
    Some(alloc::string::String::from_utf16_lossy(wchars))
}

/// Parse a double-NUL terminated UTF-16LE environment block from guest memory
/// into a `Vec<String>` of `"KEY=VALUE"` strings.
///
/// The caller-provided `env_ptr` points to the start of the environment block
/// in guest memory (from `RTL_USER_PROCESS_PARAMETERS.Environment`).
fn parse_env_block_from_guest(env_ptr: usize) -> alloc::vec::Vec<alloc::string::String> {
    let mut result = alloc::vec::Vec::new();
    let mut ptr = env_ptr;
    // Safety limit: don't read more than 128 KB of env data.
    let end = env_ptr + 128 * 1024;
    loop {
        if ptr >= end {
            break;
        }
        // Read one UTF-16 NUL-terminated string.
        let mut chars = alloc::vec::Vec::new();
        loop {
            if ptr + 2 > end {
                return result;
            }
            let ch = match crate::try_read_guest_value_unaligned::<u16>(ptr) {
                Some(v) => v,
                None => return result, // unmapped memory, stop
            };
            ptr += 2;
            if ch == 0 {
                break;
            }
            chars.push(ch);
            if chars.len() > 32768 {
                break; // single env var too long, bail
            }
        }
        if chars.is_empty() {
            break; // double-NUL = end of env block
        }
        let s = alloc::string::String::from_utf16_lossy(&chars);
        result.push(s);
    }
    result
}

fn is_absolute_nt_or_dos_path(path: &str) -> bool {
    path.starts_with('\\') || path.as_bytes().get(1).is_some_and(|second| *second == b':')
}

fn join_nt_paths(root: &str, child: &str) -> String {
    if root.ends_with('\\') || root.ends_with('/') {
        alloc::format!("{root}{child}")
    } else {
        alloc::format!(r"{root}\{child}")
    }
}

fn resolve_object_attributes_path<FS: crate::NtShimFS>(
    obj_attr_ptr: usize,
    handles: Option<&HandleTable<FS>>,
) -> Result<String, NtStatus> {
    if obj_attr_ptr == 0 {
        return Err(NtStatus::STATUS_INVALID_PARAMETER);
    }

    let Some(obj_attr) = crate::try_read_guest_value_unaligned::<ObjectAttributes>(obj_attr_ptr)
    else {
        return Err(NtStatus::STATUS_INVALID_PARAMETER);
    };
    let Some(mut nt_path) = read_unicode_string_from_guest(obj_attr.object_name as usize) else {
        return Err(NtStatus::STATUS_OBJECT_NAME_INVALID);
    };

    if obj_attr.root_directory != 0
        && !is_absolute_nt_or_dos_path(&nt_path)
        && let Some(handles) = handles
    {
        let root_handle = obj_attr.root_directory as u32;
        let root_path = handles.with(root_handle, |entry| match &entry.object {
            NtObject::Directory { path, .. } => Some(path.clone()),
            NtObject::RegistryKey { path } => Some(path.clone()),
            NtObject::PipeRootDevice => Some(alloc::string::String::from("\\Device\\NamedPipe")),
            _ => None,
        }).flatten();
        if let Some(root_path) = root_path {
            nt_path = join_nt_paths(&root_path, &nt_path);
        }
    }

    Ok(nt_path)
}

fn query_object_attributes_file_status<FS: crate::NtShimFS>(
    obj_attr_ptr: usize,
    handles: Option<&HandleTable<FS>>,
    shared: &super::super::NtSharedState<FS>,
) -> Result<litebox::fs::FileStatus, NtStatus> {
    let nt_path = resolve_object_attributes_path(obj_attr_ptr, handles)?;
    query_nt_path_file_status(&nt_path, shared)
}

fn query_nt_path_file_status<FS: crate::NtShimFS>(
    nt_path: &str,
    shared: &super::super::NtSharedState<FS>,
) -> Result<litebox::fs::FileStatus, NtStatus> {
    let translated = translate_nt_path(nt_path).ok_or(NtStatus::STATUS_OBJECT_NAME_NOT_FOUND)?;
    let path = match translated {
        TranslatedPath::Vfs(path) | TranslatedPath::Device(path) => path,
        TranslatedPath::Registry(_) | TranslatedPath::Pipe(_) => return Err(NtStatus::STATUS_OBJECT_NAME_NOT_FOUND),
    };

    let Some(fs) = shared.fs.get() else {
        return Err(NtStatus::STATUS_OBJECT_NAME_NOT_FOUND);
    };

    fs.file_status(path.as_str())
        .map_err(|_| NtStatus::STATUS_OBJECT_NAME_NOT_FOUND)
}

fn filetime_to_i64(file_time: FileTime) -> i64 {
    ((u64::from(file_time.high_date_time) << 32) | u64::from(file_time.low_date_time)) as i64
}

fn current_system_file_time() -> i64 {
    unsafe extern "system" {
        fn GetSystemTimeAsFileTime(system_time_as_file_time: *mut FileTime);
    }

    let mut file_time = FileTime {
        low_date_time: 0,
        high_date_time: 0,
    };
    unsafe {
        GetSystemTimeAsFileTime(&mut file_time);
    }
    filetime_to_i64(file_time)
}

fn synthetic_file_times() -> HostFileTimes {
    let now = current_system_file_time();
    HostFileTimes {
        creation_time: now,
        last_access_time: now,
        last_write_time: now,
        change_time: now,
    }
}

fn query_host_file_times(_nt_path: &str) -> HostFileTimes {
    // LiteBox's VFS backends do not yet preserve host timestamps end-to-end.
    // Use a valid current NT system time rather than returning zero/1601-era
    // placeholders or issuing host filesystem calls from inside the guest
    // syscall path.
    synthetic_file_times()
}

fn file_attributes_from_status(status: &litebox::fs::FileStatus) -> u32 {
    if status.file_type == litebox::fs::FileType::Directory {
        file_attributes::FILE_ATTRIBUTE_DIRECTORY
    } else {
        file_attributes::FILE_ATTRIBUTE_NORMAL
    }
}

fn file_size_from_status(status: &litebox::fs::FileStatus) -> i64 {
    i64::try_from(status.size).unwrap_or(i64::MAX)
}

fn allocation_size_from_status(status: &litebox::fs::FileStatus) -> i64 {
    let end_of_file = file_size_from_status(status);
    if end_of_file == 0 {
        return 0;
    }

    let block_size = match i64::try_from(status.blksize) {
        Ok(size) if size > 0 => size,
        _ => 4096,
    };
    let rem = end_of_file % block_size;
    if rem == 0 {
        end_of_file
    } else {
        end_of_file.saturating_add(block_size - rem)
    }
}

fn synthetic_file_id(status: &litebox::fs::FileStatus) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    let parts = [
        u64::try_from(status.node_info.dev).unwrap_or(u64::MAX),
        u64::try_from(status.node_info.ino).unwrap_or(u64::MAX),
        status
            .node_info
            .rdev
            .map(|rdev| u64::try_from(rdev.get()).unwrap_or(u64::MAX))
            .unwrap_or(0),
    ];
    for part in parts {
        for byte in part.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

fn synthetic_file_id128(status: &litebox::fs::FileStatus, file_id: u64) -> FileId128 {
    let mut file_id128 = FileId128::default();
    file_id128.identifier[..8].copy_from_slice(&file_id.to_le_bytes());
    let dev = u64::try_from(status.node_info.dev).unwrap_or(u64::MAX);
    file_id128.identifier[8..].copy_from_slice(&dev.to_le_bytes());
    file_id128
}

// ========================================================================
// NtCreateFile
// ========================================================================

/// Map a VFS `MkdirError` to the appropriate NTSTATUS.
fn map_mkdir_error(e: litebox::fs::errors::MkdirError) -> NtStatus {
    use litebox::fs::errors::MkdirError;
    match e {
        MkdirError::AlreadyExists => NtStatus::STATUS_OBJECT_NAME_COLLISION,
        MkdirError::ReadOnlyFileSystem => NtStatus::STATUS_ACCESS_DENIED,
        MkdirError::NoWritePerms => NtStatus::STATUS_ACCESS_DENIED,
        MkdirError::Io => NtStatus::STATUS_UNEXPECTED_IO_ERROR,
        MkdirError::PathError(_) => NtStatus::STATUS_OBJECT_NAME_NOT_FOUND,
        _ => NtStatus::STATUS_OBJECT_NAME_NOT_FOUND,
    }
}

fn map_open_error_to_ntstatus(e: &litebox::fs::errors::OpenError) -> NtStatus {
    use litebox::fs::errors::OpenError;
    match e {
        OpenError::PathError(_) => NtStatus::STATUS_OBJECT_PATH_NOT_FOUND,
        OpenError::AccessNotAllowed => NtStatus::STATUS_ACCESS_DENIED,
        OpenError::NoWritePerms => NtStatus::STATUS_ACCESS_DENIED,
        OpenError::ReadOnlyFileSystem => NtStatus::STATUS_ACCESS_DENIED,
        OpenError::AlreadyExists => NtStatus::STATUS_OBJECT_NAME_COLLISION,
        OpenError::NotADirectory => NtStatus::STATUS_NOT_A_DIRECTORY,
        OpenError::Io => NtStatus::STATUS_UNEXPECTED_IO_ERROR,
        _ => NtStatus::STATUS_OBJECT_NAME_NOT_FOUND,
    }
}

fn map_readdir_error_to_ntstatus(e: &litebox::fs::errors::ReadDirError) -> NtStatus {
    use litebox::fs::errors::ReadDirError;
    match e {
        ReadDirError::ClosedFd => NtStatus::STATUS_INVALID_HANDLE,
        ReadDirError::NotADirectory => NtStatus::STATUS_NOT_A_DIRECTORY,
        ReadDirError::Io => NtStatus::STATUS_UNEXPECTED_IO_ERROR,
        _ => NtStatus::STATUS_UNEXPECTED_IO_ERROR,
    }
}

/// Helper: insert a `NtObject::Directory` handle and write the IOSB.
fn insert_directory_handle<FS: crate::NtShimFS>(
    handles: &mut HandleTable<FS>,
    nt_path: &str,
    handle_out_ptr: usize,
    io_status_ptr: usize,
    iosb_information: u64,
) -> NtStatus {
    let dir_handle = handles.insert(NtObject::Directory {
        path: alloc::string::String::from(nt_path),
        enum_entries: alloc::vec::Vec::new(),
        enum_index: 0,
    });
    crate::try_write_guest_value_unaligned(handle_out_ptr, dir_handle as usize);
    if io_status_ptr != 0 {
        let iosb = IoStatusBlock {
            status: NtStatus::STATUS_SUCCESS.0,
            _pad: 0,
            information: iosb_information,
        };
        crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
    }
    NtStatus::STATUS_SUCCESS
}

/// Helper: insert an arbitrary NT object handle and write a successful IOSB.
fn insert_object_handle<FS: crate::NtShimFS>(
    handles: &mut HandleTable<FS>,
    obj: NtObject<FS>,
    handle_out_ptr: usize,
    io_status_ptr: usize,
    iosb_information: u64,
) -> NtStatus {
    let handle = handles.insert(obj);
    crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
    if io_status_ptr != 0 {
        let iosb = IoStatusBlock {
            status: NtStatus::STATUS_SUCCESS.0,
            _pad: 0,
            information: iosb_information,
        };
        crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
    }
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// AFD (Ancillary Function Driver) socket creation
// ========================================================================

/// WinSock address families.
const AF_INET: u32 = 2;

/// WinSock socket types.
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

/// WinSock IP protocols.
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

/// NT Extended Attribute header used by NtCreateFile for AFD opens.
///
/// Layout (from ntifs.h / ReactOS):
/// ```text
/// typedef struct _FILE_FULL_EA_INFORMATION {
///     ULONG  NextEntryOffset;  // +0x00
///     UCHAR  Flags;            // +0x04
///     UCHAR  EaNameLength;     // +0x05
///     USHORT EaValueLength;    // +0x06
///     CHAR   EaName[1];        // +0x08  (null-terminated, then EaValue follows)
/// } FILE_FULL_EA_INFORMATION;
/// ```
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct FileFullEaInformation {
    next_entry_offset: u32,
    flags: u8,
    ea_name_length: u8,
    ea_value_length: u16,
    // followed by: ea_name[ea_name_length + 1], then ea_value[ea_value_length]
}

/// AFD open packet embedded in the EA value.
///
/// This is what mswsock.dll passes via the EA buffer when opening `\Device\Afd\Endpoint`.
/// Based on ReactOS `afd.h` / Wine `nsi.h` / libuv `winsock.c`:
/// ```text
/// typedef struct _AFD_CREATE_PACKET {
///     ULONG  EndpointFlags;               // +0x00 (unused by us)
///     ULONG  GroupID;                      // +0x04 (unused by us)
///     ULONG  AddressFamily;               // +0x08
///     ULONG  SocketType;                  // +0x0C
///     ULONG  Protocol;                    // +0x10
///     // ... transport device name follows
/// } AFD_CREATE_PACKET;
/// ```
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct AfdCreatePacket {
    endpoint_flags: u32,
    group_id: u32,
    address_family: u32,
    socket_type: u32,
    protocol: u32,
    // Followed by transport device name (WCHAR), which we ignore.
}

/// The EA name used by mswsock.dll for AFD socket creation.
const AFD_OPEN_PACKET_EA_NAME: &[u8] = b"AfdOpenPacketXX";

/// Try to open an AFD socket device path.
///
/// When `mswsock.dll` calls `NtCreateFile` with a path like `\Device\Afd\Endpoint`,
/// it passes an `EaBuffer` containing an `AFD_CREATE_PACKET` that describes the
/// socket parameters (address family, socket type, protocol).
///
/// Returns `Some(status)` if the path was an AFD path (even on failure),
/// or `None` if the path is not an AFD path.
fn try_open_afd_socket<FS: crate::NtShimFS>(
    nt_path: &str,
    ea_buffer_ptr: usize,
    ea_length: u32,
    handles: &mut HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
    handle_out_ptr: usize,
    io_status_ptr: usize,
) -> Option<NtStatus> {
    // Check if this is an AFD device path.
    let path_lower = nt_path.to_ascii_lowercase();
    if !path_lower.starts_with("\\device\\afd") {
        return None;
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtCreateFile AFD path={nt_path:?} ea_buf=0x{ea_buffer_ptr:X} ea_len={ea_length}\n",
        ));
    }

    // Parse the EA buffer to extract socket parameters.
    if ea_buffer_ptr == 0 || ea_length < (core::mem::size_of::<FileFullEaInformation>() as u32) {
        // No EA buffer — cannot determine socket parameters.
        // Return a stub handle (some callers just open \Device\Afd for ioctls).
        return Some(insert_object_handle(
            handles,
            NtObject::Stub {
                kind: String::from("Afd"),
                io_completion: None,
            },
            handle_out_ptr,
            io_status_ptr,
            1, // FILE_OPENED
        ));
    }

    // Read the FILE_FULL_EA_INFORMATION header.
    let Some(ea_header) =
        crate::try_read_guest_value_unaligned::<FileFullEaInformation>(ea_buffer_ptr)
    else {
        return Some(NtStatus::STATUS_INVALID_PARAMETER);
    };

    let ea_name_offset = ea_buffer_ptr + core::mem::size_of::<FileFullEaInformation>();
    let ea_name_len = ea_header.ea_name_length as usize;
    let ea_value_offset = ea_name_offset + ea_name_len + 1; // +1 for null terminator
    let ea_value_len = ea_header.ea_value_length as usize;

    // Verify the EA name matches "AfdOpenPacketXX".
    if ea_name_len == AFD_OPEN_PACKET_EA_NAME.len() {
        let mut name_buf = [0u8; 15]; // "AfdOpenPacketXX" is 15 bytes
        for (i, byte) in name_buf.iter_mut().enumerate() {
            if let Some(b) = crate::try_read_guest_value_unaligned::<u8>(ea_name_offset + i) {
                *byte = b;
            }
        }
        if &name_buf[..ea_name_len] != AFD_OPEN_PACKET_EA_NAME {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: AFD EA name mismatch: {:?}\n",
                    core::str::from_utf8(&name_buf[..ea_name_len])
                ));
            }
            return Some(NtStatus::STATUS_INVALID_PARAMETER);
        }
    } else {
        // EA name length doesn't match — unexpected.
        return Some(NtStatus::STATUS_INVALID_PARAMETER);
    }

    // Parse the AFD_CREATE_PACKET from the EA value.
    if ea_value_len < core::mem::size_of::<AfdCreatePacket>() {
        return Some(NtStatus::STATUS_INVALID_PARAMETER);
    }

    let Some(afd_packet) =
        crate::try_read_guest_value_unaligned::<AfdCreatePacket>(ea_value_offset)
    else {
        return Some(NtStatus::STATUS_INVALID_PARAMETER);
    };

    let address_family = afd_packet.address_family;
    let socket_type = afd_packet.socket_type;
    let protocol_num = afd_packet.protocol;

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: AFD create socket AF={address_family} type={socket_type} proto={protocol_num}\n",
        ));
    }

    // Only support AF_INET for now.
    if address_family != AF_INET {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: AFD unsupported address family {address_family}\n",
            ));
        }
        return Some(NtStatus::STATUS_NOT_SUPPORTED);
    }

    // Map WinSock socket type + protocol to litebox Protocol.
    let lb_protocol = match (socket_type, protocol_num) {
        (SOCK_STREAM, 0 | IPPROTO_TCP) => litebox::net::Protocol::Tcp,
        (SOCK_DGRAM, 0 | IPPROTO_UDP) => litebox::net::Protocol::Udp,
        _ => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: AFD unsupported socket type={socket_type} proto={protocol_num}\n",
                ));
            }
            return Some(NtStatus::STATUS_NOT_SUPPORTED);
        }
    };

    // Get the network stack.
    let Some(net_arc) = shared.net.get() else {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform()
                .debug_log_print("NT shim: AFD socket creation failed — network not initialized\n");
        }
        return Some(NtStatus::STATUS_DEVICE_NOT_READY);
    };

    // Create the socket in the smoltcp stack.
    let socket_fd = match net_arc.lock().socket(lb_protocol) {
        Ok(fd) => fd,
        Err(e) => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: AFD Network::socket() failed: {e:?}\n",
                ));
            }
            return Some(NtStatus::STATUS_INSUFFICIENT_RESOURCES);
        }
    };

    // Create the NetworkProxy (lock-free ring buffers for I/O).
    let proxy = match socket_type {
        SOCK_STREAM => {
            let channel = litebox::net::socket_channel::StreamSocketChannel::new();
            litebox::net::socket_channel::NetworkProxy::Stream(channel)
        }
        SOCK_DGRAM => {
            let channel = litebox::net::socket_channel::DatagramSocketChannel::new();
            litebox::net::socket_channel::NetworkProxy::Datagram(channel)
        }
        _ => unreachable!(), // already filtered above
    };
    let proxy = alloc::sync::Arc::new(proxy);

    // Wire the proxy into the network subsystem so the network worker thread
    // can pump data between the smoltcp stack and the proxy ring buffers.
    if !net_arc.lock().set_socket_proxy(&socket_fd, proxy.clone()) {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform()
                .debug_log_print("NT shim: AFD set_socket_proxy failed\n");
        }
        return Some(NtStatus::STATUS_INSUFFICIENT_RESOURCES);
    }

    // Store the SocketFd + proxy directly in the handle table entry.
    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: AFD socket created type={socket_type}\n",
        ));
    }

    // Insert the Socket handle into the handle table.
    Some(insert_object_handle(
        handles,
        NtObject::Socket { socket_fd, proxy, net: alloc::sync::Arc::clone(net_arc), io_completion: None, pending_observers: alloc::vec::Vec::new(), pending_recv_observers: alloc::vec::Vec::new(), pending_dgram_event_observers: alloc::vec::Vec::new(), pending_select_observers: alloc::vec::Vec::new(), skip_completion_on_success: false },
        handle_out_ptr,
        io_status_ptr,
        1, // FILE_OPENED
    ))
}

/// Open synthetic device handles that are backed by shim logic rather than VFS.
fn try_open_special_device<FS: crate::NtShimFS>(
    nt_path: &str,
    handles: &mut HandleTable<FS>,
    handle_out_ptr: usize,
    io_status_ptr: usize,
) -> Option<NtStatus> {
    let path_lower = nt_path.to_ascii_lowercase();
    let (kind, obj) = match path_lower.as_str() {
        "\\device\\cng" => (
            "CNG",
            NtObject::Stub {
                kind: String::from("CNG"),
                io_completion: None,
            },
        ),
        "\\device\\ksecdd" => (
            "KsecDD",
            NtObject::Stub {
                kind: String::from("KsecDD"),
                io_completion: None,
            },
        ),
        "\\device\\srpdevice" => (
            "SrpDevice",
            NtObject::Stub {
                kind: String::from("SrpDevice"),
                io_completion: None,
            },
        ),
        "\\??\\nsi" => (
            "Nsi",
            NtObject::Stub {
                kind: String::from("Nsi"),
                io_completion: None,
            },
        ),
        _ => return None,
    };

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: opened synthetic device {kind} path={nt_path:?}\n",
        ));
    }

    Some(insert_object_handle(
        handles,
        obj,
        handle_out_ptr,
        io_status_ptr,
        1, // FILE_OPENED
    ))
}

/// NtCreateFile — open or create a file.
///
/// NT signature:
/// ```text
/// NTSTATUS NtCreateFile(
///     PHANDLE FileHandle,                 // r10 (out)
///     ACCESS_MASK DesiredAccess,           // rdx
///     POBJECT_ATTRIBUTES ObjectAttributes, // r8
///     PIO_STATUS_BLOCK IoStatusBlock,      // r9
///     PLARGE_INTEGER AllocationSize,       // [rsp+0x28]
///     ULONG FileAttributes,               // [rsp+0x30]
///     ULONG ShareAccess,                  // [rsp+0x38]
///     ULONG CreateDisposition,            // [rsp+0x40]
///     ULONG CreateOptions,                // [rsp+0x48]
///     PVOID EaBuffer,                     // [rsp+0x50]
///     ULONG EaLength                      // [rsp+0x58]
/// );
/// ```
pub(crate) fn nt_create_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_ptr = args.arg0;
    let desired_access = args.arg1 as u32;
    let obj_attr_ptr = args.arg2;
    let io_status_ptr = args.arg3;

    // Read stack arguments.
    let file_attributes =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let share_access =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);
    let create_disposition =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x40).unwrap_or(0);
    let create_options =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x48).unwrap_or(0);
    let ea_buffer_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x50).unwrap_or(0);
    let ea_length =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x58).unwrap_or(0);

    if handle_out_ptr == 0 || obj_attr_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Read OBJECT_ATTRIBUTES from guest memory.
    let Some(obj_attr) = crate::try_read_guest_value_unaligned::<ObjectAttributes>(obj_attr_ptr)
    else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };

    // Read the path from UNICODE_STRING.
    let Some(nt_path) = read_unicode_string_from_guest(obj_attr.object_name as usize) else {
        return NtStatus::STATUS_OBJECT_NAME_INVALID;
    };

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtCreateFile path={nt_path:?} root_dir=0x{:X} access=0x{desired_access:X}\n",
            obj_attr.root_directory,
        ));
    }

    // Handle device paths that don't go through the filesystem.
    if let Some(status) = try_open_special_device(&nt_path, handles, handle_out_ptr, io_status_ptr)
    {
        return status;
    }

    // Handle AFD (Ancillary Function Driver) socket creation.
    // mswsock.dll opens \Device\Afd\Endpoint with an EA buffer containing socket parameters.
    if let Some(status) = try_open_afd_socket(
        &nt_path,
        ea_buffer_ptr,
        ea_length,
        handles,
        shared,
        handle_out_ptr,
        io_status_ptr,
    ) {
        return status;
    }

    let nt_path_lower = nt_path.to_lowercase();
    let is_condrv_path = nt_path_lower.contains("\\device\\condrv\\");
    // Check if root directory handle is a ConDrv stub (relative open).
    let is_condrv_relative = if obj_attr.root_directory != 0 && !is_condrv_path {
        let root_h = obj_attr.root_directory as u32;
        handles
            .with(root_h, |entry| matches!(&entry.object, NtObject::Stub { kind, .. } if kind == "ConDrv"))
            .unwrap_or(false)
    } else {
        false
    };
    if is_condrv_path || is_condrv_relative {
        // When the child process has no console (spawned with pipe stdio),
        // redirect ConDrv Input/Output opens to the pipe handles instead of
        // creating real console handles.  This ensures child CRT writes go
        // through the pipe to the parent, matching real Windows behaviour
        // for processes spawned with STARTF_USESTDHANDLES + CREATE_NO_WINDOW.
        //
        // Server/Reference/Connect sub-paths always succeed as ConDrv stubs
        // (kernelbase needs them for DllMain init).
        // Console driver device — dispatch to proper handle type based on
        // the path suffix: \\Input → ConsoleInput, \\Output → ConsoleOutput,
        // everything else → generic ConDrv stub.
        let path_lower = nt_path.to_lowercase();
        let is_input = path_lower.ends_with("\\input") || path_lower.ends_with("\\currentin");
        let is_output = path_lower.ends_with("\\output") || path_lower.ends_with("\\currentout");
        let obj = if !shared.has_console && (is_input || is_output) {
            // No console: redirect Input/Output to the pipe handles from
            // ProcessParameters.  Clone the pipe buffer from the existing
            // stdio handle so writes go through the pipe to the parent.
            let src_handle = if is_input {
                shared.stdin_handle
            } else {
                shared.stdout_handle
            };
            #[cfg(feature = "trace_debug")]
            {
                use litebox::platform::DebugLogProvider as _;
                let obj_desc = handles.with(src_handle, |entry| alloc::format!("{:?}", core::mem::discriminant(&entry.object)));
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtCreateFile ConDrv->Pipe redirect attempt path={nt_path:?} src_h=0x{src_handle:X} is_input={is_input} obj={obj_desc:?}\n",
                ));
            }
            let pipe_data = handles.with(src_handle, |entry| {
                if let NtObject::Pipe { buffer, is_server, .. } = &entry.object {
                    Some((Arc::clone(buffer), *is_server))
                } else {
                    None
                }
            }).flatten();
            if let Some((cloned_buf, srv)) = pipe_data {
                #[cfg(feature = "trace_debug")]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtCreateFile ConDrv->Pipe redirect OK path={nt_path:?} src_h=0x{src_handle:X}\n",
                    ));
                }
                cloned_buf.increment(srv); // bump reference count for new handle
                NtObject::Pipe {
                    buffer: cloned_buf,
                    is_server: srv,
                    io_completion: None,
                }
            } else {
                // Fallback: no pipe found (shouldn't happen), create regular
                // console handle so DllMain doesn't crash.
                if is_input {
                    NtObject::ConsoleInput
                } else {
                    NtObject::ConsoleOutput { is_stderr: false }
                }
            }
        } else if is_input {
            NtObject::ConsoleInput
        } else if is_output {
            NtObject::ConsoleOutput { is_stderr: false }
        } else {
            NtObject::Stub {
                kind: alloc::string::String::from("ConDrv"),
                io_completion: None,
            }
        };
        let h = handles.insert(obj);
        if handle_out_ptr != 0 {
            crate::try_write_guest_value_unaligned(handle_out_ptr, h as usize);
        }
        if io_status_ptr != 0 {
            crate::try_write_guest_value_unaligned(io_status_ptr as usize, 0u64);
            crate::try_write_guest_value_unaligned((io_status_ptr + 8) as usize, 1u64);
        }
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtCreateFile ConDrv stub handle=0x{h:X} path={nt_path:?}\n",
            ));
        }
        return NtStatus::STATUS_SUCCESS;
    }

    // ── Pipe client open via server handle as RootDirectory ─────────
    // CreatePipe step 3: NtOpenFile/NtCreateFile with ObjectAttributes
    // where RootDirectory = server pipe handle, ObjectName = "" (empty).
    // This opens the client (write) end of the same pipe.
    if obj_attr.root_directory != 0 && nt_path.is_empty() {
        let root_h = obj_attr.root_directory as u32;
        let pipe_buf = handles.with(root_h, |entry| {
            if let NtObject::Pipe { buffer, .. } = &entry.object {
                Some(Arc::clone(buffer))
            } else {
                None
            }
        }).flatten();
        if let Some(client_buf) = pipe_buf {
            client_buf.increment(false); // bump client reference count
            let handle = handles.insert(NtObject::Pipe {
                buffer: client_buf,
                is_server: false,
                io_completion: None,
            });
            crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: 1, // FILE_OPENED
                };
                crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
            }
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtCreateFile pipe client open via server RootDir handle=0x{handle:X}\n",
                ));
            }
            return NtStatus::STATUS_SUCCESS;
        }
    }

    // Check for directory opens.
    let is_directory = create_options & file_options::FILE_DIRECTORY_FILE != 0;

    // MountPointManager device — used by GetFinalPathNameByHandleW to map
    // device paths (\Device\HarddiskVolumeN) to drive letters.
    if nt_path == "\\??\\MountPointManager" || nt_path == "\\Device\\MountPointManager" {
        let h = handles.insert(NtObject::Stub {
            kind: alloc::string::String::from("MountPointManager"),
            io_completion: None,
        });
        crate::try_write_guest_value_unaligned(handle_out_ptr, h as usize);
        if io_status_ptr != 0 {
            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 1 /* FILE_OPENED */);
        }
        return NtStatus::STATUS_SUCCESS;
    }

    // Translate NT path using the VFS-aware translator.
    let translated = translate_nt_path(&nt_path);

    // Try VFS path first if VFS is available.
    if let Some(ref translated) = translated
        && let Some(fs) = shared.fs.get()
    {
        let vfs_path = match translated {
            TranslatedPath::Vfs(p) => Some(p.as_str()),
            TranslatedPath::Device(p) => Some(p.as_str()),
            TranslatedPath::Registry(_) | TranslatedPath::Pipe(_) => None,
        };

        if let Some(path) = vfs_path {

            if is_directory {
                // Directory operations on VFS-translatable paths stay in VFS.
                let is_vfs_dir = fs
                    .file_status(path)
                    .is_ok_and(|s| s.file_type == litebox::fs::FileType::Directory);

                match create_disposition {
                    file_disposition::FILE_CREATE => {
                        if is_vfs_dir {
                            if io_status_ptr != 0 {
                                write_iosb(
                                    io_status_ptr,
                                    NtStatus::STATUS_OBJECT_NAME_COLLISION,
                                    0,
                                );
                            }
                            return NtStatus::STATUS_OBJECT_NAME_COLLISION;
                        }
                        // Create in VFS.
                        if let Err(e) = fs.mkdir(path, litebox::fs::Mode::RWXU) {
                            return map_mkdir_error(e);
                        }
                        return insert_directory_handle(
                            handles,
                            &nt_path,
                            handle_out_ptr,
                            io_status_ptr,
                            2, // FILE_CREATED
                        );
                    }
                    file_disposition::FILE_OPEN => {
                        if is_vfs_dir {
                            return insert_directory_handle(
                                handles,
                                &nt_path,
                                handle_out_ptr,
                                io_status_ptr,
                                1, // FILE_OPENED
                            );
                        }
                        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
                    }
                    file_disposition::FILE_OPEN_IF => {
                        if is_vfs_dir {
                            return insert_directory_handle(
                                handles,
                                &nt_path,
                                handle_out_ptr,
                                io_status_ptr,
                                1, // FILE_OPENED
                            );
                        }
                        // Create in VFS.
                        if let Err(e) = fs.mkdir(path, litebox::fs::Mode::RWXU) {
                            return map_mkdir_error(e);
                        }
                        return insert_directory_handle(
                            handles,
                            &nt_path,
                            handle_out_ptr,
                            io_status_ptr,
                            2, // FILE_CREATED
                        );
                    }
                    _ => {
                        // FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF —
                        // treat as "open existing" for directories.
                        if is_vfs_dir {
                            return insert_directory_handle(
                                handles,
                                &nt_path,
                                handle_out_ptr,
                                io_status_ptr,
                                1, // FILE_OPENED
                            );
                        }
                        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
                    }
                }
            }

            // Map NT disposition to VFS OFlags.
            let mut oflags = litebox::fs::OFlags::empty();
            match create_disposition {
                file_disposition::FILE_OPEN => {
                    // Open existing — no CREAT
                    oflags |= litebox::fs::OFlags::RDONLY;
                }
                file_disposition::FILE_CREATE => {
                    oflags |= litebox::fs::OFlags::CREAT | litebox::fs::OFlags::EXCL;
                }
                file_disposition::FILE_OPEN_IF => {
                    oflags |= litebox::fs::OFlags::CREAT;
                }
                file_disposition::FILE_OVERWRITE => {
                    oflags |= litebox::fs::OFlags::TRUNC;
                }
                file_disposition::FILE_OVERWRITE_IF | file_disposition::FILE_SUPERSEDE => {
                    oflags |= litebox::fs::OFlags::CREAT | litebox::fs::OFlags::TRUNC;
                }
                _ => {}
            }

            // Determine read/write from DesiredAccess.
            let want_read = desired_access & 0x8000_0001 != 0;
            let want_write = desired_access & 0x4000_0006 != 0;
            if want_write {
                if want_read {
                    oflags |= litebox::fs::OFlags::RDWR;
                } else {
                    oflags |= litebox::fs::OFlags::WRONLY;
                }
            } else {
                oflags |= litebox::fs::OFlags::RDONLY;
            }

            #[cfg(feature = "trace_debug")]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtCreateFile VFS open path={path:?} oflags={oflags:?} disp={create_disposition} access=0x{desired_access:X} create_options=0x{create_options:X}\n"
                ));
            }

            match fs.open(
                path,
                oflags,
                litebox::fs::Mode::RUSR | litebox::fs::Mode::WUSR,
            ) {
                Ok(typed_fd) => {
                    // Check if opened path is a directory — if so, create a
                    // Directory handle instead of File so NtQueryDirectoryFile
                    // can enumerate it (e.g. libuv's readdirSync).
                    let is_dir = fs
                        .fd_file_status(&typed_fd)
                        .map(|st| st.file_type == litebox::fs::FileType::Directory)
                        .unwrap_or(false);

                    if is_dir {
                        // Close the VFS fd — directory enumeration in
                        // nt_query_directory_file_inner opens its own fd.
                        #[cfg(any(debug_assertions, feature = "trace_debug"))]
                        {
                            use litebox::platform::DebugLogProvider as _;
                            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                                "NT shim: NtCreateFile detected DIR (fd_file_status) path={path:?} nt_path={nt_path:?}\n"
                            ));
                        }
                        let _ = fs.close(&typed_fd);
                        let handle = handles.insert(NtObject::Directory {
                            path: nt_path,
                            enum_entries: alloc::vec::Vec::new(),
                            enum_index: 0,
                        });
                        crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
                        if io_status_ptr != 0 {
                            let iosb = IoStatusBlock {
                                status: NtStatus::STATUS_SUCCESS.0,
                                _pad: 0,
                                information: 1, // FILE_OPENED
                            };
                            crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
                        }
                        return NtStatus::STATUS_SUCCESS;
                    }

                    let vfs_fd = alloc::sync::Arc::new(typed_fd);
                    let delete_flag = create_options & file_options::FILE_DELETE_ON_CLOSE != 0;
                    let handle = handles.insert(NtObject::File {
                        path: nt_path,
                        vfs_path: Some(alloc::string::String::from(path)),
                        position: Arc::new(AtomicU64::new(0)),
                        vfs_fd: alloc::sync::Arc::clone(&vfs_fd),
                        delete_on_close: Arc::new(core::sync::atomic::AtomicBool::new(delete_flag)),
                        fs: alloc::sync::Arc::clone(fs),
                    });
                    crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
                    if io_status_ptr != 0 {
                        let info = match create_disposition {
                            file_disposition::FILE_CREATE => 2, // FILE_CREATED
                            file_disposition::FILE_OPEN => 1,   // FILE_OPENED
                            _ => 1,
                        };
                        let iosb = IoStatusBlock {
                            status: NtStatus::STATUS_SUCCESS.0,
                            _pad: 0,
                            information: info,
                        };
                        crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
                    }
                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtCreateFile VFS OK path={path:?}\n",
                        ));
                    }
                    return NtStatus::STATUS_SUCCESS;
                }
                Err(e) => {
                    // VFS open failed — check if this is a phantom executable.
                    // CreateProcessW pre-flight opens the target exe; returning a
                    // PhantomExe handle lets it proceed to NtCreateUserProcess.
                    if is_phantom_executable_path(&nt_path) {
                        let handle = handles.insert(NtObject::PhantomExe {
                            path: nt_path,
                        });
                        crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
                        if io_status_ptr != 0 {
                            let iosb = IoStatusBlock {
                                status: NtStatus::STATUS_SUCCESS.0,
                                _pad: 0,
                                information: 1, // FILE_OPENED
                            };
                            crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
                        }
                        #[cfg(any(debug_assertions, feature = "trace_debug"))]
                        {
                            use litebox::platform::DebugLogProvider as _;
                            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                                "NT shim: NtCreateFile phantom exe handle=0x{handle:X} path={path:?}\n",
                            ));
                        }
                        return NtStatus::STATUS_SUCCESS;
                    }
                    // Not a phantom exe — authoritative error, no host fallback.
                    #[cfg(feature = "trace_debug")]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtCreateFile VFS FAIL path={path:?} oflags={oflags:?} err={e:?}\n",
                        ));
                    }
                    return map_open_error_to_ntstatus(&e);
                }
            }
        }
    }

    // Named pipe client open: NtCreateFile on a pipe path connects
    // to an existing pipe created by NtCreateNamedPipeFile.
    if let Some(TranslatedPath::Pipe(ref pipe_name)) = translated {
        // Empty pipe name = the root device "\Device\NamedPipe\".
        if pipe_name.is_empty() {
            let handle = handles.insert(NtObject::PipeRootDevice);
            crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: 1, // FILE_OPENED
                };
                crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
            }
            return NtStatus::STATUS_SUCCESS;
        }
        let pipe_buf = {
            let lower_name = pipe_name.to_ascii_lowercase();
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                let registry = shared.pipe_registry.lock();
                let keys: alloc::vec::Vec<_> = registry.keys().collect();
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtCreateFile pipe client lookup name=\"{}\" registry_keys={:?}\n",
                    lower_name, keys,
                ));
            }
            let registry = shared.pipe_registry.lock();
            registry.get(&lower_name).cloned()
        };
        if let Some(buf) = pipe_buf {
            buf.increment(false); // bump client reference count
            let handle = handles.insert(NtObject::Pipe {
                buffer: buf,
                is_server: false, // client (write) end
                io_completion: None,
            });
            crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: 1, // FILE_OPENED
                };
                crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
            }
            return NtStatus::STATUS_SUCCESS;
        }
        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Path not translatable to VFS — no host fallback.
    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!("NT shim: NtCreateFile path not translatable: {nt_path:?}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }
    NtStatus::STATUS_OBJECT_NAME_NOT_FOUND
}

// ========================================================================
// NtReadFile / NtWriteFile — VFS path
// ========================================================================

/// NtReadFile — read from a VFS file descriptor.
///
/// Called after handle-table lock is dropped. Uses the raw_fd to look up
/// the TypedFd in RawDescriptorStorage and reads via the VFS.
pub(crate) fn nt_read_file_vfs<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    vfs_fd: &litebox::fd::TypedFd<FS>,
    position: &alloc::sync::Arc<AtomicU64>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let io_status_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let buffer_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let length = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);
    let byte_offset_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x40).unwrap_or(0);

    if buffer_ptr == 0 || length == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    const FILE_USE_FILE_POINTER_POSITION: i64 = -2;

    let (read_offset, advance_pos) = if byte_offset_ptr != 0 {
        let Some(offset) = crate::try_read_guest_value_unaligned::<i64>(byte_offset_ptr) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        if offset >= 0 {
            (Some(offset as u64), false) // positional read
        } else if offset == FILE_USE_FILE_POINTER_POSITION {
            let pos = position.load(Relaxed);
            (Some(pos), true) // sequential read
        } else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
    } else {
        let pos = position.load(Relaxed);
        (Some(pos), true) // no offset pointer → sequential
    };

    if !crate::is_addr_range_writable(buffer_ptr, length as usize) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    // Safety: range validated by is_addr_range_writable above.
    let buf = unsafe { core::slice::from_raw_parts_mut(buffer_ptr as *mut u8, length as usize) };
    let Some(fs) = shared.fs.get() else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    match fs.read(vfs_fd, buf, read_offset.map(|o| o as usize)) {
        Ok(bytes_read) => {
            if advance_pos {
                position.fetch_add(bytes_read as u64, Relaxed);
            }
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: bytes_read as u64,
                };
                crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
            }
            if bytes_read == 0 {
                NtStatus::STATUS_END_OF_FILE
            } else {
                NtStatus::STATUS_SUCCESS
            }
        }
        Err(_) => NtStatus::STATUS_END_OF_FILE,
    }
}

/// NtWriteFile — write to a VFS file descriptor.
pub(crate) fn nt_write_file_vfs<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    vfs_fd: &litebox::fd::TypedFd<FS>,
    position: &alloc::sync::Arc<AtomicU64>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let io_status_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let buffer_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let length = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);
    let byte_offset_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x40).unwrap_or(0);

    if length == 0 {
        if io_status_ptr != 0 {
            let iosb = IoStatusBlock {
                status: NtStatus::STATUS_SUCCESS.0,
                _pad: 0,
                information: 0,
            };
            crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
        }
        return NtStatus::STATUS_SUCCESS;
    }
    if buffer_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let (write_offset, advance_pos) = if byte_offset_ptr != 0 {
        let Some(offset) = crate::try_read_guest_value_unaligned::<i64>(byte_offset_ptr) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        if offset >= 0 {
            (Some(offset as u64), false)
        } else {
            let pos = position.load(Relaxed);
            (Some(pos), true)
        }
    } else {
        let pos = position.load(Relaxed);
        (Some(pos), true)
    };

    if !crate::is_addr_range_committed(buffer_ptr, length as usize) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    // Safety: range validated by is_addr_range_committed above.
    let buf = unsafe { core::slice::from_raw_parts(buffer_ptr as *const u8, length as usize) };

    let Some(fs) = shared.fs.get() else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    match fs.write(vfs_fd, buf, write_offset.map(|o| o as usize)) {
        Ok(bytes_written) => {
            if advance_pos {
                position.fetch_add(bytes_written as u64, Relaxed);
            }
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: bytes_written as u64,
                };
                crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
            }
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => NtStatus::STATUS_UNSUCCESSFUL,
    }
}

/// FILE_ATTRIBUTE_DIRECTORY — used for directory metadata.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

// ========================================================================
// NtReadFile — console only; host read path removed (all files via VFS).
// ========================================================================

/// NtReadFile — read from ConsoleInput.
///
/// Called after handle-table lock is dropped.
pub(crate) fn nt_read_file_console(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let io_status_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let buffer_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let length = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);

    if buffer_ptr == 0 || length == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    if !crate::is_addr_range_writable(buffer_ptr, length as usize) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    // Safety: range validated by is_addr_range_writable above.
    let buf = unsafe { core::slice::from_raw_parts_mut(buffer_ptr as *mut u8, length as usize) };
    use litebox::platform::StdioProvider as _;
    match litebox_platform_multiplex::platform().read_from_stdin(buf) {
        Ok(bytes_read) => {
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: bytes_read as u64,
                };
                crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
            }
            if bytes_read == 0 {
                NtStatus::STATUS_END_OF_FILE
            } else {
                NtStatus::STATUS_SUCCESS
            }
        }
        Err(_) => NtStatus::STATUS_END_OF_FILE,
    }
}

// ========================================================================
// NtWriteFile (enhanced for file handles)
// ========================================================================

/// NtWriteFile — write to ConsoleOutput via platform StdioProvider.
///
/// Called after handle-table lock is dropped.
pub(crate) fn nt_write_file_console(
    ctx: &mut super::super::ExecutionContext,
    is_stderr: bool,
) -> NtStatus {
    let io_status_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let buffer_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let length = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);

    let mut bytes_written = 0u32;
    if buffer_ptr != 0 && length > 0 {
        if !crate::is_addr_range_committed(buffer_ptr, length as usize) {
            return NtStatus::STATUS_ACCESS_VIOLATION;
        }
        // Safety: range validated by is_addr_range_committed above.
        let buf = unsafe { core::slice::from_raw_parts(buffer_ptr as *const u8, length as usize) };
        let stream = if is_stderr {
            litebox::platform::StdioOutStream::Stderr
        } else {
            litebox::platform::StdioOutStream::Stdout
        };
        use litebox::platform::StdioProvider as _;
        match litebox_platform_multiplex::platform().write_to(stream, buf) {
            Ok(n) => bytes_written = n as u32,
            Err(_) => return NtStatus::STATUS_UNSUCCESSFUL,
        }
    }
    if io_status_ptr != 0 {
        let iosb = IoStatusBlock {
            status: NtStatus::STATUS_SUCCESS.0,
            _pad: 0,
            information: bytes_written as u64,
        };
        crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
    }
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// NtQueryInformationFile
// ========================================================================

/// NtQueryInformationFile — query file metadata.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryInformationFile(
///     HANDLE FileHandle,                    // r10
///     PIO_STATUS_BLOCK IoStatusBlock,       // rdx
///     PVOID FileInformation,                // r8
///     ULONG Length,                         // r9
///     FILE_INFORMATION_CLASS FileInfoClass  // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_query_information_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let file_handle = args.arg0 as u32;
    let io_status_ptr = args.arg1;
    let info_ptr = args.arg2;
    let info_length = args.arg3 as u32;

    let info_class = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x28).unwrap_or(0);

    let Some(status) = handles.with(file_handle, |entry| {
    match &entry.object {
        NtObject::File {
            vfs_fd, position, ..
        } => {
            // All files are now VFS-backed.
            match info_class {
                // FileBasicInformation (4) — synthesize from VFS.
                4 => {
                    let size = core::mem::size_of::<FileBasicInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    // Return default timestamps for VFS files.
                    let info = FileBasicInformation {
                        file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
                        ..FileBasicInformation::default()
                    };
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FileStandardInformation (5) — get size from VFS.
                5 => {
                    let size = core::mem::size_of::<FileStandardInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let file_size = (|| -> Option<i64> {
                        let fs = shared.fs.get()?;
                        let st = fs.fd_file_status(vfs_fd).ok()?;
                        Some(st.size as i64)
                    })()
                    .unwrap_or(0);
                    let info = FileStandardInformation {
                        allocation_size: (file_size + 4095) & !4095,
                        end_of_file: file_size,
                        number_of_links: 1,
                        delete_pending: 0,
                        directory: 0,
                        _pad: [0; 2],
                    };
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FilePositionInformation (14) — from cached position.
                14 => {
                    let size = core::mem::size_of::<FilePositionInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FilePositionInformation {
                        current_byte_offset: position.load(Relaxed) as i64,
                    };
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FileAttributeTagInformation (35) — needed by DeleteFileW.
                // Returns { ULONG FileAttributes; ULONG ReparseTag; } = 8 bytes.
                35 => {
                    if (info_length as usize) < 8 || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let attrs: u32 = 0x80; // FILE_ATTRIBUTE_NORMAL
                    let reparse_tag: u32 = 0;
                    crate::try_write_guest_value_unaligned(info_ptr, attrs);
                    crate::try_write_guest_value_unaligned(info_ptr + 4, reparse_tag);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 8);
                    NtStatus::STATUS_SUCCESS
                }
                // FileAllInformation (18) — combined struct needed by libuv's
                // fs__unlink (queries this before NtSetInformationFile delete).
                // Layout (minimum 104 bytes):
                //   +0   FileBasicInformation      (40 bytes)
                //   +40  FileStandardInformation    (24 bytes)
                //   +64  FileInternalInformation    (8 bytes)
                //   +72  FileEaInformation          (4 bytes)
                //   +76  FileAccessInformation      (4 bytes)
                //   +80  FilePositionInformation    (8 bytes)
                //   +88  FileModeInformation        (4 bytes)
                //   +92  FileAlignmentInformation   (4 bytes)
                //   +96  FileNameInformation        (8+ bytes: 4 len + variable name)
                // We return 104 bytes total (FileNameLength=0, no name chars).
                18 => {
                    const FILE_ALL_MIN_SIZE: usize = 104;
                    if (info_length as usize) < FILE_ALL_MIN_SIZE || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    if !crate::is_addr_range_writable(info_ptr, FILE_ALL_MIN_SIZE) {
                        return NtStatus::STATUS_ACCESS_VIOLATION;
                    }
                    // Zero the entire buffer first.
                    unsafe {
                        core::ptr::write_bytes(info_ptr as *mut u8, 0, FILE_ALL_MIN_SIZE);
                    }

                    // Get file size from VFS (same pattern as class 5 handler).
                    let file_size = (|| -> Option<i64> {
                        let fs = shared.fs.get()?;
                        let st = fs.fd_file_status(vfs_fd).ok()?;
                        Some(st.size as i64)
                    })()
                    .unwrap_or(0);

                    // +0: FileBasicInformation (40 bytes)
                    // Timestamps stay 0, just set FileAttributes.
                    let file_attrs: u32 = 0x80; // FILE_ATTRIBUTE_NORMAL
                    crate::try_write_guest_value_unaligned(info_ptr + 32, file_attrs);

                    // +40: FileStandardInformation (24 bytes)
                    let alloc_size: i64 = (file_size + 4095) & !4095;
                    crate::try_write_guest_value_unaligned(info_ptr + 40, alloc_size);
                    crate::try_write_guest_value_unaligned(info_ptr + 48, file_size); // EndOfFile
                    let num_links: u32 = 1;
                    crate::try_write_guest_value_unaligned(info_ptr + 56, num_links);
                    // DeletePending(u8)=0, Directory(u8)=0, pad=0 — already zeroed

                    // +64: FileInternalInformation (8 bytes) — IndexNumber = 0 (zeroed)
                    // +72: FileEaInformation (4 bytes) — EaSize = 0 (zeroed)

                    // +76: FileAccessInformation (4 bytes)
                    // Return a generous access mask so libuv doesn't bail.
                    let access_flags: u32 = 0x1F01FF; // FILE_ALL_ACCESS
                    crate::try_write_guest_value_unaligned(info_ptr + 76, access_flags);

                    // +80: FilePositionInformation (8 bytes)
                    let cur_offset: i64 = position.load(Relaxed) as i64;
                    crate::try_write_guest_value_unaligned(info_ptr + 80, cur_offset);

                    // +88: FileModeInformation (4 bytes) — Mode = 0 (zeroed)
                    // +92: FileAlignmentInformation (4 bytes) — AlignmentReq = 0 (zeroed)

                    // +96: FileNameInformation (8 bytes minimum)
                    // FileNameLength = 0 (no name); the 4-byte length field + 4 bytes
                    // of padding/space already zeroed — total 104 bytes.

                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, FILE_ALL_MIN_SIZE);
                    NtStatus::STATUS_SUCCESS
                }
                _ => NtStatus::STATUS_INVALID_INFO_CLASS,
            }
        }
        NtObject::ConsoleOutput { .. } | NtObject::ConsoleInput => {
            // Console handles: return minimal info.
            // With FILE_DEVICE_DISK, the CRT treats these as disk files and may
            // query FilePositionInformation (14) and FileBasicInformation (4)
            // during _write().  We must succeed for these or CRT silently skips
            // the write (the _flushall() mystery).
            match info_class {
                // FileBasicInformation (4)
                4 => {
                    let size = core::mem::size_of::<FileBasicInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FileBasicInformation {
                        file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
                        ..FileBasicInformation::default()
                    };
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FileStandardInformation (5)
                5 => {
                    let size = core::mem::size_of::<FileStandardInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FileStandardInformation::default();
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FilePositionInformation (14) — CRT queries position before disk writes.
                14 => {
                    let size = core::mem::size_of::<FilePositionInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FilePositionInformation {
                        current_byte_offset: 0,
                    };
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                _ => NtStatus::STATUS_INVALID_INFO_CLASS,
            }
        }
        NtObject::Directory { path, .. } => {
            // Directory handles: return basic metadata.
            match info_class {
                // FileBasicInformation (4)
                4 => {
                    let size = core::mem::size_of::<FileBasicInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FileBasicInformation {
                        file_attributes: FILE_ATTRIBUTE_DIRECTORY,
                        ..FileBasicInformation::default()
                    };
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FileStandardInformation (5)
                5 => {
                    let size = core::mem::size_of::<FileStandardInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FileStandardInformation {
                        directory: 1,
                        ..FileStandardInformation::default()
                    };
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FileAttributeTagInformation (35)
                35 => {
                    if (info_length as usize) < 8 || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let attrs: u32 = FILE_ATTRIBUTE_DIRECTORY;
                    let reparse_tag: u32 = 0;
                    crate::try_write_guest_value_unaligned(info_ptr, attrs);
                    crate::try_write_guest_value_unaligned(info_ptr + 4, reparse_tag);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 8);
                    NtStatus::STATUS_SUCCESS
                }
                // FileNameInformation (9) — needed by GetFinalPathNameByHandleW
                9 => {
                    let nt_path = path;
                    // Extract the path portion after the drive letter.
                    // The path is stored as \??\C:\Users\... — we need \Users\...
                    let file_part = if let Some(rest) = nt_path.strip_prefix("\\??\\") {
                        if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
                            &rest[2..]
                        } else {
                            rest
                        }
                    } else {
                        nt_path.as_str()
                    };
                    let utf16: alloc::vec::Vec<u16> = file_part.encode_utf16().collect();
                    let name_bytes = utf16.len() * 2;
                    // FILE_NAME_INFORMATION: u32 FileNameLength + WCHAR FileName[]
                    let needed = 4 + name_bytes;
                    if (info_length as usize) < needed || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    // FileNameLength (in bytes)
                    crate::try_write_guest_value_unaligned(info_ptr, name_bytes as u32);
                    // FileName (UTF-16)
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            utf16.as_ptr() as *const u8,
                            (info_ptr + 4) as *mut u8,
                            name_bytes,
                        );
                    }
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, needed);
                    NtStatus::STATUS_SUCCESS
                }
                _ => NtStatus::STATUS_INVALID_INFO_CLASS,
            }
        }
        NtObject::Pipe { is_server, buffer, .. } => {
            let is_server = *is_server;
            // Named pipe handles: return pipe-appropriate metadata.
            match info_class {
                // FileBasicInformation (4)
                4 => {
                    let size = core::mem::size_of::<FileBasicInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FileBasicInformation {
                        file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
                        ..FileBasicInformation::default()
                    };
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FileStandardInformation (5) — pipes have no meaningful size
                5 => {
                    let size = core::mem::size_of::<FileStandardInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FileStandardInformation::default();
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FilePipeInformation (23) — libuv queries this
                // Return minimal: { ReadMode: BYTE_STREAM(0), CompletionMode: QUEUE(0) }
                23 => {
                    if (info_length as usize) < 8 || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let read_mode: u32 = 0; // FILE_PIPE_BYTE_STREAM_MODE
                    let completion_mode: u32 = 0; // FILE_PIPE_QUEUE_OPERATION
                    crate::try_write_guest_value_unaligned(info_ptr, read_mode);
                    crate::try_write_guest_value_unaligned(info_ptr + 4, completion_mode);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 8);
                    NtStatus::STATUS_SUCCESS
                }
                // FilePipeLocalInformation (24) — libuv queries this during
                // pipe shutdown to check if the write buffer is empty.
                //
                // FILE_PIPE_LOCAL_INFORMATION (40 bytes / 10 ULONGs):
                //   offset  0: NamedPipeType          (0 = byte stream)
                //   offset  4: NamedPipeConfiguration (0 = full duplex)
                //   offset  8: MaximumInstances       (1)
                //   offset 12: CurrentInstances       (1)
                //   offset 16: InboundQuota           (capacity)
                //   offset 20: ReadDataAvailable      (bytes buffered)
                //   offset 24: OutboundQuota          (capacity)
                //   offset 28: WriteQuotaAvailable    (capacity - buffered)
                //   offset 32: NamedPipeState         (3 = connected)
                //   offset 36: NamedPipeEnd           (0 = client, 1 = server)
                24 => {
                    const PIPE_LOCAL_INFO_SIZE: usize = 40;
                    if (info_length as usize) < PIPE_LOCAL_INFO_SIZE || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    if !crate::is_addr_range_writable(info_ptr, PIPE_LOCAL_INFO_SIZE) {
                        return NtStatus::STATUS_ACCESS_VIOLATION;
                    }
                    // Zero the struct first, then fill in fields.
                    unsafe { core::ptr::write_bytes(info_ptr as *mut u8, 0, PIPE_LOCAL_INFO_SIZE); }

                    let cap = buffer.capacity as u32;
                    let buffered = buffer.data.lock().len() as u32;
                    let write_avail = cap.saturating_sub(buffered);
                    let pipe_end: u32 = if is_server { 1 } else { 0 };

                    // NamedPipeType (offset 0) = 0 (byte stream) — already zeroed
                    // NamedPipeConfiguration (offset 4) = 0 (full duplex) — already zeroed
                    crate::try_write_guest_value_unaligned(info_ptr + 8, 1u32);        // MaximumInstances
                    crate::try_write_guest_value_unaligned(info_ptr + 12, 1u32);       // CurrentInstances
                    crate::try_write_guest_value_unaligned(info_ptr + 16, cap);        // InboundQuota
                    crate::try_write_guest_value_unaligned(info_ptr + 20, buffered);   // ReadDataAvailable
                    crate::try_write_guest_value_unaligned(info_ptr + 24, cap);        // OutboundQuota
                    crate::try_write_guest_value_unaligned(info_ptr + 28, write_avail);// WriteQuotaAvailable
                    crate::try_write_guest_value_unaligned(info_ptr + 32, 3u32);       // NamedPipeState (FILE_PIPE_CONNECTED_STATE)
                    crate::try_write_guest_value_unaligned(info_ptr + 36, pipe_end);   // NamedPipeEnd

                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, PIPE_LOCAL_INFO_SIZE);
                    NtStatus::STATUS_SUCCESS
                }
                _ => NtStatus::STATUS_INVALID_INFO_CLASS,
            }
        }
        _ => NtStatus::STATUS_INVALID_HANDLE,
    }
    }) else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };
    status
}

// ========================================================================
// NtSetInformationFile
// ========================================================================

/// NtSetInformationFile — set file metadata (mainly position/seek).
///
/// NT signature:
/// ```text
/// NTSTATUS NtSetInformationFile(
///     HANDLE FileHandle,                    // r10
///     PIO_STATUS_BLOCK IoStatusBlock,       // rdx
///     PVOID FileInformation,                // r8
///     ULONG Length,                         // r9
///     FILE_INFORMATION_CLASS FileInfoClass  // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_set_information_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let file_handle = args.arg0 as u32;
    let io_status_ptr = args.arg1;
    let info_ptr = args.arg2;
    let info_length = args.arg3 as u32;

    let info_class = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x28).unwrap_or(0);

    // ── FileIoCompletionNotificationInformation (41) ────────────────
    // Set completion notification modes on a handle.
    // Layout: struct { ULONG Flags; } = 4 bytes.
    //   FILE_SKIP_COMPLETION_PORT_ON_SUCCESS = 0x1
    //   FILE_SKIP_SET_EVENT_ON_HANDLE        = 0x2
    // Used by c-ares and libuv (via SetFileCompletionNotificationModes).
    //   FILE_SKIP_COMPLETION_PORT_ON_SUCCESS = 0x1
    //   FILE_SKIP_SET_EVENT_ON_HANDLE        = 0x2
    // When flag 0x1 is set, synchronous I/O completions (status != PENDING)
    // must NOT post to the I/O completion port. libuv sets this on sockets
    // to avoid spurious IOCP notifications for operations that complete
    // immediately (like zero-byte recv fast-path hits).
    if info_class == 41 {
        if (info_length as usize) < 4 || info_ptr == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
        let flags = crate::try_read_guest_value_unaligned::<u32>(info_ptr).unwrap_or(0);

        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtSetInformationFile FileIoCompletionNotificationInfo handle=0x{file_handle:X} flags=0x{flags:X}\n"
            ));
        }

        // Store the skip-completion flag on socket handles.
        if (flags & 0x1) != 0 {
            handles.with_mut(file_handle, |entry| {
                if let crate::handle_table::NtObject::Socket {
                    ref mut skip_completion_on_success, ..
                } = entry.object
                {
                    *skip_completion_on_success = true;
                }
            });
        }

        write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 4);
        return NtStatus::STATUS_SUCCESS;
    }

    // ── FileCompletionInformation (30) ──────────────────────────────
    // Bind a file/pipe handle to an I/O Completion Port.
    // Layout: struct { HANDLE Port; PVOID Key; } = 16 bytes on x64.
    // Handled before the main match because it needs mutable handle access.
    if info_class == 30 {
        if (info_length as usize) < 16 || info_ptr == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
        if !handles.contains(file_handle) {
            return NtStatus::STATUS_INVALID_HANDLE;
        }
        let iocp_handle =
            crate::try_read_guest_value_unaligned::<u64>(info_ptr).unwrap_or(0) as u32;
        let completion_key =
            crate::try_read_guest_value_unaligned::<usize>(info_ptr + 8).unwrap_or(0);

        #[cfg(feature = "trace_debug")]
        {
            // Dump the raw 16 bytes of FILE_COMPLETION_INFORMATION for debugging
            let mut raw = [0u8; 16];
            for i in 0..16 {
                raw[i] = crate::try_read_guest_value_unaligned::<u8>(info_ptr + i).unwrap_or(0xFF);
            }
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: FileCompletionInfo raw bytes at 0x{info_ptr:X}: {:02X?}\n", raw
            ));
        }

        // Look up the IOCP object.
        let iocp_arc = super::sync::lookup_io_completion(handles, iocp_handle);
        let Some(port) = iocp_arc else {
            #[cfg(feature = "trace_debug")]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtSetInformationFile FileCompletionInfo IOCP handle 0x{iocp_handle:X} not found\n",
                ));
            }
            // Not an IOCP handle — silently succeed (matches Windows behavior).
            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 0);
            return NtStatus::STATUS_SUCCESS;
        };

        // Mutably access the file handle to store the IOCP binding.
        handles.with_mut(file_handle, |entry| {
            match &mut entry.object {
                NtObject::Pipe { io_completion, buffer, is_server, .. } => {
                    #[cfg(feature = "trace_debug")]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtSetInformationFile FileCompletionInfo pipe 0x{file_handle:X} is_server={} -> IOCP 0x{iocp_handle:X} key=0x{completion_key:X}\n",
                            is_server,
                        ));
                    }
                    *io_completion = Some((Arc::clone(&port), completion_key));
                    // Also record the binding on the shared PipeBuffer so that
                    // break_pending_reads() can post pipe-broken even with 0
                    // pending reads.
                    if *is_server {
                        *buffer.server_iocp.lock() = Some((Arc::clone(&port), completion_key));
                    }
                }
                NtObject::Stub { io_completion, .. } => {
                    #[cfg(feature = "trace_debug")]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtSetInformationFile FileCompletionInfo stub 0x{file_handle:X} -> IOCP 0x{iocp_handle:X} key=0x{completion_key:X}\n",
                        ));
                    }
                    *io_completion = Some((Arc::clone(&port), completion_key));
                }
                NtObject::Socket { io_completion, .. } => {
                    #[cfg(feature = "trace_debug")]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtSetInformationFile FileCompletionInfo socket 0x{file_handle:X} -> IOCP 0x{iocp_handle:X} key=0x{completion_key:X} iocp_ptr={:p}\n",
                            Arc::as_ptr(&port),
                        ));
                    }
                    *io_completion = Some((Arc::clone(&port), completion_key));
                }
                _ => {
                    #[cfg(feature = "trace_debug")]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtSetInformationFile FileCompletionInfo on non-pipe/stub 0x{file_handle:X} (ignored)\n",
                        ));
                    }
                }
            }
        });

        write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 16);
        return NtStatus::STATUS_SUCCESS;
    }

    // ── FileRenameInformation (10) / FileRenameInformationEx (65) ───
    // Rename a file or directory.
    // Layout (x64):
    //   offset 0:  union { BOOLEAN ReplaceIfExists; ULONG Flags; } (4 bytes + 4 pad)
    //   offset 8:  HANDLE  RootDirectory  (8 bytes)
    //   offset 16: ULONG   FileNameLength (in bytes)
    //   offset 20: WCHAR   FileName[1]    (new name, UTF-16LE, not null-terminated)
    if info_class == 10 || info_class == 65 {
        // Minimum header is 20 bytes + at least 2 bytes for one WCHAR.
        if (info_length as usize) < 22 || info_ptr == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }

        let _replace_flags =
            crate::try_read_guest_value_unaligned::<u32>(info_ptr).unwrap_or(0);
        let root_dir_handle =
            crate::try_read_guest_value_unaligned::<u64>(info_ptr + 8).unwrap_or(0);
        let file_name_length =
            crate::try_read_guest_value_unaligned::<u32>(info_ptr + 16).unwrap_or(0) as usize;

        if file_name_length == 0 || file_name_length > 0x10000 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }

        // Read the UTF-16LE new filename.
        let wchar_count = file_name_length / 2;
        let mut new_name_u16 = alloc::vec::Vec::with_capacity(wchar_count);
        for i in 0..wchar_count {
            let w = crate::try_read_guest_value_unaligned::<u16>(info_ptr + 20 + i * 2)
                .unwrap_or(0);
            new_name_u16.push(w);
        }
        let new_name_raw = alloc::string::String::from_utf16_lossy(&new_name_u16);

        // Get the old NT path from the handle.
        let old_nt_path = handles
            .with(file_handle, |entry| match &entry.object {
                NtObject::File { path, .. } => Some(path.clone()),
                NtObject::Directory { path, .. } => Some(path.clone()),
                _ => None,
            })
            .flatten();
        let Some(old_nt_path) = old_nt_path else {
            return NtStatus::STATUS_INVALID_HANDLE;
        };

        // Build full new NT path. If RootDirectory handle is set and the name
        // is relative, resolve against that directory.
        let full_new_nt_path = if root_dir_handle != 0
            && !is_absolute_nt_or_dos_path(&new_name_raw)
        {
            let root_path = handles
                .with(root_dir_handle as u32, |entry| match &entry.object {
                    NtObject::Directory { path, .. } => Some(path.clone()),
                    NtObject::File { path, .. } => Some(path.clone()),
                    _ => None,
                })
                .flatten();
            match root_path {
                Some(rp) => join_nt_paths(&rp, &new_name_raw),
                None => new_name_raw.clone(),
            }
        } else {
            new_name_raw.clone()
        };

        // Translate NT paths → VFS paths.
        let old_vfs = translate_nt_path(&old_nt_path).and_then(|t| match t {
            TranslatedPath::Vfs(p) => Some(p),
            _ => None,
        });
        let new_vfs = translate_nt_path(&full_new_nt_path).and_then(|t| match t {
            TranslatedPath::Vfs(p) => Some(p),
            _ => None,
        });

        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtSetInformationFile FileRenameInformation handle=0x{file_handle:X} old={old_nt_path:?} new={full_new_nt_path:?} old_vfs={old_vfs:?} new_vfs={new_vfs:?}\n"
            ));
        }

        let (Some(old_vfs_path), Some(new_vfs_path)) = (old_vfs, new_vfs) else {
            return NtStatus::STATUS_OBJECT_NAME_INVALID;
        };

        if let Some(fs) = shared.fs.get() {
            match fs.rename(old_vfs_path.as_str(), new_vfs_path.as_str()) {
                Ok(()) => {
                    // Update the handle's stored path to reflect the new name.
                    handles.with_mut(file_handle, |entry| {
                        match &mut entry.object {
                            NtObject::File { path, vfs_path, .. } => {
                                *path = full_new_nt_path.clone();
                                *vfs_path = Some(new_vfs_path.clone());
                            }
                            NtObject::Directory { path, .. } => {
                                *path = full_new_nt_path.clone();
                            }
                            _ => {}
                        }
                    });
                    write_iosb(
                        io_status_ptr,
                        NtStatus::STATUS_SUCCESS,
                        info_length as usize,
                    );
                    return NtStatus::STATUS_SUCCESS;
                }
                Err(_e) => {
                    #[cfg(feature = "trace_debug")]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtSetInformationFile FileRenameInformation FAILED: {_e:?}\n"
                        ));
                    }
                    return NtStatus::STATUS_ACCESS_DENIED;
                }
            }
        } else {
            return NtStatus::STATUS_UNSUCCESSFUL;
        }
    }

    let Some(status) = handles.with(file_handle, |entry| {
    match &entry.object {
        NtObject::File { position, vfs_fd, delete_on_close, .. } => match info_class {
            // FilePositionInformation (14) — seek. VFS files just update cached position.
            14 => {
                let size = core::mem::size_of::<FilePositionInformation>();
                if (info_length as usize) < size || info_ptr == 0 {
                    return NtStatus::STATUS_INVALID_PARAMETER;
                }
                let Some(info) =
                    crate::try_read_guest_value_unaligned::<FilePositionInformation>(info_ptr)
                else {
                    return NtStatus::STATUS_INVALID_PARAMETER;
                };
                if info.current_byte_offset >= 0 {
                    position.store(info.current_byte_offset as u64, Relaxed);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                } else {
                    NtStatus::STATUS_INVALID_PARAMETER
                }
            }
            // FileDispositionInformation (13) — mark/unmark for delete-on-close.
            // Layout: struct { BOOLEAN DeleteFile; } — 1 byte, non-zero means delete.
            13 => {
                if info_length < 1 || info_ptr == 0 {
                    return NtStatus::STATUS_INVALID_PARAMETER;
                }
                let flag = crate::try_read_guest_value_unaligned::<u8>(info_ptr).unwrap_or(0);
                delete_on_close.store(flag != 0, core::sync::atomic::Ordering::Release);
                write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 1);
                NtStatus::STATUS_SUCCESS
            }
            // FileDispositionInformationEx (64) — extended delete-on-close.
            // Layout: struct { ULONG Flags; } where bit 0 = FILE_DISPOSITION_DELETE.
            64 => {
                if (info_length as usize) < 4 || info_ptr == 0 {
                    return NtStatus::STATUS_INVALID_PARAMETER;
                }
                let flags = crate::try_read_guest_value_unaligned::<u32>(info_ptr).unwrap_or(0);
                // Bit 0: FILE_DISPOSITION_DELETE
                let should_delete = flags & 1 != 0;
                delete_on_close.store(should_delete, core::sync::atomic::Ordering::Release);
                write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 4);
                NtStatus::STATUS_SUCCESS
            }
            // FileAllocationInformation (19) / FileEndOfFileInformation (20) — truncate.
            19 | 20 => {
                if (info_length as usize) < 8 || info_ptr == 0 {
                    return NtStatus::STATUS_INVALID_PARAMETER;
                }
                let Some(new_size) =
                    crate::try_read_guest_value_unaligned::<i64>(info_ptr)
                else {
                    return NtStatus::STATUS_INVALID_PARAMETER;
                };
                if new_size < 0 {
                    return NtStatus::STATUS_INVALID_PARAMETER;
                }
                if let Some(fs) = shared.fs.get() {
                    match fs.truncate(vfs_fd, new_size as usize, false) {
                        Ok(()) => {
                            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 8);
                            NtStatus::STATUS_SUCCESS
                        }
                        Err(_) => NtStatus::STATUS_ACCESS_DENIED,
                    }
                } else {
                    NtStatus::STATUS_UNSUCCESSFUL
                }
            }
            _ => NtStatus::STATUS_INVALID_INFO_CLASS,
        },
        _ => {
            // Non-file handles: accept silently.
            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 0);
            NtStatus::STATUS_SUCCESS
        }
    }
    }) else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };
    status
}

// ========================================================================
// NtQueryAttributesFile
// ========================================================================

/// NtQueryAttributesFile — quick file existence/attribute check.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryAttributesFile(
///     POBJECT_ATTRIBUTES ObjectAttributes,           // r10
///     PFILE_BASIC_INFORMATION FileInformation         // rdx
/// );
/// ```
pub(crate) fn nt_query_attributes_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let obj_attr_ptr = args.arg0;
    let info_ptr = args.arg1;

    // Resolve the path first for logging
    let nt_path_for_log = resolve_object_attributes_path(obj_attr_ptr, Some(handles))
        .unwrap_or_default();

    match query_object_attributes_file_status(obj_attr_ptr, Some(handles), shared) {
        Ok(status) => {
            let attrs = file_attributes_from_status(&status);
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtQueryAttributesFile OK path={nt_path_for_log:?} attrs=0x{attrs:08X} file_type={:?}\n",
                    status.file_type,
                ));
            }
            if info_ptr != 0 {
                let info = FileBasicInformation {
                    file_attributes: attrs,
                    ..FileBasicInformation::default()
                };
                crate::try_write_guest_value_unaligned(info_ptr, info);
            }
            NtStatus::STATUS_SUCCESS
        }
        Err(status) => {
            // If the file wasn't found in VFS but the path is a phantom
            // executable, report it as existing so CreateProcessW's pre-flight
            // NtQueryAttributesFile checks pass.
            if is_phantom_executable_path(&nt_path_for_log) {
                if info_ptr != 0 {
                    let info = FileBasicInformation {
                        file_attributes: file_attributes::FILE_ATTRIBUTE_NORMAL,
                        ..FileBasicInformation::default()
                    };
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                }
                #[cfg(any(debug_assertions, feature = "trace_debug"))]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtQueryAttributesFile phantom exe OK path={nt_path_for_log:?}\n",
                    ));
                }
                return NtStatus::STATUS_SUCCESS;
            }
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtQueryAttributesFile FAIL path={nt_path_for_log:?} status=0x{:08X}\n",
                    status.0,
                ));
            }
            status
        }
    }
}

// ========================================================================
// NtQueryFullAttributesFile
// ========================================================================

/// NtQueryFullAttributesFile — quick file existence/attribute check that
/// returns FILE_NETWORK_OPEN_INFORMATION (includes sizes + times + attrs).
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryFullAttributesFile(
///     POBJECT_ATTRIBUTES ObjectAttributes,                 // r10
///     PFILE_NETWORK_OPEN_INFORMATION NetworkInformation    // rdx
/// );
/// ```
pub(crate) fn nt_query_full_attributes_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    use litebox_common_windows::nt_types::FileNetworkOpenInformation;

    let args = NtSyscallArgs::from_ctx(ctx);
    let obj_attr_ptr = args.arg0;
    let info_ptr = args.arg1;

    let nt_path_for_log = resolve_object_attributes_path(obj_attr_ptr, Some(handles))
        .unwrap_or_default();

    match query_object_attributes_file_status(obj_attr_ptr, Some(handles), shared) {
        Ok(status) => {
            let attrs = file_attributes_from_status(&status);
            let end_of_file = file_size_from_status(&status);
            let alloc_size = allocation_size_from_status(&status);
            let times = query_host_file_times(&nt_path_for_log);

            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtQueryFullAttributesFile OK path={nt_path_for_log:?} attrs=0x{attrs:08X} size={end_of_file}\n",
                ));
            }

            if info_ptr != 0 {
                let info = FileNetworkOpenInformation {
                    creation_time: times.creation_time,
                    last_access_time: times.last_access_time,
                    last_write_time: times.last_write_time,
                    change_time: times.change_time,
                    allocation_size: alloc_size,
                    end_of_file,
                    file_attributes: attrs,
                    _pad: 0,
                };
                crate::try_write_guest_value_unaligned(info_ptr, info);
            }
            NtStatus::STATUS_SUCCESS
        }
        Err(status) => {
            // Phantom executable fallback (same as NtQueryAttributesFile).
            if is_phantom_executable_path(&nt_path_for_log) {
                if info_ptr != 0 {
                    let times = synthetic_file_times();
                    let info = FileNetworkOpenInformation {
                        creation_time: times.creation_time,
                        last_access_time: times.last_access_time,
                        last_write_time: times.last_write_time,
                        change_time: times.change_time,
                        allocation_size: 0,
                        end_of_file: 0,
                        file_attributes: file_attributes::FILE_ATTRIBUTE_NORMAL,
                        _pad: 0,
                    };
                    crate::try_write_guest_value_unaligned(info_ptr, info);
                }
                #[cfg(any(debug_assertions, feature = "trace_debug"))]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtQueryFullAttributesFile phantom exe OK path={nt_path_for_log:?}\n",
                    ));
                }
                return NtStatus::STATUS_SUCCESS;
            }
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtQueryFullAttributesFile FAIL path={nt_path_for_log:?} status=0x{:08X}\n",
                    status.0,
                ));
            }
            status
        }
    }
}

/// Helper: write an IO_STATUS_BLOCK to guest memory.
fn write_iosb(io_status_ptr: usize, status: NtStatus, info: usize) {
    if io_status_ptr != 0 {
        let iosb = IoStatusBlock {
            status: status.0,
            _pad: 0,
            information: info as u64,
        };
        crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
    }
}

/// NtQueryInformationByName — query file metadata by path without opening.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryInformationByName(
///     POBJECT_ATTRIBUTES ObjectAttributes,   // r10
///     PIO_STATUS_BLOCK IoStatusBlock,        // rdx
///     PVOID FileInformation,                 // r8
///     ULONG Length,                          // r9
///     FILE_INFORMATION_CLASS FileInfoClass   // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_query_information_by_name<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let obj_attr_ptr = args.arg0;
    let io_status_ptr = args.arg1;
    let info_ptr = args.arg2;
    let info_length = args.arg3 as u32;
    let info_class = NtSyscallArgs::arg4(ctx) as u32;

    let info_size = match info_class {
        FILE_STAT_INFORMATION_CLASS => core::mem::size_of::<FileStatInformation>(),
        FILE_STAT_BASIC_INFORMATION_CLASS => core::mem::size_of::<FileStatBasicInformation>(),
        _ => {
            write_iosb(io_status_ptr, NtStatus::STATUS_INVALID_INFO_CLASS, 0);
            return NtStatus::STATUS_INVALID_INFO_CLASS;
        }
    };

    if info_ptr == 0 || (info_length as usize) < info_size {
        write_iosb(io_status_ptr, NtStatus::STATUS_INFO_LENGTH_MISMATCH, 0);
        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
    }

    let nt_path = match resolve_object_attributes_path(obj_attr_ptr, Some(handles)) {
        Ok(path) => path,
        Err(status) => {
            write_iosb(io_status_ptr, status, 0);
            return status;
        }
    };
    let status = match query_nt_path_file_status(&nt_path, shared) {
        Ok(status) => {
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtQueryInformationByName OK path={nt_path:?} file_type={:?} class={info_class}\n",
                    status.file_type,
                ));
            }
            status
        }
        Err(err_status) => {
            // If this is a phantom executable, return synthetic metadata
            // so CreateProcessW's NtQueryInformationByName succeeds.
            if is_phantom_executable_path(&nt_path) {
                #[cfg(any(debug_assertions, feature = "trace_debug"))]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtQueryInformationByName phantom exe OK path={nt_path:?}\n",
                    ));
                }
                let times = synthetic_file_times();
                let phantom_file_id = 0xFFFF_FFFE_u64;
                let common_file_id = phantom_file_id as i64;
                match info_class {
                    FILE_STAT_INFORMATION_CLASS => {
                        let info = FileStatInformation {
                            file_id: common_file_id,
                            creation_time: times.creation_time,
                            last_access_time: times.last_access_time,
                            last_write_time: times.last_write_time,
                            change_time: times.change_time,
                            allocation_size: 65536,
                            end_of_file: 65536,
                            file_attributes: file_attributes::FILE_ATTRIBUTE_NORMAL,
                            reparse_tag: 0,
                            number_of_links: 1,
                            effective_access: file_access::FILE_GENERIC_READ | file_access::FILE_EXECUTE,
                        };
                        crate::try_write_guest_value_unaligned(info_ptr, info);
                    }
                    FILE_STAT_BASIC_INFORMATION_CLASS => {
                        let info = FileStatBasicInformation {
                            file_id: common_file_id,
                            creation_time: times.creation_time,
                            last_access_time: times.last_access_time,
                            last_write_time: times.last_write_time,
                            change_time: times.change_time,
                            allocation_size: 65536,
                            end_of_file: 65536,
                            file_attributes: file_attributes::FILE_ATTRIBUTE_NORMAL,
                            reparse_tag: 0,
                            number_of_links: 1,
                            device_type: FILE_DEVICE_DISK,
                            device_characteristics: FILE_DEVICE_IS_MOUNTED,
                            reserved: 0,
                            volume_serial_number: SYNTHETIC_VOLUME_SERIAL_NUMBER,
                            file_id128: FileId128 { identifier: [0xFE; 16] },
                        };
                        crate::try_write_guest_value_unaligned(info_ptr, info);
                    }
                    _ => unreachable!(),
                }
                write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, info_size);
                return NtStatus::STATUS_SUCCESS;
            }
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtQueryInformationByName FAIL path={nt_path:?} status=0x{:08X}\n",
                    err_status.0,
                ));
            }
            write_iosb(io_status_ptr, err_status, 0);
            return err_status;
        }
    };
    let times = query_host_file_times(&nt_path);

    let file_id = synthetic_file_id(&status);
    let common_file_id = i64::from_le_bytes(file_id.to_le_bytes());
    let allocation_size = allocation_size_from_status(&status);
    let end_of_file = file_size_from_status(&status);
    let file_attributes = file_attributes_from_status(&status);

    match info_class {
        FILE_STAT_INFORMATION_CLASS => {
            let info = FileStatInformation {
                file_id: common_file_id,
                creation_time: times.creation_time,
                last_access_time: times.last_access_time,
                last_write_time: times.last_write_time,
                change_time: times.change_time,
                allocation_size,
                end_of_file,
                file_attributes,
                reparse_tag: 0,
                number_of_links: 1,
                effective_access: file_access::FILE_GENERIC_READ | file_access::FILE_EXECUTE,
            };
            crate::try_write_guest_value_unaligned(info_ptr, info);
        }
        FILE_STAT_BASIC_INFORMATION_CLASS => {
            let info = FileStatBasicInformation {
                file_id: common_file_id,
                creation_time: times.creation_time,
                last_access_time: times.last_access_time,
                last_write_time: times.last_write_time,
                change_time: times.change_time,
                allocation_size,
                end_of_file,
                file_attributes,
                reparse_tag: 0,
                number_of_links: 1,
                device_type: FILE_DEVICE_DISK,
                device_characteristics: FILE_DEVICE_IS_MOUNTED,
                reserved: 0,
                volume_serial_number: SYNTHETIC_VOLUME_SERIAL_NUMBER,
                file_id128: synthetic_file_id128(&status, file_id),
            };
            crate::try_write_guest_value_unaligned(info_ptr, info);
        }
        _ => unreachable!(),
    }

    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, info_size);
    NtStatus::STATUS_SUCCESS
}

/// Map a Win32 error code to an NTSTATUS value.
fn map_win32_error_to_ntstatus(win_err: u32) -> NtStatus {
    match win_err {
        2 => NtStatus::STATUS_OBJECT_NAME_NOT_FOUND, // ERROR_FILE_NOT_FOUND
        3 => NtStatus::STATUS_OBJECT_PATH_NOT_FOUND, // ERROR_PATH_NOT_FOUND
        5 => NtStatus::STATUS_ACCESS_DENIED,         // ERROR_ACCESS_DENIED
        32 => NtStatus::STATUS_SHARING_VIOLATION,    // ERROR_SHARING_VIOLATION
        80 => NtStatus::STATUS_OBJECT_NAME_COLLISION, // ERROR_FILE_EXISTS
        183 => NtStatus::STATUS_OBJECT_NAME_COLLISION, // ERROR_ALREADY_EXISTS
        _ => NtStatus::STATUS_UNSUCCESSFUL,
    }
}

// ========================================================================
// NtQueryVolumeInformationFile
// ========================================================================

/// NtQueryVolumeInformationFile — return basic volume metadata.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryVolumeInformationFile(
///     HANDLE FileHandle,                        // r10
///     PIO_STATUS_BLOCK IoStatusBlock,           // rdx
///     PVOID FsInformation,                      // r8
///     ULONG Length,                             // r9
///     FS_INFORMATION_CLASS FsInformationClass   // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_query_volume_information_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
) -> NtStatus {
    let args = super::NtSyscallArgs::from_ctx(ctx);
    let file_handle = args.arg0 as u32;
    let io_status_ptr = args.arg1;
    let info_ptr = args.arg2;
    let info_length = args.arg3 as u32;

    let info_class = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x28).unwrap_or(0);

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtQueryVolumeInformationFile handle=0x{file_handle:X} class={info_class} len={info_length}\n"
        ));
    }

    // Determine the device type based on the handle's object type.
    let is_console = handles.with(file_handle, |entry| matches!(
        &entry.object,
        NtObject::ConsoleOutput { .. } | NtObject::ConsoleInput
    )).unwrap_or(false);

    match info_class {
        // FileFsVolumeInformation (1) — volume label and serial number.
        1 => {
            // Minimum header is 18 bytes (without label).
            if info_length < 18 || info_ptr == 0 {
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            // VolumeCreationTime (i64)
            crate::try_write_guest_value_unaligned(info_ptr, 0i64);
            // VolumeSerialNumber (u32)
            crate::try_write_guest_value_unaligned(info_ptr + 8, 0x1234_5678u32);
            // VolumeLabelLength (u32) — 0 means empty label
            crate::try_write_guest_value_unaligned(info_ptr + 12, 0u32);
            // SupportsObjects (u8) + padding
            crate::try_write_guest_value_unaligned(info_ptr + 16, 0u8);
            crate::try_write_guest_value_unaligned(info_ptr + 17, 0u8);
            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 18);
            NtStatus::STATUS_SUCCESS
        }
        // FileFsDeviceInformation (4) — device type and characteristics.
        4 => {
            // FILE_FS_DEVICE_INFORMATION is 8 bytes: DeviceType(u32) + Characteristics(u32)
            if info_length < 8 || info_ptr == 0 {
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            if is_console {
                // FILE_DEVICE_CONSOLE = 0x50 — report console handles as console
                // character devices so that GetFileType() returns FILE_TYPE_CHAR
                // and _isatty(1) returns true → CRT uses line buffering.
                // Following the Linux model: always report as character device,
                // intercept terminal ioctls.
                crate::try_write_guest_value_unaligned(info_ptr, 0x50u32);
            } else {
                // FILE_DEVICE_DISK = 7
                crate::try_write_guest_value_unaligned(info_ptr, 7u32);
            }
            // No special characteristics
            crate::try_write_guest_value_unaligned(info_ptr + 4, 0u32);
            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 8);
            NtStatus::STATUS_SUCCESS
        }
        // FileFsSizeInformation (3) — total/available units.
        3 => {
            if is_console {
                // Console handles don't have volume size info.
                return NtStatus::STATUS_INVALID_INFO_CLASS;
            }
            // FILE_FS_SIZE_INFORMATION: 24 bytes
            if info_length < 24 || info_ptr == 0 {
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            // TotalAllocationUnits: large number
            crate::try_write_guest_value_unaligned(info_ptr, 0x1_0000_0000i64);
            // AvailableAllocationUnits
            crate::try_write_guest_value_unaligned(info_ptr + 8, 0x8000_0000i64);
            // SectorsPerAllocationUnit
            crate::try_write_guest_value_unaligned(info_ptr + 16, 8u32);
            // BytesPerSector
            crate::try_write_guest_value_unaligned(info_ptr + 20, 512u32);
            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 24);
            NtStatus::STATUS_SUCCESS
        }
        // FileFsAttributeInformation (5) — file system attributes and name.
        5 => {
            // FILE_FS_ATTRIBUTE_INFORMATION:
            //   ULONG FileSystemAttributes;   // 4 bytes
            //   LONG MaximumComponentNameLength; // 4 bytes
            //   ULONG FileSystemNameLength;    // 4 bytes
            //   WCHAR FileSystemName[];        // variable
            // We report "NTFS" — 4 chars = 8 bytes, total = 12 + 8 = 20 bytes.
            let fs_name: &[u16] = &[b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16];
            let name_bytes = (fs_name.len() * 2) as u32; // 8
            let total_size = 12 + name_bytes as usize;    // 20
            if (info_length as usize) < total_size || info_ptr == 0 {
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            // FileSystemAttributes: FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
            //   FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS | FILE_SUPPORTS_REPARSE_POINTS
            crate::try_write_guest_value_unaligned(info_ptr, 0x000F_00FFu32);
            // MaximumComponentNameLength
            crate::try_write_guest_value_unaligned(info_ptr + 4, 255u32);
            // FileSystemNameLength
            crate::try_write_guest_value_unaligned(info_ptr + 8, name_bytes);
            // FileSystemName — write UTF-16LE "NTFS"
            for (i, &ch) in fs_name.iter().enumerate() {
                crate::try_write_guest_value_unaligned(info_ptr + 12 + i * 2, ch);
            }
            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, total_size);
            NtStatus::STATUS_SUCCESS
        }
        _ => NtStatus::STATUS_INVALID_INFO_CLASS,
    }
}
// ========================================================================

/// NtQueryDirectoryFile — enumerate directory entries.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryDirectoryFile(
///     HANDLE FileHandle,                 // r10
///     HANDLE Event,                      // rdx
///     PIO_APC_ROUTINE ApcRoutine,        // r8
///     PVOID ApcContext,                   // r9
///     PIO_STATUS_BLOCK IoStatusBlock,     // [rsp+0x28]
///     PVOID FileInformation,             // [rsp+0x30]
///     ULONG Length,                      // [rsp+0x38]
///     FILE_INFORMATION_CLASS InfoClass,   // [rsp+0x40]
///     BOOLEAN ReturnSingleEntry,         // [rsp+0x48]
///     PUNICODE_STRING FileName,          // [rsp+0x50]
///     BOOLEAN RestartScan                // [rsp+0x58]
/// );
/// ```
///
/// Supports FileDirectoryInformation (1), FileBothDirectoryInformation (3),
/// and FileIdBothDirectoryInformation (37).
/// Tracks enumeration state per directory handle for forward progress.
pub(crate) fn nt_query_directory_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = super::NtSyscallArgs::from_ctx(ctx);
    let file_handle = args.arg0 as u32;

    let io_status_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let info_ptr = crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let info_length =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);
    let info_class = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x40).unwrap_or(0);
    let return_single =
        crate::try_read_guest_value_unaligned::<u8>(ctx.regs.rsp + 0x48).unwrap_or(0) != 0;
    let filename_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x50).unwrap_or(0);
    let restart_scan =
        crate::try_read_guest_value_unaligned::<u8>(ctx.regs.rsp + 0x58).unwrap_or(0) != 0;

    if info_ptr == 0 || info_length < 72 {
        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
    }

    if info_class != 1 && info_class != 3 && info_class != 37 {
        write_iosb(io_status_ptr, NtStatus::STATUS_INVALID_INFO_CLASS, 0);
        return NtStatus::STATUS_INVALID_INFO_CLASS;
    }

    nt_query_directory_file_inner(
        file_handle,
        io_status_ptr,
        info_ptr,
        info_length,
        info_class,
        return_single,
        filename_ptr,
        restart_scan,
        ctx,
        handles,
        shared,
    )
}

/// Shared inner implementation for both NtQueryDirectoryFile and
/// NtQueryDirectoryFileEx. All parameters have already been extracted
/// and validated by the caller.
fn nt_query_directory_file_inner<FS: crate::NtShimFS>(
    file_handle: u32,
    io_status_ptr: usize,
    info_ptr: usize,
    info_length: u32,
    info_class: u32,
    return_single: bool,
    filename_ptr: usize,
    restart_scan: bool,
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    use crate::handle_table::DirEnumEntry;

    // Phase 1: Check if it's a Directory handle and determine if we need to
    // (re)populate entries. Extract the path for VFS lookups.
    // This uses a read-only closure to avoid holding the Descriptors write lock.
    let dir_info = handles.with(file_handle, |entry| {
        if let NtObject::Directory {
            path,
            enum_entries,
            ..
        } = &entry.object
        {
            Some((path.clone(), restart_scan || enum_entries.is_empty()))
        } else {
            None
        }
    }).flatten();

    let Some((path, needs_populate)) = dir_info else {
        write_iosb(io_status_ptr, NtStatus::STATUS_INVALID_HANDLE, 0);
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    // Phase 2: If entries need populating, do VFS operations OUTSIDE the
    // descriptor lock to avoid deadlocking on descriptor_table_mut().
    let new_entries: Option<Result<alloc::vec::Vec<DirEnumEntry>, NtStatus>> = if needs_populate {
        // Determine if this is a VFS-translatable path AND VFS is available.
        let is_vfs_path = shared.fs.get().is_some()
            && (matches!(
                drive_path_to_vfs(&path),
                Some(TranslatedPath::Vfs(_) | TranslatedPath::Device(_))
            ) || matches!(
                translate_nt_path(&path),
                Some(TranslatedPath::Vfs(_) | TranslatedPath::Device(_))
            ));

        let vfs_result: Option<Result<alloc::vec::Vec<DirEnumEntry>, NtStatus>> =
            (|| -> Option<Result<alloc::vec::Vec<DirEnumEntry>, NtStatus>> {
                let vfs_path = match drive_path_to_vfs(&path) {
                    Some(TranslatedPath::Vfs(p)) => p,
                    _ => match translate_nt_path(&path) {
                        Some(TranslatedPath::Vfs(p)) => p,
                        _ => return None,
                    },
                };
                let fs = shared.fs.get()?;
                let dir_fd = match fs.open(
                    &*vfs_path,
                    litebox::fs::OFlags::DIRECTORY | litebox::fs::OFlags::RDONLY,
                    litebox::fs::Mode::empty(),
                ) {
                    Ok(fd) => fd,
                    Err(ref e) => return Some(Err(map_open_error_to_ntstatus(e))),
                };
                let entries = match fs.read_dir(&dir_fd) {
                    Ok(e) => {
                        let _ = fs.close(&dir_fd);
                        e
                    }
                    Err(ref e) => {
                        let _ = fs.close(&dir_fd);
                        return Some(Err(map_readdir_error_to_ntstatus(e)));
                    }
                };
                Some(Ok(entries
                    .into_iter()
                    .map(|e| {
                        let is_dir = e.file_type == litebox::fs::FileType::Directory;
                        let file_size = if is_dir {
                            0
                        } else {
                            let full = alloc::format!("{}/{}", vfs_path, e.name);
                            fs.file_status(&*full).map(|s| s.size as i64).unwrap_or(0)
                        };
                        let attrs = if is_dir {
                            0x10 // FILE_ATTRIBUTE_DIRECTORY
                        } else {
                            0x80 // FILE_ATTRIBUTE_NORMAL
                        };
                        DirEnumEntry {
                            name: e.name,
                            attributes: attrs,
                            file_size,
                            creation_time: 0,
                            last_access_time: 0,
                            last_write_time: 0,
                        }
                    })
                    .collect()))
            })();

        match vfs_result {
            Some(Ok(entries)) => {
                // Apply filename filter if provided.
                let filter = if filename_ptr != 0 {
                    read_unicode_string_from_guest(filename_ptr)
                } else {
                    None
                };
                let filtered: alloc::vec::Vec<DirEnumEntry> = if let Some(ref pattern) = filter {
                    let pat_lower = pattern.to_ascii_lowercase();
                    entries
                        .into_iter()
                        .filter(|e| nt_wildcard_match(&e.name.to_ascii_lowercase(), &pat_lower))
                        .collect()
                } else {
                    entries
                };
                Some(Ok(filtered))
            }
            Some(Err(status)) => {
                // Real VFS error — return immediately.
                write_iosb(io_status_ptr, status, 0);
                return status;
            }
            None if is_vfs_path => {
                // VFS-translatable but no fs available — empty result.
                Some(Ok(alloc::vec::Vec::new()))
            }
            None => {
                // Path not VFS-translatable — no host fallback.
                write_iosb(io_status_ptr, NtStatus::STATUS_OBJECT_PATH_NOT_FOUND, 0);
                return NtStatus::STATUS_OBJECT_PATH_NOT_FOUND;
            }
        }
    } else {
        None // entries already populated, no VFS work needed
    };

    // Phase 3: Write entries back and pack the output buffer inside with_mut().
    // VFS operations are done, so only the per-entry RwLock is held.
    if let Some(status) = handles.with_mut(file_handle, |entry| {
        let NtObject::Directory {
            enum_entries,
            enum_index,
            ..
        } = &mut entry.object
        else {
            write_iosb(io_status_ptr, NtStatus::STATUS_INVALID_HANDLE, 0);
            return NtStatus::STATUS_INVALID_HANDLE;
        };

        // Store new entries if we populated them.
        if let Some(Ok(entries)) = new_entries {
            *enum_entries = entries;
            *enum_index = 0;
        }

        // Check if enumeration is exhausted.
        if *enum_index >= enum_entries.len() {
            write_iosb(io_status_ptr, NtStatus::STATUS_NO_MORE_FILES, 0);
            return NtStatus::STATUS_NO_MORE_FILES;
        }

        // Pack entries into the output buffer.
        // Info class layout:
        //   1 = FileDirectoryInformation — 64-byte header + FileName
        //   3 = FileBothDirectoryInformation — 94-byte header + FileName
        //   37 = FileIdBothDirectoryInformation — 104-byte header + FileName
        let (is_both, has_file_id) = match info_class {
            3 => (true, false),
            37 => (true, true),
            1 => (false, false),
            _ => unreachable!(), // rejected by early check above
        };
        let header_size: usize = if has_file_id {
            104 // FileBothDir(94) + padding(2) + FileId(8)
        } else if is_both {
            94
        } else {
            64
        };

        let buf_base = info_ptr;
        let buf_end = info_ptr + info_length as usize;
        let mut offset: usize = 0;
        let mut prev_entry_offset: usize = 0;
        let mut count = 0;

        while *enum_index < enum_entries.len() {
            let entry = &enum_entries[*enum_index];
            let name_u16: alloc::vec::Vec<u16> = entry.name.encode_utf16().collect();
            let name_bytes = name_u16.len() * 2;
            let entry_size = (header_size + name_bytes + 7) & !7;

            if buf_base + offset + entry_size > buf_end {
                break;
            }

            let entry_ptr = buf_base + offset;
            // Safety: we verified the buffer is large enough.
            unsafe {
                core::ptr::write_bytes(entry_ptr as *mut u8, 0, entry_size);

                core::ptr::write((entry_ptr + 8) as *mut i64, entry.creation_time);
                core::ptr::write((entry_ptr + 16) as *mut i64, entry.last_access_time);
                core::ptr::write((entry_ptr + 24) as *mut i64, entry.last_write_time);
                core::ptr::write((entry_ptr + 32) as *mut i64, entry.last_write_time);
                core::ptr::write((entry_ptr + 40) as *mut i64, entry.file_size);
                let alloc_size = (entry.file_size + 4095) & !4095;
                core::ptr::write((entry_ptr + 48) as *mut i64, alloc_size);
                core::ptr::write((entry_ptr + 56) as *mut u32, entry.attributes);
                core::ptr::write((entry_ptr + 60) as *mut u32, name_bytes as u32);

                if has_file_id {
                    // FileIdBothDirectoryInformation: FileName at offset 104.
                    // FileId (i64) at offset 96 — generate a unique synthetic ID
                    // by hashing the filename (FNV-1a).
                    let file_id = {
                        let mut h: u64 = 0xcbf29ce484222325;
                        for w in &name_u16 {
                            let bytes: [u8; 2] = w.to_le_bytes();
                            for &b in &bytes {
                                h ^= b as u64;
                                h = h.wrapping_mul(0x100000001b3);
                            }
                        }
                        h as i64
                    };
                    core::ptr::write((entry_ptr + 96) as *mut i64, file_id);
                    core::ptr::copy_nonoverlapping(
                        name_u16.as_ptr() as *const u8,
                        (entry_ptr + 104) as *mut u8,
                        name_bytes,
                    );
                } else if is_both {
                    // FileBothDirectoryInformation: FileName at offset 94.
                    core::ptr::copy_nonoverlapping(
                        name_u16.as_ptr() as *const u8,
                        (entry_ptr + 94) as *mut u8,
                        name_bytes,
                    );
                } else {
                    // FileDirectoryInformation: FileName at offset 64.
                    core::ptr::copy_nonoverlapping(
                        name_u16.as_ptr() as *const u8,
                        (entry_ptr + 64) as *mut u8,
                        name_bytes,
                    );
                }

                if count > 0 {
                    core::ptr::write(
                        (buf_base + prev_entry_offset) as *mut u32,
                        (offset - prev_entry_offset) as u32,
                    );
                }
            }

            prev_entry_offset = offset;
            offset += entry_size;
            count += 1;
            *enum_index += 1;

            if return_single {
                break;
            }
        }

        if count == 0 {
            // No entries fit in the buffer. If the enumeration isn't exhausted,
            // this means the buffer is too small — not that the directory is empty.
            if *enum_index < enum_entries.len() {
                write_iosb(io_status_ptr, NtStatus::STATUS_BUFFER_OVERFLOW, 0);
                return NtStatus::STATUS_BUFFER_OVERFLOW;
            }
            write_iosb(io_status_ptr, NtStatus::STATUS_NO_MORE_FILES, 0);
            return NtStatus::STATUS_NO_MORE_FILES;
        }

        write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, offset);
        NtStatus::STATUS_SUCCESS
    }) {
        status
    } else {
        write_iosb(io_status_ptr, NtStatus::STATUS_INVALID_HANDLE, 0);
        NtStatus::STATUS_INVALID_HANDLE
    }
}

// ========================================================================
// NtQueryDirectoryFileEx
// ========================================================================

/// NtQueryDirectoryFileEx — extended directory enumeration (Windows 10+).
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryDirectoryFileEx(
///     HANDLE FileHandle,                 // r10
///     HANDLE Event,                      // rdx
///     PIO_APC_ROUTINE ApcRoutine,        // r8
///     PVOID ApcContext,                   // r9
///     PIO_STATUS_BLOCK IoStatusBlock,     // [rsp+0x28]
///     PVOID FileInformation,             // [rsp+0x30]
///     ULONG Length,                      // [rsp+0x38]
///     FILE_INFORMATION_CLASS InfoClass,   // [rsp+0x40]
///     ULONG QueryFlags,                  // [rsp+0x48]
///     PUNICODE_STRING FileName           // [rsp+0x50]
/// );
/// ```
///
/// QueryFlags bits:
///   0x01 = SL_RESTART_SCAN
///   0x02 = SL_RETURN_SINGLE_ENTRY
///   0x10 = SL_INDEX_SPECIFIED
///
/// Translates to the NtQueryDirectoryFile calling convention and delegates.
pub(crate) fn nt_query_directory_file_ex<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = super::NtSyscallArgs::from_ctx(ctx);
    let file_handle = args.arg0 as u32;

    let io_status_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let info_ptr = crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let info_length =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);
    let info_class = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x40).unwrap_or(0);
    let query_flags =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x48).unwrap_or(0);
    let filename_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x50).unwrap_or(0);

    // Translate QueryFlags to the NtQueryDirectoryFile semantics
    let restart_scan = (query_flags & 0x01) != 0;   // SL_RESTART_SCAN
    let return_single = (query_flags & 0x02) != 0;   // SL_RETURN_SINGLE_ENTRY

    if info_ptr == 0 || info_length < 72 {
        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
    }

    // Only support FileDirectoryInformation(1), FileBothDirectoryInformation(3),
    // and FileIdBothDirectoryInformation(37).
    if info_class != 1 && info_class != 3 && info_class != 37 {
        write_iosb(io_status_ptr, NtStatus::STATUS_INVALID_INFO_CLASS, 0);
        return NtStatus::STATUS_INVALID_INFO_CLASS;
    }

    // Delegate to the core directory enumeration logic (shared with NtQueryDirectoryFile).
    nt_query_directory_file_inner(
        file_handle,
        io_status_ptr,
        info_ptr,
        info_length,
        info_class,
        return_single,
        filename_ptr,
        restart_scan,
        ctx,
        handles,
        shared,
    )
}

// ========================================================================
// NtOpenFile
// ========================================================================

/// NtOpenFile — open an existing file.
///
/// NT signature:
/// ```text
/// NTSTATUS NtOpenFile(
///     PHANDLE FileHandle,                 // r10 (out)
///     ACCESS_MASK DesiredAccess,           // rdx
///     POBJECT_ATTRIBUTES ObjectAttributes, // r8
///     PIO_STATUS_BLOCK IoStatusBlock,      // r9
///     ULONG ShareAccess,                  // [rsp+0x28]
///     ULONG OpenOptions                   // [rsp+0x30]
/// );
/// ```
///
/// During ntdll-driven initialization, ntdll's loader calls NtOpenFile to
/// open DLL files. We first check the tar archive (dll_tar_files) and
/// return a `MemoryFile` handle if found; otherwise fall back to the host.
pub(crate) fn nt_open_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_ptr = args.arg0;
    let desired_access = args.arg1 as u32;
    let obj_attr_ptr = args.arg2;
    let io_status_ptr = args.arg3;

    // Stack arguments.
    let _share_access =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let open_options =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x30).unwrap_or(0);

    if handle_out_ptr == 0 || obj_attr_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Read OBJECT_ATTRIBUTES from guest memory.
    let Some(obj_attr) = crate::try_read_guest_value_unaligned::<ObjectAttributes>(obj_attr_ptr)
    else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };

    // Read the path from UNICODE_STRING.
    let Some(nt_path) = read_unicode_string_from_guest(obj_attr.object_name as usize) else {
        return NtStatus::STATUS_OBJECT_NAME_INVALID;
    };

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!("NT shim: NtOpenFile path={nt_path:?} access=0x{desired_access:X} open_options=0x{open_options:X}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    if let Some(status) = try_open_special_device(&nt_path, handles, handle_out_ptr, io_status_ptr)
    {
        return status;
    }

    // ── Pipe client open via server handle as RootDirectory ─────────
    // CreatePipe step 3: NtOpenFile with ObjectAttributes where
    // RootDirectory = server pipe handle, ObjectName = "" (empty).
    // This opens the client (write) end of the same pipe.
    if obj_attr.root_directory != 0 && nt_path.is_empty() {
        let root_h = obj_attr.root_directory as u32;
        let pipe_buf = handles.with(root_h, |entry| match &entry.object {
            NtObject::Pipe { buffer, .. } => Some(Arc::clone(buffer)),
            _ => None,
        }).flatten();
        if let Some(client_buf) = pipe_buf {
            client_buf.increment(false); // bump client reference count
            let handle = handles.insert(NtObject::Pipe {
                buffer: client_buf,
                is_server: false,
                io_completion: None,
            });
            crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: 1, // FILE_OPENED
                };
                crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
            }
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtOpenFile pipe client open via server RootDir handle=0x{handle:X}\n",
                ));
            }
            return NtStatus::STATUS_SUCCESS;
        }
    }

    // ── VFS path ─────────────────────────────────────────────────────
    let translated = translate_nt_path(&nt_path);
    if let Some(ref translated) = translated {
        let vfs_path = match translated {
            TranslatedPath::Vfs(p) => Some(p.as_str()),
            TranslatedPath::Device(p) => Some(p.as_str()),
            TranslatedPath::Registry(_) | TranslatedPath::Pipe(_) => None,
        };
        if let (Some(path), Some(fs)) = (vfs_path, shared.fs.get()) {
            let is_directory = open_options & file_options::FILE_DIRECTORY_FILE != 0;

            if is_directory {
                // NtOpenFile is always "open existing" — validate the directory.
                // VFS-translatable paths must not escape to host.
                let is_vfs_dir = fs
                    .file_status(path)
                    .is_ok_and(|s| s.file_type == litebox::fs::FileType::Directory);
                if is_vfs_dir {
                    return insert_directory_handle(
                        handles,
                        &nt_path,
                        handle_out_ptr,
                        io_status_ptr,
                        1, // FILE_OPENED
                    );
                }
                // Directory not found in VFS — authoritative failure.
                return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
            }

            // NtOpenFile is always "open existing" — determine read/write
            // from DesiredAccess using the same masks as NtCreateFile.
            let want_read = desired_access & 0x8000_0001 != 0; // GENERIC_READ | FILE_READ_DATA
            let want_write = desired_access & 0x4000_0006 != 0; // GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA
            let oflags = if want_write {
                if want_read {
                    litebox::fs::OFlags::RDWR
                } else {
                    litebox::fs::OFlags::WRONLY
                }
            } else {
                litebox::fs::OFlags::RDONLY
            };
            match fs.open(
                path,
                oflags,
                litebox::fs::Mode::RUSR | litebox::fs::Mode::WUSR,
            ) {
                Ok(typed_fd) => {
                    // Check if opened path is actually a directory — if so,
                    // create a Directory handle (same logic as NtCreateFile).
                    let is_dir = fs
                        .fd_file_status(&typed_fd)
                        .map(|st| st.file_type == litebox::fs::FileType::Directory)
                        .unwrap_or(false);

                    if is_dir {
                        #[cfg(any(debug_assertions, feature = "trace_debug"))]
                        {
                            use litebox::platform::DebugLogProvider as _;
                            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                                "NT shim: NtOpenFile detected DIR (fd_file_status) path={path:?} nt_path={nt_path:?}\n"
                            ));
                        }
                        let _ = fs.close(&typed_fd);
                        return insert_directory_handle(
                            handles,
                            &nt_path,
                            handle_out_ptr,
                            io_status_ptr,
                            1, // FILE_OPENED
                        );
                    }

                    let vfs_fd = alloc::sync::Arc::new(typed_fd);
                    let delete_flag = open_options & file_options::FILE_DELETE_ON_CLOSE != 0;
                    let handle = handles.insert(NtObject::File {
                        path: nt_path,
                        vfs_path: Some(alloc::string::String::from(path)),
                        position: Arc::new(AtomicU64::new(0)),
                        vfs_fd: alloc::sync::Arc::clone(&vfs_fd),
                        delete_on_close: Arc::new(core::sync::atomic::AtomicBool::new(delete_flag)),
                        fs: alloc::sync::Arc::clone(fs),
                    });
                    crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
                    if io_status_ptr != 0 {
                        let iosb = IoStatusBlock {
                            status: NtStatus::STATUS_SUCCESS.0,
                            _pad: 0,
                            information: 1,
                        };
                        crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
                    }
                    #[cfg(any(debug_assertions, feature = "trace_debug"))]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtOpenFile VFS OK path={path:?} delete_on_close={delete_flag}\n",
                        ));
                    }
                    return NtStatus::STATUS_SUCCESS;
                }
                Err(e) => {
                    // VFS open failed — check if this is a phantom executable.
                    if is_phantom_executable_path(&nt_path) {
                        let handle = handles.insert(NtObject::PhantomExe {
                            path: nt_path,
                        });
                        crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
                        if io_status_ptr != 0 {
                            let iosb = IoStatusBlock {
                                status: NtStatus::STATUS_SUCCESS.0,
                                _pad: 0,
                                information: 1, // FILE_OPENED
                            };
                            crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
                        }
                        #[cfg(any(debug_assertions, feature = "trace_debug"))]
                        {
                            use litebox::platform::DebugLogProvider as _;
                            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                                "NT shim: NtOpenFile phantom exe handle=0x{handle:X} path={path:?}\n",
                            ));
                        }
                        return NtStatus::STATUS_SUCCESS;
                    }
                    // Not a phantom exe — authoritative error, no host fallback.
                    #[cfg(any(debug_assertions, feature = "trace_debug"))]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtOpenFile VFS error path={path:?} err={e:?}\n",
                        ));
                    }
                    return map_open_error_to_ntstatus(&e);
                }
            }
        }
    }

    // Named pipe client open: NtOpenFile on a pipe path connects
    // to an existing pipe created by NtCreateNamedPipeFile.
    if let Some(TranslatedPath::Pipe(ref pipe_name)) = translated {
        // Empty pipe name = the root device "\Device\NamedPipe\".
        // Return a PipeRootDevice handle used as RootDirectory for
        // subsequent NtCreateNamedPipeFile / NtOpenFile calls.
        if pipe_name.is_empty() {
            let handle = handles.insert(NtObject::PipeRootDevice);
            crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: 1, // FILE_OPENED
                };
                crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
            }
            return NtStatus::STATUS_SUCCESS;
        }
        let pipe_buf = {
            let lower_name = pipe_name.to_ascii_lowercase();
            let registry = shared.pipe_registry.lock();
            registry.get(&lower_name).cloned()
        };
        if let Some(buf) = pipe_buf {
            buf.increment(false); // bump client reference count
            let handle = handles.insert(NtObject::Pipe {
                buffer: buf,
                is_server: false, // client (write) end
                io_completion: None,
            });
            crate::try_write_guest_value_unaligned(handle_out_ptr, handle as usize);
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: 1, // FILE_OPENED
                };
                crate::try_write_guest_value_unaligned(io_status_ptr, iosb);
            }
            return NtStatus::STATUS_SUCCESS;
        }
        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Path not translatable to VFS — no host fallback.
    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!("NT shim: NtOpenFile path not translatable: {nt_path:?}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }
    NtStatus::STATUS_OBJECT_NAME_NOT_FOUND
}

// ========================================================================
// NtDeleteFile
// ========================================================================

/// NtDeleteFile — delete a file by path without opening a handle.
///
/// NT signature:
/// ```text
/// NTSTATUS NtDeleteFile(
///     POBJECT_ATTRIBUTES ObjectAttributes  // r10
/// );
/// ```
pub(crate) fn nt_delete_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let obj_attr_ptr = args.arg0;

    if obj_attr_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let Some(obj_attr) = crate::try_read_guest_value_unaligned::<ObjectAttributes>(obj_attr_ptr)
    else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };

    let Some(nt_path) = read_unicode_string_from_guest(obj_attr.object_name as usize) else {
        return NtStatus::STATUS_OBJECT_NAME_INVALID;
    };

    if let Some(translated) = translate_nt_path(&nt_path) {
        let vfs_path = match &translated {
            TranslatedPath::Vfs(p) => Some(p.as_str()),
            TranslatedPath::Device(p) => Some(p.as_str()),
            TranslatedPath::Registry(_) | TranslatedPath::Pipe(_) => None,
        };
        if let (Some(path), Some(fs)) = (vfs_path, shared.fs.get()) {
            return match fs.unlink(path) {
                Ok(()) => NtStatus::STATUS_SUCCESS,
                Err(litebox::fs::errors::UnlinkError::IsADirectory) => {
                    NtStatus::STATUS_FILE_IS_A_DIRECTORY
                }
                Err(litebox::fs::errors::UnlinkError::NoWritePerms) => {
                    NtStatus::STATUS_ACCESS_DENIED
                }
                Err(_) => NtStatus::STATUS_OBJECT_NAME_NOT_FOUND,
            };
        }
    }

    NtStatus::STATUS_OBJECT_NAME_NOT_FOUND
}

// ---------------------------------------------------------------------------
// Phase 3: Pipe Support + Process Spawning
// ---------------------------------------------------------------------------

/// NtCreateNamedPipeFile — creates the server (read) endpoint of a named pipe.
///
/// Called by `CreateNamedPipeA/W` (kernel32). The server end is the "read" end;
/// the client connects later via `NtCreateFile` / `NtOpenFile`.
///
/// Syscall signature (x64, args after first 4 on stack):
///   NtCreateNamedPipeFile(
///     OUT PHANDLE            FileHandle,           // rcx  (arg0)
///     IN  ACCESS_MASK        DesiredAccess,        // rdx  (arg1)
///     IN  POBJECT_ATTRIBUTES ObjectAttributes,     // r8   (arg2)
///     OUT PIO_STATUS_BLOCK   IoStatusBlock,        // r9   (arg3)
///     IN  ULONG              ShareAccess,          // [rsp+0x28] (arg4/stack0)
///     IN  ULONG              CreateDisposition,    // [rsp+0x30] (stack1)
///     IN  ULONG              CreateOptions,        // [rsp+0x38] (stack2)
///     IN  ULONG              NamedPipeType,        // [rsp+0x40] (stack3)
///     IN  ULONG              ReadMode,             // [rsp+0x48] (stack4)
///     IN  ULONG              CompletionMode,       // [rsp+0x50] (stack5)
///     IN  ULONG              MaximumInstances,     // [rsp+0x58] (stack6)
///     IN  ULONG              InboundQuota,         // [rsp+0x60] (stack7)
///     IN  ULONG              OutboundQuota,        // [rsp+0x68] (stack8)
///     IN  PLARGE_INTEGER     DefaultTimeout,       // [rsp+0x70] (stack9)
///   );
pub(crate) fn nt_create_named_pipe_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out = args.arg0;
    let obj_attr_ptr = args.arg2;
    let iosb_ptr = args.arg3;

    // Resolve the pipe path, handling RootDirectory (e.g. PipeRootDevice).
    let nt_path = match resolve_object_attributes_path(obj_attr_ptr, Some(handles)) {
        Ok(p) => p,
        Err(st) => return st,
    };

    // Read InboundQuota and OutboundQuota from the stack.
    let inbound_quota =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x60).unwrap_or(4096) as usize;
    let outbound_quota =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x68).unwrap_or(4096) as usize;
    let capacity = core::cmp::max(inbound_quota, outbound_quota).max(4096);

    // Normalize the pipe name for registry lookup.
    // Extract just the relative name (after the device prefix) and lowercase it
    // for case-insensitive matching.
    let pipe_name = {
        let lower = nt_path.to_ascii_lowercase();
        let name = if let Some(rest) = lower.strip_prefix("\\device\\namedpipe\\") {
            String::from(rest)
        } else if let Some(rest) = lower.strip_prefix("\\??\\pipe\\") {
            String::from(rest)
        } else {
            lower
        };
        // If the name is empty, auto-generate one (anonymous pipe via CreatePipe).
        if name.is_empty() {
            static ANON_PIPE_SEQ: core::sync::atomic::AtomicU32 =
                core::sync::atomic::AtomicU32::new(1);
            let id = ANON_PIPE_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            alloc::format!("__litebox_anon_pipe_{}", id)
        } else {
            name
        }
    };

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtCreateNamedPipeFile path=\"{}\" capacity={}\n",
            pipe_name, capacity,
        ));
    }

    // Create the pipe buffer and register it.
    let buffer = Arc::new(crate::handle_table::PipeBuffer::new(
        capacity,
        pipe_name.clone(),
    ));
    {
        let mut registry = shared.pipe_registry.lock();
        registry.insert(pipe_name, buffer.clone());
    }

    // Create the server (read) handle and bump the server reference count.
    buffer.increment(true);
    let handle = handles.insert(NtObject::Pipe {
        buffer,
        is_server: true,
        io_completion: None,
    });

    // Write the handle to the caller.
    if handle_out != 0 {
        crate::try_write_guest_value_unaligned(handle_out, handle);
    }
    // Write IoStatusBlock.
    if iosb_ptr != 0 {
        crate::try_write_guest_value_unaligned(iosb_ptr, 0i32); // Status = SUCCESS
        crate::try_write_guest_value_unaligned(iosb_ptr + 8, 0usize); // Information = 0
    }

    NtStatus::STATUS_SUCCESS
}

/// NtFsControlFile — handles pipe-related FSCTLs.
///
/// Syscall signature (x64):
///   NtFsControlFile(
///     IN  HANDLE           FileHandle,          // rcx  (arg0)
///     IN  HANDLE           Event,               // rdx  (arg1)
///     IN  PIO_APC_ROUTINE  ApcRoutine,          // r8   (arg2)
///     IN  PVOID            ApcContext,           // r9   (arg3)
///     OUT PIO_STATUS_BLOCK IoStatusBlock,        // [rsp+0x28] (arg4/stack0)
///     IN  ULONG            FsControlCode,        // [rsp+0x30] (stack1)
///     IN  PVOID            InputBuffer,           // [rsp+0x38] (stack2)
///     IN  ULONG            InputBufferLength,     // [rsp+0x40] (stack3)
///     OUT PVOID            OutputBuffer,          // [rsp+0x48] (stack4)
///     IN  ULONG            OutputBufferLength,    // [rsp+0x50] (stack5)
///   );
pub(crate) fn nt_fs_control_file<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable<FS>,
    shared: &super::super::NtSharedState<FS>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let file_handle = args.arg0 as u32;
    let iosb_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let fsctl_code =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x30).unwrap_or(0);

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtFsControlFile handle=0x{:X} fsctl=0x{:08X}\n",
            file_handle, fsctl_code,
        ));
    }

    const FSCTL_PIPE_LISTEN: u32 = 0x0011_0008;
    const FSCTL_PIPE_DISCONNECT: u32 = 0x0011_0004;
    const FSCTL_PIPE_WAIT: u32 = 0x0011_0018;

    match fsctl_code {
        FSCTL_PIPE_LISTEN => {
            // ConnectNamedPipe: the server end waits for a client to connect.
            // In our virtual pipe, the client end is created synchronously by
            // NtCreateFile/NtOpenFile, so we can return immediately.
            // Check that the handle is a pipe.
            let pipe_info = handles.with(file_handle, |entry| match &entry.object {
                NtObject::Pipe { buffer, is_server, .. } => Some((*is_server, buffer.client_count.load(core::sync::atomic::Ordering::Acquire))),
                _ => None,
            }).flatten();
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: FSCTL_PIPE_LISTEN handle=0x{:X} pipe_info={:?}\n",
                    file_handle, pipe_info,
                ));
            }
            match pipe_info {
                None => return NtStatus::STATUS_INVALID_HANDLE,
                Some((_is_server, _client_count)) => {
                    if iosb_ptr != 0 {
                        crate::try_write_guest_value_unaligned(iosb_ptr, 0i32);
                        crate::try_write_guest_value_unaligned(iosb_ptr + 8, 0usize);
                    }
                    NtStatus::STATUS_PIPE_CONNECTED
                }
            }
        }
        FSCTL_PIPE_DISCONNECT => {
            // Server disconnects; force client_count to 0 so reads see EOF.
            if let Some(buf) = handles.with(file_handle, |entry| match &entry.object {
                NtObject::Pipe { buffer, .. } => Some(Arc::clone(buffer)),
                _ => None,
            }).flatten() {
                buf
                    .client_count
                    .store(0, core::sync::atomic::Ordering::Release);
                buf.wake_readers();
                buf.wake_writers();
            }
            if iosb_ptr != 0 {
                crate::try_write_guest_value_unaligned(iosb_ptr, 0i32);
                crate::try_write_guest_value_unaligned(iosb_ptr + 8, 0usize);
            }
            NtStatus::STATUS_SUCCESS
        }
        FSCTL_PIPE_WAIT => {
            // Wait for a pipe instance to become available — return immediately.
            if iosb_ptr != 0 {
                crate::try_write_guest_value_unaligned(iosb_ptr, 0i32);
                crate::try_write_guest_value_unaligned(iosb_ptr + 8, 0usize);
            }
            NtStatus::STATUS_SUCCESS
        }
        _ => {
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtFsControlFile unhandled fsctl=0x{:08X}\n",
                    fsctl_code,
                ));
            }
            NtStatus::STATUS_NOT_IMPLEMENTED
        }
    }
}

/// Read data from a pipe handle.
///
/// Called from the NtReadFile dispatch when the target is an `NtObject::Pipe`.
/// If the buffer is empty and the writer hasn't closed, returns
/// `STATUS_PIPE_EMPTY` (the caller can retry). If the writer has closed and
/// buffer is empty, returns `STATUS_PIPE_BROKEN`.
pub(crate) fn nt_read_file_pipe(
    ctx: &mut super::super::ExecutionContext,
    buffer: &Arc<crate::handle_table::PipeBuffer>,
    wait_cx: &litebox::event::wait::WaitContext<'_, litebox_platform_multiplex::Platform>,
) -> NtStatus {
    // NtReadFile args: arg0=FileHandle, arg1=Event, arg2=ApcRoutine,
    // arg3=ApcContext, arg4=IoStatusBlock, arg5=Buffer, arg6=Length
    let iosb_ptr = NtSyscallArgs::arg4(ctx);
    let out_buf = NtSyscallArgs::arg5(ctx);
    let out_len =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0) as usize;

    if out_buf == 0 || out_len == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        let data_len = buffer.data.lock().len();
        let cc = buffer.client_closed();
        let sc = buffer.server_closed();
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: nt_read_file_pipe ENTER out_len={out_len} buf_len={data_len} client_closed={cc} server_closed={sc}\n",
        ));
    }

    // Register our waker so pipe writers / close paths can wake us.
    buffer.read_waiters.lock().push(wait_cx.waker().clone());

    // Block until data is available or the writer has closed.
    let cx = wait_cx.with_timeout(None);
    let result = cx.wait_until(|| {
        let data = buffer.data.lock();
        if !data.is_empty() {
            return true; // data available
        }
        // No data — check if writer has closed (EOF).
        buffer.client_closed()
    });

    // Unregister our waker.
    buffer
        .read_waiters
        .lock()
        .retain(|w| !w.ptr_eq(wait_cx.waker()));

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: nt_read_file_pipe AFTER_WAIT result={result:?}\n",
        ));
    }

    // If the wait was interrupted (e.g. process exit), return pipe broken.
    if result.is_err() {
        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: nt_read_file_pipe INTERRUPTED\n",
            ));
        }
        if iosb_ptr != 0 {
            crate::try_write_guest_value_unaligned(
                iosb_ptr,
                NtStatus::STATUS_PIPE_BROKEN.raw() as i32,
            );
            crate::try_write_guest_value_unaligned(iosb_ptr + 8, 0usize);
        }
        return NtStatus::STATUS_PIPE_BROKEN;
    }

    // Now try to read.
    let mut data = buffer.data.lock();
    if data.is_empty() {
        // Writer closed and buffer is empty — EOF / pipe broken.
        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: nt_read_file_pipe EOF (writer closed, empty)\n",
            ));
        }
        if iosb_ptr != 0 {
            crate::try_write_guest_value_unaligned(
                iosb_ptr,
                NtStatus::STATUS_PIPE_BROKEN.raw() as i32,
            );
            crate::try_write_guest_value_unaligned(iosb_ptr + 8, 0usize);
        }
        return NtStatus::STATUS_PIPE_BROKEN;
    }

    let to_read = core::cmp::min(out_len, data.len());
    let dest = unsafe { core::slice::from_raw_parts_mut(out_buf as *mut u8, to_read) };
    for (i, byte) in data.drain(..to_read).enumerate() {
        dest[i] = byte;
    }
    drop(data);
    buffer.wake_writers();

    // Write IoStatusBlock.
    if iosb_ptr != 0 {
        crate::try_write_guest_value_unaligned(iosb_ptr, 0i32);
        crate::try_write_guest_value_unaligned(iosb_ptr + 8, to_read);
    }

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: nt_read_file_pipe read {} bytes\n",
            to_read,
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// Asynchronous read from a pipe handle bound to an I/O Completion Port.
///
/// Instead of blocking, this queues a `PendingPipeRead` and returns
/// `STATUS_PENDING`.  When data arrives (or the pipe breaks), the pending
/// read is fulfilled by `PipeBuffer::drain_pending_reads()` /
/// `break_pending_reads()` which also posts an IOCP completion packet.
pub(crate) fn nt_read_file_pipe_async(
    ctx: &mut super::super::ExecutionContext,
    buffer: &Arc<crate::handle_table::PipeBuffer>,
    port: &Arc<crate::handle_table::IoCompletionObject>,
    key: usize,
    event: Option<Arc<crate::handle_table::EventObject>>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let apc_context = args.arg3; // libuv passes the overlapped pointer here
    let iosb_ptr = NtSyscallArgs::arg4(ctx);
    let out_buf = NtSyscallArgs::arg5(ctx);
    let out_len =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0) as usize;

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: nt_read_file_pipe_async args: out_buf=0x{out_buf:X} out_len={out_len} iosb=0x{iosb_ptr:X} apc_ctx=0x{apc_context:X} event={} rsp=0x{:X}\n",
            event.is_some(),
            ctx.regs.rsp,
        ));
    }

    if out_buf == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Zero-length reads are valid on IOCP-bound pipes (libuv uses them to
    // get a "data available" notification).  drain_pending_reads() will
    // satisfy them with 0 bytes copied once data arrives.

    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        let data_len = buffer.data.lock().len();
        let cc = buffer.client_closed();
        let wg = buffer.writer_gone.load(core::sync::atomic::Ordering::Acquire);
        let buf_ptr = Arc::as_ptr(buffer) as usize;
        let port_ptr = Arc::as_ptr(port) as usize;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: nt_read_file_pipe_async out_buf=0x{out_buf:X} out_len={out_len} apc_ctx=0x{apc_context:X} iosb=0x{iosb_ptr:X} buf_data={data_len} client_closed={cc} writer_gone={wg} PipeBuffer={buf_ptr:#X} IOCP={port_ptr:#X}\n",
        ));
    }

    // If the writer is already gone and no data remains, complete
    // immediately with STATUS_PIPE_BROKEN.  On real Windows NtReadFile on a
    // broken pipe does the same — it posts the IOCP completion and signals
    // the Event before returning STATUS_PENDING.
    if buffer.writer_gone.load(core::sync::atomic::Ordering::Acquire)
        && buffer.data.lock().is_empty()
    {
        if iosb_ptr != 0 {
            crate::try_write_guest_value_unaligned(
                iosb_ptr,
                NtStatus::STATUS_PIPE_BROKEN.raw() as i32,
            );
            crate::try_write_guest_value_unaligned(iosb_ptr + 8, 0usize);
        }
        port.push(crate::handle_table::IoCompletionEntry {
            key_context: key,
            apc_context,
            status: NtStatus::STATUS_PIPE_BROKEN,
            information: 0,
        });
        // Signal the event if one was provided.
        if let Some(ref ev) = event {
            *ev.state.lock() = true;
            ev.wake_waiters();
        }
        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: nt_read_file_pipe_async writer_gone + empty -> immediate PIPE_BROKEN\n",
            ));
        }
        return NtStatus::STATUS_PENDING;
    }

    // Set the IOSB status to STATUS_PENDING so the caller knows the I/O is
    // in progress.
    if iosb_ptr != 0 {
        crate::try_write_guest_value_unaligned(iosb_ptr, NtStatus::STATUS_PENDING.raw() as i32);
        crate::try_write_guest_value_unaligned(iosb_ptr + 8, 0usize);
    }

    // Queue the pending read.
    let pending = crate::handle_table::PendingPipeRead {
        buffer_ptr: out_buf,
        buffer_len: out_len,
        iosb_ptr,
        apc_context,
        port: Arc::clone(port),
        key,
        event,
    };
    buffer.pending_reads.lock().push(pending);

    // Try to drain immediately — data may already be in the pipe.
    buffer.drain_pending_reads();

    NtStatus::STATUS_PENDING
}

/// Write data to a pipe handle.
///
/// Called from the NtWriteFile dispatch when the target is an `NtObject::Pipe`.
/// If the reader has closed, returns `STATUS_PIPE_BROKEN`.
pub(crate) fn nt_write_file_pipe(
    ctx: &mut super::super::ExecutionContext,
    buffer: &Arc<crate::handle_table::PipeBuffer>,
) -> NtStatus {
    // NtWriteFile args: arg0=FileHandle, arg1=Event, arg2=ApcRoutine,
    // arg3=ApcContext, arg4=IoStatusBlock, arg5=Buffer, arg6=Length
    let iosb_ptr = NtSyscallArgs::arg4(ctx);
    let in_buf = NtSyscallArgs::arg5(ctx);
    let in_len =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0) as usize;

    if in_buf == 0 || in_len == 0 {
        // Write 0 bytes is a no-op success.
        if iosb_ptr != 0 {
            crate::try_write_guest_value_unaligned(iosb_ptr, 0i32);
            crate::try_write_guest_value_unaligned(iosb_ptr + 8, 0usize);
        }
        return NtStatus::STATUS_SUCCESS;
    }

    let reader_closed = buffer.server_closed();
    if reader_closed {
        if iosb_ptr != 0 {
            crate::try_write_guest_value_unaligned(
                iosb_ptr,
                NtStatus::STATUS_PIPE_BROKEN.raw() as i32,
            );
            crate::try_write_guest_value_unaligned(iosb_ptr + 8, 0usize);
        }
        return NtStatus::STATUS_PIPE_BROKEN;
    }

    let src = unsafe { core::slice::from_raw_parts(in_buf as *const u8, in_len) };
    let mut data = buffer.data.lock();
    data.extend(src.iter().copied());
    drop(data);
    buffer.wake_readers();
    // Fulfill any pending async reads that can now be satisfied.
    buffer.drain_pending_reads();

    // Write IoStatusBlock.
    if iosb_ptr != 0 {
        crate::try_write_guest_value_unaligned(iosb_ptr, 0i32);
        crate::try_write_guest_value_unaligned(iosb_ptr + 8, in_len);
    }

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        let buf_ptr = Arc::as_ptr(buffer) as usize;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: nt_write_file_pipe wrote {} bytes PipeBuffer={:#X}\n",
            in_len, buf_ptr,
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// NtCreateUserProcess — virtual process spawning.
///
/// This does NOT actually create a new process. Instead it:
///   1. Reads the command line from RTL_USER_PROCESS_PARAMETERS
///   2. Executes a built-in mini-shell to handle simple commands
///   3. Captures stdout/stderr through pipe handles
///   4. Fills in CreateInfo and the ProcessParameters attribute in the
///      caller's PS_ATTRIBUTE_LIST
///
/// Syscall signature (x64):
///   NtCreateUserProcess(
///     OUT PHANDLE                ProcessHandle,           // rcx  (arg0)
///     OUT PHANDLE                ThreadHandle,            // rdx  (arg1)
///     IN  ACCESS_MASK            ProcessDesiredAccess,    // r8   (arg2)
///     IN  ACCESS_MASK            ThreadDesiredAccess,     // r9   (arg3)
///     IN  POBJECT_ATTRIBUTES     ProcessObjectAttributes, // [rsp+0x28] (stack0)
///     IN  POBJECT_ATTRIBUTES     ThreadObjectAttributes,  // [rsp+0x30] (stack1)
///     IN  ULONG                  ProcessFlags,            // [rsp+0x38] (stack2)
///     IN  ULONG                  ThreadFlags,             // [rsp+0x40] (stack3)
///     IN  PRTL_USER_PROCESS_PARAMETERS ProcessParameters, // [rsp+0x48] (stack4)
///     IN OUT PPS_CREATE_INFO     CreateInfo,              // [rsp+0x50] (stack5)
///     IN  PPS_ATTRIBUTE_LIST     AttributeList,           // [rsp+0x58] (stack6)
///   );
pub(crate) fn nt_create_user_process<FS: crate::NtShimFS>(
    ctx: &mut super::super::ExecutionContext,
    shared: &Arc<super::super::NtSharedState<FS>>,
) -> NtStatus {
    // arg0 = r10 (not rcx! — the ntdll stub does `mov r10, rcx` before `syscall`,
    // and the CPU clobbers rcx with the return address during `syscall`).
    let process_handle_out = ctx.regs.r10 as usize;
    let thread_handle_out = ctx.regs.rdx as usize;

    let process_params_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x48).unwrap_or(0);
    let create_info_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x50).unwrap_or(0);

    // Read command line from RTL_USER_PROCESS_PARAMETERS.
    // CommandLine is a UNICODE_STRING at offset +0x70.
    let cmd_line = if process_params_ptr != 0 {
        read_unicode_string_from_guest(process_params_ptr + 0x70).unwrap_or_default()
    } else {
        String::new()
    };

    // Read image path from PS_ATTRIBUTE_LIST (PsAttributeImageName = 0x20005).
    let attribute_list_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x58).unwrap_or(0);
    let image_path_nt = extract_image_path_from_attributes(attribute_list_ptr);

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtCreateUserProcess cmd_line=\"{}\" image_path=\"{}\"\n",
            cmd_line,
            image_path_nt.as_deref().unwrap_or("<none>"),
        ));
    }

    // Read hStdInput / hStdOutput / hStdError from RTL_USER_PROCESS_PARAMETERS.
    //   +0x20: StandardInput  (HANDLE)
    //   +0x28: StandardOutput (HANDLE)
    //   +0x30: StandardError  (HANDLE)
    let stdin_handle = if process_params_ptr != 0 {
        crate::try_read_guest_value_unaligned::<u32>(process_params_ptr + 0x20).unwrap_or(0)
    } else {
        0
    };
    let stdout_handle = if process_params_ptr != 0 {
        crate::try_read_guest_value_unaligned::<u32>(process_params_ptr + 0x28).unwrap_or(0)
    } else {
        0
    };
    let stderr_handle = if process_params_ptr != 0 {
        crate::try_read_guest_value_unaligned::<u32>(process_params_ptr + 0x30).unwrap_or(0)
    } else {
        0
    };

    // Read Environment pointer from RTL_USER_PROCESS_PARAMETERS (+0x80).
    // Parse the double-NUL terminated UTF-16LE environment block into a
    // Vec of "KEY=VALUE" strings for the child process.
    let child_env_strings: alloc::vec::Vec<alloc::string::String> = if process_params_ptr != 0 {
        let env_ptr =
            crate::try_read_guest_value_unaligned::<usize>(process_params_ptr + 0x80).unwrap_or(0);
        if env_ptr != 0 {
            parse_env_block_from_guest(env_ptr)
        } else {
            alloc::vec::Vec::new()
        }
    } else {
        alloc::vec::Vec::new()
    };

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        let env_keys: alloc::vec::Vec<&str> = child_env_strings
            .iter()
            .filter_map(|s| s.split('=').next())
            .collect();
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtCreateUserProcess stdin=0x{:X} stdout=0x{:X} stderr=0x{:X} env_vars={} keys={:?}\n",
            stdin_handle, stdout_handle, stderr_handle, child_env_strings.len(), env_keys,
        ));
    }

    // Determine whether this is a builtin cmd.exe command or a real EXE spawn.
    //
    // Strategy: if the image is cmd.exe, try the builtin handler first.
    // If the builtin handler doesn't recognize the command (returns the
    // "not recognized" error), fall through to the real spawn path.
    // For non-cmd.exe images, go straight to the real spawn path.
    let is_cmd_exe = is_cmd_exe_image(&cmd_line, image_path_nt.as_deref());

    if is_cmd_exe {
        let (builtin_exit_code, builtin_output, was_recognized) =
            try_execute_builtin_command(&cmd_line, shared);

        if was_recognized {
            // Builtin command handled inline — write output to pipes, fill in
            // return structures, and return success.
            return finish_inline_process(
                shared,
                process_handle_out,
                thread_handle_out,
                process_params_ptr,
                create_info_ptr,
                attribute_list_ptr,
                stdin_handle,
                stdout_handle,
                stderr_handle,
                builtin_exit_code,
                &builtin_output,
            );
        }
        // Not a recognized builtin — fall through to real spawn.
    }

    // ── gh auth token interception ───────────────────────────────────
    //
    // Copilot (and other GitHub CLI tools) may spawn `gh auth token` to
    // retrieve auth tokens.  Since the real `gh` CLI is not available in
    // the sandbox, intercept the command and return the token directly
    // from the child's environment (GH_TOKEN / GITHUB_TOKEN /
    // COPILOT_GITHUB_TOKEN).
    {
        let is_gh_auth = {
            let lower_cmd = cmd_line.to_ascii_lowercase();
            // Match "gh auth token" in the command line (covers both cmd.exe
            // wrappers and direct gh.exe/gh.com spawns).
            let cmd_has_gh_auth = lower_cmd.contains("gh auth token")
                || lower_cmd.contains("gh.exe auth token")
                || lower_cmd.contains("gh.com auth token");
            // Also match by image path for direct spawns where the command
            // line only contains "auth token ..." without the "gh" prefix.
            let img_is_gh = image_path_nt.as_deref().map_or(false, |img| {
                let lower = img.to_ascii_lowercase();
                lower.ends_with("\\gh.exe")
                    || lower.ends_with("\\gh.com")
                    || lower.ends_with("/gh.exe")
                    || lower.ends_with("/gh.com")
            });
            cmd_has_gh_auth || (img_is_gh && lower_cmd.contains("auth") && lower_cmd.contains("token"))
        };

        if is_gh_auth {
            // Find the token in the child's env block.
            let token = child_env_strings
                .iter()
                .find_map(|s| {
                    if let Some(rest) = s.strip_prefix("GH_TOKEN=") {
                        Some(rest)
                    } else if let Some(rest) = s.strip_prefix("GITHUB_TOKEN=") {
                        Some(rest)
                    } else if let Some(rest) = s.strip_prefix("COPILOT_GITHUB_TOKEN=") {
                        Some(rest)
                    } else {
                        None
                    }
                })
                .unwrap_or("");

            if !token.is_empty() {
                #[cfg(any(debug_assertions, feature = "trace_debug"))]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtCreateUserProcess intercepted gh auth token, returning token from env (len={})\n",
                        token.len(),
                    ));
                }
                return finish_inline_process(
                    shared,
                    process_handle_out,
                    thread_handle_out,
                    process_params_ptr,
                    create_info_ptr,
                    attribute_list_ptr,
                    stdin_handle,
                    stdout_handle,
                    stderr_handle,
                    0,
                    &alloc::format!("{}\n", token),
                );
            }
        }
    }

    // ── Real spawn path ──────────────────────────────────────────────
    //
    // Extract pipe buffers from the parent's handle table for the child
    // process to inherit as its stdin/stdout/stderr.
    let (stdin_pipe, stdout_pipe, stderr_pipe) = {
        let handles = shared.handles.lock();
        (
            extract_pipe_buffer(&handles, stdin_handle),
            extract_pipe_buffer(&handles, stdout_handle),
            extract_pipe_buffer(&handles, stderr_handle),
        )
    };

    // Determine the NT image path for the child. Use the explicit
    // PsAttributeImageName if available, otherwise derive from cmd_line.
    let spawn_image_path = image_path_nt
        .as_deref()
        .map(|s| alloc::string::String::from(s))
        .unwrap_or_else(|| derive_image_path_from_cmdline(&cmd_line));

    // For Node.js SEA binaries (e.g. copilot.exe) that use
    // execArgvExtension: "cli", inject --node-options= into the child
    // command line so the DNS patch is loaded via --require.
    // The SEA binary strips --node-options= from argv before running JS,
    // so it won't conflict with the application's CLI parser.
    let cmd_line = {
        let image_lower = spawn_image_path.to_ascii_lowercase();
        let needs_node_options = (image_lower.ends_with("copilot.exe")
            || image_lower.ends_with("node.exe"))
            && !cmd_line.contains("--node-options=");
        if needs_node_options {
            inject_node_options_into_cmdline(
                &cmd_line,
                r#"--require C:\Windows\System32\__litebox_dns_patch.js"#,
            )
        } else {
            cmd_line
        }
    };

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtCreateUserProcess real spawn: image=\"{}\"\n",
            spawn_image_path,
        ));
    }

    match super::process::spawn_child_process(
        shared,
        &spawn_image_path,
        &cmd_line,
        stdin_pipe,
        stdout_pipe,
        stderr_pipe,
        child_env_strings,
    ) {
        Ok(result) => {
            // Write handles to caller.
            if process_handle_out != 0 {
                crate::try_write_guest_value_unaligned(process_handle_out, result.process_handle);
            }
            if thread_handle_out != 0 {
                crate::try_write_guest_value_unaligned(thread_handle_out, result.thread_handle);
            }

            // Fill in PS_CREATE_INFO.
            fill_create_info(create_info_ptr, process_params_ptr);

            // Fill in PS_ATTRIBUTE_LIST return values.
            fill_attribute_list_output(attribute_list_ptr, result.process_id, result.thread_id);

            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtCreateUserProcess real spawn success: pid={} tid={} proc_h=0x{:X} thread_h=0x{:X}\n",
                    result.process_id, result.thread_id, result.process_handle, result.thread_handle,
                ));
            }

            NtStatus::STATUS_SUCCESS
        }
        Err(status) => {
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtCreateUserProcess real spawn FAILED: 0x{:X}\n",
                    status as u32,
                ));
            }
            NtStatus(status)
        }
    }
}

/// Insert `--node-options=<value>` after the first token (program name) in a
/// Windows command line string.  This is consumed by Node.js SEA binaries that
/// use `execArgvExtension: "cli"`.
fn inject_node_options_into_cmdline(
    cmd_line: &str,
    node_options_value: &str,
) -> alloc::string::String {
    // Find the end of the first token (program name).
    let trimmed = cmd_line.trim_start();
    let first_end = if trimmed.starts_with('"') {
        // Quoted program name — find closing quote.
        trimmed[1..].find('"').map(|i| i + 2).unwrap_or(trimmed.len())
    } else {
        trimmed.find(' ').unwrap_or(trimmed.len())
    };
    let (prog, rest) = trimmed.split_at(first_end);
    alloc::format!(
        "{} \"--node-options={}\"{}",
        prog,
        node_options_value,
        rest,
    )
}

/// Check if the target image is cmd.exe based on the image path or command line.
fn is_cmd_exe_image(cmd_line: &str, image_path: Option<&str>) -> bool {
    if let Some(path) = image_path {
        let lower = path.to_ascii_lowercase();
        return lower.ends_with("\\cmd.exe") || lower.ends_with("/cmd.exe");
    }
    // No explicit image path — check if cmd_line starts with cmd.exe.
    let lower = cmd_line.trim().to_ascii_lowercase();
    lower.starts_with("cmd.exe ")
        || lower.starts_with("cmd /")
        || lower.starts_with("\"cmd.exe\"")
        || lower.starts_with("\"cmd\"")
        || lower.contains("\\cmd.exe")
}

/// Try executing as a builtin command. Returns (exit_code, output, was_recognized).
/// `was_recognized` is false only for the `_` (catch-all) arm.
fn try_execute_builtin_command<FS: crate::NtShimFS>(
    cmd_line: &str,
    shared: &super::super::NtSharedState<FS>,
) -> (i32, String, bool) {
    let body = parse_cmd_body(cmd_line);
    let args = shell_split(body);

    if args.is_empty() {
        return (0, String::new(), true);
    }

    let cmd = args[0].to_ascii_lowercase();
    match cmd.as_str() {
        "echo" | "set" | "type" | "exit" | "ver" | "cd" | "dir" | "mkdir" | "md" => {
            let (code, output) = execute_builtin_command(cmd_line, shared);
            (code, output, true)
        }
        _ => {
            // Not a recognized builtin command.
            (1, String::new(), false)
        }
    }
}

/// Extract a PipeBuffer Arc from a handle, if it's a Pipe.
fn extract_pipe_buffer<FS: crate::NtShimFS>(
    handles: &HandleTable<FS>,
    handle: u32,
) -> Option<Arc<crate::handle_table::PipeBuffer>> {
    if handle == 0 {
        return None;
    }
    handles.with(handle, |entry| match &entry.object {
        NtObject::Pipe { buffer, .. } => Some(Arc::clone(buffer)),
        _ => None,
    }).flatten()
}

/// Derive an NT image path from the command line for cases where
/// PsAttributeImageName wasn't provided.
fn derive_image_path_from_cmdline(cmd_line: &str) -> String {
    let trimmed = cmd_line.trim();
    // Extract the first token (possibly quoted).
    let exe = if trimmed.starts_with('"') {
        // Find closing quote.
        if let Some(end) = trimmed[1..].find('"') {
            &trimmed[1..1 + end]
        } else {
            trimmed.split_whitespace().next().unwrap_or(trimmed)
        }
    } else {
        trimmed.split_whitespace().next().unwrap_or(trimmed)
    };
    // If it already looks like an NT path, return as-is.
    if exe.starts_with("\\??\\") || exe.starts_with("\\\\?\\") {
        return alloc::string::String::from(exe);
    }
    // Wrap in NT path prefix.
    alloc::format!("\\??\\{exe}")
}

/// Extract the image path from PS_ATTRIBUTE_LIST (PsAttributeImageName = 0x20005).
fn extract_image_path_from_attributes(attribute_list_ptr: usize) -> Option<String> {
    if attribute_list_ptr == 0 {
        return None;
    }
    let total_length =
        crate::try_read_guest_value_unaligned::<usize>(attribute_list_ptr).unwrap_or(0);
    if total_length <= 8 {
        return None;
    }
    let entry_size = 4 * core::mem::size_of::<usize>(); // 32
    let num_attrs = (total_length - core::mem::size_of::<usize>()) / entry_size;
    for i in 0..num_attrs {
        let attr_base = attribute_list_ptr + 8 + i * entry_size;
        let attr_id = crate::try_read_guest_value_unaligned::<usize>(attr_base).unwrap_or(0);
        let attr_size = crate::try_read_guest_value_unaligned::<usize>(attr_base + 8).unwrap_or(0);
        let attr_value =
            crate::try_read_guest_value_unaligned::<usize>(attr_base + 16).unwrap_or(0);

        // PsAttributeImageName = 0x20005
        if attr_id == 0x20005 && attr_value != 0 && attr_size > 0 {
            // attr_value points to a UNICODE_STRING-like buffer (raw wide chars).
            // attr_size is the byte length of the wide string.
            let char_count = attr_size / 2;
            if crate::is_addr_range_committed(attr_value, attr_size) {
                let wchars =
                    unsafe { core::slice::from_raw_parts(attr_value as *const u16, char_count) };
                return Some(alloc::string::String::from_utf16_lossy(wchars));
            }
        }
    }
    None
}

/// Complete an inline (builtin) process creation — writes output to pipes,
/// creates a fake process/thread, fills in return structures.
#[allow(clippy::too_many_arguments)]
fn finish_inline_process<FS: crate::NtShimFS>(
    shared: &Arc<super::super::NtSharedState<FS>>,
    process_handle_out: usize,
    thread_handle_out: usize,
    process_params_ptr: usize,
    create_info_ptr: usize,
    attribute_list_ptr: usize,
    _stdin_handle: u32,
    stdout_handle: u32,
    stderr_handle: u32,
    exit_code: i32,
    output: &str,
) -> NtStatus {
    // Create a process object.
    let process_obj = Arc::new(crate::handle_table::ProcessObject::new(None, None));

    // Lock the handle table for pipe writes and handle creation.
    let mut handles = shared.handles.lock();

    // Write output to the stdout pipe if we have one.
    if !output.is_empty() && stdout_handle != 0 {
        let pipe_buf = handles.with(stdout_handle, |entry| match &entry.object {
            NtObject::Pipe { buffer, .. } => Some(Arc::clone(buffer)),
            _ => None,
        }).flatten();
        if let Some(buf) = pipe_buf {
            let mut data = buf.data.lock();
            data.extend(output.as_bytes().iter().copied());
            drop(data);
            buf.wake_readers();

            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtCreateUserProcess wrote {} bytes to stdout pipe 0x{:X}\n",
                    output.len(), stdout_handle,
                ));
            }
        }
    }

    // NOTE: For inline (builtin) processes, we do NOT close the child's
    // pipe handles here. The parent owns those handles and will NtClose them
    // after NtCreateUserProcess returns. The NtClose will decrement the pipe
    // reference count to zero, signaling EOF to the parent's reader threads.
    // The output has already been written to the pipe buffer above.

    // Mark process as exited.
    process_obj.set_exited(exit_code);

    // Allocate a virtual PID.
    let pid = {
        let mut pid_guard = shared.next_process_id.lock();
        let id = *pid_guard;
        *pid_guard = id.wrapping_add(1);
        id
    };

    // Create handles for the process and a virtual thread.
    let proc_handle = handles.insert(NtObject::Process {
        state: process_obj.clone(),
    });
    let thread_handle = handles.insert(NtObject::VirtualThread {
        process: process_obj.clone(),
    });

    // Write handles to caller.
    if process_handle_out != 0 {
        crate::try_write_guest_value_unaligned(process_handle_out, proc_handle);
    }
    if thread_handle_out != 0 {
        crate::try_write_guest_value_unaligned(thread_handle_out, thread_handle);
    }

    // Fill in PS_CREATE_INFO.
    fill_create_info(create_info_ptr, process_params_ptr);

    // Fill in PS_ATTRIBUTE_LIST return values.
    fill_attribute_list_output(attribute_list_ptr, pid, pid + 1);

    #[cfg(any(debug_assertions, feature = "trace_debug"))]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtCreateUserProcess (inline) pid={} exit_code={} proc_handle=0x{:X} thread_handle=0x{:X}\n",
            pid, exit_code, proc_handle, thread_handle,
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// Fill PS_CREATE_INFO output structure at `create_info_ptr`.
fn fill_create_info(create_info_ptr: usize, process_params_ptr: usize) {
    if create_info_ptr == 0 || !crate::is_addr_range_writable(create_info_ptr, 0x50) {
        return;
    }
    unsafe {
        // Preserve Size at +0x00, zero the rest of the success structure.
        let saved_size = core::ptr::read(create_info_ptr as *const usize);
        core::ptr::write_bytes((create_info_ptr + 8) as *mut u8, 0, 0x48);
        // State = PsCreateSuccess (6).
        core::ptr::write((create_info_ptr + 8) as *mut u32, 6);
        // Restore Size.
        core::ptr::write(create_info_ptr as *mut usize, saved_size);
        // UserProcessParametersNative = the original params ptr.
        core::ptr::write((create_info_ptr + 0x28) as *mut u64, process_params_ptr as u64);
        // CurrentParameterFlags = 1 (already normalized).
        core::ptr::write((create_info_ptr + 0x30) as *mut u32, 1);
        // PebAddressNative — set to a plausible non-zero value.
        core::ptr::write((create_info_ptr + 0x38) as *mut u64, 0x0000_0001_0000_0000u64);
        // OutputFlags — set bit 0 to indicate the process is running.
        core::ptr::write((create_info_ptr + 0x10) as *mut u32, 0x1);
    }
}

/// Fill PS_ATTRIBUTE_LIST output values (CLIENT_ID and SECTION_IMAGE_INFORMATION).
fn fill_attribute_list_output(attribute_list_ptr: usize, pid: u32, tid: u32) {
    if attribute_list_ptr == 0 {
        return;
    }
    let total_length =
        crate::try_read_guest_value_unaligned::<usize>(attribute_list_ptr).unwrap_or(0);
    if total_length <= 8 {
        return;
    }
    let entry_size = 4 * core::mem::size_of::<usize>(); // 32
    let num_attrs = (total_length - core::mem::size_of::<usize>()) / entry_size;
    for i in 0..num_attrs {
        let attr_base = attribute_list_ptr + 8 + i * entry_size;
        let attr_id = crate::try_read_guest_value_unaligned::<usize>(attr_base).unwrap_or(0);
        let attr_size = crate::try_read_guest_value_unaligned::<usize>(attr_base + 8).unwrap_or(0);
        let attr_value =
            crate::try_read_guest_value_unaligned::<usize>(attr_base + 16).unwrap_or(0);

        // PS_ATTRIBUTE_CLIENT_ID = 0x10003
        if attr_id == 0x10003 && attr_value != 0 {
            crate::try_write_guest_value_unaligned(attr_value, pid as usize);
            crate::try_write_guest_value_unaligned(
                attr_value + core::mem::size_of::<usize>(),
                tid as usize,
            );
        }
        // PsAttributeImageInfo = 0x6
        if attr_id == 0x6 && attr_value != 0 && attr_size >= 64 {
            unsafe {
                let min_size = if attr_size < 64 { attr_size } else { 64 };
                core::ptr::write_bytes(attr_value as *mut u8, 0, min_size);
            }
            // TransferAddress
            crate::try_write_guest_value_unaligned(attr_value, 0x140001000usize);
            // MaximumStackSize = 1MB
            crate::try_write_guest_value_unaligned(attr_value + 0x10, 0x100000usize);
            // CommittedStackSize = 4KB
            crate::try_write_guest_value_unaligned(attr_value + 0x18, 0x1000usize);
            // SubSystemType = IMAGE_SUBSYSTEM_WINDOWS_CUI (3)
            crate::try_write_guest_value_unaligned(attr_value + 0x20, 3u32);
            // MajorSubSystemVersion = 6, MinorSubSystemVersion = 0
            crate::try_write_guest_value_unaligned(attr_value + 0x24, 0u16);
            crate::try_write_guest_value_unaligned(attr_value + 0x26, 6u16);
            // MajorOSVersion = 10, MinorOSVersion = 0
            crate::try_write_guest_value_unaligned(attr_value + 0x28, 10u16);
            crate::try_write_guest_value_unaligned(attr_value + 0x2A, 0u16);
            // ImageCharacteristics = EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
            crate::try_write_guest_value_unaligned(attr_value + 0x2C, 0x0022u16);
            // DllCharacteristics = DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
            crate::try_write_guest_value_unaligned(attr_value + 0x2E, 0x8160u16);
            // Machine = AMD64 (0x8664)
            crate::try_write_guest_value_unaligned(attr_value + 0x30, 0x8664u16);
            // ImageContainsCode = 1
            crate::try_write_guest_value_unaligned(attr_value + 0x32, 1u8);
            // ImageFlags = 0
            crate::try_write_guest_value_unaligned(attr_value + 0x33, 0u8);
        }
    }
}

/// Execute a built-in shell command and return (exit_code, stdout_output).
///
/// Supported commands: echo, set, type, exit, ver, cd, dir, mkdir.
/// Commands prefixed with `cmd.exe /c` or `cmd /c` are stripped first.
fn execute_builtin_command<FS: crate::NtShimFS>(
    cmd_line: &str,
    shared: &super::super::NtSharedState<FS>,
) -> (i32, String) {
    let body = parse_cmd_body(cmd_line);
    let args = shell_split(body);

    if args.is_empty() {
        return (0, String::new());
    }

    let cmd = args[0].to_ascii_lowercase();
    match cmd.as_str() {
        "echo" => {
            // echo everything after "echo"
            let rest = if body.len() > 5 { &body[5..] } else { "" };
            (0, alloc::format!("{}\r\n", rest.trim()))
        }
        "set" => {
            // set — just return empty (no env vars in sandbox)
            (0, String::new())
        }
        "type" => {
            // type <filename> — read from VFS
            if args.len() < 2 {
                return (1, alloc::format!("The syntax of the command is incorrect.\r\n"));
            }
            let filename = &args[1];
            let vfs_path = if filename.len() >= 3 && filename.as_bytes()[1] == b':' {
                let drive = (filename.as_bytes()[0] as char).to_ascii_lowercase();
                let rest = filename[2..].replace('\\', "/");
                alloc::format!("/{}{}", drive, rest)
            } else {
                filename.replace('\\', "/")
            };
            if let Some(fs) = shared.fs.get() {
                use litebox::fs::{OFlags, Mode};
                match fs.open(&vfs_path, OFlags::RDONLY, Mode::empty()) {
                    Ok(fd) => {
                        let mut contents = alloc::vec::Vec::new();
                        let mut buf = [0u8; 4096];
                        loop {
                            match fs.read(&fd, &mut buf, None) {
                                Ok(0) => break,
                                Ok(n) => contents.extend_from_slice(&buf[..n]),
                                Err(_) => break,
                            }
                        }
                        let _ = fs.close(&fd);
                        let text = String::from_utf8_lossy(&contents).into_owned();
                        (0, text)
                    }
                    Err(_) => (
                        1,
                        alloc::format!(
                            "The system cannot find the file specified.\r\n"
                        ),
                    ),
                }
            } else {
                (1, alloc::format!("The system cannot find the file specified.\r\n"))
            }
        }
        "exit" => {
            let code = args.get(1).and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
            (code, String::new())
        }
        "ver" => (
            0,
            alloc::format!("Microsoft Windows [Version 10.0.22631.0]\r\n"),
        ),
        "cd" => {
            // Just return C:\ as the current directory.
            (0, alloc::format!("C:\\\r\n"))
        }
        "dir" => {
            // Minimal dir output.
            if args.len() < 2 {
                return (0, alloc::format!(" Volume in drive C has no label.\r\n Directory of C:\\\r\n\r\n"));
            }
            let dirname = &args[1];
            let vfs_path = if dirname.len() >= 3 && dirname.as_bytes()[1] == b':' {
                let drive = (dirname.as_bytes()[0] as char).to_ascii_lowercase();
                let rest = dirname[2..].replace('\\', "/");
                alloc::format!("/{}{}", drive, rest)
            } else {
                dirname.replace('\\', "/")
            };
            if let Some(fs) = shared.fs.get() {
                use litebox::fs::{OFlags, Mode};
                match fs.open(&vfs_path, OFlags::RDONLY, Mode::empty()) {
                    Ok(fd) => {
                        match fs.read_dir(&fd) {
                            Ok(entries) => {
                                let mut out = alloc::format!(" Directory of {}\r\n\r\n", dirname);
                                for entry in entries {
                                    use core::fmt::Write;
                                    let type_str = match entry.file_type {
                                        litebox::fs::FileType::Directory => "<DIR>         ",
                                        _ => "              ",
                                    };
                                    let _ = write!(out, "               {} {}\r\n", type_str, entry.name);
                                }
                                let _ = fs.close(&fd);
                                (0, out)
                            }
                            Err(_) => {
                                let _ = fs.close(&fd);
                                (1, alloc::format!("File Not Found\r\n"))
                            }
                        }
                    }
                    Err(_) => (
                        1,
                        alloc::format!("File Not Found\r\n"),
                    ),
                }
            } else {
                (1, alloc::format!("File Not Found\r\n"))
            }
        }
        "mkdir" | "md" => {
            if args.len() < 2 {
                return (1, alloc::format!("The syntax of the command is incorrect.\r\n"));
            }
            let dirname = &args[1];
            let vfs_path = if dirname.len() >= 3 && dirname.as_bytes()[1] == b':' {
                let drive = (dirname.as_bytes()[0] as char).to_ascii_lowercase();
                let rest = dirname[2..].replace('\\', "/");
                alloc::format!("/{}{}", drive, rest)
            } else {
                dirname.replace('\\', "/")
            };
            if let Some(fs) = shared.fs.get() {
                use litebox::fs::Mode;
                match fs.mkdir(&vfs_path, Mode::empty()) {
                    Ok(()) => (0, String::new()),
                    Err(_) => (1, alloc::format!("A subdirectory or file already exists.\r\n")),
                }
            } else {
                (1, alloc::format!("The system cannot find the path specified.\r\n"))
            }
        }
        _ => {
            #[cfg(any(debug_assertions, feature = "trace_debug"))]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: execute_builtin_command unrecognized: \"{}\"\n",
                    body,
                ));
            }
            // Unknown command — return exit code 1.
            (
                1,
                alloc::format!("'{}' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n", args[0]),
            )
        }
    }
}

/// Strip `cmd.exe /c` or `cmd /c` prefix from a command line.
///
/// When `cmd.exe /c "echo hello"` is used, the outer quotes are grouping
/// quotes — cmd.exe strips them and interprets the inner content as the
/// command.  We replicate this behavior: after stripping the `/c ` prefix,
/// if the remaining body starts and ends with `"`, strip those outer quotes.
fn parse_cmd_body(cmd_line: &str) -> &str {
    let trimmed = cmd_line.trim();
    let lower = trimmed.to_ascii_lowercase();

    // Try stripping various cmd.exe invocation prefixes.
    let body = 'find: {
        for prefix in &[
            "cmd.exe /c ",
            "cmd /c ",
            "cmd.exe /s /c ",
            "cmd /s /c ",
            "\"cmd.exe\" /c ",
            "\"cmd\" /c ",
            "c:\\windows\\system32\\cmd.exe /c ",
            "c:\\windows\\system32\\cmd.exe /s /c ",
        ] {
            if lower.starts_with(prefix) {
                break 'find &trimmed[prefix.len()..];
            }
        }
        return trimmed;
    };

    // cmd.exe /c "..." strips the outer grouping quotes.
    let body = body.trim();
    if body.len() >= 2 && body.starts_with('"') && body.ends_with('"') {
        &body[1..body.len() - 1]
    } else {
        body
    }
}

/// Split a command line into tokens, respecting double quotes.
fn shell_split(s: &str) -> alloc::vec::Vec<String> {
    let mut tokens = alloc::vec::Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(core::mem::take(&mut current));
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}
