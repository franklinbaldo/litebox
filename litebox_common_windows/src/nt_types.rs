// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT kernel data structures used by the shim's syscall interface.
//!
//! These are the structures that appear in NT syscall arguments and return
//! values. They must match the layout that Windows user-mode code expects.

use zerocopy::{FromBytes, IntoBytes};

/// NT UNICODE_STRING: a counted (not null-terminated) wide string.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct UnicodeString {
    /// Length of the string in **bytes** (not characters), excluding any
    /// trailing null.
    pub length: u16,
    /// Maximum length of the buffer in bytes.
    pub maximum_length: u16,
    /// Padding for alignment on 64-bit.
    pub _pad: u32,
    /// Pointer to the wide-character buffer (guest VA).
    pub buffer: u64,
}

/// OBJECT_ATTRIBUTES: passed to most NtCreate* / NtOpen* syscalls.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct ObjectAttributes {
    /// Size of this structure in bytes (must be `size_of::<ObjectAttributes>()`).
    pub length: u32,
    pub _pad0: u32,
    /// Optional HANDLE to a root directory for relative path resolution.
    pub root_directory: u64,
    /// Pointer to a `UnicodeString` containing the object name (guest VA).
    pub object_name: u64,
    /// `OBJ_*` attribute flags.
    pub attributes: u32,
    pub _pad1: u32,
    /// Security descriptor (guest VA); typically null in our shim.
    pub security_descriptor: u64,
    /// Security QoS (guest VA); typically null.
    pub security_quality_of_service: u64,
}

/// OBJ_* attribute flags for `ObjectAttributes`.
pub mod obj_attributes {
    pub const OBJ_INHERIT: u32 = 0x0000_0002;
    pub const OBJ_PERMANENT: u32 = 0x0000_0010;
    pub const OBJ_EXCLUSIVE: u32 = 0x0000_0020;
    pub const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    pub const OBJ_OPENIF: u32 = 0x0000_0080;
    pub const OBJ_OPENLINK: u32 = 0x0000_0100;
    pub const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;
}

/// IO_STATUS_BLOCK: returned by NtReadFile, NtWriteFile, NtCreateFile, etc.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct IoStatusBlock {
    /// NTSTATUS (or pointer, in some overlap scenarios).
    pub status: i32,
    pub _pad: u32,
    /// Number of bytes transferred, or other information.
    pub information: u64,
}

/// LARGE_INTEGER: a 64-bit signed integer used in many NT APIs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct LargeInteger {
    pub quad_part: i64,
}

/// Client ID: process + thread identifier pair.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct ClientId {
    pub unique_process: u64,
    pub unique_thread: u64,
}

/// SECURITY_QUALITY_OF_SERVICE: LPC/ALPC connection security settings.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct SecurityQualityOfService {
    pub length: u32,
    pub impersonation_level: u32,
    pub context_tracking_mode: u8,
    pub effective_only: u8,
    pub _pad: [u8; 2],
}

/// PORT_VIEW: client-side section mapping description for NtConnectPort.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct PortView {
    pub length: u32,
    pub _pad0: u32,
    pub section_handle: u64,
    pub section_offset: u32,
    pub _pad1: u32,
    pub view_size: u64,
    pub view_base: u64,
    pub view_remote_base: u64,
}

/// REMOTE_PORT_VIEW: server-side mapping description returned by NtConnectPort.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct RemotePortView {
    pub length: u32,
    pub _pad0: u32,
    pub view_size: u64,
    pub view_base: u64,
}

/// PORT_MESSAGE: LPC/ALPC message header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PortMessage {
    pub data_length: u16,
    pub total_length: u16,
    pub type_: u16,
    pub data_info_offset: u16,
    pub client_id: ClientId,
    pub message_id: u32,
    pub client_view_size_or_callback_id: u64,
}

/// FILE_BASIC_INFORMATION (class 4).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct FileBasicInformation {
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub file_attributes: u32,
    pub _pad: u32,
}

/// FILE_NETWORK_OPEN_INFORMATION (class 34).
/// Returned by NtQueryFullAttributesFile.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct FileNetworkOpenInformation {
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub file_attributes: u32,
    pub _pad: u32,
}

/// FILE_STANDARD_INFORMATION (class 5).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct FileStandardInformation {
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub number_of_links: u32,
    pub delete_pending: u8,
    pub directory: u8,
    pub _pad: [u8; 2],
}

/// FILE_ID_128.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct FileId128 {
    pub identifier: [u8; 16],
}

/// FILE_STAT_INFORMATION (class 68).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct FileStatInformation {
    pub file_id: i64,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub file_attributes: u32,
    pub reparse_tag: u32,
    pub number_of_links: u32,
    pub effective_access: u32,
}

/// FILE_STAT_BASIC_INFORMATION (class 77).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct FileStatBasicInformation {
    pub file_id: i64,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub file_attributes: u32,
    pub reparse_tag: u32,
    pub number_of_links: u32,
    pub device_type: u32,
    pub device_characteristics: u32,
    pub reserved: u32,
    pub volume_serial_number: i64,
    pub file_id128: FileId128,
}

/// FILE_POSITION_INFORMATION (class 14).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct FilePositionInformation {
    pub current_byte_offset: i64,
}

/// File attribute constants.
pub mod file_attributes {
    pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
    pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
    pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
    pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
    pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
}

/// File access rights.
pub mod file_access {
    pub const FILE_READ_DATA: u32 = 0x0001;
    pub const FILE_WRITE_DATA: u32 = 0x0002;
    pub const FILE_APPEND_DATA: u32 = 0x0004;
    pub const FILE_READ_EA: u32 = 0x0008;
    pub const FILE_WRITE_EA: u32 = 0x0010;
    pub const FILE_EXECUTE: u32 = 0x0020;
    pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    pub const FILE_GENERIC_READ: u32 =
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
    pub const FILE_GENERIC_WRITE: u32 =
        FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE;
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    pub const GENERIC_READ: u32 = 0x8000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;
}

/// File create disposition values for NtCreateFile.
pub mod file_disposition {
    pub const FILE_SUPERSEDE: u32 = 0;
    pub const FILE_OPEN: u32 = 1;
    pub const FILE_CREATE: u32 = 2;
    pub const FILE_OPEN_IF: u32 = 3;
    pub const FILE_OVERWRITE: u32 = 4;
    pub const FILE_OVERWRITE_IF: u32 = 5;
}

/// File create options for NtCreateFile.
pub mod file_options {
    pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    pub const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
    pub const FILE_SEQUENTIAL_ONLY: u32 = 0x0000_0004;
    pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    pub const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0010;
    pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    pub const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
    pub const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
}

/// Memory protection constants for NtAllocateVirtualMemory / NtProtectVirtualMemory.
pub mod mem_protect {
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_WRITECOPY: u32 = 0x08;
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_GUARD: u32 = 0x100;
}

/// Memory allocation type flags.
pub mod mem_alloc_type {
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_DECOMMIT: u32 = 0x4000;
    pub const MEM_RELEASE: u32 = 0x8000;
    pub const MEM_RESET: u32 = 0x0008_0000;
    pub const MEM_TOP_DOWN: u32 = 0x0010_0000;

    // Placeholder memory flags (Windows 10 1803+).
    // Used by V8 and other JIT engines for virtual memory reservation management.
    pub const MEM_COALESCE_PLACEHOLDERS: u32 = 0x0000_0001;
    pub const MEM_PRESERVE_PLACEHOLDER: u32 = 0x0000_0002;
    /// Passed with MEM_RESERVE in VirtualAlloc2/NtAllocateVirtualMemoryEx.
    pub const MEM_RESERVE_PLACEHOLDER: u32 = 0x0004_0000;
    /// Passed with MEM_COMMIT|MEM_RESERVE in VirtualAlloc2 to replace a
    /// placeholder with committed pages. Same numeric value as MEM_DECOMMIT
    /// but used in allocation context, not free context.
    pub const MEM_REPLACE_PLACEHOLDER: u32 = 0x0000_4000;
}

/// Memory state constants returned by NtQueryVirtualMemory.
pub mod mem_state {
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_FREE: u32 = 0x0001_0000;
}

/// MEMORY_BASIC_INFORMATION returned by NtQueryVirtualMemory(MemoryBasicInformation).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct MemoryBasicInformation {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub _pad0: u32,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
    pub _pad1: u32,
}
