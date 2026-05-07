// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A placeholder Windows NT shim for LiteBox.
//!
//! This crate intentionally only exposes the runner-facing skeleton for now.
//! The actual NT syscall, PE loading, and Windows process environment support
//! will be filled in piece by piece.

#![no_std]
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

extern crate alloc;

use alloc::sync::Arc;
use alloc::{format, string::String, vec, vec::Vec};
use core::ffi::c_void;
use core::fmt::Write as _;
use core::marker::PhantomData;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicI32, AtomicI64, AtomicUsize, Ordering};

use litebox::fd::TypedFd;
use litebox::fs::{Mode, OFlags};
use litebox::mm::PageManager;
use litebox::mm::linux::{
    CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, VmemProtectError,
};
use litebox::platform::{
    PunchthroughProvider as _, PunchthroughToken as _, RawConstPointer as _, RawMutPointer as _,
    SystemInfoProvider as _,
};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::{LiteBox, platform::RawPointerProvider};
use litebox_common_windows::loader::{
    AccessMemory, Fault, MapMemory, MappingInfo, PeExport, PeExportForwarder, PeImport,
    PeImportTarget, PeLoadError, PeParseError, PeParsedFile, Protection, ReadAt,
};
use litebox_platform_multiplex::Platform;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "GetStdHandle"]
    fn host_get_std_handle(n_std_handle: u32) -> *mut c_void;
    #[link_name = "WriteFile"]
    fn host_write_file(
        file: *mut c_void,
        buffer: *const c_void,
        bytes_to_write: u32,
        bytes_written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}

extern "system" fn litebox_ntdll_rtl_allocate_heap(
    _heap: *mut c_void,
    flags: u32,
    bytes: usize,
) -> *mut c_void {
    let memory = ntdll_guest_heap_allocate(bytes);
    litebox_util_log::debug!(
        flags:% = format_args!("{flags:#x}"),
        bytes,
        memory:% = format_args!("{memory:p}");
        "Handled ntdll!RtlAllocateHeap through built-in thunk"
    );
    memory
}

extern "system" fn litebox_ntdll_rtl_free_heap(
    _heap: *mut c_void,
    flags: u32,
    memory: *mut c_void,
) -> u8 {
    let free_result = ntdll_guest_heap_free(memory);
    litebox_util_log::debug!(
        flags:% = format_args!("{flags:#x}"),
        memory:% = format_args!("{memory:p}"),
        reclaimed_top = free_result.unwrap_or(false);
        "Handled ntdll!RtlFreeHeap through built-in thunk"
    );
    u8::from(free_result.is_some())
}

extern "system" fn litebox_ntdll_rtl_reallocate_heap(
    _heap: *mut c_void,
    flags: u32,
    memory: *mut c_void,
    bytes: usize,
) -> *mut c_void {
    let new_memory = ntdll_guest_heap_reallocate(memory, bytes);
    litebox_util_log::debug!(
        flags:% = format_args!("{flags:#x}"),
        memory:% = format_args!("{memory:p}"),
        bytes,
        new_memory:% = format_args!("{new_memory:p}");
        "Handled ntdll!RtlReAllocateHeap through built-in thunk"
    );
    new_memory
}

extern "system" fn litebox_ntdll_rtl_size_heap(
    _heap: *mut c_void,
    flags: u32,
    memory: *const c_void,
) -> usize {
    let size = ntdll_guest_heap_size(memory);
    litebox_util_log::debug!(
        flags:% = format_args!("{flags:#x}"),
        memory:% = format_args!("{memory:p}"),
        size;
        "Handled ntdll!RtlSizeHeap through built-in thunk"
    );
    size
}

extern "system" fn litebox_ntdll_rtl_create_heap(
    _flags: u32,
    _heap_base: *mut c_void,
    _reserve_size: usize,
    _commit_size: usize,
    _lock: *mut c_void,
    _parameters: *mut c_void,
) -> *mut c_void {
    let heap = NTDLL_HEAP_HANDLE.load(Ordering::Relaxed) as *mut c_void;
    litebox_util_log::debug!(
        heap:% = format_args!("{heap:p}");
        "Handled ntdll!RtlCreateHeap through built-in thunk"
    );
    heap
}

extern "system" fn litebox_ntdll_rtl_destroy_heap(_heap: *mut c_void) -> *mut c_void {
    litebox_util_log::debug!("Handled ntdll!RtlDestroyHeap through built-in thunk");
    core::ptr::null_mut()
}

extern "system" fn litebox_ntdll_api_set_resolve_unicode(
    api_set_map: *const c_void,
    name: *const UnicodeString,
    parent_name: *const UnicodeString,
    resolved: *mut u8,
    resolved_name: *mut UnicodeString,
) -> usize {
    let name_address = name as usize;
    let unicode_string = read_value::<UnicodeString>(name_address).unwrap_or_default();
    let api_set_name = if unicode_string.buffer != 0 && unicode_string.length != 0 {
        read_utf16_string(unicode_string.buffer, unicode_string.length).ok()
    } else {
        None
    };
    let mut replacement_name = None;
    let mut replacement_path = None;
    if let Some(api_set_name) = api_set_name.as_deref()
        && let Some(host_dll) = api_set_host_dll_or_default(api_set_map as usize, api_set_name)
    {
        let path = format!("C:\\Windows\\System32\\{host_dll}");
        if let Some(replacement) = ntdll_guest_heap_utf16_string(&path) {
            replacement_name = Some(replacement);
            replacement_path = Some(path);
        }
    }
    if unicode_string.buffer == 0
        && unicode_string.length != 0
        && let Some(replacement) =
            ntdll_guest_heap_utf16_string("C:\\Windows\\System32\\kernel32.dll")
    {
        let _ = write_value(name_address, replacement);
        replacement_name = Some(replacement);
        replacement_path = Some(String::from("C:\\Windows\\System32\\kernel32.dll"));
    }
    if !resolved.is_null() {
        let _ = write_value(resolved as usize, u8::from(replacement_name.is_some()));
    }
    if !resolved_name.is_null() {
        let _ = write_value(
            resolved_name as usize,
            replacement_name.unwrap_or_else(UnicodeString::default),
        );
    }
    litebox_util_log::debug!(
        api_set_map:% = format_args!("{api_set_map:p}"),
        name:% = format_args!("{name:p}"),
        length = unicode_string.length,
        maximum_length = unicode_string.maximum_length,
        buffer:% = format_args!("{:#x}", unicode_string.buffer),
        api_set_name:% = api_set_name.as_deref().unwrap_or("<unreadable>"),
        replacement_path:% = replacement_path.as_deref().unwrap_or("<none>"),
        parent_name:% = format_args!("{parent_name:p}"),
        resolved:% = format_args!("{resolved:p}"),
        resolved_name:% = format_args!("{resolved_name:p}"),
        replacement_buffer:% = format_args!("{:#x}", replacement_name.map_or(0, |name| name.buffer));
        "Handled ntdll API-set Unicode wrapper through built-in guard"
    );
    STATUS_SUCCESS
}

fn ntdll_guest_heap_allocate(bytes: usize) -> *mut c_void {
    let requested_size = bytes.max(1);
    if let Some(memory) = ntdll_guest_heap_reuse_free_block(requested_size) {
        return memory;
    }

    let Some(total_size) = ntdll_guest_heap_total_size(requested_size) else {
        return core::ptr::null_mut();
    };

    loop {
        let current = NTDLL_HEAP_BUMP.load(Ordering::Relaxed);
        let limit = NTDLL_HEAP_LIMIT.load(Ordering::Relaxed);
        let Some(allocation) = align_up_power_of_two(current, NTDLL_HEAP_ALIGNMENT) else {
            return core::ptr::null_mut();
        };
        let Some(next) = allocation.checked_add(total_size) else {
            return core::ptr::null_mut();
        };
        if current == 0 || next > limit {
            return core::ptr::null_mut();
        }
        if NTDLL_HEAP_BUMP
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            // SAFETY: The bump range is initialized from pages mapped and owned by the shim.
            unsafe {
                core::ptr::write_bytes(allocation as *mut u8, 0, total_size);
                (allocation as *mut usize).write(requested_size);
            }
            return allocation.saturating_add(NTDLL_HEAP_HEADER_SIZE) as *mut c_void;
        }
    }
}

fn ntdll_guest_heap_reuse_free_block(requested_size: usize) -> Option<*mut c_void> {
    loop {
        let free_header = NTDLL_HEAP_FREE_LIST.load(Ordering::Relaxed);
        if free_header == 0 {
            return None;
        }
        let free_memory = free_header.checked_add(NTDLL_HEAP_HEADER_SIZE)?;
        let free_size = ntdll_guest_heap_requested_size(free_memory as *const c_void)?;
        if free_size < requested_size {
            return None;
        }
        let next_free = read_usize_or_zero(free_memory);
        if NTDLL_HEAP_FREE_LIST
            .compare_exchange(free_header, next_free, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let total_size = ntdll_guest_heap_total_size(free_size)?;
            // SAFETY: The block came from the shim heap free list and is no longer reachable there.
            unsafe {
                core::ptr::write_bytes(
                    free_memory as *mut u8,
                    0,
                    total_size - NTDLL_HEAP_HEADER_SIZE,
                );
                (free_header as *mut usize).write(requested_size);
            }
            return Some(free_memory as *mut c_void);
        }
    }
}

fn ntdll_guest_heap_total_size(requested_size: usize) -> Option<usize> {
    requested_size
        .checked_add(NTDLL_HEAP_HEADER_SIZE)
        .and_then(|size| align_up_power_of_two(size, NTDLL_HEAP_ALIGNMENT))
}

fn ntdll_guest_heap_requested_size(memory: *const c_void) -> Option<usize> {
    if memory.is_null() {
        return None;
    }
    let header = (memory as usize).checked_sub(NTDLL_HEAP_HEADER_SIZE)?;
    let heap_base = NTDLL_HEAP_HANDLE.load(Ordering::Relaxed);
    let heap_limit = NTDLL_HEAP_LIMIT.load(Ordering::Relaxed);
    if heap_base == 0 || header < heap_base || header >= heap_limit {
        return None;
    }
    // SAFETY: The bounds check above verifies the header lies inside the shim heap range.
    Some(unsafe { (header as *const usize).read() })
}

fn ntdll_guest_heap_free(memory: *mut c_void) -> Option<bool> {
    if memory.is_null() {
        return Some(false);
    }
    let header = (memory as usize).checked_sub(NTDLL_HEAP_HEADER_SIZE)?;
    let heap_base = NTDLL_HEAP_HANDLE.load(Ordering::Relaxed);
    let heap_limit = NTDLL_HEAP_LIMIT.load(Ordering::Relaxed);
    if heap_base == 0 || header < heap_base || header >= heap_limit {
        return None;
    }
    let requested_size = ntdll_guest_heap_requested_size(memory.cast_const())?;
    let allocation_end = header.checked_add(ntdll_guest_heap_total_size(requested_size)?)?;
    if allocation_end > heap_limit {
        return None;
    }

    loop {
        let current = NTDLL_HEAP_BUMP.load(Ordering::Relaxed);
        if current != allocation_end {
            break;
        }
        if NTDLL_HEAP_BUMP
            .compare_exchange(current, header, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Some(true);
        }
    }

    let free_memory = header.checked_add(NTDLL_HEAP_HEADER_SIZE)?;
    loop {
        let next_free = NTDLL_HEAP_FREE_LIST.load(Ordering::Relaxed);
        write_value(free_memory, next_free).ok()?;
        if NTDLL_HEAP_FREE_LIST
            .compare_exchange(next_free, header, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Some(false);
        }
    }
}

fn ntdll_guest_heap_utf16_string(text: &str) -> Option<UnicodeString> {
    let code_units = text.encode_utf16().count();
    let byte_len = code_units.checked_mul(size_of::<u16>())?;
    let maximum_byte_len = byte_len.checked_add(size_of::<u16>())?;
    let buffer = ntdll_guest_heap_allocate(maximum_byte_len) as usize;
    if buffer == 0 {
        return None;
    }

    for (index, code_unit) in text.encode_utf16().chain(core::iter::once(0)).enumerate() {
        let offset = index.checked_mul(size_of::<u16>())?;
        let address = buffer.checked_add(offset)?;
        write_value(address, code_unit).ok()?;
    }

    Some(UnicodeString {
        length: u16::try_from(byte_len).ok()?,
        maximum_length: u16::try_from(maximum_byte_len).ok()?,
        buffer,
        ..Default::default()
    })
}

fn ntdll_guest_heap_reallocate(memory: *mut c_void, bytes: usize) -> *mut c_void {
    if memory.is_null() {
        return ntdll_guest_heap_allocate(bytes);
    }

    let old_size = ntdll_guest_heap_size(memory.cast_const());
    if bytes <= old_size {
        return memory;
    }

    let new_memory = ntdll_guest_heap_allocate(bytes);
    if new_memory.is_null() {
        return core::ptr::null_mut();
    }

    let copy_size = old_size.min(bytes);
    // SAFETY: Both pointers are allocations from the shim bump heap and do not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(memory.cast::<u8>(), new_memory.cast::<u8>(), copy_size);
    }
    new_memory
}

fn ntdll_guest_heap_size(memory: *const c_void) -> usize {
    ntdll_guest_heap_requested_size(memory).unwrap_or(usize::MAX)
}

fn align_up_power_of_two(value: usize, alignment: usize) -> Option<usize> {
    let mask = alignment.checked_sub(1)?;
    value.checked_add(mask).map(|value| value & !mask)
}

mod nt_sysno {
    include!(concat!(env!("OUT_DIR"), "/nt_sysno.rs"));
}

use nt_sysno::NtSysno;

const PAGE_SIZE: usize = litebox_common_windows::loader::PAGE_SIZE;
const INITIAL_STACK_SIZE: usize = 1024 * 1024;
const INITIAL_PEB_SIZE: usize = PAGE_SIZE;
const INITIAL_TEB_SIZE: usize = PAGE_SIZE * 2;
const INITIAL_LDR_DATA_SIZE: usize = PAGE_SIZE;
const INITIAL_LDR_ENTRIES_SIZE: usize = PAGE_SIZE;
const DYNAMIC_LDR_ENTRY_SIZE: usize = PAGE_SIZE;
const INITIAL_PROCESS_PARAMETERS_SIZE: usize = PAGE_SIZE;
const INITIAL_PROCESS_HEAP_SIZE: usize = 1024 * 1024;
const NTDLL_HEAP_ALIGNMENT: usize = 16;
const NTDLL_HEAP_HEADER_SIZE: usize = size_of::<usize>();
const INITIAL_FAST_PEB_LOCK_SIZE: usize = PAGE_SIZE;
const INITIAL_API_SET_NAMESPACE_SIZE: usize = PAGE_SIZE * 64;
const INITIAL_THREAD_CONTEXT_SIZE: usize = PAGE_SIZE;
const INITIAL_SYSTEM_DLL_INIT_BLOCK_SIZE: usize = PAGE_SIZE;
const DEFAULT_PROCESS_EXIT_CODE: i32 = 1;
const NTDLL_PATHS: &[&str] = &[
    "/windows/system32/ntdll.dll",
    "/Windows/System32/ntdll.dll",
    "/ntdll.dll",
];
const NTDLL_LOADER_ENTRYPOINT: &[u8] = b"LdrInitializeThunk";
// Current forced-loader diagnostics use the host ntdll fixture. These RVAs are
// host-version-specific guard rails for early ntdll loader bring-up.
const NTDLL_API_SET_RESOLVE_UNICODE_WRAPPER_RVA: usize = 0x41600;
const NTDLL_APPHELP_FAILURE_BRANCH_RVAS: &[usize] = &[0xbb56d];
const NTDLL_APPHELP_STATUS_TEST_RVA: usize = 0xbb41a;
const INITIAL_CURRENT_DIRECTORY_PATH: &str = "C:\\";
const INITIAL_DLL_SEARCH_PATH: &str = "C:\\Windows\\System32";
const SYMBOLIC_LINK_TARGET_PATH: &str = "C:\\Windows\\System32";
const WINDOWS_STD_INPUT_HANDLE: u32 = u32::MAX - 9;
const WINDOWS_STD_OUTPUT_HANDLE: u32 = u32::MAX - 10;
const WINDOWS_STD_ERROR_HANDLE: u32 = u32::MAX - 11;
const STATUS_SUCCESS: usize = 0;
const STATUS_INVALID_INFO_CLASS: usize = 0xc000_0003;
const STATUS_INFO_LENGTH_MISMATCH: usize = 0xc000_0004;
const STATUS_ACCESS_VIOLATION: usize = 0xc000_0005;
const STATUS_INVALID_PARAMETER: usize = 0xc000_000d;
const STATUS_NOT_MAPPED_VIEW: usize = 0xc000_0019;
const STATUS_OBJECT_NAME_NOT_FOUND: usize = 0xc000_0034;
const STATUS_NO_TOKEN: usize = 0xc000_007c;
const STATUS_MEMORY_NOT_ALLOCATED: usize = 0xc000_00a0;
const STATUS_NOT_SUPPORTED: usize = 0xc000_00bb;
const STATUS_NOT_SAME_DEVICE: usize = 0xc000_00d4;
const STATUS_DEBUGGER_INACTIVE: usize = 0xc000_0354;
const WINDOWS_CONTEXT_AMD64: u32 = 0x0010_0000;
const WINDOWS_CONTEXT_CONTROL: u32 = WINDOWS_CONTEXT_AMD64 | 0x0000_0001;
const WINDOWS_CONTEXT_INTEGER: u32 = WINDOWS_CONTEXT_AMD64 | 0x0000_0002;
const WINDOWS_CONTEXT_SEGMENTS: u32 = WINDOWS_CONTEXT_AMD64 | 0x0000_0004;
const WINDOWS_INITIAL_MXCSR: u32 = 0x1f80;
const WINDOWS_INITIAL_CS: u16 = 0x33;
const WINDOWS_INITIAL_SS: u16 = 0x2b;
const PERFORMANCE_FREQUENCY: i64 = 10_000_000;
const WINDOWS_PAGE_SIZE_U32: u32 = 4096;
const WINDOWS_ALLOCATION_GRANULARITY: u32 = 0x1_0000;
const WINDOWS_ALLOCATION_GRANULARITY_USIZE: usize = 0x1_0000;
const WINDOWS_MINIMUM_USER_ADDRESS: usize = 0x1_0000;
const WINDOWS_MAXIMUM_USER_ADDRESS: usize = 0x7fff_fffe_ffff;
const WINDOWS_STACK_ARGUMENT_5_OFFSET: usize = 0x28;
const WINDOWS_STACK_ARGUMENT_6_OFFSET: usize = 0x30;
const WINDOWS_STACK_ARGUMENT_7_OFFSET: usize = 0x38;
const WINDOWS_STACK_ARGUMENT_8_OFFSET: usize = 0x40;
const WINDOWS_STACK_ARGUMENT_9_OFFSET: usize = 0x48;
const WINDOWS_STACK_ARGUMENT_10_OFFSET: usize = 0x50;
const SYSTEM_BASIC_INFORMATION_CLASS: usize = 0;
const SYSTEM_NUMA_PROCESSOR_MAP_CLASS: usize = 55;
const SYSTEM_EMULATION_BASIC_INFORMATION_CLASS: usize = 62;
const SYSTEM_LOGICAL_PROCESSOR_AND_GROUP_INFORMATION_CLASS: usize = 107;
const SYSTEM_FLUSH_INFORMATION_CLASS: usize = 192;
const SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION_CLASS: usize = 197;
const SYSTEM_FEATURE_CONFIGURATION_INFORMATION_CLASS: usize = 210;
const SYSTEM_FEATURE_CONFIGURATION_SECTION_INFORMATION_CLASS: usize = 0xd3;
const SYSTEM_PROCESSOR_FEATURES_BITMAP_INFORMATION_CLASS: usize = 250;
const SYSTEM_SUPPORTED_FLUSH_METHODS: u32 = 0x7;
const SYSTEM_PROCESSOR_CACHE_FLUSH_SIZE: u32 = 0x40;
const PS_SYSTEM_DLL_INIT_BLOCK_V3_SIZE: u32 = 0x118;
const LOGICAL_PROCESSOR_RELATIONSHIP_GROUP: u32 = 4;
const PROCESS_BASIC_INFORMATION_CLASS: usize = 0;
const PROCESS_COOKIE_INFORMATION_CLASS: usize = 36;
const PROCESS_SCHEDULER_SHARED_DATA_CLASS: usize = 112;
const THREAD_SCHEDULER_SHARED_DATA_SLOT_CLASS: usize = 57;
const MEMORY_BASIC_INFORMATION_CLASS: usize = 0;
const MEMORY_WORKING_SET_EX_INFORMATION_CLASS: usize = 4;
const MEMORY_IMAGE_INFORMATION_CLASS: usize = 6;
const MEMORY_IMAGE_EXTENSION_INFORMATION_CLASS: usize = 0xe;
const FILE_FS_SIZE_INFORMATION_CLASS: usize = 3;
const FILE_FS_DEVICE_INFORMATION_CLASS: usize = 4;
const FILE_FS_ATTRIBUTE_INFORMATION_CLASS: usize = 5;
const WINDOWS_FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const WINDOWS_FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
const WINDOWS_FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
const WINDOWS_FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const WINDOWS_FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;
const WINDOWS_FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;
const WINDOWS_FILE_DEVICE_DISK: u32 = 0x0000_0007;
const MEM_EXTENDED_PARAMETER_TYPE_MASK: u64 = 0xff;
const MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS: u64 = 1;
const MEM_EXTENDED_PARAMETER_NUMA_NODE: u64 = 2;
const MEM_EXTENDED_PARAMETER_PARTITION_HANDLE: u64 = 3;
const MEM_EXTENDED_PARAMETER_USER_PHYSICAL_HANDLE: u64 = 4;
const MEM_EXTENDED_PARAMETER_ATTRIBUTE_FLAGS: u64 = 5;
const MEM_EXTENDED_PARAMETER_IMAGE_MACHINE: u64 = 6;
const MEM_EXTENDED_PARAMETER_MAX: u64 = 7;
const MEM_EXTENDED_PARAMETER_SUPPORTED_ATTRIBUTE_FLAGS: usize = 0x7f;
const WINDOWS_MEM_COMMIT_FLAG: usize = 0x1000;
const WINDOWS_MEM_RESERVE_FLAG: usize = 0x2000;
const WINDOWS_MEM_DECOMMIT_FLAG: usize = 0x4000;
const WINDOWS_MEM_RELEASE_FLAG: usize = 0x8000;
const WINDOWS_PAGE_PROTECTION_MASK: usize = 0xff;
const WINDOWS_PAGE_NOACCESS: u32 = 0x01;
const WINDOWS_PAGE_READONLY: u32 = 0x02;
const WINDOWS_PAGE_READWRITE: u32 = 0x04;
const WINDOWS_PAGE_WRITECOPY: u32 = 0x08;
const WINDOWS_PAGE_EXECUTE: u32 = 0x10;
const WINDOWS_PAGE_EXECUTE_READ: u32 = 0x20;
const WINDOWS_PAGE_EXECUTE_READWRITE: u32 = 0x40;
const WINDOWS_PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const WINDOWS_OLD_PROTECTION_FALLBACK: u32 = WINDOWS_PAGE_EXECUTE_READWRITE;
const WINDOWS_MEM_COMMIT: u32 = 0x1000;
const WINDOWS_MEM_FREE: u32 = 0x1_0000;
const WINDOWS_MEM_PRIVATE: u32 = 0x2_0000;
const WINDOWS_MEM_IMAGE: u32 = 0x100_0000;
const INITIAL_PROCESS_ID: usize = 1000;
const INITIAL_THREAD_ID: usize = 1000;
const RTL_USER_PROCESS_PARAMETERS_NORMALIZED: u32 = 1;
const PEB_LDR_IN_LOAD_ORDER_MODULE_LIST_OFFSET: usize = 0x10;
const PEB_LDR_IN_MEMORY_ORDER_MODULE_LIST_OFFSET: usize = 0x20;
const PEB_LDR_IN_INITIALIZATION_ORDER_MODULE_LIST_OFFSET: usize = 0x30;
const LDR_DATA_TABLE_ENTRY_IN_LOAD_ORDER_LINKS_OFFSET: usize = 0x00;
const LDR_DATA_TABLE_ENTRY_IN_MEMORY_ORDER_LINKS_OFFSET: usize = 0x10;
const LDR_DATA_TABLE_ENTRY_IN_INITIALIZATION_ORDER_LINKS_OFFSET: usize = 0x20;
const LDR_DATA_TABLE_ENTRY_SIZE: usize = 0x120;
const LDR_DDAG_NODE_SIZE: usize = 0x68;
const TEB_AFTER_WIN32_THREAD_INFO_OFFSET: usize = 0x80;
const TEB_TLS_SLOTS_OFFSET: usize = 0x1480;
const TEB_TLS_SLOT_COUNT: usize = 64;
const TEB_SCHEDULER_SHARED_DATA_SLOT_OFFSET: usize = 0x1850;
const TEB_SCHEDULER_SHARED_DATA_STORAGE_OFFSET: usize = 0x1860;
const TEB_PROCESSOR_FEATURES_BITMAP_OFFSET: usize = 0x1870;
const HOST_TEB_PEB_OFFSET: usize = 0x60;
const HOST_PEB_API_SET_MAP_OFFSET: usize = 0x68;
const SCHEDULER_SHARED_SLOT_ASSIGN: u32 = 0;
const SCHEDULER_SHARED_SLOT_FREE: u32 = 1;
const SCHEDULER_SHARED_SLOT_QUERY: u32 = 2;
const COMMON_PROCESSOR_FEATURE_BITS: u64 = 0x0003_8005_0001_3b2a;

static PERFORMANCE_COUNTER: AtomicI64 = AtomicI64::new(1_000_000);
static NEXT_SYNTHETIC_HANDLE: AtomicUsize = AtomicUsize::new(0x10000);
static NTDLL_HEAP_HANDLE: AtomicUsize = AtomicUsize::new(0);
static NTDLL_HEAP_BUMP: AtomicUsize = AtomicUsize::new(0);
static NTDLL_HEAP_LIMIT: AtomicUsize = AtomicUsize::new(0);
static NTDLL_HEAP_FREE_LIST: AtomicUsize = AtomicUsize::new(0);
static GUEST_NTDLL_BASE: AtomicUsize = AtomicUsize::new(0);
static GUEST_NTDLL_SIZE: AtomicUsize = AtomicUsize::new(0);
static GUEST_PEB_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static GUEST_API_SET_MAP: AtomicUsize = AtomicUsize::new(0);

const _: () =
    assert!(TEB_SCHEDULER_SHARED_DATA_SLOT_OFFSET + size_of::<usize>() <= INITIAL_TEB_SIZE);
const _: () =
    assert!(TEB_SCHEDULER_SHARED_DATA_STORAGE_OFFSET + size_of::<u64>() <= INITIAL_TEB_SIZE);
const _: () = assert!(
    TEB_PROCESSOR_FEATURES_BITMAP_OFFSET + size_of::<ProcessorFeatureBitmapWords>()
        <= INITIAL_TEB_SIZE
);

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct ListEntry {
    /// LIST_ENTRY.Flink.
    flink: usize,
    /// LIST_ENTRY.Blink.
    blink: usize,
}

impl ListEntry {
    const fn new_self(address: usize) -> Self {
        Self {
            flink: address,
            blink: address,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct UnicodeString {
    /// UNICODE_STRING.Length.
    length: u16,
    /// UNICODE_STRING.MaximumLength.
    maximum_length: u16,
    /// Explicit padding before the x64 pointer field.
    _padding0: u32,
    /// UNICODE_STRING.Buffer.
    buffer: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct ObjectAttributes {
    length: u32,
    _padding0: u32,
    root_directory: usize,
    object_name: usize,
    attributes: u32,
    _padding1: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct FileBasicInformation {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: u32,
    _padding0: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct FileFsSizeInformation {
    total_allocation_units: i64,
    available_allocation_units: i64,
    sectors_per_allocation_unit: u32,
    bytes_per_sector: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct FileFsDeviceInformation {
    device_type: u32,
    characteristics: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct FileFsAttributeInformation {
    file_system_attributes: u32,
    maximum_component_name_length: i32,
    file_system_name_length: u32,
    file_system_name: [u16; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct ApiSetNamespace {
    version: u32,
    size: u32,
    flags: u32,
    count: u32,
    entry_offset: u32,
    hash_offset: u32,
    hash_factor: u32,
}

impl ApiSetNamespace {
    fn empty() -> Self {
        let size = u32::try_from(size_of::<Self>()).expect("API set namespace fits in u32");
        Self {
            version: 6,
            size,
            entry_offset: size,
            hash_offset: size,
            hash_factor: 1,
            ..Self::default()
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct ApiSetNamespaceEntry {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    hashed_length: u32,
    value_offset: u32,
    value_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct ApiSetValueEntry {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    value_offset: u32,
    value_length: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct CurrentDirectory {
    /// CURDIR.DosPath.
    dos_path: UnicodeString,
    /// CURDIR.Handle.
    handle: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct PebLdrData {
    /// PEB_LDR_DATA.Length.
    length: u32,
    /// PEB_LDR_DATA.Initialized.
    initialized: u8,
    /// Explicit padding before pointer-sized fields.
    _padding0: [u8; 3],
    /// PEB_LDR_DATA.SsHandle.
    ss_handle: usize,
    /// PEB_LDR_DATA.InLoadOrderModuleList.
    in_load_order_module_list: ListEntry,
    /// PEB_LDR_DATA.InMemoryOrderModuleList.
    in_memory_order_module_list: ListEntry,
    /// PEB_LDR_DATA.InInitializationOrderModuleList.
    in_initialization_order_module_list: ListEntry,
    /// PEB_LDR_DATA.EntryInProgress.
    entry_in_progress: usize,
    /// PEB_LDR_DATA.ShutdownInProgress.
    shutdown_in_progress: u8,
    /// Explicit padding before pointer-sized fields.
    _padding1: [u8; 7],
    /// PEB_LDR_DATA.ShutdownThreadId.
    shutdown_thread_id: usize,
}

impl PebLdrData {
    fn new(address: usize, first_entry: Option<usize>, last_entry: Option<usize>) -> Self {
        let in_load_order_module_list = module_list_head(
            address + PEB_LDR_IN_LOAD_ORDER_MODULE_LIST_OFFSET,
            first_entry,
            last_entry,
            LDR_DATA_TABLE_ENTRY_IN_LOAD_ORDER_LINKS_OFFSET,
        );
        let in_memory_order_module_list = module_list_head(
            address + PEB_LDR_IN_MEMORY_ORDER_MODULE_LIST_OFFSET,
            first_entry,
            last_entry,
            LDR_DATA_TABLE_ENTRY_IN_MEMORY_ORDER_LINKS_OFFSET,
        );
        let in_initialization_order_module_list = module_list_head(
            address + PEB_LDR_IN_INITIALIZATION_ORDER_MODULE_LIST_OFFSET,
            first_entry,
            last_entry,
            LDR_DATA_TABLE_ENTRY_IN_INITIALIZATION_ORDER_LINKS_OFFSET,
        );
        Self {
            length: u32::try_from(size_of::<Self>()).expect("PEB_LDR_DATA prefix fits in u32"),
            in_load_order_module_list,
            in_memory_order_module_list,
            in_initialization_order_module_list,
            ..Default::default()
        }
    }
}

fn module_list_head(
    head: usize,
    first_entry: Option<usize>,
    last_entry: Option<usize>,
    link_offset: usize,
) -> ListEntry {
    match (first_entry, last_entry) {
        (Some(first_entry), Some(last_entry)) => ListEntry {
            flink: first_entry + link_offset,
            blink: last_entry + link_offset,
        },
        _ => ListEntry::new_self(head),
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: usize,
    entry_point: usize,
    size_of_image: u32,
    _padding0: u32,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    flags: u32,
    load_count: u16,
    tls_index: u16,
    hash_links: ListEntry,
    time_date_stamp: u32,
    _padding1: u32,
    entry_point_activation_context: usize,
    lock: usize,
    ddag_node: usize,
    node_module_link: ListEntry,
    load_context: usize,
    parent_dll_base: usize,
    switch_back_context: usize,
    base_address_index_node: RtlBalancedNode,
    mapping_info_index_node: RtlBalancedNode,
    original_base: usize,
    load_time: u64,
    base_name_hash_value: u32,
    load_reason: u32,
    implicit_path_options: u32,
    reference_count: u32,
    dependent_load_flags: u32,
    signing_level: u8,
    _padding2: [u8; 3],
}

const _: () = assert!(offset_of!(LdrDataTableEntry, dll_base) == 0x30);
const _: () = assert!(offset_of!(LdrDataTableEntry, full_dll_name) == 0x48);
const _: () = assert!(offset_of!(LdrDataTableEntry, base_dll_name) == 0x58);
const _: () = assert!(offset_of!(LdrDataTableEntry, ddag_node) == 0x98);
const _: () = assert!(offset_of!(LdrDataTableEntry, node_module_link) == 0xa0);
const _: () = assert!(size_of::<LdrDataTableEntry>() == LDR_DATA_TABLE_ENTRY_SIZE);

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct RtlBalancedNode {
    left: usize,
    right: usize,
    parent_value: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct LdrDdagNode {
    modules: ListEntry,
    service_tag_list: usize,
    load_count: u32,
    load_while_unloading_count: u32,
    lowest_link: usize,
    dependencies: usize,
    incoming_dependencies: ListEntry,
    state: i32,
    _padding0: u32,
    condense_link: ListEntry,
    predecessor: usize,
    incoming_service_tag: usize,
}

const _: () = assert!(offset_of!(LdrDdagNode, incoming_dependencies) == 0x30);
const _: () = assert!(size_of::<LdrDdagNode>() == LDR_DDAG_NODE_SIZE);

impl LdrDdagNode {
    fn new(address: usize, node_module_link: usize) -> Self {
        Self {
            modules: ListEntry {
                flink: node_module_link,
                blink: node_module_link,
            },
            load_count: 1,
            incoming_dependencies: ListEntry::new_self(address + 0x30),
            state: 4,
            condense_link: ListEntry::new_self(address + 0x48),
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy)]
struct LdrEntryAddresses {
    entry: usize,
    ddag_node: usize,
}

impl LdrDataTableEntry {
    fn new(
        previous_entry: Option<usize>,
        next_entry: Option<usize>,
        list_heads: LdrListHeads,
        mapping: &MappingInfo,
        addresses: LdrEntryAddresses,
        full_dll_name: UnicodeString,
        base_dll_name: UnicodeString,
    ) -> Self {
        Self {
            in_load_order_links: module_list_entry(
                previous_entry,
                next_entry,
                list_heads.load,
                LDR_DATA_TABLE_ENTRY_IN_LOAD_ORDER_LINKS_OFFSET,
            ),
            in_memory_order_links: module_list_entry(
                previous_entry,
                next_entry,
                list_heads.memory,
                LDR_DATA_TABLE_ENTRY_IN_MEMORY_ORDER_LINKS_OFFSET,
            ),
            in_initialization_order_links: module_list_entry(
                previous_entry,
                next_entry,
                list_heads.initialization,
                LDR_DATA_TABLE_ENTRY_IN_INITIALIZATION_ORDER_LINKS_OFFSET,
            ),
            dll_base: mapping.base_addr,
            entry_point: mapping.entry_point,
            size_of_image: u32::try_from(mapping.image_size).expect("image size fits u32"),
            full_dll_name,
            base_dll_name,
            flags: 0x22,
            load_count: 0xffff,
            hash_links: ListEntry::new_self(addresses.entry + 0x70),
            ddag_node: addresses.ddag_node,
            node_module_link: ListEntry {
                flink: addresses.ddag_node,
                blink: addresses.ddag_node,
            },
            original_base: mapping.base_addr,
            load_reason: 4,
            reference_count: 1,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy)]
struct LdrListHeads {
    load: usize,
    memory: usize,
    initialization: usize,
}

fn module_list_entry(
    previous_entry: Option<usize>,
    next_entry: Option<usize>,
    head: usize,
    link_offset: usize,
) -> ListEntry {
    ListEntry {
        flink: next_entry.map_or(head, |entry| entry + link_offset),
        blink: previous_entry.map_or(head, |entry| entry + link_offset),
    }
}

fn append_ldr_list_entry(
    head: usize,
    previous_entry: Option<usize>,
    entry: usize,
    link_offset: usize,
) -> Result<(), PeImageAccessError> {
    let entry_link = entry
        .checked_add(link_offset)
        .ok_or(PeImageAccessError::AddressOverflow)?;
    let mut head_link = read_value::<ListEntry>(head)?;
    head_link.blink = entry_link;
    if previous_entry.is_none() {
        head_link.flink = entry_link;
    }
    write_value(head, head_link)?;

    if let Some(previous_entry) = previous_entry {
        let previous_link_address = previous_entry
            .checked_add(link_offset)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let mut previous_link = read_value::<ListEntry>(previous_link_address)?;
        previous_link.flink = entry_link;
        write_value(previous_link_address, previous_link)?;
    }

    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct RtlUserProcessParameters {
    /// RTL_USER_PROCESS_PARAMETERS.MaximumLength.
    maximum_length: u32,
    /// RTL_USER_PROCESS_PARAMETERS.Length.
    length: u32,
    /// RTL_USER_PROCESS_PARAMETERS.Flags.
    flags: u32,
    /// RTL_USER_PROCESS_PARAMETERS.DebugFlags.
    debug_flags: u32,
    /// RTL_USER_PROCESS_PARAMETERS.ConsoleHandle.
    console_handle: usize,
    /// RTL_USER_PROCESS_PARAMETERS.ConsoleFlags.
    console_flags: u32,
    /// Explicit padding before pointer-sized fields.
    _padding0: u32,
    /// RTL_USER_PROCESS_PARAMETERS.StandardInput.
    standard_input: usize,
    /// RTL_USER_PROCESS_PARAMETERS.StandardOutput.
    standard_output: usize,
    /// RTL_USER_PROCESS_PARAMETERS.StandardError.
    standard_error: usize,
    /// RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.
    current_directory: CurrentDirectory,
    /// RTL_USER_PROCESS_PARAMETERS.DllPath.
    dll_path: UnicodeString,
    /// RTL_USER_PROCESS_PARAMETERS.ImagePathName.
    image_path_name: UnicodeString,
    /// RTL_USER_PROCESS_PARAMETERS.CommandLine.
    command_line: UnicodeString,
    /// RTL_USER_PROCESS_PARAMETERS.Environment.
    environment: usize,
}

impl RtlUserProcessParameters {
    fn new() -> Self {
        Self {
            maximum_length: u32::try_from(INITIAL_PROCESS_PARAMETERS_SIZE)
                .expect("process parameters page size fits in u32"),
            length: u32::try_from(size_of::<Self>())
                .expect("RTL_USER_PROCESS_PARAMETERS prefix fits in u32"),
            flags: RTL_USER_PROCESS_PARAMETERS_NORMALIZED,
            ..Default::default()
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
// Minimal PEB prefix used to bootstrap the first guest thread. This is not a
// complete Windows PEB definition and is subject to change as loader support grows.
struct ProcessEnvironmentBlock {
    /// PEB.InheritedAddressSpace.
    inherited_address_space: u8,
    /// PEB.ReadImageFileExecOptions.
    read_image_file_exec_options: u8,
    /// PEB.BeingDebugged.
    being_debugged: u8,
    /// PEB.BitField.
    bit_field: u8,
    /// Explicit padding before pointer-sized fields.
    _padding0: u32,
    /// PEB.Mutant.
    mutant: usize,
    /// PEB.ImageBaseAddress: base address of the initial executable image.
    image_base_address: usize,
    /// PEB.Ldr.
    loader_data: usize,
    /// PEB.ProcessParameters.
    process_parameters: usize,
    /// PEB.SubSystemData.
    sub_system_data: usize,
    /// PEB.ProcessHeap.
    process_heap: usize,
    /// PEB.FastPebLock.
    fast_peb_lock: usize,
    /// PEB.AtlThunkSListPtr.
    atl_thunk_s_list_ptr: usize,
    /// PEB.IFEOKey.
    ifeo_key: usize,
    /// PEB.CrossProcessFlags.
    cross_process_flags: u32,
    /// Explicit padding before pointer-sized fields.
    _padding1: u32,
    /// PEB.KernelCallbackTable / UserSharedInfoPtr.
    kernel_callback_table: usize,
    /// PEB.SystemReserved.
    system_reserved: u32,
    /// PEB.AtlThunkSListPtr32.
    atl_thunk_s_list_ptr32: u32,
    /// PEB.ApiSetMap.
    api_set_map: usize,
}

impl ProcessEnvironmentBlock {
    fn new(
        image_base_address: usize,
        loader_data: usize,
        process_parameters: usize,
        process_heap: usize,
        fast_peb_lock: usize,
        api_set_map: usize,
    ) -> Self {
        Self {
            image_base_address,
            loader_data,
            process_parameters,
            process_heap,
            fast_peb_lock,
            api_set_map,
            ..Default::default()
        }
    }
}

const _: () =
    assert!(offset_of!(ProcessEnvironmentBlock, api_set_map) == HOST_PEB_API_SET_MAP_OFFSET);

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct InitialNtTib {
    /// NT_TIB.ExceptionList.
    exception_list: usize,
    /// NT_TIB.StackBase: the high address of the initial thread stack.
    stack_base: usize,
    /// NT_TIB.StackLimit: the low address of the initial thread stack.
    stack_limit: usize,
    /// NT_TIB.SubSystemTib.
    sub_system_tib: usize,
    /// NT_TIB.FiberData / Version.
    fiber_data: usize,
    /// NT_TIB.ArbitraryUserPointer.
    arbitrary_user_pointer: usize,
    /// NT_TIB.Self: points back to this TEB.
    self_pointer: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct InitialClientId {
    /// CLIENT_ID.UniqueProcess: placeholder process identifier.
    unique_process: usize,
    /// CLIENT_ID.UniqueThread: placeholder thread identifier.
    unique_thread: usize,
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct InitialThreadContext {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
}

const _: () = assert!(offset_of!(InitialThreadContext, rax) == 0x78);
const _: () = assert!(offset_of!(InitialThreadContext, rip) == 0xf8);

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct PsSystemDllInitBlockV3 {
    size: u32,
    _padding0: u32,
    system_dll_wow_relocation: u64,
    system_dll_native_relocation: u64,
    wow64_shared_information: [u64; 16],
    rng_data: u32,
    flags: u32,
    mitigation_options_map: [u64; 3],
    cfg_bitmap: u64,
    cfg_bitmap_size: u64,
    wow64_cfg_bitmap: u64,
    wow64_cfg_bitmap_size: u64,
    mitigation_audit_options_map: usize,
    scp_cfg_check_function: u64,
    scp_cfg_check_es_function: u64,
    scp_cfg_dispatch_function: u64,
    scp_cfg_dispatch_es_function: u64,
    scp_arm64ec_call_check: u64,
    scp_arm64ec_cfg_check_function: u64,
    scp_arm64ec_cfg_check_es_function: u64,
}

impl PsSystemDllInitBlockV3 {
    fn new() -> Self {
        Self {
            size: PS_SYSTEM_DLL_INIT_BLOCK_V3_SIZE,
            ..Self::default()
        }
    }
}

const _: () = assert!(offset_of!(PsSystemDllInitBlockV3, system_dll_wow_relocation) == 0x8);
const _: () = assert!(offset_of!(PsSystemDllInitBlockV3, rng_data) == 0x98);
const _: () = assert!(offset_of!(PsSystemDllInitBlockV3, mitigation_options_map) == 0xa0);
const _: () =
    assert!(size_of::<PsSystemDllInitBlockV3>() == PS_SYSTEM_DLL_INIT_BLOCK_V3_SIZE as usize);

impl InitialThreadContext {
    fn new(entry_point: usize, stack_top: usize, image_base: usize) -> Self {
        Self {
            context_flags: WINDOWS_CONTEXT_CONTROL
                | WINDOWS_CONTEXT_INTEGER
                | WINDOWS_CONTEXT_SEGMENTS,
            mx_csr: WINDOWS_INITIAL_MXCSR,
            seg_cs: WINDOWS_INITIAL_CS,
            seg_ss: WINDOWS_INITIAL_SS,
            eflags: 0x202,
            rcx: u64::try_from(image_base).expect("image base fits in Windows context"),
            rsp: u64::try_from(stack_top).expect("stack top fits in Windows context"),
            rip: u64::try_from(entry_point).expect("entry point fits in Windows context"),
            ..Self::default()
        }
    }

    fn apply_to(self, ctx: &mut litebox_common_linux::PtRegs) {
        ctx.r15 = Self::usize_register(self.r15);
        ctx.r14 = Self::usize_register(self.r14);
        ctx.r13 = Self::usize_register(self.r13);
        ctx.r12 = Self::usize_register(self.r12);
        ctx.rbp = Self::usize_register(self.rbp);
        ctx.rbx = Self::usize_register(self.rbx);
        ctx.r11 = Self::usize_register(self.r11);
        ctx.r10 = Self::usize_register(self.r10);
        ctx.r9 = Self::usize_register(self.r9);
        ctx.r8 = Self::usize_register(self.r8);
        ctx.rax = Self::usize_register(self.rax);
        ctx.rcx = Self::usize_register(self.rcx);
        ctx.rdx = Self::usize_register(self.rdx);
        ctx.rsi = Self::usize_register(self.rsi);
        ctx.rdi = Self::usize_register(self.rdi);
        ctx.rip = Self::usize_register(self.rip);
        ctx.eflags = self.eflags as usize;
        ctx.rsp = Self::usize_register(self.rsp);
    }

    fn usize_register(value: u64) -> usize {
        usize::try_from(value).expect("Windows x64 context register fits usize")
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct MemoryBasicInformation {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    partition_id: u16,
    _padding0: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    type_: u32,
    _padding1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct MemoryImageInformation {
    image_base: usize,
    size_of_image: usize,
    image_flags: u32,
    _padding0: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct MemoryImageExtensionInformation {
    extension_type: u32,
    flags: u32,
    extension_image_base_rva: usize,
    extension_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct MemoryWorkingSetExInformation {
    virtual_address: usize,
    virtual_attributes: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct MemExtendedParameter {
    type_and_reserved: u64,
    value: usize,
}

impl MemExtendedParameter {
    fn type_(&self) -> u64 {
        self.type_and_reserved & MEM_EXTENDED_PARAMETER_TYPE_MASK
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct MemAddressRequirements {
    lowest_starting_address: usize,
    highest_ending_address: usize,
    alignment: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct SystemBasicInformation {
    reserved: u32,
    timer_resolution: u32,
    page_size: u32,
    number_of_physical_pages: u32,
    lowest_physical_page_number: u32,
    highest_physical_page_number: u32,
    allocation_granularity: u32,
    _padding0: u32,
    minimum_user_mode_address: usize,
    maximum_user_mode_address: usize,
    active_processors_affinity_mask: usize,
    number_of_processors: u8,
    _padding1: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct SystemFlushInformation {
    supported_flush_methods: u32,
    processor_cache_flush_size: u32,
    system_flush_capabilities: u64,
    reserved: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct RtlBitmapEx {
    size_of_bit_map: u64,
    buffer: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct ProcessorFeatureBitmapWords {
    bits0: u64,
    bits1: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct RtlFeatureConfiguration {
    feature_id: u32,
    flags: u32,
    variant_payload: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct SystemFeatureConfigurationInformation {
    change_stamp: u64,
    configuration: RtlFeatureConfiguration,
    _padding0: u32,
}

impl SystemFeatureConfigurationInformation {
    fn new(feature_id: u32) -> Self {
        Self {
            configuration: RtlFeatureConfiguration {
                feature_id,
                ..RtlFeatureConfiguration::default()
            },
            ..Self::default()
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct SystemFeatureConfigurationSectionsInformationEntry {
    change_stamp: u64,
    section_handle: usize,
    size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct SystemFeatureConfigurationSectionsInformation {
    overall_change_stamp: u64,
    descriptors: [SystemFeatureConfigurationSectionsInformationEntry; 4],
}

const _: () = assert!(size_of::<SystemFeatureConfigurationInformation>() == 0x18);
const _: () = assert!(size_of::<SystemFeatureConfigurationSectionsInformationEntry>() == 0x18);
const _: () = assert!(size_of::<SystemFeatureConfigurationSectionsInformation>() == 0x68);

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct GroupAffinity {
    mask: usize,
    group: u16,
    reserved: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes)]
struct SystemNumaInformation {
    highest_node_number: u32,
    reserved: u32,
    active_processors_group_affinity: [GroupAffinity; 64],
}

impl Default for SystemNumaInformation {
    fn default() -> Self {
        Self {
            highest_node_number: 0,
            reserved: 0,
            active_processors_group_affinity: [GroupAffinity::default(); 64],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct SystemHypervisorSharedPageInformation {
    hypervisor_shared_user_va: usize,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes)]
struct ProcessorGroupInfo {
    maximum_processor_count: u8,
    active_processor_count: u8,
    reserved: [u8; 38],
    active_processor_mask: usize,
}

impl Default for ProcessorGroupInfo {
    fn default() -> Self {
        Self {
            maximum_processor_count: 0,
            active_processor_count: 0,
            reserved: [0; 38],
            active_processor_mask: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct GroupRelationship {
    maximum_group_count: u16,
    active_group_count: u16,
    reserved: [u8; 20],
    group_info: ProcessorGroupInfo,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct SystemLogicalProcessorGroupInformation {
    relationship: u32,
    size: u32,
    group: GroupRelationship,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct ProcessBasicInformation {
    exit_status: usize,
    peb_base_address: usize,
    affinity_mask: usize,
    base_priority: usize,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
struct SchedulerSharedDataSlotInformation {
    action: u32,
    _padding0: u32,
    scheduler_shared_data_handle: usize,
    slot: usize,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes)]
// Minimal TEB prefix used to bootstrap the first guest thread. This is not a
// complete Windows TEB definition and is subject to change as loader support grows.
struct ThreadEnvironmentBlock {
    /// TEB.NtTib.
    nt_tib: InitialNtTib,
    /// TEB.EnvironmentPointer.
    environment_pointer: usize,
    /// TEB.ClientId.
    client_id: InitialClientId,
    /// TEB.ActiveRpcHandle.
    active_rpc_handle: usize,
    /// TEB.ThreadLocalStoragePointer.
    thread_local_storage_pointer: usize,
    /// TEB.ProcessEnvironmentBlock: points to the process PEB.
    process_environment_block: usize,
    /// TEB.LastErrorValue.
    last_error_value: u32,
    /// TEB.CountOfOwnedCriticalSections.
    count_of_owned_critical_sections: u32,
    /// TEB.CsrClientThread.
    csr_client_thread: usize,
    /// TEB.Win32ThreadInfo.
    win32_thread_info: usize,
    /// Reserved TEB fields before TEB.TlsSlots.
    _reserved_to_tls_slots: [u8; TEB_TLS_SLOTS_OFFSET - TEB_AFTER_WIN32_THREAD_INFO_OFFSET],
    /// TEB.TlsSlots.
    tls_slots: [usize; TEB_TLS_SLOT_COUNT],
}

const _: () = assert!(
    TEB_AFTER_WIN32_THREAD_INFO_OFFSET
        == offset_of!(ThreadEnvironmentBlock, _reserved_to_tls_slots)
);

impl Default for ThreadEnvironmentBlock {
    fn default() -> Self {
        Self {
            nt_tib: InitialNtTib::default(),
            environment_pointer: 0,
            client_id: InitialClientId::default(),
            active_rpc_handle: 0,
            thread_local_storage_pointer: 0,
            process_environment_block: 0,
            last_error_value: 0,
            count_of_owned_critical_sections: 0,
            csr_client_thread: 0,
            win32_thread_info: 0,
            _reserved_to_tls_slots: [0; TEB_TLS_SLOTS_OFFSET - TEB_AFTER_WIN32_THREAD_INFO_OFFSET],
            tls_slots: [0; TEB_TLS_SLOT_COUNT],
        }
    }
}

impl ThreadEnvironmentBlock {
    fn new(
        teb_address: usize,
        peb_address: usize,
        stack_base: usize,
        stack_top: usize,
        tls_slots_address: usize,
    ) -> Self {
        Self {
            nt_tib: InitialNtTib {
                stack_base: stack_top,
                stack_limit: stack_base,
                self_pointer: teb_address,
                ..Default::default()
            },
            client_id: InitialClientId {
                unique_process: INITIAL_PROCESS_ID,
                unique_thread: INITIAL_THREAD_ID,
            },
            thread_local_storage_pointer: tls_slots_address,
            process_environment_block: peb_address,
            ..Default::default()
        }
    }
}

type WindowsPageManager = PageManager<Platform, PAGE_SIZE>;

pub type DefaultFS = WindowsFS;

type WindowsFS = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

/// A trait required for file systems to be used by the Windows shim.
pub trait NtShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> NtShimFS for T {}

/// Builds a Windows NT shim instance.
pub struct WindowsShimBuilder {
    litebox: LiteBox<Platform>,
}

impl Default for WindowsShimBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsShimBuilder {
    /// Returns a new shim builder.
    #[must_use]
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            litebox: LiteBox::new(platform),
        }
    }

    /// Returns the LiteBox object for the shim.
    #[must_use]
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Create a default layered file system with the given in-memory and tar read-only layers.
    #[must_use]
    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
    ) -> DefaultFS {
        default_fs(&self.litebox, in_mem_fs, tar_ro_fs)
    }

    /// Build the shim.
    #[must_use]
    pub fn build<FS: NtShimFS>(self) -> WindowsShim<FS> {
        let page_manager = Arc::new(PageManager::new(&self.litebox));
        WindowsShim {
            litebox: Arc::new(self.litebox),
            page_manager,
            _fs: PhantomData,
        }
    }
}

/// A placeholder Windows shim.
pub struct WindowsShim<FS: NtShimFS> {
    litebox: Arc<LiteBox<Platform>>,
    page_manager: Arc<WindowsPageManager>,
    _fs: PhantomData<FS>,
}

impl<FS: NtShimFS> WindowsShim<FS> {
    /// Loads the program at `path` as the shim's initial task.
    ///
    /// TODO: Implement PE parsing/loading, PEB/TEB setup, initial handle table
    /// state, and register initialization.
    pub fn load_program(
        &self,
        fs: Arc<FS>,
        path: &str,
        _argv: Vec<alloc::ffi::CString>,
        _envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram<FS>, WindowsLoadError> {
        let image = self.load_image(fs.clone(), path)?;
        let application_entry_point = image.mapping.entry_point;
        let ntdll = self
            .load_ntdll(fs.clone())?
            .ok_or(WindowsLoadError::MissingNtDll)?;
        if !ntdll.has_trampoline {
            return Err(WindowsLoadError::UnrewrittenNtDll);
        }
        self.patch_ntdll_builtin_exports(&ntdll)?;
        let entry_point = ntdll
            .export_address(NTDLL_LOADER_ENTRYPOINT)?
            .ok_or(WindowsLoadError::MissingNtDllLoaderEntrypoint)?;
        litebox_util_log::debug!(
            entry_point:% = format_args!("{entry_point:#x}"),
            application_entry_point:% = format_args!("{application_entry_point:#x}");
            "Starting Windows guest through ntdll!LdrInitializeThunk"
        );

        let length =
            NonZeroPageSize::new(INITIAL_STACK_SIZE).ok_or(PeImageAccessError::AddressOverflow)?;
        let stack_base = unsafe {
            self.page_manager
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(PeImageAccessError::Mapping)?
        };
        let stack_top = stack_base
            .as_usize()
            .checked_add(INITIAL_STACK_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let process_environment = self.create_process_environment(
            &image.mapping,
            Some(&ntdll.mapping),
            stack_base.as_usize(),
            stack_top,
            path,
        )?;
        let application_stack_top = stack_top
            .checked_sub(0x28)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let initial_context = initial_context_address_on_stack(application_stack_top)?;
        write_value(
            initial_context,
            InitialThreadContext::new(
                application_entry_point,
                application_stack_top,
                image.mapping.base_addr,
            ),
        )?;
        let start_mode = WindowsStartMode {
            application_entry_point,
            image_base: image.mapping.base_addr,
            initial_context,
            system_dll_init_block: process_environment.system_dll_init_block,
        };
        let exit_code = Arc::new(AtomicI32::new(DEFAULT_PROCESS_EXIT_CODE));
        let diagnostic_regions = guest_address_regions(
            &image.mapping,
            Some(&ntdll.mapping),
            stack_base.as_usize(),
            stack_top,
            &process_environment,
        );
        let ntdll_mapping = ntdll.mapping;
        GUEST_NTDLL_BASE.store(ntdll_mapping.base_addr, Ordering::Relaxed);
        GUEST_NTDLL_SIZE.store(ntdll_mapping.image_size, Ordering::Relaxed);

        Ok(LoadedProgram {
            entrypoints: WindowsShimEntrypoints {
                entry_point,
                stack_top,
                teb_address: process_environment.teb,
                peb_address: process_environment.peb,
                start_mode,
                fs,
                application_base: image.mapping.base_addr,
                application_imports: image.imports.clone(),
                ldr_data_address: process_environment.ldr_data,
                ldr_tail_entry: litebox::sync::Mutex::new(process_environment.ldr_tail_entry),
                exit_code: exit_code.clone(),
                page_manager: self.page_manager.clone(),
                handles: litebox::sync::Mutex::new(Vec::new()),
                mapped_section_views: litebox::sync::Mutex::new(Vec::new()),
                loaded_modules: litebox::sync::Mutex::new(vec![LoadedModule {
                    path: String::from("/Windows/System32/ntdll.dll"),
                    base_addr: ntdll_mapping.base_addr,
                    image_size: ntdll_mapping.image_size,
                    exports: ntdll.exports,
                }]),
                api_set_hosts: litebox::sync::Mutex::new(Vec::new()),
                diagnostic_regions: litebox::sync::Mutex::new(diagnostic_regions),
            },
            process: WindowsShimProcess {
                mapping: image.mapping,
                _ntdll_mapping: Some(ntdll_mapping),
                exit_code,
            },
        })
    }

    fn load_ntdll(&self, fs: Arc<FS>) -> Result<Option<LoadedImage>, WindowsLoadError> {
        for path in NTDLL_PATHS {
            match self.load_image(fs.clone(), path) {
                Ok(image) => {
                    litebox_util_log::debug!(path:% = path; "Loaded guest ntdll.dll");
                    return Ok(Some(image));
                }
                Err(error) if is_missing_file_error(&error) => {}
                Err(error) => return Err(error),
            }
        }

        litebox_util_log::debug!("Guest ntdll.dll was not found in the initial filesystem");
        Ok(None)
    }

    fn load_image(&self, fs: Arc<FS>, path: &str) -> Result<LoadedImage, WindowsLoadError> {
        let file = PeImageFile::open(fs, path)?;
        let mut parsed = PeParsedFile::parse(&mut &file).map_err(WindowsLoadError::Parse)?;
        let imports = parsed.imports.clone();
        let exports = parsed.exports.clone();
        parsed
            .parse_trampoline(
                &mut &file,
                litebox_platform_multiplex::platform().get_syscall_entry_point(),
            )
            .map_err(WindowsLoadError::Parse)?;
        let has_trampoline = parsed.has_trampoline();
        let mut mapper = PeImageMapper {
            file: &file,
            page_manager: &self.page_manager,
        };
        let mut memory = PeImageMemory;
        let mapping = parsed
            .load(&mut mapper, &mut memory)
            .map_err(WindowsLoadError::Load)?;
        Ok(LoadedImage {
            mapping,
            imports,
            exports,
            has_trampoline,
        })
    }

    fn patch_ntdll_builtin_exports(&self, image: &LoadedImage) -> Result<(), WindowsLoadError> {
        let thunks: &[(&[u8], usize)] = &[
            (
                b"RtlAllocateHeap".as_slice(),
                litebox_ntdll_rtl_allocate_heap as *const () as usize,
            ),
            (
                b"RtlFreeHeap".as_slice(),
                litebox_ntdll_rtl_free_heap as *const () as usize,
            ),
            (
                b"RtlReAllocateHeap".as_slice(),
                litebox_ntdll_rtl_reallocate_heap as *const () as usize,
            ),
            (
                b"RtlSizeHeap".as_slice(),
                litebox_ntdll_rtl_size_heap as *const () as usize,
            ),
            (
                b"RtlCreateHeap".as_slice(),
                litebox_ntdll_rtl_create_heap as *const () as usize,
            ),
            (
                b"RtlDestroyHeap".as_slice(),
                litebox_ntdll_rtl_destroy_heap as *const () as usize,
            ),
        ];

        for &(name, target) in thunks {
            let Some(address) = image.export_address(name)? else {
                continue;
            };
            write_absolute_jump(&self.page_manager, address, target)?;
            litebox_util_log::debug!(
                name:% = String::from_utf8_lossy(name),
                address:% = format_args!("{address:#x}"),
                target:% = format_args!("{target:#x}");
                "Patched guest ntdll export to built-in thunk"
            );
        }

        let api_set_unicode_wrapper = image
            .mapping
            .base_addr
            .checked_add(NTDLL_API_SET_RESOLVE_UNICODE_WRAPPER_RVA)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        write_absolute_jump(
            &self.page_manager,
            api_set_unicode_wrapper,
            litebox_ntdll_api_set_resolve_unicode as *const () as usize,
        )?;
        litebox_util_log::debug!(
            address:% = format_args!("{api_set_unicode_wrapper:#x}");
            "Patched guest ntdll API-set Unicode wrapper to built-in guard"
        );

        for &branch_rva in NTDLL_APPHELP_FAILURE_BRANCH_RVAS {
            let branch_address = image
                .mapping
                .base_addr
                .checked_add(branch_rva)
                .ok_or(PeImageAccessError::AddressOverflow)?;
            write_code_bytes(&self.page_manager, branch_address, &[0x90; 6])?;
            litebox_util_log::debug!(
                address:% = format_args!("{branch_address:#x}");
                "Patched guest ntdll apphelp failure branch"
            );
        }

        let apphelp_status_test = image
            .mapping
            .base_addr
            .checked_add(NTDLL_APPHELP_STATUS_TEST_RVA)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        write_code_bytes(&self.page_manager, apphelp_status_test, &[0x31, 0xdb])?;
        litebox_util_log::debug!(
            address:% = format_args!("{apphelp_status_test:#x}");
            "Patched guest ntdll apphelp cached status check"
        );

        Ok(())
    }

    fn create_process_environment(
        &self,
        image: &MappingInfo,
        ntdll: Option<&MappingInfo>,
        stack_base: usize,
        stack_top: usize,
        image_path: &str,
    ) -> Result<WindowsProcessEnvironment, WindowsLoadError> {
        let peb_address = self.create_zeroed_pages(INITIAL_PEB_SIZE)?;
        let teb_address = self.create_zeroed_pages(INITIAL_TEB_SIZE)?;
        let ldr_data_address = self.create_zeroed_pages(INITIAL_LDR_DATA_SIZE)?;
        let ldr_entries_address = self.create_zeroed_pages(INITIAL_LDR_ENTRIES_SIZE)?;
        let process_parameters_address =
            self.create_zeroed_pages(INITIAL_PROCESS_PARAMETERS_SIZE)?;
        let process_heap_address = self.create_zeroed_pages(INITIAL_PROCESS_HEAP_SIZE)?;
        let process_heap_bump = process_heap_address
            .checked_add(PAGE_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let process_heap_limit = process_heap_address
            .checked_add(INITIAL_PROCESS_HEAP_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        NTDLL_HEAP_HANDLE.store(process_heap_address, Ordering::Relaxed);
        NTDLL_HEAP_BUMP.store(process_heap_bump, Ordering::Relaxed);
        NTDLL_HEAP_LIMIT.store(process_heap_limit, Ordering::Relaxed);
        NTDLL_HEAP_FREE_LIST.store(0, Ordering::Relaxed);
        let fast_peb_lock_address = self.create_zeroed_pages(INITIAL_FAST_PEB_LOCK_SIZE)?;
        let api_set_namespace_address = self.create_zeroed_pages(INITIAL_API_SET_NAMESPACE_SIZE)?;
        let initial_thread_context_address =
            self.create_zeroed_pages(INITIAL_THREAD_CONTEXT_SIZE)?;
        let system_dll_init_block_address =
            self.create_zeroed_pages(INITIAL_SYSTEM_DLL_INIT_BLOCK_SIZE)?;
        let tls_slots_address = teb_address
            .checked_add(TEB_TLS_SLOTS_OFFSET)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let scheduler_shared_data_slot_address = teb_address
            .checked_add(TEB_SCHEDULER_SHARED_DATA_STORAGE_OFFSET)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let processor_feature_bitmap_address = teb_address
            .checked_add(TEB_PROCESSOR_FEATURES_BITMAP_OFFSET)
            .ok_or(PeImageAccessError::AddressOverflow)?;

        let mut process_parameters = RtlUserProcessParameters::new();
        process_parameters.standard_input = host_standard_handle(WINDOWS_STD_INPUT_HANDLE);
        process_parameters.standard_output = host_standard_handle(WINDOWS_STD_OUTPUT_HANDLE);
        process_parameters.standard_error = host_standard_handle(WINDOWS_STD_ERROR_HANDLE);
        let mut process_parameters_string_cursor = process_parameters_address
            .checked_add(align_up(size_of::<RtlUserProcessParameters>(), 16)?)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let process_image_path = initial_dos_image_path(image_path);
        process_parameters.current_directory.dos_path = write_utf16_string(
            &mut process_parameters_string_cursor,
            INITIAL_CURRENT_DIRECTORY_PATH,
        )?;
        process_parameters.dll_path = write_utf16_string(
            &mut process_parameters_string_cursor,
            INITIAL_DLL_SEARCH_PATH,
        )?;
        process_parameters.image_path_name =
            write_utf16_string(&mut process_parameters_string_cursor, &process_image_path)?;
        process_parameters.command_line =
            write_utf16_string(&mut process_parameters_string_cursor, &process_image_path)?;

        let ldr_entries = Self::write_initial_ldr_entries(
            ldr_entries_address,
            ldr_data_address,
            image,
            ntdll,
            &process_image_path,
            &mut process_parameters_string_cursor,
        )?;
        write_value(
            ldr_data_address,
            PebLdrData::new(ldr_data_address, ldr_entries.first, ldr_entries.last),
        )?;
        write_initial_api_set_namespace(api_set_namespace_address)?;
        write_value(process_parameters_address, process_parameters)?;
        write_value(
            peb_address,
            ProcessEnvironmentBlock::new(
                image.base_addr,
                ldr_data_address,
                process_parameters_address,
                process_heap_address,
                fast_peb_lock_address,
                api_set_namespace_address,
            ),
        )?;
        write_value(
            teb_address,
            ThreadEnvironmentBlock::new(
                teb_address,
                peb_address,
                stack_base,
                stack_top,
                tls_slots_address,
            ),
        )?;
        write_value(
            teb_address
                .checked_add(TEB_SCHEDULER_SHARED_DATA_SLOT_OFFSET)
                .ok_or(PeImageAccessError::AddressOverflow)?,
            scheduler_shared_data_slot_address,
        )?;
        write_value(scheduler_shared_data_slot_address, 0u64)?;
        write_value(
            processor_feature_bitmap_address,
            Self::processor_feature_bitmap_words(),
        )?;
        write_value(system_dll_init_block_address, PsSystemDllInitBlockV3::new())?;
        GUEST_PEB_ADDRESS.store(peb_address, Ordering::Relaxed);
        GUEST_API_SET_MAP.store(api_set_namespace_address, Ordering::Relaxed);

        litebox_util_log::debug!(
            peb:% = format_args!("{peb_address:#x}"),
            teb:% = format_args!("{teb_address:#x}"),
            ldr:% = format_args!("{ldr_data_address:#x}"),
            ldr_entries:% = format_args!("{ldr_entries_address:#x}"),
            process_parameters:% = format_args!("{process_parameters_address:#x}"),
            process_heap:% = format_args!("{process_heap_address:#x}"),
            api_set_namespace:% = format_args!("{api_set_namespace_address:#x}"),
            initial_thread_context:% = format_args!("{initial_thread_context_address:#x}"),
            system_dll_init_block:% = format_args!("{system_dll_init_block_address:#x}"),
            tls_slots:% = format_args!("{tls_slots_address:#x}"),
            scheduler_shared_data_slot:% = format_args!("{scheduler_shared_data_slot_address:#x}"),
            processor_feature_bitmap:% = format_args!("{processor_feature_bitmap_address:#x}"),
            image_base:% = format_args!("{:#x}", image.base_addr);
            "Created initial Windows PEB/TEB"
        );

        Ok(WindowsProcessEnvironment {
            peb: peb_address,
            ldr_data: ldr_data_address,
            ldr_entries: ldr_entries_address,
            ldr_tail_entry: ldr_entries.last,
            process_parameters: process_parameters_address,
            process_heap: process_heap_address,
            fast_peb_lock: fast_peb_lock_address,
            api_set_namespace: api_set_namespace_address,
            initial_thread_context: initial_thread_context_address,
            system_dll_init_block: system_dll_init_block_address,
            teb: teb_address,
        })
    }

    fn write_initial_ldr_entries(
        entries_address: usize,
        ldr_data_address: usize,
        image: &MappingInfo,
        ntdll: Option<&MappingInfo>,
        process_image_path: &str,
        string_cursor: &mut usize,
    ) -> Result<InitialLdrEntries, PeImageAccessError> {
        let app_entry_address = entries_address;
        let ntdll_entry_address = entries_address
            .checked_add(LDR_DATA_TABLE_ENTRY_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let app_ddag_node_address = entries_address
            .checked_add(LDR_DATA_TABLE_ENTRY_SIZE * 2)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let ntdll_ddag_node_address = app_ddag_node_address
            .checked_add(LDR_DDAG_NODE_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let last_entry = if ntdll.is_some() {
            ntdll_entry_address
        } else {
            app_entry_address
        };
        let list_heads = LdrListHeads {
            load: ldr_data_address + PEB_LDR_IN_LOAD_ORDER_MODULE_LIST_OFFSET,
            memory: ldr_data_address + PEB_LDR_IN_MEMORY_ORDER_MODULE_LIST_OFFSET,
            initialization: ldr_data_address + PEB_LDR_IN_INITIALIZATION_ORDER_MODULE_LIST_OFFSET,
        };
        let app_entry = LdrDataTableEntry::new(
            None,
            ntdll.map(|_| ntdll_entry_address),
            list_heads,
            image,
            LdrEntryAddresses {
                entry: app_entry_address,
                ddag_node: app_ddag_node_address,
            },
            write_utf16_string(string_cursor, process_image_path)?,
            write_utf16_string(string_cursor, initial_image_base_name(process_image_path))?,
        );
        write_value(app_entry_address, app_entry)?;
        write_value(
            app_ddag_node_address,
            LdrDdagNode::new(app_ddag_node_address, app_entry_address + 0xa0),
        )?;

        if let Some(ntdll) = ntdll {
            let ntdll_entry = LdrDataTableEntry::new(
                Some(app_entry_address),
                None,
                list_heads,
                ntdll,
                LdrEntryAddresses {
                    entry: ntdll_entry_address,
                    ddag_node: ntdll_ddag_node_address,
                },
                write_utf16_string(string_cursor, "C:\\Windows\\System32\\ntdll.dll")?,
                write_utf16_string(string_cursor, "ntdll.dll")?,
            );
            write_value(ntdll_entry_address, ntdll_entry)?;
            write_value(
                ntdll_ddag_node_address,
                LdrDdagNode::new(ntdll_ddag_node_address, ntdll_entry_address + 0xa0),
            )?;
        }

        Ok(InitialLdrEntries {
            first: Some(app_entry_address),
            last: Some(last_entry),
        })
    }

    fn create_zeroed_pages(&self, size: usize) -> Result<usize, WindowsLoadError> {
        let length = NonZeroPageSize::new(size).ok_or(PeImageAccessError::AddressOverflow)?;
        // SAFETY: These pages are private shim-created process metadata initialized before guest execution.
        let ptr = unsafe {
            self.page_manager
                .create_writable_pages(None, length, CreatePagesFlags::empty(), |_| Ok(0))
        }
        .map_err(PeImageAccessError::Mapping)?;
        ptr.copy_from_slice(0, &vec![0; size])
            .ok_or(PeImageAccessError::MemoryAccess)?;
        Ok(ptr.as_usize())
    }

    fn processor_feature_bitmap_words() -> ProcessorFeatureBitmapWords {
        ProcessorFeatureBitmapWords {
            bits0: COMMON_PROCESSOR_FEATURE_BITS,
            bits1: 0,
        }
    }

    /// Returns the LiteBox object for the shim.
    #[must_use]
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }
}

/// The shim entrypoint object passed to the platform.
pub struct WindowsShimEntrypoints<FS: NtShimFS> {
    entry_point: usize,
    stack_top: usize,
    teb_address: usize,
    peb_address: usize,
    start_mode: WindowsStartMode,
    fs: Arc<FS>,
    application_base: usize,
    application_imports: Vec<PeImport>,
    ldr_data_address: usize,
    ldr_tail_entry: litebox::sync::Mutex<Platform, Option<usize>>,
    exit_code: Arc<AtomicI32>,
    page_manager: Arc<WindowsPageManager>,
    handles: litebox::sync::Mutex<Platform, Vec<WindowsHandle>>,
    mapped_section_views: litebox::sync::Mutex<Platform, Vec<MappedSectionView>>,
    loaded_modules: litebox::sync::Mutex<Platform, Vec<LoadedModule>>,
    api_set_hosts: litebox::sync::Mutex<Platform, Vec<ApiSetHostCacheEntry>>,
    diagnostic_regions: litebox::sync::Mutex<Platform, Vec<GuestAddressRegion>>,
}

struct LoadedModule {
    path: String,
    base_addr: usize,
    image_size: usize,
    exports: Vec<PeExport>,
}

#[derive(Default)]
struct ImportResolutionStats {
    resolved: usize,
    unresolved: usize,
    write_failed: usize,
    unresolved_samples: Vec<String>,
}

struct ApiSetHostCacheEntry {
    api_set_name: String,
    host_dll: String,
}

struct WindowsHandle {
    handle: usize,
    kind: WindowsHandleKind,
}

enum WindowsHandleKind {
    File { path: String },
    Section { path: Option<String> },
}

struct MappedSectionView {
    base_addr: usize,
    size: usize,
    path: Option<String>,
    region_name: &'static str,
}

impl MappedSectionView {
    fn contains(&self, address: usize) -> bool {
        self.base_addr
            .checked_add(self.size)
            .is_some_and(|end| (self.base_addr..end).contains(&address))
    }
}

#[derive(Clone, Copy)]
struct GuestAddressRegion {
    name: &'static str,
    start: usize,
    end: usize,
}

impl GuestAddressRegion {
    fn new(name: &'static str, start: usize, size: usize) -> Option<Self> {
        let end = start.checked_add(size)?;
        (start < end).then_some(Self { name, start, end })
    }

    fn contains(&self, address: usize) -> bool {
        (self.start..self.end).contains(&address)
    }

    fn is_image(&self) -> bool {
        matches!(
            self.name,
            "app" | "ntdll" | "kernel32" | "kernelbase" | "dll"
        )
    }
}

fn guest_address_regions(
    image: &MappingInfo,
    ntdll: Option<&MappingInfo>,
    stack_base: usize,
    stack_top: usize,
    process_environment: &WindowsProcessEnvironment,
) -> Vec<GuestAddressRegion> {
    let mut regions = Vec::new();
    push_region(&mut regions, "app", image.base_addr, image.image_size);
    if let Some(ntdll) = ntdll {
        push_region(&mut regions, "ntdll", ntdll.base_addr, ntdll.image_size);
    }
    push_region(
        &mut regions,
        "stack",
        stack_base,
        stack_top.saturating_sub(stack_base),
    );
    push_region(
        &mut regions,
        "peb",
        process_environment.peb,
        INITIAL_PEB_SIZE,
    );
    push_region(
        &mut regions,
        "teb",
        process_environment.teb,
        INITIAL_TEB_SIZE,
    );
    push_region(
        &mut regions,
        "ldr-data",
        process_environment.ldr_data,
        INITIAL_LDR_DATA_SIZE,
    );
    push_region(
        &mut regions,
        "ldr-entries",
        process_environment.ldr_entries,
        INITIAL_LDR_ENTRIES_SIZE,
    );
    push_region(
        &mut regions,
        "process-parameters",
        process_environment.process_parameters,
        INITIAL_PROCESS_PARAMETERS_SIZE,
    );
    push_region(
        &mut regions,
        "process-heap",
        process_environment.process_heap,
        INITIAL_PROCESS_HEAP_SIZE,
    );
    push_region(
        &mut regions,
        "fast-peb-lock",
        process_environment.fast_peb_lock,
        INITIAL_FAST_PEB_LOCK_SIZE,
    );
    push_region(
        &mut regions,
        "api-set",
        process_environment.api_set_namespace,
        INITIAL_API_SET_NAMESPACE_SIZE,
    );
    push_region(
        &mut regions,
        "thread-context",
        process_environment.initial_thread_context,
        INITIAL_THREAD_CONTEXT_SIZE,
    );
    push_region(
        &mut regions,
        "system-dll-init-block",
        process_environment.system_dll_init_block,
        INITIAL_SYSTEM_DLL_INIT_BLOCK_SIZE,
    );
    regions
}

fn push_region(
    regions: &mut Vec<GuestAddressRegion>,
    name: &'static str,
    start: usize,
    size: usize,
) {
    if let Some(region) = GuestAddressRegion::new(name, start, size) {
        regions.push(region);
    }
}

fn windows_object_path_to_guest_path(path: &str) -> String {
    let without_prefix = path
        .strip_prefix("\\??\\")
        .or_else(|| path.strip_prefix("\\DosDevices\\"))
        .unwrap_or(path);
    let lower_without_prefix = without_prefix.to_ascii_lowercase();
    let without_drive = if let Some(drive_index) = lower_without_prefix.rfind("c:\\") {
        &without_prefix[drive_index + 3..]
    } else {
        without_prefix
    };
    let mut guest_path = String::from("/");
    let mut first = true;
    for component in without_drive
        .split(['\\', '/'])
        .filter(|component| !component.is_empty())
    {
        if !first {
            guest_path.push('/');
        }
        first = false;
        if component.eq_ignore_ascii_case("windows") {
            guest_path.push_str("Windows");
        } else if component.eq_ignore_ascii_case("system32") {
            guest_path.push_str("System32");
        } else if component
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("dll"))
        {
            guest_path.push_str(&component.to_ascii_lowercase());
        } else {
            guest_path.push_str(component);
        }
    }
    guest_path
}

fn guest_path_to_dos_path(path: &str) -> String {
    let mut dos_path = String::from("C:");
    for component in path
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
    {
        dos_path.push('\\');
        dos_path.push_str(component);
    }
    dos_path
}

fn is_ntdll_guest_path(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .unwrap_or(path)
        .eq_ignore_ascii_case("ntdll.dll")
}

fn module_basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn import_library_name(library: &[u8]) -> &str {
    core::str::from_utf8(library).unwrap_or("")
}

fn import_library_is_kernel32(library: &[u8]) -> bool {
    module_name_matches("kernel32.dll", import_library_name(library))
}

fn import_library_is_api_set(library: &[u8]) -> bool {
    let name = module_basename(import_library_name(library));
    name.starts_with("api-ms-") || name.starts_with("ext-ms-")
}

fn well_known_api_set_host_dll(normalized_name: &str) -> Option<&'static str> {
    if normalized_name.starts_with("api-ms-win-core-apiquery-")
        || normalized_name.starts_with("api-ms-win-core-rtlsupport-")
    {
        Some("ntdll.dll")
    } else {
        None
    }
}

fn api_set_host_dll_or_default(api_set_map: usize, api_set_name: &str) -> Option<String> {
    let normalized_name = normalize_api_set_name(api_set_name);
    if !(normalized_name.starts_with("api-ms-") || normalized_name.starts_with("ext-ms-")) {
        return None;
    }
    resolve_api_set_host_dll(api_set_map, api_set_name)
        .or_else(|| well_known_api_set_host_dll(&normalized_name).map(String::from))
        .or_else(|| Some(String::from("kernelbase.dll")))
}

fn module_matches_import(module: &LoadedModule, library: &[u8]) -> bool {
    let module_name = module_basename(&module.path);
    let library_name = module_basename(import_library_name(library));
    module_name_matches(module_name, library_name)
}

fn module_name_matches(module_name: &str, library_name: &str) -> bool {
    if module_name.eq_ignore_ascii_case(library_name) {
        return true;
    }
    if library_name
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("dll"))
    {
        return false;
    }
    module_name
        .rsplit_once('.')
        .filter(|(_, extension)| extension.eq_ignore_ascii_case("dll"))
        .map_or(module_name, |(stem, _)| stem)
        .eq_ignore_ascii_case(library_name)
}

fn import_name(import: &PeImport) -> alloc::borrow::Cow<'_, str> {
    match &import.target {
        PeImportTarget::Ordinal(ordinal) => alloc::borrow::Cow::Owned(format!("#{ordinal}")),
        PeImportTarget::Name { name, .. } => String::from_utf8_lossy(name),
    }
}

fn resolve_api_set_host_dll(api_set_map: usize, api_set_name: &str) -> Option<String> {
    if api_set_map == 0 {
        return None;
    }

    let namespace = read_value::<ApiSetNamespace>(api_set_map).ok()?;
    let count = usize::try_from(namespace.count).ok()?;
    let entry_offset = usize::try_from(namespace.entry_offset).ok()?;
    let normalized_name = normalize_api_set_name(api_set_name);

    for index in 0..count {
        let entry_address = api_set_map
            .checked_add(entry_offset)?
            .checked_add(index.checked_mul(size_of::<ApiSetNamespaceEntry>())?)?;
        let entry = read_value::<ApiSetNamespaceEntry>(entry_address).ok()?;
        let namespace_name = read_api_set_string(
            api_set_map,
            entry.name_offset,
            entry.hashed_length.max(entry.name_length),
        )?;
        if !normalize_api_set_name(&namespace_name).eq_ignore_ascii_case(&normalized_name) {
            continue;
        }

        let value_count = usize::try_from(entry.value_count).ok()?;
        let value_offset = usize::try_from(entry.value_offset).ok()?;
        for value_index in 0..value_count {
            let value_address = api_set_map
                .checked_add(value_offset)?
                .checked_add(value_index.checked_mul(size_of::<ApiSetValueEntry>())?)?;
            let value = read_value::<ApiSetValueEntry>(value_address).ok()?;
            if value.value_length == 0 {
                continue;
            }
            let host_dll =
                read_api_set_string(api_set_map, value.value_offset, value.value_length)?;
            litebox_util_log::trace!(
                api_set_name:% = api_set_name,
                namespace_name:% = namespace_name,
                host_dll:% = host_dll;
                "Resolved API-set namespace entry"
            );
            return Some(host_dll);
        }
    }

    None
}

fn normalize_api_set_name(name: &str) -> String {
    let basename = module_basename(name);
    basename
        .strip_suffix(".dll")
        .or_else(|| basename.strip_suffix(".DLL"))
        .unwrap_or(basename)
        .to_ascii_lowercase()
}

fn read_api_set_string(api_set_map: usize, offset: u32, byte_length: u32) -> Option<String> {
    let address = api_set_map.checked_add(usize::try_from(offset).ok()?)?;
    read_utf16_string(address, u16::try_from(byte_length).ok()?).ok()
}

fn import_library_guest_path(library: &[u8]) -> Option<String> {
    let library_name = module_basename(import_library_name(library));
    if library_name.is_empty() {
        return None;
    }

    let dll_name = if import_library_is_api_set(library) {
        module_basename(
            &api_set_host_dll_or_default(GUEST_API_SET_MAP.load(Ordering::Relaxed), library_name)
                .unwrap_or_else(|| String::from("kernelbase.dll")),
        )
        .to_ascii_lowercase()
    } else if library_name
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("dll"))
    {
        library_name.to_ascii_lowercase()
    } else {
        format!("{}.dll", library_name.to_ascii_lowercase())
    };

    Some(format!("/Windows/System32/{dll_name}"))
}

fn host_standard_handle(kind: u32) -> usize {
    // SAFETY: The shim process hosts the current userland prototype, so its
    // standard handles are the backing console handles for guest process params.
    unsafe { host_get_std_handle(kind) as usize }
}

fn loaded_image_region_name(path: &str) -> &'static str {
    match path
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
        .as_str()
    {
        "kernel32.dll" => "kernel32",
        "kernelbase.dll" => "kernelbase",
        _ => "dll",
    }
}

#[derive(Clone, Copy)]
struct WindowsStartMode {
    application_entry_point: usize,
    image_base: usize,
    initial_context: usize,
    system_dll_init_block: usize,
}

impl<FS: NtShimFS> EnterShim for WindowsShimEntrypoints<FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        if !set_guest_teb(self.teb_address) {
            return ContinueOperation::Terminate;
        }
        ctx.rip = self.entry_point;
        ctx.rsp = self.stack_top - size_of::<usize>();
        ctx.eflags = 0x202;
        ctx.rcx = self.start_mode.initial_context;
        ctx.rsp = self
            .start_mode
            .initial_context
            .saturating_sub(size_of::<usize>());
        ctx.rdx = self.start_mode.image_base;
        ctx.r8 = 0;
        ctx.r9 = 0;
        litebox_util_log::debug!(
            application_entry_point:% = format_args!("{:#x}", self.start_mode.application_entry_point),
            image_base:% = format_args!("{:#x}", self.start_mode.image_base),
            initial_context:% = format_args!("{:#x}", self.start_mode.initial_context),
            loader_parameter:% = format_args!("{:#x}", ctx.rdx),
            system_dll_init_block:% = format_args!("{:#x}", self.start_mode.system_dll_init_block),
            loader_stack:% = format_args!("{:#x}", ctx.rsp);
            "Prepared initial ntdll loader arguments"
        );
        litebox_util_log::debug!(
            entry_point:% = format_args!("{:#x}", self.entry_point),
            stack_top:% = format_args!("{:#x}", self.stack_top),
            teb:% = format_args!("{:#x}", self.teb_address);
            "Starting initial Windows guest thread"
        );
        ContinueOperation::Resume
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        match NtSysno::from_raw(ctx.orig_rax) {
            Some(NtSysno::NtTerminateProcess) => {
                litebox_util_log::debug!(
                    syscall_number = ctx.orig_rax,
                    process_handle:% = format_args!("{:#x}", ctx.r10),
                    exit_status:% = format_args!("{:#x}", ctx.rdx);
                    "Handling NtTerminateProcess syscall"
                );
                self.exit_code
                    .store(windows_exit_status_to_i32(ctx.rdx), Ordering::Relaxed);
                ContinueOperation::Terminate
            }
            Some(NtSysno::NtQueryPerformanceCounter) => {
                self.nt_query_performance_counter(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtProtectVirtualMemory) => {
                self.nt_protect_virtual_memory(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtAllocateVirtualMemory) => {
                self.nt_allocate_virtual_memory(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtAllocateVirtualMemoryEx) => {
                self.nt_allocate_virtual_memory_ex(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtFreeVirtualMemory) => {
                self.nt_free_virtual_memory(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtContinue) => {
                self.nt_continue(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtTestAlert) => {
                litebox_util_log::debug!("Handling NtTestAlert as no-op");
                ctx.rax = STATUS_SUCCESS;
                ContinueOperation::Resume
            }
            Some(NtSysno::NtQueryVirtualMemory) => {
                self.nt_query_virtual_memory(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtClose) => {
                self.nt_close(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtWriteFile) => {
                Self::nt_write_file(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtOpenFile) => {
                self.nt_open_file(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtQueryAttributesFile) => {
                Self::nt_query_attributes_file(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtQueryVolumeInformationFile) => {
                Self::nt_query_volume_information_file(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtGetCachedSigningLevel) => {
                Self::nt_get_cached_signing_level(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtCompareSigningLevels) => {
                litebox_util_log::debug!(
                    first_signing_level:% = format_args!("{:#x}", ctx.r10),
                    second_signing_level:% = format_args!("{:#x}", ctx.rdx);
                    "Handling NtCompareSigningLevels as compatible"
                );
                ctx.rax = STATUS_SUCCESS;
                ContinueOperation::Resume
            }
            Some(NtSysno::NtCreateSection) => {
                self.nt_create_section(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtOpenSection) => {
                self.nt_open_section(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtApphelpCacheControl) => {
                litebox_util_log::debug!(
                    service_class:% = format_args!("{:#x}", ctx.r10),
                    service_data:% = format_args!("{:#x}", ctx.rdx);
                    "Handling NtApphelpCacheControl as no-op"
                );
                ctx.rax = STATUS_SUCCESS;
                ContinueOperation::Resume
            }
            Some(NtSysno::NtMapViewOfSection) => {
                self.nt_map_view_of_section(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtAreMappedFilesTheSame) => {
                self.nt_are_mapped_files_the_same(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtUnmapViewOfSection) => {
                self.nt_unmap_view_of_section(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtCreateEvent) => {
                Self::nt_create_event(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtCreateIoCompletion) => {
                Self::nt_create_io_completion(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtCreateWorkerFactory) => {
                Self::nt_create_worker_factory(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtCreateTimer2) => {
                Self::nt_create_timer2(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtCreateWaitCompletionPacket) => {
                Self::nt_create_wait_completion_packet(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtAssociateWaitCompletionPacket) => {
                Self::nt_associate_wait_completion_packet(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtSetInformationWorkerFactory) => {
                Self::nt_set_information_worker_factory(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtSetWnfProcessNotificationEvent) => {
                Self::nt_set_wnf_process_notification_event(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtSubscribeWnfStateChange) => {
                Self::nt_subscribe_wnf_state_change(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtTraceControl) => {
                Self::nt_trace_control(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtManageHotPatch) => {
                litebox_util_log::debug!(
                    request:% = format_args!("{:#x}", ctx.r10),
                    flags:% = format_args!("{:#x}", ctx.rdx);
                    "Handling NtManageHotPatch as unsupported"
                );
                ctx.rax = STATUS_NOT_SUPPORTED;
                ContinueOperation::Resume
            }
            Some(NtSysno::NtSetEvent) => {
                Self::nt_set_event(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtQuerySystemInformation) => {
                self.nt_query_system_information(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtQuerySystemInformationEx) => {
                self.nt_query_system_information_ex(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtQueryDebugFilterState) => {
                litebox_util_log::debug!(
                    component_id:% = format_args!("{:#x}", ctx.r10),
                    level:% = format_args!("{:#x}", ctx.rdx);
                    "Handling NtQueryDebugFilterState as debugger inactive"
                );
                ctx.rax = STATUS_DEBUGGER_INACTIVE;
                ContinueOperation::Resume
            }
            Some(NtSysno::NtQueryInformationProcess) => {
                self.nt_query_information_process(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtSetInformationProcess) => {
                self.nt_set_information_process(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtSetInformationThread) => {
                self.nt_set_information_thread(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtOpenKey) => {
                litebox_util_log::debug!(
                    key_handle_ptr:% = format_args!("{:#x}", ctx.r10),
                    desired_access:% = format_args!("{:#x}", ctx.rdx),
                    object_attributes:% = format_args!("{:#x}", ctx.r8);
                    "Handling NtOpenKey as missing registry key"
                );
                ctx.rax = STATUS_OBJECT_NAME_NOT_FOUND;
                ContinueOperation::Resume
            }
            Some(NtSysno::NtOpenThreadToken) => {
                litebox_util_log::debug!(
                    thread_handle:% = format_args!("{:#x}", ctx.r10),
                    desired_access:% = format_args!("{:#x}", ctx.rdx),
                    open_as_self:% = format_args!("{:#x}", ctx.r8),
                    token_handle_ptr:% = format_args!("{:#x}", ctx.r9);
                    "Handling NtOpenThreadToken as no impersonation token"
                );
                ctx.rax = STATUS_NO_TOKEN;
                ContinueOperation::Resume
            }
            Some(NtSysno::NtOpenDirectoryObject) => {
                let handle = NEXT_SYNTHETIC_HANDLE.fetch_add(4, Ordering::Relaxed);
                if ctx.r10 == 0 || write_value(ctx.r10, handle).is_err() {
                    ctx.rax = STATUS_ACCESS_VIOLATION;
                    return ContinueOperation::Resume;
                }

                litebox_util_log::debug!(
                    directory_handle_ptr:% = format_args!("{:#x}", ctx.r10),
                    handle:% = format_args!("{handle:#x}"),
                    desired_access:% = format_args!("{:#x}", ctx.rdx),
                    object_attributes:% = format_args!("{:#x}", ctx.r8);
                    "Handling NtOpenDirectoryObject syscall"
                );
                ctx.rax = STATUS_SUCCESS;
                ContinueOperation::Resume
            }
            Some(NtSysno::NtOpenSymbolicLinkObject) => {
                let handle = NEXT_SYNTHETIC_HANDLE.fetch_add(4, Ordering::Relaxed);
                if ctx.r10 == 0 || write_value(ctx.r10, handle).is_err() {
                    ctx.rax = STATUS_ACCESS_VIOLATION;
                    return ContinueOperation::Resume;
                }

                litebox_util_log::debug!(
                    link_handle_ptr:% = format_args!("{:#x}", ctx.r10),
                    handle:% = format_args!("{handle:#x}"),
                    desired_access:% = format_args!("{:#x}", ctx.rdx),
                    object_attributes:% = format_args!("{:#x}", ctx.r8);
                    "Handling NtOpenSymbolicLinkObject syscall"
                );
                ctx.rax = STATUS_SUCCESS;
                ContinueOperation::Resume
            }
            Some(NtSysno::NtQuerySymbolicLinkObject) => {
                Self::nt_query_symbolic_link_object(ctx);
                ContinueOperation::Resume
            }
            Some(NtSysno::NtTraceEvent) => {
                let trace_field0 = read_usize_or_zero(ctx.r9);
                let trace_field1 = read_usize_or_zero(ctx.r9.saturating_add(size_of::<usize>()));
                let trace_field2 =
                    read_usize_or_zero(ctx.r9.saturating_add(size_of::<usize>().saturating_mul(2)));
                let trace_field3 =
                    read_usize_or_zero(ctx.r9.saturating_add(size_of::<usize>().saturating_mul(3)));
                litebox_util_log::debug!(
                    trace_handle:% = format_args!("{:#x}", ctx.r10),
                    flags:% = format_args!("{:#x}", ctx.rdx),
                    field_size:% = format_args!("{:#x}", ctx.r8),
                    fields:% = format_args!("{:#x}", ctx.r9),
                    field0:% = format_args!("{trace_field0:#x}"),
                    field1:% = format_args!("{trace_field1:#x}"),
                    field2:% = format_args!("{trace_field2:#x}"),
                    field3:% = format_args!("{trace_field3:#x}");
                    "Handling NtTraceEvent as no-op"
                );
                ctx.rax = STATUS_SUCCESS;
                ContinueOperation::Resume
            }
            Some(NtSysno::NtRaiseHardError) => {
                let valid_response_options =
                    read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));
                let response =
                    read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_6_OFFSET));
                let guest_return_address = read_usize_or_zero(ctx.rsp);
                let parameter0 = read_usize_or_zero(ctx.r9);
                litebox_util_log::error!(
                    error_status:% = format_args!("{:#x}", ctx.r10),
                    number_of_parameters = ctx.rdx,
                    unicode_string_parameter_mask:% = format_args!("{:#x}", ctx.r8),
                    parameters:% = format_args!("{:#x}", ctx.r9),
                    parameter0:% = format_args!("{parameter0:#x}"),
                    valid_response_options:% = format_args!("{valid_response_options:#x}"),
                    response:% = format_args!("{response:#x}"),
                    rip:% = format_args!("{:#x}", ctx.rip),
                    rip_region:% = self.describe_guest_address(ctx.rip),
                    rax:% = format_args!("{:#x}", ctx.rax),
                    rbx:% = format_args!("{:#x}", ctx.rbx),
                    rcx:% = format_args!("{:#x}", ctx.rcx),
                    rdx:% = format_args!("{:#x}", ctx.rdx),
                    r8:% = format_args!("{:#x}", ctx.r8),
                    r9:% = format_args!("{:#x}", ctx.r9),
                    stack:% = format_stack_words(ctx.rsp, 32),
                    guest_return_address:% = format_args!("{guest_return_address:#x}"),
                    guest_return_region:% = self.describe_guest_address(guest_return_address);
                    "Guest called NtRaiseHardError"
                );
                ContinueOperation::Terminate
            }
            syscall => {
                let guest_return_address = read_usize_or_zero(ctx.rsp);
                litebox_util_log::debug!(
                    syscall:? = syscall,
                    arg1:% = format_args!("{:#x}", ctx.r10),
                    rip:% = format_args!("{:#x}", ctx.rip),
                    rip_region:% = self.describe_guest_address(ctx.rip),
                    guest_return_address:% = format_args!("{guest_return_address:#x}"),
                    guest_return_region:% = self.describe_guest_address(guest_return_address);
                    "Unsupported Windows syscall"
                );
                ContinueOperation::Terminate
            }
        }
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        litebox_util_log::error!(
            exception:? = info.exception,
            rip:% = format_args!("{:#x}", ctx.rip),
            rip_region:% = self.describe_guest_address(ctx.rip),
            cr2:% = format_args!("{:#x}", info.cr2),
            cr2_region:% = self.describe_guest_address(info.cr2),
            rsp:% = format_args!("{:#x}", ctx.rsp),
            rax:% = format_args!("{:#x}", ctx.rax),
            rbx:% = format_args!("{:#x}", ctx.rbx),
            rcx:% = format_args!("{:#x}", ctx.rcx),
            rdx:% = format_args!("{:#x}", ctx.rdx),
            rbp:% = format_args!("{:#x}", ctx.rbp),
            rsi:% = format_args!("{:#x}", ctx.rsi),
            rdi:% = format_args!("{:#x}", ctx.rdi),
            r8:% = format_args!("{:#x}", ctx.r8),
            r9:% = format_args!("{:#x}", ctx.r9),
            r10:% = format_args!("{:#x}", ctx.r10),
            r11:% = format_args!("{:#x}", ctx.r11),
            r12:% = format_args!("{:#x}", ctx.r12),
            r13:% = format_args!("{:#x}", ctx.r13),
            r14:% = format_args!("{:#x}", ctx.r14),
            r15:% = format_args!("{:#x}", ctx.r15),
            stack:% = format_stack_words(ctx.rsp, 16),
            guest_return_address:% = format_args!("{:#x}", read_usize_or_zero(ctx.rsp)),
            guest_return_region:% = self.describe_guest_address(read_usize_or_zero(ctx.rsp));
            "Windows guest exception"
        );
        // TODO: Translate hardware exceptions into Windows SEH where appropriate.
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        // TODO: Handle host interrupts for Windows guest waits/APCs.
        ContinueOperation::Terminate
    }
}

impl<FS: NtShimFS> WindowsShimEntrypoints<FS> {
    fn load_image(&self, fs: Arc<FS>, path: &str) -> Result<LoadedImage, WindowsLoadError> {
        let file = PeImageFile::open(fs, path)?;
        let mut parsed = PeParsedFile::parse(&mut &file).map_err(WindowsLoadError::Parse)?;
        let imports = parsed.imports.clone();
        let exports = parsed.exports.clone();
        parsed
            .parse_trampoline(
                &mut &file,
                litebox_platform_multiplex::platform().get_syscall_entry_point(),
            )
            .map_err(WindowsLoadError::Parse)?;
        let has_trampoline = parsed.has_trampoline();
        let mut mapper = PeImageMapper {
            file: &file,
            page_manager: &self.page_manager,
        };
        let mut memory = PeImageMemory;
        let mapping = parsed
            .load(&mut mapper, &mut memory)
            .map_err(WindowsLoadError::Load)?;
        Ok(LoadedImage {
            mapping,
            imports,
            exports,
            has_trampoline,
        })
    }

    fn ensure_support_dll_loaded(&self, path: &str, region_name: &'static str) {
        if self.has_loaded_module(path) {
            return;
        }

        match self.load_image(self.fs.clone(), path) {
            Ok(image) => {
                self.record_named_memory_region(region_name, &image.mapping);
                self.record_loaded_module(path, &image);
                self.ensure_import_modules_loaded(&image.imports);
                self.resolve_image_imports_from_loaded_modules(
                    image.mapping.base_addr,
                    &image.imports,
                    path,
                );
                self.resolve_application_imports_from_loaded_modules();
            }
            Err(error) if is_missing_file_error(&error) => {}
            Err(error) => {
                litebox_util_log::debug!(
                    error:%,
                    path:% = path;
                    "Support DLL could not be loaded"
                );
            }
        }
    }

    fn ensure_import_modules_loaded(&self, imports: &[PeImport]) {
        let mut paths = Vec::new();
        for import in imports {
            let Some(path) = import_library_guest_path(&import.library) else {
                continue;
            };
            if paths.iter().any(|existing: &String| {
                module_name_matches(module_basename(existing), module_basename(&path))
            }) {
                continue;
            }
            paths.push(path);
        }

        for path in paths {
            let region_name = loaded_image_region_name(&path);
            self.ensure_support_dll_loaded(&path, region_name);
        }
    }

    fn has_loaded_module(&self, path: &str) -> bool {
        self.loaded_modules
            .lock()
            .iter()
            .any(|module| module_basename(&module.path).eq_ignore_ascii_case(module_basename(path)))
    }

    fn loaded_module_mapping(&self, path: &str) -> Option<(usize, usize)> {
        self.loaded_modules.lock().iter().find_map(|module| {
            module_basename(&module.path)
                .eq_ignore_ascii_case(module_basename(path))
                .then_some((module.base_addr, module.image_size))
        })
    }

    fn section_object_guest_path(&self, object_name: &str) -> Option<String> {
        let library_name = module_basename(object_name.trim());
        if library_name.is_empty() {
            return None;
        }
        let lower_library_name = library_name.to_ascii_lowercase();
        if !(lower_library_name.starts_with("api-ms-")
            || lower_library_name.starts_with("ext-ms-")
            || lower_library_name
                .rsplit_once('.')
                .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("dll")))
        {
            return None;
        }
        let normalized_library = self.import_lookup_library(library_name.as_bytes());
        import_library_guest_path(&normalized_library)
    }

    fn record_loaded_module(&self, path: &str, image: &LoadedImage) {
        let mut loaded_modules = self.loaded_modules.lock();
        if loaded_modules
            .iter()
            .any(|module| module_basename(&module.path).eq_ignore_ascii_case(module_basename(path)))
        {
            return;
        }
        loaded_modules.push(LoadedModule {
            path: String::from(path),
            base_addr: image.mapping.base_addr,
            image_size: image.mapping.image_size,
            exports: image.exports.clone(),
        });
        litebox_util_log::debug!(
            path:% = path,
            base:% = format_args!("{:#x}", image.mapping.base_addr),
            export_count = image.exports.len();
            "Recorded loaded Windows module"
        );
        if let Err(error) = self.append_dynamic_ldr_entry(path, &image.mapping) {
            litebox_util_log::debug!(
                error:?,
                path:% = path,
                base:% = format_args!("{:#x}", image.mapping.base_addr);
                "Could not append dynamic Windows LDR entry"
            );
        }
    }

    fn append_dynamic_ldr_entry(
        &self,
        path: &str,
        mapping: &MappingInfo,
    ) -> Result<(), PeImageAccessError> {
        let entry_address = self.create_metadata_pages(DYNAMIC_LDR_ENTRY_SIZE)?;
        let ddag_node_address = entry_address
            .checked_add(LDR_DATA_TABLE_ENTRY_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let mut string_cursor = ddag_node_address
            .checked_add(LDR_DDAG_NODE_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let list_heads = LdrListHeads {
            load: self.ldr_data_address + PEB_LDR_IN_LOAD_ORDER_MODULE_LIST_OFFSET,
            memory: self.ldr_data_address + PEB_LDR_IN_MEMORY_ORDER_MODULE_LIST_OFFSET,
            initialization: self.ldr_data_address
                + PEB_LDR_IN_INITIALIZATION_ORDER_MODULE_LIST_OFFSET,
        };
        let mut tail = self.ldr_tail_entry.lock();
        let previous_entry = *tail;
        let entry = LdrDataTableEntry::new(
            previous_entry,
            None,
            list_heads,
            mapping,
            LdrEntryAddresses {
                entry: entry_address,
                ddag_node: ddag_node_address,
            },
            write_utf16_string(&mut string_cursor, &guest_path_to_dos_path(path))?,
            write_utf16_string(&mut string_cursor, module_basename(path))?,
        );
        write_value(entry_address, entry)?;
        write_value(
            ddag_node_address,
            LdrDdagNode::new(ddag_node_address, entry_address + 0xa0),
        )?;
        append_ldr_list_entry(
            list_heads.load,
            previous_entry,
            entry_address,
            LDR_DATA_TABLE_ENTRY_IN_LOAD_ORDER_LINKS_OFFSET,
        )?;
        append_ldr_list_entry(
            list_heads.memory,
            previous_entry,
            entry_address,
            LDR_DATA_TABLE_ENTRY_IN_MEMORY_ORDER_LINKS_OFFSET,
        )?;
        append_ldr_list_entry(
            list_heads.initialization,
            previous_entry,
            entry_address,
            LDR_DATA_TABLE_ENTRY_IN_INITIALIZATION_ORDER_LINKS_OFFSET,
        )?;
        *tail = Some(entry_address);
        litebox_util_log::debug!(
            path:% = path,
            entry:% = format_args!("{entry_address:#x}"),
            previous_entry:% = previous_entry.map_or_else(|| String::from("<none>"), |entry| format!("{entry:#x}"));
            "Appended dynamic Windows LDR entry"
        );
        Ok(())
    }

    fn create_metadata_pages(&self, size: usize) -> Result<usize, PeImageAccessError> {
        let length = NonZeroPageSize::new(size).ok_or(PeImageAccessError::AddressOverflow)?;
        // SAFETY: These pages are private guest metadata pages owned and initialized by the shim.
        let ptr = unsafe {
            self.page_manager
                .create_writable_pages(None, length, CreatePagesFlags::empty(), |_| Ok(0))
        }
        .map_err(PeImageAccessError::Mapping)?;
        ptr.copy_from_slice(0, &vec![0; size])
            .ok_or(PeImageAccessError::MemoryAccess)?;
        Ok(ptr.as_usize())
    }

    fn resolve_application_imports_from_loaded_modules(&self) {
        self.resolve_image_imports_from_loaded_modules(
            self.application_base,
            &self.application_imports,
            "app",
        );
    }

    fn resolve_image_imports_from_loaded_modules(
        &self,
        image_base: usize,
        imports: &[PeImport],
        image_name: &str,
    ) {
        let mut stats = ImportResolutionStats::default();
        for import in imports {
            let Some(address) = self.loaded_module_import_address(import) else {
                stats.unresolved += 1;
                if stats.unresolved_samples.len() < 8 {
                    stats.unresolved_samples.push(format!(
                        "{}!{}",
                        String::from_utf8_lossy(&import.library),
                        import_name(import)
                    ));
                }
                litebox_util_log::trace!(
                    image:% = image_name,
                    library:% = String::from_utf8_lossy(&import.library),
                    name:% = import_name(import);
                    "Windows import is not resolved from loaded guest modules yet"
                );
                continue;
            };
            let Some(iat_address) = image_base.checked_add(import.iat_rva as usize) else {
                stats.write_failed += 1;
                continue;
            };
            if make_pages_writable(&self.page_manager, iat_address, size_of::<usize>()).is_err()
                || write_value(iat_address, address).is_err()
            {
                stats.write_failed += 1;
                litebox_util_log::debug!(
                    image:% = image_name,
                    library:% = String::from_utf8_lossy(&import.library),
                    iat:% = format_args!("{iat_address:#x}");
                    "Could not write resolved Windows import"
                );
                continue;
            }
            stats.resolved += 1;
            litebox_util_log::trace!(
                image:% = image_name,
                library:% = String::from_utf8_lossy(&import.library),
                name:% = import_name(import),
                iat:% = format_args!("{iat_address:#x}"),
                address:% = format_args!("{address:#x}");
                "Resolved Windows import from loaded guest module"
            );
        }

        if !imports.is_empty() {
            litebox_util_log::debug!(
                image:% = image_name,
                total = imports.len(),
                resolved = stats.resolved,
                unresolved = stats.unresolved,
                write_failed = stats.write_failed,
                unresolved_samples:? = stats.unresolved_samples;
                "Resolved Windows imports from loaded guest modules"
            );
        }
    }

    fn loaded_module_import_address(&self, import: &PeImport) -> Option<usize> {
        let loaded_modules = self.loaded_modules.lock();
        match &import.target {
            PeImportTarget::Name { name, .. } => self
                .export_address(&loaded_modules, &import.library, name)
                .or_else(|| {
                    if import_library_is_kernel32(&import.library) {
                        self.export_address(&loaded_modules, b"kernelbase.dll", name)
                    } else {
                        None
                    }
                }),
            PeImportTarget::Ordinal(ordinal) => self
                .export_ordinal_address(&loaded_modules, &import.library, u32::from(*ordinal))
                .or_else(|| {
                    if import_library_is_kernel32(&import.library) {
                        self.export_ordinal_address(
                            &loaded_modules,
                            b"kernelbase.dll",
                            u32::from(*ordinal),
                        )
                    } else {
                        None
                    }
                }),
        }
    }

    fn export_address(
        &self,
        modules: &[LoadedModule],
        library: &[u8],
        name: &[u8],
    ) -> Option<usize> {
        self.resolve_export_name(modules, library, name, 0)
    }

    fn export_ordinal_address(
        &self,
        modules: &[LoadedModule],
        library: &[u8],
        ordinal: u32,
    ) -> Option<usize> {
        self.resolve_export_ordinal(modules, library, ordinal, 0)
    }

    fn resolve_export_name(
        &self,
        modules: &[LoadedModule],
        library: &[u8],
        name: &[u8],
        depth: usize,
    ) -> Option<usize> {
        const MAX_EXPORT_FORWARD_DEPTH: usize = 8;

        if depth >= MAX_EXPORT_FORWARD_DEPTH {
            return None;
        }

        let lookup_library = self.import_lookup_library(library);
        modules.iter().enumerate().find_map(|(index, module)| {
            if module_matches_import(module, &lookup_library) {
                self.resolve_export_name_in_module(modules, index, name, depth)
            } else {
                None
            }
        })
    }

    fn resolve_export_name_in_module(
        &self,
        modules: &[LoadedModule],
        module_index: usize,
        name: &[u8],
        depth: usize,
    ) -> Option<usize> {
        let module = modules.get(module_index)?;
        let export = module
            .exports
            .iter()
            .find(|export| export.name.eq_ignore_ascii_case(name))?;
        match &export.forwarder {
            None => module.base_addr.checked_add(export.rva as usize),
            Some(PeExportForwarder::Name { library, name }) => {
                self.resolve_export_name(modules, library, name, depth + 1)
            }
            Some(PeExportForwarder::Ordinal { library, ordinal }) => {
                self.resolve_export_ordinal(modules, library, *ordinal, depth + 1)
            }
        }
    }

    fn resolve_export_ordinal(
        &self,
        modules: &[LoadedModule],
        library: &[u8],
        ordinal: u32,
        depth: usize,
    ) -> Option<usize> {
        const MAX_EXPORT_FORWARD_DEPTH: usize = 8;

        if depth >= MAX_EXPORT_FORWARD_DEPTH {
            return None;
        }

        let lookup_library = self.import_lookup_library(library);
        modules.iter().enumerate().find_map(|(index, module)| {
            if module_matches_import(module, &lookup_library) {
                self.resolve_export_ordinal_in_module(modules, index, ordinal, depth)
            } else {
                None
            }
        })
    }

    fn resolve_export_ordinal_in_module(
        &self,
        modules: &[LoadedModule],
        module_index: usize,
        ordinal: u32,
        depth: usize,
    ) -> Option<usize> {
        let module = modules.get(module_index)?;
        let export = module
            .exports
            .iter()
            .find(|export| export.ordinal == ordinal)?;
        match &export.forwarder {
            None => module.base_addr.checked_add(export.rva as usize),
            Some(PeExportForwarder::Name { library, name }) => {
                self.resolve_export_name(modules, library, name, depth + 1)
            }
            Some(PeExportForwarder::Ordinal { library, ordinal }) => {
                self.resolve_export_ordinal(modules, library, *ordinal, depth + 1)
            }
        }
    }

    fn import_lookup_library(&self, library: &[u8]) -> Vec<u8> {
        if !import_library_is_api_set(library) {
            return library.to_vec();
        }

        let api_set_name = module_basename(import_library_name(library)).to_ascii_lowercase();
        let mut api_set_hosts = self.api_set_hosts.lock();
        if let Some(entry) = api_set_hosts
            .iter()
            .find(|entry| entry.api_set_name.eq_ignore_ascii_case(&api_set_name))
        {
            return entry.host_dll.as_bytes().to_vec();
        }

        let host_dll = api_set_host_dll_or_default(
            GUEST_API_SET_MAP.load(Ordering::Relaxed),
            api_set_name.as_str(),
        )
        .unwrap_or_else(|| String::from("kernelbase.dll"));
        api_set_hosts.push(ApiSetHostCacheEntry {
            api_set_name,
            host_dll: host_dll.clone(),
        });
        host_dll.into_bytes()
    }

    fn nt_query_performance_counter(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let counter = PERFORMANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
        if ctx.r10 == 0
            || write_value(ctx.r10, counter).is_err()
            || (ctx.rdx != 0 && write_value(ctx.rdx, PERFORMANCE_FREQUENCY).is_err())
        {
            litebox_util_log::error!(
                counter_ptr:% = format_args!("{:#x}", ctx.r10),
                counter_region:% = self.describe_guest_address(ctx.r10),
                frequency_ptr:% = format_args!("{:#x}", ctx.rdx),
                frequency_region:% = self.describe_guest_address(ctx.rdx);
                "NtQueryPerformanceCounter could not write guest output"
            );
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            counter_ptr:% = format_args!("{:#x}", ctx.r10),
            frequency_ptr:% = format_args!("{:#x}", ctx.rdx),
            counter;
            "Handling NtQueryPerformanceCounter syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_protect_virtual_memory(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let old_protection_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_5_OFFSET);
        let Some(old_protection_slot) = old_protection_slot else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        let (Ok(base_address), Ok(region_size), Ok(old_protection_address)) = (
            read_value::<usize>(ctx.rdx),
            read_value::<usize>(ctx.r8),
            read_value::<usize>(old_protection_slot),
        ) else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        let Some(protection) = windows_protection(ctx.r9) else {
            litebox_util_log::error!(new_protection:% = format_args!("{:#x}", ctx.r9); "NtProtectVirtualMemory unsupported protection flags");
            ctx.rax = STATUS_INVALID_PARAMETER;
            return;
        };

        if base_address == 0 || region_size == 0 || old_protection_address == 0 {
            ctx.rax = STATUS_INVALID_PARAMETER;
            return;
        }

        let Ok((protected_base, protected_len)) = page_range(base_address, region_size) else {
            ctx.rax = STATUS_INVALID_PARAMETER;
            return;
        };

        match protect_pages(
            &self.page_manager,
            protected_base,
            protected_len,
            protection,
        ) {
            Ok(()) => {}
            Err(error) => {
                litebox_util_log::error!(
                    error:? = error,
                    base:% = format_args!("{protected_base:#x}"),
                    len = protected_len,
                    base_region:% = self.describe_guest_address(protected_base),
                    new_protection:% = format_args!("{:#x}", ctx.r9);
                    "NtProtectVirtualMemory failed to update guest page permissions"
                );
                ctx.rax = STATUS_ACCESS_VIOLATION;
                return;
            }
        }

        if write_value(ctx.rdx, protected_base).is_err()
            || write_value(ctx.r8, protected_len).is_err()
            || write_value(old_protection_address, WINDOWS_OLD_PROTECTION_FALLBACK).is_err()
        {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            process_handle:% = format_args!("{:#x}", ctx.r10),
            base:% = format_args!("{protected_base:#x}"),
            len = protected_len,
            new_protection:% = format_args!("{:#x}", ctx.r9),
            old_protection_ptr:% = format_args!("{old_protection_address:#x}");
            "Handling NtProtectVirtualMemory syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_allocate_virtual_memory(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let allocation_type_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_5_OFFSET);
        let page_protection_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_6_OFFSET);
        let (Some(allocation_type_slot), Some(page_protection_slot)) =
            (allocation_type_slot, page_protection_slot)
        else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        let (Ok(allocation_type), Ok(page_protection)) = (
            read_value::<usize>(allocation_type_slot),
            read_value::<usize>(page_protection_slot),
        ) else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        ctx.rax = self.allocate_virtual_memory(ctx.rdx, ctx.r9, allocation_type, page_protection);
        if ctx.rax == STATUS_SUCCESS {
            litebox_util_log::debug!(
                process_handle:% = format_args!("{:#x}", ctx.r10),
                base_address_ptr:% = format_args!("{:#x}", ctx.rdx),
                zero_bits = ctx.r8,
                region_size_ptr:% = format_args!("{:#x}", ctx.r9),
                allocation_type:% = format_args!("{allocation_type:#x}"),
                page_protection:% = format_args!("{page_protection:#x}");
                "Handling NtAllocateVirtualMemory syscall"
            );
        }
    }

    fn nt_allocate_virtual_memory_ex(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let page_protection_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_5_OFFSET);
        let extended_parameters_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_6_OFFSET);
        let extended_parameter_count_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_7_OFFSET);
        let (
            Some(page_protection_slot),
            Some(extended_parameters_slot),
            Some(extended_parameter_count_slot),
        ) = (
            page_protection_slot,
            extended_parameters_slot,
            extended_parameter_count_slot,
        )
        else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        let (Ok(page_protection), Ok(extended_parameters), Ok(extended_parameter_count)) = (
            read_value::<usize>(page_protection_slot),
            read_value::<usize>(extended_parameters_slot),
            read_value::<usize>(extended_parameter_count_slot),
        ) else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        let extended_parameters_result =
            Self::validate_mem_extended_parameters(extended_parameters, extended_parameter_count);
        if extended_parameters_result != STATUS_SUCCESS {
            ctx.rax = extended_parameters_result;
            return;
        }

        ctx.rax = self.allocate_virtual_memory(ctx.rdx, ctx.r8, ctx.r9, page_protection);
        if ctx.rax == STATUS_SUCCESS {
            litebox_util_log::debug!(
                process_handle:% = format_args!("{:#x}", ctx.r10),
                base_address_ptr:% = format_args!("{:#x}", ctx.rdx),
                region_size_ptr:% = format_args!("{:#x}", ctx.r8),
                allocation_type:% = format_args!("{:#x}", ctx.r9),
                page_protection:% = format_args!("{page_protection:#x}"),
                extended_parameters:% = format_args!("{extended_parameters:#x}"),
                extended_parameter_count;
                "Handling NtAllocateVirtualMemoryEx syscall"
            );
        }
    }

    fn nt_free_virtual_memory(&self, ctx: &mut litebox_common_linux::PtRegs) {
        if ctx.rdx == 0 || ctx.r8 == 0 {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        let (Ok(base_address), Ok(region_size)) =
            (read_value::<usize>(ctx.rdx), read_value::<usize>(ctx.r8))
        else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        let release = ctx.r9 & WINDOWS_MEM_RELEASE_FLAG != 0;
        let decommit = ctx.r9 & WINDOWS_MEM_DECOMMIT_FLAG != 0;
        if base_address == 0 || release == decommit {
            ctx.rax = STATUS_INVALID_PARAMETER;
            return;
        }

        let free_base = page_align_down(base_address);
        let free_size = if region_size == 0 && release {
            self.memory_basic_information(base_address).region_size
        } else {
            let Some(region_size) = page_align_up(region_size) else {
                ctx.rax = STATUS_INVALID_PARAMETER;
                return;
            };
            region_size
        };

        if free_size == 0 {
            ctx.rax = STATUS_INVALID_PARAMETER;
            return;
        }

        let status = if release {
            self.release_virtual_memory(free_base, free_size)
        } else {
            self.decommit_virtual_memory(free_base, free_size)
        };
        if status != STATUS_SUCCESS {
            ctx.rax = status;
            return;
        }

        if write_value(ctx.rdx, free_base).is_err() || write_value(ctx.r8, free_size).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            process_handle:% = format_args!("{:#x}", ctx.r10),
            base:% = format_args!("{free_base:#x}"),
            len = free_size,
            free_type:% = format_args!("{:#x}", ctx.r9);
            "Handling NtFreeVirtualMemory syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_continue(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let context_address = ctx.r10;
        let Ok(context) = read_value::<InitialThreadContext>(context_address) else {
            litebox_util_log::error!(
                context:% = format_args!("{context_address:#x}"),
                context_region:% = self.describe_guest_address(context_address);
                "NtContinue received unreadable context"
            );
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        litebox_util_log::debug!(
            context:% = format_args!("{context_address:#x}"),
            context_region:% = self.describe_guest_address(context_address),
            rip:% = format_args!("{:#x}", context.rip),
            rsp:% = format_args!("{:#x}", context.rsp);
            "Handling NtContinue syscall"
        );
        context.apply_to(ctx);
    }

    fn validate_mem_extended_parameters(
        extended_parameters: usize,
        extended_parameter_count: usize,
    ) -> usize {
        if extended_parameter_count == 0 {
            return if extended_parameters == 0 {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_PARAMETER
            };
        }

        if extended_parameters == 0 {
            return STATUS_INVALID_PARAMETER;
        }

        for index in 0..extended_parameter_count {
            let Some(parameter_address) = index
                .checked_mul(size_of::<MemExtendedParameter>())
                .and_then(|offset| extended_parameters.checked_add(offset))
            else {
                return STATUS_ACCESS_VIOLATION;
            };
            let Ok(parameter) = read_value::<MemExtendedParameter>(parameter_address) else {
                return STATUS_ACCESS_VIOLATION;
            };

            let parameter_type = parameter.type_();
            litebox_util_log::debug!(
                index,
                parameter_address:% = format_args!("{parameter_address:#x}"),
                parameter_type,
                type_and_reserved:% = format_args!("{:#x}", parameter.type_and_reserved),
                value:% = format_args!("{:#x}", parameter.value);
                "Decoded NtAllocateVirtualMemoryEx extended parameter"
            );

            match parameter_type {
                MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS => {
                    if parameter.value == 0 {
                        return STATUS_INVALID_PARAMETER;
                    }
                    let Ok(requirements) = read_value::<MemAddressRequirements>(parameter.value)
                    else {
                        return STATUS_ACCESS_VIOLATION;
                    };
                    litebox_util_log::debug!(
                        lowest_starting_address:% = format_args!("{:#x}", requirements.lowest_starting_address),
                        highest_ending_address:% = format_args!("{:#x}", requirements.highest_ending_address),
                        alignment:% = format_args!("{:#x}", requirements.alignment);
                        "Treating NtAllocateVirtualMemoryEx address requirements as advisory"
                    );
                }
                MEM_EXTENDED_PARAMETER_NUMA_NODE => {
                    litebox_util_log::debug!(
                        numa_node = parameter.value;
                        "Treating NtAllocateVirtualMemoryEx NUMA node as advisory"
                    );
                }
                MEM_EXTENDED_PARAMETER_ATTRIBUTE_FLAGS => {
                    if parameter.value & !MEM_EXTENDED_PARAMETER_SUPPORTED_ATTRIBUTE_FLAGS != 0 {
                        litebox_util_log::error!(
                            attribute_flags:% = format_args!("{:#x}", parameter.value);
                            "NtAllocateVirtualMemoryEx unsupported attribute flags"
                        );
                        return STATUS_NOT_SUPPORTED;
                    }
                    litebox_util_log::debug!(
                        attribute_flags:% = format_args!("{:#x}", parameter.value);
                        "Treating NtAllocateVirtualMemoryEx attribute flags as advisory"
                    );
                }
                MEM_EXTENDED_PARAMETER_IMAGE_MACHINE => {
                    litebox_util_log::debug!(
                        image_machine:% = format_args!("{:#x}", parameter.value);
                        "Treating NtAllocateVirtualMemoryEx image machine as advisory"
                    );
                }
                MEM_EXTENDED_PARAMETER_PARTITION_HANDLE
                | MEM_EXTENDED_PARAMETER_USER_PHYSICAL_HANDLE => {
                    litebox_util_log::error!(
                        parameter_type,
                        value:% = format_args!("{:#x}", parameter.value);
                        "NtAllocateVirtualMemoryEx unsupported extended parameter type"
                    );
                    return STATUS_NOT_SUPPORTED;
                }
                0 | MEM_EXTENDED_PARAMETER_MAX.. => {
                    return STATUS_INVALID_PARAMETER;
                }
            }
        }

        STATUS_SUCCESS
    }

    fn allocate_virtual_memory(
        &self,
        base_address_pointer: usize,
        region_size_pointer: usize,
        allocation_type: usize,
        page_protection: usize,
    ) -> usize {
        if base_address_pointer == 0 || region_size_pointer == 0 {
            return STATUS_ACCESS_VIOLATION;
        }

        let (Ok(base_address), Ok(region_size)) = (
            read_value::<usize>(base_address_pointer),
            read_value::<usize>(region_size_pointer),
        ) else {
            return STATUS_ACCESS_VIOLATION;
        };

        if allocation_type & (WINDOWS_MEM_COMMIT_FLAG | WINDOWS_MEM_RESERVE_FLAG) == 0 {
            return STATUS_INVALID_PARAMETER;
        }

        let Some(region_size) = page_align_up(region_size) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(length) = NonZeroPageSize::new(region_size) else {
            return STATUS_INVALID_PARAMETER;
        };

        let base_address = page_align_down(base_address);
        let reserve_pages = allocation_type & WINDOWS_MEM_RESERVE_FLAG != 0;
        let commit_pages = allocation_type & WINDOWS_MEM_COMMIT_FLAG != 0;
        if commit_pages && !reserve_pages {
            if base_address == 0 {
                return STATUS_INVALID_PARAMETER;
            }
            return self.commit_virtual_memory(
                base_address_pointer,
                region_size_pointer,
                base_address,
                region_size,
                page_protection,
            );
        }

        let suggested_address = if base_address == 0 {
            None
        } else {
            let Some(address) = NonZeroAddress::new(base_address) else {
                return STATUS_INVALID_PARAMETER;
            };
            Some(address)
        };
        let create_flags = if suggested_address.is_some() {
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE
        } else {
            CreatePagesFlags::empty()
        };

        let mapped_address = match self.create_reserved_virtual_memory(
            suggested_address,
            length,
            create_flags,
            region_size,
        ) {
            Ok(address) => address,
            Err(error) => {
                litebox_util_log::error!(
                    error:%,
                    requested_base:% = format_args!("{base_address:#x}"),
                    requested_size = region_size,
                    allocation_type:% = format_args!("{allocation_type:#x}"),
                    page_protection:% = format_args!("{page_protection:#x}"),
                    suggested_address:% = format_args!("{:#x}", suggested_address.map_or(0, NonZeroAddress::as_usize));
                    "NtAllocateVirtualMemory mapping failed"
                );
                return STATUS_INVALID_PARAMETER;
            }
        };

        if commit_pages {
            let Some(protection) = windows_protection(page_protection) else {
                return STATUS_INVALID_PARAMETER;
            };
            if make_pages_writable(&self.page_manager, mapped_address, region_size).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
            let ptr =
                <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(mapped_address);
            if ptr.copy_from_slice(0, &vec![0; region_size]).is_none() {
                return STATUS_ACCESS_VIOLATION;
            }
            if protect_pages(&self.page_manager, mapped_address, region_size, protection).is_err() {
                return STATUS_INVALID_PARAMETER;
            }
        }

        if write_value(base_address_pointer, mapped_address).is_err()
            || write_value(region_size_pointer, region_size).is_err()
        {
            return STATUS_ACCESS_VIOLATION;
        }

        self.record_memory_region(mapped_address, region_size);

        STATUS_SUCCESS
    }

    fn create_reserved_virtual_memory(
        &self,
        suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
        length: NonZeroPageSize<PAGE_SIZE>,
        create_flags: CreatePagesFlags,
        region_size: usize,
    ) -> Result<usize, MappingError> {
        if suggested_address.is_some() {
            // SAFETY: This syscall owns the newly allocated guest range and maps it
            // before returning the address to guest ntdll.
            return unsafe {
                self.page_manager
                    .create_inaccessible_pages(suggested_address, length, create_flags, |_| Ok(0))
                    .map(|ptr| ptr.as_usize())
            };
        }

        let oversized_len = region_size
            .checked_add(WINDOWS_ALLOCATION_GRANULARITY_USIZE - PAGE_SIZE)
            .and_then(NonZeroPageSize::new)
            .ok_or(MappingError::OutOfMemory)?;

        // SAFETY: This temporary over-reservation is immediately trimmed so the
        // guest-visible Windows allocation base is allocation-granularity aligned.
        let raw_address = unsafe {
            self.page_manager
                .create_inaccessible_pages(None, oversized_len, create_flags, |_| Ok(0))?
                .as_usize()
        };
        let Some(mapped_address) = align_up_to(raw_address, WINDOWS_ALLOCATION_GRANULARITY_USIZE)
        else {
            return Err(MappingError::OutOfMemory);
        };

        self.trim_reserved_virtual_memory(raw_address, mapped_address, region_size, oversized_len)?;
        Ok(mapped_address)
    }

    fn trim_reserved_virtual_memory(
        &self,
        raw_address: usize,
        mapped_address: usize,
        region_size: usize,
        oversized_len: NonZeroPageSize<PAGE_SIZE>,
    ) -> Result<(), MappingError> {
        if mapped_address > raw_address {
            let ptr =
                <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(raw_address);
            // SAFETY: This prefix is the unused part of a fresh over-reservation.
            unsafe {
                self.page_manager
                    .remove_pages(ptr, mapped_address - raw_address)
                    .map_err(|_| MappingError::OutOfMemory)?;
            }
        }

        let raw_end = raw_address
            .checked_add(oversized_len.as_usize())
            .ok_or(MappingError::OutOfMemory)?;
        let mapped_end = mapped_address
            .checked_add(region_size)
            .ok_or(MappingError::OutOfMemory)?;
        if mapped_end < raw_end {
            let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(mapped_end);
            // SAFETY: This suffix is the unused part of a fresh over-reservation.
            unsafe {
                self.page_manager
                    .remove_pages(ptr, raw_end - mapped_end)
                    .map_err(|_| MappingError::OutOfMemory)?;
            }
        }

        Ok(())
    }

    fn commit_virtual_memory(
        &self,
        base_address_pointer: usize,
        region_size_pointer: usize,
        base_address: usize,
        region_size: usize,
        page_protection: usize,
    ) -> usize {
        let Some(protection) = windows_protection(page_protection) else {
            return STATUS_INVALID_PARAMETER;
        };

        if make_pages_writable(&self.page_manager, base_address, region_size).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }

        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(base_address);
        if ptr.copy_from_slice(0, &vec![0; region_size]).is_none() {
            return STATUS_ACCESS_VIOLATION;
        }

        if protect_pages(&self.page_manager, base_address, region_size, protection).is_err() {
            return STATUS_INVALID_PARAMETER;
        }

        if write_value(base_address_pointer, base_address).is_err()
            || write_value(region_size_pointer, region_size).is_err()
        {
            return STATUS_ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            base:% = format_args!("{base_address:#x}"),
            len = region_size,
            page_protection:% = format_args!("{page_protection:#x}");
            "Committed existing virtual memory range"
        );

        STATUS_SUCCESS
    }

    fn decommit_virtual_memory(&self, base_address: usize, region_size: usize) -> usize {
        match protect_pages(
            &self.page_manager,
            base_address,
            region_size,
            Protection {
                read: false,
                write: false,
                execute: false,
            },
        ) {
            Ok(()) => STATUS_SUCCESS,
            Err(error) => {
                litebox_util_log::error!(
                    error:? = error,
                    base:% = format_args!("{base_address:#x}"),
                    len = region_size;
                    "NtFreeVirtualMemory failed to decommit range"
                );
                STATUS_ACCESS_VIOLATION
            }
        }
    }

    fn release_virtual_memory(&self, base_address: usize, region_size: usize) -> usize {
        if !self.forget_memory_region(base_address, region_size) {
            return STATUS_MEMORY_NOT_ALLOCATED;
        }

        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(base_address);
        // SAFETY: The guest explicitly released this range and the shim will not keep using it.
        match unsafe { self.page_manager.remove_pages(ptr, region_size) } {
            Ok(()) => STATUS_SUCCESS,
            Err(error) => {
                litebox_util_log::error!(
                    error:? = error,
                    base:% = format_args!("{base_address:#x}"),
                    len = region_size;
                    "NtFreeVirtualMemory failed to release range"
                );
                STATUS_ACCESS_VIOLATION
            }
        }
    }

    fn record_memory_region(&self, base_address: usize, region_size: usize) {
        if let Some(region) = GuestAddressRegion::new("allocation", base_address, region_size) {
            self.diagnostic_regions.lock().push(region);
        }
    }

    fn record_named_memory_region(&self, name: &'static str, mapping: &MappingInfo) {
        if let Some(region) = GuestAddressRegion::new(name, mapping.base_addr, mapping.image_size) {
            self.diagnostic_regions.lock().push(region);
        }
    }

    fn forget_memory_region(&self, base_address: usize, region_size: usize) -> bool {
        let Some(region_end) = base_address.checked_add(region_size) else {
            return false;
        };
        let mut regions = self.diagnostic_regions.lock();
        let Some(index) = regions.iter().position(|region| {
            region.name == "allocation" && region.start <= base_address && region_end <= region.end
        }) else {
            return false;
        };

        let region = regions[index];
        match (region.start == base_address, region.end == region_end) {
            (true, true) => {
                regions.remove(index);
            }
            (true, false) => {
                regions[index].start = region_end;
            }
            (false, true) => {
                regions[index].end = base_address;
            }
            (false, false) => {
                regions[index].end = base_address;
                regions.push(GuestAddressRegion {
                    name: region.name,
                    start: region_end,
                    end: region.end,
                });
            }
        }

        true
    }

    fn nt_query_virtual_memory(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let length_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_5_OFFSET);
        let return_length_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_6_OFFSET);
        let (Some(length_slot), Some(return_length_slot)) = (length_slot, return_length_slot)
        else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        let (Ok(memory_information_length), Ok(return_length_address)) = (
            read_value::<usize>(length_slot),
            read_value::<usize>(return_length_slot),
        ) else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        ctx.rax = match ctx.r8 {
            MEMORY_BASIC_INFORMATION_CLASS => Self::write_memory_information(
                ctx.r9,
                memory_information_length,
                return_length_address,
                self.memory_basic_information(ctx.rdx),
            ),
            MEMORY_IMAGE_INFORMATION_CLASS => match self.memory_image_information(ctx.rdx) {
                Some(memory_information) => Self::write_memory_information(
                    ctx.r9,
                    memory_information_length,
                    return_length_address,
                    memory_information,
                ),
                None => STATUS_INVALID_PARAMETER,
            },
            MEMORY_IMAGE_EXTENSION_INFORMATION_CLASS => {
                match self.memory_image_extension_information(ctx.rdx, ctx.r9) {
                    Some(memory_information) => Self::write_memory_information(
                        ctx.r9,
                        memory_information_length,
                        return_length_address,
                        memory_information,
                    ),
                    None => STATUS_INVALID_PARAMETER,
                }
            }
            MEMORY_WORKING_SET_EX_INFORMATION_CLASS => self.write_working_set_ex_information(
                ctx.rdx,
                ctx.r9,
                memory_information_length,
                return_length_address,
            ),
            memory_information_class => {
                litebox_util_log::error!(memory_information_class; "NtQueryVirtualMemory unsupported information class");
                STATUS_INVALID_INFO_CLASS
            }
        };

        if ctx.rax != STATUS_SUCCESS {
            return;
        }

        litebox_util_log::debug!(
            process_handle:% = format_args!("{:#x}", ctx.r10),
            base:% = format_args!("{:#x}", ctx.rdx),
            base_region:% = self.describe_guest_address(ctx.rdx),
            information:% = format_args!("{:#x}", ctx.r9),
            len = memory_information_length;
            "Handling NtQueryVirtualMemory syscall"
        );
    }

    fn insert_handle(&self, kind: WindowsHandleKind) -> usize {
        let handle = NEXT_SYNTHETIC_HANDLE.fetch_add(4, Ordering::Relaxed);
        self.handles.lock().push(WindowsHandle { handle, kind });
        handle
    }

    fn remove_handle(&self, handle: usize) {
        let mut handles = self.handles.lock();
        if let Some(index) = handles.iter().position(|entry| entry.handle == handle) {
            handles.remove(index);
        }
    }

    fn file_path_for_handle(&self, handle: usize) -> Option<String> {
        self.handles
            .lock()
            .iter()
            .find_map(|entry| match (&entry.kind, entry.handle == handle) {
                (WindowsHandleKind::File { path }, true) => Some(path.clone()),
                _ => None,
            })
    }

    fn section_path_for_handle(&self, handle: usize) -> Option<String> {
        self.handles
            .lock()
            .iter()
            .find_map(|entry| match (&entry.kind, entry.handle == handle) {
                (WindowsHandleKind::Section { path }, true) => path.clone(),
                _ => None,
            })
    }

    fn record_mapped_section_view(
        &self,
        base_addr: usize,
        size: usize,
        path: Option<String>,
        region_name: &'static str,
    ) {
        if size == 0 {
            return;
        }
        self.mapped_section_views.lock().push(MappedSectionView {
            base_addr,
            size,
            path,
            region_name,
        });
    }

    fn forget_mapped_section_view(&self, base_address: usize) -> Option<MappedSectionView> {
        let mut views = self.mapped_section_views.lock();
        let index = views.iter().position(|view| view.contains(base_address))?;
        Some(views.remove(index))
    }

    fn image_region_containing(&self, address: usize) -> Option<GuestAddressRegion> {
        self.diagnostic_regions
            .lock()
            .iter()
            .copied()
            .find(|region| region.is_image() && region.contains(address))
    }

    fn nt_close(&self, ctx: &mut litebox_common_linux::PtRegs) {
        self.remove_handle(ctx.r10);
        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", ctx.r10);
            "Handling NtClose as no-op"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_write_file(ctx: &mut litebox_common_linux::PtRegs) {
        let io_status = read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));
        let buffer = read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_6_OFFSET));
        let length = read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_7_OFFSET));
        let byte_offset =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_8_OFFSET));
        let key = read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_9_OFFSET));

        if buffer == 0 && length != 0 {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        let bytes_to_write = u32::try_from(length).unwrap_or(u32::MAX);
        let mut bytes_written = 0_u32;
        let host_stdout = host_standard_handle(WINDOWS_STD_OUTPUT_HANDLE) as *mut c_void;
        // SAFETY: In the Windows userland prototype the guest buffer is mapped in
        // this process, and this handler is only used to surface console writes.
        let write_ok = unsafe {
            host_write_file(
                host_stdout,
                buffer as *const c_void,
                bytes_to_write,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };
        let status = if write_ok == 0 {
            STATUS_ACCESS_VIOLATION
        } else {
            STATUS_SUCCESS
        };

        if io_status != 0
            && write_value(
                io_status,
                IoStatusBlock {
                    status,
                    information: usize::try_from(bytes_written).expect("u32 fits in usize"),
                },
            )
            .is_err()
        {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            file_handle:% = format_args!("{:#x}", ctx.r10),
            event:% = format_args!("{:#x}", ctx.rdx),
            apc_routine:% = format_args!("{:#x}", ctx.r8),
            apc_context:% = format_args!("{:#x}", ctx.r9),
            io_status:% = format_args!("{io_status:#x}"),
            buffer:% = format_args!("{buffer:#x}"),
            length,
            bytes_written,
            byte_offset:% = format_args!("{byte_offset:#x}"),
            key:% = format_args!("{key:#x}"),
            status:% = format_args!("{status:#x}");
            "Handling NtWriteFile syscall"
        );
        ctx.rax = status;
    }

    fn nt_open_file(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let share_access =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));
        let open_options =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_6_OFFSET));

        let object_name =
            read_object_attributes_name(ctx.r8).unwrap_or_else(|| String::from("<unreadable>"));
        let guest_path = windows_object_path_to_guest_path(&object_name);
        let handle = self.insert_handle(WindowsHandleKind::File {
            path: guest_path.clone(),
        });
        if ctx.r10 == 0 || write_value(ctx.r10, handle).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }
        if ctx.r9 != 0
            && write_value(
                ctx.r9,
                IoStatusBlock {
                    status: STATUS_SUCCESS,
                    information: 0,
                },
            )
            .is_err()
        {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            file_handle_ptr:% = format_args!("{:#x}", ctx.r10),
            handle:% = format_args!("{handle:#x}"),
            desired_access:% = format_args!("{:#x}", ctx.rdx),
            object_attributes:% = format_args!("{:#x}", ctx.r8),
            io_status:% = format_args!("{:#x}", ctx.r9),
            share_access:% = format_args!("{share_access:#x}"),
            open_options:% = format_args!("{open_options:#x}"),
            object_name:% = object_name,
            guest_path:% = guest_path;
            "Handling NtOpenFile syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_query_attributes_file(ctx: &mut litebox_common_linux::PtRegs) {
        let object_name =
            read_object_attributes_name(ctx.r10).unwrap_or_else(|| String::from("<unreadable>"));
        let file_attributes = if object_name.ends_with('\\') || object_name.ends_with(':') {
            WINDOWS_FILE_ATTRIBUTE_DIRECTORY
        } else {
            WINDOWS_FILE_ATTRIBUTE_ARCHIVE
        };

        if ctx.rdx == 0
            || write_value(
                ctx.rdx,
                FileBasicInformation {
                    file_attributes,
                    ..Default::default()
                },
            )
            .is_err()
        {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            object_attributes:% = format_args!("{:#x}", ctx.r10),
            file_information:% = format_args!("{:#x}", ctx.rdx),
            object_name:% = object_name,
            file_attributes:% = format_args!("{file_attributes:#x}");
            "Handling NtQueryAttributesFile syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_query_volume_information_file(ctx: &mut litebox_common_linux::PtRegs) {
        let fs_information_class =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));

        ctx.rax = match fs_information_class {
            FILE_FS_SIZE_INFORMATION_CLASS => Self::write_file_fs_information(
                ctx.rdx,
                ctx.r8,
                ctx.r9,
                FileFsSizeInformation {
                    total_allocation_units: 1024 * 1024,
                    available_allocation_units: 512 * 1024,
                    sectors_per_allocation_unit: 8,
                    bytes_per_sector: 512,
                },
            ),
            FILE_FS_DEVICE_INFORMATION_CLASS => Self::write_file_fs_information(
                ctx.rdx,
                ctx.r8,
                ctx.r9,
                FileFsDeviceInformation {
                    device_type: WINDOWS_FILE_DEVICE_DISK,
                    characteristics: 0,
                },
            ),
            FILE_FS_ATTRIBUTE_INFORMATION_CLASS => Self::write_file_fs_information(
                ctx.rdx,
                ctx.r8,
                ctx.r9,
                FileFsAttributeInformation {
                    file_system_attributes: WINDOWS_FILE_CASE_SENSITIVE_SEARCH
                        | WINDOWS_FILE_CASE_PRESERVED_NAMES
                        | WINDOWS_FILE_UNICODE_ON_DISK
                        | WINDOWS_FILE_PERSISTENT_ACLS,
                    maximum_component_name_length: 255,
                    file_system_name_length: 8,
                    file_system_name: [
                        u16::from(b'N'),
                        u16::from(b'T'),
                        u16::from(b'F'),
                        u16::from(b'S'),
                    ],
                },
            ),
            information_class => {
                litebox_util_log::error!(information_class; "NtQueryVolumeInformationFile unsupported information class");
                STATUS_INVALID_INFO_CLASS
            }
        };

        litebox_util_log::debug!(
            file_handle:% = format_args!("{:#x}", ctx.r10),
            io_status:% = format_args!("{:#x}", ctx.rdx),
            fs_information:% = format_args!("{:#x}", ctx.r8),
            length = ctx.r9,
            fs_information_class,
            status:% = format_args!("{:#x}", ctx.rax);
            "Handling NtQueryVolumeInformationFile syscall"
        );
    }

    fn nt_get_cached_signing_level(ctx: &mut litebox_common_linux::PtRegs) {
        let thumbprint_size =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));
        let thumbprint_algorithm =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_6_OFFSET));

        if ctx.rdx != 0 && write_value(ctx.rdx, 0_u32).is_err()
            || ctx.r8 != 0 && write_value(ctx.r8, 0_u8).is_err()
            || thumbprint_size != 0 && write_value(thumbprint_size, 0_u32).is_err()
            || thumbprint_algorithm != 0 && write_value(thumbprint_algorithm, 0_u32).is_err()
        {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            file_handle:% = format_args!("{:#x}", ctx.r10),
            flags:% = format_args!("{:#x}", ctx.rdx),
            signing_level:% = format_args!("{:#x}", ctx.r8),
            thumbprint:% = format_args!("{:#x}", ctx.r9),
            thumbprint_size:% = format_args!("{thumbprint_size:#x}"),
            thumbprint_algorithm:% = format_args!("{thumbprint_algorithm:#x}");
            "Handling NtGetCachedSigningLevel syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_create_section(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let section_page_protection =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));
        let allocation_attributes =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_6_OFFSET));
        let file_handle =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_7_OFFSET));

        let file_path = self.file_path_for_handle(file_handle);
        let handle = self.insert_handle(WindowsHandleKind::Section {
            path: file_path.clone(),
        });
        if ctx.r10 == 0 || write_value(ctx.r10, handle).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            section_handle_ptr:% = format_args!("{:#x}", ctx.r10),
            handle:% = format_args!("{handle:#x}"),
            desired_access:% = format_args!("{:#x}", ctx.rdx),
            object_attributes:% = format_args!("{:#x}", ctx.r8),
            maximum_size:% = format_args!("{:#x}", ctx.r9),
            section_page_protection:% = format_args!("{section_page_protection:#x}"),
            allocation_attributes:% = format_args!("{allocation_attributes:#x}"),
            file_handle:% = format_args!("{file_handle:#x}"),
            file_path:% = file_path.as_deref().unwrap_or("<none>");
            "Handling NtCreateSection syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_open_section(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let object_name = read_object_attributes_name(ctx.r8).unwrap_or_default();
        let section_path = self.section_object_guest_path(&object_name);
        let Some(section_path) = section_path else {
            litebox_util_log::debug!(
                section_handle_ptr:% = format_args!("{:#x}", ctx.r10),
                desired_access:% = format_args!("{:#x}", ctx.rdx),
                object_attributes:% = format_args!("{:#x}", ctx.r8),
                object_name:% = object_name;
                "Handling NtOpenSection as missing named section"
            );
            ctx.rax = STATUS_OBJECT_NAME_NOT_FOUND;
            return;
        };

        let handle = self.insert_handle(WindowsHandleKind::Section {
            path: Some(section_path.clone()),
        });
        if ctx.r10 == 0 || write_value(ctx.r10, handle).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            section_handle_ptr:% = format_args!("{:#x}", ctx.r10),
            handle:% = format_args!("{handle:#x}"),
            desired_access:% = format_args!("{:#x}", ctx.rdx),
            object_attributes:% = format_args!("{:#x}", ctx.r8),
            object_name:% = object_name,
            section_path:% = section_path;
            "Handling NtOpenSection syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_map_view_of_section(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let commit_size =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));
        let section_offset =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_6_OFFSET));
        let view_size = read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_7_OFFSET));
        let inherit_disposition =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_8_OFFSET));
        let allocation_type =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_9_OFFSET));
        let win32_protect =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_10_OFFSET));

        let section_path = self.section_path_for_handle(ctx.r10);
        let (mapped_base, mapped_size, region_name) = match section_path.as_deref() {
            Some(path) if !is_ntdll_guest_path(path) => {
                if let Some((base_addr, image_size)) = self.loaded_module_mapping(path) {
                    (base_addr, image_size, loaded_image_region_name(path))
                } else {
                    match self.load_image(self.fs.clone(), path) {
                        Ok(image) => {
                            let region_name = loaded_image_region_name(path);
                            self.record_named_memory_region(region_name, &image.mapping);
                            self.record_loaded_module(path, &image);
                            self.ensure_import_modules_loaded(&image.imports);
                            self.resolve_image_imports_from_loaded_modules(
                                image.mapping.base_addr,
                                &image.imports,
                                path,
                            );
                            self.resolve_application_imports_from_loaded_modules();
                            (
                                image.mapping.base_addr,
                                image.mapping.image_size,
                                region_name,
                            )
                        }
                        Err(error) => {
                            litebox_util_log::error!(
                                error:%,
                                section_handle:% = format_args!("{:#x}", ctx.r10),
                                section_path:% = path;
                                "NtMapViewOfSection failed to map guest image section"
                            );
                            ctx.rax = STATUS_OBJECT_NAME_NOT_FOUND;
                            return;
                        }
                    }
                }
            }
            _ => {
                let ntdll_base = GUEST_NTDLL_BASE.load(Ordering::Relaxed);
                let ntdll_size = GUEST_NTDLL_SIZE.load(Ordering::Relaxed);
                if ntdll_base == 0 {
                    ctx.rax = STATUS_ACCESS_VIOLATION;
                    return;
                }
                (ntdll_base, ntdll_size, "ntdll")
            }
        };

        if ctx.r8 == 0
            || write_value(ctx.r8, mapped_base).is_err()
            || view_size != 0 && write_value(view_size, mapped_size).is_err()
        {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        self.record_mapped_section_view(
            mapped_base,
            mapped_size,
            section_path.clone(),
            region_name,
        );

        litebox_util_log::debug!(
            section_handle:% = format_args!("{:#x}", ctx.r10),
            section_path:% = section_path.as_deref().unwrap_or("<none>"),
            process_handle:% = format_args!("{:#x}", ctx.rdx),
            base_address_ptr:% = format_args!("{:#x}", ctx.r8),
            mapped_base:% = format_args!("{mapped_base:#x}"),
            zero_bits:% = format_args!("{:#x}", ctx.r9),
            commit_size:% = format_args!("{commit_size:#x}"),
            section_offset:% = format_args!("{section_offset:#x}"),
            view_size:% = format_args!("{view_size:#x}"),
            mapped_size,
            region_name,
            inherit_disposition,
            allocation_type:% = format_args!("{allocation_type:#x}"),
            win32_protect:% = format_args!("{win32_protect:#x}");
            "Handling NtMapViewOfSection syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_are_mapped_files_the_same(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let first_region = self.image_region_containing(ctx.r10);
        let second_region = self.image_region_containing(ctx.rdx);
        let same_mapping = first_region
            .zip(second_region)
            .is_some_and(|(first, second)| first.start == second.start && first.end == second.end);
        litebox_util_log::debug!(
            first_address:% = format_args!("{:#x}", ctx.r10),
            first_region:% = self.describe_guest_address(ctx.r10),
            second_address:% = format_args!("{:#x}", ctx.rdx),
            second_region:% = self.describe_guest_address(ctx.rdx),
            same_mapping;
            "Handling NtAreMappedFilesTheSame syscall"
        );
        ctx.rax = if same_mapping {
            STATUS_SUCCESS
        } else {
            STATUS_NOT_SAME_DEVICE
        };
    }

    fn nt_unmap_view_of_section(&self, ctx: &mut litebox_common_linux::PtRegs) {
        if ctx.rdx == 0 {
            ctx.rax = STATUS_INVALID_PARAMETER;
            return;
        }

        if let Some(view) = self.forget_mapped_section_view(ctx.rdx) {
            litebox_util_log::debug!(
                process_handle:% = format_args!("{:#x}", ctx.r10),
                base_address:% = format_args!("{:#x}", ctx.rdx),
                mapped_base:% = format_args!("{:#x}", view.base_addr),
                mapped_size = view.size,
                section_path:% = view.path.as_deref().unwrap_or("<none>"),
                region_name = view.region_name;
                "Handling NtUnmapViewOfSection syscall"
            );
            ctx.rax = STATUS_SUCCESS;
            return;
        }

        if let Some(region) = self.image_region_containing(ctx.rdx) {
            litebox_util_log::debug!(
                process_handle:% = format_args!("{:#x}", ctx.r10),
                base_address:% = format_args!("{:#x}", ctx.rdx),
                region_name = region.name;
                "Handling NtUnmapViewOfSection for persistent image region"
            );
            ctx.rax = STATUS_SUCCESS;
            return;
        }

        litebox_util_log::debug!(
            process_handle:% = format_args!("{:#x}", ctx.r10),
            base_address:% = format_args!("{:#x}", ctx.rdx),
            base_region:% = self.describe_guest_address(ctx.rdx);
            "NtUnmapViewOfSection target was not a mapped view"
        );
        ctx.rax = STATUS_NOT_MAPPED_VIEW;
    }

    fn write_file_fs_information<GuestValue>(
        io_status_address: usize,
        fs_information_address: usize,
        length: usize,
        value: GuestValue,
    ) -> usize
    where
        GuestValue: FromBytes + IntoBytes,
    {
        let information_length = size_of::<GuestValue>();
        let status = if length < information_length {
            STATUS_INFO_LENGTH_MISMATCH
        } else if fs_information_address == 0 || write_value(fs_information_address, value).is_err()
        {
            STATUS_ACCESS_VIOLATION
        } else {
            STATUS_SUCCESS
        };

        if io_status_address != 0
            && write_value(
                io_status_address,
                IoStatusBlock {
                    status,
                    information: if status == STATUS_SUCCESS {
                        information_length
                    } else {
                        0
                    },
                },
            )
            .is_err()
        {
            return STATUS_ACCESS_VIOLATION;
        }

        status
    }

    fn nt_create_event(ctx: &mut litebox_common_linux::PtRegs) {
        let initial_state_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_5_OFFSET);
        let Some(initial_state_slot) = initial_state_slot else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };
        let Ok(initial_state) = read_value::<u8>(initial_state_slot) else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        let handle = NEXT_SYNTHETIC_HANDLE.fetch_add(4, Ordering::Relaxed);
        if ctx.r10 == 0 || write_value(ctx.r10, handle).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            event_handle_ptr:% = format_args!("{:#x}", ctx.r10),
            handle:% = format_args!("{handle:#x}"),
            desired_access:% = format_args!("{:#x}", ctx.rdx),
            object_attributes:% = format_args!("{:#x}", ctx.r8),
            event_type = ctx.r9,
            initial_state;
            "Handling NtCreateEvent syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_create_io_completion(ctx: &mut litebox_common_linux::PtRegs) {
        let handle = NEXT_SYNTHETIC_HANDLE.fetch_add(4, Ordering::Relaxed);
        if ctx.r10 == 0 || write_value(ctx.r10, handle).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            io_completion_handle_ptr:% = format_args!("{:#x}", ctx.r10),
            handle:% = format_args!("{handle:#x}"),
            desired_access:% = format_args!("{:#x}", ctx.rdx),
            object_attributes:% = format_args!("{:#x}", ctx.r8),
            number_of_concurrent_threads = ctx.r9;
            "Handling NtCreateIoCompletion syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_create_worker_factory(ctx: &mut litebox_common_linux::PtRegs) {
        let worker_process_handle =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));
        let start_routine =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_6_OFFSET));
        let start_parameter =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_7_OFFSET));
        let max_thread_count =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_8_OFFSET));
        let stack_reserve =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_9_OFFSET));
        let stack_commit =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_10_OFFSET));

        let handle = NEXT_SYNTHETIC_HANDLE.fetch_add(4, Ordering::Relaxed);
        if ctx.r10 == 0 || write_value(ctx.r10, handle).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            worker_factory_handle_ptr:% = format_args!("{:#x}", ctx.r10),
            handle:% = format_args!("{handle:#x}"),
            desired_access:% = format_args!("{:#x}", ctx.rdx),
            object_attributes:% = format_args!("{:#x}", ctx.r8),
            completion_port_handle:% = format_args!("{:#x}", ctx.r9),
            worker_process_handle:% = format_args!("{worker_process_handle:#x}"),
            start_routine:% = format_args!("{start_routine:#x}"),
            start_parameter:% = format_args!("{start_parameter:#x}"),
            max_thread_count,
            stack_reserve,
            stack_commit;
            "Handling NtCreateWorkerFactory syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_create_timer2(ctx: &mut litebox_common_linux::PtRegs) {
        let desired_access =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));
        let handle = NEXT_SYNTHETIC_HANDLE.fetch_add(4, Ordering::Relaxed);
        if ctx.r10 == 0 || write_value(ctx.r10, handle).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            timer_handle_ptr:% = format_args!("{:#x}", ctx.r10),
            handle:% = format_args!("{handle:#x}"),
            timer_id:% = format_args!("{:#x}", ctx.rdx),
            object_attributes:% = format_args!("{:#x}", ctx.r8),
            attributes:% = format_args!("{:#x}", ctx.r9),
            desired_access:% = format_args!("{desired_access:#x}");
            "Handling NtCreateTimer2 syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_create_wait_completion_packet(ctx: &mut litebox_common_linux::PtRegs) {
        let handle = NEXT_SYNTHETIC_HANDLE.fetch_add(4, Ordering::Relaxed);
        if ctx.r10 == 0 || write_value(ctx.r10, handle).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            wait_completion_packet_handle_ptr:% = format_args!("{:#x}", ctx.r10),
            handle:% = format_args!("{handle:#x}"),
            desired_access:% = format_args!("{:#x}", ctx.rdx),
            object_attributes:% = format_args!("{:#x}", ctx.r8);
            "Handling NtCreateWaitCompletionPacket syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_associate_wait_completion_packet(ctx: &mut litebox_common_linux::PtRegs) {
        let apc_context =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));
        let io_status = read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_6_OFFSET));
        let io_status_information =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_7_OFFSET));
        let already_signaled =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_8_OFFSET));

        if already_signaled != 0 && write_value(already_signaled, 0u8).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            wait_completion_packet_handle:% = format_args!("{:#x}", ctx.r10),
            io_completion_handle:% = format_args!("{:#x}", ctx.rdx),
            target_object_handle:% = format_args!("{:#x}", ctx.r8),
            key_context:% = format_args!("{:#x}", ctx.r9),
            apc_context:% = format_args!("{apc_context:#x}"),
            io_status:% = format_args!("{io_status:#x}"),
            io_status_information:% = format_args!("{io_status_information:#x}"),
            already_signaled:% = format_args!("{already_signaled:#x}");
            "Handling NtAssociateWaitCompletionPacket syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_set_information_worker_factory(ctx: &mut litebox_common_linux::PtRegs) {
        litebox_util_log::debug!(
            worker_factory_handle:% = format_args!("{:#x}", ctx.r10),
            worker_factory_information_class = ctx.rdx,
            worker_factory_information:% = format_args!("{:#x}", ctx.r8),
            worker_factory_information_length = ctx.r9;
            "Handling NtSetInformationWorkerFactory as no-op"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_set_wnf_process_notification_event(ctx: &mut litebox_common_linux::PtRegs) {
        litebox_util_log::debug!(
            notification_event:% = format_args!("{:#x}", ctx.r10);
            "Handling NtSetWnfProcessNotificationEvent as no-op"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_subscribe_wnf_state_change(ctx: &mut litebox_common_linux::PtRegs) {
        let subscription_id = u64::try_from(NEXT_SYNTHETIC_HANDLE.fetch_add(4, Ordering::Relaxed))
            .unwrap_or(u64::MAX);
        if ctx.r9 != 0 && write_value(ctx.r9, subscription_id).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        let state_name = read_usize_or_zero(ctx.r10);
        litebox_util_log::debug!(
            state_name_ptr:% = format_args!("{:#x}", ctx.r10),
            state_name:% = format_args!("{state_name:#x}"),
            change_stamp = ctx.rdx,
            event_mask:% = format_args!("{:#x}", ctx.r8),
            subscription_id_ptr:% = format_args!("{:#x}", ctx.r9),
            subscription_id:% = format_args!("{subscription_id:#x}");
            "Handling NtSubscribeWnfStateChange syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_trace_control(ctx: &mut litebox_common_linux::PtRegs) {
        let output_buffer_length =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_5_OFFSET));
        let return_length =
            read_usize_or_zero(ctx.rsp.saturating_add(WINDOWS_STACK_ARGUMENT_6_OFFSET));

        if return_length != 0 && write_value(return_length, 0u32).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            function_code:% = format_args!("{:#x}", ctx.r10),
            input_buffer:% = format_args!("{:#x}", ctx.rdx),
            input_buffer_length = ctx.r8,
            output_buffer:% = format_args!("{:#x}", ctx.r9),
            output_buffer_length,
            return_length:% = format_args!("{return_length:#x}");
            "Handling NtTraceControl as no-op"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_query_symbolic_link_object(ctx: &mut litebox_common_linux::PtRegs) {
        ctx.rax = Self::write_symbolic_link_target(ctx.rdx, ctx.r8, SYMBOLIC_LINK_TARGET_PATH);

        litebox_util_log::debug!(
            link_handle:% = format_args!("{:#x}", ctx.r10),
            target_name:% = format_args!("{:#x}", ctx.rdx),
            return_length:% = format_args!("{:#x}", ctx.r8),
            status:% = format_args!("{:#x}", ctx.rax),
            target = SYMBOLIC_LINK_TARGET_PATH;
            "Handling NtQuerySymbolicLinkObject syscall"
        );
    }

    fn write_symbolic_link_target(
        target_name_address: usize,
        return_length_address: usize,
        target: &str,
    ) -> usize {
        let target_code_units = target.encode_utf16().count();
        let Some(target_byte_length) = target_code_units.checked_mul(size_of::<u16>()) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(required_length) = target_byte_length.checked_add(size_of::<u16>()) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Ok(required_length_u32) = u32::try_from(required_length) else {
            return STATUS_INVALID_PARAMETER;
        };

        if return_length_address != 0
            && write_value(return_length_address, required_length_u32).is_err()
        {
            return STATUS_ACCESS_VIOLATION;
        }

        let Ok(mut target_name) = read_value::<UnicodeString>(target_name_address) else {
            return STATUS_ACCESS_VIOLATION;
        };
        if usize::from(target_name.maximum_length) < required_length {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        if target_name.buffer == 0 {
            return STATUS_ACCESS_VIOLATION;
        }

        for (index, code_unit) in target.encode_utf16().enumerate() {
            let Some(offset) = index.checked_mul(size_of::<u16>()) else {
                return STATUS_INVALID_PARAMETER;
            };
            let Some(address) = target_name.buffer.checked_add(offset) else {
                return STATUS_ACCESS_VIOLATION;
            };
            if write_value(address, code_unit).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
        }

        let Some(null_address) = target_name.buffer.checked_add(target_byte_length) else {
            return STATUS_ACCESS_VIOLATION;
        };
        if write_value(null_address, 0u16).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }

        let Ok(length) = u16::try_from(target_byte_length) else {
            return STATUS_INVALID_PARAMETER;
        };
        target_name.length = length;
        if write_value(target_name_address, target_name).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }

        STATUS_SUCCESS
    }

    fn nt_set_event(ctx: &mut litebox_common_linux::PtRegs) {
        if ctx.rdx != 0 && write_value(ctx.rdx, 0i32).is_err() {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        }

        litebox_util_log::debug!(
            event_handle:% = format_args!("{:#x}", ctx.r10),
            previous_state_ptr:% = format_args!("{:#x}", ctx.rdx);
            "Handling NtSetEvent syscall"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_query_system_information(&self, ctx: &mut litebox_common_linux::PtRegs) {
        ctx.rax = match ctx.r10 {
            SYSTEM_BASIC_INFORMATION_CLASS | SYSTEM_EMULATION_BASIC_INFORMATION_CLASS => {
                Self::write_u32_length_information(
                    ctx.rdx,
                    ctx.r8,
                    ctx.r9,
                    Self::system_basic_information(),
                )
            }
            SYSTEM_FLUSH_INFORMATION_CLASS => Self::write_u32_length_information(
                ctx.rdx,
                ctx.r8,
                ctx.r9,
                Self::system_flush_information(),
            ),
            SYSTEM_NUMA_PROCESSOR_MAP_CLASS => Self::write_u32_length_information(
                ctx.rdx,
                ctx.r8,
                ctx.r9,
                Self::system_numa_information(),
            ),
            SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION_CLASS => Self::write_u32_length_information(
                ctx.rdx,
                ctx.r8,
                ctx.r9,
                SystemHypervisorSharedPageInformation::default(),
            ),
            SYSTEM_PROCESSOR_FEATURES_BITMAP_INFORMATION_CLASS => {
                self.write_processor_feature_bitmap_information(ctx.rdx, ctx.r8, ctx.r9)
            }
            system_information_class => {
                litebox_util_log::error!(system_information_class; "NtQuerySystemInformation unsupported information class");
                STATUS_INVALID_INFO_CLASS
            }
        };

        let guest_return_address = read_value::<usize>(ctx.rsp).unwrap_or_default();
        litebox_util_log::debug!(
            system_information_class = ctx.r10,
            information:% = format_args!("{:#x}", ctx.rdx),
            len = ctx.r8,
            return_length:% = format_args!("{:#x}", ctx.r9),
            status:% = format_args!("{:#x}", ctx.rax),
            rip:% = format_args!("{:#x}", ctx.rip),
            rip_region:% = self.describe_guest_address(ctx.rip),
            rcx:% = format_args!("{:#x}", ctx.rcx),
            rcx_region:% = self.describe_guest_address(ctx.rcx),
            guest_return_address:% = format_args!("{guest_return_address:#x}");
            "Handling NtQuerySystemInformation syscall"
        );
    }

    fn system_numa_information() -> SystemNumaInformation {
        let mut information = SystemNumaInformation::default();
        information.active_processors_group_affinity[0].mask = 1;
        information
    }

    fn system_flush_information() -> SystemFlushInformation {
        SystemFlushInformation {
            supported_flush_methods: SYSTEM_SUPPORTED_FLUSH_METHODS,
            processor_cache_flush_size: SYSTEM_PROCESSOR_CACHE_FLUSH_SIZE,
            ..SystemFlushInformation::default()
        }
    }

    fn write_processor_feature_bitmap_information(
        &self,
        information_address: usize,
        information_length: usize,
        return_length_address: usize,
    ) -> usize {
        let bitmap_address = self
            .teb_address
            .saturating_add(TEB_PROCESSOR_FEATURES_BITMAP_OFFSET);
        if write_value(
            bitmap_address,
            WindowsShim::<FS>::processor_feature_bitmap_words(),
        )
        .is_err()
        {
            return STATUS_ACCESS_VIOLATION;
        }

        Self::write_u32_length_information(
            information_address,
            information_length,
            return_length_address,
            RtlBitmapEx {
                size_of_bit_map: 64,
                buffer: bitmap_address,
            },
        )
    }

    fn nt_query_system_information_ex(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let system_information_length_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_5_OFFSET);
        let return_length_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_6_OFFSET);
        let Some(system_information_length_slot) = system_information_length_slot else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };
        let Some(return_length_slot) = return_length_slot else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };
        let Ok(system_information_length) = read_value::<u32>(system_information_length_slot)
        else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };
        let Ok(return_length_address) = read_value::<usize>(return_length_slot) else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        let guest_return_address = read_value::<usize>(ctx.rsp).unwrap_or_default();
        let input_word0 = read_usize_or_zero(ctx.rdx);
        let input_word1 = read_usize_or_zero(ctx.rdx.saturating_add(size_of::<usize>()));
        ctx.rax = match ctx.r10 {
            SYSTEM_LOGICAL_PROCESSOR_AND_GROUP_INFORMATION_CLASS => {
                Self::write_u32_length_information(
                    ctx.r9,
                    system_information_length as usize,
                    return_length_address,
                    Self::system_logical_processor_group_information(),
                )
            }
            SYSTEM_FEATURE_CONFIGURATION_INFORMATION_CLASS => {
                if ctx.rdx == 0 || ctx.r8 < size_of::<u32>() * 2 {
                    STATUS_INVALID_PARAMETER
                } else {
                    match read_value::<u32>(ctx.rdx.saturating_add(size_of::<u32>())) {
                        Ok(feature_id) => Self::write_u32_length_information(
                            ctx.r9,
                            system_information_length as usize,
                            return_length_address,
                            SystemFeatureConfigurationInformation::new(feature_id),
                        ),
                        Err(_) => STATUS_ACCESS_VIOLATION,
                    }
                }
            }
            SYSTEM_FEATURE_CONFIGURATION_SECTION_INFORMATION_CLASS => {
                Self::write_u32_length_information(
                    ctx.r9,
                    system_information_length as usize,
                    return_length_address,
                    SystemFeatureConfigurationSectionsInformation::default(),
                )
            }
            system_information_class => {
                litebox_util_log::error!(system_information_class; "NtQuerySystemInformationEx unsupported information class");
                STATUS_INVALID_INFO_CLASS
            }
        };

        litebox_util_log::debug!(
            system_information_class = ctx.r10,
            input_buffer:% = format_args!("{:#x}", ctx.rdx),
            input_buffer_length = ctx.r8,
            system_information:% = format_args!("{:#x}", ctx.r9),
            system_information_length,
            return_length:% = format_args!("{return_length_address:#x}"),
            input_word0:% = format_args!("{input_word0:#x}"),
            input_word1:% = format_args!("{input_word1:#x}"),
            status:% = format_args!("{:#x}", ctx.rax),
            rip:% = format_args!("{:#x}", ctx.rip),
            rip_region:% = self.describe_guest_address(ctx.rip),
            guest_return_address:% = format_args!("{guest_return_address:#x}");
            "Handling NtQuerySystemInformationEx syscall"
        );
    }

    fn system_logical_processor_group_information() -> SystemLogicalProcessorGroupInformation {
        let size =
            u32::try_from(size_of::<SystemLogicalProcessorGroupInformation>()).unwrap_or(u32::MAX);

        SystemLogicalProcessorGroupInformation {
            relationship: LOGICAL_PROCESSOR_RELATIONSHIP_GROUP,
            size,
            group: GroupRelationship {
                maximum_group_count: 1,
                active_group_count: 1,
                group_info: ProcessorGroupInfo {
                    maximum_processor_count: 1,
                    active_processor_count: 1,
                    active_processor_mask: 1,
                    ..ProcessorGroupInfo::default()
                },
                ..GroupRelationship::default()
            },
        }
    }

    fn system_basic_information() -> SystemBasicInformation {
        SystemBasicInformation {
            timer_resolution: 156_250,
            page_size: WINDOWS_PAGE_SIZE_U32,
            number_of_physical_pages: 1024 * 1024,
            allocation_granularity: WINDOWS_ALLOCATION_GRANULARITY,
            minimum_user_mode_address: WINDOWS_MINIMUM_USER_ADDRESS,
            maximum_user_mode_address: WINDOWS_MAXIMUM_USER_ADDRESS,
            active_processors_affinity_mask: 1,
            number_of_processors: 1,
            ..SystemBasicInformation::default()
        }
    }

    fn write_u32_length_information<GuestValue>(
        information_address: usize,
        information_length: usize,
        return_length_address: usize,
        value: GuestValue,
    ) -> usize
    where
        GuestValue: FromBytes + IntoBytes,
    {
        let required_length = size_of::<GuestValue>();
        let Ok(required_length_u32) = u32::try_from(required_length) else {
            return STATUS_INVALID_PARAMETER;
        };

        if return_length_address != 0
            && write_value(return_length_address, required_length_u32).is_err()
        {
            return STATUS_ACCESS_VIOLATION;
        }

        if information_length < required_length {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if information_address == 0 || write_value(information_address, value).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }

        STATUS_SUCCESS
    }

    fn nt_query_information_process(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let return_length_slot = ctx.rsp.checked_add(WINDOWS_STACK_ARGUMENT_5_OFFSET);
        let Some(return_length_slot) = return_length_slot else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };
        let Ok(return_length_address) = read_value::<usize>(return_length_slot) else {
            ctx.rax = STATUS_ACCESS_VIOLATION;
            return;
        };

        ctx.rax = match ctx.rdx {
            PROCESS_BASIC_INFORMATION_CLASS => Self::write_memory_information(
                ctx.r8,
                ctx.r9,
                return_length_address,
                ProcessBasicInformation {
                    peb_base_address: self.peb_address,
                    affinity_mask: 1,
                    base_priority: 8,
                    unique_process_id: INITIAL_PROCESS_ID,
                    inherited_from_unique_process_id: 0,
                    ..ProcessBasicInformation::default()
                },
            ),
            PROCESS_COOKIE_INFORMATION_CLASS => Self::write_memory_information(
                ctx.r8,
                ctx.r9,
                return_length_address,
                0x2b99_2ddf_u32,
            ),
            process_information_class => {
                litebox_util_log::error!(process_information_class; "NtQueryInformationProcess unsupported information class");
                STATUS_INVALID_INFO_CLASS
            }
        };

        if ctx.rax == STATUS_SUCCESS {
            litebox_util_log::debug!(
                process_handle:% = format_args!("{:#x}", ctx.r10),
                process_information_class = ctx.rdx,
                information:% = format_args!("{:#x}", ctx.r8),
                len = ctx.r9,
                return_length:% = format_args!("{:#x}", return_length_address),
                peb:% = format_args!("{:#x}", self.peb_address);
                "Handling NtQueryInformationProcess syscall"
            );
        }
    }

    fn nt_set_information_process(&self, ctx: &mut litebox_common_linux::PtRegs) {
        if ctx.rdx == PROCESS_SCHEDULER_SHARED_DATA_CLASS {
            let scheduler_shared_data = read_usize_or_zero(ctx.r8);
            let fallback_scheduler_shared_data = self.scheduler_shared_data_storage_address();
            let status = if ctx.r8 == 0
                || ctx.r9 < size_of::<usize>()
                || write_value(ctx.r8, fallback_scheduler_shared_data).is_err()
            {
                STATUS_ACCESS_VIOLATION
            } else {
                STATUS_SUCCESS
            };
            litebox_util_log::debug!(
                process_handle:% = format_args!("{:#x}", ctx.r10),
                information:% = format_args!("{:#x}", ctx.r8),
                scheduler_shared_data:% = format_args!("{scheduler_shared_data:#x}"),
                fallback_scheduler_shared_data:% = format_args!("{fallback_scheduler_shared_data:#x}"),
                status:% = format_args!("{status:#x}"),
                len = ctx.r9;
                "Handling NtSetInformationProcess(ProcessSchedulerSharedData)"
            );
            ctx.rax = status;
            return;
        }

        litebox_util_log::debug!(
            process_handle:% = format_args!("{:#x}", ctx.r10),
            process_information_class = ctx.rdx,
            information:% = format_args!("{:#x}", ctx.r8),
            len = ctx.r9;
            "Handling NtSetInformationProcess as no-op"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn nt_set_information_thread(&self, ctx: &mut litebox_common_linux::PtRegs) {
        if ctx.rdx == THREAD_SCHEDULER_SHARED_DATA_SLOT_CLASS {
            ctx.rax = self.set_thread_scheduler_shared_data_slot(ctx.r8, ctx.r9);
            return;
        }

        litebox_util_log::debug!(
            thread_handle:% = format_args!("{:#x}", ctx.r10),
            thread_information_class = ctx.rdx,
            information:% = format_args!("{:#x}", ctx.r8),
            len = ctx.r9;
            "Handling NtSetInformationThread as no-op"
        );
        ctx.rax = STATUS_SUCCESS;
    }

    fn set_thread_scheduler_shared_data_slot(
        &self,
        information_address: usize,
        information_length: usize,
    ) -> usize {
        if information_address == 0
            || information_length < size_of::<SchedulerSharedDataSlotInformation>()
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        let Ok(mut information) =
            read_value::<SchedulerSharedDataSlotInformation>(information_address)
        else {
            return STATUS_ACCESS_VIOLATION;
        };

        let teb_slot_address = self
            .teb_address
            .saturating_add(TEB_SCHEDULER_SHARED_DATA_SLOT_OFFSET);
        let fallback_slot = self.scheduler_shared_data_storage_address();
        let existing_slot = read_usize_or_zero(teb_slot_address);
        let mut selected_slot = information.slot;
        if selected_slot == 0 {
            selected_slot = if existing_slot != 0 {
                existing_slot
            } else {
                fallback_slot
            };
        }

        let status = match information.action {
            SCHEDULER_SHARED_SLOT_ASSIGN | SCHEDULER_SHARED_SLOT_QUERY => {
                let fallback_write_failed =
                    selected_slot == fallback_slot && write_value(fallback_slot, 0u64).is_err();
                if fallback_write_failed || write_value(teb_slot_address, selected_slot).is_err() {
                    STATUS_ACCESS_VIOLATION
                } else {
                    if information.scheduler_shared_data_handle == 0 {
                        information.scheduler_shared_data_handle = selected_slot;
                    }
                    information.slot = selected_slot;
                    if write_value(information_address, information).is_err() {
                        STATUS_ACCESS_VIOLATION
                    } else {
                        STATUS_SUCCESS
                    }
                }
            }
            SCHEDULER_SHARED_SLOT_FREE => {
                if write_value(teb_slot_address, 0usize).is_err() {
                    STATUS_ACCESS_VIOLATION
                } else {
                    information.slot = 0;
                    let _ = write_value(information_address, information);
                    STATUS_SUCCESS
                }
            }
            _ => STATUS_INVALID_PARAMETER,
        };

        litebox_util_log::debug!(
            action = information.action,
            scheduler_shared_data_handle:% = format_args!("{:#x}", information.scheduler_shared_data_handle),
            slot:% = format_args!("{:#x}", information.slot),
            teb_slot:% = format_args!("{teb_slot_address:#x}"),
            fallback_slot:% = format_args!("{fallback_slot:#x}"),
            status:% = format_args!("{status:#x}");
            "Handling NtSetInformationThread(ThreadSchedulerSharedDataSlot)"
        );

        status
    }

    fn scheduler_shared_data_storage_address(&self) -> usize {
        self.teb_address
            .saturating_add(TEB_SCHEDULER_SHARED_DATA_STORAGE_OFFSET)
    }

    fn write_memory_information<GuestValue>(
        information_address: usize,
        information_length: usize,
        return_length_address: usize,
        value: GuestValue,
    ) -> usize
    where
        GuestValue: FromBytes + IntoBytes,
    {
        let required_length = size_of::<GuestValue>();
        if return_length_address != 0
            && write_value(return_length_address, required_length).is_err()
        {
            return STATUS_ACCESS_VIOLATION;
        }

        if information_length < required_length {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if information_address == 0 || write_value(information_address, value).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }

        STATUS_SUCCESS
    }

    fn memory_basic_information(&self, address: usize) -> MemoryBasicInformation {
        let page_base = page_align_down(address);
        let Some(region) = self.guest_region(address) else {
            return MemoryBasicInformation {
                base_address: page_base,
                allocation_base: 0,
                allocation_protect: WINDOWS_PAGE_NOACCESS,
                region_size: PAGE_SIZE,
                state: WINDOWS_MEM_FREE,
                protect: WINDOWS_PAGE_NOACCESS,
                type_: 0,
                ..MemoryBasicInformation::default()
            };
        };

        let (protect, type_) = if region.is_image() {
            (WINDOWS_PAGE_EXECUTE_READWRITE, WINDOWS_MEM_IMAGE)
        } else {
            (WINDOWS_PAGE_READWRITE, WINDOWS_MEM_PRIVATE)
        };

        MemoryBasicInformation {
            base_address: region.start,
            allocation_base: region.start,
            allocation_protect: protect,
            region_size: region.end - region.start,
            state: WINDOWS_MEM_COMMIT,
            protect,
            type_,
            ..MemoryBasicInformation::default()
        }
    }

    fn memory_image_information(&self, address: usize) -> Option<MemoryImageInformation> {
        let region = self
            .guest_region(address)
            .filter(GuestAddressRegion::is_image)?;
        Some(MemoryImageInformation {
            image_base: region.start,
            size_of_image: region.end - region.start,
            image_flags: 0,
            ..MemoryImageInformation::default()
        })
    }

    fn memory_image_extension_information(
        &self,
        address: usize,
        information_address: usize,
    ) -> Option<MemoryImageExtensionInformation> {
        self.guest_region(address)
            .filter(GuestAddressRegion::is_image)?;

        let extension_type = if information_address == 0 {
            0
        } else {
            read_value::<MemoryImageExtensionInformation>(information_address)
                .map(|information| information.extension_type)
                .unwrap_or(0)
        };

        Some(MemoryImageExtensionInformation {
            extension_type,
            ..MemoryImageExtensionInformation::default()
        })
    }

    fn write_working_set_ex_information(
        &self,
        base_address: usize,
        information_address: usize,
        information_length: usize,
        return_length_address: usize,
    ) -> usize {
        let entry_size = size_of::<MemoryWorkingSetExInformation>();
        if information_length < entry_size {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if return_length_address != 0 && write_value(return_length_address, entry_size).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }

        let Ok(mut information) = read_value::<MemoryWorkingSetExInformation>(information_address)
        else {
            return STATUS_ACCESS_VIOLATION;
        };

        if information.virtual_address == 0 {
            information.virtual_address = base_address;
        }

        information.virtual_attributes =
            self.guest_region(information.virtual_address)
                .map_or(0, |region| {
                    let protection = if region.is_image() {
                        WINDOWS_PAGE_EXECUTE_READ
                    } else {
                        WINDOWS_PAGE_READWRITE
                    };
                    1 | (usize::try_from(protection)
                        .expect("Windows page protection fits in usize")
                        << 4)
                });

        if write_value(information_address, information).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }

        STATUS_SUCCESS
    }

    fn guest_region(&self, address: usize) -> Option<GuestAddressRegion> {
        self.diagnostic_regions
            .lock()
            .iter()
            .copied()
            .find(|region| region.contains(address))
    }

    fn describe_guest_address(&self, address: usize) -> String {
        if let Some(region) = self.guest_region(address) {
            return format!(
                "{}+{:#x} [{:#x}..{:#x})",
                region.name,
                address - region.start,
                region.start,
                region.end
            );
        }
        format!("unknown({address:#x})")
    }
}

fn windows_exit_status_to_i32(status: usize) -> i32 {
    let low_bits = u32::try_from(status & 0xffff_ffff).unwrap_or_default();
    i32::from_ne_bytes(low_bits.to_ne_bytes())
}

/// A loaded Windows program and the process handle used to wait for it.
pub struct LoadedProgram<FS: NtShimFS> {
    pub entrypoints: WindowsShimEntrypoints<FS>,
    pub process: WindowsShimProcess,
}

/// A placeholder handle to a process loaded via [`WindowsShim::load_program`].
pub struct WindowsShimProcess {
    mapping: MappingInfo,
    _ntdll_mapping: Option<MappingInfo>,
    exit_code: Arc<AtomicI32>,
}

struct LoadedImage {
    mapping: MappingInfo,
    imports: Vec<PeImport>,
    exports: Vec<PeExport>,
    has_trampoline: bool,
}

impl LoadedImage {
    fn export_address(&self, name: &[u8]) -> Result<Option<usize>, PeImageAccessError> {
        let Some(export) = self.exports.iter().find(|export| export.name == name) else {
            return Ok(None);
        };
        if export.forwarder.is_some() {
            return Ok(None);
        }
        let rva = usize::try_from(export.rva).map_err(|_| PeImageAccessError::AddressOverflow)?;
        self.mapping
            .base_addr
            .checked_add(rva)
            .ok_or(PeImageAccessError::AddressOverflow)
            .map(Some)
    }
}

struct WindowsProcessEnvironment {
    peb: usize,
    ldr_data: usize,
    ldr_entries: usize,
    ldr_tail_entry: Option<usize>,
    process_parameters: usize,
    process_heap: usize,
    fast_peb_lock: usize,
    api_set_namespace: usize,
    initial_thread_context: usize,
    system_dll_init_block: usize,
    teb: usize,
}

struct InitialLdrEntries {
    first: Option<usize>,
    last: Option<usize>,
}

impl WindowsShimProcess {
    /// Returns information about the loaded PE image mapping.
    #[must_use]
    pub fn mapping(&self) -> &MappingInfo {
        &self.mapping
    }

    /// Wait for the process to exit, returning its exit code.
    #[must_use]
    pub fn wait(&self) -> i32 {
        // TODO: Wait for the NT process object once process lifecycle exists.
        self.exit_code.load(Ordering::Relaxed)
    }
}

/// Errors that can occur while opening, parsing, and mapping a Windows PE image.
#[derive(Debug, Error)]
pub enum WindowsLoadError {
    /// PE parsing failed.
    #[error("failed to parse PE image")]
    Parse(#[source] PeParseError<PeImageAccessError>),
    /// PE image mapping failed.
    #[error("failed to load PE image")]
    Load(#[source] PeLoadError<PeImageAccessError>),
    /// Opening the PE image failed.
    #[error(transparent)]
    Access(#[from] PeImageAccessError),
    /// Guest ntdll.dll does not export LdrInitializeThunk.
    #[error("guest ntdll.dll does not export LdrInitializeThunk")]
    MissingNtDllLoaderEntrypoint,
    /// Guest ntdll.dll is required for the selected load mode but was not found.
    #[error("guest ntdll.dll is required for the selected Windows load mode")]
    MissingNtDll,
    /// Guest ntdll.dll has not been rewritten for LiteBox syscall/GS handling.
    #[error("guest ntdll.dll must be rewritten for LiteBox before entering its loader")]
    UnrewrittenNtDll,
    /// A PE import library is not provided by the built-in import resolver.
    #[error("unsupported Windows import library {0:?}")]
    UnsupportedImportLibrary(Vec<u8>),
    /// A named PE import is not provided by the built-in import resolver.
    #[error("unsupported Windows import {library:?}!{name:?}")]
    UnsupportedImportName { library: Vec<u8>, name: Vec<u8> },
    /// An ordinal PE import is not provided by the built-in import resolver.
    #[error("unsupported Windows import {library:?}!#{ordinal}")]
    UnsupportedImportOrdinal { library: Vec<u8>, ordinal: u16 },
}

/// Errors from the shim-side PE image backing file and memory mapper.
#[derive(Debug, Error)]
pub enum PeImageAccessError {
    /// Opening the executable failed.
    #[error("failed to open PE image")]
    Open(#[from] litebox::fs::errors::OpenError),
    /// Reading the executable failed.
    #[error("failed to read PE image")]
    Read(#[from] litebox::fs::errors::ReadError),
    /// Reading file metadata failed.
    #[error("failed to read PE image metadata")]
    FileStatus(#[from] litebox::fs::errors::FileStatusError),
    /// The backing file ended before the requested range was read.
    #[error("short read from PE image")]
    ShortRead,
    /// A PE file offset or image address overflowed this host representation.
    #[error("PE image address overflow")]
    AddressOverflow,
    /// A memory mapping operation failed.
    #[error(transparent)]
    Mapping(#[from] MappingError),
    /// A memory protection operation failed.
    #[error(transparent)]
    Protect(#[from] VmemProtectError),
    /// A mapped memory access failed.
    #[error("mapped PE image memory access failed")]
    MemoryAccess,
}

fn is_missing_file_error(error: &WindowsLoadError) -> bool {
    let WindowsLoadError::Access(PeImageAccessError::Open(error)) = error else {
        return false;
    };

    matches!(
        error,
        litebox::fs::errors::OpenError::PathError(
            litebox::fs::errors::PathError::NoSuchFileOrDirectory
                | litebox::fs::errors::PathError::MissingComponent
        )
    )
}

fn set_guest_teb(teb_address: usize) -> bool {
    let punchthrough = litebox_common_linux::PunchthroughSyscall::SetFsBase { addr: teb_address };
    let Some(token) =
        litebox_platform_multiplex::platform().get_punchthrough_token_for(punchthrough)
    else {
        litebox_util_log::warn!(teb:% = format_args!("{teb_address:#x}"); "Failed to get punchthrough token for Windows TEB base");
        return false;
    };

    if let Err(error) = token.execute() {
        litebox_util_log::warn!(error:? = error, teb:% = format_args!("{teb_address:#x}"); "Failed to set Windows TEB base");
        return false;
    }

    true
}

fn read_value<GuestValue>(address: usize) -> Result<GuestValue, PeImageAccessError>
where
    GuestValue: FromBytes,
{
    let ptr = <Platform as RawPointerProvider>::RawConstPointer::<GuestValue>::from_usize(address);
    ptr.read_at_offset(0)
        .ok_or(PeImageAccessError::MemoryAccess)
}

fn read_usize_or_zero(address: usize) -> usize {
    read_value::<usize>(address).unwrap_or(0)
}

fn read_guest_unicode_string(address: usize) -> Option<String> {
    let unicode_string = read_value::<UnicodeString>(address).ok()?;
    if unicode_string.length == 0 {
        return Some(String::new());
    }
    if unicode_string.buffer == 0 || unicode_string.length % 2 != 0 {
        return None;
    }

    read_utf16_string(unicode_string.buffer, unicode_string.length).ok()
}

fn read_utf16_string(address: usize, byte_length: u16) -> Result<String, PeImageAccessError> {
    if !byte_length.is_multiple_of(2) {
        return Err(PeImageAccessError::MemoryAccess);
    }

    let code_unit_count = usize::from(byte_length) / size_of::<u16>();
    let mut code_units = Vec::with_capacity(code_unit_count);
    for index in 0..code_unit_count {
        let offset = index
            .checked_mul(size_of::<u16>())
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let address = address
            .checked_add(offset)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        code_units.push(read_value::<u16>(address)?);
    }

    String::from_utf16(&code_units).map_err(|_| PeImageAccessError::MemoryAccess)
}

fn read_object_attributes_name(address: usize) -> Option<String> {
    let object_attributes = read_value::<ObjectAttributes>(address).ok()?;
    if object_attributes.object_name == 0 {
        return Some(String::new());
    }

    read_guest_unicode_string(object_attributes.object_name)
}

fn write_value<GuestValue>(address: usize, value: GuestValue) -> Result<(), PeImageAccessError>
where
    GuestValue: FromBytes + IntoBytes,
{
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<GuestValue>::from_usize(address);
    ptr.write_at_offset(0, value)
        .ok_or(PeImageAccessError::MemoryAccess)
}

fn write_initial_api_set_namespace(address: usize) -> Result<(), PeImageAccessError> {
    if let Some(host_namespace) = host_api_set_namespace() {
        if host_namespace.len() <= INITIAL_API_SET_NAMESPACE_SIZE {
            let namespace = read_host_api_set_namespace_header(host_namespace)?;
            let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
            ptr.copy_from_slice(0, host_namespace)
                .ok_or(PeImageAccessError::MemoryAccess)?;
            litebox_util_log::debug!(
                address:% = format_args!("{address:#x}"),
                size = host_namespace.len(),
                version = namespace.version,
                count = namespace.count,
                entry_offset:% = format_args!("{:#x}", namespace.entry_offset),
                hash_offset:% = format_args!("{:#x}", namespace.hash_offset),
                hash_factor = namespace.hash_factor;
                "Copied host API-set namespace into guest PEB"
            );
            return Ok(());
        }

        litebox_util_log::warn!(
            address:% = format_args!("{address:#x}"),
            size = host_namespace.len(),
            capacity = INITIAL_API_SET_NAMESPACE_SIZE;
            "Host API-set namespace is too large for the initial guest allocation"
        );
    }

    write_value(address, ApiSetNamespace::empty())
}

fn read_host_api_set_namespace_header(
    host_namespace: &[u8],
) -> Result<ApiSetNamespace, PeImageAccessError> {
    let header = host_namespace
        .get(..size_of::<ApiSetNamespace>())
        .ok_or(PeImageAccessError::MemoryAccess)?;
    ApiSetNamespace::read_from_bytes(header).map_err(|_| PeImageAccessError::MemoryAccess)
}

fn host_api_set_namespace() -> Option<&'static [u8]> {
    let peb = host_peb_address()?;
    // SAFETY: `peb` is read from the current host TEB, and ApiSetMap is a pointer-sized
    // field at a fixed x64 PEB offset for the Windows process hosting this runner.
    let api_set_map_address =
        unsafe { (peb.checked_add(HOST_PEB_API_SET_MAP_OFFSET)? as *const usize).read_unaligned() };
    if api_set_map_address == 0 {
        return None;
    }

    // SAFETY: ApiSetMap points at the process-global API-set namespace header owned by Windows.
    let namespace = unsafe { (api_set_map_address as *const ApiSetNamespace).read_unaligned() };
    let size = usize::try_from(namespace.size).ok()?;
    if !(size_of::<ApiSetNamespace>()..=INITIAL_API_SET_NAMESPACE_SIZE).contains(&size) {
        return None;
    }

    // SAFETY: The size was read from the host API-set namespace header and capped to the
    // guest allocation size before exposing the immutable byte range.
    Some(unsafe { core::slice::from_raw_parts(api_set_map_address as *const u8, size) })
}

fn host_peb_address() -> Option<usize> {
    let peb: usize;
    // SAFETY: On Windows x86-64, GS points at the current host TEB and offset 0x60 is the PEB.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[{}]",
            out(reg) peb,
            const HOST_TEB_PEB_OFFSET,
            options(nostack, readonly, preserves_flags),
        );
    }
    (peb != 0).then_some(peb)
}

fn initial_dos_image_path(path: &str) -> String {
    let file_name = path.rsplit('/').next().unwrap_or(path);
    let mut dos_path = String::from("C:\\");
    dos_path.push_str(file_name);
    dos_path
}

fn initial_image_base_name(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

fn write_utf16_string(cursor: &mut usize, text: &str) -> Result<UnicodeString, PeImageAccessError> {
    let code_units = text.encode_utf16().count();
    let byte_len = code_units
        .checked_mul(size_of::<u16>())
        .ok_or(PeImageAccessError::AddressOverflow)?;
    let maximum_byte_len = byte_len
        .checked_add(size_of::<u16>())
        .ok_or(PeImageAccessError::AddressOverflow)?;
    let buffer = *cursor;

    for (index, code_unit) in text.encode_utf16().chain(core::iter::once(0)).enumerate() {
        let offset = index
            .checked_mul(size_of::<u16>())
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let address = buffer
            .checked_add(offset)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        write_value(address, code_unit)?;
    }

    *cursor = align_up(
        buffer
            .checked_add(maximum_byte_len)
            .ok_or(PeImageAccessError::AddressOverflow)?,
        size_of::<usize>(),
    )?;
    Ok(UnicodeString {
        length: u16::try_from(byte_len).map_err(|_| PeImageAccessError::AddressOverflow)?,
        maximum_length: u16::try_from(maximum_byte_len)
            .map_err(|_| PeImageAccessError::AddressOverflow)?,
        buffer,
        ..Default::default()
    })
}

fn align_up(value: usize, alignment: usize) -> Result<usize, PeImageAccessError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(PeImageAccessError::AddressOverflow)?;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .ok_or(PeImageAccessError::AddressOverflow)
}

fn format_stack_words(stack_pointer: usize, count: usize) -> String {
    let mut output = String::new();
    for index in 0..count {
        if index != 0 {
            output.push(' ');
        }
        let address = stack_pointer.saturating_add(index.saturating_mul(size_of::<usize>()));
        let _ = write!(&mut output, "{:#x}", read_usize_or_zero(address));
    }
    output
}

fn initial_context_address_on_stack(stack_top: usize) -> Result<usize, PeImageAccessError> {
    align_down(stack_top, 16)?
        .checked_sub(size_of::<InitialThreadContext>())
        .ok_or(PeImageAccessError::AddressOverflow)
}

fn align_down(value: usize, alignment: usize) -> Result<usize, PeImageAccessError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(PeImageAccessError::AddressOverflow)?;
    Ok(value & !mask)
}

fn write_absolute_jump(
    page_manager: &WindowsPageManager,
    address: usize,
    target: usize,
) -> Result<(), PeImageAccessError> {
    let mut jump = [0u8; 12];
    jump[0] = 0x48;
    jump[1] = 0xb8;
    jump[2..10].copy_from_slice(&target.to_le_bytes());
    jump[10] = 0xff;
    jump[11] = 0xe0;

    make_pages_writable(page_manager, address, jump.len())?;
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
    ptr.copy_from_slice(0, &jump)
        .ok_or(PeImageAccessError::MemoryAccess)?;
    protect_pages(
        page_manager,
        address,
        jump.len(),
        Protection {
            read: true,
            write: false,
            execute: true,
        },
    )
}

fn write_code_bytes(
    page_manager: &WindowsPageManager,
    address: usize,
    bytes: &[u8],
) -> Result<(), PeImageAccessError> {
    make_pages_writable(page_manager, address, bytes.len())?;
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
    ptr.copy_from_slice(0, bytes)
        .ok_or(PeImageAccessError::MemoryAccess)?;
    protect_pages(
        page_manager,
        address,
        bytes.len(),
        Protection {
            read: true,
            write: false,
            execute: true,
        },
    )
}

struct PeImageFile<FS: NtShimFS> {
    fs: Arc<FS>,
    fd: TypedFd<FS>,
}

impl<FS: NtShimFS> PeImageFile<FS> {
    fn open(fs: Arc<FS>, path: &str) -> Result<Self, PeImageAccessError> {
        let fd = fs.open(path, OFlags::RDONLY, Mode::empty())?;
        Ok(Self { fs, fd })
    }

    fn read_exact_at(
        &self,
        mut offset: usize,
        mut buf: &mut [u8],
    ) -> Result<(), PeImageAccessError> {
        while !buf.is_empty() {
            let bytes_read = self.fs.read(&self.fd, buf, Some(offset))?;
            if bytes_read == 0 {
                return Err(PeImageAccessError::ShortRead);
            }
            offset = offset
                .checked_add(bytes_read)
                .ok_or(PeImageAccessError::AddressOverflow)?;
            buf = &mut buf[bytes_read..];
        }
        Ok(())
    }
}

impl<FS: NtShimFS> Drop for PeImageFile<FS> {
    fn drop(&mut self) {
        let _ = self.fs.close(&self.fd);
    }
}

impl<FS: NtShimFS> ReadAt for &'_ PeImageFile<FS> {
    type Error = PeImageAccessError;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.read_exact_at(
            offset
                .try_into()
                .map_err(|_| PeImageAccessError::AddressOverflow)?,
            buf,
        )
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        self.fs
            .fd_file_status(&self.fd)?
            .size
            .try_into()
            .map_err(|_| PeImageAccessError::AddressOverflow)
    }
}

struct PeImageMapper<'a, FS: NtShimFS> {
    file: &'a PeImageFile<FS>,
    page_manager: &'a WindowsPageManager,
}

impl<FS: NtShimFS> MapMemory for PeImageMapper<'_, FS> {
    type Error = PeImageAccessError;

    fn reserve(
        &mut self,
        preferred_base: usize,
        len: usize,
        _align: usize,
    ) -> Result<usize, Self::Error> {
        let length = NonZeroPageSize::new(len).ok_or(PeImageAccessError::AddressOverflow)?;
        let suggested_address = if preferred_base == 0 {
            None
        } else {
            Some(NonZeroAddress::new(preferred_base).ok_or(PeImageAccessError::AddressOverflow)?)
        };

        // SAFETY: The PE loader owns this reserved image range and maps concrete
        // headers/sections into it before any guest execution is allowed.
        let ptr = unsafe {
            self.page_manager.create_inaccessible_pages(
                suggested_address,
                length,
                CreatePagesFlags::empty(),
                |_| Ok(0),
            )?
        };
        Ok(ptr.as_usize())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        make_pages_writable(self.page_manager, address, len)?;
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
        for index in 0..len {
            ptr.write_at_offset(
                index
                    .try_into()
                    .map_err(|_| PeImageAccessError::AddressOverflow)?,
                0,
            )
            .ok_or(PeImageAccessError::MemoryAccess)?;
        }
        protect_pages(self.page_manager, address, len, *prot)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        make_pages_writable(self.page_manager, address, len)?;
        let mut data = vec![0; len];
        self.file.read_exact_at(
            offset
                .try_into()
                .map_err(|_| PeImageAccessError::AddressOverflow)?,
            &mut data,
        )?;
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
        ptr.copy_from_slice(0, &data)
            .ok_or(PeImageAccessError::MemoryAccess)?;
        protect_pages(self.page_manager, address, len, *prot)
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        protect_pages(self.page_manager, address, len, *prot)
    }
}

struct PeImageMemory;

impl AccessMemory for PeImageMemory {
    fn read(&mut self, address: usize, buf: &mut [u8]) -> Result<(), Fault> {
        let ptr = <Platform as RawPointerProvider>::RawConstPointer::<u8>::from_usize(address);
        buf.copy_from_slice(&ptr.to_owned_slice(buf.len()).ok_or(Fault)?);
        Ok(())
    }

    fn write(&mut self, address: usize, data: &[u8]) -> Result<(), Fault> {
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
        ptr.copy_from_slice(0, data).ok_or(Fault)
    }
}

fn make_pages_writable(
    page_manager: &WindowsPageManager,
    address: usize,
    len: usize,
) -> Result<(), PeImageAccessError> {
    let (start, len) = page_range(address, len)?;
    if len == 0 {
        return Ok(());
    }
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(start);
    // SAFETY: Loading happens before the initial guest thread is allowed to execute.
    unsafe { page_manager.make_pages_writable(ptr, len)? };
    Ok(())
}

fn protect_pages(
    page_manager: &WindowsPageManager,
    address: usize,
    len: usize,
    prot: Protection,
) -> Result<(), PeImageAccessError> {
    let (start, len) = page_range(address, len)?;
    if len == 0 {
        return Ok(());
    }
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(start);
    // SAFETY: Loading and final image protection happen before guest execution.
    unsafe {
        match (prot.read, prot.write, prot.execute) {
            (_, true, true) => page_manager.make_pages_rwx(ptr, len)?,
            (_, true, false) => page_manager.make_pages_writable(ptr, len)?,
            (_, false, true) => page_manager.make_pages_executable(ptr, len)?,
            (true, false, false) => page_manager.make_pages_readable(ptr, len)?,
            (false, false, false) => page_manager.make_pages_inaccessible(ptr, len)?,
        }
    }
    Ok(())
}

fn windows_protection(protection: usize) -> Option<Protection> {
    match u32::try_from(protection & WINDOWS_PAGE_PROTECTION_MASK).ok()? {
        WINDOWS_PAGE_NOACCESS => Some(Protection {
            read: false,
            write: false,
            execute: false,
        }),
        WINDOWS_PAGE_READONLY => Some(Protection {
            read: true,
            write: false,
            execute: false,
        }),
        WINDOWS_PAGE_READWRITE | WINDOWS_PAGE_WRITECOPY => Some(Protection {
            read: true,
            write: true,
            execute: false,
        }),
        WINDOWS_PAGE_EXECUTE => Some(Protection {
            read: false,
            write: false,
            execute: true,
        }),
        WINDOWS_PAGE_EXECUTE_READ => Some(Protection {
            read: true,
            write: false,
            execute: true,
        }),
        WINDOWS_PAGE_EXECUTE_READWRITE | WINDOWS_PAGE_EXECUTE_WRITECOPY => Some(Protection {
            read: true,
            write: true,
            execute: true,
        }),
        _ => None,
    }
}

fn page_range(address: usize, len: usize) -> Result<(usize, usize), PeImageAccessError> {
    if len == 0 {
        return Ok((address, 0));
    }
    let start = page_align_down(address);
    let end = page_align_up(
        address
            .checked_add(len)
            .ok_or(PeImageAccessError::AddressOverflow)?,
    )
    .ok_or(PeImageAccessError::AddressOverflow)?;
    Ok((start, end - start))
}

fn page_align_down(address: usize) -> usize {
    address & !(PAGE_SIZE - 1)
}

fn page_align_up(address: usize) -> Option<usize> {
    address.checked_add(PAGE_SIZE - 1).map(page_align_down)
}

fn align_up_to(address: usize, alignment: usize) -> Option<usize> {
    address
        .checked_add(alignment.checked_sub(1)?)
        .map(|address| address & !(alignment - 1))
}

fn default_fs(
    litebox: &LiteBox<Platform>,
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
) -> WindowsFS {
    let dev_stdio = litebox::fs::devices::FileSystem::new(litebox);
    litebox::fs::layered::FileSystem::new(
        litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            litebox,
            dev_stdio,
            tar_ro_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    )
}
