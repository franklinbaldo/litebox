// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT section syscall handlers.
//!
//! Implements NtCreateSection, NtMapViewOfSection, and NtQuerySection.
//! These are used by ntdll's loader to map DLL images into the guest
//! address space during initialization.

use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
use litebox::platform::{RawConstPointer, RawPointerProvider};
use litebox_common_windows::ntstatus::NtStatus;
use litebox_common_windows::pe_loader::{PeLoadError, PeMemoryMapper, SectionPermissions};
use litebox_common_windows::pe_parser::PeParsedFile;

use crate::handle_table::{HandleTable, NtObject};
use crate::{NtInitState, NtProcessState, Platform, PAGE_SIZE};

use super::NtSyscallArgs;

/// SEC_IMAGE flag (0x01000000) ΓÇö indicates an image section.
const SEC_IMAGE: u32 = 0x0100_0000;
// ========================================================================
// NtCreateSection
// ========================================================================

/// NtCreateSection ΓÇö create a section object from a file handle.
///
/// NT signature:
/// ```text
/// NTSTATUS NtCreateSection(
///     PHANDLE SectionHandle,               // r10 (out)
///     ACCESS_MASK DesiredAccess,            // rdx
///     POBJECT_ATTRIBUTES ObjectAttributes,  // r8
///     PLARGE_INTEGER MaximumSize,           // r9
///     ULONG SectionPageProtection,         // [rsp+0x28]
///     ULONG AllocationAttributes,          // [rsp+0x30]
///     HANDLE FileHandle                    // [rsp+0x38]
/// );
/// ```
///
/// For SEC_IMAGE sections, we read the PE data from the file handle,
/// parse it, and store the parsed info in a Section handle.
pub(crate) fn nt_create_section(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let section_handle_ptr = args.arg0;
    let _desired_access = args.arg1 as u32;
    let _obj_attr_ptr = args.arg2;
    let _max_size_ptr = args.arg3;

    // Stack arguments.
    let _page_protection =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let alloc_attributes =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let file_handle =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);

    if section_handle_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let is_image = alloc_attributes & SEC_IMAGE != 0;

    if !is_image {
        // Non-image (data) section ΓÇö anonymous shared memory.
        // Read MaximumSize from r9.
        let max_size = if _max_size_ptr != 0 {
            (crate::try_read_guest_value_unaligned::<i64>(_max_size_ptr).unwrap_or(0)) as u64
        } else {
            0x10000 // default 64KB
        };

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtCreateSection data (alloc_attrs=0x{alloc_attributes:X}, size=0x{max_size:X})\n",
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }

        let handle = handles.insert(NtObject::DataSection { max_size });
        if !crate::try_write_guest_value_unaligned(section_handle_ptr, handle) {
            return NtStatus::STATUS_ACCESS_VIOLATION;
        }
        return NtStatus::STATUS_SUCCESS;
    }

    // SEC_IMAGE: read PE data from the file handle.
    // First check if this is a phantom executable handle — if so, return a
    // stub section that lets NtCreateUserProcess work with virtual processes.
    let phantom_path = handles
        .with(file_handle, |entry| match &entry.object {
            NtObject::PhantomExe { path } => Some(path.clone()),
            _ => None,
        })
        .flatten();
    if let Some(phantom_path) = phantom_path {
        #[cfg(any(debug_assertions, feature = "trace_debug"))]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtCreateSection SEC_IMAGE phantom exe path={phantom_path:?}\n",
            ));
        }
        // Create a minimal stub section — NtCreateUserProcess reads the command
        // line from RTL_USER_PROCESS_PARAMETERS, not from the section data.
        let handle = handles.insert(NtObject::Section {
            pe_data: Arc::new(Vec::new()),
            module_path: Some(phantom_path),
            module_name: Some(alloc::string::String::from("phantom.exe")),
            image_size: 0x1000,
            image_base: 0x0040_0000,
            entry_point: 0x1000,
            section_alignment: 0x1000,
            is_dll: false,
        });
        if !crate::try_write_guest_value_unaligned(section_handle_ptr, handle) {
            return NtStatus::STATUS_ACCESS_VIOLATION;
        }
        return NtStatus::STATUS_SUCCESS;
    }

    let Some((pe_data, section_path)) = read_pe_from_handle(handles, file_handle, shared) else {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtCreateSection SEC_IMAGE ΓÇö invalid file handle 0x{file_handle:X}\n"
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    // Parse the PE.
    let parsed = match PeParsedFile::parse(&pe_data) {
        Ok(p) => p,
        Err(e) => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtCreateSection SEC_IMAGE ΓÇö PE parse error: {e:?}\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
        }
    };

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtCreateSection SEC_IMAGE ok ΓÇö size_of_image=0x{:X}, base=0x{:X}, is_dll={}\n",
            parsed.size_of_image,
            parsed.image_base,
            parsed.is_dll,
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    let export_name = get_pe_export_dll_name(&parsed, &pe_data);
    let module_path = normalize_module_path(section_path.as_deref(), export_name);
    let module_name = module_name_from_image(&parsed, &pe_data, section_path.as_deref());
    let handle = handles.insert(NtObject::Section {
        pe_data: Arc::new(pe_data),
        module_path,
        module_name: Some(module_name),
        image_size: parsed.size_of_image,
        image_base: parsed.image_base,
        entry_point: parsed.entry_point,
        section_alignment: parsed.section_alignment,
        is_dll: parsed.is_dll,
    });

    if !crate::try_write_guest_value_unaligned(section_handle_ptr, handle) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    NtStatus::STATUS_SUCCESS
}

pub(crate) fn open_csr_shared_section(
    handles: &mut HandleTable,
    section_handle_ptr: usize,
) -> NtStatus {
    let handle = handles.insert(NtObject::Stub {
        kind: alloc::string::String::from("CsrSharedSection"),
        io_completion: None,
    });
    if !crate::try_write_guest_value_unaligned(section_handle_ptr, handle) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    NtStatus::STATUS_SUCCESS
}

/// Read the full PE data from a file handle (VFS-backed).
fn read_pe_from_handle(
    handles: &HandleTable,
    file_handle: u32,
    shared: &crate::NtSharedState,
) -> Option<(Vec<u8>, Option<alloc::string::String>)> {
    let (vfs_fd, path) = handles
        .with(file_handle, |entry| match &entry.object {
            NtObject::File { vfs_fd, path, .. } => {
                Some((alloc::sync::Arc::clone(vfs_fd), path.clone()))
            }
            _ => None,
        })
        .flatten()?;

    // Read from VFS.
    let fs = shared.fs.get()?;
    // Get file size via fd_file_status, then read the entire file.
    use litebox::fs::FileSystem as _;
    let status = fs.fd_file_status(&vfs_fd).ok()?;
    let size = status.size;
    if size == 0 || size > 256 * 1024 * 1024 {
        return None;
    }
    let mut buf = alloc::vec![0u8; size];
    let mut offset = 0usize;
    while offset < size {
        let bytes_read = fs.read(&vfs_fd, &mut buf[offset..], Some(offset)).ok()?;
        if bytes_read == 0 {
            return None;
        }
        offset = offset.checked_add(bytes_read)?;
    }
    Some((buf, Some(path)))
}

fn module_name_from_image(
    parsed: &PeParsedFile,
    pe_data: &[u8],
    section_path: Option<&str>,
) -> alloc::string::String {
    if let Some(name) = get_pe_export_dll_name(parsed, pe_data) {
        return alloc::string::String::from(name);
    }

    if let Some(path) = section_path {
        let trimmed = path
            .strip_suffix('\\')
            .or_else(|| path.strip_suffix('/'))
            .unwrap_or(path);
        if let Some((_, tail)) = trimmed
            .rsplit_once('\\')
            .or_else(|| trimmed.rsplit_once('/'))
        {
            return alloc::string::String::from(tail);
        }
        return alloc::string::String::from(trimmed);
    }

    alloc::string::String::from(if parsed.is_dll {
        "mapped-image.dll"
    } else {
        "mapped-image.exe"
    })
}

fn normalize_module_path(
    section_path: Option<&str>,
    export_name: Option<&str>,
) -> Option<alloc::string::String> {
    let normalized = section_path.map(|path| {
        if let Some(rest) = path
            .strip_prefix("\\??\\")
            .or_else(|| path.strip_prefix("\\DosDevices\\"))
        {
            alloc::string::String::from(rest)
        } else if let Some(rest) = path.strip_prefix("\\SystemRoot\\") {
            alloc::format!("C:\\Windows\\{rest}")
        } else if let Some(rest) = path.strip_prefix("\\KnownDlls\\") {
            alloc::format!("C:\\Windows\\System32\\{rest}")
        } else {
            alloc::string::String::from(path)
        }
    });

    normalized.or_else(|| export_name.map(|name| alloc::format!("C:\\Windows\\System32\\{name}")))
}

// ========================================================================
// NtMapViewOfSection
// ========================================================================

/// NtMapViewOfSection ΓÇö map a section into the guest address space.
///
/// NT signature:
/// ```text
/// NTSTATUS NtMapViewOfSection(
///     HANDLE SectionHandle,         // r10
///     HANDLE ProcessHandle,         // rdx
///     PVOID *BaseAddress,           // r8  (in/out)
///     ULONG_PTR ZeroBits,           // r9
///     SIZE_T CommitSize,            // [rsp+0x28]
///     PLARGE_INTEGER SectionOffset, // [rsp+0x30]
///     PSIZE_T ViewSize,             // [rsp+0x38]
///     ULONG InheritDisposition,     // [rsp+0x40]
///     ULONG AllocationType,         // [rsp+0x48]
///     ULONG Win32Protect            // [rsp+0x50]
/// );
/// ```
///
/// For SEC_IMAGE sections, we map the PE into guest memory using the
/// page manager, applying relocations as needed.
pub(crate) fn nt_map_view_of_section(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable,
    shim_shared: &crate::NtSharedState,
    init_state: Option<&NtInitState>,
) -> NtStatus {
    let process_state = &shim_shared.process_state;
    let args = NtSyscallArgs::from_ctx(ctx);
    let section_handle = args.arg0 as u32;
    let _process_handle = args.arg1; // should be NtCurrentProcess (-1)
    let base_addr_ptr = args.arg2;
    let _zero_bits = args.arg3;

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtMapViewOfSection args: section=0x{:X} process=0x{:X} base_ptr=0x{:X} zero_bits=0x{:X} rsp=0x{:X}\n",
            section_handle,
            _process_handle,
            base_addr_ptr,
            _zero_bits,
            ctx.regs.rsp,
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    // Stack arguments.
    let _commit_size =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let _section_offset_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let view_size_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x38).unwrap_or(0);
    let _inherit_disposition =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x40).unwrap_or(0);
    let _allocation_type =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x48).unwrap_or(0);
    let _win32_protect =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x50).unwrap_or(0);

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtMapViewOfSection stack: commit=0x{_commit_size:X} offset_ptr=0x{_section_offset_ptr:X} view_size_ptr=0x{view_size_ptr:X}\n",
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    if base_addr_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Determine section type.
    enum SectionType {
        Image {
            pe_data: Arc<Vec<u8>>,
            module_path: Option<alloc::string::String>,
            module_name: Option<alloc::string::String>,
            image_size: u32,
            image_base: u64,
        },
        Data {
            max_size: u64,
        },
        StaticView {
            base: usize,
            size: usize,
        },
    }

    let section_type = handles
        .with(section_handle, |entry| match &entry.object {
            NtObject::Section {
                pe_data,
                module_path,
                module_name,
                image_size,
                image_base,
                ..
            } => Some(SectionType::Image {
                pe_data: Arc::clone(pe_data),
                module_path: module_path.clone(),
                module_name: module_name.clone(),
                image_size: *image_size,
                image_base: *image_base,
            }),
            NtObject::DataSection { max_size } => Some(SectionType::Data {
                max_size: *max_size,
            }),
            NtObject::Stub { kind, .. } if kind == "CsrSharedSection" => {
                let csr = *shim_shared.csr_state.lock();
                Some(SectionType::StaticView {
                    base: csr.shared_section_base,
                    size: csr.shared_section_size,
                })
            }
            _ => None,
        })
        .flatten();

    let Some(section_type) = section_type else {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtMapViewOfSection — invalid section handle 0x{section_handle:X}\n",
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    match section_type {
        SectionType::Data { max_size } => {
            map_data_section(ctx, process_state, base_addr_ptr, view_size_ptr, max_size)
        }
        SectionType::StaticView { base, size } => {
            if !crate::try_write_guest_value_unaligned(base_addr_ptr, base) {
                return NtStatus::STATUS_ACCESS_VIOLATION;
            }
            if view_size_ptr != 0 {
                crate::try_write_guest_value_unaligned(view_size_ptr, size);
            }
            NtStatus::STATUS_SUCCESS
        }
        SectionType::Image {
            pe_data,
            module_path,
            module_name,
            image_size,
            image_base: preferred_base,
        } => map_image_section(
            ctx,
            shim_shared,
            process_state,
            init_state,
            base_addr_ptr,
            view_size_ptr,
            &pe_data,
            module_path.as_deref(),
            module_name.as_deref(),
            image_size,
            preferred_base,
        ),
    }
}

/// NtMapViewOfSectionEx — map a section using the Win10+ extended ABI.
///
/// The Ex variant differs from NtMapViewOfSection after the third argument:
/// `SectionOffset` is passed in `r9`, `ViewSize` moves to `[rsp+0x28]`, and the
/// remaining stack parameters shift down by one slot. Parsing it with the
/// legacy layout corrupts the view-size pointer the guest loader / segment
/// heap relies on.
pub(crate) fn nt_map_view_of_section_ex(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable,
    shim_shared: &crate::NtSharedState,
    init_state: Option<&NtInitState>,
) -> NtStatus {
    let process_state = &shim_shared.process_state;
    let args = NtSyscallArgs::from_ctx(ctx);
    let section_handle = args.arg0 as u32;
    let _process_handle = args.arg1; // should be NtCurrentProcess (-1)
    let base_addr_ptr = args.arg2;
    let _section_offset_ptr = args.arg3;
    let view_size_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let _allocation_type =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let _win32_protect =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);
    let _extended_parameters =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x40).unwrap_or(0);
    let _extended_parameter_count =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x48).unwrap_or(0);

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtMapViewOfSectionEx args: section=0x{:X} process=0x{:X} base_ptr=0x{:X} offset_ptr=0x{:X} view_size_ptr=0x{view_size_ptr:X} ext=0x{_extended_parameters:X} count={_extended_parameter_count} rsp=0x{:X}\n",
            section_handle,
            _process_handle,
            base_addr_ptr,
            _section_offset_ptr,
            ctx.regs.rsp,
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    if base_addr_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    enum SectionType {
        Image {
            pe_data: Arc<Vec<u8>>,
            module_path: Option<alloc::string::String>,
            module_name: Option<alloc::string::String>,
            image_size: u32,
            image_base: u64,
        },
        Data {
            max_size: u64,
        },
        StaticView {
            base: usize,
            size: usize,
        },
    }

    let section_type = handles
        .with(section_handle, |entry| match &entry.object {
            NtObject::Section {
                pe_data,
                module_path,
                module_name,
                image_size,
                image_base,
                ..
            } => Some(SectionType::Image {
                pe_data: Arc::clone(pe_data),
                module_path: module_path.clone(),
                module_name: module_name.clone(),
                image_size: *image_size,
                image_base: *image_base,
            }),
            NtObject::DataSection { max_size } => Some(SectionType::Data {
                max_size: *max_size,
            }),
            NtObject::Stub { kind, .. } if kind == "CsrSharedSection" => {
                let csr = *shim_shared.csr_state.lock();
                Some(SectionType::StaticView {
                    base: csr.shared_section_base,
                    size: csr.shared_section_size,
                })
            }
            _ => None,
        })
        .flatten();

    let Some(section_type) = section_type else {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtMapViewOfSection — invalid section handle 0x{section_handle:X}\n",
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    match section_type {
        SectionType::Data { max_size } => {
            map_data_section(ctx, process_state, base_addr_ptr, view_size_ptr, max_size)
        }
        SectionType::StaticView { base, size } => {
            if !crate::try_write_guest_value_unaligned(base_addr_ptr, base) {
                return NtStatus::STATUS_ACCESS_VIOLATION;
            }
            if view_size_ptr != 0 {
                crate::try_write_guest_value_unaligned(view_size_ptr, size);
            }
            NtStatus::STATUS_SUCCESS
        }
        SectionType::Image {
            pe_data,
            module_path,
            module_name,
            image_size,
            image_base: preferred_base,
        } => map_image_section(
            ctx,
            shim_shared,
            process_state,
            init_state,
            base_addr_ptr,
            view_size_ptr,
            &pe_data,
            module_path.as_deref(),
            module_name.as_deref(),
            image_size,
            preferred_base,
        ),
    }
}

/// Map a data section (anonymous shared memory) into guest address space.
fn map_data_section(
    ctx: &mut super::super::ExecutionContext,
    process_state: &Arc<NtProcessState>,
    base_addr_ptr: usize,
    view_size_ptr: usize,
    max_size: u64,
) -> NtStatus {
    let suggested_base = crate::try_read_guest_value_unaligned::<usize>(base_addr_ptr).unwrap_or(0);
    let view_size = if view_size_ptr != 0 {
        let vs = crate::try_read_guest_value_unaligned::<usize>(view_size_ptr).unwrap_or(0);
        if vs != 0 {
            vs
        } else {
            max_size as usize
        }
    } else {
        max_size as usize
    };

    let (mapped_addr, aligned_size) =
        match map_data_section_pages(process_state, suggested_base, view_size) {
            Ok(mapped) => mapped,
            Err(status) => return status,
        };

    if !crate::try_write_guest_value_unaligned(base_addr_ptr, mapped_addr) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    if view_size_ptr != 0 {
        crate::try_write_guest_value_unaligned(view_size_ptr, aligned_size);
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtMapViewOfSection data at 0x{mapped_addr:X} (size=0x{aligned_size:X})\n",
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    NtStatus::STATUS_SUCCESS
}

pub(crate) fn map_data_section_pages(
    process_state: &Arc<NtProcessState>,
    suggested_base: usize,
    view_size: usize,
) -> Result<(usize, usize), NtStatus> {
    let aligned_size = (view_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    if aligned_size == 0 {
        return Err(NtStatus::STATUS_INVALID_PARAMETER);
    }

    let Some(nz_size) = NonZeroPageSize::<PAGE_SIZE>::new(aligned_size) else {
        return Err(NtStatus::STATUS_INVALID_PARAMETER);
    };

    let suggested = if suggested_base != 0 {
        NonZeroAddress::<PAGE_SIZE>::new(suggested_base)
    } else {
        None
    };

    let flags = if suggested.is_some() {
        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY
    } else {
        CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY
    };

    let result = unsafe {
        process_state
            .pm
            .create_writable_pages(suggested, nz_size, flags, |_| Ok(0))
    };

    match result {
        Ok(ptr) => {
            use litebox::platform::RawConstPointer as _;
            let mapped_addr = ptr.as_usize();

            process_state.track_section_view(mapped_addr, aligned_size);
            Ok((mapped_addr, aligned_size))
        }
        Err(_) => Err(NtStatus::STATUS_NO_MEMORY),
    }
}

/// Map an image section (SEC_IMAGE PE) into guest address space.
fn map_image_section(
    ctx: &mut super::super::ExecutionContext,
    shim_shared: &crate::NtSharedState,
    process_state: &Arc<NtProcessState>,
    init_state: Option<&NtInitState>,
    base_addr_ptr: usize,
    view_size_ptr: usize,
    pe_data: &[u8],
    module_path: Option<&str>,
    module_name: Option<&str>,
    image_size: u32,
    preferred_base: u64,
) -> NtStatus {
    // Re-parse the PE (lightweight ΓÇö just reads headers).
    let Ok(parsed) = PeParsedFile::parse(pe_data) else {
        return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
    };

    // Determine load address.
    let suggested_base = crate::try_read_guest_value_unaligned::<usize>(base_addr_ptr).unwrap_or(0);
    let preferred = if suggested_base != 0 {
        suggested_base
    } else {
        preferred_base as usize
    };

    let aligned_size = (image_size as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let mut mapper = PmMapper {
        pm: &process_state.pm,
    };

    // Windows requires PE images to be mapped at allocation-granularity-
    // aligned addresses (64 KB). Try the preferred address first, then
    // fall back to a 64 KB-aligned system-chosen address.
    const ALLOC_GRANULARITY: usize = 0x10000; // 64 KB

    let load_base = if mapper.pre_reserve(preferred, aligned_size).is_ok() {
        preferred
    } else {
        // Over-allocate to guarantee a 64 KB-aligned range within the
        // allocation, then trim the leading/trailing excess.
        //
        // We must NOT free-then-re-allocate: between the free and the
        // re-allocation, PM considers the VA range available and other
        // allocations (e.g. heap MEM_RESERVE) could claim overlapping
        // addresses.  Instead, we keep the over-allocation intact, find
        // the aligned base within it, and trim only the excess pages at
        // the edges.  This mirrors how the real Windows kernel uses
        // placeholders (MEM_RESERVE_PLACEHOLDER / MEM_REPLACE_PLACEHOLDER)
        // to hold VA during section mapping without ever releasing it.
        let over_size = aligned_size + ALLOC_GRANULARITY - PAGE_SIZE;
        let Some(over_nz) = NonZeroPageSize::<PAGE_SIZE>::new(over_size) else {
            return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
        };
        let flags = CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
        let over_ptr = match unsafe {
            process_state
                .pm
                .create_writable_pages(None, over_nz, flags, |_| Ok(0))
        } {
            Ok(ptr) => ptr,
            Err(_) => {
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtMapViewOfSection — \
                             pre_reserve(0x{preferred:X}, 0x{aligned_size:X}) and fallback alloc both failed\n",
                    ));
                }
                return NtStatus::STATUS_CONFLICTING_ADDRESSES;
            }
        };
        let over_base = {
            use litebox::platform::RawConstPointer as _;
            over_ptr.as_usize()
        };
        let aligned_base = (over_base + ALLOC_GRANULARITY - 1) & !(ALLOC_GRANULARITY - 1);

        // Trim leading excess (pages before the aligned base).
        let leading = aligned_base - over_base;
        if leading > 0 {
            unsafe {
                let _ = process_state.pm.remove_pages(over_ptr, leading);
            }
        }
        // Trim trailing excess (pages after the image end).
        let trailing = over_size - leading - aligned_size;
        if trailing > 0 {
            let trail_ptr = {
                use litebox::platform::RawConstPointer as _;
                <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(
                    aligned_base + aligned_size,
                )
            };
            unsafe {
                let _ = process_state.pm.remove_pages(trail_ptr, trailing);
            }
        }

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtMapViewOfSection — fallback alloc: over=0x{over_base:X}+0x{over_size:X}, \
                 aligned=0x{aligned_base:X}+0x{aligned_size:X}, trimmed lead=0x{leading:X} trail=0x{trailing:X}\n",
            ));
        }

        aligned_base
    };

    // Apply base relocations ourselves. The real Windows kernel applies
    // relocations inside NtMapViewOfSection for SEC_IMAGE sections and
    // ntdll trusts that the image is already relocated. If we skip this,
    // all absolute pointers (including TLS directory entries) would still
    // reference the preferred base address, causing crashes.
    let load_info = match litebox_common_windows::pe_loader::load_pe(
        &parsed,
        pe_data,
        load_base,
        &mut mapper,
    ) {
        Ok(info) => info,
        Err(e) => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!("NT shim: NtMapViewOfSection ΓÇö load_pe failed: {e}\n");
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
        }
    };

    // Patch the in-memory PE header's ImageBase to match the actual load
    // address.  We already applied relocations in load_pe, but ntdll will
    // ALSO apply relocations when it sees STATUS_IMAGE_NOT_AT_BASE.
    // By setting ImageBase = actual load address, ntdll computes delta = 0
    // and its relocation pass becomes a no-op, preventing double-relocation
    // corruption.
    if load_info.image_base != preferred_base as usize {
        unsafe {
            let pe_sig_off =
                core::ptr::read((load_info.image_base as *const u32).byte_add(0x3C)) as usize;
            let opt_hdr = load_info.image_base + pe_sig_off + 0x18;
            let image_base_ptr = (opt_hdr + 0x18) as *mut u64;
            core::ptr::write(image_base_ptr, load_info.image_base as u64);
        }
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtMapViewOfSection mapped at 0x{:X} (size=0x{:X}, entry=0x{:X})\n",
            load_info.image_base,
            load_info.image_size,
            load_info.entry_point,
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);

        // Log TLS directory info for this PE if present
        use litebox_common_windows::pe::{ImageTlsDirectory64, IMAGE_DIRECTORY_ENTRY_TLS};
        if let Some(tls_dd) = parsed.data_directory(IMAGE_DIRECTORY_ENTRY_TLS) {
            let tls_rva = tls_dd.virtual_address as usize;
            let tls_va = load_info.image_base + tls_rva;
            let tls_dir = unsafe { core::ptr::read(tls_va as *const ImageTlsDirectory64) };
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "  TLS dir at 0x{:X} (rva=0x{:X}): start=0x{:X} end=0x{:X} \
                 addr_of_index=0x{:X} addr_of_callbacks=0x{:X} zero_fill=0x{:X}\n",
                tls_va,
                tls_rva,
                tls_dir.start_address_of_raw_data,
                tls_dir.end_address_of_raw_data,
                tls_dir.address_of_index,
                tls_dir.address_of_callbacks,
                tls_dir.size_of_zero_fill,
            ));
            // Check if address_of_index is within this image (pre-relocation check)
            let pref = preferred_base as usize;
            let in_preferred = (tls_dir.address_of_index as usize) >= pref
                && (tls_dir.address_of_index as usize) < pref + load_info.image_size;
            let in_actual = (tls_dir.address_of_index as usize) >= load_info.image_base
                && (tls_dir.address_of_index as usize)
                    < load_info.image_base + load_info.image_size;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "  TLS addr_of_index: in_preferred_range={} in_actual_range={} \
                 (preferred=0x{:X} actual=0x{:X})\n",
                in_preferred,
                in_actual,
                pref,
                load_info.image_base,
            ));
        }
    }

    if !crate::try_write_guest_value_unaligned(base_addr_ptr, load_info.image_base) {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    if view_size_ptr != 0 {
        crate::try_write_guest_value_unaligned(view_size_ptr, load_info.image_size);
    }

    // Track this image mapping so NtQueryVirtualMemory returns MEM_IMAGE type.
    process_state.track_image_mapping(load_info.image_base, load_info.image_size);
    process_state.register_module(crate::ModuleBase {
        name: module_name
            .map(alloc::string::String::from)
            .unwrap_or_else(|| module_name_from_image(&parsed, pe_data, module_path)),
        path: normalize_module_path(module_path, get_pe_export_dll_name(&parsed, pe_data))
            .unwrap_or_else(|| {
                alloc::format!(
                    "C:\\image_{:X}.{}",
                    load_info.image_base,
                    if parsed.is_dll { "dll" } else { "exe" }
                )
            }),
        base_address: load_info.image_base,
        image_size: load_info.image_size,
    });

    // Static TLS belongs to the guest loader. Mapping an image must not
    // pre-populate module TLS indices, vectors, or blocks from the shim.

    // Real guest DLL code must run unmodified here. The supported
    // interception boundary in this path is the real guest syscall entry:
    // ntdll stubs plus the current guest win32u.dll Win32k stubs that are
    // rewritten into the trampoline.
    if module_name.is_some_and(|name| name.eq_ignore_ascii_case("win32u.dll")) {
        patch_win32k_stubs(
            load_info.image_base,
            load_info.image_size,
            &process_state.pm,
            process_state.trampoline_code_va(),
        );
        let map = super::win32k::build_win32k_syscall_map(&parsed, pe_data);
        let _ = shim_shared.win32k_syscall_map.call_once(|| map);
    }

    // ── Register in the inverted function table for SEH unwinding ──
    //
    // ntdll's SEH unwinding (RtlpxLookupFunctionTable) searches the
    // inverted function table for the .pdata (RUNTIME_FUNCTION array)
    // of each image on the stack.  Without an entry, unwinding fails
    // with STATUS_BAD_STACK.
    //
    // DISABLED: We now make ntdll's .mrdata section writable in the runner,
    // which allows ntdll's own RtlInsertInvertedFunctionTable to work.
    // Letting ntdll manage its own IFT is more correct than our interleaved
    // insertion (which could conflict with ntdll's sorted insertion logic).
    //
    // register_inverted_function_table_entry(
    //     &parsed,
    //     pe_data,
    //     load_info.image_base,
    //     load_info.image_size,
    //     process_state,
    // );

    // Return STATUS_IMAGE_NOT_AT_BASE when the image was loaded at a
    // different address than its preferred base. The loader uses this to
    // decide whether to apply relocations.
    if load_base == preferred_base as usize {
        NtStatus::STATUS_SUCCESS
    } else {
        NtStatus::STATUS_IMAGE_NOT_AT_BASE
    }
}

/// Unmap a previously mapped section view from the guest address space.
///
/// If the base address corresponds to a tracked SEC_IMAGE mapping, the
/// pages are removed from the page manager and the tracking entry is
/// deleted.  Otherwise we return STATUS_NOT_MAPPED_VIEW.
pub fn nt_unmap_view_of_section(process_state: &NtProcessState, base_address: usize) -> NtStatus {
    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtUnmapViewOfSection base=0x{base_address:X}\n",
        ));
    }

    // Look up the address in our tracked image mappings.
    if let Some((mapped_base, size)) = process_state.untrack_image_mapping(base_address) {
        // Remove the pages from the page manager.
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(mapped_base);
        unsafe {
            let _ = process_state.pm.remove_pages(ptr, size);
        }

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtUnmapViewOfSection — unmapped image at 0x{mapped_base:X}+0x{size:X}\n",
            ));
        }

        NtStatus::STATUS_SUCCESS
    } else if let Some((mapped_base, size)) = process_state.untrack_section_view(base_address) {
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(mapped_base);
        unsafe {
            let _ = process_state.pm.remove_pages(ptr, size);
        }

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtUnmapViewOfSection — unmapped section view at 0x{mapped_base:X}+0x{size:X}\n",
            ));
        }

        NtStatus::STATUS_SUCCESS
    } else {
        // Not a tracked image mapping — still return success since the
        // caller may be unmapping a data section or a mapping we didn't
        // track (e.g., NLS data from NtMapViewOfSection for non-SEC_IMAGE
        // sections).  Returning an error here could confuse ntdll's loader.
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtUnmapViewOfSection — base 0x{base_address:X} not tracked, returning SUCCESS\n",
            ));
        }
        NtStatus::STATUS_SUCCESS
    }
}

/// Scan a freshly mapped PE image for Win32k syscall stubs and rewrite
/// each one to jump through the sandbox trampoline.
///
/// The current guest bundle places the needed `NtUser*` and `NtGdi*` stubs
/// in `win32u.dll`. Rewriting those entry points keeps USER32/GDI startup on
/// the same syscall boundary as ntdll instead of letting the guest reach host
/// win32k and host callback machinery.
fn patch_win32k_stubs(
    image_base: usize,
    image_size: usize,
    pm: &litebox::mm::PageManager<Platform, PAGE_SIZE>,
    trampoline_code_va: usize,
) {
    const STUB_LEN: usize = 0x20;
    const PREFIX: [u8; 3] = [0x4C, 0x8B, 0xD1];
    const SYSCALL_BYTES: [u8; 2] = [0x0F, 0x05];
    const JMP_INDIRECT: [u8; 6] = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];

    if trampoline_code_va == 0 {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform()
                .debug_log_print("NT shim: skipping Win32k stub patching (trampoline=0)\n");
        }
        return;
    }

    let tramp_addr_bytes = (trampoline_code_va as u64).to_le_bytes();
    let end = image_base + image_size;
    let mut patched = 0u32;
    let mut pos = image_base;

    while pos + STUB_LEN <= end {
        // Safety: the image was just mapped into guest memory.
        let bytes = unsafe { core::slice::from_raw_parts(pos as *const u8, STUB_LEN) };

        if bytes[0..3] == PREFIX && bytes[3] == 0xB8 {
            let nr = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            if nr >= 0x1000 {
                let has_syscall = (8..STUB_LEN - 1)
                    .any(|i| bytes[i] == SYSCALL_BYTES[0] && bytes[i + 1] == SYSCALL_BYTES[1]);
                if has_syscall {
                    let page_addr = pos & !(PAGE_SIZE - 1);
                    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(
                        page_addr,
                    );
                    let _ = unsafe { pm.make_pages_writable(ptr, PAGE_SIZE) };

                    let patch_end_page = (pos + 0x1D) & !(PAGE_SIZE - 1);
                    if patch_end_page != page_addr {
                        let next_ptr =
                            <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(
                                patch_end_page,
                            );
                        let _ = unsafe { pm.make_pages_writable(next_ptr, PAGE_SIZE) };
                    }

                    let patch_base = pos + 0x10;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            JMP_INDIRECT.as_ptr(),
                            patch_base as *mut u8,
                            JMP_INDIRECT.len(),
                        );
                        core::ptr::copy_nonoverlapping(
                            tramp_addr_bytes.as_ptr(),
                            (patch_base + 6) as *mut u8,
                            8,
                        );
                    }

                    patched += 1;
                    pos += STUB_LEN;
                    continue;
                }
            }
        }

        pos += 1;
    }

    if patched > 0 {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: patched {patched} Win32k stubs at 0x{image_base:X}\n",
            ));
        }
    }
}

/// Register a loaded DLL in `KiUserInvertedFunctionTable` so that SEH
/// unwinding can find its `.pdata` (RUNTIME_FUNCTION array).
///
/// Table layout:
/// ```text
///   +0x00  u32  CurrentSize
///   +0x04  u32  MaximumSize  (512)
///   +0x08  u32  Epoch
///   +0x0C  u8   Overflow + 3 reserved
///   +0x10  Entry[0]:  { u64 ExcDir, u64 Base, u32 Size, u32 ExcSize }  (24 bytes)
///   +0x28  Entry[1]:
///   ...
/// ```
fn register_inverted_function_table_entry(
    parsed: &PeParsedFile,
    _pe_data: &[u8],
    image_base: usize,
    image_size: usize,
    process_state: &crate::NtProcessState,
) {
    let ift_va = process_state.inverted_function_table_va();
    if ift_va == 0 {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform()
                .debug_log_print("NT shim: IFT registration skipped (ift_va=0)\n");
        }
        return;
    }

    // IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
    let exc_dd = match parsed.data_directory(3) {
        Some(dd) if dd.virtual_address != 0 && dd.size != 0 => dd,
        _ => return, // No .pdata — nothing to register.
    };

    let exc_dir_va = image_base + exc_dd.virtual_address as usize;
    let exc_dir_size = exc_dd.size;

    // Read current entry count and max.
    // The IFT is in ntdll's .mrdata section which may be read-only.
    // Make the page writable before reading/writing.
    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
    let ift_page = ift_va & !(PAGE_SIZE - 1);
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(ift_page);
    // SAFETY: ift_page is within the mapped ntdll PE image in guest VA.
    let _ = unsafe { process_state.pm.make_pages_writable(ptr, PAGE_SIZE) };

    // SAFETY: ift_va points into committed guest memory (ntdll's .mrdata).
    let current_size = unsafe { core::ptr::read(ift_va as *const u32) };
    let max_size = unsafe { core::ptr::read((ift_va + 4) as *const u32) };

    if current_size >= max_size {
        return; // Table full.
    }

    // Each entry is 24 bytes, starting at offset 0x10.
    let entry_offset = 0x10 + (current_size as usize) * 24;
    let entry_va = ift_va + entry_offset;

    // Make sure the entry's page is writable too (may span pages).
    let entry_page = entry_va & !(PAGE_SIZE - 1);
    if entry_page != ift_page {
        let ptr2 = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(entry_page);
        let _ = unsafe { process_state.pm.make_pages_writable(ptr2, PAGE_SIZE) };
    }

    if current_size >= max_size {
        return; // Table full.
    }

    // Each entry is 24 bytes, starting at offset 0x10.
    let entry_offset = 0x10 + (current_size as usize) * 24;
    let entry_va = ift_va + entry_offset;

    // SAFETY: entry_va is within the table's allocated space.
    unsafe {
        // ExceptionDirectory (u64)
        (entry_va as *mut u64).write(exc_dir_va as u64);
        // ImageBase (u64)
        ((entry_va + 8) as *mut u64).write(image_base as u64);
        // ImageSize (u32)
        ((entry_va + 16) as *mut u32).write(image_size as u32);
        // ExceptionDirectorySize (u32)
        ((entry_va + 20) as *mut u32).write(exc_dir_size);
        // Increment CurrentSize.
        (ift_va as *mut u32).write(current_size + 1);
    }

    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: IFT entry {current_size}: ExcDir=0x{exc_dir_va:X} Base=0x{image_base:X} Size=0x{image_size:X} ExcSize=0x{exc_dir_size:X}\n"
        ));
    }
}

/// Extract the DLL name from a PE file's export directory.
///
/// Returns `None` if the PE has no export directory or the name RVA is
/// invalid.
fn get_pe_export_dll_name<'a>(parsed: &PeParsedFile, pe_data: &'a [u8]) -> Option<&'a str> {
    let dd = parsed.data_directory(0)?; // IMAGE_DIRECTORY_ENTRY_EXPORT = 0
    if dd.virtual_address == 0 || dd.size == 0 {
        return None;
    }

    let export_dir_offset = parsed.rva_to_file_offset(dd.virtual_address)?;

    // The DLL name RVA is at offset 12 in IMAGE_EXPORT_DIRECTORY
    // (characteristics:4 + time_date_stamp:4 + major:2 + minor:2 = 12).
    let name_rva_off = export_dir_offset + 12;
    let name_rva_bytes = pe_data.get(name_rva_off..name_rva_off + 4)?;
    let name_rva = u32::from_le_bytes(name_rva_bytes.try_into().ok()?);

    if name_rva == 0 {
        return None;
    }

    parsed.read_string_at_rva(pe_data, name_rva)
}
///
/// Pre-reserves the entire image range as writable pages, then copies
/// section data and adjusts per-section permissions ΓÇö same strategy
/// as the runner's `PmMapper`.
struct PmMapper<'a> {
    pm: &'a litebox::mm::PageManager<Platform, PAGE_SIZE>,
}

impl PmMapper<'_> {
    fn pre_reserve(&self, va: usize, size: usize) -> Result<(), PeLoadError> {
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let addr = NonZeroAddress::<PAGE_SIZE>::new(va).ok_or(PeLoadError::MapFailed)?;
        let page_size = NonZeroPageSize::<PAGE_SIZE>::new(aligned).ok_or(PeLoadError::MapFailed)?;
        // NOREPLACE: fail if any part of the range is already mapped, preventing
        // DLL loads from silently overwriting existing heap/loader allocations.
        let flags = CreatePagesFlags::FIXED_ADDR
            | CreatePagesFlags::NOREPLACE
            | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
        unsafe {
            self.pm
                .create_writable_pages(Some(addr), page_size, flags, |_| Ok(0))
        }
        .map_err(|_| PeLoadError::MapFailed)?;
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
        if aligned == 0 {
            return Ok(());
        }

        // Pages are already committed-writable from pre_reserve().
        // Copy section data.
        if !data.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), va as *mut u8, data.len());
            }
        }
        if data.len() < size {
            unsafe {
                core::ptr::write_bytes((va + data.len()) as *mut u8, 0, size - data.len());
            }
        }

        // Leave all pages WRITABLE — ntdll's loader will write relocation
        // fixups, then call NtProtectVirtualMemory to set final permissions.
        // This emulates the real Windows kernel's PAGE_WRITECOPY behavior
        // where all SEC_IMAGE pages start copy-on-write (effectively writable).
        let _ = perm; // permissions applied later by ntdll

        Ok(())
    }
}

// ========================================================================
// NtQuerySection
// ========================================================================

/// NtQuerySection ΓÇö query information about a section object.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQuerySection(
///     HANDLE SectionHandle,                  // r10
///     SECTION_INFORMATION_CLASS InfoClass,    // rdx
///     PVOID SectionInformation,              // r8 (out)
///     SIZE_T SectionInformationLength,        // r9
///     PSIZE_T ReturnLength                   // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_query_section(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let section_handle = args.arg0 as u32;
    let info_class = args.arg1 as u32;
    let buffer_ptr = args.arg2;
    let buffer_len = args.arg3;

    let return_length_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);

    let section = handles
        .with(section_handle, |entry| match &entry.object {
            NtObject::Section {
                image_size,
                image_base,
                entry_point,
                section_alignment,
                is_dll,
                pe_data,
                ..
            } => Some((
                *image_size,
                *image_base,
                *entry_point,
                *section_alignment,
                *is_dll,
                Arc::clone(pe_data),
            )),
            _ => None,
        })
        .flatten();

    let Some(section) = section else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    let (image_size, image_base, entry_point, section_alignment, is_dll, pe_data) = section;

    match info_class {
        // SectionBasicInformation (0)
        0 => {
            // SECTION_BASIC_INFORMATION { BaseAddress, Attributes, Size }
            #[repr(C)]
            struct SectionBasicInfo {
                base_address: usize,
                attributes: u32,
                _pad: u32,
                size: i64,
            }
            let size = core::mem::size_of::<SectionBasicInfo>();
            if buffer_len < size {
                return NtStatus::STATUS_BUFFER_TOO_SMALL;
            }
            let info = SectionBasicInfo {
                base_address: 0,
                attributes: SEC_IMAGE,
                _pad: 0,
                size: image_size as i64,
            };
            if !crate::is_addr_range_writable(buffer_ptr, size) {
                return NtStatus::STATUS_ACCESS_VIOLATION;
            }
            unsafe {
                core::ptr::write_unaligned(buffer_ptr as *mut SectionBasicInfo, info);
            }
            if return_length_ptr != 0 {
                crate::try_write_guest_value_unaligned(return_length_ptr, size);
            }
            NtStatus::STATUS_SUCCESS
        }
        // SectionImageInformation (1)
        1 => {
            // SECTION_IMAGE_INFORMATION ΓÇö ntdll needs this for DLL loading.
            #[repr(C)]
            struct SectionImageInfo {
                transfer_address: usize, // entry point VA
                zero_bits: u32,
                maximum_stack_size: usize,
                committed_stack_size: usize,
                sub_system: u32,
                minor_sub_system_version: u16,
                major_sub_system_version: u16,
                major_operating_system_version: u16,
                minor_operating_system_version: u16,
                image_characteristics: u16,
                dll_characteristics: u16,
                machine: u16,
                image_contains_code: u8,
                image_flags: u8,
                loader_flags: u32,
                image_file_size: u32,
                checksum: u32,
            }
            let size = core::mem::size_of::<SectionImageInfo>();
            if buffer_len < size {
                return NtStatus::STATUS_BUFFER_TOO_SMALL;
            }

            // Re-parse to get detailed info.
            let Ok(parsed) = PeParsedFile::parse(&pe_data) else {
                return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
            };

            let info = SectionImageInfo {
                transfer_address: image_base as usize + entry_point as usize,
                zero_bits: 0,
                maximum_stack_size: parsed.optional_header.size_of_stack_reserve as usize,
                committed_stack_size: parsed.optional_header.size_of_stack_commit as usize,
                sub_system: parsed.optional_header.subsystem as u32,
                minor_sub_system_version: parsed.optional_header.minor_subsystem_version,
                major_sub_system_version: parsed.optional_header.major_subsystem_version,
                major_operating_system_version: parsed.optional_header.major_os_version,
                minor_operating_system_version: parsed.optional_header.minor_os_version,
                image_characteristics: parsed.file_header.characteristics,
                dll_characteristics: parsed.optional_header.dll_characteristics,
                machine: parsed.file_header.machine,
                image_contains_code: 1,
                image_flags: if is_dll { 0x04 } else { 0x00 }, // IMAGE_FLAGS_IS_DLL
                loader_flags: 0,
                image_file_size: pe_data.len() as u32,
                checksum: parsed.optional_header.checksum,
            };
            if !crate::is_addr_range_writable(buffer_ptr, size) {
                return NtStatus::STATUS_ACCESS_VIOLATION;
            }
            unsafe {
                core::ptr::write_unaligned(buffer_ptr as *mut SectionImageInfo, info);
            }
            if return_length_ptr != 0 {
                crate::try_write_guest_value_unaligned(return_length_ptr, size);
            }
            NtStatus::STATUS_SUCCESS
        }
        other => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!("NT shim: NtQuerySection unhandled info class {other}\n");
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_NOT_IMPLEMENTED
        }
    }
}
