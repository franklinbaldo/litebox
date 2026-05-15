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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicI32, Ordering};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use litebox::LiteBox;
use litebox::mm::PageManager;
use litebox::platform::CrngProvider as _;
use litebox::platform::PunchthroughToken as _;
use litebox::platform::{
    PunchthroughProvider as _, RawConstPointer as _, RawMutPointer, RawPointerProvider,
    TimeProvider as _,
};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox_common_windows::loader::MappingInfo;
use litebox_platform_multiplex::Platform;

pub mod loader;
pub mod syscalls;

#[cfg(test)]
mod tests;

pub use loader::nt_types;
pub use loader::{PeImageAccessError, WindowsLoadError};

use crate::syscalls::event;
use crate::syscalls::wait_completion_packet;
use crate::syscalls::{NtSysno, SyscallRequest, hard_error, mm, registry, sysinfo, trace};

const PAGE_SIZE: usize = litebox_common_windows::loader::PAGE_SIZE;
const DEFAULT_PROCESS_EXIT_CODE: i32 = 1;
const HANDLE_SHIFT: u32 = 2;
const HANDLE_TAG_MASK: usize = (1usize << HANDLE_SHIFT) - 1;

#[repr(transparent)]
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub(crate) struct Handle(usize);

impl Handle {
    #[must_use]
    pub(crate) const fn from_raw(raw: usize) -> Self {
        Self(raw)
    }

    #[must_use]
    pub(crate) fn from_raw_fd(raw_fd: usize) -> Option<Self> {
        raw_fd
            .checked_add(1)?
            .checked_mul(1usize << HANDLE_SHIFT)
            .map(Self)
    }

    #[must_use]
    pub(crate) fn raw_fd(self) -> Option<usize> {
        if self.0 & HANDLE_TAG_MASK != 0 {
            return None;
        }
        (self.0 >> HANDLE_SHIFT).checked_sub(1)
    }

    #[must_use]
    pub(crate) const fn as_raw(self) -> usize {
        self.0
    }

    #[must_use]
    pub(crate) const fn is_null(self) -> bool {
        self.as_raw() == 0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProcessHandle(Handle);

impl ProcessHandle {
    pub(crate) const CURRENT: Self = Self::from_raw(usize::MAX);

    #[must_use]
    pub(crate) const fn from_raw(raw: usize) -> Self {
        Self(Handle::from_raw(raw))
    }

    #[must_use]
    pub(crate) const fn as_raw(self) -> usize {
        self.0.as_raw()
    }

    #[must_use]
    pub(crate) const fn is_null(self) -> bool {
        self.as_raw() == 0
    }

    #[must_use]
    pub(crate) fn is_current(self) -> bool {
        self == Self::CURRENT
    }
}

pub(crate) type WindowsPageManager = PageManager<Platform, PAGE_SIZE>;
pub(crate) type WindowsHandleStore =
    litebox::sync::RwLock<Platform, litebox::fd::RawDescriptorStorage>;
type WindowsEventHandle = alloc::sync::Arc<litebox::fd::TypedFd<event::EventSubsystem>>;
type WindowsObjectDirectoryHandle =
    alloc::sync::Arc<litebox::fd::TypedFd<syscalls::object::ObjectDirectorySubsystem>>;
type WindowsRegistryKeyHandle =
    alloc::sync::Arc<litebox::fd::TypedFd<registry::RegistryKeySubsystem>>;
type WindowsWaitCompletionPacketHandle =
    alloc::sync::Arc<litebox::fd::TypedFd<wait_completion_packet::WaitCompletionPacketSubsystem>>;
type WindowsNlsSectionMappings =
    litebox::sync::Mutex<Platform, BTreeMap<(u32, u32), (usize, usize)>>;
pub(crate) type WindowsVirtualAllocations =
    litebox::sync::Mutex<Platform, BTreeMap<usize, WindowsVirtualAllocation>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsVirtualAllocation {
    pub(crate) base: usize,
    pub(crate) size: usize,
    pub(crate) allocation_protect: u32,
}

pub(crate) fn insert_raw_handle<Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore,
    typed: litebox::fd::TypedFd<Subsystem>,
) -> Result<Handle, NtStatus> {
    let mut handles = handles.write();
    let raw_fd = handles.fd_into_raw_integer(typed);
    let Some(handle) = Handle::from_raw_fd(raw_fd) else {
        let typed = handles.fd_consume_raw_integer::<Subsystem>(raw_fd).ok();
        drop(handles);
        if let Some(typed) = typed {
            let removed = litebox.descriptor_table_mut().remove(&typed);
            debug_assert!(removed.is_some());
        }
        return Err(NtStatus::QUOTA_EXCEEDED);
    };
    Ok(handle)
}

pub(crate) fn raw_handle_entry<Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore,
    handle: Handle,
) -> Option<litebox::fd::EntryHandle<Platform, Subsystem>> {
    let raw_fd = handle.raw_fd()?;
    let typed = {
        let handles = handles.read();
        handles.fd_from_raw_integer::<Subsystem>(raw_fd).ok()
    }?;
    litebox.descriptor_table().entry_handle(&typed)
}

pub(crate) fn remove_raw_handle<Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore,
    handle: Handle,
) {
    let Some(raw_fd) = handle.raw_fd() else {
        return;
    };
    let typed = {
        let mut handles = handles.write();
        handles.fd_consume_raw_integer::<Subsystem>(raw_fd).ok()
    };
    if let Some(typed) = typed {
        let removed = litebox.descriptor_table_mut().remove(&typed);
        debug_assert!(removed.is_some());
    }
}

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

fn write_value<GuestValue>(address: usize, value: GuestValue) -> Option<()>
where
    GuestValue: FromBytes + IntoBytes,
{
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<GuestValue>::from_usize(address);
    ptr.write_at_offset(0, value)
}

fn write_slice<GuestValue>(address: usize, values: &[GuestValue]) -> Option<()>
where
    GuestValue: Copy + FromBytes + IntoBytes,
{
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<GuestValue>::from_usize(address);
    for (index, value) in values.iter().copied().enumerate() {
        ptr.write_at_offset(index.try_into().ok()?, value)?;
    }
    Some(())
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
        let platform = litebox_platform_multiplex::platform();
        let global = Arc::new(GlobalState {
            platform,
            page_manager: PageManager::new(&self.litebox),
            qpc_boot_instant: platform.now(),
            registry: registry::RegistryStore::new(&self.litebox),
            litebox: self.litebox,
            _fs: PhantomData,
        });
        WindowsShim(global)
    }
}

/// A placeholder Windows shim.
pub struct WindowsShim<FS: NtShimFS>(Arc<GlobalState<FS>>);

impl<FS: NtShimFS> Clone for WindowsShim<FS> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
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
        let load_info = loader::PeLoader::new(fs.clone(), &self.0.page_manager).load(path)?;
        let process = Arc::new(Process {
            mapping: load_info.application_mapping,
            ntdll_mapping: load_info.ntdll_mapping,
            handles: WindowsHandleStore::new(litebox::fd::RawDescriptorStorage::new()),
            nls_section_mappings: WindowsNlsSectionMappings::new(BTreeMap::new()),
            virtual_allocations: WindowsVirtualAllocations::new(
                load_info
                    .environment
                    .virtual_allocations
                    .into_iter()
                    .map(|allocation| (allocation.base, allocation))
                    .collect(),
            ),
            peb_address: load_info.environment.peb,
            cookie: generate_process_cookie(self.0.platform),
            exit_code: AtomicI32::new(DEFAULT_PROCESS_EXIT_CODE),
        });

        Ok(LoadedProgram {
            entrypoints: WindowsShimEntrypoints {
                task: Task {
                    global: self.0.clone(),
                    fs,
                    process: process.clone(),
                    entry_point: load_info.entry_point,
                    stack_top: load_info.stack_top,
                    teb_address: load_info.environment.teb,
                },
                _not_send: PhantomData,
            },
            process: WindowsShimProcess(process),
        })
    }

    /// Returns the LiteBox object for the shim.
    #[must_use]
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.0.litebox
    }
}

/// Global shim state shared by all Windows tasks loaded by this shim.
struct GlobalState<FS: NtShimFS> {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    page_manager: WindowsPageManager,
    qpc_boot_instant: <Platform as litebox::platform::TimeProvider>::Instant,
    registry: registry::RegistryStore,
    _fs: PhantomData<FS>,
}

/// Per-process Windows state shared by every thread in the process.
struct Process {
    mapping: MappingInfo,
    ntdll_mapping: Option<MappingInfo>,
    handles: WindowsHandleStore,
    nls_section_mappings: WindowsNlsSectionMappings,
    virtual_allocations: WindowsVirtualAllocations,
    peb_address: usize,
    cookie: u32,
    exit_code: AtomicI32,
}

struct Task<FS: NtShimFS> {
    global: Arc<GlobalState<FS>>,
    fs: Arc<FS>,
    process: Arc<Process>,
    entry_point: usize,
    stack_top: usize,
    teb_address: usize,
}

/// The shim entrypoint object passed to the platform.
pub struct WindowsShimEntrypoints<FS: NtShimFS> {
    task: Task<FS>,
    _not_send: PhantomData<*const ()>,
}

impl<FS: NtShimFS> EnterShim for WindowsShimEntrypoints<FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.task.init(ctx)
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.task.handle_syscall_request(ctx)
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        self.task.handle_exception_request(ctx, info)
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.task.handle_interrupt_request(ctx)
    }
}

impl<FS: NtShimFS> Task<FS> {
    fn init(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        ctx.rip = self.entry_point;
        let stack_top_alignment = self.stack_top % 16;
        debug_assert!(stack_top_alignment == 0 || stack_top_alignment == 8);
        ctx.rsp = if stack_top_alignment == 0 {
            self.stack_top - core::mem::size_of::<usize>()
        } else {
            self.stack_top
        };
        ctx.eflags = 0x202;
        // TODO: Build the initial CONTEXT
        ctx.rcx = 0;
        ctx.rdx = if self.process.ntdll_mapping.is_some() {
            self.process.mapping.base_addr
        } else {
            0
        };
        ctx.r8 = 0;
        ctx.r9 = 0;
        litebox_util_log::debug!(
            entry_point:% = format_args!("{:#x}", self.entry_point),
            stack_top:% = format_args!("{:#x}", self.stack_top);
            "Starting initial Windows guest thread"
        );

        set_guest_teb(self.teb_address);

        ContinueOperation::Resume
    }

    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        let Some(req) = SyscallRequest::<Platform>::try_from_raw(ctx) else {
            litebox_util_log::debug!(
                syscall:? = NtSysno::from_raw(ctx.orig_rax),
                process_handle:% = format_args!("{:#x}", ctx.r10);
                "Unsupported Windows syscall"
            );
            return ContinueOperation::Terminate;
        };
        litebox_util_log::debug!(
            syscall:? = req;
            "Handling Windows"
        );
        let (result, op) = match req {
            SyscallRequest::NtCreateEvent {
                event_handle,
                desired_access,
                object_attributes,
                event_type,
                initial_state,
            } => {
                let status = event::handle_nt_create_event(
                    &self.global.litebox,
                    &self.process.handles,
                    event_handle,
                    desired_access,
                    object_attributes,
                    event_type,
                    initial_state,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateWaitCompletionPacket {
                wait_completion_packet_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.handle_nt_create_wait_completion_packet(
                    wait_completion_packet_handle,
                    desired_access,
                    object_attributes,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenDirectoryObject {
                directory_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.handle_nt_open_directory_object(
                    directory_handle,
                    desired_access,
                    object_attributes,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtClose { handle } => {
                let status = self.handle_nt_close(handle);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtClearEvent { event_handle } => {
                let status = event::handle_nt_clear_event(
                    &self.global.litebox,
                    &self.process.handles,
                    event_handle,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenKey {
                key_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.handle_nt_open_key(key_handle, desired_access, object_attributes);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryValueKey {
                key_handle,
                value_name,
                key_value_information_class,
                key_value_information,
                length,
                result_length,
            } => {
                let status = self.handle_nt_query_value_key(
                    key_handle,
                    value_name,
                    key_value_information_class,
                    key_value_information,
                    length,
                    result_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtResetEvent {
                event_handle,
                previous_state,
            } => {
                let status = event::handle_nt_reset_event(
                    &self.global.litebox,
                    &self.process.handles,
                    event_handle,
                    previous_state,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetEvent {
                event_handle,
                previous_state,
            } => {
                let status = event::handle_nt_set_event(
                    &self.global.litebox,
                    &self.process.handles,
                    event_handle,
                    previous_state,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtAllocateVirtualMemory {
                process_handle,
                base_address,
                zero_bits,
                region_size,
                allocation_type,
                protect,
            } => {
                let status = self.handle_nt_allocate_virtual_memory(
                    process_handle,
                    base_address,
                    zero_bits,
                    region_size,
                    allocation_type,
                    protect,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtAllocateVirtualMemoryEx {
                process_handle,
                base_address,
                region_size,
                allocation_type,
                protect,
                extended_parameters,
                extended_parameter_count,
            } => {
                let status = self.handle_nt_allocate_virtual_memory_ex(
                    process_handle,
                    base_address,
                    region_size,
                    allocation_type,
                    protect,
                    mm::MemoryExtendedParameters {
                        parameters: extended_parameters,
                        count: extended_parameter_count,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtFreeVirtualMemory {
                process_handle,
                base_address,
                region_size,
                free_type,
            } => {
                let status = self.handle_nt_free_virtual_memory(
                    process_handle,
                    base_address,
                    region_size,
                    free_type,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtProtectVirtualMemory {
                process_handle,
                base_address,
                region_size,
                new_protect,
                old_protect,
            } => {
                let status = self.handle_nt_protect_virtual_memory(
                    process_handle,
                    base_address,
                    region_size,
                    new_protect,
                    old_protect,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryVirtualMemory {
                process_handle,
                base_address,
                memory_information_class,
                memory_information,
                memory_information_length,
                return_length,
            } => {
                let status = self.handle_nt_query_virtual_memory(
                    process_handle,
                    base_address,
                    memory_information_class,
                    memory_information,
                    memory_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryInformationProcess {
                process_handle,
                process_information_class,
                process_information,
                process_information_length,
                return_length,
            } => {
                let status = self.handle_nt_query_information_process(
                    process_handle,
                    process_information_class,
                    process_information,
                    process_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtGetNlsSectionPtr {
                section_type,
                section_data,
                context_data,
                section_pointer,
                section_size,
            } => {
                let status = self.handle_nt_get_nls_section_ptr(
                    section_type,
                    section_data,
                    context_data,
                    section_pointer,
                    section_size,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtTerminateProcess {
                process_handle,
                exit_status,
            } => {
                if !process_handle.is_null() && !process_handle.is_current() {
                    // TODO: allow terminating other processes
                    (NtStatus::INVALID_HANDLE, ContinueOperation::Resume)
                } else {
                    // TODO: Terminate all threads except the calling one if process_handle is zero.
                    self.process.exit_code.store(exit_status, Ordering::Relaxed);
                    (NtStatus::SUCCESS, ContinueOperation::Terminate)
                }
            }
            SyscallRequest::NtQueryPerformanceCounter {
                performance_counter,
                performance_frequency,
            } => {
                let status = sysinfo::handle_nt_query_performance_counter(
                    performance_counter,
                    performance_frequency,
                    self.global.qpc_boot_instant,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySystemInformation {
                system_information_class,
                system_information,
                system_information_length,
                return_length,
            } => {
                let status = sysinfo::handle_nt_query_system_information(
                    system_information_class,
                    system_information,
                    system_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySystemInformationEx {
                system_information_class,
                input_buffer,
                input_buffer_length,
                system_information,
                system_information_length,
                return_length,
            } => {
                let status = sysinfo::handle_nt_query_system_information_ex(
                    system_information_class,
                    input_buffer,
                    input_buffer_length,
                    system_information,
                    system_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtTraceEvent {
                trace_handle,
                flags,
                field_size,
                fields,
            } => {
                let status = trace::handle_nt_trace_event(trace_handle, flags, field_size, fields);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtRaiseHardError {
                error_status,
                number_of_parameters,
                unicode_string_parameter_mask,
                parameters,
                valid_response_options,
                response,
            } => {
                let status = hard_error::handle_nt_raise_hard_error(
                    error_status,
                    number_of_parameters,
                    unicode_string_parameter_mask,
                    parameters,
                    valid_response_options,
                    response,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtManageHotPatch => {
                (NtStatus::NOT_IMPLEMENTED, ContinueOperation::Resume)
            }
        };

        ctx.rax = result.as_raw().cast_unsigned() as usize;
        op
    }

    pub(crate) fn handle_nt_close(&self, handle: Handle) -> NtStatus {
        let status = self
            .run_on_raw_handle(
                handle,
                |raw_fd, _event| self.close_raw_handle::<event::EventSubsystem>(raw_fd),
                |raw_fd, _directory| {
                    self.close_raw_handle::<syscalls::object::ObjectDirectorySubsystem>(raw_fd)
                },
                |raw_fd, _key| self.close_raw_handle::<registry::RegistryKeySubsystem>(raw_fd),
                |raw_fd, _packet| {
                    self.close_raw_handle::<wait_completion_packet::WaitCompletionPacketSubsystem>(
                        raw_fd,
                    )
                },
            )
            .unwrap_or(NtStatus::INVALID_HANDLE);

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                handle:% = format_args!("{:#x}", handle.as_raw());
                "Handled NtClose syscall"
            );
        }

        status
    }

    pub(crate) fn run_on_raw_handle<R>(
        &self,
        handle: Handle,
        event: impl FnOnce(usize, WindowsEventHandle) -> R,
        object_directory: impl FnOnce(usize, WindowsObjectDirectoryHandle) -> R,
        registry_key: impl FnOnce(usize, WindowsRegistryKeyHandle) -> R,
        wait_completion_packet: impl FnOnce(usize, WindowsWaitCompletionPacketHandle) -> R,
    ) -> Result<R, NtStatus> {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let handles = self.process.handles.read();
        if let Ok(fd) = handles.fd_from_raw_integer::<event::EventSubsystem>(raw_fd) {
            drop(handles);
            return Ok(event(raw_fd, fd));
        }
        if let Ok(fd) =
            handles.fd_from_raw_integer::<syscalls::object::ObjectDirectorySubsystem>(raw_fd)
        {
            drop(handles);
            return Ok(object_directory(raw_fd, fd));
        }
        if let Ok(fd) = handles.fd_from_raw_integer::<registry::RegistryKeySubsystem>(raw_fd) {
            drop(handles);
            return Ok(registry_key(raw_fd, fd));
        }
        if let Ok(fd) = handles
            .fd_from_raw_integer::<wait_completion_packet::WaitCompletionPacketSubsystem>(raw_fd)
        {
            drop(handles);
            return Ok(wait_completion_packet(raw_fd, fd));
        }

        Err(NtStatus::INVALID_HANDLE)
    }

    fn close_raw_handle<Subsystem: litebox::fd::FdEnabledSubsystem>(
        &self,
        raw_fd: usize,
    ) -> NtStatus {
        let typed = {
            let mut handles = self.process.handles.write();
            handles.fd_consume_raw_integer::<Subsystem>(raw_fd).ok()
        };
        let Some(typed) = typed else {
            return NtStatus::INVALID_HANDLE;
        };
        let removed = self.global.litebox.descriptor_table_mut().remove(&typed);
        debug_assert!(removed.is_some());
        NtStatus::SUCCESS
    }

    fn handle_exception_request(
        &self,
        ctx: &mut litebox_common_linux::PtRegs,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        litebox_util_log::debug!(
            exception:? = info.exception,
            rip:% = format_args!("{:#x}", ctx.rip),
            cr2:% = format_args!("{:#x}", info.cr2),
            teb:% = format_args!("{:#x}", self.teb_address);
            "Windows guest exception"
        );
        // TODO: Translate hardware exceptions into Windows SEH where appropriate.
        ContinueOperation::Terminate
    }

    fn handle_interrupt_request(
        &self,
        _ctx: &mut litebox_common_linux::PtRegs,
    ) -> ContinueOperation {
        litebox_util_log::debug!(
            teb:% = format_args!("{:#x}", self.teb_address);
            "Windows guest interrupt"
        );
        ContinueOperation::Resume
    }
}

fn generate_process_cookie(platform: &Platform) -> u32 {
    let mut bytes = [0; size_of::<u32>()];
    platform.fill_bytes_crng(&mut bytes);
    let cookie = u32::from_ne_bytes(bytes);
    if cookie == 0 { 1 } else { cookie }
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

/// A loaded Windows program and the process handle used to wait for it.
pub struct LoadedProgram<FS: NtShimFS> {
    pub entrypoints: WindowsShimEntrypoints<FS>,
    pub process: WindowsShimProcess,
}

/// A placeholder handle to a process loaded via [`WindowsShim::load_program`].
pub struct WindowsShimProcess(Arc<Process>);

impl WindowsShimProcess {
    /// Returns information about the loaded PE image mapping.
    #[must_use]
    pub fn mapping(&self) -> &MappingInfo {
        &self.0.mapping
    }

    /// Wait for the process to exit, returning its exit code.
    #[must_use]
    pub fn wait(&self) -> i32 {
        // TODO: Wait for the NT process object once process lifecycle exists.
        self.0.exit_code.load(Ordering::Relaxed)
    }
}
