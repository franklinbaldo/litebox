// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A placeholder Windows NT shim for LiteBox.
//!
//! This crate intentionally only exposes the runner-facing skeleton for now.
//! The actual NT syscall, PE loading, and Windows process environment support
//! will be filled in piece by piece.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};
use litebox_common_windows::nt_status::NtStatus;

use litebox::LiteBox;
use litebox::mm::PageManager;
use litebox::platform::{
    CrngProvider, PageManagementProvider, PunchthroughProvider, PunchthroughToken,
    RawConstPointer as _, RawMutPointer as _, RawPointerProvider, StdioProvider,
    SystemInfoProvider, TimeProvider,
};
use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
use litebox::sync::RawSyncPrimitivesProvider;
use litebox_common_windows::NtSysno;
use litebox_common_windows::loader::{MappingInfo, PAGE_SIZE};

use crate::syscalls::SyscallRequest;
use crate::syscalls::directory_object::{
    DirectoryObject, DirectoryObjectHandleObject, DirectoryObjectSubsystem,
    QueryDirectoryObjectParameters, SymbolicLinkHandleObject, SymbolicLinkObject,
    SymbolicLinkSubsystem,
};
use crate::syscalls::event::{EventHandleObject, EventObject, EventSubsystem};
use crate::syscalls::file::{FileObject, FileObjectSubsystem};
use crate::syscalls::iocp::{IoCompletionHandleObject, IoCompletionSubsystem};
use crate::syscalls::mm;
use crate::syscalls::port::{ConnectPortParameters, PortHandleObject, PortSubsystem};
use crate::syscalls::registry::{RegistryKeyObject, RegistryKeySubsystem};
use crate::syscalls::section::{
    MapViewOfSectionParameters, SectionHandleObject, SectionObject, SectionSubsystem,
};
use crate::syscalls::timer::{
    TimerCreateParameters, TimerHandleObject, TimerSetParameters, TimerSubsystem,
};
use crate::syscalls::token::{TokenHandleObject, TokenSubsystem};
use crate::syscalls::wait_completion_packet::{
    WaitCompletionPacketAssociateParameters, WaitCompletionPacketCancelParameters,
    WaitCompletionPacketCreateParameters, WaitCompletionPacketHandleObject,
    WaitCompletionPacketSubsystem,
};
use crate::syscalls::worker_factory::{
    WorkerFactoryCreateParameters, WorkerFactoryHandleObject,
    WorkerFactorySetInformationParameters, WorkerFactoryShutdownParameters, WorkerFactorySubsystem,
};

mod loader;
mod nt_types;
mod syscalls;

#[cfg(test)]
mod tests;

const DEFAULT_PROCESS_EXIT_CODE: i32 = 1;
const AMD64_EXCEPTION_RECORD_SIZE: usize = 0x98;
const AMD64_MACHINE_FRAME_ALIGN: usize = 0x10;
const AMD64_MACHINE_FRAME_SIZE: usize = core::mem::size_of::<GuestMachineFrame>();
const AMD64_USER_CS: u16 = 0x33;
const AMD64_USER_SS: u16 = 0x2b;
const INITIAL_CONTEXT_MXCSR: u32 = 0x1f80;
const LEGACY_EXCEPTION_RECORD_OFFSET_AMD64: usize = 0x4f0;
const LEGACY_CONTEXT_PADDING_SIZE_AMD64: usize =
    LEGACY_EXCEPTION_RECORD_OFFSET_AMD64 - core::mem::size_of::<nt_types::X64Context>();
const LEGACY_CONTEXT_PADDING_AMD64: [u8; LEGACY_CONTEXT_PADDING_SIZE_AMD64] =
    [0; LEGACY_CONTEXT_PADDING_SIZE_AMD64];
const STATUS_INTEGER_DIVIDE_BY_ZERO: NtStatus = NtStatus::from_raw(0xc000_0094);

const _: () = assert!(core::mem::size_of::<GuestExceptionRecord>() == AMD64_EXCEPTION_RECORD_SIZE);

#[repr(C)]
#[derive(Clone, Copy, Debug, zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable)]
struct GuestExceptionRecord {
    exception_code: u32,
    exception_flags: u32,
    exception_record: u64,
    exception_address: u64,
    number_parameters: u32,
    unused_alignment: u32,
    exception_information: [u64; 15],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable)]
struct GuestMachineFrame {
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
}

fn align_up_pow2(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + (align - 1)) & !(align - 1)
}

fn exception_frame_rsp(rsp: usize, frame_size: usize) -> Option<usize> {
    Some(rsp.checked_sub(frame_size)? & !0x3f)
}

fn exception_frame_address(frame_base: usize, offset: usize) -> Option<usize> {
    frame_base.checked_add(offset)
}

fn ki_user_exception_dispatcher_machine_frame_offset(exception_record_offset: usize) -> usize {
    align_up_pow2(
        exception_record_offset + AMD64_EXCEPTION_RECORD_SIZE,
        AMD64_MACHINE_FRAME_ALIGN,
    )
}

fn ki_user_exception_dispatcher_frame_size(exception_record_offset: usize) -> usize {
    align_up_pow2(
        ki_user_exception_dispatcher_machine_frame_offset(exception_record_offset)
            + AMD64_MACHINE_FRAME_SIZE,
        0x40,
    )
}

fn read_value<Platform, T>(address: usize) -> Option<T>
where
    Platform: RawPointerProvider,
    T: zerocopy::FromBytes,
{
    let ptr = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<T>::from_usize(
        address,
    );
    ptr.read_at_offset(0)
}

/// A LiteBox platform with the services required by the Windows shim.
pub trait ShimPlatform:
    RawSyncPrimitivesProvider
    + RawPointerProvider
    + PageManagementProvider<PAGE_SIZE>
    + SystemInfoProvider
    + TimeProvider
    + 'static
{
}

impl<T> ShimPlatform for T where
    T: RawSyncPrimitivesProvider
        + RawPointerProvider
        + PageManagementProvider<PAGE_SIZE>
        + SystemInfoProvider
        + TimeProvider
        + 'static
{
}

fn initial_image_mappings<Platform: ShimPlatform>(
    image_path: &str,
    virtual_allocations: &WindowsVirtualAllocations<Platform>,
    application_mapping: MappingInfo,
    ntdll_mapping: Option<MappingInfo>,
    ntdll_path: Option<&str>,
) -> WindowsImageMappings<Platform> {
    let ntdll_base = ntdll_mapping.map(|mapping| mapping.base_addr);
    let mut image_mappings = BTreeMap::new();
    for (&base, allocation) in virtual_allocations.read().iter() {
        if allocation.type_ != mm::MemoryType::MEM_IMAGE.bits() {
            continue;
        }
        let name = if Some(base) == ntdll_base {
            ntdll_path.unwrap_or("/Windows/System32/ntdll.dll")
        } else {
            image_path
        };
        let entry_point = if Some(base) == ntdll_base {
            ntdll_mapping.map_or(0, |mapping| mapping.entry_point)
        } else if base == application_mapping.base_addr {
            application_mapping.entry_point
        } else {
            0
        };
        image_mappings.insert(
            base,
            WindowsImageMapping {
                name: String::from(name),
                size: allocation.size,
                entry_point,
            },
        );
    }
    WindowsImageMappings::<Platform>::new(image_mappings)
}

pub(crate) type ConstPtr<Platform, T> =
    <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
pub(crate) type MutPtr<Platform, T> =
    <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;
pub(crate) type WindowsPageManager<Platform> = PageManager<Platform, PAGE_SIZE>;
pub(crate) type WindowsHandleStore<Platform> =
    litebox::sync::RwLock<Platform, litebox::fd::RawDescriptorStorage>;
pub(crate) type WindowsNlsSectionMappings<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<(u32, u32), (usize, usize)>>;
pub(crate) type WindowsVirtualAllocations<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<usize, WindowsVirtualAllocation>>;
pub(crate) type WindowsImageMappings<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<usize, WindowsImageMapping>>;
pub(crate) type WindowsEventNamespace<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<String, Weak<EventObject<Platform>>>>;
pub(crate) type WindowsDirectoryNamespace<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<String, Arc<DirectoryObject<Platform>>>>;
pub(crate) type WindowsSymbolicLinkNamespace<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<String, Arc<SymbolicLinkObject<Platform>>>>;
pub(crate) type WindowsSectionNamespace<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<String, Weak<SectionObject>>>;
pub(crate) type WindowsSectionViews<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<usize, WindowsSectionView>>;

fn exception_to_ntstatus(info: &ExceptionInfo) -> NtStatus {
    match info.exception {
        Exception::DIVIDE_ERROR => {
            if info.error_code == 0 {
                STATUS_INTEGER_DIVIDE_BY_ZERO
            } else {
                NtStatus::from_raw(info.error_code)
            }
        }
        Exception::BREAKPOINT => NtStatus::BREAKPOINT,
        Exception::INVALID_OPCODE => NtStatus::ILLEGAL_INSTRUCTION,
        Exception::GENERAL_PROTECTION_FAULT | Exception::PAGE_FAULT => NtStatus::ACCESS_VIOLATION,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsSectionView {
    pub(crate) size: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsVirtualAllocation {
    pub(crate) base: usize,
    pub(crate) size: usize,
    pub(crate) allocation_protect: syscalls::mm::PageProtection,
    pub(crate) type_: u32,
    pub(crate) pages: rangemap::RangeMap<usize, syscalls::mm::PageProtection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsImageMapping {
    pub(crate) name: String,
    pub(crate) size: usize,
    pub(crate) entry_point: usize,
}

pub type DefaultFS<Platform> = WindowsFS<Platform>;

pub type WindowsFS<Platform> = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

/// A trait required for file systems to be used by the Windows shim.
pub trait ShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> ShimFS for T {}

fn write_value<Platform, T>(address: usize, value: T) -> Option<()>
where
    Platform: RawPointerProvider,
    T: zerocopy::FromBytes + zerocopy::IntoBytes,
{
    let ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<T>::from_usize(
        address,
    );
    ptr.write_at_offset(0, value)
}

fn write_slice<Platform, T>(address: usize, values: &[T]) -> Option<()>
where
    Platform: RawPointerProvider,
    T: Copy + zerocopy::FromBytes + zerocopy::IntoBytes,
{
    let ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<T>::from_usize(
        address,
    );
    for (index, value) in values.iter().copied().enumerate() {
        ptr.write_at_offset(index.try_into().ok()?, value)?;
    }
    Some(())
}

pub(crate) fn probe_guest_output_preserving_value<Platform, T>(
    ptr: MutPtr<Platform, T>,
) -> Result<(), NtStatus>
where
    Platform: RawPointerProvider,
    T: zerocopy::FromBytes + zerocopy::IntoBytes,
{
    let value = ptr.read_at_offset(0).ok_or(NtStatus::ACCESS_VIOLATION)?;
    ptr.write_at_offset(0, value)
        .ok_or(NtStatus::ACCESS_VIOLATION)
}

fn set_guest_teb<Platform>(platform: &Platform, teb_address: usize) -> bool
where
    Platform: PunchthroughProvider + RawPointerProvider,
    <Platform as PunchthroughProvider>::PunchthroughToken<'static>: PunchthroughToken<
        Punchthrough = litebox_common_linux::PunchthroughSyscall<'static, Platform>,
    >,
{
    let punchthrough: litebox_common_linux::PunchthroughSyscall<'static, Platform> =
        litebox_common_linux::PunchthroughSyscall::SetFsBase { addr: teb_address };
    let Some(token) = platform.get_punchthrough_token_for(punchthrough) else {
        litebox_util_log::warn!(teb:% = format_args!("{teb_address:#x}"); "Failed to get punchthrough token for Windows TEB base");
        return false;
    };

    if let Err(error) = token.execute() {
        litebox_util_log::warn!(error:? = error, teb:% = format_args!("{teb_address:#x}"); "Failed to set Windows TEB base");
        return false;
    }

    true
}

pub(crate) fn insert_raw_handle<Platform, Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore<Platform>,
    typed: litebox::fd::TypedFd<Subsystem>,
    cleanup_entry: impl FnOnce(Subsystem::Entry),
) -> Result<syscalls::Handle, NtStatus>
where
    Platform: RawSyncPrimitivesProvider,
{
    let mut handles = handles.write();
    let raw_fd = handles.fd_into_raw_integer(typed);
    let Some(handle) = syscalls::Handle::from_raw_fd(raw_fd) else {
        let typed = handles.fd_consume_raw_integer::<Subsystem>(raw_fd).ok();
        drop(handles);
        let entry = typed.and_then(|typed| {
            let mut descriptor_table = litebox.descriptor_table_mut();
            descriptor_table.remove(&typed)
        });
        if let Some(entry) = entry {
            cleanup_entry(entry);
        }
        return Err(NtStatus::QUOTA_EXCEEDED);
    };
    Ok(handle)
}

pub(crate) fn raw_handle_entry<Platform, Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore<Platform>,
    handle: syscalls::Handle,
) -> Option<litebox::fd::EntryHandle<Platform, Subsystem>>
where
    Platform: RawSyncPrimitivesProvider,
{
    let raw_fd = handle.raw_fd()?;
    let typed = {
        let handles = handles.read();
        handles.fd_from_raw_integer::<Subsystem>(raw_fd).ok()
    }?;
    litebox.descriptor_table().entry_handle(&typed)
}

pub(crate) fn duplicate_raw_handle<Platform, Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore<Platform>,
    handle: syscalls::Handle,
) -> Result<Option<syscalls::Handle>, NtStatus>
where
    Platform: RawSyncPrimitivesProvider,
{
    let Some(raw_fd) = handle.raw_fd() else {
        return Ok(None);
    };
    let typed = {
        let handles = handles.read();
        handles.fd_from_raw_integer::<Subsystem>(raw_fd).ok()
    };
    let Some(typed) = typed else {
        return Ok(None);
    };
    let Some(duplicated) = litebox.descriptor_table_mut().duplicate(&typed) else {
        return Ok(None);
    };
    insert_raw_handle::<Platform, Subsystem>(litebox, handles, duplicated, drop).map(Some)
}

pub(crate) fn remove_raw_handle<Platform, Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore<Platform>,
    handle: syscalls::Handle,
    cleanup_entry: impl FnOnce(Subsystem::Entry),
) where
    Platform: RawSyncPrimitivesProvider,
{
    let Some(raw_fd) = handle.raw_fd() else {
        return;
    };
    let _ =
        remove_raw_handle_by_raw_fd::<Platform, Subsystem>(litebox, handles, raw_fd, cleanup_entry);
}

pub(crate) fn remove_raw_handle_by_raw_fd<Platform, Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore<Platform>,
    raw_fd: usize,
    cleanup_entry: impl FnOnce(Subsystem::Entry),
) -> bool
where
    Platform: RawSyncPrimitivesProvider,
{
    let typed = {
        let mut handles = handles.write();
        handles.fd_consume_raw_integer::<Subsystem>(raw_fd).ok()
    };
    let Some(typed) = typed else {
        return false;
    };
    let entry = {
        let mut descriptor_table = litebox.descriptor_table_mut();
        descriptor_table.remove(&typed)
    };
    if let Some(entry) = entry {
        cleanup_entry(entry);
    }
    true
}

/// Builds a Windows NT shim instance.
pub struct WindowsShimBuilder<Platform: ShimPlatform> {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
}

impl<Platform: ShimPlatform> WindowsShimBuilder<Platform> {
    #[must_use]
    pub fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
            litebox: LiteBox::new(platform),
        }
    }

    #[must_use]
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Build a default layered file system with the given in-memory and tar read-only layers.
    #[must_use]
    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
    ) -> DefaultFS<Platform>
    where
        Platform: CrngProvider + StdioProvider,
    {
        default_fs(&self.litebox, in_mem_fs, tar_ro_fs)
    }

    #[must_use]
    pub fn build<FS: ShimFS>(self) -> WindowsShim<Platform, FS> {
        let global = Arc::new(GlobalState {
            platform: self.platform,
            page_manager: PageManager::new(&self.litebox),
            registry: syscalls::registry::RegistryStore::new(&self.litebox),
            qpc_boot_instant: TimeProvider::now(self.platform),
            litebox: self.litebox,
            _fs: PhantomData,
        });
        WindowsShim(global)
    }
}

pub struct WindowsShim<Platform: ShimPlatform, FS: ShimFS>(Arc<GlobalState<Platform, FS>>);

impl<Platform: ShimPlatform, FS: ShimFS> WindowsShim<Platform, FS> {
    /// Loads the program at `path` as the shim's initial task.
    ///
    /// TODO: PEB/TEB setup and initial handle table state are not yet implemented.
    pub fn load_program(
        &self,
        fs: Arc<FS>,
        path: &str,
        _argv: Vec<alloc::ffi::CString>,
        _envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram<Platform, FS>, loader::WindowsLoadError> {
        let load_info =
            loader::PeLoader::new(self.0.platform, fs.clone(), &self.0.page_manager).load(path)?;
        let image_mappings = initial_image_mappings::<Platform>(
            path,
            &load_info.virtual_allocations,
            load_info.application_mapping,
            load_info.ntdll_mapping,
            load_info.ntdll_path.as_deref(),
        );
        let process = Arc::new(Process {
            ntdll_mapping: load_info.ntdll_mapping,
            ntdll_exception_dispatcher: load_info.ntdll_exception_dispatcher,
            peb_address: load_info.environment.peb,
            handles: WindowsHandleStore::<Platform>::new(litebox::fd::RawDescriptorStorage::new()),
            event_namespace: WindowsEventNamespace::<Platform>::new(BTreeMap::new()),
            directory_namespace: WindowsDirectoryNamespace::<Platform>::new(
                syscalls::directory_object::initial_directory_namespace(),
            ),
            symbolic_link_namespace: WindowsSymbolicLinkNamespace::<Platform>::new(
                syscalls::directory_object::initial_symbolic_link_namespace(),
            ),
            section_namespace: WindowsSectionNamespace::<Platform>::new(BTreeMap::new()),
            section_views: WindowsSectionViews::<Platform>::new(BTreeMap::new()),
            nls_section_mappings: WindowsNlsSectionMappings::<Platform>::new(BTreeMap::new()),
            // TODO: Register stack, PEB/TEB, and process parameters once VM metadata can
            // distinguish those loader-owned mappings from guest-releasable allocations.
            virtual_allocations: load_info.virtual_allocations,
            image_mappings,
            system_lcid: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            user_lcid: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            user_ui_language: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            default_hard_error_mode: AtomicU32::new(0),
            cookie: syscalls::process::default_process_cookie(),
            scheduler_shared_data: AtomicUsize::new(0),
            thread_hidden_from_debugger: AtomicBool::new(false),
            exit_code: AtomicI32::new(DEFAULT_PROCESS_EXIT_CODE),
        });
        let task = Task {
            global: self.0.clone(),
            process: process.clone(),
            fs,
            entry_point: load_info.entry_point,
            stack_top: load_info.stack_top,
            teb_address: load_info.environment.teb,
            context: load_info.environment.context,
        };
        task.initialize_process_nls_sections();
        Ok(LoadedProgram {
            entrypoints: WindowsShimEntrypoints {
                task,
                _not_send: PhantomData,
            },
            process,
        })
    }
}

/// Global shim state shared by all Windows tasks loaded by this shim.
struct GlobalState<Platform: ShimPlatform, FS: ShimFS> {
    platform: &'static Platform,
    page_manager: WindowsPageManager<Platform>,
    registry: syscalls::registry::RegistryStore<Platform>,
    qpc_boot_instant: <Platform as TimeProvider>::Instant,
    litebox: LiteBox<Platform>,
    _fs: PhantomData<FS>,
}

/// Per-process Windows state shared by every thread in the process.
pub struct Process<Platform: ShimPlatform> {
    ntdll_mapping: Option<MappingInfo>,
    ntdll_exception_dispatcher: Option<usize>,
    peb_address: usize,
    handles: WindowsHandleStore<Platform>,
    event_namespace: WindowsEventNamespace<Platform>,
    directory_namespace: WindowsDirectoryNamespace<Platform>,
    symbolic_link_namespace: WindowsSymbolicLinkNamespace<Platform>,
    section_namespace: WindowsSectionNamespace<Platform>,
    section_views: WindowsSectionViews<Platform>,
    nls_section_mappings: WindowsNlsSectionMappings<Platform>,
    virtual_allocations: WindowsVirtualAllocations<Platform>,
    image_mappings: WindowsImageMappings<Platform>,
    system_lcid: AtomicU32,
    user_lcid: AtomicU32,
    user_ui_language: AtomicU32,
    default_hard_error_mode: AtomicU32,
    cookie: u32,
    scheduler_shared_data: AtomicUsize,
    thread_hidden_from_debugger: AtomicBool,
    exit_code: AtomicI32,
}

impl<Platform: ShimPlatform> Process<Platform> {
    /// Wait for the process to exit, returning its exit code.
    ///
    /// Currently a placeholder that returns a fixed exit code immediately.
    /// Once NT process lifecycle exists, this will actually block.
    #[must_use]
    pub fn wait(&self) -> i32 {
        // TODO: Wait for the NT process object once process lifecycle exists.
        self.exit_code.load(Ordering::Relaxed)
    }
}

struct Task<Platform: ShimPlatform, FS: ShimFS> {
    global: Arc<GlobalState<Platform, FS>>,
    process: Arc<Process<Platform>>,
    fs: Arc<FS>,
    entry_point: usize,
    stack_top: usize,
    context: usize,
    teb_address: usize,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn init(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation
    where
        Platform: PunchthroughProvider,
        <Platform as PunchthroughProvider>::PunchthroughToken<'static>: PunchthroughToken<
            Punchthrough = litebox_common_linux::PunchthroughSyscall<'static, Platform>,
        >,
    {
        if !set_guest_teb(self.global.platform, self.teb_address) {
            return ContinueOperation::Terminate;
        }

        ctx.rip = self.entry_point;
        debug_assert!(self.stack_top % 16 == core::mem::size_of::<usize>());
        ctx.rsp = self.stack_top;
        ctx.eflags = 0x202;
        ctx.rcx = self.context;
        ctx.rdx = self
            .process
            .ntdll_mapping
            .as_ref()
            .map_or(0, |mapping| mapping.base_addr);
        litebox_util_log::debug!(
            entry_point:% = format_args!("{:#x}", self.entry_point),
            stack_top:% = format_args!("{:#x}", self.stack_top);
            "Starting initial Windows guest thread"
        );

        ContinueOperation::Resume
    }

    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        let Some(req) = SyscallRequest::<Platform>::try_from_raw(ctx) else {
            litebox_util_log::debug!(
                syscall:? = NtSysno::from_raw(ctx.orig_rax);
                "Unsupported Windows syscall"
            );
            return ContinueOperation::Terminate;
        };
        litebox_util_log::debug!(
            syscall:? = NtSysno::from_raw(ctx.orig_rax);
            "Handling Windows syscall"
        );
        let (result, op) = match req {
            SyscallRequest::NtClose { handle } => {
                let status = self.sys_nt_close(handle);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtDuplicateObject {
                source_process_handle,
                source_handle,
                target_process_handle,
                target_handle,
                desired_access,
                handle_attributes,
                options,
            } => {
                let status = self.sys_nt_duplicate_object(
                    source_process_handle,
                    source_handle,
                    target_process_handle,
                    target_handle,
                    desired_access,
                    handle_attributes,
                    options,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtApphelpCacheControl {
                service_class,
                service_data,
            } => {
                let status = syscalls::apphelp::sys_nt_apphelp_cache_control::<Platform>(
                    service_class,
                    service_data,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtConnectPort {
                port_handle,
                port_name,
                security_quality_of_service,
                client_view,
                server_view,
                max_message_length,
                connection_information,
                connection_information_length,
            } => {
                let status = self.sys_nt_connect_port(ConnectPortParameters {
                    port_handle,
                    port_name,
                    security_quality_of_service,
                    client_view,
                    server_view,
                    max_message_length,
                    connection_information: connection_information
                        .map(|ptr| MutPtr::<Platform, _>::from_usize(ptr.as_usize())),
                    connection_information_length,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtAlpcSendWaitReceivePort {
                port_handle,
                flags,
                send_message,
                send_message_attributes,
                receive_message,
                buffer_length,
                receive_message_attributes,
                timeout,
            } => {
                let status = self.sys_nt_alpc_send_wait_receive_port(
                    syscalls::port::AlpcSendWaitReceivePortParameters {
                        port_handle,
                        flags,
                        send_message,
                        send_message_attributes,
                        receive_message,
                        buffer_length,
                        receive_message_attributes,
                        timeout,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateDirectoryObject {
                directory_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.sys_nt_create_directory_object(
                    directory_handle,
                    desired_access,
                    object_attributes,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateDirectoryObjectEx {
                directory_handle,
                desired_access,
                object_attributes,
                shadow_directory_handle,
                flags,
            } => {
                let status = self.sys_nt_create_directory_object_ex(
                    directory_handle,
                    desired_access,
                    object_attributes,
                    shadow_directory_handle,
                    flags,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateEvent {
                event_handle,
                desired_access,
                object_attributes,
                event_type,
                initial_state,
            } => {
                let status = self.sys_nt_create_event(
                    event_handle,
                    desired_access,
                    object_attributes,
                    event_type,
                    initial_state,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateIoCompletion {
                io_completion_handle,
                desired_access,
                object_attributes,
                number_of_concurrent_threads,
            } => {
                let status = self.sys_nt_create_io_completion(
                    io_completion_handle,
                    desired_access,
                    object_attributes,
                    number_of_concurrent_threads,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateSection {
                section_handle,
                desired_access,
                object_attributes,
                maximum_size,
                section_page_protection,
                allocation_attributes,
                file_handle,
            } => {
                let status = self.sys_nt_create_section(
                    section_handle,
                    desired_access,
                    object_attributes,
                    maximum_size,
                    section_page_protection,
                    allocation_attributes,
                    file_handle,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateSectionEx {
                section_handle,
                desired_access,
                object_attributes,
                maximum_size,
                section_page_protection,
                allocation_attributes,
                file_handle,
                extended_parameters,
                extended_parameter_count,
            } => {
                let status = self.sys_nt_create_section_ex(
                    section_handle,
                    desired_access,
                    object_attributes,
                    maximum_size,
                    section_page_protection,
                    allocation_attributes,
                    file_handle,
                    extended_parameters,
                    extended_parameter_count,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateSymbolicLinkObject {
                link_handle,
                desired_access,
                object_attributes,
                link_target,
            } => {
                let status = self.sys_nt_create_symbolic_link_object(
                    link_handle,
                    desired_access,
                    object_attributes,
                    link_target,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtAssociateWaitCompletionPacket {
                wait_completion_packet_handle,
                io_completion_handle,
                target_object_handle,
                key_context,
                apc_context,
                io_status,
                io_status_information,
                already_signaled,
            } => {
                let status = self.sys_nt_associate_wait_completion_packet(
                    WaitCompletionPacketAssociateParameters {
                        wait_completion_packet_handle,
                        io_completion_handle,
                        target_object_handle,
                        key_context,
                        apc_context,
                        io_status,
                        io_status_information,
                        already_signaled,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCancelWaitCompletionPacket {
                wait_completion_packet_handle,
                remove_signaled_packet,
            } => {
                let status = self.sys_nt_cancel_wait_completion_packet(
                    WaitCompletionPacketCancelParameters {
                        wait_completion_packet_handle,
                        remove_signaled_packet,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtContinue {
                context,
                test_alert,
            } => {
                let status = Self::sys_nt_continue(ctx, context, test_alert);
                litebox_util_log::debug!(
                    syscall:? = NtSysno::from_raw(ctx.orig_rax),
                    status:? = status;
                    "Handled Windows syscall"
                );
                if status.is_success() {
                    return ContinueOperation::Resume;
                }
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateTimer2 {
                timer_handle,
                timer_id,
                object_attributes,
                attributes,
                desired_access,
            } => {
                let status = self.sys_nt_create_timer2(TimerCreateParameters {
                    timer_handle,
                    timer_id,
                    object_attributes,
                    attributes,
                    desired_access,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetTimer2 {
                timer_handle,
                due_time,
                period,
                parameters,
            } => {
                let status = self.sys_nt_set_timer2(TimerSetParameters {
                    timer_handle,
                    due_time,
                    period,
                    parameters,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateWaitCompletionPacket {
                wait_completion_packet_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.sys_nt_create_wait_completion_packet(
                    WaitCompletionPacketCreateParameters {
                        wait_completion_packet_handle,
                        desired_access,
                        object_attributes,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateWorkerFactory {
                worker_factory_handle,
                desired_access,
                object_attributes,
                completion_port_handle,
                worker_process_handle,
                start_routine,
                start_parameter,
                max_thread_count,
                stack_reserve,
                stack_commit,
            } => {
                let status = self.sys_nt_create_worker_factory(WorkerFactoryCreateParameters {
                    worker_factory_handle,
                    desired_access,
                    object_attributes,
                    completion_port_handle,
                    worker_process_handle,
                    start_routine,
                    start_parameter,
                    max_thread_count,
                    stack_reserve,
                    stack_commit,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetInformationWorkerFactory {
                worker_factory_handle,
                worker_factory_information_class,
                worker_factory_information,
                worker_factory_information_length,
            } => {
                let status = self.sys_nt_set_information_worker_factory(
                    WorkerFactorySetInformationParameters {
                        handle: worker_factory_handle,
                        information_class: worker_factory_information_class,
                        information: worker_factory_information,
                        information_length: worker_factory_information_length,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtShutdownWorkerFactory {
                worker_factory_handle,
                pending_worker_count,
            } => {
                let status = self.sys_nt_shutdown_worker_factory(WorkerFactoryShutdownParameters {
                    handle: worker_factory_handle,
                    pending_worker_count,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenDirectoryObject {
                directory_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.sys_nt_open_directory_object(
                    directory_handle,
                    desired_access,
                    object_attributes,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenEvent {
                event_handle,
                desired_access,
                object_attributes,
            } => {
                let status =
                    self.sys_nt_open_event(event_handle, desired_access, object_attributes);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenSymbolicLinkObject {
                link_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.sys_nt_open_symbolic_link_object(
                    link_handle,
                    desired_access,
                    object_attributes,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenSection {
                section_handle,
                desired_access,
                object_attributes,
            } => {
                let status =
                    self.sys_nt_open_section(section_handle, desired_access, object_attributes);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetEvent {
                event_handle,
                previous_state,
            } => {
                let status = self.sys_nt_set_event(event_handle, previous_state);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtResetEvent {
                event_handle,
                previous_state,
            } => {
                let status = self.sys_nt_reset_event(event_handle, previous_state);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtClearEvent { event_handle } => {
                let status = self.sys_nt_clear_event(event_handle);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtPulseEvent {
                event_handle,
                previous_state,
            } => {
                let status = self.sys_nt_pulse_event(event_handle, previous_state);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryEvent {
                event_handle,
                event_information_class,
                event_information,
                event_information_length,
                return_length,
            } => {
                let status = self.sys_nt_query_event(
                    event_handle,
                    event_information_class,
                    event_information,
                    event_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryDirectoryObject {
                directory_handle,
                buffer,
                length,
                return_single_entry,
                restart_scan,
                context,
                return_length,
            } => {
                let status = self.sys_nt_query_directory_object(QueryDirectoryObjectParameters {
                    directory_handle,
                    buffer,
                    length,
                    return_single_entry,
                    restart_scan,
                    context,
                    return_length,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetEventBoostPriority { event_handle } => {
                let status = self.sys_nt_set_event(event_handle, None);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenFile {
                file_handle,
                desired_access,
                object_attributes,
                io_status_block,
                share_access,
                open_options,
            } => {
                let status = self.sys_nt_open_file(
                    file_handle,
                    desired_access,
                    object_attributes,
                    io_status_block,
                    share_access,
                    open_options,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateFile {
                file_handle,
                desired_access,
                object_attributes,
                io_status_block,
                allocation_size,
                file_attributes,
                share_access,
                create_disposition,
                create_options,
                ea_buffer,
                ea_length,
            } => {
                let status = self.sys_nt_create_file(
                    file_handle,
                    desired_access,
                    object_attributes,
                    io_status_block,
                    allocation_size,
                    file_attributes,
                    share_access,
                    create_disposition,
                    create_options,
                    ea_buffer,
                    ea_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtDeviceIoControlFile {
                file_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                io_control_code,
                input_buffer,
                input_buffer_length,
                output_buffer,
                output_buffer_length,
            } => {
                let status = self.sys_nt_device_io_control_file(
                    file_handle,
                    event,
                    apc_routine,
                    apc_context,
                    io_status_block,
                    io_control_code,
                    input_buffer,
                    input_buffer_length,
                    output_buffer,
                    output_buffer_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryVolumeInformationFile {
                file_handle,
                io_status_block,
                fs_information,
                fs_information_length,
                fs_information_class,
            } => {
                let status = self.sys_nt_query_volume_information_file(
                    file_handle,
                    io_status_block,
                    fs_information,
                    fs_information_length,
                    fs_information_class,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenKey {
                key_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.sys_nt_open_key(key_handle, desired_access, object_attributes);
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
                let status = self.sys_nt_query_value_key(
                    key_handle,
                    value_name,
                    key_value_information_class,
                    key_value_information,
                    length,
                    result_length,
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
                let status = self.sys_nt_get_nls_section_ptr(
                    section_type,
                    section_data,
                    context_data,
                    section_pointer,
                    section_size,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtInitializeNlsFiles {
                base_address,
                default_locale_id,
                default_casing_table_size,
            } => {
                let status = self.sys_nt_initialize_nls_files(
                    base_address,
                    default_locale_id,
                    default_casing_table_size,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryDefaultLocale {
                user_profile,
                default_locale_id,
            } => {
                let status = self.sys_nt_query_default_locale(user_profile, default_locale_id);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetDefaultLocale {
                user_profile,
                default_locale_id,
            } => {
                let status = self.sys_nt_set_default_locale(user_profile, default_locale_id);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryDefaultUILanguage {
                default_ui_language,
            } => {
                let status = self.sys_nt_query_default_ui_language(default_ui_language);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetDefaultUILanguage {
                default_ui_language,
            } => {
                let status = self.sys_nt_set_default_ui_language(default_ui_language);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryInstallUILanguage {
                install_ui_language,
            } => {
                let status = self.sys_nt_query_install_ui_language(install_ui_language);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryPerformanceCounter {
                performance_counter,
                performance_frequency,
            } => {
                let status = self
                    .sys_nt_query_performance_counter(performance_counter, performance_frequency);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySystemInformation {
                system_information_class,
                system_information,
                system_information_length,
                return_length,
            } => {
                let status = Self::sys_nt_query_system_information(
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
                let status = Self::sys_nt_query_system_information_ex(
                    system_information_class,
                    input_buffer,
                    input_buffer_length,
                    system_information,
                    system_information_length,
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
                let status = self.sys_nt_query_information_process(
                    process_handle,
                    process_information_class,
                    process_information,
                    process_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryInformationThread {
                thread_handle,
                thread_information_class,
                thread_information,
                thread_information_length,
                return_length,
            } => {
                let status = self.sys_nt_query_information_thread(
                    thread_handle,
                    thread_information_class,
                    thread_information,
                    thread_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryInformationToken {
                token_handle,
                token_information_class,
                token_information,
                token_information_length,
                return_length,
            } => {
                let status = self.sys_nt_query_information_token(
                    token_handle,
                    token_information_class,
                    token_information,
                    token_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySection {
                section_handle,
                section_information_class,
                section_information,
                section_information_length,
                return_length,
            } => {
                let status = self.sys_nt_query_section(
                    section_handle,
                    section_information_class,
                    section_information,
                    section_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySecurityAttributesToken {
                token_handle,
                attributes,
                number_of_attributes,
                buffer,
                length,
                return_length,
            } => {
                let status = self.sys_nt_query_security_attributes_token(
                    token_handle,
                    attributes,
                    number_of_attributes,
                    buffer,
                    length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySymbolicLinkObject {
                link_handle,
                link_target,
                return_length,
            } => {
                let status =
                    self.sys_nt_query_symbolic_link_object(link_handle, link_target, return_length);
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
                let status = Self::sys_nt_raise_hard_error(
                    error_status,
                    number_of_parameters,
                    unicode_string_parameter_mask,
                    parameters,
                    valid_response_options,
                    response,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtRaiseException {
                exception_record,
                context,
                first_chance,
            } => self.sys_nt_raise_exception(ctx, exception_record, context, first_chance),
            SyscallRequest::NtSetInformationProcess {
                process_handle,
                process_information_class,
                process_information,
                process_information_length,
            } => {
                let status = self.sys_nt_set_information_process(
                    process_handle,
                    process_information_class,
                    process_information,
                    process_information_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetInformationThread {
                thread_handle,
                thread_information_class,
                thread_information,
                thread_information_length,
            } => {
                let status = self.sys_nt_set_information_thread(
                    thread_handle,
                    thread_information_class,
                    thread_information,
                    thread_information_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtTestAlert => (NtStatus::SUCCESS, ContinueOperation::Resume),
            SyscallRequest::NtOpenThreadToken {
                thread_handle,
                desired_access,
                open_as_self,
                token_handle,
            } => {
                let status = self.sys_nt_open_thread_token(
                    thread_handle,
                    desired_access,
                    open_as_self,
                    token_handle,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenThreadTokenEx {
                thread_handle,
                desired_access,
                open_as_self,
                handle_attributes,
                token_handle,
            } => {
                let status = self.sys_nt_open_thread_token_ex(
                    thread_handle,
                    desired_access,
                    open_as_self,
                    handle_attributes,
                    token_handle,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenProcessToken {
                process_handle,
                desired_access,
                token_handle,
            } => {
                let status =
                    self.sys_nt_open_process_token(process_handle, desired_access, token_handle);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenProcessTokenEx {
                process_handle,
                desired_access,
                handle_attributes,
                token_handle,
            } => {
                let status = self.sys_nt_open_process_token_ex(
                    process_handle,
                    desired_access,
                    handle_attributes,
                    token_handle,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtConvertBetweenAuxiliaryCounterAndPerformanceCounter {
                flag,
                source,
                destination,
                conversion_error,
            } => {
                let status = Self::sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    flag,
                    source,
                    destination,
                    conversion_error,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtTraceControl {
                function_code,
                input_buffer,
                input_buffer_length,
                output_buffer,
                output_buffer_length,
                return_length,
            } => {
                let status = self.sys_nt_trace_control(
                    function_code,
                    input_buffer,
                    input_buffer_length,
                    output_buffer,
                    output_buffer_length,
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
                let status = self.sys_nt_trace_event(trace_handle, flags, field_size, fields);
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
                let status = self.sys_nt_allocate_virtual_memory(
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
                let status = self.sys_nt_allocate_virtual_memory_ex(
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
                let status = self.sys_nt_free_virtual_memory(
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
                let status = self.sys_nt_protect_virtual_memory(
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
                let status = self.sys_nt_query_virtual_memory(
                    process_handle,
                    base_address,
                    memory_information_class,
                    memory_information,
                    memory_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtMapViewOfSection {
                section_handle,
                process_handle,
                base_address,
                zero_bits,
                commit_size,
                section_offset,
                view_size,
                inherit_disposition,
                allocation_type,
                page_protection,
            } => {
                let status = self.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                    section_handle,
                    process_handle,
                    base_address,
                    zero_bits,
                    commit_size,
                    section_offset,
                    view_size,
                    inherit_disposition,
                    allocation_type,
                    page_protection,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtMapViewOfSectionEx {
                section_handle,
                process_handle,
                base_address,
                section_offset,
                view_size,
                allocation_type,
                page_protection,
                extended_parameters,
                extended_parameter_count,
            } => {
                let status = self.sys_nt_map_view_of_section_ex(
                    MapViewOfSectionParameters {
                        section_handle,
                        process_handle,
                        base_address,
                        zero_bits: 0,
                        commit_size: 0,
                        section_offset,
                        view_size,
                        inherit_disposition: 2,
                        allocation_type,
                        page_protection,
                    },
                    extended_parameters,
                    extended_parameter_count,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtUnmapViewOfSection {
                process_handle,
                base_address,
            } => {
                let status = self.sys_nt_unmap_view_of_section(process_handle, base_address);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtUnmapViewOfSectionEx {
                process_handle,
                base_address,
                flags,
            } => {
                let status =
                    self.sys_nt_unmap_view_of_section_ex(process_handle, base_address, flags);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtTerminateProcess {
                process_handle,
                exit_status,
            } => {
                if !process_handle.is_null() && !process_handle.is_current() {
                    // TODO: allow terminating other processes
                    litebox_util_log::error!("Terminating other processes is not yet supported");
                    (NtStatus::INVALID_HANDLE, ContinueOperation::Resume)
                } else {
                    // TODO: Terminate all threads except the calling one if process_handle is zero.
                    self.process.exit_code.store(exit_status, Ordering::Relaxed);
                    (NtStatus::SUCCESS, ContinueOperation::Terminate)
                }
            }
            SyscallRequest::NtSetWnfProcessNotificationEvent { notification_event } => {
                let _ = notification_event.as_raw();
                let status = syscalls::wnf::sys_nt_set_wnf_process_notification_event();
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryWnfStateData {
                state_name,
                type_id,
                explicit_scope,
                change_stamp,
                buffer,
                buffer_length,
            } => {
                let status = syscalls::wnf::sys_nt_query_wnf_state_data::<Platform>(
                    state_name,
                    type_id,
                    explicit_scope,
                    change_stamp,
                    buffer,
                    buffer_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryWnfStateNameInformation {
                state_name,
                name_information_class,
                explicit_scope,
                buffer,
                buffer_length,
            } => {
                let status = syscalls::wnf::sys_nt_query_wnf_state_name_information::<Platform>(
                    state_name,
                    name_information_class,
                    explicit_scope,
                    buffer,
                    buffer_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSubscribeWnfStateChange {
                state_name,
                change_stamp,
                event_mask,
                subscription_id,
            } => {
                let _ = (state_name, change_stamp, event_mask, subscription_id);
                let status = syscalls::wnf::sys_nt_subscribe_wnf_state_change();
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtUnsubscribeWnfStateChange { state_name } => {
                let _ = state_name;
                let status = syscalls::wnf::sys_nt_unsubscribe_wnf_state_change();
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtUpdateWnfStateData {
                state_name,
                buffer,
                length,
                type_id,
                explicit_scope,
                matching_change_stamp,
                check_stamp,
            } => {
                let status = syscalls::wnf::sys_nt_update_wnf_state_data::<Platform>(
                    state_name,
                    buffer,
                    length,
                    type_id,
                    explicit_scope,
                    matching_change_stamp,
                    check_stamp,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtManageHotPatch => {
                (NtStatus::NOT_IMPLEMENTED, ContinueOperation::Resume)
            }
        };

        litebox_util_log::debug!(
            syscall:? = NtSysno::from_raw(ctx.orig_rax),
            status:? = result;
            "Handled Windows syscall"
        );
        ctx.rax = result.as_raw().cast_unsigned() as usize;
        op
    }

    pub(crate) fn sys_nt_close(&self, handle: syscalls::Handle) -> NtStatus {
        let Some(raw_fd) = handle.raw_fd() else {
            return NtStatus::INVALID_HANDLE;
        };
        self.close_raw_fd(raw_fd, CloseRawHandleVisitor { task: self })
    }

    #[expect(clippy::too_many_arguments, reason = "models the Windows syscall ABI")]
    pub(crate) fn sys_nt_duplicate_object(
        &self,
        source_process_handle: syscalls::ProcessHandle,
        source_handle: syscalls::Handle,
        target_process_handle: syscalls::ProcessHandle,
        target_handle: Option<MutPtr<Platform, syscalls::Handle>>,
        _desired_access: u32,
        _handle_attributes: u32,
        options: u32,
    ) -> NtStatus {
        const DUPLICATE_CLOSE_SOURCE: u32 = 0x0000_0001;

        litebox_util_log::debug!(
            source_process_handle:% = format_args!("{:#x}", source_process_handle.as_handle().as_raw()),
            source_handle:% = format_args!("{:#x}", source_handle.as_raw()),
            target_process_handle:% = format_args!("{:#x}", target_process_handle.as_handle().as_raw()),
            target_handle:% = format_args!("{:#x}", target_handle.map_or(0, |ptr| ptr.as_usize())),
            options = options;
            "Handling NtDuplicateObject syscall"
        );

        if !source_process_handle.is_current() || !target_process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        if let Some(target_handle) = target_handle
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(target_handle)
        {
            return status;
        }

        let Some(raw_fd) = source_handle.raw_fd() else {
            return NtStatus::INVALID_HANDLE;
        };
        let Ok(duplicated_handle) = self.duplicate_raw_fd(raw_fd) else {
            return NtStatus::INVALID_HANDLE;
        };

        if let Some(target_handle) = target_handle
            && target_handle
                .write_at_offset(0, duplicated_handle)
                .is_none()
        {
            let _ = self.sys_nt_close(duplicated_handle);
            return NtStatus::ACCESS_VIOLATION;
        }

        if options & DUPLICATE_CLOSE_SOURCE != 0 {
            let _ = self.close_raw_fd(raw_fd, CloseRawHandleVisitor { task: self });
        }

        NtStatus::SUCCESS
    }

    fn duplicate_raw_fd(&self, raw_fd: usize) -> Result<syscalls::Handle, NtStatus> {
        if let Some(handle) = duplicate_raw_handle::<Platform, FileObjectSubsystem<FS>>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        if let Some(handle) = duplicate_raw_handle::<Platform, RegistryKeySubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        if let Some(handle) = duplicate_raw_handle::<Platform, EventSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        if let Some(handle) = duplicate_raw_handle::<Platform, DirectoryObjectSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        if let Some(handle) = duplicate_raw_handle::<Platform, SymbolicLinkSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        if let Some(handle) = duplicate_raw_handle::<Platform, IoCompletionSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        if let Some(handle) = duplicate_raw_handle::<Platform, PortSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        if let Some(handle) = duplicate_raw_handle::<Platform, TimerSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        if let Some(handle) =
            duplicate_raw_handle::<Platform, WaitCompletionPacketSubsystem<Platform>>(
                &self.global.litebox,
                &self.process.handles,
                syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
            )?
        {
            return Ok(handle);
        }
        if let Some(handle) = duplicate_raw_handle::<Platform, WorkerFactorySubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        if let Some(handle) = duplicate_raw_handle::<Platform, SectionSubsystem>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        if let Some(handle) = duplicate_raw_handle::<Platform, TokenSubsystem>(
            &self.global.litebox,
            &self.process.handles,
            syscalls::Handle::from_raw_fd(raw_fd).ok_or(NtStatus::INVALID_HANDLE)?,
        )? {
            return Ok(handle);
        }
        Err(NtStatus::INVALID_HANDLE)
    }

    fn close_raw_fd(
        &self,
        raw_fd: usize,
        visitor: impl RawHandleVisitor<Platform, FS>,
    ) -> NtStatus {
        if remove_raw_handle_by_raw_fd::<Platform, FileObjectSubsystem<FS>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |file| visitor.file(file),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, RegistryKeySubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |key| visitor.registry_key(key),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, EventSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |event| visitor.event(event),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, DirectoryObjectSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |directory| visitor.directory_object(directory),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, SymbolicLinkSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |link| visitor.symbolic_link(link),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, IoCompletionSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |io_completion| visitor.io_completion(io_completion),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, PortSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |port| visitor.port(port),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, TimerSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |timer| visitor.timer(timer),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, WaitCompletionPacketSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |wait_completion_packet| visitor.wait_completion_packet(wait_completion_packet),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, WorkerFactorySubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |worker_factory| visitor.worker_factory(worker_factory),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, SectionSubsystem>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |section| visitor.section(section),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, TokenSubsystem>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |token| visitor.token(token),
        ) {
            return NtStatus::SUCCESS;
        }
        NtStatus::INVALID_HANDLE
    }

    fn handle_interrupt_request(
        &self,
        _ctx: &mut litebox_common_linux::PtRegs,
    ) -> ContinueOperation {
        litebox_util_log::debug!(
            stack_top:% = format_args!("{:#x}", self.stack_top);
            "Windows guest interrupt"
        );
        ContinueOperation::Resume
    }

    fn sys_nt_raise_exception(
        &self,
        ctx: &mut litebox_common_linux::PtRegs,
        exception_record: ConstPtr<Platform, u8>,
        context: ConstPtr<Platform, u8>,
        first_chance: u8,
    ) -> (NtStatus, ContinueOperation) {
        let status = read_value::<Platform, u32>(exception_record.as_usize())
            .map_or(NtStatus::ACCESS_VIOLATION, NtStatus::from_raw);
        if first_chance == 0 {
            self.process
                .exit_code
                .store(status.as_raw(), Ordering::Relaxed);
            return (status, ContinueOperation::Terminate);
        }

        let Some(context) = read_value::<Platform, nt_types::X64Context>(context.as_usize()) else {
            return (NtStatus::ACCESS_VIOLATION, ContinueOperation::Resume);
        };
        let Some(exception_record) =
            read_value::<Platform, GuestExceptionRecord>(exception_record.as_usize())
        else {
            return (NtStatus::ACCESS_VIOLATION, ContinueOperation::Resume);
        };

        if self.redirect_to_guest_seh(ctx, &context, exception_record) {
            (NtStatus::SUCCESS, ContinueOperation::Resume)
        } else {
            self.process
                .exit_code
                .store(NtStatus::ACCESS_VIOLATION.as_raw(), Ordering::Relaxed);
            (NtStatus::ACCESS_VIOLATION, ContinueOperation::Terminate)
        }
    }

    fn handle_exception_request(
        &self,
        ctx: &mut litebox_common_linux::PtRegs,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        litebox_util_log::debug!(
            exception:? = info.exception,
            rip:% = format_args!("{:#x}", ctx.rip),
            cr2:% = format_args!("{:#x}", info.cr2);
            "Windows guest exception"
        );

        let status = exception_to_ntstatus(info);
        let context = Self::x64_context_from_regs(ctx);
        let exception_record = Self::guest_exception_record(ctx.rip, info, status);
        if self.redirect_to_guest_seh(ctx, &context, exception_record) {
            ContinueOperation::Resume
        } else {
            self.process
                .exit_code
                .store(status.as_raw(), Ordering::Relaxed);
            ContinueOperation::Terminate
        }
    }

    fn redirect_to_guest_seh(
        &self,
        ctx: &mut litebox_common_linux::PtRegs,
        context: &nt_types::X64Context,
        exception_record: GuestExceptionRecord,
    ) -> bool {
        let Some(dispatcher) = self.process.ntdll_exception_dispatcher else {
            litebox_util_log::debug!(
                "Cannot forward Windows guest exception: missing guest ntdll!KiUserExceptionDispatcher"
            );
            return false;
        };

        let exception_record_offset = LEGACY_EXCEPTION_RECORD_OFFSET_AMD64;
        let frame_size = ki_user_exception_dispatcher_frame_size(exception_record_offset);
        let Some(new_rsp) = exception_frame_rsp(ctx.rsp, frame_size) else {
            return false;
        };

        let Some(exception_record_address) =
            exception_frame_address(new_rsp, exception_record_offset)
        else {
            return false;
        };
        let Some(machine_frame_address) = exception_frame_address(
            new_rsp,
            ki_user_exception_dispatcher_machine_frame_offset(exception_record_offset),
        ) else {
            return false;
        };

        if write_value::<Platform, _>(new_rsp, *context).is_none()
            || write_slice::<Platform, _>(
                new_rsp + core::mem::size_of::<nt_types::X64Context>(),
                &LEGACY_CONTEXT_PADDING_AMD64,
            )
            .is_none()
            || write_value::<Platform, _>(exception_record_address, exception_record).is_none()
            || write_value::<Platform, _>(
                machine_frame_address,
                GuestMachineFrame {
                    rip: context.rip,
                    cs: u64::from(AMD64_USER_CS),
                    eflags: u64::from(context.e_flags),
                    rsp: context.rsp,
                    ss: u64::from(AMD64_USER_SS),
                },
            )
            .is_none()
        {
            return false;
        }

        ctx.rsp = new_rsp;
        ctx.rip = dispatcher;
        ctx.rcx = dispatcher;
        ctx.rax = 0;
        true
    }

    fn x64_context_from_regs(ctx: &litebox_common_linux::PtRegs) -> nt_types::X64Context {
        nt_types::X64Context {
            context_flags: nt_types::X64_CONTEXT_CONTROL
                | nt_types::X64_CONTEXT_INTEGER
                | nt_types::X64_CONTEXT_FLOATING_POINT
                | nt_types::X64_CONTEXT_DEBUG_REGISTERS,
            mx_csr: INITIAL_CONTEXT_MXCSR,
            seg_cs: AMD64_USER_CS,
            seg_ss: AMD64_USER_SS,
            e_flags: u32::try_from(ctx.eflags).unwrap_or(u32::MAX),
            rax: ctx.rax as u64,
            rcx: ctx.rcx as u64,
            rdx: ctx.rdx as u64,
            rbx: ctx.rbx as u64,
            rsp: ctx.rsp as u64,
            rbp: ctx.rbp as u64,
            rsi: ctx.rsi as u64,
            rdi: ctx.rdi as u64,
            r8: ctx.r8 as u64,
            r9: ctx.r9 as u64,
            r10: ctx.r10 as u64,
            r11: ctx.r11 as u64,
            r12: ctx.r12 as u64,
            r13: ctx.r13 as u64,
            r14: ctx.r14 as u64,
            r15: ctx.r15 as u64,
            rip: ctx.rip as u64,
            ..nt_types::X64Context::default()
        }
    }

    fn sys_nt_continue(
        ctx: &mut litebox_common_linux::PtRegs,
        context: ConstPtr<Platform, nt_types::X64Context>,
        test_alert: u8,
    ) -> NtStatus {
        let Some(context) = context.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let _ = test_alert;

        ctx.rax = context.rax as usize;
        ctx.rcx = context.rcx as usize;
        ctx.rdx = context.rdx as usize;
        ctx.rbx = context.rbx as usize;
        ctx.rsp = context.rsp as usize;
        ctx.rbp = context.rbp as usize;
        ctx.rsi = context.rsi as usize;
        ctx.rdi = context.rdi as usize;
        ctx.r8 = context.r8 as usize;
        ctx.r9 = context.r9 as usize;
        ctx.r10 = context.r10 as usize;
        ctx.r11 = context.r11 as usize;
        ctx.r12 = context.r12 as usize;
        ctx.r13 = context.r13 as usize;
        ctx.r14 = context.r14 as usize;
        ctx.r15 = context.r15 as usize;
        ctx.rip = context.rip as usize;
        ctx.eflags = context.e_flags as usize;

        NtStatus::SUCCESS
    }

    fn guest_exception_record(
        exception_address: usize,
        info: &ExceptionInfo,
        status: NtStatus,
    ) -> GuestExceptionRecord {
        let mut exception_information = [0; 15];
        let number_parameters = if info.exception == Exception::PAGE_FAULT {
            exception_information[0] = u64::from((info.error_code & (1 << 1)) != 0);
            exception_information[1] = info.cr2 as u64;
            2
        } else {
            0
        };

        GuestExceptionRecord {
            exception_code: u32::from_ne_bytes(status.as_raw().to_ne_bytes()),
            exception_flags: 0,
            exception_record: 0,
            exception_address: exception_address as u64,
            number_parameters,
            unused_alignment: 0,
            exception_information,
        }
    }
}

trait RawHandleVisitor<Platform: ShimPlatform, FS: ShimFS> {
    fn file(&self, file: FileObject<FS>);

    fn registry_key(&self, key: RegistryKeyObject<Platform>);

    fn event(&self, event: EventHandleObject<Platform>);

    fn directory_object(&self, directory: DirectoryObjectHandleObject<Platform>);

    fn symbolic_link(&self, link: SymbolicLinkHandleObject<Platform>);

    fn io_completion(&self, io_completion: IoCompletionHandleObject<Platform>);

    fn port(&self, port: PortHandleObject);

    fn timer(&self, timer: TimerHandleObject<Platform>);

    fn wait_completion_packet(
        &self,
        wait_completion_packet: WaitCompletionPacketHandleObject<Platform>,
    );

    fn worker_factory(&self, worker_factory: WorkerFactoryHandleObject<Platform>);

    fn section(&self, section: SectionHandleObject);

    fn token(&self, token: TokenHandleObject);
}

struct CloseRawHandleVisitor<'task, Platform: ShimPlatform, FS: ShimFS> {
    task: &'task Task<Platform, FS>,
}

impl<Platform: ShimPlatform, FS: ShimFS> RawHandleVisitor<Platform, FS>
    for CloseRawHandleVisitor<'_, Platform, FS>
{
    fn file(&self, file: FileObject<FS>) {
        self.task.close_file(file);
    }

    fn registry_key(&self, key: RegistryKeyObject<Platform>) {
        self.task.close_registry_key(key);
    }

    fn event(&self, event: EventHandleObject<Platform>) {
        Task::<Platform, FS>::close_event(event);
    }

    fn directory_object(&self, directory: DirectoryObjectHandleObject<Platform>) {
        Task::<Platform, FS>::close_directory_object(directory);
    }

    fn symbolic_link(&self, link: SymbolicLinkHandleObject<Platform>) {
        Task::<Platform, FS>::close_symbolic_link(link);
    }

    fn io_completion(&self, io_completion: IoCompletionHandleObject<Platform>) {
        Task::<Platform, FS>::close_io_completion(io_completion);
    }

    fn port(&self, port: PortHandleObject) {
        Task::<Platform, FS>::close_port(port);
    }

    fn timer(&self, timer: TimerHandleObject<Platform>) {
        Task::<Platform, FS>::close_timer(timer);
    }

    fn wait_completion_packet(
        &self,
        wait_completion_packet: WaitCompletionPacketHandleObject<Platform>,
    ) {
        Task::<Platform, FS>::close_wait_completion_packet(wait_completion_packet);
    }

    fn worker_factory(&self, worker_factory: WorkerFactoryHandleObject<Platform>) {
        Task::<Platform, FS>::close_worker_factory(worker_factory);
    }

    fn section(&self, section: SectionHandleObject) {
        Task::<Platform, FS>::close_section(section);
    }

    fn token(&self, token: TokenHandleObject) {
        Task::<Platform, FS>::close_token(token);
    }
}

/// The shim entrypoint object passed to the platform.
pub struct WindowsShimEntrypoints<Platform: ShimPlatform, FS: ShimFS> {
    task: Task<Platform, FS>,
    _not_send: PhantomData<*const ()>,
}

impl<Platform, FS> EnterShim for WindowsShimEntrypoints<Platform, FS>
where
    Platform: ShimPlatform + PunchthroughProvider,
    <Platform as PunchthroughProvider>::PunchthroughToken<'static>: PunchthroughToken<
        Punchthrough = litebox_common_linux::PunchthroughSyscall<'static, Platform>,
    >,
    FS: ShimFS,
{
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

/// A loaded Windows program and the process handle used to wait for it.
pub struct LoadedProgram<Platform: ShimPlatform, FS: ShimFS> {
    /// The initial-thread entrypoint state passed to the platform's `run_thread`.
    pub entrypoints: WindowsShimEntrypoints<Platform, FS>,
    /// Handle used to wait for the loaded program to exit.
    pub process: Arc<Process<Platform>>,
}

fn default_fs<Platform>(
    litebox: &LiteBox<Platform>,
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
) -> WindowsFS<Platform>
where
    Platform: ShimPlatform + CrngProvider + StdioProvider,
{
    let devices = litebox::fs::devices::FileSystem::new(litebox);
    litebox::fs::layered::FileSystem::new(
        litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            litebox,
            devices,
            tar_ro_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    )
}
