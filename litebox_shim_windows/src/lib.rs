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
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use core::sync::atomic::{AtomicI32, Ordering};

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
    AccessMemory, Fault, MapMemory, MappingInfo, PeLoadError, PeParseError, PeParsedFile,
    Protection, ReadAt,
};
use litebox_platform_multiplex::Platform;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

mod nt_sysno {
    include!(concat!(env!("OUT_DIR"), "/nt_sysno.rs"));
}

use nt_sysno::NtSysno;

const PAGE_SIZE: usize = litebox_common_windows::loader::PAGE_SIZE;
const INITIAL_STACK_SIZE: usize = 1024 * 1024;
const INITIAL_PEB_SIZE: usize = PAGE_SIZE;
const INITIAL_TEB_SIZE: usize = PAGE_SIZE * 2;
const DEFAULT_PROCESS_EXIT_CODE: i32 = 1;
const NTDLL_PATHS: &[&str] = &[
    "/windows/system32/ntdll.dll",
    "/Windows/System32/ntdll.dll",
    "/ntdll.dll",
];
const INITIAL_PROCESS_ID: usize = 1000;
const INITIAL_THREAD_ID: usize = 1000;

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes)]
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
}

impl ProcessEnvironmentBlock {
    const fn new(image_base_address: usize) -> Self {
        Self {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            bit_field: 0,
            _padding0: 0,
            mutant: 0,
            image_base_address,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes)]
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
#[derive(Clone, Copy, FromBytes, IntoBytes)]
struct InitialClientId {
    /// CLIENT_ID.UniqueProcess: placeholder process identifier.
    unique_process: usize,
    /// CLIENT_ID.UniqueThread: placeholder thread identifier.
    unique_thread: usize,
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
}

impl ThreadEnvironmentBlock {
    const fn new(
        teb_address: usize,
        peb_address: usize,
        stack_base: usize,
        stack_top: usize,
    ) -> Self {
        Self {
            nt_tib: InitialNtTib {
                exception_list: 0,
                stack_base: stack_top,
                stack_limit: stack_base,
                sub_system_tib: 0,
                fiber_data: 0,
                arbitrary_user_pointer: 0,
                self_pointer: teb_address,
            },
            environment_pointer: 0,
            client_id: InitialClientId {
                unique_process: INITIAL_PROCESS_ID,
                unique_thread: INITIAL_THREAD_ID,
            },
            active_rpc_handle: 0,
            thread_local_storage_pointer: 0,
            process_environment_block: peb_address,
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
        let mapping = self.load_image(fs.clone(), path)?;
        let entry_point = mapping.entry_point;
        self.load_ntdll(fs)?;

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
        let process_environment =
            self.create_process_environment(mapping.base_addr, stack_base.as_usize(), stack_top)?;
        let exit_code = Arc::new(AtomicI32::new(DEFAULT_PROCESS_EXIT_CODE));

        Ok(LoadedProgram {
            entrypoints: WindowsShimEntrypoints {
                entry_point,
                stack_top,
                teb_address: process_environment.teb_address,
                exit_code: exit_code.clone(),
                _fs: PhantomData,
            },
            process: WindowsShimProcess { mapping, exit_code },
        })
    }

    fn load_ntdll(&self, fs: Arc<FS>) -> Result<(), WindowsLoadError> {
        for path in NTDLL_PATHS {
            match self.load_image(fs.clone(), path) {
                Ok(_) => {
                    litebox_util_log::debug!(path:% = path; "Loaded guest ntdll.dll");
                    return Ok(());
                }
                Err(error) if is_missing_file_error(&error) => {}
                Err(error) => return Err(error),
            }
        }

        litebox_util_log::debug!("Guest ntdll.dll was not found in the initial filesystem");
        Ok(())
    }

    fn load_image(&self, fs: Arc<FS>, path: &str) -> Result<MappingInfo, WindowsLoadError> {
        let file = PeImageFile::open(fs, path)?;
        let mut parsed = PeParsedFile::parse(&mut &file).map_err(WindowsLoadError::Parse)?;
        parsed
            .parse_trampoline(
                &mut &file,
                litebox_platform_multiplex::platform().get_syscall_entry_point(),
            )
            .map_err(WindowsLoadError::Parse)?;
        let mut mapper = PeImageMapper {
            file: &file,
            page_manager: &self.page_manager,
        };
        let mut memory = PeImageMemory;
        parsed
            .load(&mut mapper, &mut memory)
            .map_err(WindowsLoadError::Load)
    }

    fn create_process_environment(
        &self,
        image_base: usize,
        stack_base: usize,
        stack_top: usize,
    ) -> Result<WindowsProcessEnvironment, WindowsLoadError> {
        let peb_address = self.create_zeroed_pages(INITIAL_PEB_SIZE)?;
        let teb_address = self.create_zeroed_pages(INITIAL_TEB_SIZE)?;

        write_value(peb_address, ProcessEnvironmentBlock::new(image_base))?;
        write_value(
            teb_address,
            ThreadEnvironmentBlock::new(teb_address, peb_address, stack_base, stack_top),
        )?;

        litebox_util_log::debug!(
            peb:% = format_args!("{peb_address:#x}"),
            teb:% = format_args!("{teb_address:#x}"),
            image_base:% = format_args!("{image_base:#x}");
            "Created initial Windows PEB/TEB"
        );

        Ok(WindowsProcessEnvironment {
            _peb_address: peb_address,
            teb_address,
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
    exit_code: Arc<AtomicI32>,
    _fs: PhantomData<FS>,
}

impl<FS: NtShimFS> EnterShim for WindowsShimEntrypoints<FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        if !set_guest_teb(self.teb_address) {
            return ContinueOperation::Terminate;
        }
        ctx.rip = self.entry_point;
        ctx.rsp = self.stack_top;
        ctx.eflags = 0x202;
        litebox_util_log::debug!(
            entry_point:% = format_args!("{:#x}", self.entry_point),
            stack_top:% = format_args!("{:#x}", self.stack_top),
            teb:% = format_args!("{:#x}", self.teb_address);
            "Starting initial Windows guest thread"
        );
        ContinueOperation::Resume
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        if NtSysno::from_raw(ctx.orig_rax) == Some(NtSysno::NtTerminateProcess) {
            litebox_util_log::debug!(
                syscall_number = ctx.orig_rax,
                process_handle:% = format_args!("{:#x}", ctx.r10),
                exit_status:% = format_args!("{:#x}", ctx.rdx);
                "Handling NtTerminateProcess syscall"
            );
            self.exit_code
                .store(windows_exit_status_to_i32(ctx.rdx), Ordering::Relaxed);
        } else {
            litebox_util_log::debug!(
                syscall:? = NtSysno::from_raw(ctx.orig_rax),
                process_handle:% = format_args!("{:#x}", ctx.r10);
                "Unsupported Windows syscall"
            );
        }
        ContinueOperation::Terminate
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        litebox_util_log::debug!(
            exception:? = info.exception,
            rip:% = format_args!("{:#x}", ctx.rip),
            cr2:% = format_args!("{:#x}", info.cr2);
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
    exit_code: Arc<AtomicI32>,
}

struct WindowsProcessEnvironment {
    _peb_address: usize,
    teb_address: usize,
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

fn write_value<GuestValue>(address: usize, value: GuestValue) -> Result<(), PeImageAccessError>
where
    GuestValue: FromBytes + IntoBytes,
{
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<GuestValue>::from_usize(address);
    ptr.write_at_offset(0, value)
        .ok_or(PeImageAccessError::MemoryAccess)
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
