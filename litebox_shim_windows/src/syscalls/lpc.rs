use core::marker::PhantomData;
use core::mem::size_of;

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use rangemap::RangeMap;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::Handle;
use super::mm::{MemoryType, PageProtection, create_pages};
use crate::nt_types::{ProcessEnvironmentBlock, ThreadEnvironmentBlock, UnicodeString};
use crate::{
    ConstPtr, MutPtr, PAGE_SIZE, ShimFS, ShimPlatform, Task, WindowsSectionView,
    WindowsVirtualAllocation, insert_raw_handle, remove_raw_handle,
};

const WINDOWS_API_PORT: &str = r"\Windows\ApiPort";
const CSR_API_CONNECTINFO_SIZE: usize = 0x30;
const CSR_MAX_MESSAGE_LENGTH: u32 = 0x148;
const CSR_SERVER_PROCESS_ID: usize = 1;
const CSR_SERVER_DLL_NAMES: u32 = 2;

#[cfg(test)]
static FAIL_NEXT_LPC_WRITEBACK_AFTER_MAPPING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub(crate) struct LpcPortSubsystem(PhantomData<fn()>);

impl FdEnabledSubsystem for LpcPortSubsystem {
    type Entry = LpcPortHandleObject;
}

impl FdEnabledSubsystemEntry for LpcPortHandleObject {}

/// Connect-only LPC port handle for the CSR API port.
///
/// `NtRequestWaitReplyPort` is intentionally not decoded by the shim yet, so
/// any future request/reply traffic fails closed as an unsupported syscall
/// instead of succeeding against a half-emulated CSR server.
pub(crate) struct LpcPortHandleObject {
    _port_name: alloc::string::String,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct PortView {
    length: u32,
    _padding: u32,
    section_handle: Handle,
    section_offset: u64,
    view_size: usize,
    view_base: usize,
    view_remote_base: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct RemotePortView {
    length: u32,
    _padding: u32,
    view_size: usize,
    view_base: usize,
}

/// Win10 x64 `CSR_API_CONNECTINFO`/`CSR_CONNECTION_INFO` layout.
///
/// The guest supplies the expected byte length, which must match this 0x30-byte
/// layout before Phase-1 fills it. A different ntdll layout therefore fails
/// closed with `STATUS_INFO_LENGTH_MISMATCH`.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct CsrApiConnectInfo {
    shared_section_base: usize,
    shared_static_server_data: usize,
    shared_section_heap: usize,
    debug_flags: u32,
    size_of_peb_data: u32,
    size_of_teb_data: u32,
    number_of_server_dll_names: u32,
    server_process_id: usize,
}

const _: () = assert!(size_of::<CsrApiConnectInfo>() == CSR_API_CONNECTINFO_SIZE);

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_connect_port(
        &self,
        port_handle: MutPtr<Platform, Handle>,
        port_name: ConstPtr<Platform, UnicodeString>,
        _security_qos: Option<ConstPtr<Platform, u8>>,
        client_view: Option<MutPtr<Platform, u8>>,
        server_view: Option<MutPtr<Platform, u8>>,
        max_message_length: Option<MutPtr<Platform, u32>>,
        connection_information: Option<MutPtr<Platform, u8>>,
        connection_information_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let port_name = match port_name
            .read_at_offset(0)
            .ok_or(NtStatus::ACCESS_VIOLATION)
            .and_then(UnicodeString::read_string::<Platform>)
        {
            Ok(name) => name,
            Err(status) => return status,
        };
        if !port_name.eq_ignore_ascii_case(WINDOWS_API_PORT) {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        }

        let client_view = match client_view {
            Some(client_view) => client_view,
            None => return NtStatus::INVALID_PARAMETER,
        };
        let connection_information = match connection_information {
            Some(connection_information) => connection_information,
            None => return NtStatus::INVALID_PARAMETER,
        };
        let connection_information_length = match connection_information_length {
            Some(connection_information_length) => connection_information_length,
            None => return NtStatus::INVALID_PARAMETER,
        };

        let client_view_value = match read_process_output::<Platform, PortView>(client_view) {
            Some(view) => view,
            None => return NtStatus::ACCESS_VIOLATION,
        };
        if client_view_value.length as usize != size_of::<PortView>()
            || client_view_value.view_size == 0
        {
            return NtStatus::INVALID_PARAMETER;
        }
        if let Some(server_view) = server_view
            && let Some(view) = read_process_output::<Platform, RemotePortView>(server_view)
            && view.length as usize != size_of::<RemotePortView>()
        {
            return NtStatus::INVALID_PARAMETER;
        }

        let connection_info_len = match connection_information_length.read_at_offset(0) {
            Some(length) => length as usize,
            None => return NtStatus::ACCESS_VIOLATION,
        };
        if connection_info_len != size_of::<CsrApiConnectInfo>() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }

        if probe_lpc_outputs::<Platform>(
            port_handle,
            client_view,
            server_view,
            max_message_length,
            connection_information,
            connection_information_length,
            client_view_value,
        )
        .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        let connect_info = match self.csr_api_connect_info() {
            Some(connect_info) => connect_info,
            None => return NtStatus::ACCESS_VIOLATION,
        };

        let port = LpcPortHandleObject {
            _port_name: port_name.clone(),
        };
        let typed = self.global.litebox.descriptor_table_mut().insert(port);
        let handle = match insert_raw_handle::<Platform, LpcPortSubsystem>(
            &self.global.litebox,
            &self.process.handles,
            typed,
            drop,
        ) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        let mapped_view = match self.map_csr_client_view(client_view_value.view_size) {
            Ok(mapped_view) => mapped_view,
            Err(status) => {
                self.close_lpc_port_handle(handle);
                return status;
            }
        };
        let mut written_client_view = client_view_value;
        written_client_view.view_base = mapped_view.base;
        written_client_view.view_remote_base = mapped_view.base;

        if should_fail_lpc_writeback_after_mapping()
            || write_process_output::<Platform, PortView>(client_view, written_client_view)
                .is_none()
            || max_message_length
                .map(|ptr| ptr.write_at_offset(0, CSR_MAX_MESSAGE_LENGTH))
                .is_some_and(|result| result.is_none())
            || write_process_output::<Platform, CsrApiConnectInfo>(
                connection_information,
                connect_info,
            )
            .is_none()
            || connection_information_length
                .write_at_offset(0, CSR_API_CONNECTINFO_SIZE as u32)
                .is_none()
            || port_handle.write_at_offset(0, handle).is_none()
        {
            self.close_lpc_port_handle(handle);
            let _ = remove_view_pages::<Platform>(
                &self.global.page_manager,
                mapped_view.base,
                mapped_view.size,
            );
            return NtStatus::ACCESS_VIOLATION;
        }

        // Publish metadata only after all guest writebacks have succeeded. If a
        // writeback fails, rollback above closes the unpublished handle and frees
        // the unpublished client view, avoiding half-published ownership.
        self.process.section_views.write().insert(
            mapped_view.base,
            WindowsSectionView {
                size: mapped_view.size,
                // Unlike the loader-owned CSR base alias, the LPC client view is
                // freshly allocated here and should be freed by NtUnmapViewOfSection.
                remove_pages_on_unmap: true,
            },
        );
        self.process.virtual_allocations.write().insert(
            mapped_view.base,
            WindowsVirtualAllocation {
                base: mapped_view.base,
                size: mapped_view.size,
                allocation_protect: PageProtection::PAGE_READWRITE,
                type_: MemoryType::MEM_MAPPED,
                pages: committed_pages(mapped_view.base, mapped_view.size),
            },
        );

        litebox_util_log::debug!(
            port_name:% = port_name,
            handle:% = format_args!("{:#x}", handle.as_raw()),
            client_view_base:% = format_args!("{:#x}", mapped_view.base),
            client_view_size = mapped_view.view_size;
            "Handled NtConnectPort for CSR API port"
        );
        NtStatus::SUCCESS
    }

    pub(crate) fn close_lpc_port_handle(&self, handle: Handle) {
        remove_raw_handle::<Platform, LpcPortSubsystem>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            drop,
        );
    }

    /// Closing the port handle does not free the client view.
    ///
    /// The guest receives that view in `ClientView.ViewBase`; its lifetime is
    /// decoupled from the port handle and ends at explicit unmap or process
    /// teardown.
    pub(crate) fn close_lpc_port(_port: LpcPortHandleObject) {}

    fn csr_api_connect_info(&self) -> Option<CsrApiConnectInfo> {
        let peb =
            ConstPtr::<Platform, ProcessEnvironmentBlock>::from_usize(self.process.peb_address)
                .read_at_offset(0)?;
        Some(CsrApiConnectInfo {
            shared_section_base: peb.read_only_shared_memory_base,
            shared_static_server_data: peb.read_only_static_server_data,
            shared_section_heap: peb.read_only_shared_memory_base,
            debug_flags: 0,
            size_of_peb_data: size_of::<ProcessEnvironmentBlock>() as u32,
            size_of_teb_data: size_of::<ThreadEnvironmentBlock>() as u32,
            number_of_server_dll_names: CSR_SERVER_DLL_NAMES,
            server_process_id: CSR_SERVER_PROCESS_ID,
        })
    }

    fn map_csr_client_view(&self, view_size: usize) -> Result<MappedCsrClientView, NtStatus> {
        let Some(mapped_size) = view_size.checked_next_multiple_of(PAGE_SIZE) else {
            return Err(NtStatus::INVALID_VIEW_SIZE);
        };
        let Some(length) = NonZeroPageSize::<PAGE_SIZE>::new(mapped_size) else {
            return Err(NtStatus::INVALID_VIEW_SIZE);
        };
        let mapping = create_pages(
            &self.global.page_manager,
            None,
            length,
            CreatePagesFlags::empty(),
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            |_| Ok(0),
        )
        .map_err(|_| NtStatus::NO_MEMORY)?;
        Ok(MappedCsrClientView {
            base: mapping.as_usize(),
            size: mapped_size,
            view_size,
        })
    }
}

struct MappedCsrClientView {
    base: usize,
    size: usize,
    view_size: usize,
}

fn read_process_output<Platform: ShimPlatform, T: FromBytes>(
    ptr: MutPtr<Platform, u8>,
) -> Option<T> {
    let bytes = ptr.to_owned_slice(size_of::<T>())?;
    T::read_from_bytes(bytes.as_ref()).ok()
}

fn write_process_output<Platform: ShimPlatform, T: FromBytes + IntoBytes + Immutable>(
    ptr: MutPtr<Platform, u8>,
    value: T,
) -> Option<()> {
    ptr.write_slice_at_offset(0, value.as_bytes())
}

fn probe_lpc_outputs<Platform: ShimPlatform>(
    port_handle: MutPtr<Platform, Handle>,
    client_view: MutPtr<Platform, u8>,
    server_view: Option<MutPtr<Platform, u8>>,
    max_message_length: Option<MutPtr<Platform, u32>>,
    connection_information: MutPtr<Platform, u8>,
    connection_information_length: MutPtr<Platform, u32>,
    client_view_value: PortView,
) -> Option<()> {
    port_handle.write_at_offset(0, port_handle.read_at_offset(0)?)?;
    write_process_output::<Platform, PortView>(client_view, client_view_value)?;
    if let Some(server_view) = server_view {
        let server_view_value = read_process_output::<Platform, RemotePortView>(server_view)?;
        write_process_output::<Platform, RemotePortView>(server_view, server_view_value)?;
    }
    if let Some(max_message_length) = max_message_length {
        max_message_length.write_at_offset(0, max_message_length.read_at_offset(0)?)?;
    }
    let connection_info =
        read_process_output::<Platform, CsrApiConnectInfo>(connection_information)?;
    write_process_output::<Platform, CsrApiConnectInfo>(connection_information, connection_info)?;
    connection_information_length
        .write_at_offset(0, connection_information_length.read_at_offset(0)?)?;
    Some(())
}

fn committed_pages(base: usize, size: usize) -> RangeMap<usize, PageProtection> {
    let mut pages = RangeMap::new();
    if let Some(end) = base.checked_add(size) {
        pages.insert(base..end, PageProtection::PAGE_READWRITE);
    }
    pages
}

fn remove_view_pages<Platform: ShimPlatform>(
    page_manager: &crate::WindowsPageManager<Platform>,
    base: usize,
    size: usize,
) -> Result<(), ()> {
    let ptr = MutPtr::<Platform, u8>::from_usize(base);
    // SAFETY: The caller passes a view range created by this LPC path that has not been published,
    // or a tracked view being rolled back after output write failure.
    unsafe { page_manager.remove_pages(ptr, size) }.map_err(|_| ())
}

#[cfg(test)]
fn should_fail_lpc_writeback_after_mapping() -> bool {
    FAIL_NEXT_LPC_WRITEBACK_AFTER_MAPPING.swap(false, core::sync::atomic::Ordering::SeqCst)
}

#[cfg(not(test))]
fn should_fail_lpc_writeback_after_mapping() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use zerocopy::FromZeros as _;

    use super::*;
    use crate::tests::{TestFS, TestPlatform, const_ptr, mut_byte_ptr, mut_ptr};

    fn task_with_peb(peb: &mut ProcessEnvironmentBlock) -> Task<TestPlatform, TestFS> {
        let mut task = crate::tests::test_task();
        alloc::sync::Arc::get_mut(&mut task.process)
            .expect("test task has a unique process reference")
            .peb_address = core::ptr::from_mut(peb) as usize;
        task
    }

    fn port_name(name: &str) -> (alloc::vec::Vec<u16>, UnicodeString) {
        let name_units = name.encode_utf16().collect::<alloc::vec::Vec<_>>();
        let name = UnicodeString {
            length: u16::try_from(name_units.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from((name_units.len() + 1) * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: name_units.as_ptr() as usize,
        };
        (name_units, name)
    }

    fn valid_client_view() -> PortView {
        PortView {
            length: size_of::<PortView>() as u32,
            _padding: 0,
            section_handle: Handle::from_raw(0x24),
            section_offset: 0,
            view_size: PAGE_SIZE,
            view_base: 0,
            view_remote_base: 0,
        }
    }

    fn empty_connection_info() -> CsrApiConnectInfo {
        CsrApiConnectInfo {
            shared_section_base: 0,
            shared_static_server_data: 0,
            shared_section_heap: 0,
            debug_flags: 0,
            size_of_peb_data: 0,
            size_of_teb_data: 0,
            number_of_server_dll_names: 0,
            server_process_id: 0,
        }
    }

    #[test]
    fn nt_connect_port_fills_csr_connect_info_from_existing_peb_values() {
        let mut peb = ProcessEnvironmentBlock::new_zeroed();
        peb.read_only_shared_memory_base = 0x7000_0000;
        peb.read_only_static_server_data = 0x7000_1000;
        let task = task_with_peb(&mut peb);
        let (_name_units, name) = port_name(WINDOWS_API_PORT);
        let mut handle = Handle::from_raw(0);
        let mut client_view = valid_client_view();
        let mut server_view = RemotePortView {
            length: size_of::<RemotePortView>() as u32,
            _padding: 0,
            view_size: 0,
            view_base: 0,
        };
        let mut max_message_length = 0u32;
        let mut connection_info = empty_connection_info();
        let mut connection_info_len = size_of::<CsrApiConnectInfo>() as u32;

        assert_eq!(
            task.sys_nt_connect_port(
                mut_ptr(&mut handle),
                crate::tests::const_ptr(&name),
                None,
                Some(mut_byte_ptr(&mut client_view)),
                Some(mut_byte_ptr(&mut server_view)),
                Some(mut_ptr(&mut max_message_length)),
                Some(mut_byte_ptr(&mut connection_info)),
                Some(mut_ptr(&mut connection_info_len)),
            ),
            NtStatus::SUCCESS
        );

        assert!(!handle.is_null());
        assert_ne!(client_view.view_base, 0);
        assert_eq!(client_view.view_remote_base, client_view.view_base);
        assert_eq!(max_message_length, CSR_MAX_MESSAGE_LENGTH);
        assert_eq!(
            connection_info.shared_section_base,
            peb.read_only_shared_memory_base
        );
        assert_eq!(
            connection_info.shared_static_server_data,
            peb.read_only_static_server_data
        );
        assert_eq!(
            connection_info.shared_section_heap,
            peb.read_only_shared_memory_base
        );
        assert_eq!(
            connection_info.size_of_peb_data,
            size_of::<ProcessEnvironmentBlock>() as u32
        );
        assert_eq!(
            connection_info.size_of_teb_data,
            size_of::<ThreadEnvironmentBlock>() as u32
        );
    }

    #[test]
    fn nt_connect_port_rejects_unknown_port_name() {
        let mut peb = ProcessEnvironmentBlock::new_zeroed();
        let task = task_with_peb(&mut peb);
        let (_name_units, name) = port_name(r"\Windows\OtherPort");
        let mut handle = Handle::from_raw(0);
        let mut client_view = valid_client_view();
        let mut connection_info = empty_connection_info();
        let mut connection_info_len = size_of::<CsrApiConnectInfo>() as u32;

        assert_eq!(
            task.sys_nt_connect_port(
                mut_ptr(&mut handle),
                const_ptr(&name),
                None,
                Some(mut_byte_ptr(&mut client_view)),
                None,
                None,
                Some(mut_byte_ptr(&mut connection_info)),
                Some(mut_ptr(&mut connection_info_len)),
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
    }

    #[test]
    fn nt_connect_port_rejects_missing_client_view() {
        let mut peb = ProcessEnvironmentBlock::new_zeroed();
        let task = task_with_peb(&mut peb);
        let (_name_units, name) = port_name(WINDOWS_API_PORT);
        let mut handle = Handle::from_raw(0);
        let mut connection_info = empty_connection_info();
        let mut connection_info_len = size_of::<CsrApiConnectInfo>() as u32;

        assert_eq!(
            task.sys_nt_connect_port(
                mut_ptr(&mut handle),
                const_ptr(&name),
                None,
                None,
                None,
                None,
                Some(mut_byte_ptr(&mut connection_info)),
                Some(mut_ptr(&mut connection_info_len)),
            ),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn nt_connect_port_rejects_wrong_connection_info_length() {
        let mut peb = ProcessEnvironmentBlock::new_zeroed();
        let task = task_with_peb(&mut peb);
        let (_name_units, name) = port_name(WINDOWS_API_PORT);
        let mut handle = Handle::from_raw(0);
        let mut client_view = valid_client_view();
        let mut connection_info = empty_connection_info();
        let mut connection_info_len = (size_of::<CsrApiConnectInfo>() - 1) as u32;

        assert_eq!(
            task.sys_nt_connect_port(
                mut_ptr(&mut handle),
                const_ptr(&name),
                None,
                Some(mut_byte_ptr(&mut client_view)),
                None,
                None,
                Some(mut_byte_ptr(&mut connection_info)),
                Some(mut_ptr(&mut connection_info_len)),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
    }

    #[test]
    fn nt_connect_port_rolls_back_handle_and_view_on_writeback_failure() {
        let mut peb = ProcessEnvironmentBlock::new_zeroed();
        peb.read_only_shared_memory_base = 0x7000_0000;
        peb.read_only_static_server_data = 0x7000_1000;
        let task = task_with_peb(&mut peb);
        let (_name_units, name) = port_name(WINDOWS_API_PORT);
        let mut handle = Handle::from_raw(0);
        let mut client_view = valid_client_view();
        let mut connection_info = empty_connection_info();
        let mut connection_info_len = size_of::<CsrApiConnectInfo>() as u32;

        FAIL_NEXT_LPC_WRITEBACK_AFTER_MAPPING.store(true, core::sync::atomic::Ordering::SeqCst);

        assert_eq!(
            task.sys_nt_connect_port(
                mut_ptr(&mut handle),
                const_ptr(&name),
                None,
                Some(mut_byte_ptr(&mut client_view)),
                None,
                None,
                Some(mut_byte_ptr(&mut connection_info)),
                Some(mut_ptr(&mut connection_info_len)),
            ),
            NtStatus::ACCESS_VIOLATION
        );
        assert!(handle.is_null());
        assert!(task.process.handles.read().iter_alive().next().is_none());
        assert!(task.process.section_views.read().is_empty());
        assert!(task.process.virtual_allocations.read().is_empty());
    }
}
