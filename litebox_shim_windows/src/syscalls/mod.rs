// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod nt_sysno {
    include!(concat!(env!("OUT_DIR"), "/nt_sysno.rs"));
}

pub(crate) mod apphelp;
pub(crate) mod event;
pub(crate) mod file;
pub(crate) mod hard_error;
pub(crate) mod mm;
pub(crate) mod nls;
pub(crate) mod object;
pub(crate) mod process;
pub(crate) mod registry;
pub(crate) mod section;
pub(crate) mod sysinfo;
pub(crate) mod thread;
pub(crate) mod token;
pub(crate) mod trace;
pub(crate) mod wait_completion_packet;

pub(crate) use nt_sysno::NtSysno;

use litebox::platform::{RawConstPointer as _, RawPointerProvider};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;

use crate::{Handle, ProcessHandle, ThreadHandle};

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub(crate) enum SyscallRequest<Platform: RawPointerProvider> {
    NtClose {
        handle: Handle,
    },
    NtApphelpCacheControl {
        service_class: u32,
        service_data: Option<Platform::RawMutPointer<u8>>,
    },
    NtCreateEvent {
        event_handle: Platform::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<Platform::RawConstPointer<object::ObjectAttributes>>,
        event_type: u32,
        initial_state: u8,
    },
    NtCreateWaitCompletionPacket {
        wait_completion_packet_handle: Platform::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<Platform::RawConstPointer<object::ObjectAttributes>>,
    },
    NtOpenDirectoryObject {
        directory_handle: Platform::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<Platform::RawConstPointer<object::ObjectAttributes>>,
    },
    NtOpenSymbolicLinkObject {
        link_handle: Platform::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<Platform::RawConstPointer<object::ObjectAttributes>>,
    },
    NtQuerySymbolicLinkObject {
        link_handle: Handle,
        link_target: Platform::RawMutPointer<crate::loader::nt_types::UnicodeString>,
        returned_length: Option<Platform::RawMutPointer<u32>>,
    },
    NtOpenFile {
        file_handle: Platform::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<Platform::RawConstPointer<object::ObjectAttributes>>,
        io_status_block: Platform::RawMutPointer<file::IoStatusBlock>,
        share_access: u32,
        open_options: u32,
    },
    NtQueryAttributesFile {
        object_attributes: Platform::RawConstPointer<object::ObjectAttributes>,
        file_information: Platform::RawMutPointer<file::FileBasicInformation>,
    },
    NtQueryVolumeInformationFile {
        file_handle: Handle,
        io_status_block: Platform::RawMutPointer<file::IoStatusBlock>,
        fs_information: Platform::RawMutPointer<u8>,
        fs_information_length: u32,
        fs_information_class: u32,
    },
    NtOpenKey {
        key_handle: Platform::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<Platform::RawConstPointer<object::ObjectAttributes>>,
    },
    NtOpenThreadToken {
        thread_handle: ThreadHandle,
        desired_access: u32,
        open_as_self: u8,
        token_handle: Platform::RawMutPointer<Handle>,
    },
    NtOpenSection {
        section_handle: Platform::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<Platform::RawConstPointer<object::ObjectAttributes>>,
    },
    NtMapViewOfSection {
        section_handle: Handle,
        process_handle: ProcessHandle,
        base_address: Platform::RawMutPointer<usize>,
        zero_bits: usize,
        commit_size: usize,
        section_offset: Option<Platform::RawMutPointer<i64>>,
        view_size: Platform::RawMutPointer<usize>,
        inherit_disposition: u32,
        allocation_type: u32,
        page_protection: u32,
    },
    NtUnmapViewOfSection {
        process_handle: ProcessHandle,
        base_address: usize,
    },
    NtQueryValueKey {
        key_handle: Handle,
        value_name: Platform::RawConstPointer<crate::loader::nt_types::UnicodeString>,
        key_value_information_class: u32,
        key_value_information: Platform::RawMutPointer<u8>,
        length: u32,
        result_length: Platform::RawMutPointer<u32>,
    },
    NtClearEvent {
        event_handle: Handle,
    },
    NtResetEvent {
        event_handle: Handle,
        previous_state: Option<Platform::RawMutPointer<i32>>,
    },
    NtSetEvent {
        event_handle: Handle,
        previous_state: Option<Platform::RawMutPointer<i32>>,
    },
    NtTerminateProcess {
        process_handle: ProcessHandle,
        exit_status: i32,
    },
    NtAllocateVirtualMemory {
        process_handle: ProcessHandle,
        base_address: Platform::RawMutPointer<usize>,
        zero_bits: usize,
        region_size: Platform::RawMutPointer<usize>,
        allocation_type: u32,
        protect: u32,
    },
    NtAllocateVirtualMemoryEx {
        process_handle: ProcessHandle,
        base_address: Platform::RawMutPointer<usize>,
        region_size: Platform::RawMutPointer<usize>,
        allocation_type: u32,
        protect: u32,
        extended_parameters: Option<Platform::RawConstPointer<mm::MemoryExtendedParameter>>,
        extended_parameter_count: u32,
    },
    NtFreeVirtualMemory {
        process_handle: ProcessHandle,
        base_address: Platform::RawMutPointer<usize>,
        region_size: Platform::RawMutPointer<usize>,
        free_type: u32,
    },
    NtProtectVirtualMemory {
        process_handle: ProcessHandle,
        base_address: Platform::RawMutPointer<usize>,
        region_size: Platform::RawMutPointer<usize>,
        new_protect: u32,
        old_protect: Platform::RawMutPointer<u32>,
    },
    NtQueryVirtualMemory {
        process_handle: ProcessHandle,
        base_address: usize,
        memory_information_class: u32,
        memory_information: Platform::RawMutPointer<u8>,
        memory_information_length: usize,
        return_length: Option<Platform::RawMutPointer<usize>>,
    },
    NtQueryInformationProcess {
        process_handle: ProcessHandle,
        process_information_class: u32,
        process_information: Platform::RawMutPointer<u8>,
        process_information_length: u32,
        return_length: Option<Platform::RawMutPointer<u32>>,
    },
    NtSetInformationProcess {
        process_handle: ProcessHandle,
        process_information_class: u32,
        process_information: Platform::RawConstPointer<u8>,
        process_information_length: u32,
    },
    NtSetInformationThread {
        thread_handle: ThreadHandle,
        thread_information_class: u32,
        thread_information: Platform::RawConstPointer<u8>,
        thread_information_length: u32,
    },
    NtGetNlsSectionPtr {
        section_type: u32,
        section_data: u32,
        context_data: usize,
        section_pointer: Platform::RawMutPointer<usize>,
        section_size: Option<Platform::RawMutPointer<u32>>,
    },
    NtQueryPerformanceCounter {
        performance_counter: Platform::RawMutPointer<i64>,
        performance_frequency: Platform::RawMutPointer<i64>,
    },
    NtQuerySystemInformation {
        system_information_class: u32,
        system_information: Platform::RawMutPointer<u8>,
        system_information_length: u32,
        return_length: Option<Platform::RawMutPointer<u32>>,
    },
    NtQuerySystemInformationEx {
        system_information_class: u32,
        input_buffer: Option<Platform::RawConstPointer<u8>>,
        input_buffer_length: u32,
        system_information: Platform::RawMutPointer<u8>,
        system_information_length: u32,
        return_length: Option<Platform::RawMutPointer<u32>>,
    },
    NtTraceEvent {
        trace_handle: Handle,
        flags: u32,
        field_size: u32,
        fields: Option<Platform::RawConstPointer<u8>>,
    },
    NtRaiseHardError {
        error_status: NtStatus,
        number_of_parameters: u32,
        unicode_string_parameter_mask: u32,
        parameters: Option<Platform::RawConstPointer<usize>>,
        valid_response_options: u32,
        response: Platform::RawMutPointer<u32>,
    },
    /// TODO: not supported yet
    NtManageHotPatch,
}

impl<Platform: RawPointerProvider> SyscallRequest<Platform> {
    pub(crate) fn try_from_raw(pt_regs: &litebox_common_linux::PtRegs) -> Option<Self> {
        // Windows x64 syscall arguments are carried in r10, rdx, r8, r9 for
        // the first four arguments after the ntdll syscall stub shuffles rcx.
        // Additional arguments are read from the user stack below.
        macro_rules! sys_req {
            ($id:ident { $( $field:ident $(:$star:tt)? ),* $(,)? }) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 ] [ ])
            };
            (@[$id:ident] [ $f:ident $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: win_sys_req_arg::<Platform, _>(pt_regs, $n)?, ])
            };
            (@[$id:ident] [ $f:ident : * $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: win_sys_req_ptr::<Platform, _, _>(pt_regs, $n)?, ])
            };
            (@[$id:ident] [ $f:ident : { $expr:expr } $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: ($expr)(win_sys_req_arg::<Platform, _>(pt_regs, $n)?), ])
            };
            (@[$id:ident] [ ] [ $($ns:literal),* ] [ $($tail:tt)* ]) => {
                SyscallRequest::$id { $($tail)* }
            };
        }

        match NtSysno::from_raw(pt_regs.orig_rax)? {
            NtSysno::NtClose => Some(sys_req!(NtClose {
                handle: { Handle::from_raw },
            })),
            NtSysno::NtApphelpCacheControl => Some(sys_req!(NtApphelpCacheControl {
                service_class,
                service_data: *,
            })),
            NtSysno::NtCreateEvent => Some(sys_req!(NtCreateEvent {
                event_handle:*,
                desired_access,
                object_attributes:*,
                event_type,
                initial_state,
            })),
            NtSysno::NtCreateWaitCompletionPacket => Some(sys_req!(NtCreateWaitCompletionPacket {
                wait_completion_packet_handle:*,
                desired_access,
                object_attributes:*,
            })),
            NtSysno::NtOpenDirectoryObject => Some(sys_req!(NtOpenDirectoryObject {
                directory_handle:*,
                desired_access,
                object_attributes:*,
            })),
            NtSysno::NtOpenSymbolicLinkObject => Some(sys_req!(NtOpenSymbolicLinkObject {
                link_handle:*,
                desired_access,
                object_attributes:*,
            })),
            NtSysno::NtQuerySymbolicLinkObject => Some(sys_req!(NtQuerySymbolicLinkObject {
                link_handle:{Handle::from_raw},
                link_target:*,
                returned_length:*,
            })),
            NtSysno::NtOpenFile => Some(sys_req!(NtOpenFile {
                file_handle:*,
                desired_access,
                object_attributes:*,
                io_status_block:*,
                share_access,
                open_options,
            })),
            NtSysno::NtQueryAttributesFile => Some(sys_req!(NtQueryAttributesFile {
                object_attributes:*,
                file_information:*,
            })),
            NtSysno::NtQueryVolumeInformationFile => Some(sys_req!(NtQueryVolumeInformationFile {
                file_handle:{Handle::from_raw},
                io_status_block:*,
                fs_information:*,
                fs_information_length,
                fs_information_class,
            })),
            NtSysno::NtOpenKey => Some(sys_req!(NtOpenKey {
                key_handle:*,
                desired_access,
                object_attributes:*,
            })),
            NtSysno::NtOpenThreadToken => Some(sys_req!(NtOpenThreadToken {
                thread_handle:{ThreadHandle::from_raw},
                desired_access,
                open_as_self,
                token_handle:*,
            })),
            NtSysno::NtOpenSection => Some(sys_req!(NtOpenSection {
                section_handle:*,
                desired_access,
                object_attributes:*,
            })),
            NtSysno::NtMapViewOfSection => Some(sys_req!(NtMapViewOfSection {
                section_handle:{Handle::from_raw},
                process_handle:{ProcessHandle::from_raw},
                base_address:*,
                zero_bits,
                commit_size,
                section_offset:*,
                view_size:*,
                inherit_disposition,
                allocation_type,
                page_protection,
            })),
            NtSysno::NtUnmapViewOfSection => Some(sys_req!(NtUnmapViewOfSection {
                process_handle: { ProcessHandle::from_raw },
                base_address,
            })),
            NtSysno::NtQueryValueKey => Some(sys_req!(NtQueryValueKey {
                key_handle:{Handle::from_raw},
                value_name:*,
                key_value_information_class,
                key_value_information:*,
                length,
                result_length:*,
            })),
            NtSysno::NtClearEvent => Some(sys_req!(NtClearEvent {
                event_handle: { Handle::from_raw },
            })),
            NtSysno::NtResetEvent => Some(sys_req!(NtResetEvent {
                event_handle:{Handle::from_raw},
                previous_state:*,
            })),
            NtSysno::NtSetEvent => Some(sys_req!(NtSetEvent {
                event_handle:{Handle::from_raw},
                previous_state:*,
            })),
            NtSysno::NtAllocateVirtualMemory => Some(sys_req!(NtAllocateVirtualMemory {
                process_handle:{ProcessHandle::from_raw},
                base_address:*,
                zero_bits,
                region_size:*,
                allocation_type,
                protect,
            })),
            NtSysno::NtAllocateVirtualMemoryEx => Some(sys_req!(NtAllocateVirtualMemoryEx {
                process_handle:{ProcessHandle::from_raw},
                base_address:*,
                region_size:*,
                allocation_type,
                protect,
                extended_parameters:*,
                extended_parameter_count,
            })),
            NtSysno::NtFreeVirtualMemory => Some(sys_req!(NtFreeVirtualMemory {
                process_handle:{ProcessHandle::from_raw},
                base_address:*,
                region_size:*,
                free_type,
            })),
            NtSysno::NtTerminateProcess => Some(sys_req!(NtTerminateProcess {
                process_handle: { ProcessHandle::from_raw },
                exit_status,
            })),
            NtSysno::NtProtectVirtualMemory => Some(sys_req!(NtProtectVirtualMemory {
                process_handle:{ProcessHandle::from_raw},
                base_address:*,
                region_size:*,
                new_protect,
                old_protect:*,
            })),
            NtSysno::NtQueryVirtualMemory => Some(sys_req!(NtQueryVirtualMemory {
                process_handle:{ProcessHandle::from_raw},
                base_address,
                memory_information_class,
                memory_information:*,
                memory_information_length,
                return_length:*,
            })),
            NtSysno::NtQueryInformationProcess => Some(sys_req!(NtQueryInformationProcess {
                process_handle:{ProcessHandle::from_raw},
                process_information_class,
                process_information:*,
                process_information_length,
                return_length:*,
            })),
            NtSysno::NtSetInformationProcess => Some(sys_req!(NtSetInformationProcess {
                process_handle:{ProcessHandle::from_raw},
                process_information_class,
                process_information:*,
                process_information_length,
            })),
            NtSysno::NtSetInformationThread => Some(sys_req!(NtSetInformationThread {
                thread_handle:{ThreadHandle::from_raw},
                thread_information_class,
                thread_information:*,
                thread_information_length,
            })),
            NtSysno::NtGetNlsSectionPtr => Some(sys_req!(NtGetNlsSectionPtr {
                section_type,
                section_data,
                context_data,
                section_pointer:*,
                section_size:*,
            })),
            NtSysno::NtQueryPerformanceCounter => Some(sys_req!(NtQueryPerformanceCounter {
                performance_counter:*,
                performance_frequency:*,
            })),
            NtSysno::NtQuerySystemInformation => Some(sys_req!(NtQuerySystemInformation {
                system_information_class,
                system_information:*,
                system_information_length,
                return_length:*,
            })),
            NtSysno::NtQuerySystemInformationEx => Some(sys_req!(NtQuerySystemInformationEx {
                system_information_class,
                input_buffer:*,
                input_buffer_length,
                system_information:*,
                system_information_length,
                return_length:*,
            })),
            NtSysno::NtTraceEvent => Some(sys_req!(NtTraceEvent {
                trace_handle:{Handle::from_raw},
                flags,
                field_size,
                fields:*,
            })),
            NtSysno::NtRaiseHardError => Some(sys_req!(NtRaiseHardError {
                error_status,
                number_of_parameters,
                unicode_string_parameter_mask,
                parameters:*,
                valid_response_options,
                response:*,
            })),
            NtSysno::NtManageHotPatch => Some(SyscallRequest::NtManageHotPatch),
            _ => None,
        }
    }
}

fn win_syscall_arg<Platform: RawPointerProvider>(
    pt_regs: &litebox_common_linux::PtRegs,
    idx: usize,
) -> Option<usize> {
    match idx {
        0 => Some(pt_regs.r10),
        1 => Some(pt_regs.rdx),
        2 => Some(pt_regs.r8),
        3 => Some(pt_regs.r9),
        idx => {
            let stack_offset = 0x28usize.checked_add((idx - 4).checked_mul(size_of::<usize>())?)?;
            let stack_address = pt_regs.rsp.checked_add(stack_offset)?;
            let stack_arg = Platform::RawConstPointer::<usize>::from_usize(stack_address);
            stack_arg.read_at_offset(0)
        }
    }
}

fn win_sys_req_arg<Platform: RawPointerProvider, T: ReinterpretTruncatedFromUsize>(
    pt_regs: &litebox_common_linux::PtRegs,
    idx: usize,
) -> Option<T> {
    Some(T::reinterpret_truncated_from_usize(win_syscall_arg::<
        Platform,
    >(pt_regs, idx)?))
}

fn win_sys_req_ptr<
    Platform: RawPointerProvider,
    T: zerocopy::FromBytes,
    P: ReinterpretUsizeAsPtr<T>,
>(
    pt_regs: &litebox_common_linux::PtRegs,
    idx: usize,
) -> Option<P> {
    Some(P::reinterpret_usize_as_ptr(win_syscall_arg::<Platform>(
        pt_regs, idx,
    )?))
}

trait ReinterpretTruncatedFromUsize: Sized {
    fn reinterpret_truncated_from_usize(value: usize) -> Self;
}

impl ReinterpretTruncatedFromUsize for usize {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        value
    }
}

impl ReinterpretTruncatedFromUsize for u64 {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        value as u64
    }
}

impl ReinterpretTruncatedFromUsize for isize {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        value.cast_signed()
    }
}

impl ReinterpretTruncatedFromUsize for NtStatus {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        Self::from_raw(value.truncate())
    }
}

macro_rules! reinterpret_truncated_unsigned {
    ($($ty:ty),* $(,)?) => {
        $(
            impl ReinterpretTruncatedFromUsize for $ty {
                fn reinterpret_truncated_from_usize(value: usize) -> Self {
                    value.truncate()
                }
            }
        )*
    };
}

macro_rules! reinterpret_truncated_signed {
    ($($sty:ty),* $(,)?) => {
        $(
            impl ReinterpretTruncatedFromUsize for $sty {
                fn reinterpret_truncated_from_usize(value: usize) -> Self {
                    value.cast_signed().truncate()
                }
            }
        )*
    };
}

reinterpret_truncated_unsigned!(u8, u16, u32);
reinterpret_truncated_signed!(i8, i16, i32);

trait ReinterpretUsizeAsPtr<T>: Sized {
    fn reinterpret_usize_as_ptr(value: usize) -> Self;
}

impl<T: zerocopy::FromBytes, P: litebox::platform::RawConstPointer<T>>
    ReinterpretUsizeAsPtr<core::marker::PhantomData<((), T)>> for P
{
    fn reinterpret_usize_as_ptr(value: usize) -> Self {
        P::from_usize(value)
    }
}

impl<T: zerocopy::FromBytes, P: litebox::platform::RawConstPointer<T>>
    ReinterpretUsizeAsPtr<core::marker::PhantomData<(bool, T)>> for Option<P>
{
    fn reinterpret_usize_as_ptr(value: usize) -> Self {
        if value == 0 {
            None
        } else {
            Some(P::from_usize(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Platform;

    #[test]
    fn nt_map_view_of_section_decodes_stack_arguments() {
        crate::tests::init_platform();
        let mut base_address = 0usize;
        let mut section_offset = 0i64;
        let mut view_size = 0usize;
        let stack_args = [
            0x10usize,
            core::ptr::from_mut(&mut section_offset) as usize,
            core::ptr::from_mut(&mut view_size) as usize,
            2,
            0x4000_0000,
            0x02,
        ];
        let pt_regs = litebox_common_linux::PtRegs {
            r10: 0x20,
            rdx: ProcessHandle::CURRENT.as_raw(),
            r8: core::ptr::from_mut(&mut base_address) as usize,
            r9: 3,
            orig_rax: 0x28,
            rsp: stack_args.as_ptr() as usize - 0x28,
            ..Default::default()
        };

        let Some(SyscallRequest::NtMapViewOfSection {
            section_handle,
            process_handle,
            base_address: decoded_base_address,
            zero_bits,
            commit_size,
            section_offset: decoded_section_offset,
            view_size: decoded_view_size,
            inherit_disposition,
            allocation_type,
            page_protection,
        }) = SyscallRequest::<Platform>::try_from_raw(&pt_regs)
        else {
            panic!("NtMapViewOfSection did not decode");
        };

        assert_eq!(section_handle, Handle::from_raw(0x20));
        assert!(process_handle.is_current());
        assert_eq!(
            decoded_base_address.as_usize(),
            core::ptr::from_mut(&mut base_address) as usize
        );
        assert_eq!(zero_bits, 3);
        assert_eq!(commit_size, 0x10);
        assert_eq!(
            decoded_section_offset.unwrap().as_usize(),
            core::ptr::from_mut(&mut section_offset) as usize
        );
        assert_eq!(
            decoded_view_size.as_usize(),
            core::ptr::from_mut(&mut view_size) as usize
        );
        assert_eq!(inherit_disposition, 2);
        assert_eq!(allocation_type, 0x4000_0000);
        assert_eq!(page_protection, 0x02);
    }

    #[test]
    fn nt_unmap_view_of_section_decodes_arguments() {
        crate::tests::init_platform();
        let pt_regs = litebox_common_linux::PtRegs {
            r10: ProcessHandle::CURRENT.as_raw(),
            rdx: 0x1234_5000,
            orig_rax: 0x2a,
            ..Default::default()
        };

        let Some(SyscallRequest::NtUnmapViewOfSection {
            process_handle,
            base_address,
        }) = SyscallRequest::<Platform>::try_from_raw(&pt_regs)
        else {
            panic!("NtUnmapViewOfSection did not decode");
        };

        assert!(process_handle.is_current());
        assert_eq!(base_address, 0x1234_5000);
    }

    #[test]
    fn nt_apphelp_cache_control_decodes_arguments() {
        crate::tests::init_platform();
        let mut service_data = 0u8;
        let pt_regs = litebox_common_linux::PtRegs {
            r10: 2,
            rdx: core::ptr::from_mut(&mut service_data) as usize,
            orig_rax: 0x4c,
            ..Default::default()
        };

        let Some(SyscallRequest::NtApphelpCacheControl {
            service_class,
            service_data: decoded_service_data,
        }) = SyscallRequest::<Platform>::try_from_raw(&pt_regs)
        else {
            panic!("NtApphelpCacheControl did not decode");
        };

        assert_eq!(service_class, 2);
        assert_eq!(
            decoded_service_data
                .expect("service data pointer")
                .as_usize(),
            core::ptr::from_mut(&mut service_data) as usize
        );
    }
}
