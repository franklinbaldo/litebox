// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod nt_sysno {
    include!(concat!(env!("OUT_DIR"), "/nt_sysno.rs"));
}

pub(crate) mod mm;
pub(crate) mod sysinfo;

pub(crate) use nt_sysno::NtSysno;

pub(crate) const NT_CURRENT_PROCESS: usize = usize::MAX;

pub(crate) fn is_current_process_handle(process_handle: usize) -> bool {
    process_handle == NT_CURRENT_PROCESS
}

use litebox::platform::{RawConstPointer as _, RawPointerProvider};
use litebox::utils::TruncateExt as _;

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub(crate) enum SyscallRequest<Platform: RawPointerProvider> {
    NtTerminateProcess {
        process_handle: usize,
        exit_status: i32,
    },
    NtAllocateVirtualMemory {
        process_handle: usize,
        base_address: Platform::RawMutPointer<usize>,
        zero_bits: usize,
        region_size: Platform::RawMutPointer<usize>,
        allocation_type: u32,
        protect: u32,
    },
    NtFreeVirtualMemory {
        process_handle: usize,
        base_address: Platform::RawMutPointer<usize>,
        region_size: Platform::RawMutPointer<usize>,
        free_type: u32,
    },
    NtProtectVirtualMemory {
        process_handle: usize,
        base_address: Platform::RawMutPointer<usize>,
        region_size: Platform::RawMutPointer<usize>,
        new_protect: u32,
        old_protect: Platform::RawMutPointer<u32>,
    },
    NtQueryVirtualMemory {
        process_handle: usize,
        base_address: usize,
        memory_information_class: u32,
        memory_information: Platform::RawMutPointer<u8>,
        memory_information_length: usize,
        return_length: Option<Platform::RawMutPointer<usize>>,
    },
    NtQueryPerformanceCounter {
        performance_counter: Platform::RawMutPointer<i64>,
        performance_frequency: Platform::RawMutPointer<i64>,
    },
}

impl<Platform: RawPointerProvider> SyscallRequest<Platform> {
    pub(crate) fn try_from_raw(pt_regs: &litebox_common_linux::PtRegs) -> Option<Self> {
        // Windows x64 syscall arguments are carried in r10, rdx, r8, r9 for
        // the first four arguments after the ntdll syscall stub shuffles rcx.
        // Additional arguments are read from the user stack below.
        macro_rules! sys_req {
            ($id:ident { $( $field:ident $(:$star:tt)? ),* $(,)? }) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ 0, 1, 2, 3, 4, 5 ] [ ])
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
            NtSysno::NtAllocateVirtualMemory => Some(sys_req!(NtAllocateVirtualMemory {
                process_handle,
                base_address:*,
                zero_bits,
                region_size:*,
                allocation_type,
                protect,
            })),
            NtSysno::NtFreeVirtualMemory => Some(sys_req!(NtFreeVirtualMemory {
                process_handle,
                base_address:*,
                region_size:*,
                free_type,
            })),
            NtSysno::NtTerminateProcess => Some(sys_req!(NtTerminateProcess {
                process_handle,
                exit_status,
            })),
            NtSysno::NtProtectVirtualMemory => Some(sys_req!(NtProtectVirtualMemory {
                process_handle,
                base_address:*,
                region_size:*,
                new_protect,
                old_protect:*,
            })),
            NtSysno::NtQueryVirtualMemory => Some(sys_req!(NtQueryVirtualMemory {
                process_handle,
                base_address,
                memory_information_class,
                memory_information:*,
                memory_information_length,
                return_length:*,
            })),
            NtSysno::NtQueryPerformanceCounter => Some(sys_req!(NtQueryPerformanceCounter {
                performance_counter:*,
                performance_frequency:*,
            })),
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
