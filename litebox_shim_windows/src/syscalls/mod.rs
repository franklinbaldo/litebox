// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod nt_sysno {
    include!(concat!(env!("OUT_DIR"), "/nt_sysno.rs"));
}

pub(crate) mod sysinfo;

pub(crate) use nt_sysno::NtSysno;

use litebox::utils::TruncateExt as _;

#[derive(Debug)]
pub(crate) enum SyscallRequest<Platform: litebox::platform::RawPointerProvider> {
    NtTerminateProcess {
        process_handle: usize,
        exit_status: i32,
    },
    NtQueryPerformanceCounter {
        performance_counter: Platform::RawMutPointer<i64>,
        performance_frequency: Platform::RawMutPointer<i64>,
    },
}

impl<Platform: litebox::platform::RawPointerProvider> SyscallRequest<Platform> {
    pub(crate) fn try_from_raw(pt_regs: &litebox_common_linux::PtRegs) -> Option<Self> {
        // Windows x64 syscall arguments are carried in r10, rdx, r8, r9 for
        // the first four arguments after the ntdll syscall stub shuffles rcx.
        macro_rules! sys_req {
            ($id:ident { $( $field:ident $(:$star:tt)? ),* $(,)? }) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ 0, 1, 2, 3 ] [ ])
            };
            (@[$id:ident] [ $f:ident $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: pt_regs.win_sys_req_arg($n), ])
            };
            (@[$id:ident] [ $f:ident : * $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: pt_regs.win_sys_req_ptr($n), ])
            };
            (@[$id:ident] [ $f:ident : { $expr:expr } $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: ($expr)(pt_regs.win_sys_req_arg($n)), ])
            };
            (@[$id:ident] [ ] [ $($ns:literal),* ] [ $($tail:tt)* ]) => {
                SyscallRequest::$id { $($tail)* }
            };
        }

        match NtSysno::from_raw(pt_regs.orig_rax)? {
            NtSysno::NtTerminateProcess => Some(sys_req!(NtTerminateProcess {
                process_handle,
                exit_status,
            })),
            NtSysno::NtQueryPerformanceCounter => Some(sys_req!(NtQueryPerformanceCounter {
                performance_counter:*,
                performance_frequency:*,
            })),
            _ => None,
        }
    }
}

trait WindowsSyscallArgs {
    fn win_syscall_arg(&self, idx: usize) -> usize;
    fn win_sys_req_arg<T: ReinterpretTruncatedFromUsize>(&self, idx: usize) -> T {
        T::reinterpret_truncated_from_usize(self.win_syscall_arg(idx))
    }
    fn win_sys_req_ptr<T: zerocopy::FromBytes, P: ReinterpretUsizeAsPtr<T>>(
        &self,
        idx: usize,
    ) -> P {
        P::reinterpret_usize_as_ptr(self.win_syscall_arg(idx))
    }
}

impl WindowsSyscallArgs for litebox_common_linux::PtRegs {
    fn win_syscall_arg(&self, idx: usize) -> usize {
        match idx {
            0 => self.r10,
            1 => self.rdx,
            2 => self.r8,
            3 => self.r9,
            _ => panic!("Invalid Windows syscall argument index: {}", idx),
        }
    }
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
